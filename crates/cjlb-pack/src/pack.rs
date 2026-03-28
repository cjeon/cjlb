use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rand::RngCore;

use cjlb_crypto::{compute_chunk_hmac, encrypt_page, MasterKey};
use cjlb_format::chunk::{ChunkHeader, CHUNK_HEADER_SIZE, CHUNK_MAGIC, PAGES_PER_CHUNK};
use cjlb_format::manifest::{ManifestPreamble, MANIFEST_MAGIC, MANIFEST_PREAMBLE_SIZE};
use cjlb_format::nonce::{
    make_nonce, DOMAIN_BASE_PAGES, DOMAIN_MANIFEST_HEADER, DOMAIN_MANIFEST_ROUTE_TABLE,
};
use cjlb_format::page::{PAGE_BODY_SIZE, PAGE_TOTAL_SIZE};

use crate::route_table_builder::{
    build_route_table, serialize_route_table, FilePageKind, RouteTableResult,
};

/// Pack configuration (deserialized from JSON config file).
#[derive(Debug, serde::Deserialize)]
pub struct PackConfig {
    pub input_dir: String,
    pub output_dir: String,
    /// Log verbosity — "error", "warn", "info", "debug", "trace".
    /// Defaults to "info" when absent or unrecognised.
    #[serde(default)]
    pub log_level: Option<String>,
}

impl PackConfig {
    /// Resolve the configured log level to a `log::LevelFilter`.
    #[must_use]
    pub fn log_level_filter(&self) -> log::LevelFilter {
        match self.log_level.as_deref() {
            Some("error") => log::LevelFilter::Error,
            Some("warn") => log::LevelFilter::Warn,
            Some("debug") => log::LevelFilter::Debug,
            Some("trace") => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        }
    }
}

/// Result of a successful pack operation.
#[derive(Debug)]
pub struct PackOutput {
    pub master_key_hex: String,
    pub bundle_id_hex: String,
}

/// Run the full packing pipeline.
///
/// # Errors
///
/// Returns an error if the input directory cannot be read, files cannot be
/// opened, encryption fails, or the output directory is not writable.
pub fn run_pack(config: &PackConfig) -> Result<PackOutput> {
    let input_dir = Path::new(&config.input_dir)
        .canonicalize()
        .with_context(|| format!("cannot resolve input_dir: {}", config.input_dir))?;
    let output_dir = Path::new(&config.output_dir);

    // 1. Generate fresh MasterKey and derive sub-keys.
    let master_key = MasterKey::generate();
    let dk = master_key.derive_keys();
    let key_commit = master_key.key_commit();

    // 2. Generate random 16-byte bundle_id.
    let mut bundle_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bundle_id);

    // 3-4. Walk directory and build route table.
    log::info!("Building route table from {}", input_dir.display());
    let mut rt = build_route_table(&input_dir)?;

    // 5. Read file data into page buffers.
    log::info!(
        "Packing {} files into {} pages",
        rt.file_read_order.len(),
        rt.pages.len()
    );
    fill_page_data(&mut rt)?;

    // Remove trailing empty pages (pages that were pre-allocated but have no data).
    trim_empty_trailing_pages(&mut rt);

    // 6. Encrypt all pages.
    let encrypted_pages = encrypt_all_pages(&rt.pages, &dk.bundle_dek, &bundle_id)?;

    // 7. Write chunk files.
    let chunks_dir = output_dir.join("chunks");
    fs::create_dir_all(&chunks_dir)
        .with_context(|| format!("cannot create chunks dir: {}", chunks_dir.display()))?;

    write_chunks(&encrypted_pages, &dk.hmac_key, &chunks_dir)?;

    // 8. Build and write manifest.
    let route_table_bytes = serialize_route_table(&rt);
    write_manifest(
        &route_table_bytes,
        &dk.manifest_dek,
        &bundle_id,
        &key_commit,
        output_dir,
    )?;

    let master_key_hex = hex_encode(master_key.as_bytes());
    let bundle_id_hex = hex_encode(&bundle_id);

    Ok(PackOutput {
        master_key_hex,
        bundle_id_hex,
    })
}

/// Read file contents into the pre-allocated page buffers.
fn fill_page_data(rt: &mut RouteTableResult) -> Result<()> {
    for entry in &rt.file_read_order {
        if entry.size == 0 {
            continue;
        }
        match &entry.kind {
            FilePageKind::Small {
                page_id,
                offset_in_page,
            } => {
                let mut file = fs::File::open(&entry.abs_path)
                    .with_context(|| format!("cannot open file: {}", entry.abs_path.display()))?;
                let page = &mut rt.pages[*page_id as usize];
                let offset = *offset_in_page as usize;
                let size = usize::try_from(entry.size).expect("file size fits in usize");
                file.read_exact(&mut page[offset..offset + size])
                    .with_context(|| format!("cannot read file: {}", entry.abs_path.display()))?;
            }
            FilePageKind::Large {
                first_span_index,
                span_count,
            } => {
                let mut file = fs::File::open(&entry.abs_path)
                    .with_context(|| format!("cannot open file: {}", entry.abs_path.display()))?;
                for i in 0..*span_count {
                    let span = &rt.spans[(*first_span_index + i) as usize];
                    let page_id = u32::from_le(span.page_id) as usize;
                    let size = u32::from_le(span.size_in_page) as usize;
                    let page = &mut rt.pages[page_id];
                    file.read_exact(&mut page[..size]).with_context(|| {
                        format!("cannot read file: {}", entry.abs_path.display())
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// Remove trailing pages that are completely zero (unused).
fn trim_empty_trailing_pages(rt: &mut RouteTableResult) {
    while let Some(page) = rt.pages.last() {
        if page.iter().all(|&b| b == 0) {
            // Check no file references this page.
            let page_id = u32::try_from(rt.pages.len() - 1).expect("page count fits in u32");
            let referenced = rt.file_read_order.iter().any(|e| match &e.kind {
                FilePageKind::Small { page_id: pid, .. } => *pid == page_id,
                FilePageKind::Large {
                    first_span_index,
                    span_count,
                } => {
                    for i in 0..*span_count {
                        let span = &rt.spans[(*first_span_index + i) as usize];
                        if u32::from_le(span.page_id) == page_id {
                            return true;
                        }
                    }
                    false
                }
            });
            if referenced {
                break;
            }
            rt.pages.pop();
        } else {
            break;
        }
    }
}

/// Encrypt all page buffers using `DOMAIN_BASE_PAGES` nonces.
fn encrypt_all_pages(
    pages: &[Vec<u8>],
    dek: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<Vec<Vec<u8>>> {
    let mut encrypted = Vec::with_capacity(pages.len());
    for (i, page_data) in pages.iter().enumerate() {
        let nonce = make_nonce(
            DOMAIN_BASE_PAGES,
            u64::try_from(i).expect("page index fits in u64"),
        );
        let enc = encrypt_page(page_data, dek, &nonce, bundle_id)
            .with_context(|| format!("encrypt_page failed for page {i}"))?;
        encrypted.push(enc);
    }
    Ok(encrypted)
}

/// Group encrypted pages into chunks and write chunk files.
fn write_chunks(encrypted_pages: &[Vec<u8>], hmac_key: &[u8; 32], chunks_dir: &Path) -> Result<()> {
    let total_pages = encrypted_pages.len();
    let pages_per_chunk = PAGES_PER_CHUNK as usize;
    let chunk_count = total_pages.div_ceil(pages_per_chunk);

    for chunk_idx in 0..chunk_count {
        let start = chunk_idx * pages_per_chunk;
        let end = std::cmp::min(start + pages_per_chunk, total_pages);
        let page_count = u16::try_from(end - start).expect("pages per chunk fits in u16");

        // Collect page data for HMAC.
        let mut page_data_buf = Vec::with_capacity(page_count as usize * PAGE_TOTAL_SIZE);
        for page in &encrypted_pages[start..end] {
            page_data_buf.extend_from_slice(page);
        }

        let hmac = compute_chunk_hmac(hmac_key, &page_data_buf);

        let header = ChunkHeader {
            magic: CHUNK_MAGIC,
            version: 1,
            reserved: 0,
            page_count: page_count.to_le(),
            chunk_id: u64::try_from(chunk_idx)
                .expect("chunk index fits in u64")
                .to_le(),
            chunk_hmac: hmac,
        };

        // Write chunk file.
        let chunk_filename = format!("{chunk_idx:06}.enc");
        let chunk_path = chunks_dir.join(&chunk_filename);
        let mut chunk_data = Vec::with_capacity(CHUNK_HEADER_SIZE + page_data_buf.len());
        chunk_data.extend_from_slice(bytemuck::bytes_of(&header));
        chunk_data.extend_from_slice(&page_data_buf);

        fs::write(&chunk_path, &chunk_data)
            .with_context(|| format!("cannot write chunk file: {}", chunk_path.display()))?;

        log::info!(
            "Wrote chunk {} ({} pages, {} bytes)",
            chunk_idx,
            page_count,
            chunk_data.len()
        );
    }

    Ok(())
}

/// Build and write the manifest file.
fn write_manifest(
    route_table_bytes: &[u8],
    manifest_dek: &[u8; 32],
    bundle_id: &[u8; 16],
    key_commit: &[u8; 32],
    output_dir: &Path,
) -> Result<()> {
    // Compress route table with zstd.
    let compressed_rt =
        zstd::encode_all(route_table_bytes, 3).context("zstd compression of route table failed")?;

    // Encrypt compressed route table as manifest pages (DOMAIN_MANIFEST_ROUTE_TABLE).
    let rt_pages = encrypt_data_as_pages(
        &compressed_rt,
        manifest_dek,
        bundle_id,
        DOMAIN_MANIFEST_ROUTE_TABLE,
    )?;

    // Build manifest header JSON.
    let header_json = serde_json::json!({
        "version": 1,
        "route_table_compressed_size": compressed_rt.len(),
        "route_table_uncompressed_size": route_table_bytes.len(),
    });
    let header_bytes = serde_json::to_vec(&header_json)?;

    // Encrypt header as manifest page(s) (DOMAIN_MANIFEST_HEADER).
    let header_pages = encrypt_data_as_pages(
        &header_bytes,
        manifest_dek,
        bundle_id,
        DOMAIN_MANIFEST_HEADER,
    )?;

    // Build manifest preamble.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let preamble = ManifestPreamble {
        magic: MANIFEST_MAGIC,
        version: 1u32.to_le(),
        header_page_count: u32::try_from(header_pages.len())
            .expect("header page count fits in u32")
            .to_le(),
        route_table_page_count: u32::try_from(rt_pages.len())
            .expect("rt page count fits in u32")
            .to_le(),
        bundle_id: *bundle_id,
        key_commit: *key_commit,
        deployment_ts: now.to_le(),
        reserved: [0u8; 24],
    };

    // Write manifest.enc: preamble (96 bytes cleartext) + header pages + route table pages.
    let manifest_path = output_dir.join("manifest.enc");
    let preamble_bytes = bytemuck::bytes_of(&preamble);
    debug_assert_eq!(preamble_bytes.len(), MANIFEST_PREAMBLE_SIZE);

    let total_size = MANIFEST_PREAMBLE_SIZE
        + header_pages.len() * PAGE_TOTAL_SIZE
        + rt_pages.len() * PAGE_TOTAL_SIZE;
    let mut manifest_data = Vec::with_capacity(total_size);
    manifest_data.extend_from_slice(preamble_bytes);
    for page in &header_pages {
        manifest_data.extend_from_slice(page);
    }
    for page in &rt_pages {
        manifest_data.extend_from_slice(page);
    }

    fs::write(&manifest_path, &manifest_data)
        .with_context(|| format!("cannot write manifest: {}", manifest_path.display()))?;

    log::info!(
        "Wrote manifest ({} bytes, {} header pages, {} rt pages)",
        manifest_data.len(),
        header_pages.len(),
        rt_pages.len()
    );

    Ok(())
}

/// Encrypt arbitrary data as a sequence of pages using the given domain.
fn encrypt_data_as_pages(
    data: &[u8],
    dek: &[u8; 32],
    bundle_id: &[u8; 16],
    domain: u32,
) -> Result<Vec<Vec<u8>>> {
    let mut pages = Vec::new();
    let mut offset = 0;
    let mut counter: u64 = 0;

    while offset < data.len() {
        let end = std::cmp::min(offset + PAGE_BODY_SIZE, data.len());
        let chunk = &data[offset..end];
        let nonce = make_nonce(domain, counter);
        let encrypted = encrypt_page(chunk, dek, &nonce, bundle_id)
            .with_context(|| format!("encrypt manifest page failed at counter {counter}"))?;
        pages.push(encrypted);
        offset = end;
        counter += 1;
    }

    // If data is empty, we still need at least one page.
    if pages.is_empty() {
        let nonce = make_nonce(domain, 0);
        let encrypted = encrypt_page(&[], dek, &nonce, bundle_id)
            .context("encrypt empty manifest page failed")?;
        pages.push(encrypted);
    }

    Ok(pages)
}

/// Simple hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_pack_empty_directory() {
        let input = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();

        let config = PackConfig {
            input_dir: input.path().to_str().unwrap().to_string(),
            output_dir: output.path().to_str().unwrap().to_string(),
            log_level: None,
        };

        let result = run_pack(&config).unwrap();
        assert_eq!(result.master_key_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(result.bundle_id_hex.len(), 32); // 16 bytes = 32 hex chars

        // Check output structure.
        assert!(output.path().join("manifest.enc").exists());
        assert!(output.path().join("chunks").is_dir());
    }

    #[test]
    fn test_pack_small_files() {
        let input = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();

        // Create some small files.
        fs::write(input.path().join("hello.txt"), b"Hello, world!").unwrap();
        fs::write(input.path().join("data.bin"), vec![0xABu8; 1024]).unwrap();
        fs::create_dir(input.path().join("subdir")).unwrap();
        fs::write(input.path().join("subdir/nested.txt"), b"nested content").unwrap();

        let config = PackConfig {
            input_dir: input.path().to_str().unwrap().to_string(),
            output_dir: output.path().to_str().unwrap().to_string(),
            log_level: None,
        };

        let result = run_pack(&config).unwrap();
        assert_eq!(result.master_key_hex.len(), 64);
        assert_eq!(result.bundle_id_hex.len(), 32);

        // Check output structure.
        assert!(output.path().join("manifest.enc").exists());
        assert!(output.path().join("chunks").is_dir());

        // There should be at least one chunk file.
        let chunk_files: Vec<_> = fs::read_dir(output.path().join("chunks"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(!chunk_files.is_empty());

        // First chunk should be named 000000.enc.
        assert!(output.path().join("chunks/000000.enc").exists());

        // Verify chunk file structure: header (48 bytes) + N * PAGE_TOTAL_SIZE.
        let chunk_data = fs::read(output.path().join("chunks/000000.enc")).unwrap();
        assert!(chunk_data.len() >= CHUNK_HEADER_SIZE);
        let payload_size = chunk_data.len() - CHUNK_HEADER_SIZE;
        assert_eq!(payload_size % PAGE_TOTAL_SIZE, 0);

        // Verify chunk magic.
        assert_eq!(&chunk_data[0..4], &CHUNK_MAGIC);

        // Verify manifest structure: preamble (96) + pages.
        let manifest_data = fs::read(output.path().join("manifest.enc")).unwrap();
        assert!(manifest_data.len() >= MANIFEST_PREAMBLE_SIZE);
        assert_eq!(&manifest_data[0..4], &MANIFEST_MAGIC);
        let after_preamble = manifest_data.len() - MANIFEST_PREAMBLE_SIZE;
        assert_eq!(after_preamble % PAGE_TOTAL_SIZE, 0);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }
}
