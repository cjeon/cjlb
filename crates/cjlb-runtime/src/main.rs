// cjlb-runtime — Layer 1 encrypted runtime.
//
// Exec'd from memory by bootstrap via fexecve. Receives master key + bundle_id
// on FD 200, decrypts the manifest & route table, loads configs.json from the
// encrypted payload, prepares the shim config blob, and exec's the client
// entrypoint.

mod config_blob;
mod exec;
mod manifest;

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use cjlb_crypto::{decrypt_page, MasterKey};
use cjlb_format::chunk::page_location;
use cjlb_format::config::ClientConfig;
use cjlb_format::page::PAGE_TOTAL_SIZE;
use cjlb_format::route_table::PAGE_ID_SENTINEL;

/// The well-known FD that bootstrap writes key material to.
const KEY_FD: RawFd = 200;

/// Size of key material on FD 200: `master_key`(32) + `bundle_id`(16).
const KEY_MATERIAL_SIZE: usize = 48;

fn main() {
    if let Err(e) = run() {
        eprintln!("cjlb-runtime: fatal: {e:#}");
        std::process::exit(1);
    }
    // If run() succeeded, execve replaced this process.
    // If we reach here, something went wrong.
    eprintln!("cjlb-runtime: fatal: exec returned unexpectedly");
    std::process::exit(1);
}

fn run() -> Result<()> {
    // ── 0. Disable core dumps before touching any secrets ───────────
    exec::set_non_dumpable();

    // ── 1. Read 48 bytes from FD 200: key(32) + bundle_id(16) ───────
    let mut key_material = [0u8; KEY_MATERIAL_SIZE];
    {
        let mut fd_file = unsafe { fs::File::from_raw_fd(KEY_FD) };
        let read_result = fd_file
            .read_exact(&mut key_material)
            .context("failed to read key material from FD 200");
        // fd_file is dropped here, closing FD 200
        if let Err(e) = read_result {
            key_material.zeroize();
            return Err(e);
        }
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&key_material[..32]);
    let mut bundle_id = [0u8; 16];
    bundle_id.copy_from_slice(&key_material[32..48]);
    key_material.zeroize();

    let result = run_inner(&key_bytes, &bundle_id);

    // Zeroize on any exit path (on success, execve replaced us, so this
    // only runs on failure)
    key_bytes.zeroize();
    bundle_id.zeroize();

    result
}

#[allow(clippy::too_many_lines)]
fn run_inner(key_bytes: &[u8; 32], bundle_id: &[u8; 16]) -> Result<()> {
    // ── 2. Derive all keys via HKDF ─────────────────────────────────
    let master = MasterKey::from_bytes(*key_bytes);
    let dk = master.derive_keys();

    // ── 3. Open manifest.enc, read preamble ─────────────────────────
    let bundle_dir = exec::resolve_bundle_dir().context("failed to resolve bundle directory")?;

    let (preamble, manifest_bytes) =
        manifest::read_preamble(&bundle_dir).context("failed to read manifest preamble")?;

    // ── 4. Verify magic (already done in read_preamble) + key_commit ─
    let expected_commit = master.key_commit();
    if preamble.key_commit != expected_commit {
        bail!("key commitment mismatch — wrong master key for this bundle");
    }

    // ── 5. Verify bundle_id matches manifest ────────────────────────
    if *bundle_id != preamble.bundle_id {
        bail!("bundle_id mismatch: received key does not match manifest");
    }

    let header_page_count = u32::from_le(preamble.header_page_count) as usize;
    let rt_page_count = u32::from_le(preamble.route_table_page_count) as usize;

    // ── 6. Decrypt manifest header pages ────────────────────────────
    let manifest_header = manifest::decrypt_header(
        &manifest_bytes,
        header_page_count,
        &dk.manifest_dek,
        bundle_id,
    )
    .context("failed to decrypt manifest header")?;

    log::debug!("manifest header: {manifest_header}");

    // ── 7. Parse manifest header JSON → get configs_json_path ───────
    let configs_path = manifest_header
        .get("configs_json_path")
        .and_then(|v| v.as_str())
        .unwrap_or("configs.json");

    log::info!("configs_json_path: {configs_path}");

    // ── 8. Decrypt route table pages ────────────────────────────────
    let rt_compressed_size = manifest_header
        .get("route_table_compressed_size")
        .and_then(serde_json::Value::as_u64);

    let route_table = manifest::RouteTable::load(
        &manifest_bytes,
        header_page_count,
        rt_page_count,
        &dk.manifest_dek,
        bundle_id,
        rt_compressed_size,
    )
    .context("failed to load route table")?;

    log::info!(
        "route table: {} dirs, {} files, {} spans",
        route_table.header.dir_count,
        route_table.header.file_count,
        route_table.header.span_count
    );

    // We no longer need the raw manifest bytes
    drop(manifest_bytes);

    // ── 9. Find and read configs.json from the encrypted payload ────
    let (_dir_idx, file_idx) = route_table
        .resolve_file(configs_path)
        .with_context(|| format!("failed to find '{configs_path}' in route table"))?;

    let files = route_table
        .files()
        .context("failed to access file records")?;
    let file_record = &files[file_idx];
    let config_bytes = read_file_from_payload(
        &bundle_dir,
        file_record,
        &route_table,
        &dk.bundle_dek,
        bundle_id,
    )
    .with_context(|| format!("failed to read '{configs_path}' from payload"))?;

    // ── 10. Parse as ClientConfig, validate ─────────────────────────
    let mut config: ClientConfig =
        serde_json::from_slice(&config_bytes).context("failed to parse configs.json")?;

    config.validate().context("config validation failed")?;

    log::info!(
        "config: entrypoint={}, virtual_root={}, memory_budget={:?}, log_level={}",
        config.entrypoint,
        config.virtual_root,
        config.memory_budget_mb,
        config.log_level
    );

    // ── 11. Prepare shim config blob ────────────────────────────────
    let write_dir = exec::write_layer_dir(&bundle_dir);

    // Ensure write layer directory exists
    if let Err(e) = fs::create_dir_all(&write_dir) {
        log::warn!("failed to create write layer directory: {e}");
    }

    let config_blob = config_blob::serialize_config_blob(
        &config.virtual_root,
        &bundle_dir,
        &write_dir,
        bundle_id,
        key_bytes,
        config.memory_budget_mb.unwrap_or(0),
        &config.log_level,
        config.memory_pressure_monitor,
        config.ipc_socket,
    )
    .context("failed to serialize config blob")?;

    // ── 12-13. LD_PRELOAD — look for libcjlb_shim.so in bundle dir ──
    let shim_path = bundle_dir.join("libcjlb_shim.so");
    let ld_preload_path: Option<String> = if shim_path.exists() {
        let p = shim_path.to_string_lossy().into_owned();
        log::info!("shim found: {p}");
        Some(p)
    } else {
        log::warn!(
            "libcjlb_shim.so not found in bundle dir ({}), proceeding without LD_PRELOAD",
            bundle_dir.display()
        );
        None
    };

    // ── 14-15. Parse entrypoint and exec ────────────────────────────
    // Zeroize key material right before exec
    // (key_bytes is zeroized by the caller after we return on error;
    //  on success, execve replaces the process image)

    exec::exec_entrypoint(
        &config.entrypoint,
        &config_blob,
        &config.env,
        ld_preload_path.as_deref(),
    )
    .context("failed to exec entrypoint")?;

    // exec_entrypoint only returns on error
    unreachable!("exec_entrypoint returned Ok without exec succeeding");
}

// ---------------------------------------------------------------------------
// Read a file from the encrypted payload via chunk files
// ---------------------------------------------------------------------------

fn read_file_from_payload(
    bundle_dir: &Path,
    file_record: &cjlb_format::route_table::FileRecord,
    route_table: &manifest::RouteTable,
    bundle_dek: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<Vec<u8>> {
    let file_size = usize::try_from(file_record.file_size()).context("file size exceeds usize")?;

    if file_record.page_id == PAGE_ID_SENTINEL {
        // Large file: spans multiple pages
        let span_count = file_record.span_count as usize;
        let all_spans = route_table.spans().context("failed to access page spans")?;
        let span_offset = file_record.offset_in_page as usize;
        if span_offset + span_count > all_spans.len() {
            bail!("page span range out of bounds");
        }
        let spans = &all_spans[span_offset..span_offset + span_count];

        let mut result = Vec::with_capacity(file_size);
        for span in spans {
            let page_data = read_page_from_chunk(bundle_dir, span.page_id, bundle_dek, bundle_id)?;
            let take = span.size_in_page as usize;
            if take > page_data.len() {
                bail!(
                    "span size {} exceeds page data length {}",
                    take,
                    page_data.len()
                );
            }
            result.extend_from_slice(&page_data[..take]);
        }

        if result.len() < file_size {
            bail!(
                "reassembled file is shorter than expected: {} < {}",
                result.len(),
                file_size
            );
        }

        result.truncate(file_size);
        Ok(result)
    } else {
        // Small file: single page
        let page_data =
            read_page_from_chunk(bundle_dir, file_record.page_id, bundle_dek, bundle_id)?;
        let start = file_record.offset_in_page as usize;
        let end = start + file_size;
        if end > page_data.len() {
            bail!(
                "file data exceeds page boundary: offset {} + size {} > page len {}",
                start,
                file_size,
                page_data.len()
            );
        }
        Ok(page_data[start..end].to_vec())
    }
}

/// Read and decrypt a single page by global page ID from a chunk file.
fn read_page_from_chunk(
    bundle_dir: &Path,
    page_id: u32,
    bundle_dek: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<Vec<u8>> {
    let (chunk_id, offset) = page_location(page_id);
    let chunk_path = bundle_dir.join(format!("chunks/{chunk_id:06}.enc"));

    let mut file = fs::File::open(&chunk_path)
        .with_context(|| format!("failed to open chunk {}", chunk_path.display()))?;

    file.seek(SeekFrom::Start(offset))
        .context("failed to seek in chunk file")?;

    let mut buf = vec![0u8; PAGE_TOTAL_SIZE];
    file.read_exact(&mut buf)
        .context("failed to read page from chunk")?;

    let decrypted = decrypt_page(&buf, bundle_dek, bundle_id).context("failed to decrypt page")?;

    Ok(decrypted)
}
