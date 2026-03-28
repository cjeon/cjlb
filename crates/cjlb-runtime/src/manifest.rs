// manifest.rs — Manifest loading: preamble, header JSON, route table.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use anyhow::{bail, Context, Result};

use cjlb_crypto::decrypt_page;
use cjlb_format::manifest::{ManifestPreamble, MANIFEST_MAGIC, MANIFEST_PREAMBLE_SIZE};
use cjlb_format::page::{PAGE_BODY_SIZE, PAGE_TOTAL_SIZE};
use cjlb_format::route_table::{
    DirEntry, FileRecord, PageSpan, RouteTableHeader, ROUTE_TABLE_MAGIC,
};

// ---------------------------------------------------------------------------
// Safe casting helpers for repr(C) + Pod types
// ---------------------------------------------------------------------------

fn cast_from_bytes<T: Copy>(bytes: &[u8]) -> Result<&T> {
    let size = std::mem::size_of::<T>();
    anyhow::ensure!(
        bytes.len() >= size,
        "cast_from_bytes: need {} bytes, got {}",
        size,
        bytes.len()
    );
    let ptr = bytes.as_ptr();
    anyhow::ensure!(
        ptr.align_offset(std::mem::align_of::<T>()) == 0,
        "cast_from_bytes: misaligned pointer"
    );
    Ok(unsafe { &*ptr.cast::<T>() })
}

fn cast_slice<T: Copy>(bytes: &[u8], count: usize) -> Result<&[T]> {
    let item_size = std::mem::size_of::<T>();
    let needed = item_size * count;
    anyhow::ensure!(
        bytes.len() >= needed,
        "cast_slice: need {} bytes for {} items, got {}",
        needed,
        count,
        bytes.len()
    );
    let ptr = bytes.as_ptr();
    anyhow::ensure!(
        ptr.align_offset(std::mem::align_of::<T>()) == 0,
        "cast_slice: misaligned pointer"
    );
    Ok(unsafe { std::slice::from_raw_parts(ptr.cast::<T>(), count) })
}

// ---------------------------------------------------------------------------
// Preamble
// ---------------------------------------------------------------------------

/// Read and validate the manifest preamble (cleartext 96 bytes).
/// Returns the preamble and the full manifest bytes.
pub fn read_preamble(bundle_dir: &Path) -> Result<(ManifestPreamble, Vec<u8>)> {
    let manifest_path = bundle_dir.join("manifest.enc");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;

    if manifest_bytes.len() < MANIFEST_PREAMBLE_SIZE {
        bail!("manifest.enc too short for preamble");
    }

    let preamble: ManifestPreamble = *cast_from_bytes(&manifest_bytes[..MANIFEST_PREAMBLE_SIZE])?;

    if preamble.magic != MANIFEST_MAGIC {
        bail!(
            "invalid manifest magic: expected {:?}, got {:?}",
            MANIFEST_MAGIC,
            preamble.magic
        );
    }

    Ok((preamble, manifest_bytes))
}

// ---------------------------------------------------------------------------
// Header JSON
// ---------------------------------------------------------------------------

/// Decrypt the manifest header pages and parse as JSON.
pub fn decrypt_header(
    manifest_bytes: &[u8],
    header_page_count: usize,
    manifest_dek: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<serde_json::Value> {
    let mut header_data = Vec::with_capacity(header_page_count * PAGE_BODY_SIZE);
    for i in 0..header_page_count {
        let offset = MANIFEST_PREAMBLE_SIZE + i * PAGE_TOTAL_SIZE;
        let end = offset + PAGE_TOTAL_SIZE;
        if end > manifest_bytes.len() {
            bail!(
                "manifest.enc too short for header page {}: need {} bytes, got {}",
                i,
                end,
                manifest_bytes.len()
            );
        }
        let page_bytes = &manifest_bytes[offset..end];
        let decrypted = decrypt_page(page_bytes, manifest_dek, bundle_id)
            .context("failed to decrypt manifest header page")?;
        header_data.extend_from_slice(&decrypted);
    }

    // Trim trailing zero-padding and parse JSON
    let end = header_data
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |p| p + 1);

    if end == 0 {
        bail!("manifest header is empty");
    }

    let header: serde_json::Value = serde_json::from_slice(&header_data[..end])
        .context("failed to parse manifest header JSON")?;

    Ok(header)
}

// ---------------------------------------------------------------------------
// Route table
// ---------------------------------------------------------------------------

/// Holds the decompressed, aligned route table and its parsed header.
pub struct RouteTable {
    /// Aligned buffer (u64 vec for 8-byte alignment)
    rt_data: Vec<u64>,
    /// Actual byte length of the route table data (before u64 padding).
    rt_len: usize,
    pub header: RouteTableHeader,
}

impl RouteTable {
    /// Decrypt the route table pages, decompress with zstd, and parse header.
    ///
    /// `route_table_compressed_size` is the exact number of compressed bytes
    /// (from the manifest header JSON). Decrypted pages are quantized to 4 KB,
    /// so trailing zeros must be truncated before zstd decompression.
    pub fn load(
        manifest_bytes: &[u8],
        header_page_count: usize,
        rt_page_count: usize,
        manifest_dek: &[u8; 32],
        bundle_id: &[u8; 16],
        route_table_compressed_size: Option<u64>,
    ) -> Result<Self> {
        let mut rt_encrypted = Vec::with_capacity(rt_page_count * PAGE_BODY_SIZE);
        for i in 0..rt_page_count {
            let offset = MANIFEST_PREAMBLE_SIZE + (header_page_count + i) * PAGE_TOTAL_SIZE;
            let end = offset + PAGE_TOTAL_SIZE;
            if end > manifest_bytes.len() {
                bail!(
                    "manifest.enc too short for route table page {}: need {} bytes, got {}",
                    i,
                    end,
                    manifest_bytes.len()
                );
            }
            let page_bytes = &manifest_bytes[offset..end];
            let decrypted = decrypt_page(page_bytes, manifest_dek, bundle_id)
                .context("failed to decrypt route table page")?;
            rt_encrypted.extend_from_slice(&decrypted);
        }

        // Truncate to actual compressed size before decompression.
        // Decrypted pages are quantized/padded with trailing zeros that zstd
        // would misinterpret as a second frame.
        if let Some(cs) = route_table_compressed_size {
            let cs = usize::try_from(cs).context("compressed size exceeds usize")?;
            if cs < rt_encrypted.len() {
                rt_encrypted.truncate(cs);
            }
        }

        // Decompress with zstd
        let rt_raw = zstd::decode_all(Cursor::new(&rt_encrypted))
            .context("failed to decompress route table")?;

        if rt_raw.len() < std::mem::size_of::<RouteTableHeader>() {
            bail!("route table too short for header");
        }

        // Copy into aligned buffer
        let rt_len = rt_raw.len();
        let aligned_len = rt_len.div_ceil(8);
        let mut rt_aligned: Vec<u64> = vec![0u64; aligned_len];
        let rt_bytes =
            unsafe { std::slice::from_raw_parts_mut(rt_aligned.as_mut_ptr().cast::<u8>(), rt_len) };
        rt_bytes.copy_from_slice(&rt_raw);

        let header: RouteTableHeader = *cast_from_bytes(rt_bytes)?;
        if header.magic != ROUTE_TABLE_MAGIC {
            bail!(
                "invalid route table magic: expected {:?}, got {:?}",
                ROUTE_TABLE_MAGIC,
                header.magic
            );
        }

        Ok(Self {
            rt_data: rt_aligned,
            rt_len,
            header,
        })
    }

    // -- Byte slice accessor --

    const fn rt_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.rt_data.as_ptr().cast::<u8>(), self.rt_len) }
    }

    // -- Section offsets --

    const fn dirs_offset() -> usize {
        std::mem::size_of::<RouteTableHeader>()
    }

    const fn files_offset(&self) -> usize {
        Self::dirs_offset() + self.header.dir_count as usize * std::mem::size_of::<DirEntry>()
    }

    const fn spans_offset(&self) -> usize {
        self.files_offset() + self.header.file_count as usize * std::mem::size_of::<FileRecord>()
    }

    const fn dir_name_table_offset(&self) -> usize {
        self.spans_offset() + self.header.span_count as usize * std::mem::size_of::<PageSpan>()
    }

    const fn filename_table_offset(&self) -> usize {
        self.dir_name_table_offset() + self.header.dir_name_table_len as usize
    }

    // -- Public accessors --

    pub fn dirs(&self) -> Result<&[DirEntry]> {
        let bytes = self.rt_bytes();
        let off = Self::dirs_offset();
        anyhow::ensure!(off <= bytes.len(), "dirs offset out of bounds");
        cast_slice(&bytes[off..], self.header.dir_count as usize)
    }

    pub fn files(&self) -> Result<&[FileRecord]> {
        let bytes = self.rt_bytes();
        let off = self.files_offset();
        anyhow::ensure!(off <= bytes.len(), "files offset out of bounds");
        cast_slice(&bytes[off..], self.header.file_count as usize)
    }

    pub fn spans(&self) -> Result<&[PageSpan]> {
        let bytes = self.rt_bytes();
        let off = self.spans_offset();
        anyhow::ensure!(off <= bytes.len(), "spans offset out of bounds");
        cast_slice(&bytes[off..], self.header.span_count as usize)
    }

    fn dir_name_table(&self) -> Result<&[u8]> {
        let bytes = self.rt_bytes();
        let off = self.dir_name_table_offset();
        let len = self.header.dir_name_table_len as usize;
        anyhow::ensure!(
            off.checked_add(len).is_some_and(|end| end <= bytes.len()),
            "dir name table out of bounds"
        );
        Ok(&bytes[off..off + len])
    }

    fn filename_table(&self) -> Result<&[u8]> {
        let bytes = self.rt_bytes();
        let off = self.filename_table_offset();
        let len = self.header.filename_table_len as usize;
        anyhow::ensure!(
            off.checked_add(len).is_some_and(|end| end <= bytes.len()),
            "filename table out of bounds"
        );
        Ok(&bytes[off..off + len])
    }

    /// Get the name of a directory entry.
    pub fn dir_name(&self, dir: &DirEntry) -> Result<&str> {
        let table = self.dir_name_table()?;
        let start = dir.name_offset as usize;
        let end = start + dir.name_len as usize;
        anyhow::ensure!(end <= table.len(), "dir name range out of bounds");
        Ok(std::str::from_utf8(&table[start..end]).unwrap_or("<invalid utf8>"))
    }

    /// Get the filename of a file record, using the parent dir's `filename_block_offset`.
    pub fn file_name(&self, file: &FileRecord, parent: &DirEntry) -> Result<&str> {
        let table = self.filename_table()?;
        let base = parent.filename_block_offset as usize;
        let start = base + file.filename_offset as usize;
        let end = start + file.filename_len as usize;
        anyhow::ensure!(end <= table.len(), "filename range out of bounds");
        Ok(std::str::from_utf8(&table[start..end]).unwrap_or("<invalid utf8>"))
    }

    /// Get child directories and files for a given directory.
    pub fn dir_children(&self, dir: &DirEntry) -> Result<(&[DirEntry], &[FileRecord])> {
        let dirs = self.dirs()?;
        let files = self.files()?;

        let child_dirs = if dir.child_dir_count > 0 {
            let start = dir.first_child_dir as usize;
            let end = start + dir.child_dir_count as usize;
            anyhow::ensure!(end <= dirs.len(), "child dir range out of bounds");
            &dirs[start..end]
        } else {
            &[]
        };

        let child_files = if dir.file_count > 0 {
            let start = dir.file_block_offset as usize;
            let end = start + dir.file_count as usize;
            anyhow::ensure!(end <= files.len(), "child file range out of bounds");
            &files[start..end]
        } else {
            &[]
        };

        Ok((child_dirs, child_files))
    }

    /// Resolve a path (e.g. "configs.json" or "config/configs.json") to a `FileRecord`.
    /// Returns (`dir_index`, `file_index`) if found.
    pub fn resolve_file(&self, path: &str) -> Result<(usize, usize)> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            bail!("empty path");
        }

        let components: Vec<&str> = path.split('/').collect();
        let mut current_dir_idx: usize = 0;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let all_dirs = self.dirs()?;
            anyhow::ensure!(
                current_dir_idx < all_dirs.len(),
                "directory index out of bounds"
            );
            let dir = &all_dirs[current_dir_idx];
            let (child_dirs, child_files) = self.dir_children(dir)?;

            if is_last {
                // Last component: must be a file
                for (j, child_file) in child_files.iter().enumerate() {
                    if self.file_name(child_file, dir)? == *component {
                        let file_idx = dir.file_block_offset as usize + j;
                        return Ok((current_dir_idx, file_idx));
                    }
                }
                bail!("file '{component}' not found in path '{path}'");
            }
            // Must be a directory
            let mut found = false;
            for (j, child_dir) in child_dirs.iter().enumerate() {
                if self.dir_name(child_dir)? == *component {
                    current_dir_idx = dir.first_child_dir as usize + j;
                    found = true;
                    break;
                }
            }
            if !found {
                bail!("directory '{component}' not found in path '{path}'");
            }
        }

        bail!("path '{path}' does not resolve to a file");
    }
}
