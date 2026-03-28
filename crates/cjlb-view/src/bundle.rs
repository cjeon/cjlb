use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use cjlb_crypto::{decrypt_page, DerivedKeys, MasterKey};
use cjlb_format::chunk::page_location;
use cjlb_format::manifest::{ManifestPreamble, MANIFEST_MAGIC, MANIFEST_PREAMBLE_SIZE};
// Nonce domain constants are used during encryption; on decrypt, the nonce is
// embedded in the page header, so we don't need them here.
use cjlb_format::page::{PAGE_BODY_SIZE, PAGE_TOTAL_SIZE};
use cjlb_format::route_table::{
    DirEntry, FileRecord, PageSpan, RouteTableHeader, PAGE_ID_SENTINEL, ROUTE_TABLE_MAGIC,
};

// ---------------------------------------------------------------------------
// Safe casting helpers for repr(C) + Pod types
// ---------------------------------------------------------------------------

/// Cast a byte slice to a reference of a repr(C) type.
/// Panics if size or alignment is wrong.
fn cast_from_bytes<T: Copy>(bytes: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    assert!(
        bytes.len() >= size,
        "cast_from_bytes: need {} bytes, got {}",
        size,
        bytes.len()
    );
    let ptr = bytes.as_ptr();
    assert!(
        ptr.align_offset(std::mem::align_of::<T>()) == 0,
        "cast_from_bytes: misaligned pointer"
    );
    unsafe { &*ptr.cast::<T>() }
}

/// Cast a byte slice to a slice of repr(C) items.
fn cast_slice<T: Copy>(bytes: &[u8], count: usize) -> &[T] {
    let item_size = std::mem::size_of::<T>();
    let needed = item_size * count;
    assert!(
        bytes.len() >= needed,
        "cast_slice: need {} bytes for {} items, got {}",
        needed,
        count,
        bytes.len()
    );
    let ptr = bytes.as_ptr();
    assert!(
        ptr.align_offset(std::mem::align_of::<T>()) == 0,
        "cast_slice: misaligned pointer"
    );
    unsafe { std::slice::from_raw_parts(ptr.cast::<T>(), count) }
}

// ---------------------------------------------------------------------------
// ResolvedPath
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ResolvedPath {
    Dir(usize),
    File { dir_idx: usize, file_idx: usize },
}

// ---------------------------------------------------------------------------
// BundleReader
// ---------------------------------------------------------------------------

pub struct BundleReader {
    bundle_dir: PathBuf,
    bundle_id: [u8; 16],
    derived_keys: DerivedKeys,
    // Route table: aligned buffer + parsed header
    rt_data: Vec<u64>,  // stored as u64 vec for guaranteed 8-byte alignment
    rt_byte_len: usize, // actual byte length of the route table data
    rt_header: RouteTableHeader,
    // Manifest metadata
    pub manifest_header: serde_json::Value,
    pub preamble_version: u32,
    pub deployment_ts: u64,
}

impl std::fmt::Debug for BundleReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleReader")
            .field("bundle_dir", &self.bundle_dir)
            .field("preamble_version", &self.preamble_version)
            .field("deployment_ts", &self.deployment_ts)
            .finish_non_exhaustive()
    }
}

impl BundleReader {
    /// Open a bundle directory and parse its manifest + route table.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest file cannot be read or decrypted, the
    /// key commitment check fails, or the route table is malformed.
    #[allow(clippy::too_many_lines)]
    pub fn open(bundle_dir: &Path, master_key: &MasterKey) -> Result<Self> {
        let manifest_path = bundle_dir.join("manifest.enc");
        let manifest_bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;

        if manifest_bytes.len() < MANIFEST_PREAMBLE_SIZE {
            bail!("manifest.enc too short for preamble");
        }

        // 1. Parse preamble (cleartext)
        let preamble: &ManifestPreamble =
            cast_from_bytes(&manifest_bytes[..MANIFEST_PREAMBLE_SIZE]);

        if preamble.magic != MANIFEST_MAGIC {
            bail!(
                "invalid manifest magic: expected {:?}, got {:?}",
                MANIFEST_MAGIC,
                preamble.magic
            );
        }

        // 2. Verify key commitment
        let expected_commit = master_key.key_commit();
        if preamble.key_commit != expected_commit {
            bail!("key commitment mismatch — wrong master key for this bundle");
        }

        let bundle_id = preamble.bundle_id;
        let derived_keys = master_key.derive_keys();

        let header_page_count = u32::from_le(preamble.header_page_count) as usize;
        let rt_page_count = u32::from_le(preamble.route_table_page_count) as usize;
        let version = u32::from_le(preamble.version);
        let deployment_ts = u64::from_le(preamble.deployment_ts);

        let total_pages = header_page_count
            .checked_add(rt_page_count)
            .context("page count overflow: header_page_count + rt_page_count")?;
        let pages_byte_len = total_pages
            .checked_mul(PAGE_TOTAL_SIZE)
            .context("page size overflow: total_pages * PAGE_TOTAL_SIZE")?;
        let expected_len = MANIFEST_PREAMBLE_SIZE + pages_byte_len;
        if manifest_bytes.len() < expected_len {
            bail!(
                "manifest.enc too short: expected at least {} bytes, got {}",
                expected_len,
                manifest_bytes.len()
            );
        }

        // 3. Decrypt header pages
        let mut header_data = Vec::with_capacity(header_page_count * PAGE_BODY_SIZE);
        for i in 0..header_page_count {
            let offset = MANIFEST_PREAMBLE_SIZE + i * PAGE_TOTAL_SIZE;
            let page_bytes = &manifest_bytes[offset..offset + PAGE_TOTAL_SIZE];
            let decrypted = decrypt_page(page_bytes, &derived_keys.manifest_dek, &bundle_id)
                .context("failed to decrypt manifest header page")?;
            header_data.extend_from_slice(&decrypted);
        }

        // Parse header JSON
        let manifest_header: serde_json::Value = if header_data.is_empty() {
            serde_json::Value::Null
        } else {
            // Find the end of JSON data (trim trailing zeros)
            let end = header_data
                .iter()
                .rposition(|&b| b != 0)
                .map_or(0, |p| p + 1);
            if end > 0 {
                serde_json::from_slice(&header_data[..end])
                    .context("failed to parse manifest header JSON")?
            } else {
                serde_json::Value::Null
            }
        };

        // 4. Decrypt route table pages
        let mut rt_decrypted = Vec::with_capacity(rt_page_count * PAGE_BODY_SIZE);
        for i in 0..rt_page_count {
            let offset = MANIFEST_PREAMBLE_SIZE + (header_page_count + i) * PAGE_TOTAL_SIZE;
            let page_bytes = &manifest_bytes[offset..offset + PAGE_TOTAL_SIZE];
            let decrypted = decrypt_page(page_bytes, &derived_keys.manifest_dek, &bundle_id)
                .context("failed to decrypt route table page")?;
            rt_decrypted.extend_from_slice(&decrypted);
        }

        // Truncate to the actual compressed size (pages are quantized/padded,
        // and zstd::decode_all reads the entire stream — trailing zeros would be
        // misinterpreted as a second frame).
        if let Some(compressed_size) = manifest_header
            .get("route_table_compressed_size")
            .and_then(serde_json::Value::as_u64)
        {
            let truncate_len =
                usize::try_from(compressed_size).context("compressed size exceeds usize")?;
            rt_decrypted.truncate(truncate_len);
        }

        // 5. Decompress route table with zstd
        let rt_raw = zstd::decode_all(std::io::Cursor::new(&rt_decrypted))
            .context("failed to decompress route table")?;

        // 6. Parse RouteTableHeader
        if rt_raw.len() < std::mem::size_of::<RouteTableHeader>() {
            bail!("route table too short for header");
        }

        // Copy into an aligned buffer (u64 vec ensures 8-byte alignment)
        let rt_byte_len = rt_raw.len();
        let aligned_len = rt_byte_len.div_ceil(8);
        let mut rt_aligned: Vec<u64> = vec![0u64; aligned_len];
        let rt_buf = unsafe {
            std::slice::from_raw_parts_mut(rt_aligned.as_mut_ptr().cast::<u8>(), rt_byte_len)
        };
        rt_buf.copy_from_slice(&rt_raw);

        let rt_header: RouteTableHeader = *cast_from_bytes(rt_buf);

        if rt_header.magic != ROUTE_TABLE_MAGIC {
            bail!(
                "invalid route table magic: expected {:?}, got {:?}",
                ROUTE_TABLE_MAGIC,
                rt_header.magic
            );
        }

        Ok(Self {
            bundle_dir: bundle_dir.to_path_buf(),
            bundle_id,
            derived_keys,
            rt_data: rt_aligned,
            rt_byte_len,
            rt_header,
            manifest_header,
            preamble_version: version,
            deployment_ts,
        })
    }

    // -- Route table byte slice accessor --

    const fn rt_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.rt_data.as_ptr().cast::<u8>(), self.rt_byte_len) }
    }

    // -- Route table slices --

    const fn dirs_offset() -> usize {
        std::mem::size_of::<RouteTableHeader>()
    }

    const fn files_offset(&self) -> usize {
        Self::dirs_offset() + self.rt_header.dir_count as usize * std::mem::size_of::<DirEntry>()
    }

    const fn spans_offset(&self) -> usize {
        self.files_offset() + self.rt_header.file_count as usize * std::mem::size_of::<FileRecord>()
    }

    const fn dir_name_table_offset(&self) -> usize {
        self.spans_offset() + self.rt_header.span_count as usize * std::mem::size_of::<PageSpan>()
    }

    const fn filename_table_offset(&self) -> usize {
        self.dir_name_table_offset() + self.rt_header.dir_name_table_len as usize
    }

    #[must_use]
    pub fn dirs(&self) -> &[DirEntry] {
        let bytes = self.rt_bytes();
        let off = Self::dirs_offset();
        cast_slice(&bytes[off..], self.rt_header.dir_count as usize)
    }

    #[must_use]
    pub fn files(&self) -> &[FileRecord] {
        let bytes = self.rt_bytes();
        let off = self.files_offset();
        cast_slice(&bytes[off..], self.rt_header.file_count as usize)
    }

    #[must_use]
    pub fn spans(&self) -> &[PageSpan] {
        let bytes = self.rt_bytes();
        let off = self.spans_offset();
        cast_slice(&bytes[off..], self.rt_header.span_count as usize)
    }

    fn dir_name_table(&self) -> &[u8] {
        let bytes = self.rt_bytes();
        let off = self.dir_name_table_offset();
        &bytes[off..off + self.rt_header.dir_name_table_len as usize]
    }

    fn filename_table(&self) -> &[u8] {
        let bytes = self.rt_bytes();
        let off = self.filename_table_offset();
        &bytes[off..off + self.rt_header.filename_table_len as usize]
    }

    // -- Public accessors --

    #[must_use]
    #[allow(dead_code)]
    pub fn root_dir(&self) -> &DirEntry {
        &self.dirs()[0]
    }

    #[must_use]
    pub fn dir_entry(&self, idx: usize) -> &DirEntry {
        &self.dirs()[idx]
    }

    #[must_use]
    pub const fn dir_count(&self) -> u32 {
        self.rt_header.dir_count
    }

    #[must_use]
    pub const fn file_count(&self) -> u32 {
        self.rt_header.file_count
    }

    /// Get child directories and files for a given directory.
    #[must_use]
    pub fn dir_children(&self, dir: &DirEntry) -> (&[DirEntry], &[FileRecord]) {
        let dirs = self.dirs();
        let files = self.files();

        let child_dirs = if dir.child_dir_count > 0 {
            let start = dir.first_child_dir as usize;
            let end = start + dir.child_dir_count as usize;
            &dirs[start..end]
        } else {
            &[]
        };

        let child_files = if dir.file_count > 0 {
            let start = dir.file_block_offset as usize;
            let end = start + dir.file_count as usize;
            &files[start..end]
        } else {
            &[]
        };

        (child_dirs, child_files)
    }

    /// Get the name of a directory entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored name is not valid UTF-8.
    pub fn dir_name(&self, dir: &DirEntry) -> Result<&str> {
        let table = self.dir_name_table();
        let start = dir.name_offset as usize;
        let end = start + dir.name_len as usize;
        std::str::from_utf8(&table[start..end]).context("directory name is not valid UTF-8")
    }

    /// Get the filename of a file record, using the parent dir's `filename_block_offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored filename is not valid UTF-8.
    pub fn file_name(&self, file: &FileRecord, parent: &DirEntry) -> Result<&str> {
        let table = self.filename_table();
        let base = parent.filename_block_offset as usize;
        let start = base + file.filename_offset as usize;
        let end = start + file.filename_len as usize;
        std::str::from_utf8(&table[start..end]).context("filename is not valid UTF-8")
    }

    /// Read and decrypt a single page by its global page ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk file cannot be opened/read or decryption fails.
    pub fn read_page(&self, page_id: u32) -> Result<Vec<u8>> {
        let (chunk_id, offset) = page_location(page_id);
        let chunk_path = self.bundle_dir.join(format!("chunks/{chunk_id:06}.enc"));

        let mut file = fs::File::open(&chunk_path)
            .with_context(|| format!("failed to open chunk {}", chunk_path.display()))?;

        file.seek(SeekFrom::Start(offset))
            .context("failed to seek in chunk file")?;

        let mut buf = vec![0u8; PAGE_TOTAL_SIZE];
        file.read_exact(&mut buf)
            .context("failed to read page from chunk")?;

        let decrypted = decrypt_page(&buf, &self.derived_keys.bundle_dek, &self.bundle_id)
            .context("failed to decrypt page")?;

        Ok(decrypted)
    }

    /// Read and reassemble a complete file from its `FileRecord`.
    ///
    /// # Errors
    ///
    /// Returns an error if page spans are out of bounds, decryption fails, or
    /// the reassembled data is shorter than expected.
    pub fn read_file(&self, file_record: &FileRecord) -> Result<Vec<u8>> {
        let file_size =
            usize::try_from(file_record.file_size()).context("file size exceeds usize")?;

        if file_record.page_id == PAGE_ID_SENTINEL {
            // Large file: spans multiple pages
            let span_count = file_record.span_count as usize;
            let all_spans = self.spans();
            let span_offset = file_record.offset_in_page as usize;
            if span_offset + span_count > all_spans.len() {
                bail!("page span range out of bounds");
            }
            let spans = &all_spans[span_offset..span_offset + span_count];

            let mut result = Vec::with_capacity(file_size);
            for span in spans {
                let page_data = self.read_page(span.page_id)?;
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
            let page_data = self.read_page(file_record.page_id)?;
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

    /// Resolve a path string (e.g. "/foo/bar/baz.txt") to a dir or file index.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist in the bundle.
    pub fn resolve_path(&self, path: &str) -> Result<ResolvedPath> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Ok(ResolvedPath::Dir(0));
        }

        let components: Vec<&str> = path.split('/').collect();
        let mut current_dir_idx: usize = 0;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let dir = &self.dirs()[current_dir_idx];
            let (child_dirs, child_files) = self.dir_children(dir);

            // Try to find component as a child directory
            let mut found_dir = false;
            for (j, child_dir) in child_dirs.iter().enumerate() {
                if self.dir_name(child_dir)? == *component {
                    current_dir_idx = dir.first_child_dir as usize + j;
                    found_dir = true;
                    break;
                }
            }

            if found_dir {
                if is_last {
                    return Ok(ResolvedPath::Dir(current_dir_idx));
                }
                continue;
            }

            // If this is the last component, try as a file
            if is_last {
                for (j, child_file) in child_files.iter().enumerate() {
                    if self.file_name(child_file, dir)? == *component {
                        let file_idx = dir.file_block_offset as usize + j;
                        return Ok(ResolvedPath::File {
                            dir_idx: current_dir_idx,
                            file_idx,
                        });
                    }
                }
            }

            bail!("path not found: component '{component}' in '{path}'");
        }

        Ok(ResolvedPath::Dir(current_dir_idx))
    }

    /// Find the parent `DirEntry` index for a given file index.
    #[must_use]
    #[allow(dead_code)]
    pub fn find_parent_dir_for_file(&self, file_idx: usize) -> Option<usize> {
        let dirs = self.dirs();
        for (i, dir) in dirs.iter().enumerate() {
            let start = dir.file_block_offset as usize;
            let end = start + dir.file_count as usize;
            if file_idx >= start && file_idx < end {
                return Some(i);
            }
        }
        None
    }
}
