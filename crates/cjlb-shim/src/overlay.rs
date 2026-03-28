// overlay.rs -- Write layer overlay index with encrypted persistence.
//
// Files written through the shim are accumulated in memory, flushed as
// encrypted pages to write_dir/pages/, and tracked by an in-memory index.
// The index is atomically persisted to write_dir/wal_manifest.enc on fsync.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use cjlb_crypto::{decrypt_page, encrypt_page};
use cjlb_format::nonce::{make_nonce, DOMAIN_WRITE_LAYER_MANIFEST, DOMAIN_WRITE_LAYER_PAGES};

/// Overlay index tracking files written through the shim.
#[allow(missing_debug_implementations)] // contains crypto keys, Debug would leak secrets
pub struct OverlayIndex {
    inner: RwLock<OverlayInner>,
    write_dir: String,
    write_dek: [u8; 32],
    bundle_id: [u8; 16],
    next_page_id: AtomicU32,
    nonce_counter: AtomicU64,
}

struct OverlayInner {
    files: HashMap<String, OverlayFile>,
}

/// A file in the overlay write layer.
#[derive(Debug)]
pub struct OverlayFile {
    pub size: u64,
    pub pages: Vec<OverlayPageRef>,
}

/// Reference to an encrypted page in the write layer on disk.
#[derive(Debug)]
pub struct OverlayPageRef {
    pub page_id: u32,
    pub offset_in_page: u32,
    pub size_in_page: u32,
}

// -- Serde types for WAL manifest JSON ------------------------------------

#[derive(Serialize, Deserialize)]
struct WalManifest {
    version: u32,
    next_page_id: u32,
    nonce_counter: u64,
    files: HashMap<String, WalFile>,
}

#[derive(Serialize, Deserialize)]
struct WalFile {
    size: u64,
    pages: Vec<WalPageRef>,
}

#[derive(Serialize, Deserialize)]
struct WalPageRef {
    page_id: u32,
    offset: u32,
    size: u32,
}

impl Drop for OverlayIndex {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.write_dek.zeroize();
    }
}

#[allow(clippy::significant_drop_tightening)] // lock must be held across read operations
impl OverlayIndex {
    /// Create a new overlay index, scanning for existing pages on disk.
    pub fn new(
        write_dir: String,
        write_dek: [u8; 32],
        bundle_id: [u8; 16],
        start_page_id: u32,
    ) -> Self {
        // Scan pages/ dir for max existing page ID.
        let pages_dir = format!("{write_dir}/pages");
        let mut max_page_id: u32 = start_page_id;

        if let Ok(entries) = std::fs::read_dir(&pages_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(hex) = name
                        .strip_prefix("page_")
                        .and_then(|s| s.strip_suffix(".enc"))
                    {
                        if let Ok(id) = u32::from_str_radix(hex, 16) {
                            let next = id + 1;
                            if next > max_page_id {
                                max_page_id = next;
                            }
                        }
                    }
                }
            }
        }

        Self {
            inner: RwLock::new(OverlayInner {
                files: HashMap::new(),
            }),
            write_dir,
            write_dek,
            bundle_id,
            next_page_id: AtomicU32::new(max_page_id),
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Check if a path exists in the overlay.
    pub fn contains(&self, vpath: &str) -> bool {
        let inner = self.inner.read().unwrap();
        inner.files.contains_key(vpath)
    }

    /// Get the file size if the path exists in the overlay.
    pub fn file_size(&self, vpath: &str) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        inner.files.get(vpath).map(|f| f.size)
    }

    /// Allocate the next write-layer page ID.
    pub fn alloc_page_id(&self) -> u32 {
        self.next_page_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the next nonce counter value for write encryption.
    pub fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Encrypt data and write it as a page file to `write_dir/pages`/.
    /// Returns the `page_id` on success.
    pub fn flush_page(&self, data: &[u8]) -> Result<u32, ()> {
        let page_id = self.alloc_page_id();
        let nonce_counter = self.next_nonce();
        let nonce = make_nonce(DOMAIN_WRITE_LAYER_PAGES, nonce_counter);

        let encrypted =
            encrypt_page(data, &self.write_dek, &nonce, &self.bundle_id).map_err(|_| ())?;

        // Ensure pages/ directory exists.
        let pages_dir = format!("{}/pages", self.write_dir);
        let _ = std::fs::create_dir_all(&pages_dir);

        let page_path = format!("{pages_dir}/page_{page_id:08x}.enc");
        std::fs::write(&page_path, &encrypted).map_err(|_| ())?;

        Ok(page_id)
    }

    /// Register (add or replace) a file in the overlay index.
    pub fn register_file(&self, vpath: &str, file: OverlayFile) {
        let mut inner = self.inner.write().unwrap();
        inner.files.insert(vpath.to_string(), file);
    }

    /// Remove a file's overlay data (used for `O_TRUNC`).
    pub fn truncate_file(&self, vpath: &str) {
        let mut inner = self.inner.write().unwrap();
        if let Some(f) = inner.files.get_mut(vpath) {
            f.size = 0;
            f.pages.clear();
        }
    }

    /// Atomically persist the overlay index to `write_dir/wal_manifest.enc`.
    pub fn persist_index(&self) -> Result<(), ()> {
        let inner = self.inner.read().unwrap();

        let manifest = WalManifest {
            version: 1,
            next_page_id: self.next_page_id.load(Ordering::Relaxed),
            nonce_counter: self.nonce_counter.load(Ordering::Relaxed),
            files: inner
                .files
                .iter()
                .map(|(k, v)| {
                    let wal_file = WalFile {
                        size: v.size,
                        pages: v
                            .pages
                            .iter()
                            .map(|p| WalPageRef {
                                page_id: p.page_id,
                                offset: p.offset_in_page,
                                size: p.size_in_page,
                            })
                            .collect(),
                    };
                    (k.clone(), wal_file)
                })
                .collect(),
        };

        let json = serde_json::to_vec(&manifest).map_err(|_| ())?;

        // Encrypt the JSON as a single page with DOMAIN_WRITE_LAYER_MANIFEST nonce.
        let nonce_counter = self.next_nonce();
        let nonce = make_nonce(DOMAIN_WRITE_LAYER_MANIFEST, nonce_counter);
        let encrypted =
            encrypt_page(&json, &self.write_dek, &nonce, &self.bundle_id).map_err(|_| ())?;

        // Atomic write: tmp -> fsync -> rename.
        let _ = std::fs::create_dir_all(&self.write_dir);
        let tmp_path = format!("{}/.wal_manifest.enc.tmp", self.write_dir);
        let final_path = format!("{}/wal_manifest.enc", self.write_dir);

        std::fs::write(&tmp_path, &encrypted).map_err(|_| ())?;

        // fsync the tmp file.
        if let Ok(f) = std::fs::File::open(&tmp_path) {
            let _ = f.sync_all();
        }

        std::fs::rename(&tmp_path, &final_path).map_err(|_| ())?;

        // fsync the parent directory so the rename is durable on crash.
        if let Ok(dir) = std::fs::File::open(&self.write_dir) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Load an existing `wal_manifest.enc` from disk. Returns a fully populated
    /// `OverlayIndex`, or None if the manifest doesn't exist.
    pub fn load_index(write_dir: &str, write_dek: &[u8; 32], bundle_id: &[u8; 16]) -> Option<Self> {
        let manifest_path = format!("{write_dir}/wal_manifest.enc");
        let encrypted = std::fs::read(&manifest_path).ok()?;

        // Decrypt the manifest page.
        let json_bytes = decrypt_page(&encrypted, write_dek, bundle_id).ok()?;
        let manifest: WalManifest = serde_json::from_slice(&json_bytes).ok()?;

        let mut files = HashMap::new();
        for (path, wf) in manifest.files {
            let overlay_file = OverlayFile {
                size: wf.size,
                pages: wf
                    .pages
                    .iter()
                    .map(|p| OverlayPageRef {
                        page_id: p.page_id,
                        offset_in_page: p.offset,
                        size_in_page: p.size,
                    })
                    .collect(),
            };
            files.insert(path, overlay_file);
        }

        // Scan disk for max page ID too (crash safety: disk may have pages
        // that were flushed after the last manifest persist).
        let mut next_page_id = manifest.next_page_id;
        let pages_dir = format!("{write_dir}/pages");
        if let Ok(entries) = std::fs::read_dir(&pages_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(hex) = name
                        .strip_prefix("page_")
                        .and_then(|s| s.strip_suffix(".enc"))
                    {
                        if let Ok(id) = u32::from_str_radix(hex, 16) {
                            let next = id + 1;
                            if next > next_page_id {
                                next_page_id = next;
                            }
                        }
                    }
                }
            }
        }

        // Bump nonce counter past any nonces consumed by pages flushed after
        // the last manifest persist. Each flush_page call consumes one nonce,
        // so extra_pages beyond the persisted next_page_id means that many
        // extra nonces were used. Add 1 more for the persist_index nonce itself.
        let extra_pages = u64::from(next_page_id.saturating_sub(manifest.next_page_id));
        let nonce_counter = manifest.nonce_counter + extra_pages + 1;

        Some(Self {
            inner: RwLock::new(OverlayInner { files }),
            write_dir: write_dir.to_string(),
            write_dek: *write_dek,
            bundle_id: *bundle_id,
            next_page_id: AtomicU32::new(next_page_id),
            nonce_counter: AtomicU64::new(nonce_counter),
        })
    }

    /// Read decrypted data from an overlay page file.
    pub fn read_overlay_page(&self, page_id: u32) -> Option<Vec<u8>> {
        let page_path = format!("{}/pages/page_{:08x}.enc", self.write_dir, page_id);
        let encrypted = std::fs::read(&page_path).ok()?;
        decrypt_page(&encrypted, &self.write_dek, &self.bundle_id).ok()
    }

    /// Read data from overlay file pages at the given cursor position.
    /// Returns the bytes read (up to `count`).
    pub fn read_file_data(&self, vpath: &str, cursor: u64, count: usize) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        let file = inner.files.get(vpath)?;

        if cursor >= file.size {
            return Some(Vec::new());
        }

        let to_read = count.min((file.size - cursor) as usize);
        let mut result = Vec::with_capacity(to_read);
        let mut pos = cursor;
        let mut span_offset: u64 = 0;

        for page_ref in &file.pages {
            let span_size = u64::from(page_ref.size_in_page);
            let span_end = span_offset + span_size;

            if pos >= span_end {
                span_offset = span_end;
                continue;
            }

            let page_data = self.read_overlay_page(page_ref.page_id)?;

            let local_start = (pos - span_offset) as usize + page_ref.offset_in_page as usize;
            let local_end = (page_ref.offset_in_page as usize + page_ref.size_in_page as usize)
                .min(page_data.len());

            if local_start >= local_end {
                span_offset = span_end;
                continue;
            }

            let avail = local_end - local_start;
            let n = (to_read - result.len()).min(avail);
            result.extend_from_slice(&page_data[local_start..local_start + n]);
            pos += n as u64;
            span_offset = span_end;

            if result.len() >= to_read {
                break;
            }
        }

        Some(result)
    }

    /// List overlay files whose virtual path starts with `prefix`.
    ///
    /// Returns `(relative_name, size)` pairs for files directly under the given
    /// directory prefix (no recursive descent). `prefix` should end with `/`
    /// for subdirectory matching, or be empty for root.
    #[allow(dead_code)] // used by IPC server ls handler
    pub fn list_files_under(&self, prefix: &str) -> Vec<(String, u64)> {
        let inner = self.inner.read().unwrap();
        let mut result = Vec::new();
        for (path, file) in &inner.files {
            if let Some(rest) = path.strip_prefix(prefix) {
                // Only direct children — no further '/' separators.
                if !rest.contains('/') && !rest.is_empty() {
                    result.push((rest.to_string(), file.size));
                }
            }
        }
        result
    }

    /// Collect the current pages list for a given file (snapshot for building
    /// an updated `OverlayFile` after `write_buf` flush).
    pub fn get_file_pages(&self, vpath: &str) -> Vec<OverlayPageRef> {
        let inner = self.inner.read().unwrap();
        match inner.files.get(vpath) {
            Some(f) => f
                .pages
                .iter()
                .map(|p| OverlayPageRef {
                    page_id: p.page_id,
                    offset_in_page: p.offset_in_page,
                    size_in_page: p.size_in_page,
                })
                .collect(),
            None => Vec::new(),
        }
    }
}
