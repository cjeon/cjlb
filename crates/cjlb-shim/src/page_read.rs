// page_read.rs -- Shared page reading and decryption logic.
//
// Extracted from hooks.rs so that other modules (e.g., IPC server, stream hub)
// can read decrypted pages and whole files without duplicating the cache-aware
// read-decrypt-insert pipeline.

use std::ffi::CString;
use std::sync::Arc;

use cjlb_crypto::decrypt_page;
use cjlb_format::chunk::page_location;
use cjlb_format::page::PAGE_TOTAL_SIZE;
use cjlb_format::route_table::PAGE_ID_SENTINEL;

use crate::cache::DecryptedPage;
use crate::route_table_view::ResolvedEntry;
use crate::state::ShimState;

/// Read and decrypt a single page from the bundle, using the cache.
///
/// Returns `None` if the page cannot be read or decrypted.
///
/// # Safety
///
/// Calls raw libc functions through `state.real` to avoid re-entering the
/// `LD_PRELOAD` hooks. The caller must ensure `state` is valid.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe fn read_page(
    state: &ShimState,
    page_id: u32,
) -> Option<Arc<DecryptedPage>> {
    unsafe {
        // Check cache first.
        if let Some(cached) = state.cache.get(page_id) {
            return Some(cached);
        }

        // Cache miss: read from chunk file, decrypt, insert into cache.
        let (chunk_id, byte_offset) = page_location(page_id);
        let chunk_path = format!("{}/chunks/{:06}.enc", state.bundle_dir, chunk_id);
        let c_path = CString::new(chunk_path).ok()?;

        let fd = state.real.real_open(c_path.as_ptr(), libc::O_RDONLY, 0);
        if fd < 0 {
            return None;
        }

        // Seek to the page offset.
        let pos =
            state
                .real
                .real_lseek(fd, i64::try_from(byte_offset).unwrap_or(0), libc::SEEK_SET);
        if pos < 0 {
            state.real.real_close(fd);
            return None;
        }

        // Read PAGE_TOTAL_SIZE bytes.
        let mut page_buf = vec![0u8; PAGE_TOTAL_SIZE];
        let mut total_read = 0usize;
        while total_read < PAGE_TOTAL_SIZE {
            let n = state.real.real_read(
                fd,
                page_buf[total_read..].as_mut_ptr().cast(),
                PAGE_TOTAL_SIZE - total_read,
            );
            if n <= 0 {
                state.real.real_close(fd);
                return None;
            }
            total_read += n.cast_unsigned();
        }
        state.real.real_close(fd);

        // Decrypt.
        let decrypted =
            decrypt_page(&page_buf, &state.derived_keys.bundle_dek, &state.bundle_id).ok()?;

        // Insert into cache.
        Some(state.cache.insert(page_id, decrypted))
    }
}

/// Read the entire contents of a virtual file, returning the raw bytes.
///
/// Resolves `vpath` through the route table (checking overlay first), then
/// reads all pages (handling both single-page and multi-page files).
///
/// Returns `None` if the path does not resolve to a file.
///
/// # Safety
///
/// Delegates to [`read_page`] which calls raw libc functions through
/// `state.real`. The caller must ensure `state` is valid.
#[allow(
    dead_code, // used by IPC/stream modules (not yet wired)
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub unsafe fn read_entire_file(state: &ShimState, vpath: &str) -> Option<Vec<u8>> {
    unsafe {
        // Check overlay first.
        if state.overlay.contains(vpath) {
            let file_size = state.overlay.file_size(vpath)?;
            return state
                .overlay
                .read_file_data(vpath, 0, file_size as usize);
        }

        // Resolve from the base bundle route table.
        let resolved = state.route_table.resolve_path(vpath)?;
        let file_idx = match resolved {
            ResolvedEntry::File { file_idx, .. } => file_idx,
            ResolvedEntry::Dir { .. } => return None,
        };

        let file_rec = state.route_table.file_record(file_idx);
        let file_size = file_rec.file_size() as usize;

        if file_size == 0 {
            return Some(Vec::new());
        }

        if file_rec.page_id != PAGE_ID_SENTINEL {
            // Single-page file: data starts at offset_in_page within that page.
            let page = read_page(state, file_rec.page_id)?;
            let offset = file_rec.offset_in_page as usize;
            let end = (offset + file_size).min(page.data.len());
            if offset >= end {
                return Some(Vec::new());
            }
            return Some(page.data[offset..end].to_vec());
        }

        // Multi-page file: walk PageSpan array.
        let spans = state.route_table.page_spans(file_rec);
        let mut result = Vec::with_capacity(file_size);

        for span in spans {
            let page = read_page(state, span.page_id)?;
            let avail = (span.size_in_page as usize).min(page.data.len());
            let needed = file_size - result.len();
            let n = avail.min(needed);
            result.extend_from_slice(&page.data[..n]);

            if result.len() >= file_size {
                break;
            }
        }

        Some(result)
    }
}

/// Read from a base-bundle file into a caller-provided buffer at a given cursor
/// position. This is the buffer-pointer variant used by the hooks' `read()`
/// implementation where data is copied directly into the userspace buffer.
///
/// Returns the number of bytes copied.
///
/// # Safety
///
/// `buf` must be valid for writes of at least `count` bytes. Delegates to
/// [`read_page`] which calls raw libc functions through `state.real`.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn read_virtual_file_into_buf(
    state: &ShimState,
    buf: *mut u8,
    count: usize,
    file_idx: usize,
    cursor: u64,
    file_size: u64,
) -> usize {
    unsafe {
        if cursor >= file_size {
            return 0;
        }

        let file_rec = state.route_table.file_record(file_idx);
        let to_read = count.min((file_size - cursor) as usize);

        if file_rec.page_id != PAGE_ID_SENTINEL {
            // Single-page file: data starts at offset_in_page within that page.
            let page = match read_page(state, file_rec.page_id) {
                Some(p) => p,
                None => return 0,
            };
            let offset_in_page = file_rec.offset_in_page as usize;
            let avail_start = offset_in_page + cursor as usize;
            let avail_end = (offset_in_page + file_size as usize).min(page.data.len());
            if avail_start >= avail_end {
                return 0;
            }
            let n = to_read.min(avail_end - avail_start);
            std::ptr::copy_nonoverlapping(page.data[avail_start..].as_ptr(), buf, n);
            return n;
        }

        // Multi-page file: walk PageSpan array.
        let spans = state.route_table.page_spans(file_rec);
        let mut copied = 0usize;
        let mut pos = cursor;
        let mut span_offset: u64 = 0;

        for span in spans {
            let span_size = u64::from(span.size_in_page);
            let span_end = span_offset + span_size;

            if pos >= span_end {
                span_offset = span_end;
                continue;
            }

            let page = match read_page(state, span.page_id) {
                Some(p) => p,
                None => return copied,
            };

            let local_start = (pos - span_offset) as usize;
            let local_end = (span_size as usize).min(page.data.len());
            if local_start >= local_end {
                span_offset = span_end;
                continue;
            }
            let avail = local_end - local_start;
            let n = (to_read - copied).min(avail);

            std::ptr::copy_nonoverlapping(page.data[local_start..].as_ptr(), buf.add(copied), n);

            copied += n;
            pos += n as u64;
            span_offset = span_end;

            if copied >= to_read {
                break;
            }
        }

        copied
    }
}
