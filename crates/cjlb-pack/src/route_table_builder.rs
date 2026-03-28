use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cjlb_format::page::PAGE_BODY_SIZE;
use cjlb_format::route_table::{
    DirEntry, FileRecord, PageSpan, RouteTableHeader, PAGE_ID_SENTINEL, ROUTE_TABLE_MAGIC,
};

/// Intermediate file info collected during directory walk.
#[derive(Debug)]
struct FileInfo {
    /// Path relative to the input root.
    rel_path: PathBuf,
    /// Absolute path on disk.
    abs_path: PathBuf,
    /// File size in bytes.
    size: u64,
}

/// Result of building the route table.
#[derive(Debug)]
pub struct RouteTableResult {
    pub header: RouteTableHeader,
    pub dirs: Vec<DirEntry>,
    pub files: Vec<FileRecord>,
    pub spans: Vec<PageSpan>,
    pub dir_name_table: Vec<u8>,
    pub filename_table: Vec<u8>,
    /// Ordered list of page buffers (plaintext, each up to `PAGE_BODY_SIZE`).
    pub pages: Vec<Vec<u8>>,
    /// Map from absolute file path to (`page_id`, `offset_in_page`) for small files,
    /// or (`PAGE_ID_SENTINEL`, `span_start_index`) for large files.
    /// Used by the packer to know where each file's data lives.
    pub file_read_order: Vec<FileReadEntry>,
}

/// Describes how to read a file's data into pages.
#[derive(Debug)]
pub struct FileReadEntry {
    pub abs_path: PathBuf,
    pub size: u64,
    /// For small files: the page index and byte offset within that page.
    /// For large files: dedicated pages are allocated separately.
    pub kind: FilePageKind,
}

#[derive(Debug)]
pub enum FilePageKind {
    /// File fits in a shared page. (`page_index`, `offset_in_page`)
    Small { page_id: u32, offset_in_page: u32 },
    /// File spans multiple dedicated pages. `first_span_index`, `span_count`
    Large {
        first_span_index: u32,
        span_count: u32,
    },
}

/// Walk the directory tree and build the route table structures.
///
/// Returns all route-table metadata plus the page allocation plan.
///
/// # Errors
///
/// Returns an error if `input_dir` cannot be walked (e.g. permission denied)
/// or file metadata cannot be read.
///
/// # Panics
///
/// Panics if internal counters (directory count, file count, name table size)
/// exceed `u32::MAX`. This is unreachable for any realistic input directory.
#[allow(clippy::too_many_lines)]
pub fn build_route_table(input_dir: &Path) -> anyhow::Result<RouteTableResult> {
    // Collect all files sorted by relative path.
    let mut file_infos: Vec<FileInfo> = Vec::new();
    let mut dir_set: BTreeMap<PathBuf, Vec<usize>> = BTreeMap::new();

    // Root directory
    dir_set.insert(PathBuf::new(), Vec::new());

    for entry in walkdir::WalkDir::new(input_dir).sort_by_file_name() {
        let entry = entry?;
        let abs_path = entry.path().to_path_buf();
        let rel_path = abs_path
            .strip_prefix(input_dir)
            .unwrap_or(&abs_path)
            .to_path_buf();

        if entry.file_type().is_dir() {
            if rel_path != PathBuf::new() {
                dir_set.entry(rel_path).or_default();
            }
        } else if entry.file_type().is_file() {
            let size = entry.metadata()?.len();
            let parent_rel = rel_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            let file_idx = file_infos.len();
            file_infos.push(FileInfo {
                rel_path,
                abs_path,
                size,
            });
            dir_set.entry(parent_rel).or_default().push(file_idx);
        } else if entry.file_type().is_symlink() {
            eprintln!("warning: skipping symlink: {}", abs_path.display());
        }
    }

    // Assign directory IDs in breadth-first order so that direct children of
    // each parent are contiguous in the resulting array.  The BTreeMap keys are
    // sorted lexicographically by full path, which interleaves nested children
    // (e.g. "data", "data/nested", "empty_dir") — that breaks the contiguity
    // assumption in BundleReader::dir_children.
    let dir_paths: Vec<PathBuf> = {
        let all_paths: Vec<PathBuf> = dir_set.keys().cloned().collect();
        let mut bfs: Vec<PathBuf> = Vec::with_capacity(all_paths.len());
        // Root is always first.
        bfs.push(PathBuf::new());
        let mut cursor = 0;
        while cursor < bfs.len() {
            let parent = bfs[cursor].clone();
            // Collect direct children of `parent`, sorted.
            let mut children: Vec<PathBuf> = all_paths
                .iter()
                .filter(|p| {
                    **p != PathBuf::new()
                        && p.parent().unwrap_or_else(|| Path::new("")).to_path_buf() == parent
                })
                .cloned()
                .collect();
            children.sort();
            bfs.extend(children);
            cursor += 1;
        }
        bfs
    };
    let dir_id_map: BTreeMap<PathBuf, u32> = dir_paths
        .iter()
        .enumerate()
        .map(|(i, p)| (p.clone(), u32::try_from(i).expect("dir count fits in u32")))
        .collect();

    // Build dir entries.
    let mut dirs: Vec<DirEntry> = Vec::with_capacity(dir_paths.len());
    let mut dir_name_table: Vec<u8> = Vec::new();

    // First pass: create entries with names and parent IDs.
    for (idx, dir_path) in dir_paths.iter().enumerate() {
        let name = if dir_path == &PathBuf::new() {
            "" // root has empty name
        } else {
            dir_path
                .file_name()
                .map_or("", |s| s.to_str().unwrap_or(""))
        };

        let name_offset = u32::try_from(dir_name_table.len()).expect("dir name table fits in u32");
        let name_len = u16::try_from(name.len()).expect("dir name fits in u16");
        dir_name_table.extend_from_slice(name.as_bytes());

        let parent_id = if idx == 0 {
            0 // root is its own parent
        } else {
            let parent_path = dir_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            dir_id_map.get(&parent_path).copied().unwrap_or(0)
        };

        dirs.push(DirEntry {
            name_offset: name_offset.to_le(),
            name_len: name_len.to_le(),
            pad0: 0,
            parent_id: parent_id.to_le(),
            first_child_dir: 0, // filled in second pass
            child_dir_count: 0, // filled in second pass
            pad1: 0,
            file_block_offset: 0,     // filled later
            file_count: 0,            // filled later
            filename_block_offset: 0, // filled later
        });
    }

    // Second pass: compute child dir relationships.
    for (idx, dir_path) in dir_paths.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let parent_path = dir_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        let parent_id = dir_id_map.get(&parent_path).copied().unwrap_or(0) as usize;
        let count = u16::from_le(dirs[parent_id].child_dir_count);
        if count == 0 {
            dirs[parent_id].first_child_dir =
                u32::try_from(idx).expect("dir index fits in u32").to_le();
        }
        dirs[parent_id].child_dir_count = (count + 1).to_le();
    }

    // Now allocate pages and build file records.
    let mut files: Vec<FileRecord> = Vec::new();
    let mut spans: Vec<PageSpan> = Vec::new();
    let mut filename_table: Vec<u8> = Vec::new();
    let mut file_read_order: Vec<FileReadEntry> = Vec::new();

    // Shared page buffer state.
    let mut next_page_id: u32 = 1; // page 0 is the first shared page
    let mut shared_page_offset: u32 = 0; // current offset in the shared page
    let mut pages: Vec<Vec<u8>> = Vec::new();

    // Initialize first shared page.
    pages.push(vec![0u8; PAGE_BODY_SIZE]);

    // Process files grouped by directory.
    let mut global_file_offset: u32 = 0;
    for (dir_idx, dir_path) in dir_paths.iter().enumerate() {
        let file_indices = dir_set.get(dir_path).cloned().unwrap_or_default();
        let dir_file_count = u32::try_from(file_indices.len()).expect("file count fits in u32");

        dirs[dir_idx].file_block_offset = global_file_offset.to_le();
        dirs[dir_idx].file_count = dir_file_count.to_le();
        dirs[dir_idx].filename_block_offset = u32::try_from(filename_table.len())
            .expect("filename table fits in u32")
            .to_le();

        let dir_fn_base = u32::try_from(filename_table.len()).expect("filename table fits in u32");

        for &fi in &file_indices {
            let info = &file_infos[fi];
            let filename = info
                .rel_path
                .file_name()
                .map_or("", |s| s.to_str().unwrap_or(""));

            // filename_offset is relative to the directory's filename_block_offset.
            let fn_offset = u32::try_from(filename_table.len())
                .expect("filename table fits in u32")
                - dir_fn_base;
            let fn_len = u16::try_from(filename.len()).expect("filename fits in u16");
            filename_table.extend_from_slice(filename.as_bytes());

            let file_size = info.size;

            #[allow(clippy::cast_possible_truncation)]
            let page_body_size_u64 = PAGE_BODY_SIZE as u64;
            if file_size <= page_body_size_u64 {
                // Small file: pack into shared page.
                let needed = u32::try_from(file_size).expect("small file size fits in u32");

                // Check if current shared page has room.
                let page_body_size_u32 =
                    u32::try_from(PAGE_BODY_SIZE).expect("PAGE_BODY_SIZE fits in u32");
                if shared_page_offset + needed > page_body_size_u32 {
                    // Current shared page is full, start a new one.
                    pages.push(vec![0u8; PAGE_BODY_SIZE]);
                    next_page_id += 1;
                    shared_page_offset = 0;
                }

                let current_page_id = next_page_id - 1;
                let offset_in_page = shared_page_offset;

                let mut rec = FileRecord {
                    filename_offset: fn_offset.to_le(),
                    filename_len: fn_len.to_le(),
                    pad: 0,
                    file_size_lo: 0,
                    file_size_hi: 0,
                    page_id: current_page_id.to_le(),
                    offset_in_page: offset_in_page.to_le(),
                    span_count: 0u32.to_le(),
                };
                rec.set_file_size(file_size);

                files.push(rec);
                file_read_order.push(FileReadEntry {
                    abs_path: info.abs_path.clone(),
                    size: file_size,
                    kind: FilePageKind::Small {
                        page_id: current_page_id,
                        offset_in_page,
                    },
                });

                shared_page_offset += needed;
            } else {
                // Large file: dedicated pages.
                let full_pages =
                    u32::try_from(file_size / page_body_size_u64).expect("page count fits in u32");
                let remainder =
                    u32::try_from(file_size % page_body_size_u64).expect("remainder fits in u32");
                let total_pages = full_pages + u32::from(remainder > 0);

                let first_span_index = u32::try_from(spans.len()).expect("span count fits in u32");
                let first_dedicated_page = next_page_id;

                for p in 0..total_pages {
                    let size_in_page = if p < full_pages {
                        u32::try_from(PAGE_BODY_SIZE).expect("PAGE_BODY_SIZE fits in u32")
                    } else {
                        remainder
                    };
                    spans.push(PageSpan {
                        page_id: (first_dedicated_page + p).to_le(),
                        size_in_page: size_in_page.to_le(),
                    });
                    pages.push(vec![0u8; PAGE_BODY_SIZE]);
                }
                next_page_id += total_pages;

                // Mark the current shared page as full so the next small file
                // lazily allocates a new one.  Avoids a wasted trailing page
                // when no more small files follow.
                shared_page_offset =
                    u32::try_from(PAGE_BODY_SIZE).expect("PAGE_BODY_SIZE fits in u32");

                let mut rec = FileRecord {
                    filename_offset: fn_offset.to_le(),
                    filename_len: fn_len.to_le(),
                    pad: 0,
                    file_size_lo: 0,
                    file_size_hi: 0,
                    page_id: PAGE_ID_SENTINEL.to_le(),
                    offset_in_page: first_span_index.to_le(),
                    span_count: total_pages.to_le(),
                };
                rec.set_file_size(file_size);

                files.push(rec);
                file_read_order.push(FileReadEntry {
                    abs_path: info.abs_path.clone(),
                    size: file_size,
                    kind: FilePageKind::Large {
                        first_span_index,
                        span_count: total_pages,
                    },
                });
            }

            global_file_offset += 1;
        }
    }

    // Remove trailing empty shared pages (ones that were allocated but never written to).
    // We keep all pages since they'll be filled with file data in the pack step.

    let header = RouteTableHeader {
        magic: ROUTE_TABLE_MAGIC,
        version: 1u32.to_le(),
        dir_count: u32::try_from(dirs.len())
            .expect("dir count fits in u32")
            .to_le(),
        file_count: u32::try_from(files.len())
            .expect("file count fits in u32")
            .to_le(),
        span_count: u32::try_from(spans.len())
            .expect("span count fits in u32")
            .to_le(),
        dir_name_table_len: u32::try_from(dir_name_table.len())
            .expect("dir name table fits in u32")
            .to_le(),
        filename_table_len: u32::try_from(filename_table.len())
            .expect("filename table fits in u32")
            .to_le(),
        reserved: 0,
    };

    Ok(RouteTableResult {
        header,
        dirs,
        files,
        spans,
        dir_name_table,
        filename_table,
        pages,
        file_read_order,
    })
}

/// Serialize route table to bytes:
/// `RouteTableHeader` || `DirEntry[]` || `FileRecord[]` || `PageSpan[]` || `dir_name_table` || `filename_table`
#[must_use]
pub fn serialize_route_table(rt: &RouteTableResult) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(bytemuck::bytes_of(&rt.header));
    for d in &rt.dirs {
        buf.extend_from_slice(bytemuck::bytes_of(d));
    }
    for f in &rt.files {
        buf.extend_from_slice(bytemuck::bytes_of(f));
    }
    for s in &rt.spans {
        buf.extend_from_slice(bytemuck::bytes_of(s));
    }
    buf.extend_from_slice(&rt.dir_name_table);
    buf.extend_from_slice(&rt.filename_table);

    buf
}
