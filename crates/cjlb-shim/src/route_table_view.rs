// route_table_view.rs -- Zero-copy accessor over a decompressed route table.
//
// The route table is a flat binary blob laid out as:
//   RouteTableHeader | DirEntry[] | FileRecord[] | PageSpan[] | dir_names | filenames

use cjlb_format::route_table::{
    DirEntry, FileRecord, PageSpan, RouteTableHeader, ROUTE_TABLE_MAGIC,
};

/// Resolved path lookup result.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ResolvedEntry {
    /// Path resolved to a file.
    File { dir_idx: usize, file_idx: usize },
    /// Path resolved to a directory.
    Dir { dir_idx: usize },
}

/// Owns the decompressed route table bytes (in an aligned buffer) and provides
/// zero-copy accessors into its sections.
#[allow(missing_debug_implementations)] // contains raw byte buffers, Debug is not useful
pub struct RouteTableView {
    /// u64-aligned backing storage; actual byte length may be shorter.
    data: Vec<u64>,
    byte_len: usize,
    pub header: RouteTableHeader,
}

impl RouteTableView {
    /// Construct from raw decompressed route table bytes.
    /// Copies into an aligned buffer and validates the magic.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < std::mem::size_of::<RouteTableHeader>() {
            return Err("route table too short for header");
        }

        // Copy into u64-aligned storage.
        let aligned_len = raw.len().div_ceil(8);
        let mut data = vec![0u64; aligned_len];
        let dest =
            unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u8>(), raw.len()) };
        dest.copy_from_slice(raw);

        let header: RouteTableHeader =
            *bytemuck::from_bytes(&dest[..std::mem::size_of::<RouteTableHeader>()]);

        if header.magic != ROUTE_TABLE_MAGIC {
            return Err("invalid route table magic");
        }

        Ok(Self {
            data,
            byte_len: raw.len(),
            header,
        })
    }

    // -- byte slice --------------------------------------------------------

    const fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), self.byte_len) }
    }

    // -- section offsets ---------------------------------------------------

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

    // -- public accessors --------------------------------------------------

    pub fn dirs(&self) -> &[DirEntry] {
        let b = self.bytes();
        let off = Self::dirs_offset();
        let count = self.header.dir_count as usize;
        bytemuck::cast_slice(&b[off..off + count * std::mem::size_of::<DirEntry>()])
    }

    pub fn files(&self) -> &[FileRecord] {
        let b = self.bytes();
        let off = self.files_offset();
        let count = self.header.file_count as usize;
        bytemuck::cast_slice(&b[off..off + count * std::mem::size_of::<FileRecord>()])
    }

    pub fn spans(&self) -> &[PageSpan] {
        let b = self.bytes();
        let off = self.spans_offset();
        let count = self.header.span_count as usize;
        bytemuck::cast_slice(&b[off..off + count * std::mem::size_of::<PageSpan>()])
    }

    fn dir_name_table(&self) -> &[u8] {
        let b = self.bytes();
        let off = self.dir_name_table_offset();
        &b[off..off + self.header.dir_name_table_len as usize]
    }

    fn filename_table(&self) -> &[u8] {
        let b = self.bytes();
        let off = self.filename_table_offset();
        &b[off..off + self.header.filename_table_len as usize]
    }

    // -- name helpers ------------------------------------------------------

    /// Directory name from the dir-name string table.
    pub fn dir_name(&self, dir: &DirEntry) -> &str {
        let table = self.dir_name_table();
        let start = dir.name_offset as usize;
        let end = start + dir.name_len as usize;
        std::str::from_utf8(&table[start..end]).unwrap_or("<invalid utf8>")
    }

    /// Filename from the filename string table, offset relative to parent dir's block.
    pub fn file_name(&self, file: &FileRecord, parent: &DirEntry) -> &str {
        let table = self.filename_table();
        let base = parent.filename_block_offset as usize;
        let start = base + file.filename_offset as usize;
        let end = start + file.filename_len as usize;
        std::str::from_utf8(&table[start..end]).unwrap_or("<invalid utf8>")
    }

    // -- child accessors ---------------------------------------------------

    /// Get child directories and files for a given directory.
    pub fn dir_entries(&self, dir_idx: usize) -> (&[DirEntry], &[FileRecord]) {
        let dir = &self.dirs()[dir_idx];
        let all_dirs = self.dirs();
        let all_files = self.files();

        let child_dirs = if dir.child_dir_count > 0 {
            let start = dir.first_child_dir as usize;
            let end = start + dir.child_dir_count as usize;
            &all_dirs[start..end]
        } else {
            &[]
        };

        let child_files = if dir.file_count > 0 {
            let start = dir.file_block_offset as usize;
            let end = start + dir.file_count as usize;
            &all_files[start..end]
        } else {
            &[]
        };

        (child_dirs, child_files)
    }

    /// Get a single file record by global index.
    pub fn file_record(&self, file_idx: usize) -> &FileRecord {
        &self.files()[file_idx]
    }

    /// Get page spans for a file that uses multi-page storage.
    pub fn page_spans(&self, file: &FileRecord) -> &[PageSpan] {
        if file.span_count == 0 {
            return &[];
        }
        // The span_count field doubles as the count; the page_id field when == SENTINEL
        // means the spans start at file.offset_in_page index into the global spans array.
        let all_spans = self.spans();
        let start = file.offset_in_page as usize;
        let end = start + file.span_count as usize;
        &all_spans[start..end]
    }

    // -- path resolution ---------------------------------------------------

    /// Resolve a virtual path (e.g. "dir/subdir/file.txt") to either a file or
    /// directory. The path should have the virtual root already stripped and no
    /// leading slash.
    pub fn resolve_path(&self, path: &str) -> Option<ResolvedEntry> {
        let path = path.trim_matches('/');

        // Empty path -> root directory.
        if path.is_empty() {
            return Some(ResolvedEntry::Dir { dir_idx: 0 });
        }

        let components: Vec<&str> = path.split('/').collect();
        let mut current_dir_idx: usize = 0;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let dir = &self.dirs()[current_dir_idx];
            let (child_dirs, child_files) = self.dir_entries(current_dir_idx);

            if is_last {
                // Try file first.
                for (j, child_file) in child_files.iter().enumerate() {
                    if self.file_name(child_file, dir) == *component {
                        let file_idx = dir.file_block_offset as usize + j;
                        return Some(ResolvedEntry::File {
                            dir_idx: current_dir_idx,
                            file_idx,
                        });
                    }
                }
                // Try directory.
                for (j, child_dir) in child_dirs.iter().enumerate() {
                    if self.dir_name(child_dir) == *component {
                        let idx = dir.first_child_dir as usize + j;
                        return Some(ResolvedEntry::Dir { dir_idx: idx });
                    }
                }
                // Not found.
                return None;
            }
            // Must be a directory.
            let mut found = false;
            for (j, child_dir) in child_dirs.iter().enumerate() {
                if self.dir_name(child_dir) == *component {
                    current_dir_idx = dir.first_child_dir as usize + j;
                    found = true;
                    break;
                }
            }
            if !found {
                return None;
            }
        }

        None
    }

    /// Resolve a virtual path to a directory index, or None.
    pub fn resolve_dir(&self, path: &str) -> Option<usize> {
        match self.resolve_path(path) {
            Some(ResolvedEntry::Dir { dir_idx }) => Some(dir_idx),
            _ => None,
        }
    }

    /// Resolve a virtual path to (`dir_idx`, `file_idx`), or None.
    #[allow(dead_code)]
    pub fn resolve_file(&self, path: &str) -> Option<(usize, usize)> {
        match self.resolve_path(path) {
            Some(ResolvedEntry::File { dir_idx, file_idx }) => Some((dir_idx, file_idx)),
            _ => None,
        }
    }
}
