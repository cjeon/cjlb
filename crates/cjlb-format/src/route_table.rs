use bytemuck::{Pod, Zeroable};

/// Magic bytes: "SMRT"
pub const ROUTE_TABLE_MAGIC: [u8; 4] = *b"SMRT";

/// Sentinel value for `page_id` meaning "look in `page_spans`".
pub const PAGE_ID_SENTINEL: u32 = u32::MAX;

/// Size of the route table header in bytes.
pub const ROUTE_TABLE_HEADER_SIZE: usize = 32;

/// Size of a single directory entry in bytes.
pub const DIR_ENTRY_SIZE: usize = 32;

/// Size of a single file record in bytes.
pub const FILE_RECORD_SIZE: usize = 28;

/// Size of a single page span in bytes.
pub const PAGE_SPAN_SIZE: usize = 8;

/// Route table header — fixed 32-byte preamble.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RouteTableHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub dir_count: u32,
    pub file_count: u32,
    pub span_count: u32,
    pub dir_name_table_len: u32,
    pub filename_table_len: u32,
    pub reserved: u32,
}

unsafe impl Zeroable for RouteTableHeader {}
unsafe impl Pod for RouteTableHeader {}

/// Directory entry — 32 bytes.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DirEntry {
    pub name_offset: u32,
    pub name_len: u16,
    pub pad0: u16,
    pub parent_id: u32,
    pub first_child_dir: u32,
    pub child_dir_count: u16,
    pub pad1: u16,
    pub file_block_offset: u32,
    pub file_count: u32,
    pub filename_block_offset: u32,
}

unsafe impl Zeroable for DirEntry {}
unsafe impl Pod for DirEntry {}

/// File record — 28 bytes.
///
/// `file_size` is stored as two u32 halves (little-endian) to keep the struct
/// 4-byte aligned and exactly 28 bytes with no tail padding.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileRecord {
    pub filename_offset: u32,
    pub filename_len: u16,
    pub pad: u16,
    pub file_size_lo: u32,
    pub file_size_hi: u32,
    pub page_id: u32,
    pub offset_in_page: u32,
    pub span_count: u32,
}

unsafe impl Zeroable for FileRecord {}
unsafe impl Pod for FileRecord {}

impl FileRecord {
    /// Read the full 64-bit file size (little-endian halves).
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        (self.file_size_hi as u64) << 32 | self.file_size_lo as u64
    }

    /// Set the 64-bit file size, storing as little-endian halves.
    ///
    /// The casts intentionally split a u64 into two u32 halves — the low bits
    /// are kept via truncation and the high bits are obtained by shifting first.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn set_file_size(&mut self, size: u64) {
        self.file_size_lo = size as u32;
        self.file_size_hi = (size >> 32) as u32;
    }
}

/// Page span — 8 bytes. Used when a file spans multiple pages.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageSpan {
    pub page_id: u32,
    pub size_in_page: u32,
}

unsafe impl Zeroable for PageSpan {}
unsafe impl Pod for PageSpan {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table_header_size() {
        assert_eq!(
            std::mem::size_of::<RouteTableHeader>(),
            ROUTE_TABLE_HEADER_SIZE
        );
    }

    #[test]
    fn dir_entry_size() {
        assert_eq!(std::mem::size_of::<DirEntry>(), DIR_ENTRY_SIZE);
    }

    #[test]
    fn file_record_size() {
        assert_eq!(std::mem::size_of::<FileRecord>(), FILE_RECORD_SIZE);
    }

    #[test]
    fn page_span_size() {
        assert_eq!(std::mem::size_of::<PageSpan>(), PAGE_SPAN_SIZE);
    }

    #[test]
    fn sentinel_value() {
        assert_eq!(PAGE_ID_SENTINEL, 0xFFFF_FFFF);
    }
}
