use bytemuck::{Pod, Zeroable};

use crate::page::PAGE_TOTAL_SIZE;

/// Magic bytes: "LBCK" (LockBox Chunk).
pub const CHUNK_MAGIC: [u8; 4] = *b"LBCK";

/// Size of the chunk header in bytes.
pub const CHUNK_HEADER_SIZE: usize = 48;

/// Maximum number of pages in a single chunk.
pub const PAGES_PER_CHUNK: u16 = 256;

/// 48-byte chunk header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ChunkHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub reserved: u8,
    pub page_count: u16,
    pub chunk_id: u64,
    pub chunk_hmac: [u8; 32],
}

// SAFETY: ChunkHeader is #[repr(C)], all fields are Pod, and layout is 48 bytes
// with no implicit padding (4+1+1+2+8+32 = 48).
unsafe impl Zeroable for ChunkHeader {}
unsafe impl Pod for ChunkHeader {}

/// Given a global page ID, compute which chunk it lives in and the byte offset
/// within that chunk file where the page data starts.
///
/// Pages are packed sequentially: chunk 0 holds pages 0..255, chunk 1 holds 256..511, etc.
#[must_use]
pub const fn page_location(page_id: u32) -> (u32, u64) {
    let pages_per_chunk = PAGES_PER_CHUNK as u32;
    let chunk_id = page_id / pages_per_chunk;
    let index_in_chunk = page_id % pages_per_chunk;
    let offset = CHUNK_HEADER_SIZE as u64 + index_in_chunk as u64 * PAGE_TOTAL_SIZE as u64;
    (chunk_id, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_header_size() {
        assert_eq!(std::mem::size_of::<ChunkHeader>(), CHUNK_HEADER_SIZE);
    }

    #[test]
    fn page_location_first_page() {
        let (chunk, offset) = page_location(0);
        assert_eq!(chunk, 0);
        assert_eq!(offset, CHUNK_HEADER_SIZE as u64);
    }

    #[test]
    fn page_location_last_in_first_chunk() {
        let (chunk, offset) = page_location(255);
        assert_eq!(chunk, 0);
        assert_eq!(
            offset,
            CHUNK_HEADER_SIZE as u64 + 255 * PAGE_TOTAL_SIZE as u64
        );
    }

    #[test]
    fn page_location_first_in_second_chunk() {
        let (chunk, offset) = page_location(256);
        assert_eq!(chunk, 1);
        assert_eq!(offset, CHUNK_HEADER_SIZE as u64);
    }

    #[test]
    fn page_location_arbitrary() {
        // page 513 => chunk 2, index 1
        let (chunk, offset) = page_location(513);
        assert_eq!(chunk, 2);
        assert_eq!(
            offset,
            CHUNK_HEADER_SIZE as u64 + 1 * PAGE_TOTAL_SIZE as u64
        );
    }
}
