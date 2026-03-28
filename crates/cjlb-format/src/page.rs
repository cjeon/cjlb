use bytemuck::{Pod, Zeroable};

/// Magic bytes: "LBPG" (LockBox Page)
pub const PAGE_MAGIC: [u8; 4] = *b"LBPG";

/// Current page format version.
pub const PAGE_VERSION: u8 = 1;

/// Size of the cleartext header (used as GCM AAD).
pub const PAGE_HEADER_SIZE: usize = 24;

/// Size of the encrypted body (1 MiB).
pub const PAGE_BODY_SIZE: usize = 1_048_576;

/// Size of the GCM authentication tag.
pub const PAGE_TAG_SIZE: usize = 16;

/// Total on-disk size of one page: header + body + tag.
pub const PAGE_TOTAL_SIZE: usize = PAGE_HEADER_SIZE + PAGE_BODY_SIZE + PAGE_TAG_SIZE; // 1_048_616

/// Plaintext length is quantized to this boundary (4 KiB).
pub const PLAINTEXT_QUANTUM: u32 = 4096;

/// 24-byte page header — cleartext, used as GCM AAD.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub reserved: [u8; 2],
    pub nonce: [u8; 12],
    pub plaintext_len: u32,
}

// SAFETY: PageHeader is #[repr(C)] with no padding and all fields are Pod.
unsafe impl Zeroable for PageHeader {}
unsafe impl Pod for PageHeader {}

/// Round `len` up to the nearest multiple of `PLAINTEXT_QUANTUM` (4 KiB).
/// Returns 0 for input 0.
///
/// # Panics (debug builds)
///
/// Panics if `len` exceeds `PAGE_BODY_SIZE`, which would overflow the
/// quantization arithmetic.
#[must_use]
pub const fn quantize_plaintext_len(len: u32) -> u32 {
    debug_assert!(len <= 1_048_576, "len exceeds PAGE_BODY_SIZE"); // PAGE_BODY_SIZE = 1 MiB
    if len == 0 {
        return 0;
    }
    let q = PLAINTEXT_QUANTUM;
    len.div_ceil(q) * q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_header_size() {
        assert_eq!(std::mem::size_of::<PageHeader>(), PAGE_HEADER_SIZE);
    }

    #[test]
    fn page_total_size_constant() {
        assert_eq!(PAGE_TOTAL_SIZE, 1_048_616);
    }

    #[test]
    fn quantize_zero() {
        assert_eq!(quantize_plaintext_len(0), 0);
    }

    #[test]
    fn quantize_exact_boundary() {
        assert_eq!(quantize_plaintext_len(4096), 4096);
        assert_eq!(quantize_plaintext_len(8192), 8192);
    }

    #[test]
    fn quantize_rounds_up() {
        assert_eq!(quantize_plaintext_len(1), 4096);
        assert_eq!(quantize_plaintext_len(4095), 4096);
        assert_eq!(quantize_plaintext_len(4097), 8192);
        assert_eq!(quantize_plaintext_len(5000), 8192);
    }

    #[test]
    fn quantize_at_page_body_size() {
        // PAGE_BODY_SIZE is 1 MiB = 1_048_576, an exact multiple of 4096
        assert_eq!(
            quantize_plaintext_len(PAGE_BODY_SIZE as u32),
            PAGE_BODY_SIZE as u32
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "len exceeds PAGE_BODY_SIZE")]
    fn quantize_overflow_panics_in_debug() {
        let _ = quantize_plaintext_len(u32::MAX);
    }

    #[test]
    fn bytemuck_page_header_roundtrip() {
        let hdr = PageHeader {
            magic: PAGE_MAGIC,
            version: PAGE_VERSION,
            flags: 0,
            reserved: [0; 2],
            nonce: [0xAA; 12],
            plaintext_len: 4096u32.to_le(),
        };
        let bytes = bytemuck::bytes_of(&hdr);
        assert_eq!(bytes.len(), PAGE_HEADER_SIZE);
        let hdr2: &PageHeader = bytemuck::from_bytes(bytes);
        assert_eq!(hdr2.magic, PAGE_MAGIC);
        assert_eq!(hdr2.nonce, [0xAA; 12]);
    }
}
