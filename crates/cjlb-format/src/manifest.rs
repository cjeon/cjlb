use bytemuck::{Pod, Zeroable};

/// Magic bytes: "LBMF" (LockBox Manifest)
pub const MANIFEST_MAGIC: [u8; 4] = *b"LBMF";

/// Total size of the manifest preamble.
pub const MANIFEST_PREAMBLE_SIZE: usize = 96;

/// 96-byte manifest preamble — the very first thing in the manifest.
///
/// Layout: 4 + 4 + 4 + 4 + 16 + 32 + 8 + 24 = 96 bytes.
/// All multi-byte integer fields are stored in **little-endian** byte order.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ManifestPreamble {
    /// Magic bytes identifying this as an CJLB manifest (`"CJLBM"`).
    pub magic: [u8; 4],
    /// Format version number (little-endian u32).
    pub version: u32,
    /// Number of pages used for the encrypted header (little-endian u32).
    pub header_page_count: u32,
    /// Number of pages used for the encrypted route table (little-endian u32).
    pub route_table_page_count: u32,
    /// 128-bit UUID identifying this bundle.
    pub bundle_id: [u8; 16],
    /// HMAC-based key commitment — binds the manifest to a specific master key.
    pub key_commit: [u8; 32],
    /// Deployment timestamp as Unix epoch seconds (little-endian u64).
    pub deployment_ts: u64,
    /// Reserved for future use; must be zeroed.
    pub reserved: [u8; 24],
}

unsafe impl Zeroable for ManifestPreamble {}
unsafe impl Pod for ManifestPreamble {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_preamble_size() {
        assert_eq!(
            std::mem::size_of::<ManifestPreamble>(),
            MANIFEST_PREAMBLE_SIZE
        );
    }

    #[test]
    fn bytemuck_roundtrip() {
        let p = ManifestPreamble {
            magic: MANIFEST_MAGIC,
            version: 1u32.to_le(),
            header_page_count: 2u32.to_le(),
            route_table_page_count: 10u32.to_le(),
            bundle_id: [0xBB; 16],
            key_commit: [0xCC; 32],
            deployment_ts: 1_700_000_000u64.to_le(),
            reserved: [0; 24],
        };
        let bytes = bytemuck::bytes_of(&p);
        assert_eq!(bytes.len(), MANIFEST_PREAMBLE_SIZE);
        let p2: &ManifestPreamble = bytemuck::from_bytes(bytes);
        assert_eq!(p2.magic, MANIFEST_MAGIC);
        assert_eq!(p2.bundle_id, [0xBB; 16]);
    }
}
