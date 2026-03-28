/// Size of a GCM nonce in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

// Domain constants — occupy the first 4 bytes of the nonce (big-endian u32).

/// Domain tag for encrypting base (read-only) pages in chunk files.
pub const DOMAIN_BASE_PAGES: u32 = 0x0000_0001;

/// Domain tag for encrypting the manifest header section.
pub const DOMAIN_MANIFEST_HEADER: u32 = 0x0000_0002;

/// Domain tag for encrypting the manifest's route table section.
pub const DOMAIN_MANIFEST_ROUTE_TABLE: u32 = 0x0000_0003;

/// Domain tag for encrypting pages in the mutable write layer.
pub const DOMAIN_WRITE_LAYER_PAGES: u32 = 0x0000_0004;

/// Domain tag for encrypting the write layer's manifest.
pub const DOMAIN_WRITE_LAYER_MANIFEST: u32 = 0x0000_0005;

/// Build a 12-byte nonce from a domain tag and a monotonic counter.
///
/// Layout:
///   bytes [0..4)  — domain as big-endian u32
///   bytes [4..12) — counter as big-endian u64
///
/// This guarantees domain separation: two different domains will never produce
/// the same nonce even if the counter values collide.
#[must_use]
pub fn make_nonce(domain: u32, counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(&domain.to_be_bytes());
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_nonce_layout() {
        let n = make_nonce(0x00000001, 0x00000000_00000042);
        // domain bytes
        assert_eq!(&n[0..4], &[0x00, 0x00, 0x00, 0x01]);
        // counter bytes
        assert_eq!(&n[4..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42]);
    }

    #[test]
    fn different_domains_different_nonces() {
        let n1 = make_nonce(DOMAIN_BASE_PAGES, 0);
        let n2 = make_nonce(DOMAIN_MANIFEST_HEADER, 0);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_counters_different_nonces() {
        let n1 = make_nonce(DOMAIN_BASE_PAGES, 0);
        let n2 = make_nonce(DOMAIN_BASE_PAGES, 1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_size_correct() {
        let n = make_nonce(DOMAIN_BASE_PAGES, 999);
        assert_eq!(n.len(), NONCE_SIZE);
    }

    #[test]
    fn max_values() {
        let n = make_nonce(u32::MAX, u64::MAX);
        assert_eq!(&n[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(&n[4..12], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
