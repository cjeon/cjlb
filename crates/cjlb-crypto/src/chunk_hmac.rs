use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Compute HMAC-SHA256 over all page data in a chunk (excluding the 48-byte
/// chunk header).
///
/// # Panics
///
/// Cannot panic in practice — `new_from_slice` only fails if the key length is
/// unsupported, and HMAC-SHA256 accepts any key size.
#[must_use]
pub fn compute_chunk_hmac(hmac_key: &[u8; 32], page_data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("HMAC accepts any key size");
    mac.update(page_data);
    mac.finalize().into_bytes().into()
}

/// Verify a chunk's HMAC. Returns `true` if the tag matches, `false` otherwise.
///
/// # Panics
///
/// Cannot panic in practice — `new_from_slice` only fails if the key length is
/// unsupported, and HMAC-SHA256 accepts any key size.
#[must_use]
pub fn verify_chunk_hmac(hmac_key: &[u8; 32], page_data: &[u8], expected: &[u8; 32]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("HMAC accepts any key size");
    mac.update(page_data);
    mac.verify_slice(expected).is_ok()
}
