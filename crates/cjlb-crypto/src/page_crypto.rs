use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use cjlb_format::page::{
    quantize_plaintext_len, PageHeader, PAGE_BODY_SIZE, PAGE_HEADER_SIZE, PAGE_MAGIC,
    PAGE_TAG_SIZE, PAGE_TOTAL_SIZE, PAGE_VERSION,
};

use crate::error::CryptoError;

/// Encrypt plaintext into a full page (`PAGE_TOTAL_SIZE` bytes).
///
/// - `plaintext`: up to `PAGE_BODY_SIZE` bytes of cleartext data.
/// - `dek`: 32-byte AES-256-GCM key for this domain.
/// - `nonce`: 12-byte nonce (typically from `make_nonce`).
/// - `bundle_id`: 16-byte bundle identifier (included in AAD).
///
/// Returns a `Vec<u8>` of exactly `PAGE_TOTAL_SIZE` bytes:
///   header (24) || ciphertext (1 MiB) || tag (16).
///
/// # Errors
///
/// Returns [`CryptoError::PlaintextTooLarge`] if `plaintext` exceeds
/// `PAGE_BODY_SIZE`, or [`CryptoError::AuthenticationFailed`] if the
/// underlying AES-GCM seal operation fails.
///
/// # Panics
///
/// Cannot panic in practice — the `try_into` on the header bytes always
/// succeeds because `PageHeader` is exactly `PAGE_HEADER_SIZE`.
pub fn encrypt_page(
    plaintext: &[u8],
    dek: &[u8; 32],
    nonce: &[u8; 12],
    bundle_id: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > PAGE_BODY_SIZE {
        return Err(CryptoError::PlaintextTooLarge {
            len: plaintext.len(),
        });
    }

    // Build header with quantized plaintext length.
    // plaintext.len() is guaranteed <= PAGE_BODY_SIZE (1 MiB) by the check above,
    // so it always fits in a u32.
    let quantized_len = quantize_plaintext_len(
        u32::try_from(plaintext.len()).expect("plaintext length <= PAGE_BODY_SIZE fits in u32"),
    );
    let header = PageHeader {
        magic: PAGE_MAGIC,
        version: PAGE_VERSION,
        flags: 0,
        reserved: [0u8; 2],
        nonce: *nonce,
        plaintext_len: quantized_len.to_le(),
    };
    let header_bytes: &[u8; PAGE_HEADER_SIZE] = bytemuck::bytes_of(&header)
        .try_into()
        .expect("PageHeader is exactly PAGE_HEADER_SIZE");

    // Zero-pad plaintext to PAGE_BODY_SIZE.
    let mut padded = vec![0u8; PAGE_BODY_SIZE];
    padded[..plaintext.len()].copy_from_slice(plaintext);

    // AAD = header || bundle_id
    let mut aad = Vec::with_capacity(PAGE_HEADER_SIZE + 16);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(bundle_id);

    // Encrypt with AES-256-GCM via ring (hardware-accelerated).
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, dek).map_err(|_| CryptoError::AuthenticationFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let ring_nonce = Nonce::assume_unique_for_key(*nonce);
    let tag = key
        .seal_in_place_separate_tag(ring_nonce, Aad::from(&aad[..]), &mut padded)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    debug_assert_eq!(padded.len(), PAGE_BODY_SIZE);
    debug_assert_eq!(tag.as_ref().len(), PAGE_TAG_SIZE);

    // Assemble: header || ciphertext || tag
    let mut out = Vec::with_capacity(PAGE_TOTAL_SIZE);
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(&padded);
    out.extend_from_slice(tag.as_ref());
    debug_assert_eq!(out.len(), PAGE_TOTAL_SIZE);

    Ok(out)
}

/// Decrypt a page from raw bytes (`PAGE_TOTAL_SIZE`).
///
/// Verifies the page magic, version, and GCM authentication tag.
/// Returns the decrypted plaintext truncated to `plaintext_len` (quantized) bytes.
///
/// # Errors
///
/// Returns [`CryptoError`] if the page is too short, has an invalid magic or
/// version, or if GCM authentication fails.
pub fn decrypt_page(
    page_bytes: &[u8],
    dek: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if page_bytes.len() != PAGE_TOTAL_SIZE {
        return Err(CryptoError::PageTooShort {
            expected: PAGE_TOTAL_SIZE,
            got: page_bytes.len(),
        });
    }

    // Parse header.
    let header: &PageHeader = bytemuck::from_bytes(&page_bytes[..PAGE_HEADER_SIZE]);

    if header.magic != PAGE_MAGIC {
        return Err(CryptoError::InvalidPageMagic);
    }
    if header.version != PAGE_VERSION {
        return Err(CryptoError::UnsupportedPageVersion(header.version));
    }

    let nonce_bytes = &header.nonce;
    let plaintext_len = u32::from_le(header.plaintext_len) as usize;

    // AAD = header_bytes || bundle_id
    let header_bytes = &page_bytes[..PAGE_HEADER_SIZE];
    let mut aad = Vec::with_capacity(PAGE_HEADER_SIZE + 16);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(bundle_id);

    // ciphertext (1 MiB) || tag (16) — ring expects them concatenated.
    let mut ct_and_tag = page_bytes[PAGE_HEADER_SIZE..].to_vec();

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, dek).map_err(|_| CryptoError::AuthenticationFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let ring_nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    let decrypted = key
        .open_in_place(ring_nonce, Aad::from(&aad[..]), &mut ct_and_tag)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // Truncate to the quantized plaintext length stored in the header.
    let len = plaintext_len.min(decrypted.len());
    Ok(decrypted[..len].to_vec())
}
