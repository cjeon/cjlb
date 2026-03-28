// CJLB Crypto — AES-256-GCM page encryption, HKDF key hierarchy, chunk HMAC.

pub mod chunk_hmac;
pub mod error;
pub mod key;
pub mod page_crypto;

pub use chunk_hmac::{compute_chunk_hmac, verify_chunk_hmac};
pub use error::CryptoError;
pub use key::{DerivedKeys, MasterKey};
pub use page_crypto::{decrypt_page, encrypt_page};

#[cfg(test)]
mod tests {
    use super::*;
    use cjlb_format::nonce::{make_nonce, DOMAIN_BASE_PAGES, DOMAIN_MANIFEST_HEADER};
    use cjlb_format::page::{quantize_plaintext_len, PAGE_BODY_SIZE, PAGE_TOTAL_SIZE};

    // ── Key tests ────────────────────────────────────────────────────

    #[test]
    fn test_key_generate_is_random() {
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_key_derive_deterministic() {
        let key = MasterKey::from_bytes([0xAA; 32]);
        let d1 = key.derive_keys();
        let d2 = key.derive_keys();
        assert_eq!(d1.bundle_dek, d2.bundle_dek);
        assert_eq!(d1.manifest_dek, d2.manifest_dek);
        assert_eq!(d1.write_dek, d2.write_dek);
        assert_eq!(d1.runtime_dek, d2.runtime_dek);
        assert_eq!(d1.hmac_key, d2.hmac_key);
    }

    #[test]
    fn test_key_derive_different_domains() {
        let key = MasterKey::from_bytes([0xBB; 32]);
        let d = key.derive_keys();
        let keys: [&[u8; 32]; 5] = [
            &d.bundle_dek,
            &d.manifest_dek,
            &d.write_dek,
            &d.runtime_dek,
            &d.hmac_key,
        ];
        // Every pair must differ.
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "derived keys {i} and {j} collided");
            }
        }
    }

    #[test]
    fn test_key_commit_deterministic() {
        let key = MasterKey::from_bytes([0xCC; 32]);
        assert_eq!(key.key_commit(), key.key_commit());
    }

    #[test]
    fn test_key_commit_different_keys() {
        let k1 = MasterKey::from_bytes([0x01; 32]);
        let k2 = MasterKey::from_bytes([0x02; 32]);
        assert_ne!(k1.key_commit(), k2.key_commit());
    }

    // ── Page crypto tests ────────────────────────────────────────────

    fn test_bundle_id() -> [u8; 16] {
        [0xDE; 16]
    }

    #[test]
    fn test_page_roundtrip() {
        let key = MasterKey::from_bytes([0x42; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let plaintext = b"hello, CJLB world!";
        let page = encrypt_page(plaintext, &dk.bundle_dek, &nonce, &bundle_id).unwrap();
        assert_eq!(page.len(), PAGE_TOTAL_SIZE);

        let decrypted = decrypt_page(&page, &dk.bundle_dek, &bundle_id).unwrap();
        // Decrypted length is quantized (4096), but the first bytes match.
        assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn test_page_roundtrip_small() {
        let key = MasterKey::from_bytes([0x43; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 1);
        let bundle_id = test_bundle_id();

        let plaintext = vec![0xABu8; 100];
        let page = encrypt_page(&plaintext, &dk.bundle_dek, &nonce, &bundle_id).unwrap();
        let decrypted = decrypt_page(&page, &dk.bundle_dek, &bundle_id).unwrap();
        assert_eq!(&decrypted[..100], &plaintext[..]);
    }

    #[test]
    fn test_page_roundtrip_full() {
        let key = MasterKey::from_bytes([0x44; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 2);
        let bundle_id = test_bundle_id();

        let plaintext = vec![0x77u8; PAGE_BODY_SIZE];
        let page = encrypt_page(&plaintext, &dk.bundle_dek, &nonce, &bundle_id).unwrap();
        let decrypted = decrypt_page(&page, &dk.bundle_dek, &bundle_id).unwrap();
        assert_eq!(decrypted.len(), PAGE_BODY_SIZE);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_page_wrong_key_fails() {
        let key = MasterKey::from_bytes([0x50; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let page = encrypt_page(b"secret", &dk.bundle_dek, &nonce, &bundle_id).unwrap();

        let wrong_key = [0xFF; 32];
        let result = decrypt_page(&page, &wrong_key, &bundle_id);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_page_wrong_bundle_id_fails() {
        let key = MasterKey::from_bytes([0x51; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let page = encrypt_page(b"secret", &dk.bundle_dek, &nonce, &bundle_id).unwrap();

        let wrong_id = [0x00; 16];
        let result = decrypt_page(&page, &dk.bundle_dek, &wrong_id);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_page_tampered_ciphertext_fails() {
        let key = MasterKey::from_bytes([0x52; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let mut page = encrypt_page(b"secret", &dk.bundle_dek, &nonce, &bundle_id).unwrap();

        // Flip a bit in the ciphertext region (byte 100, well inside the body).
        page[100] ^= 0x01;

        let result = decrypt_page(&page, &dk.bundle_dek, &bundle_id);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_page_tampered_header_fails() {
        let key = MasterKey::from_bytes([0x53; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let mut page = encrypt_page(b"secret", &dk.bundle_dek, &nonce, &bundle_id).unwrap();

        // Flip a bit in the flags byte (offset 5) — header is AAD, so GCM
        // authentication must fail.
        page[5] ^= 0x01;

        let result = decrypt_page(&page, &dk.bundle_dek, &bundle_id);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_nonce_domain_separation() {
        let key = MasterKey::from_bytes([0x60; 32]);
        let dk = key.derive_keys();
        let bundle_id = test_bundle_id();
        let plaintext = b"same data for both";

        let nonce_a = make_nonce(DOMAIN_BASE_PAGES, 0);
        let nonce_b = make_nonce(DOMAIN_MANIFEST_HEADER, 0);
        assert_ne!(nonce_a, nonce_b);

        let page_a = encrypt_page(plaintext, &dk.bundle_dek, &nonce_a, &bundle_id).unwrap();
        let page_b = encrypt_page(plaintext, &dk.bundle_dek, &nonce_b, &bundle_id).unwrap();

        // The ciphertext bodies must differ (different nonces).
        assert_ne!(
            &page_a[24..24 + 256],
            &page_b[24..24 + 256],
            "ciphertexts should differ with different nonces"
        );
    }

    #[test]
    fn test_plaintext_len_quantized() {
        let key = MasterKey::from_bytes([0x70; 32]);
        let dk = key.derive_keys();
        let nonce = make_nonce(DOMAIN_BASE_PAGES, 0);
        let bundle_id = test_bundle_id();

        let plaintext = vec![0xABu8; 100];
        let page = encrypt_page(&plaintext, &dk.bundle_dek, &nonce, &bundle_id).unwrap();

        // Read back the plaintext_len field from the header (bytes 20..24, little-endian u32).
        let stored_len = u32::from_le_bytes(page[20..24].try_into().unwrap());
        assert_eq!(stored_len, quantize_plaintext_len(100));
        assert_eq!(stored_len, 4096);
    }

    // ── Chunk HMAC tests ─────────────────────────────────────────────

    #[test]
    fn test_chunk_hmac_roundtrip() {
        let key = MasterKey::from_bytes([0x80; 32]);
        let dk = key.derive_keys();

        let page_data = vec![0x55u8; PAGE_TOTAL_SIZE * 4]; // 4 pages worth
        let tag = compute_chunk_hmac(&dk.hmac_key, &page_data);
        assert!(verify_chunk_hmac(&dk.hmac_key, &page_data, &tag));
    }

    #[test]
    fn test_chunk_hmac_tampered_fails() {
        let key = MasterKey::from_bytes([0x81; 32]);
        let dk = key.derive_keys();

        let mut page_data = vec![0x55u8; PAGE_TOTAL_SIZE * 2];
        let tag = compute_chunk_hmac(&dk.hmac_key, &page_data);

        // Tamper with one byte.
        page_data[42] ^= 0x01;
        assert!(!verify_chunk_hmac(&dk.hmac_key, &page_data, &tag));
    }
}
