use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// 32-byte master key. All sub-keys are derived from this via HKDF.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl MasterKey {
    /// Generate a random master key using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construct from raw bytes (caller is responsible for key quality).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive the full set of sub-keys from this master key.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice — HKDF-SHA256 expand to 32 bytes always
    /// succeeds (output length <= 255 * `HashLen` = 8160).
    #[must_use]
    pub fn derive_keys(&self) -> DerivedKeys {
        fn expand(master: &[u8; 32], info: &[u8]) -> Result<[u8; 32], CryptoError> {
            let hk = Hkdf::<Sha256>::new(None, master);
            let mut out = [0u8; 32];
            hk.expand(info, &mut out)
                .map_err(|_| CryptoError::HkdfError)?;
            Ok(out)
        }

        // Unwrap is safe: HKDF-SHA256 expand to 32 bytes with these info strings
        // cannot fail (output length <= 255 * HashLen = 8160).
        DerivedKeys {
            bundle_dek: expand(&self.bytes, b"cjlb-bundle-dek-v1").unwrap(),
            manifest_dek: expand(&self.bytes, b"cjlb-manifest-dek-v1").unwrap(),
            write_dek: expand(&self.bytes, b"cjlb-write-dek-v1").unwrap(),
            runtime_dek: expand(&self.bytes, b"cjlb-runtime-dek-v1").unwrap(),
            hmac_key: expand(&self.bytes, b"cjlb-hmac-key-v1").unwrap(),
        }
    }

    /// Compute a key-commitment tag: HMAC-SHA256(key, "cjlb-key-commit").
    ///
    /// # Panics
    ///
    /// Cannot panic in practice — `new_from_slice` only fails if the key length
    /// is unsupported, and HMAC-SHA256 accepts any key size.
    #[must_use]
    pub fn key_commit(&self) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.bytes).expect("HMAC accepts any key size");
        mac.update(b"cjlb-key-commit");
        mac.finalize().into_bytes().into()
    }
}

/// Sub-keys derived from a single master key via HKDF-SHA256.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub bundle_dek: [u8; 32],
    pub manifest_dek: [u8; 32],
    pub write_dek: [u8; 32],
    pub runtime_dek: [u8; 32],
    pub hmac_key: [u8; 32],
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("bundle_dek", &"[REDACTED]")
            .field("manifest_dek", &"[REDACTED]")
            .field("write_dek", &"[REDACTED]")
            .field("runtime_dek", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}
