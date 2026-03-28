use cjlb_format::page::PAGE_BODY_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid page magic")]
    InvalidPageMagic,
    #[error("unsupported page version: {0}")]
    UnsupportedPageVersion(u8),
    #[error("page data too short: expected {expected}, got {got}")]
    PageTooShort { expected: usize, got: usize },
    #[error("plaintext too large: {len} bytes (max {max})", max = PAGE_BODY_SIZE)]
    PlaintextTooLarge { len: usize },
    #[error("GCM authentication failed")]
    AuthenticationFailed,
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    #[error("HKDF expand failed")]
    HkdfError,
}
