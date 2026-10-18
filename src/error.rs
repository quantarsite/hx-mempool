//! Error types for the HYDRA-X mempool.
//!
//! Intentionally self-contained: no references to `TxHash` or `Address` to
//! avoid circular dependencies with `types.rs`.  Callers that want to attach
//! context (e.g. which hash failed) do so at the call site.

use thiserror::Error;

// ── CryptoError ──────────────────────────────────────────────────────────────

/// Errors that arise during post-quantum signature verification or
/// key/signature length validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// ML-DSA-87 (FIPS 204) signature verification failed.
    #[error("ML-DSA-87 signature verification failed")]
    MlDsa87VerificationFailed,

    /// SLH-DSA-SHA2-256s (FIPS 205) signature verification failed.
    #[error("SLH-DSA-SHA2-256s signature verification failed")]
    SlhDsa256sVerificationFailed,

    /// Both signature legs of the AND-composition failed.
    #[error("both ML-DSA-87 and SLH-DSA-256s verification failed")]
    BothLegsFailed,

    /// The ML-DSA-87 public key has the wrong byte length.
    ///
    /// `expected` is [`ML_DSA87_PK_LEN`][crate::ML_DSA87_PK_LEN].
    #[error("ML-DSA-87 public key length {got} != {expected}")]
    InvalidMlDsa87PkLen { expected: usize, got: usize },

    /// The ML-DSA-87 signature has the wrong byte length.
    ///
    /// `expected` is [`ML_DSA87_SIG_LEN`][crate::ML_DSA87_SIG_LEN].
    #[error("ML-DSA-87 signature length {got} != {expected}")]
    InvalidMlDsa87SigLen { expected: usize, got: usize },

    /// The SLH-DSA-SHA2-256s public key has the wrong byte length.
    ///
    /// `expected` is [`SLH_DSA_256S_PK_LEN`][crate::SLH_DSA_256S_PK_LEN].
    #[error("SLH-DSA-256s public key length {got} != {expected}")]
    InvalidSlhDsaPkLen { expected: usize, got: usize },

    /// The SLH-DSA-SHA2-256s signature has the wrong byte length.
    ///
    /// `expected` is [`SLH_DSA_256S_SIG_LEN`][crate::SLH_DSA_256S_SIG_LEN].
    #[error("SLH-DSA-256s signature length {got} != {expected}")]
    InvalidSlhDsaSigLen { expected: usize, got: usize },

    /// Sender address does not match BLAKE3(ml_pk || slh_pk)[0..32].
    #[error("sender address does not match derived key hash")]
    AddressMismatch,

    /// pqcrypto returned an error while parsing a public key from raw bytes.
    #[error("failed to decode public key: {reason}")]
    PublicKeyDecodeError { reason: String },

    /// pqcrypto returned an error while parsing a detached signature from raw bytes.
    #[error("failed to decode detached signature: {reason}")]
    SignatureDecodeError { reason: String },
}

// ── MempoolError ─────────────────────────────────────────────────────────────

/// Top-level errors for mempool operations (pool management, cache I/O,
/// serialization, configuration).
#[derive(Debug, Error)]
pub enum MempoolError {
    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// sled database error (cold tier).
    #[error("cold tier sled error: {0}")]
    SledError(#[from] sled::Error),

    /// postcard serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// postcard deserialization error.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Attempted to open the cold tier but no path was configured.
    #[error("cold tier is not configured (cold_path is None)")]
    ColdTierNotConfigured,

    /// The rayon thread-pool could not be built.
    #[error("failed to build rayon thread pool: {0}")]
    ThreadPoolBuildError(String),

    /// A provided configuration value is out of range.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The mempool or cache has been shut down.
    #[error("mempool is shut down")]
    ShutDown,
}

impl From<postcard::Error> for MempoolError {
    fn from(e: postcard::Error) -> Self {
        MempoolError::SerializationError(e.to_string())
    }
}
