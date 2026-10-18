//! # hx-mempool
//!
//! HYDRA-X L1 blockchain mempool with a post-quantum signature cache.
//!
//! ## Cryptographic scheme
//!
//! Every transaction must carry an AND-composition of two post-quantum signatures:
//! * **ML-DSA-87** (FIPS 204) — lattice-based
//! * **SLH-DSA-SHA2-256s** (FIPS 205) — hash-based
//!
//! Both signatures must verify independently; if either fails the transaction is
//! rejected and no entry is made in the pool or cache.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  IngestionPipeline  (parallel verify via rayon)      │
//! │   address derivation → ML-DSA-87 ║ SLH-DSA-256s     │
//! │   AND-gate → commit to TxPool + HydraXSigCache       │
//! └──────────────┬───────────────────┬──────────────────┘
//!                │                   │
//!          ┌─────▼────┐      ┌───────▼──────────────┐
//!          │  TxPool  │      │  HydraXSigCache       │
//!          │ DashMap  │      │  ┌─────────┐          │
//!          │ + nonce  │      │  │ HotTier │ (CLOCK)  │
//!          │ ordering │      │  └────┬────┘          │
//!          └──────────┘      │  ┌────▼────┐          │
//!                            │  │ColdTier │ (sled)   │
//!                            │  └─────────┘          │
//!                            └──────────────────────┘
//! ```
//!
//! ## Crate layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`types`] | Core newtype aliases, `HydraXSignature`, `SigEntry`, `PooledTx` |
//! | [`error`] | `MempoolError`, `CryptoError` |
//! | [`metrics`] | Lock-free atomic metrics structs |
//! | [`pool`] | `TxPool` — per-sender nonce-ordered map |
//! | [`sig_cache`] | `HydraXSigCache` — two-tier hot/cold cache |
//! | [`ingestion`] | `IngestionPipeline` — batch ingest + verification |

pub mod error;
pub mod ingestion;
pub mod metrics;
pub mod pool;
pub mod sig_cache;
pub mod types;

// Crypto length constants — canonical for the HYDRA-X protocol.
// These are embedded here so downstream crates never need to depend on
// pqcrypto just to size buffers or write assertions.

/// Byte length of an ML-DSA-87 (FIPS 204) public key.
pub const ML_DSA87_PK_LEN: usize = 2592;

/// Byte length of an ML-DSA-87 (FIPS 204) detached signature.
pub const ML_DSA87_SIG_LEN: usize = 4627;

/// Byte length of an SLH-DSA-SHA2-256s (FIPS 205) public key.
pub const SLH_DSA_256S_PK_LEN: usize = 64;

/// Byte length of an SLH-DSA-SHA2-256s (FIPS 205) detached signature.
pub const SLH_DSA_256S_SIG_LEN: usize = 29792;

/// Size of a fully serialised `SigEntry` including both signatures and struct overhead.
pub const SIG_ENTRY_SIZE_BYTES: usize = 34515;

/// Blake3 transaction hash length in bytes.
pub const TX_HASH_LEN: usize = 32;

/// On-chain address length in bytes (derived from public-key hash).
pub const ADDRESS_LEN: usize = 32;

/// Canonical batch size for the ingestion pipeline.
pub const BATCH_SIZE: usize = 32;

// ── Public re-exports ────────────────────────────────────────────────────────

pub use error::{CryptoError, MempoolError};
pub use ingestion::{IngestionPipeline, IngestResult, IngestItem};
pub use metrics::{IngestionMetrics, SigCacheMetrics};
pub use pool::TxPool;
pub use sig_cache::{HydraXSigCache, SigCacheConfig, SigOrLocation};
pub use types::{
    Address, ColdSigEntry, HydraXSignature, PooledTx, RawTransaction, SigEntry, SigStatus,
    TxHash, now_ms,
};
