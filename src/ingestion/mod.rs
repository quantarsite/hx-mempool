//! Transaction ingestion pipeline for HYDRA-X.
//!
//! Exports the [`HydraXVerifier`] trait, the production [`PqCryptoVerifier`],
//! the [`MockVerifier`] (cfg(test) / feature = "test-helpers"), and the
//! [`IngestionPipeline`] with its associated [`IngestResult`] and [`IngestItem`]
//! types.

pub mod crypto;
pub mod pipeline;

pub use crypto::{HydraXVerifier, PqCryptoVerifier};
pub use pipeline::{IngestItem, IngestResult, IngestionPipeline};

#[cfg(any(test, feature = "test-helpers"))]
pub use crypto::MockVerifier;
