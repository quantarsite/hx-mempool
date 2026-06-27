//! Ingestion pipeline for HYDRA-X transactions.
//!
//! [`IngestionPipeline`] accepts batches of raw transactions, verifies their
//! post-quantum signatures in parallel via a dedicated `rayon` thread pool,
//! and commits accepted transactions to the [`TxPool`] and [`HydraXSigCache`].
//!
//! ## Processing model
//!
//! ```text
//! ingest_batch(items)
//!   └── split into chunks of BATCH_SIZE (32)
//!         └── process_chunk(chunk)                    [rayon par_iter]
//!               ├── verify_address_derivation(tx)
//!               ├── rayon::join(verify_ml_dsa87, verify_slh_dsa_256s)
//!               └── AND-gate → IngestResult
//!   └── serial commit phase
//!         ├── pool.insert(tx)                         [for each Accepted]
//!         └── sig_cache.insert(hash, sig_entry)       [for each Accepted]
//! ```

use std::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;

use crate::error::{CryptoError, MempoolError};
use crate::metrics::IngestionMetrics;
use crate::pool::TxPool;
use crate::sig_cache::HydraXSigCache;
use crate::types::{HydraXSignature, PooledTx, RawTransaction, SigEntry, TxHash};
use crate::BATCH_SIZE;

use super::crypto::HydraXVerifier;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single item submitted for ingestion: a raw transaction plus its
/// AND-composed post-quantum signature.
pub type IngestItem = (RawTransaction, HydraXSignature);

/// The result of attempting to ingest a single transaction.
#[derive(Debug)]
pub enum IngestResult {
    /// The transaction passed all checks and was admitted to the pool.
    Accepted { hash: TxHash },
    /// The transaction failed cryptographic verification.
    Rejected { reason: CryptoError },
    /// The transaction is already present in the pool.
    Duplicate { hash: TxHash },
}

// ── IngestionPipeline ─────────────────────────────────────────────────────────

/// Parallel ingestion pipeline with a dedicated rayon thread pool.
///
/// Generic over `V: HydraXVerifier` so tests can inject a `MockVerifier`
/// without any production-code changes.
pub struct IngestionPipeline<V: HydraXVerifier> {
    pool: Arc<TxPool>,
    sig_cache: Arc<HydraXSigCache>,
    verifier: Arc<V>,
    /// Dedicated rayon thread pool, isolated from the global pool to prevent
    /// ingestion from starving other rayon users (e.g. block builder).
    thread_pool: rayon::ThreadPool,
    metrics: Arc<IngestionMetrics>,
}

impl<V: HydraXVerifier + 'static> IngestionPipeline<V> {
    /// Constructs a new `IngestionPipeline`.
    ///
    /// # Arguments
    ///
    /// * `pool` — the shared transaction pool.
    /// * `sig_cache` — the shared signature cache.
    /// * `verifier` — the PQ verifier implementation.
    /// * `num_threads` — number of threads in the dedicated rayon pool.
    ///   Pass `0` to use the rayon default (number of logical CPUs).
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::ThreadPoolBuildError`] if rayon cannot create
    /// the thread pool.
    pub fn new(
        pool: Arc<TxPool>,
        sig_cache: Arc<HydraXSigCache>,
        verifier: Arc<V>,
        num_threads: usize,
    ) -> Result<Self, MempoolError> {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("hx-ingest-{i}"));
        if num_threads > 0 {
            builder = builder.num_threads(num_threads);
        }
        let thread_pool = builder
            .build()
            .map_err(|e| MempoolError::ThreadPoolBuildError(e.to_string()))?;

        Ok(Self {
            pool,
            sig_cache,
            verifier,
            thread_pool,
            metrics: Arc::new(IngestionMetrics::default()),
        })
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Ingests a batch of transactions.
    ///
    /// Items are processed in chunks of [`BATCH_SIZE`] (32).  Within each
    /// chunk, all items are verified in parallel on the dedicated thread pool.
    /// After verification, accepted items are committed serially to avoid
    /// race conditions between the pool and the sig cache.
    ///
    /// Returns one [`IngestResult`] per input item in the same order.
    pub fn ingest_batch(&self, items: Vec<IngestItem>) -> Vec<IngestResult> {
        let total = items.len();
        self.metrics.add_submitted(total as u64);
        self.metrics.inc_batch();

        let mut results = Vec::with_capacity(total);

        for chunk in items.chunks(BATCH_SIZE) {
            let chunk_results = self.process_chunk(chunk);
            for result in &chunk_results {
                match result {
                    IngestResult::Accepted { .. } => self.metrics.inc_accepted(),
                    IngestResult::Rejected { .. } => self.metrics.inc_rejected(),
                    IngestResult::Duplicate { .. } => self.metrics.inc_duplicate(),
                }
            }
            results.extend(chunk_results);
        }

        results
    }

    /// Ingests a single transaction.
    ///
    /// Convenience wrapper around [`ingest_batch`][Self::ingest_batch].
    pub fn ingest_one(&self, item: IngestItem) -> IngestResult {
        self.ingest_batch(vec![item])
            .into_iter()
            .next()
            // SAFETY: ingest_batch always returns exactly one result when
            // given exactly one item.
            .expect("ingest_batch always returns one result per input")
    }

    /// Returns a reference to the ingestion metrics.
    pub fn metrics(&self) -> &IngestionMetrics {
        &self.metrics
    }

    // ── Verification helpers ──────────────────────────────────────────────

    /// Verifies that `BLAKE3(ml_pk || slh_pk)[0..32] == tx.sender`.
    ///
    /// This prevents an attacker from stealing funds by submitting a valid
    /// signature under a different key pair than the one that owns the account.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AddressMismatch`] if derivation fails.
    pub fn verify_address_derivation(tx: &RawTransaction) -> Result<(), CryptoError> {
        let derived = tx.derived_sender();
        if derived != tx.sender {
            tracing::debug!(
                "address mismatch: sender={} derived={}",
                format_addr(&tx.sender),
                format_addr(&derived)
            );
            return Err(CryptoError::AddressMismatch);
        }
        Ok(())
    }

    // ── Internal processing ───────────────────────────────────────────────

    /// Processes a single chunk of at most [`BATCH_SIZE`] items.
    ///
    /// Phase 1 (parallel): address derivation + dual signature verification.
    /// Phase 2 (serial): commit valid items to pool + cache.
    fn process_chunk(&self, chunk: &[IngestItem]) -> Vec<IngestResult> {
        let start = Instant::now();

        // ── Phase 1: parallel verification ───────────────────────────────
        let verifier = Arc::clone(&self.verifier);
        let pool_ref = Arc::clone(&self.pool);

        // Run verification inside the dedicated thread pool.
        let verify_results: Vec<VerifyOutcome> = self.thread_pool.install(|| {
            chunk
                .par_iter()
                .map(|(tx, sig)| {
                    let hash = tx.hash();

                    // Fast-path: duplicate check before heavy crypto.
                    if pool_ref.contains(&hash) {
                        return VerifyOutcome::Duplicate { hash };
                    }

                    // Address derivation (cheap, BLAKE3 hash).
                    if let Err(e) = Self::verify_address_derivation(tx) {
                        return VerifyOutcome::Failed { reason: e };
                    }

                    // AND-composition: ML-DSA-87 ‖ SLH-DSA-256s in parallel.
                    let signing_bytes = tx.signing_bytes();
                    let ml_pk = &tx.sender_ml_dsa_pk;
                    let slh_pk = &tx.sender_slh_dsa_pk;

                    match verifier.verify_hydra_x(&signing_bytes, sig, ml_pk, slh_pk) {
                        Ok(()) => VerifyOutcome::Ok { hash },
                        Err(e) => VerifyOutcome::Failed { reason: e },
                    }
                })
                .collect()
        });

        let verify_us = start.elapsed().as_micros() as u64;
        self.metrics.add_verify_micros(verify_us);

        // ── Phase 2: serial commit ────────────────────────────────────────
        // We commit serially to keep pool + cache updates atomic per tx.
        let mut results = Vec::with_capacity(chunk.len());

        for (idx, outcome) in verify_results.into_iter().enumerate() {
            let (tx, sig) = &chunk[idx];

            match outcome {
                VerifyOutcome::Ok { hash } => {
                    // Final duplicate check inside the serial commit to handle
                    // races between parallel verify and a concurrent ingest.
                    if self.pool.contains(&hash) {
                        self.metrics.inc_duplicate();
                        results.push(IngestResult::Duplicate { hash });
                        continue;
                    }

                    // Commit to pool.
                    let pooled = PooledTx::from_raw(tx);
                    self.pool.insert(pooled);

                    // Commit to sig cache.
                    let sig_entry = SigEntry::new(
                        sig.ml_dsa87.clone(),
                        sig.slh_dsa.clone(),
                        tx.fee_per_gas,
                    );
                    if let Err(e) = self.sig_cache.insert(hash, sig_entry) {
                        // Cache insert failure is non-fatal: the tx is in the
                        // pool but its sig_status will remain Pending until the
                        // next insertion attempt succeeds.
                        tracing::warn!(
                            error = %e,
                            hash = %format_hash(&hash),
                            "sig cache insert failed; tx admitted without cached sig"
                        );
                    }

                    tracing::debug!(
                        hash = %format_hash(&hash),
                        fee_per_gas = tx.fee_per_gas,
                        "transaction accepted"
                    );
                    results.push(IngestResult::Accepted { hash });
                }

                VerifyOutcome::Failed { reason } => {
                    // Record per-algorithm failure counters.
                    match &reason {
                        CryptoError::MlDsa87VerificationFailed => {
                            self.metrics.inc_ml_dsa_failure();
                        }
                        CryptoError::SlhDsa256sVerificationFailed => {
                            self.metrics.inc_slh_dsa_failure();
                        }
                        CryptoError::BothLegsFailed => {
                            self.metrics.inc_ml_dsa_failure();
                            self.metrics.inc_slh_dsa_failure();
                        }
                        CryptoError::AddressMismatch => {
                            self.metrics.inc_address_mismatch();
                        }
                        _ => {}
                    }
                    tracing::debug!(
                        error = %reason,
                        "transaction rejected"
                    );
                    results.push(IngestResult::Rejected { reason });
                }

                VerifyOutcome::Duplicate { hash } => {
                    results.push(IngestResult::Duplicate { hash });
                }
            }
        }

        results
    }
}

// ── Internal outcome type ─────────────────────────────────────────────────────

/// Internal result of the parallel verification phase.
///
/// Using a separate enum avoids cloning `RawTransaction`/`HydraXSignature`
/// into the parallel closure — we only need the hash on success.
enum VerifyOutcome {
    Ok { hash: TxHash },
    Failed { reason: CryptoError },
    Duplicate { hash: TxHash },
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn format_hash(hash: &TxHash) -> String {
    hash.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn format_addr(addr: &[u8]) -> String {
    addr.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::crypto::MockVerifier;
    use crate::sig_cache::{HydraXSigCache, SigCacheConfig, SigOrLocation};
    use crate::types::test_helpers::{make_hydra_x_sig, make_raw_tx};
    use crate::types::SigStatus;
    use crate::SIG_ENTRY_SIZE_BYTES;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn make_pipeline(
        verifier: MockVerifier,
        hot_entries: usize,
    ) -> (IngestionPipeline<MockVerifier>, Arc<TxPool>, Arc<HydraXSigCache>) {
        let pool = Arc::new(TxPool::new());
        let config = SigCacheConfig {
            hot_capacity_bytes: (hot_entries * SIG_ENTRY_SIZE_BYTES).max(1) as u64,
            hot_window_ms: 60_000,
            cold_path: None,
            policy: crate::sig_cache::policy::EvictionPolicy::Lru,
            eviction_trigger_pct: 85,
        };
        let sig_cache = Arc::new(
            HydraXSigCache::new(config, Arc::clone(&pool)).unwrap(),
        );
        let pipeline = IngestionPipeline::new(
            Arc::clone(&pool),
            Arc::clone(&sig_cache),
            Arc::new(verifier),
            2, // 2 threads for test speed
        )
        .unwrap();
        (pipeline, pool, sig_cache)
    }

    fn make_items(seeds: &[u8]) -> Vec<IngestItem> {
        seeds
            .iter()
            .map(|&s| (make_raw_tx(s), make_hydra_x_sig(s)))
            .collect()
    }

    // ── test_batch_accepted_all ───────────────────────────────────────────

    #[test]
    fn test_batch_accepted_all() {
        let seeds: Vec<u8> = (1..=BATCH_SIZE as u8).collect();
        let (pipeline, pool, _cache) = make_pipeline(MockVerifier::default(), BATCH_SIZE * 2);

        let items = make_items(&seeds);
        let results = pipeline.ingest_batch(items);

        assert_eq!(results.len(), BATCH_SIZE);
        let accepted = results
            .iter()
            .filter(|r| matches!(r, IngestResult::Accepted { .. }))
            .count();
        assert_eq!(
            accepted, BATCH_SIZE,
            "all {BATCH_SIZE} transactions should be accepted"
        );
        assert_eq!(pool.len(), BATCH_SIZE);
        assert_eq!(
            pipeline.metrics().accepted.load(std::sync::atomic::Ordering::Relaxed),
            BATCH_SIZE as u64
        );
    }

    // ── test_batch_partial_failure ────────────────────────────────────────

    #[test]
    fn test_batch_partial_failure() {
        // We submit 9 transactions.
        // Seeds 1..=3: succeed (MockVerifier passes both legs by default)
        // Seeds 4..=6: ML-DSA fails  → we achieve this by building a bespoke
        //   item with bad ML sig length (triggers InvalidMlDsa87SigLen which
        //   the mock also checks). Easiest: override at item level.
        // Seeds 7..=9: SLH-DSA fails.

        let (pipeline, pool, _cache) =
            make_pipeline(MockVerifier::default(), 64);

        // Good items (seeds 1..=3)
        let mut items: Vec<IngestItem> = make_items(&[1, 2, 3]);

        // ML-DSA-fail items: real seeds but wrong ml sig length to trigger
        // the length check in MockVerifier.
        for seed in 4u8..=6 {
            let tx = make_raw_tx(seed);
            let mut sig = make_hydra_x_sig(seed);
            sig.ml_dsa87 = vec![0u8; 10]; // wrong length → MockVerifier rejects
            items.push((tx, sig));
        }

        // SLH-DSA-fail items: wrong slh sig length.
        for seed in 7u8..=9 {
            let tx = make_raw_tx(seed);
            let mut sig = make_hydra_x_sig(seed);
            sig.slh_dsa = vec![0u8; 5]; // wrong length
            items.push((tx, sig));
        }

        let results = pipeline.ingest_batch(items);
        assert_eq!(results.len(), 9);

        let accepted: Vec<_> = results
            .iter()
            .filter(|r| matches!(r, IngestResult::Accepted { .. }))
            .collect();
        let rejected: Vec<_> = results
            .iter()
            .filter(|r| matches!(r, IngestResult::Rejected { .. }))
            .collect();

        assert_eq!(accepted.len(), 3, "exactly 3 should be accepted");
        assert_eq!(rejected.len(), 6, "exactly 6 should be rejected");
        assert_eq!(pool.len(), 3);
    }

    // ── test_batch_duplicate_rejected ────────────────────────────────────

    #[test]
    fn test_batch_duplicate_rejected() {
        let (pipeline, pool, _cache) = make_pipeline(MockVerifier::default(), 64);

        // First submission.
        let items = make_items(&[42]);
        let r1 = pipeline.ingest_batch(items);
        assert!(matches!(r1[0], IngestResult::Accepted { .. }));

        // Second submission of the same tx.
        let items2 = make_items(&[42]);
        let r2 = pipeline.ingest_batch(items2);
        assert!(
            matches!(r2[0], IngestResult::Duplicate { .. }),
            "second submission should be a duplicate"
        );

        assert_eq!(pool.len(), 1, "pool should still have only one entry");
        assert_eq!(
            pipeline.metrics().duplicates.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    // ── test_address_mismatch_rejected ────────────────────────────────────

    #[test]
    fn test_address_mismatch_rejected() {
        let (pipeline, pool, _cache) = make_pipeline(MockVerifier::default(), 64);

        // Manually construct a tx with a sender that does NOT match the key hash.
        let mut tx = make_raw_tx(10);
        tx.sender = [0xAA; 32]; // Wrong address — BLAKE3 hash of keys is different.

        let items = vec![(tx, make_hydra_x_sig(10))];
        let results = pipeline.ingest_batch(items);

        assert!(matches!(
            results[0],
            IngestResult::Rejected {
                reason: CryptoError::AddressMismatch
            }
        ));
        assert_eq!(pool.len(), 0);
        assert_eq!(
            pipeline.metrics().address_mismatches.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    // ── test_sig_lands_in_hot_cache ───────────────────────────────────────

    #[test]
    fn test_sig_lands_in_hot_cache() {
        let (pipeline, _pool, sig_cache) = make_pipeline(MockVerifier::default(), 64);

        let tx = make_raw_tx(20);
        let hash = tx.hash();
        let sig = make_hydra_x_sig(20);
        pipeline.ingest_batch(vec![(tx, sig)]);

        assert!(
            matches!(sig_cache.get(&hash), SigOrLocation::Hot(_)),
            "accepted tx's signature should be in the hot cache"
        );
    }

    // ── test_sig_status_verified ──────────────────────────────────────────

    #[test]
    fn test_sig_status_verified() {
        let (pipeline, pool, _cache) = make_pipeline(MockVerifier::default(), 64);

        let tx = make_raw_tx(30);
        let hash = tx.hash();
        pipeline.ingest_batch(vec![(tx, make_hydra_x_sig(30))]);

        let pooled = pool.get(&hash).expect("tx should be in pool");
        assert_eq!(
            pooled.sig_status,
            SigStatus::Verified,
            "sig_status should be Verified after successful ingest"
        );
    }

    // ── test_mock_fail_ml_dsa_all ─────────────────────────────────────────

    #[test]
    fn test_mock_fail_ml_dsa_all() {
        let verifier = MockVerifier { fail_ml_dsa: true, ..Default::default() };
        let (pipeline, pool, _) = make_pipeline(verifier, 64);

        let items = make_items(&[1, 2, 3]);
        let results = pipeline.ingest_batch(items);

        assert!(results.iter().all(|r| matches!(r, IngestResult::Rejected { .. })));
        assert_eq!(pool.len(), 0);
    }

    // ── test_mock_fail_slh_dsa_all ────────────────────────────────────────

    #[test]
    fn test_mock_fail_slh_dsa_all() {
        let verifier = MockVerifier { fail_slh_dsa: true, ..Default::default() };
        let (pipeline, pool, _) = make_pipeline(verifier, 64);

        let items = make_items(&[1, 2, 3]);
        let results = pipeline.ingest_batch(items);

        assert!(results.iter().all(|r| matches!(r, IngestResult::Rejected { .. })));
        assert_eq!(pool.len(), 0);
    }

    // ── test_large_batch_spans_multiple_chunks ────────────────────────────

    #[test]
    fn test_large_batch_spans_multiple_chunks() {
        // Submit 3× BATCH_SIZE items to ensure chunking logic is exercised.
        let n = (BATCH_SIZE * 3) as u8;
        let seeds: Vec<u8> = (1..=n).collect();
        let (pipeline, pool, _) = make_pipeline(MockVerifier::default(), n as usize * 2);

        let items = make_items(&seeds);
        let results = pipeline.ingest_batch(items);

        let accepted = results
            .iter()
            .filter(|r| matches!(r, IngestResult::Accepted { .. }))
            .count();
        assert_eq!(accepted, n as usize);
        assert_eq!(pool.len(), n as usize);
    }

    // ── test_ingest_one_accepted ──────────────────────────────────────────

    #[test]
    fn test_ingest_one_accepted() {
        let (pipeline, pool, _) = make_pipeline(MockVerifier::default(), 64);
        let tx = make_raw_tx(99);
        let hash = tx.hash();
        let result = pipeline.ingest_one((tx, make_hydra_x_sig(99)));
        assert!(matches!(result, IngestResult::Accepted { hash: h } if h == hash));
        assert_eq!(pool.len(), 1);
    }
}
