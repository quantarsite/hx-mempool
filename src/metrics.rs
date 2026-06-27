//! Lock-free atomic metrics for the HYDRA-X mempool.
//!
//! All counters use `AtomicI64` or `AtomicU64` directly — no prometheus or
//! metrics-crate dependency in hot paths.  A [`SigCacheMetrics::gather`] method
//! serialises everything to a `HashMap<String, i64>` for exposition to an
//! external collector.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// ── SigCacheMetrics ───────────────────────────────────────────────────────────

/// Atomic counters for the two-tier signature cache.
///
/// All fields are public so operator dashboards can read individual gauges
/// without going through `gather()`.
#[derive(Debug)]
pub struct SigCacheMetrics {
    /// Total number of hot-tier cache hits.
    pub hot_hits: AtomicU64,
    /// Total number of cold-tier cache hits (entry had to be re-promoted).
    pub cold_hits: AtomicU64,
    /// Total number of cache misses (entry absent from both tiers).
    pub misses: AtomicU64,
    /// Total number of entries inserted into the hot tier.
    pub hot_inserts: AtomicU64,
    /// Total number of entries inserted into the cold tier.
    pub cold_inserts: AtomicU64,
    /// Number of entries evicted from the hot tier by the CLOCK algorithm.
    pub hot_evictions: AtomicU64,
    /// Number of entries evicted from the cold tier (e.g. after block finalisation).
    pub cold_evictions: AtomicU64,
    /// Number of entries dropped entirely (both tiers full, no cold configured).
    pub dropped: AtomicU64,
    /// Current approximate byte occupancy of the hot tier.
    pub hot_bytes_used: AtomicI64,
    /// Current approximate number of entries in the hot tier.
    pub hot_entry_count: AtomicI64,
    /// Current approximate number of entries in the cold tier.
    pub cold_entry_count: AtomicI64,
    /// Number of on_block_finalized calls processed.
    pub finalization_events: AtomicU64,
    /// Number of individual tx hashes cleared during finalization.
    pub finalized_cleared: AtomicU64,
}

impl Default for SigCacheMetrics {
    fn default() -> Self {
        Self {
            hot_hits: AtomicU64::new(0),
            cold_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            hot_inserts: AtomicU64::new(0),
            cold_inserts: AtomicU64::new(0),
            hot_evictions: AtomicU64::new(0),
            cold_evictions: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            hot_bytes_used: AtomicI64::new(0),
            hot_entry_count: AtomicI64::new(0),
            cold_entry_count: AtomicI64::new(0),
            finalization_events: AtomicU64::new(0),
            finalized_cleared: AtomicU64::new(0),
        }
    }
}

impl SigCacheMetrics {
    /// Serialises all counters to a flat map suitable for Prometheus text
    /// format, OpenTelemetry, or logging.
    ///
    /// All values are returned as `i64` (signed) so that gauges that can
    /// decrease (e.g. `hot_bytes_used`) don't require special handling.
    pub fn gather(&self) -> HashMap<String, i64> {
        let mut m = HashMap::with_capacity(16);
        m.insert("hx_sig_cache_hot_hits_total".into(),
            self.hot_hits.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_cold_hits_total".into(),
            self.cold_hits.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_misses_total".into(),
            self.misses.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_hot_inserts_total".into(),
            self.hot_inserts.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_cold_inserts_total".into(),
            self.cold_inserts.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_hot_evictions_total".into(),
            self.hot_evictions.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_cold_evictions_total".into(),
            self.cold_evictions.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_dropped_total".into(),
            self.dropped.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_hot_bytes_used".into(),
            self.hot_bytes_used.load(Ordering::Relaxed));
        m.insert("hx_sig_cache_hot_entry_count".into(),
            self.hot_entry_count.load(Ordering::Relaxed));
        m.insert("hx_sig_cache_cold_entry_count".into(),
            self.cold_entry_count.load(Ordering::Relaxed));
        m.insert("hx_sig_cache_finalization_events_total".into(),
            self.finalization_events.load(Ordering::Relaxed) as i64);
        m.insert("hx_sig_cache_finalized_cleared_total".into(),
            self.finalized_cleared.load(Ordering::Relaxed) as i64);
        m
    }

    // ── Convenience increment helpers ─────────────────────────────────────

    #[inline] pub fn inc_hot_hit(&self)       { self.hot_hits.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_cold_hit(&self)      { self.cold_hits.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_miss(&self)          { self.misses.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_hot_insert(&self)    { self.hot_inserts.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_cold_insert(&self)   { self.cold_inserts.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_hot_eviction(&self)  { self.hot_evictions.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_cold_eviction(&self) { self.cold_evictions.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_dropped(&self)       { self.dropped.fetch_add(1, Ordering::Relaxed); }

    #[inline]
    pub fn add_hot_bytes(&self, bytes: i64) {
        self.hot_bytes_used.fetch_add(bytes, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_hot_entries(&self, delta: i64) {
        self.hot_entry_count.fetch_add(delta, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_cold_entries(&self, delta: i64) {
        self.cold_entry_count.fetch_add(delta, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_finalization_event(&self) {
        self.finalization_events.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_finalized_cleared(&self, n: u64) {
        self.finalized_cleared.fetch_add(n, Ordering::Relaxed);
    }
}

// ── IngestionMetrics ──────────────────────────────────────────────────────────

/// Atomic counters for the ingestion pipeline.
#[derive(Debug)]
pub struct IngestionMetrics {
    /// Total number of transactions submitted for ingestion.
    pub submitted: AtomicU64,
    /// Total number of transactions accepted into the pool.
    pub accepted: AtomicU64,
    /// Total number of transactions rejected (crypto failure or config).
    pub rejected: AtomicU64,
    /// Total number of duplicate submissions (already in pool).
    pub duplicates: AtomicU64,
    /// Total number of transactions rejected due to address mismatch.
    pub address_mismatches: AtomicU64,
    /// Cumulative ML-DSA-87 verification failures.
    pub ml_dsa_failures: AtomicU64,
    /// Cumulative SLH-DSA-256s verification failures.
    pub slh_dsa_failures: AtomicU64,
    /// Total batches processed.
    pub batches_processed: AtomicU64,
    /// Cumulative microseconds spent in the parallel verify phase.
    pub verify_micros_total: AtomicU64,
}

impl Default for IngestionMetrics {
    fn default() -> Self {
        Self {
            submitted: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            address_mismatches: AtomicU64::new(0),
            ml_dsa_failures: AtomicU64::new(0),
            slh_dsa_failures: AtomicU64::new(0),
            batches_processed: AtomicU64::new(0),
            verify_micros_total: AtomicU64::new(0),
        }
    }
}

impl IngestionMetrics {
    /// Serialises all counters.
    pub fn gather(&self) -> HashMap<String, i64> {
        let mut m = HashMap::with_capacity(10);
        m.insert("hx_ingest_submitted_total".into(),
            self.submitted.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_accepted_total".into(),
            self.accepted.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_rejected_total".into(),
            self.rejected.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_duplicates_total".into(),
            self.duplicates.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_address_mismatches_total".into(),
            self.address_mismatches.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_ml_dsa_failures_total".into(),
            self.ml_dsa_failures.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_slh_dsa_failures_total".into(),
            self.slh_dsa_failures.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_batches_processed_total".into(),
            self.batches_processed.load(Ordering::Relaxed) as i64);
        m.insert("hx_ingest_verify_micros_total".into(),
            self.verify_micros_total.load(Ordering::Relaxed) as i64);
        m
    }

    #[inline] pub fn add_submitted(&self, n: u64) { self.submitted.fetch_add(n, Ordering::Relaxed); }
    #[inline] pub fn inc_accepted(&self)           { self.accepted.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_rejected(&self)           { self.rejected.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_duplicate(&self)          { self.duplicates.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_address_mismatch(&self)   { self.address_mismatches.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_ml_dsa_failure(&self)     { self.ml_dsa_failures.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_slh_dsa_failure(&self)    { self.slh_dsa_failures.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn inc_batch(&self)              { self.batches_processed.fetch_add(1, Ordering::Relaxed); }
    #[inline] pub fn add_verify_micros(&self, us: u64) {
        self.verify_micros_total.fetch_add(us, Ordering::Relaxed);
    }
}
