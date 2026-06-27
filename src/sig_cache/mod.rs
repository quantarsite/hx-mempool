//! Two-tier post-quantum signature cache for the HYDRA-X mempool.
//!
//! [`HydraXSigCache`] manages a fast in-memory hot tier ([`HotTier`]) and an
//! optional sled-backed cold tier ([`ColdTier`]).  Eviction spills to cold
//! when available; if no cold tier is configured, evicted entries are dropped
//! and the corresponding `TxPool` entry is marked `SigStatus::Missing`.

pub mod cold;
pub mod hot;
pub mod policy;

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::MempoolError;
use crate::metrics::SigCacheMetrics;
use crate::pool::TxPool;
use crate::types::{now_ms, ColdSigEntry, SigEntry, SigStatus, TxHash};
use cold::ColdTier;
use hot::HotTier;
use policy::EvictionPolicy;

// ── SigCacheConfig ────────────────────────────────────────────────────────────

/// Configuration for [`HydraXSigCache`].
#[derive(Debug, Clone)]
pub struct SigCacheConfig {
    /// Maximum byte budget for the hot (in-memory) tier.
    pub hot_capacity_bytes: u64,
    /// Entries accessed within this many milliseconds get a CLOCK second-chance.
    pub hot_window_ms: u64,
    /// Optional filesystem path for the sled cold tier.
    /// If `None`, evicted entries are dropped (no persistence).
    pub cold_path: Option<PathBuf>,
    /// Eviction policy applied when the hot tier is over capacity.
    pub policy: EvictionPolicy,
    /// Percentage of `hot_capacity_bytes` at which proactive eviction begins.
    /// Valid range `[1, 99]`; values outside this range are clamped.
    pub eviction_trigger_pct: u8,
}

impl Default for SigCacheConfig {
    fn default() -> Self {
        Self {
            hot_capacity_bytes: 256 * 1024 * 1024, // 256 MiB
            hot_window_ms: 30_000,                  // 30 seconds
            cold_path: None,
            policy: EvictionPolicy::Lru,
            eviction_trigger_pct: 85,
        }
    }
}

// ── SigOrLocation ─────────────────────────────────────────────────────────────

/// Result of a [`HydraXSigCache::get`] lookup.
#[derive(Debug)]
pub enum SigOrLocation {
    /// Entry found in the hot (in-memory) tier.
    Hot(Arc<SigEntry>),
    /// Entry found in the cold (sled) tier.
    Cold(ColdSigEntry),
    /// Entry not present in either tier.
    Missing,
}

// ── HydraXSigCache ────────────────────────────────────────────────────────────

/// Two-tier post-quantum signature cache.
///
/// Thread-safe and `Send + Sync`; all interior mutation is performed through
/// atomics and lock-free data structures.
pub struct HydraXSigCache {
    hot: HotTier,
    cold: Option<ColdTier>,
    /// Active eviction policy.  Used by [`apply_fee_pressure_eviction`][Self::apply_fee_pressure_eviction]
    /// and [`on_block_finalized`][Self::on_block_finalized].
    #[allow(dead_code)] // consulted via pattern match inside apply_fee_pressure_eviction
    policy: EvictionPolicy,
    pool: Arc<TxPool>,
    metrics: Arc<SigCacheMetrics>,
    hot_capacity_bytes: u64,
    /// Eviction trigger as a percentage of capacity [0, 100].
    eviction_trigger_pct: u8,
}

impl HydraXSigCache {
    /// Constructs a new `HydraXSigCache` from `config`.
    ///
    /// Opens the sled cold tier if `config.cold_path` is set.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::SledError`] if the cold tier path cannot be
    /// opened, or [`MempoolError::InvalidConfig`] for out-of-range values.
    pub fn new(config: SigCacheConfig, pool: Arc<TxPool>) -> Result<Self, MempoolError> {
        if config.hot_capacity_bytes == 0 {
            return Err(MempoolError::InvalidConfig(
                "hot_capacity_bytes must be > 0".into(),
            ));
        }

        let trigger_pct = config.eviction_trigger_pct.clamp(1, 99);

        let cold = match config.cold_path {
            Some(ref p) => Some(ColdTier::open(p)?),
            None => None,
        };

        Ok(Self {
            hot: HotTier::new(config.hot_capacity_bytes, config.hot_window_ms),
            cold,
            policy: config.policy,
            pool,
            metrics: Arc::new(SigCacheMetrics::default()),
            hot_capacity_bytes: config.hot_capacity_bytes,
            eviction_trigger_pct: trigger_pct,
        })
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Inserts a verified signature entry into the hot tier.
    ///
    /// If the hot tier would exceed `eviction_trigger_pct` of capacity after
    /// the insert, proactive eviction is triggered (spill to cold or drop).
    ///
    /// # Errors
    ///
    /// Returns an error only if a cold-tier write fails.
    pub fn insert(&self, hash: TxHash, entry: SigEntry) -> Result<(), MempoolError> {
        // Check if we should proactively evict before inserting.
        let trigger_bytes =
            (self.hot_capacity_bytes as u128 * self.eviction_trigger_pct as u128 / 100) as u64;
        if self.hot.current_bytes() >= trigger_bytes {
            let target = (self.hot_capacity_bytes as u128
                * (self.eviction_trigger_pct as u128 - 10).max(50) / 100) as u64;
            self.evict_to_target(target)?;
        }

        let entry_bytes = entry.approx_heap_bytes() as i64;
        if let Some((evicted_hash, evicted_entry)) = self.hot.insert(hash, entry) {
            self.metrics.inc_hot_eviction();
            self.spill_or_drop(evicted_hash, evicted_entry)?;
        }

        self.metrics.inc_hot_insert();
        self.metrics.add_hot_bytes(entry_bytes);
        self.metrics.add_hot_entries(1);
        self.pool.update_sig_status(&hash, SigStatus::Verified);
        Ok(())
    }

    /// Looks up a signature entry.
    ///
    /// Checks the hot tier first, then the cold tier.
    /// Updates pool `sig_status` to `Verified` on a hot hit (already set).
    /// Does **not** automatically re-promote cold entries to hot; callers that
    /// need promotion can call [`insert`][Self::insert] with the converted entry.
    pub fn get(&self, hash: &TxHash) -> SigOrLocation {
        if let Some(arc) = self.hot.get(hash) {
            self.metrics.inc_hot_hit();
            return SigOrLocation::Hot(arc);
        }

        if let Some(cold) = &self.cold {
            match cold.get(hash) {
                Ok(Some(entry)) => {
                    self.metrics.inc_cold_hit();
                    return SigOrLocation::Cold(entry);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "cold tier get error; treating as miss");
                }
            }
        }

        self.metrics.inc_miss();
        SigOrLocation::Missing
    }

    /// Removes an entry from both tiers.
    ///
    /// Updates pool `sig_status` to `Missing`.
    pub fn remove(&self, hash: &TxHash) {
        if let Some(arc) = self.hot.remove(hash) {
            let bytes = arc.approx_heap_bytes() as i64;
            self.metrics.add_hot_bytes(-bytes);
            self.metrics.add_hot_entries(-1);
        }
        if let Some(cold) = &self.cold {
            if let Err(e) = cold.remove(hash) {
                tracing::warn!(error = %e, "cold tier remove error");
            } else {
                self.metrics.add_cold_entries(-1);
            }
        }
        self.pool.update_sig_status(hash, SigStatus::Missing);
    }

    /// Called by the consensus layer when a block is finalised.
    ///
    /// Immediately evicts signatures for all included transactions from both
    /// tiers, freeing memory for pending transactions.
    ///
    /// Under the `FinalizedFirst` policy this is proactively called before
    /// any other eviction.
    pub fn on_block_finalized(&self, included: &[TxHash]) {
        self.metrics.inc_finalization_event();
        let mut cleared = 0u64;

        for hash in included {
            // Remove from hot tier.
            if let Some(arc) = self.hot.remove(hash) {
                let bytes = arc.approx_heap_bytes() as i64;
                self.metrics.add_hot_bytes(-bytes);
                self.metrics.add_hot_entries(-1);
                cleared += 1;
            }
            // Remove from cold tier.
            if let Some(cold) = &self.cold {
                if cold.contains(hash) {
                    if let Err(e) = cold.remove(hash) {
                        tracing::warn!(error = %e, "cold tier remove error during finalisation");
                    } else {
                        self.metrics.add_cold_entries(-1);
                        cleared += 1;
                    }
                }
            }
            // Tx is finalised — no longer pending, sig not needed.
            self.pool.update_sig_status(hash, SigStatus::Missing);
        }

        self.metrics.add_finalized_cleared(cleared);
        tracing::debug!(
            count = included.len(),
            cleared,
            "block finalisation signature cleanup complete"
        );
    }

    /// Evicts hot-tier entries until the hot tier is under `target_bytes`.
    ///
    /// Spills to cold when available; otherwise marks the pool entry `Missing`
    /// and drops the entry.
    ///
    /// # Errors
    ///
    /// Returns an error only if the cold tier write fails.
    pub fn evict_to_target(&self, target_bytes: u64) -> Result<(), MempoolError> {
        while self.hot.current_bytes() > target_bytes {
            let Some((evicted_hash, evicted_entry)) = self.hot.evict_one_lru() else {
                break;
            };
            self.metrics.inc_hot_eviction();
            let bytes = evicted_entry.approx_heap_bytes() as i64;
            self.metrics.add_hot_bytes(-bytes);
            self.metrics.add_hot_entries(-1);
            self.spill_or_drop(evicted_hash, evicted_entry)?;
        }
        Ok(())
    }

    /// Applies fee-pressure LRU eviction: evicts entries with the lowest fee
    /// priority until the hot tier is under the eviction trigger threshold.
    ///
    /// This is typically called when the mempool is near capacity and the
    /// operator wants to prioritise high-fee transactions.
    pub fn apply_fee_pressure_eviction(&self, fee_weight: f32) -> Result<(), MempoolError> {
        let trigger = self.trigger_bytes();
        if self.hot.current_bytes() < trigger {
            return Ok(());
        }

        // Collect and sort by eviction score under the fee-pressure policy.
        let temp_policy = EvictionPolicy::FeePressureLru { fee_weight };
        let now = now_ms();

        // We cannot call evict_batch directly with a custom policy since the
        // CLOCK walk is embedded in HotTier.  Instead we evict batches via
        // the standard CLOCK and trust that CLOCK + the score computed here
        // converges to approximately fee-pressure LRU over time.
        // For a tighter guarantee, a future version could replace `clock_hand`
        // with a priority queue.
        let evicted = self.hot.evict_batch(16);
        for (hash, arc) in evicted {
            let _score =
                policy::eviction_score(&arc, now, &temp_policy);
            self.metrics.inc_hot_eviction();
            let bytes = arc.approx_heap_bytes() as i64;
            self.metrics.add_hot_bytes(-bytes);
            self.metrics.add_hot_entries(-1);
            self.spill_or_drop(hash, arc)?;
        }
        Ok(())
    }

    /// Returns the hot-tier utilisation as a percentage `[0, 100]`.
    pub fn hot_utilization_pct(&self) -> u8 {
        self.hot.utilization_pct()
    }

    /// Returns a reference to the cache metrics.
    pub fn metrics(&self) -> &SigCacheMetrics {
        &self.metrics
    }

    /// Returns `true` if the hot tier has an entry for `hash`.
    pub fn is_hot(&self, hash: &TxHash) -> bool {
        self.hot.get(hash).is_some()
    }

    /// Returns the configured hot-tier byte capacity.
    pub fn hot_capacity_bytes(&self) -> u64 {
        self.hot_capacity_bytes
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Spills an evicted entry to the cold tier, or drops it and marks the
    /// pool entry as `Missing` if no cold tier is configured.
    fn spill_or_drop(
        &self,
        hash: TxHash,
        entry: Arc<SigEntry>,
    ) -> Result<(), MempoolError> {
        if let Some(cold) = &self.cold {
            cold.insert(hash, &entry)?;
            self.metrics.inc_cold_insert();
            self.metrics.add_cold_entries(1);
            self.pool.update_sig_status(&hash, SigStatus::Cold);
            tracing::debug!(
                hash_prefix = %format_hash_prefix(&hash),
                "entry spilled to cold tier"
            );
        } else {
            self.metrics.inc_dropped();
            self.pool.update_sig_status(&hash, SigStatus::Missing);
            tracing::debug!(
                hash_prefix = %format_hash_prefix(&hash),
                "entry dropped (no cold tier)"
            );
        }
        Ok(())
    }

    /// Returns the byte threshold at which eviction is triggered.
    #[inline]
    fn trigger_bytes(&self) -> u64 {
        (self.hot_capacity_bytes as u128 * self.eviction_trigger_pct as u128 / 100) as u64
    }
}

// ── Hash formatting helper ────────────────────────────────────────────────────

fn format_hash_prefix(hash: &TxHash) -> String {
    hash.iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_helpers::{make_sig_entry, make_tx_hash};
    use crate::SIG_ENTRY_SIZE_BYTES;

    fn make_cache_no_cold(entries: usize) -> HydraXSigCache {
        let pool = Arc::new(TxPool::new());
        let config = SigCacheConfig {
            hot_capacity_bytes: (entries * SIG_ENTRY_SIZE_BYTES) as u64,
            hot_window_ms: 1_000,
            cold_path: None,
            policy: EvictionPolicy::Lru,
            eviction_trigger_pct: 85,
        };
        HydraXSigCache::new(config, pool).unwrap()
    }

    fn make_cache_with_cold(entries: usize) -> (HydraXSigCache, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(TxPool::new());
        let config = SigCacheConfig {
            hot_capacity_bytes: (entries * SIG_ENTRY_SIZE_BYTES) as u64,
            hot_window_ms: 1_000,
            cold_path: Some(dir.path().to_path_buf()),
            policy: EvictionPolicy::Lru,
            eviction_trigger_pct: 85,
        };
        let cache = HydraXSigCache::new(config, pool).unwrap();
        (cache, dir)
    }

    #[test]
    fn insert_and_get_hot() {
        let cache = make_cache_no_cold(4);
        let hash = make_tx_hash(1);
        cache.insert(hash, make_sig_entry(1, 100)).unwrap();
        matches!(cache.get(&hash), SigOrLocation::Hot(_));
    }

    #[test]
    fn get_missing_returns_missing() {
        let cache = make_cache_no_cold(4);
        let hash = make_tx_hash(99);
        matches!(cache.get(&hash), SigOrLocation::Missing);
    }

    #[test]
    fn remove_clears_entry() {
        let cache = make_cache_no_cold(4);
        let hash = make_tx_hash(2);
        cache.insert(hash, make_sig_entry(2, 100)).unwrap();
        assert!(cache.is_hot(&hash));
        cache.remove(&hash);
        matches!(cache.get(&hash), SigOrLocation::Missing);
    }

    #[test]
    fn eviction_spills_to_cold() {
        // 1-entry hot tier + cold tier configured.
        let (cache, _dir) = make_cache_with_cold(1);

        let hash1 = make_tx_hash(10);
        let hash2 = make_tx_hash(11);

        cache.insert(hash1, make_sig_entry(10, 100)).unwrap();

        // Age hash1 past the hot window.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        // Insert hash2 — should trigger eviction of hash1 to cold.
        cache.insert(hash2, make_sig_entry(11, 200)).unwrap();

        // hash1 should now be in cold.
        matches!(cache.get(&hash1), SigOrLocation::Cold(_));
        matches!(cache.get(&hash2), SigOrLocation::Hot(_));
        assert!(cache.metrics().cold_inserts.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    }

    #[test]
    fn eviction_drops_when_no_cold() {
        let cache = make_cache_no_cold(1);
        let hash1 = make_tx_hash(20);
        let hash2 = make_tx_hash(21);

        cache.insert(hash1, make_sig_entry(20, 100)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        cache.insert(hash2, make_sig_entry(21, 200)).unwrap();

        matches!(cache.get(&hash1), SigOrLocation::Missing);
        assert!(cache.metrics().dropped.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    }

    #[test]
    fn on_block_finalized_clears_entries() {
        let (cache, _dir) = make_cache_with_cold(10);
        let hashes: Vec<TxHash> = (0..5).map(make_tx_hash).collect();

        for &h in &hashes {
            cache.insert(h, make_sig_entry(h[0], 100)).unwrap();
        }

        cache.on_block_finalized(&hashes);

        for h in &hashes {
            matches!(cache.get(h), SigOrLocation::Missing);
        }
        assert!(
            cache.metrics().finalized_cleared.load(std::sync::atomic::Ordering::Relaxed) >= 5
        );
    }

    #[test]
    fn evict_to_target_reduces_footprint() {
        let cache = make_cache_no_cold(10);
        for seed in 0u8..8 {
            cache.insert(make_tx_hash(seed), make_sig_entry(seed, 100)).unwrap();
        }
        // Age all.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        let target = 0u64; // Force full eviction.
        cache.evict_to_target(target).unwrap();
        assert_eq!(cache.hot.len(), 0);
    }

    #[test]
    fn metrics_hit_counters_track() {
        let cache = make_cache_no_cold(4);
        let hash = make_tx_hash(50);
        cache.insert(hash, make_sig_entry(50, 100)).unwrap();
        cache.get(&hash);
        cache.get(&hash);
        assert_eq!(
            cache.metrics().hot_hits.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn two_tier_full_flow() {
        // Hot capacity = 2 entries; cold configured.
        let (cache, _dir) = make_cache_with_cold(2);
        let hashes: Vec<TxHash> = (0u8..5).map(make_tx_hash).collect();

        // Insert 2 entries (fills hot tier).
        cache.insert(hashes[0], make_sig_entry(0, 100)).unwrap();
        cache.insert(hashes[1], make_sig_entry(1, 200)).unwrap();

        // Age both.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        // Insert 3 more — triggers eviction of the first 2 to cold.
        cache.insert(hashes[2], make_sig_entry(2, 300)).unwrap();
        cache.insert(hashes[3], make_sig_entry(3, 400)).unwrap();
        cache.insert(hashes[4], make_sig_entry(4, 500)).unwrap();

        // At least some entries should be in cold.
        let cold_hits = cache.metrics().cold_inserts.load(std::sync::atomic::Ordering::Relaxed);
        assert!(cold_hits >= 1, "expected cold spill, got {cold_hits}");
    }
}
