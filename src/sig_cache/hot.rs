//! Hot tier for the HYDRA-X signature cache.
//!
//! Implements a **CLOCK** (second-chance LRU approximation) eviction algorithm
//! on top of a `DashMap` + `SegQueue` (lock-free FIFO clock hand).
//!
//! ## CLOCK algorithm
//!
//! 1. On insert, the entry is added to `entries` and its hash is pushed onto
//!    `clock_hand`.
//! 2. On get, `last_access_ms` is updated atomically — this serves as the
//!    "referenced" bit.
//! 3. On evict, we pop hashes from the clock hand in FIFO order:
//!    - If the entry's `last_access_ms` is within the `hot_window_ms` (i.e. it
//!      was recently accessed), we **give it a second chance** by pushing its
//!      hash back onto the tail of the queue.
//!    - If the entry is cold (last access is older than the window), we evict it.
//!
//! This is O(1) amortised per eviction and lock-free in the common case.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crossbeam_queue::SegQueue;
use dashmap::DashMap;

use crate::types::{now_ms, SigEntry, TxHash};
use crate::SIG_ENTRY_SIZE_BYTES;

// ── HotTier ───────────────────────────────────────────────────────────────────

/// In-memory, lock-free hot tier using the CLOCK eviction algorithm.
pub struct HotTier {
    /// Primary storage: hash → reference-counted signature entry.
    entries: DashMap<TxHash, Arc<SigEntry>>,
    /// Clock hand: a FIFO queue of hashes in insertion / second-chance order.
    clock_hand: SegQueue<TxHash>,
    /// Current approximate byte footprint of all stored entries.
    current_bytes: AtomicU64,
    /// Maximum bytes this tier is allowed to occupy.
    capacity_bytes: u64,
    /// Entries accessed within the last `hot_window_ms` milliseconds receive a
    /// second chance during CLOCK eviction.
    hot_window_ms: u64,
}

impl HotTier {
    /// Creates a new `HotTier`.
    ///
    /// # Arguments
    ///
    /// * `capacity_bytes` — maximum byte budget.
    /// * `hot_window_ms` — recency window; entries last accessed within this
    ///   window survive one eviction pass.
    pub fn new(capacity_bytes: u64, hot_window_ms: u64) -> Self {
        let initial_capacity = (capacity_bytes as usize)
            .saturating_div(SIG_ENTRY_SIZE_BYTES)
            .max(16);
        Self {
            entries: DashMap::with_capacity(initial_capacity),
            clock_hand: SegQueue::new(),
            current_bytes: AtomicU64::new(0),
            capacity_bytes,
            hot_window_ms,
        }
    }

    // ── Mutating operations ───────────────────────────────────────────────

    /// Inserts `entry` keyed by `hash`.
    ///
    /// If the tier is over capacity, one entry is evicted via CLOCK *before*
    /// inserting the new one.  The evicted `(TxHash, Arc<SigEntry>)` pair is
    /// returned to the caller so it can be spilled to the cold tier.
    ///
    /// Returns `None` if no eviction was necessary (there was enough space).
    pub fn insert(
        &self,
        hash: TxHash,
        entry: SigEntry,
    ) -> Option<(TxHash, Arc<SigEntry>)> {
        let entry_bytes = entry.approx_heap_bytes();
        let evicted = if self.current_bytes.load(Ordering::Relaxed) + entry_bytes
            > self.capacity_bytes
        {
            self.evict_one_lru()
        } else {
            None
        };

        let arc = Arc::new(entry);
        if self.entries.insert(hash, arc).is_none() {
            // New entry — account for its bytes.
            self.current_bytes
                .fetch_add(entry_bytes, Ordering::Relaxed);
            self.clock_hand.push(hash);
        }
        // If it replaced an existing entry the byte delta is approximately
        // zero (same hash, similar size); we leave the counter unchanged to
        // avoid expensive recalculation.

        evicted
    }

    /// Looks up an entry and updates its `last_access_ms` on a hit.
    ///
    /// Returns `None` if the hash is not in the hot tier.
    pub fn get(&self, hash: &TxHash) -> Option<Arc<SigEntry>> {
        let entry = self.entries.get(hash).map(|v| Arc::clone(&*v))?;
        entry.record_access();
        Some(entry)
    }

    /// Removes an entry without evicting (used for explicit invalidation).
    ///
    /// Returns the removed entry so the caller can spill or discard it.
    pub fn remove(&self, hash: &TxHash) -> Option<Arc<SigEntry>> {
        let (_, arc) = self.entries.remove(hash)?;
        let bytes = arc.approx_heap_bytes();
        self.current_bytes
            .fetch_sub(bytes.min(self.current_bytes.load(Ordering::Relaxed)), Ordering::Relaxed);
        // The hash remains in `clock_hand`; the CLOCK walk will skip it because
        // the hash is no longer present in `entries`.
        Some(arc)
    }

    // ── CLOCK eviction ────────────────────────────────────────────────────

    /// Attempts to evict one entry using the CLOCK algorithm.
    ///
    /// Walks the clock hand:
    /// - Hashes no longer in `entries` (already removed) are silently skipped.
    /// - Entries whose `last_access_ms` is within `hot_window_ms` of now are
    ///   given a second chance: their hash is pushed back onto the queue.
    /// - The first "cold" entry encountered is removed and returned.
    ///
    /// Returns `None` if the clock hand was exhausted without finding a
    /// victim (all entries are hot or the queue is empty).
    pub fn evict_one_lru(&self) -> Option<(TxHash, Arc<SigEntry>)> {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.hot_window_ms);

        // Bound the walk to prevent infinite looping when every entry is hot.
        let max_passes = self.entries.len().max(1) * 2;

        for _ in 0..max_passes {
            let hash = self.clock_hand.pop()?;

            // Skip stale clock hand entries (entry already removed).
            let Some(arc) = self.entries.get(&hash).map(|v| Arc::clone(&*v)) else {
                continue;
            };

            if arc.last_access_ms() >= cutoff {
                // Hot — give second chance.
                self.clock_hand.push(hash);
                continue;
            }

            // Cold — evict.
            if let Some((_, evicted)) = self.entries.remove(&hash) {
                let bytes = evicted.approx_heap_bytes();
                self.current_bytes.fetch_sub(
                    bytes.min(self.current_bytes.load(Ordering::Relaxed)),
                    Ordering::Relaxed,
                );
                tracing::debug!(
                    hash = hex::encode_if_available(&hash),
                    bytes,
                    "hot tier CLOCK eviction"
                );
                return Some((hash, evicted));
            }
        }

        None
    }

    /// Evicts up to `n` entries using repeated CLOCK walks.
    ///
    /// Returns the evicted `(TxHash, Arc<SigEntry>)` pairs in eviction order.
    pub fn evict_batch(&self, n: usize) -> Vec<(TxHash, Arc<SigEntry>)> {
        let mut evicted = Vec::with_capacity(n);
        for _ in 0..n {
            match self.evict_one_lru() {
                Some(pair) => evicted.push(pair),
                None => break,
            }
        }
        evicted
    }

    // ── Observers ─────────────────────────────────────────────────────────

    /// Returns the current approximate byte occupancy.
    #[inline]
    pub fn current_bytes(&self) -> u64 {
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Returns the configured byte capacity.
    #[inline]
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Returns the number of entries currently in the hot tier.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the hot tier holds no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the utilisation as a percentage `[0, 100]`.
    #[inline]
    pub fn utilization_pct(&self) -> u8 {
        if self.capacity_bytes == 0 {
            return 100;
        }
        let used = self.current_bytes.load(Ordering::Relaxed);
        ((used * 100) / self.capacity_bytes).min(100) as u8
    }
}

// ── hex helper (avoids pulling in hex crate) ──────────────────────────────────

/// Internal helper to format a hash prefix for tracing without pulling in
/// a hex crate.  Returns the first 8 bytes as a hex string.
mod hex {
    pub fn encode_if_available(bytes: &[u8]) -> String {
        bytes
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_helpers::{make_sig_entry, make_tx_hash};
    #[allow(unused_imports)]
    use crate::{ML_DSA87_SIG_LEN, SLH_DSA_256S_SIG_LEN};

    /// Hot window of 1 second — tests use `std::thread::sleep` to age entries.
    fn make_hot_tier(capacity_entries: usize) -> HotTier {
        let capacity_bytes =
            (capacity_entries * SIG_ENTRY_SIZE_BYTES) as u64;
        HotTier::new(capacity_bytes, 1_000 /* 1 second hot window */)
    }

    #[test]
    fn insert_and_get() {
        let tier = make_hot_tier(4);
        let hash = make_tx_hash(1);
        let entry = make_sig_entry(1, 100);
        tier.insert(hash, entry);
        assert!(tier.get(&hash).is_some());
        assert_eq!(tier.len(), 1);
    }

    #[test]
    fn get_updates_access_time() {
        let tier = make_hot_tier(4);
        let hash = make_tx_hash(2);
        let entry = make_sig_entry(2, 100);
        tier.insert(hash, entry);
        let before = tier.get(&hash).unwrap().last_access_ms();
        // Tiny sleep so the timestamp actually advances.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let after = tier.get(&hash).unwrap().last_access_ms();
        assert!(after >= before, "last_access_ms should not go backwards");
    }

    #[test]
    fn remove_decrements_bytes() {
        let tier = make_hot_tier(4);
        let hash = make_tx_hash(3);
        let entry = make_sig_entry(3, 100);
        tier.insert(hash, entry);
        let bytes_after_insert = tier.current_bytes();
        assert!(bytes_after_insert > 0);

        tier.remove(&hash);
        assert_eq!(tier.current_bytes(), 0);
        assert!(tier.get(&hash).is_none());
    }

    #[test]
    fn evicts_old_entry_when_at_capacity() {
        // Capacity for exactly 1 entry.
        let tier = make_hot_tier(1);

        let hash1 = make_tx_hash(10);
        let entry1 = make_sig_entry(10, 100);
        tier.insert(hash1, entry1);

        // Age entry1 by sleeping past the 1-second hot window.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        // Insert a second entry — should trigger eviction of hash1.
        let hash2 = make_tx_hash(11);
        let entry2 = make_sig_entry(11, 200);
        let evicted = tier.insert(hash2, entry2);

        assert!(evicted.is_some(), "expected an eviction");
        let (evicted_hash, _) = evicted.unwrap();
        assert_eq!(evicted_hash, hash1);
        assert!(tier.get(&hash1).is_none(), "evicted entry should be gone");
        assert!(tier.get(&hash2).is_some(), "new entry should be present");
    }

    #[test]
    fn second_chance_protects_hot_entries() {
        // Use a hot_window_ms of 500ms so we can reliably distinguish hot from cold.
        let tier = HotTier::new(
            (2 * SIG_ENTRY_SIZE_BYTES) as u64,
            500, // 500ms hot window
        );

        let hash1 = make_tx_hash(20);
        let hash2 = make_tx_hash(21);
        tier.insert(hash1, make_sig_entry(20, 100));
        tier.insert(hash2, make_sig_entry(21, 200));

        // Sleep 600ms so both entries are now outside the hot window.
        std::thread::sleep(std::time::Duration::from_millis(600));

        // Re-access hash1 *after* the sleep — this stamps its last_access_ms
        // to NOW, making it definitively hot (within the 500ms window again).
        tier.get(&hash1);
        // hash2 is NOT accessed — it remains cold (last_access_ms ~= insert time, 600ms ago).

        // CLOCK walk: hash1 is hot → second chance; hash2 is cold → evicted.
        let evicted = tier.evict_one_lru();
        assert!(evicted.is_some(), "expected an eviction");
        let (evicted_hash, _) = evicted.unwrap();
        assert_eq!(evicted_hash, hash2, "cold entry hash2 should be evicted first");
    }

    #[test]
    fn evict_batch_evicts_multiple() {
        let tier = make_hot_tier(4);
        for seed in 0u8..4 {
            tier.insert(make_tx_hash(seed), make_sig_entry(seed, 100));
        }
        // Age all entries.
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        let evicted = tier.evict_batch(3);
        assert_eq!(evicted.len(), 3);
        assert_eq!(tier.len(), 1);
    }

    #[test]
    fn utilization_pct_correct() {
        let tier = make_hot_tier(4);
        assert_eq!(tier.utilization_pct(), 0);
        tier.insert(make_tx_hash(30), make_sig_entry(30, 100));
        let pct = tier.utilization_pct();
        assert!(pct > 0 && pct <= 100, "utilisation should be between 0 and 100");
    }
}
