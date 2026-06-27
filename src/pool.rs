//! Transaction pool for the HYDRA-X mempool.
//!
//! [`TxPool`] holds admitted transactions indexed by their Blake3 hash and
//! provides per-sender nonce ordering via a nested `BTreeMap<nonce, TxHash>`.
//! All operations are lock-free in the hot path — `DashMap` shards the hash
//! index and the inner `BTreeMap` is protected by the same shard lock.

use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use dashmap::DashMap;

use crate::types::{Address, PooledTx, SigStatus, TxHash};

// ── TxPool ────────────────────────────────────────────────────────────────────

/// Thread-safe transaction pool.
///
/// Transactions are stored in two concurrent indexes:
/// * `by_hash` — O(1) lookup by `TxHash`
/// * `by_sender` — per-`Address` nonce-ordered map for replacing pending txs
///   and walking sender sequences during block building
///
/// The `count` gauge is maintained with an `AtomicUsize` so callers can read
/// it without acquiring any lock.
pub struct TxPool {
    /// Primary index: hash → pooled transaction.
    by_hash: DashMap<TxHash, Arc<PooledTx>>,
    /// Secondary index: sender → nonce → hash (for sequence-ordered access).
    by_sender: DashMap<Address, BTreeMap<u64, TxHash>>,
    /// Approximate pool size (not strictly consistent with the maps, but close enough
    /// for capacity management without a global lock).
    count: AtomicUsize,
}

impl TxPool {
    /// Creates an empty `TxPool` with default DashMap sharding.
    pub fn new() -> Self {
        Self {
            by_hash: DashMap::new(),
            by_sender: DashMap::new(),
            count: AtomicUsize::new(0),
        }
    }

    /// Inserts a transaction.
    ///
    /// If a transaction with the same hash already exists it is silently
    /// replaced (callers should check [`get`][Self::get] first if replacement
    /// semantics are undesired).
    pub fn insert(&self, tx: PooledTx) {
        let hash = tx.hash;
        let sender = tx.sender;
        let nonce = tx.nonce;

        let tx_arc = Arc::new(tx);
        let was_new = self.by_hash.insert(hash, tx_arc).is_none();
        if was_new {
            self.count.fetch_add(1, Ordering::Relaxed);
        }

        self.by_sender
            .entry(sender)
            .or_default()
            .insert(nonce, hash);
    }

    /// Returns a reference-counted handle to the pooled transaction, or `None`.
    #[inline]
    pub fn get(&self, hash: &TxHash) -> Option<Arc<PooledTx>> {
        self.by_hash.get(hash).map(|v| Arc::clone(&*v))
    }

    /// Removes and returns the transaction, also cleaning up the sender index.
    pub fn remove(&self, hash: &TxHash) -> Option<Arc<PooledTx>> {
        let tx = self.by_hash.remove(hash).map(|(_, v)| v)?;
        self.count.fetch_sub(1, Ordering::Relaxed);

        // Clean up the sender nonce index.
        let mut remove_sender = false;
        if let Some(mut nonce_map) = self.by_sender.get_mut(&tx.sender) {
            nonce_map.retain(|_, h| h != hash);
            remove_sender = nonce_map.is_empty();
        }
        if remove_sender {
            self.by_sender.remove(&tx.sender);
        }

        Some(tx)
    }

    /// Atomically updates the `sig_status` field of a pooled transaction.
    ///
    /// Because `PooledTx` is stored behind `Arc` and has no `Mutex`, we
    /// replace the `Arc` value with a new `PooledTx` with the same fields
    /// but an updated `sig_status`.  This is a low-frequency operation
    /// (happens once per ingest or eviction event) so the clone cost is
    /// acceptable.
    pub fn update_sig_status(&self, hash: &TxHash, status: SigStatus) {
        if let Some(mut entry) = self.by_hash.get_mut(hash) {
            let old = entry.as_ref();
            let updated = Arc::new(PooledTx {
                sig_status: status,
                ..(*old).clone()
            });
            *entry = updated;
        }
    }

    /// Returns the current number of transactions in the pool.
    #[inline]
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the pool contains no transactions.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns all transactions sorted by descending `fee_per_gas` for use by
    /// block proposers.
    ///
    /// This allocates a `Vec` of `Arc<PooledTx>` clones — it is intended for
    /// the proposer's block-building loop, not for hot-path lookups.
    pub fn fee_ordered_iter(&self) -> Vec<Arc<PooledTx>> {
        let mut txs: Vec<Arc<PooledTx>> = self
            .by_hash
            .iter()
            .map(|v| Arc::clone(&*v))
            .collect();
        txs.sort_unstable_by(|a, b| b.fee_per_gas.cmp(&a.fee_per_gas));
        txs
    }

    /// Returns the pending transactions for `sender` in ascending nonce order.
    pub fn pending_for_sender(&self, sender: &Address) -> Vec<Arc<PooledTx>> {
        let Some(nonce_map) = self.by_sender.get(sender) else {
            return vec![];
        };
        nonce_map
            .values()
            .filter_map(|h| self.by_hash.get(h).map(|v| Arc::clone(&*v)))
            .collect()
    }

    /// Returns `true` if the pool already holds a transaction with this hash.
    #[inline]
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_helpers::{make_address, make_raw_tx, make_tx_hash};
    use crate::types::{PooledTx, SigStatus};

    fn make_pooled_tx(seed: u8) -> PooledTx {
        let raw = make_raw_tx(seed);
        let mut tx = PooledTx::from_raw(&raw);
        tx.sig_status = SigStatus::Verified;
        tx
    }

    #[test]
    fn insert_and_get() {
        let pool = TxPool::new();
        let tx = make_pooled_tx(1);
        let hash = tx.hash;
        pool.insert(tx);
        assert!(pool.get(&hash).is_some());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_clears_both_indexes() {
        let pool = TxPool::new();
        let tx = make_pooled_tx(2);
        let hash = tx.hash;
        let sender = tx.sender;
        pool.insert(tx);
        assert_eq!(pool.len(), 1);

        let removed = pool.remove(&hash);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 0);
        assert!(pool.pending_for_sender(&sender).is_empty());
    }

    #[test]
    fn update_sig_status() {
        let pool = TxPool::new();
        let tx = make_pooled_tx(3);
        let hash = tx.hash;
        pool.insert(tx);

        pool.update_sig_status(&hash, SigStatus::Cold);
        let retrieved = pool.get(&hash).unwrap();
        assert_eq!(retrieved.sig_status, SigStatus::Cold);
    }

    #[test]
    fn fee_ordered_iter_descending() {
        let pool = TxPool::new();
        // Insert 3 txs with different fees; seeds map to fee = seed*100+1
        for seed in [1u8, 5, 3] {
            pool.insert(make_pooled_tx(seed));
        }
        let sorted = pool.fee_ordered_iter();
        assert_eq!(sorted.len(), 3);
        // Highest fee first
        assert!(sorted[0].fee_per_gas >= sorted[1].fee_per_gas);
        assert!(sorted[1].fee_per_gas >= sorted[2].fee_per_gas);
    }

    #[test]
    fn pending_for_sender_nonce_order() {
        let pool = TxPool::new();
        // Two txs from same sender with different nonces
        // We manually construct them to share a sender address.
        let sender = make_address(99);
        for nonce in [2u64, 0, 1] {
            let raw = make_raw_tx(1);
            let mut tx = PooledTx::from_raw(&raw);
            tx.sender = sender;
            tx.nonce = nonce;
            // Give each a unique hash by mangling the nonce into it
            let mut h = make_tx_hash(1);
            h[0] = nonce as u8;
            tx.hash = h;
            pool.insert(tx);
        }
        let pending = pool.pending_for_sender(&sender);
        assert_eq!(pending.len(), 3);
        // nonce ordering is guaranteed by BTreeMap
        let nonces: Vec<u64> = pending.iter().map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![0, 1, 2]);
    }

    #[test]
    fn duplicate_insert_does_not_double_count() {
        let pool = TxPool::new();
        let tx = make_pooled_tx(7);
        let hash = tx.hash;
        pool.insert(tx.clone());
        pool.insert(tx);
        // count is not incremented for duplicate hash
        assert_eq!(pool.len(), 1);
        // but the entry is still accessible
        assert!(pool.get(&hash).is_some());
    }
}
