//! Cold tier for the HYDRA-X signature cache.
//!
//! Wraps a [`sled`] embedded database to persist signature entries that have
//! been evicted from the hot tier.  Entries are serialised with [`postcard`]
//! (compact binary, no schema overhead).
//!
//! ## Key format
//!
//! Keys are stored as raw 32-byte `TxHash` slices.  sled uses byte-ordered
//! B-tree storage, so range scans (e.g. for bulk cleanup) are efficient.

use std::path::Path;

use crate::error::MempoolError;
use crate::types::{ColdSigEntry, SigEntry, TxHash};

// ── ColdTier ─────────────────────────────────────────────────────────────────

/// Persistent cold tier backed by sled.
///
/// `ColdTier` is `Clone` because sled's `Db` handle is already `Arc`-wrapped
/// internally; cloning just bumps the reference count.
#[derive(Clone)]
pub struct ColdTier {
    db: sled::Db,
}

impl ColdTier {
    /// Opens (or creates) the sled database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::SledError`] if the database cannot be opened.
    pub fn open(path: &Path) -> Result<Self, MempoolError> {
        let db = sled::open(path)?;
        tracing::debug!(path = %path.display(), "cold tier sled database opened");
        Ok(Self { db })
    }

    /// Serialises `entry` and inserts it at `hash`.
    ///
    /// If an entry already exists for `hash`, it is overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::SerializationError`] if postcard encoding fails,
    /// or [`MempoolError::SledError`] on I/O failure.
    pub fn insert(&self, hash: TxHash, entry: &SigEntry) -> Result<(), MempoolError> {
        let cold_entry = ColdSigEntry::from(entry);
        let bytes = postcard::to_allocvec(&cold_entry)
            .map_err(|e| MempoolError::SerializationError(e.to_string()))?;
        self.db.insert(hash.as_ref(), bytes)?;
        tracing::debug!(
            hash_prefix = %format_hash_prefix(&hash),
            "cold tier insert"
        );
        Ok(())
    }

    /// Retrieves and deserialises the entry at `hash`, or `None` if absent.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::DeserializationError`] if the stored bytes are
    /// corrupted or incompatible, or [`MempoolError::SledError`] on I/O failure.
    pub fn get(&self, hash: &TxHash) -> Result<Option<ColdSigEntry>, MempoolError> {
        let Some(bytes) = self.db.get(hash.as_ref())? else {
            return Ok(None);
        };
        let entry = postcard::from_bytes::<ColdSigEntry>(&bytes)
            .map_err(|e| MempoolError::DeserializationError(e.to_string()))?;
        Ok(Some(entry))
    }

    /// Removes the entry at `hash` (no-op if absent).
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::SledError`] on I/O failure.
    pub fn remove(&self, hash: &TxHash) -> Result<(), MempoolError> {
        self.db.remove(hash.as_ref())?;
        Ok(())
    }

    /// Returns `true` if the cold tier contains an entry for `hash`.
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.db.contains_key(hash.as_ref()).unwrap_or(false)
    }

    /// Returns an approximate entry count.
    ///
    /// `sled::Db::len()` walks all trees so this is O(n) for large databases;
    /// call only from metrics paths, not the hot ingest loop.
    pub fn approx_len(&self) -> usize {
        self.db.len()
    }

    /// Promotes a cold entry back to a hot [`SigEntry`].
    ///
    /// Retrieves, deserialises, and converts the stored `ColdSigEntry` into a
    /// `SigEntry`.  Does **not** remove it from the cold tier; the caller is
    /// responsible for deciding whether to keep or remove the cold copy.
    ///
    /// Returns `None` if the hash is not in the cold tier.
    pub fn promote(&self, hash: &TxHash) -> Result<Option<SigEntry>, MempoolError> {
        Ok(self.get(hash)?.map(SigEntry::from))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

    fn open_temp() -> (ColdTier, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let tier = ColdTier::open(dir.path()).expect("open cold tier");
        (tier, dir)
    }

    #[test]
    fn insert_and_get() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(1);
        let entry = make_sig_entry(1, 500);
        tier.insert(hash, &entry).expect("insert");
        let retrieved = tier.get(&hash).expect("get").expect("some");
        assert_eq!(retrieved.fee_per_gas, 500);
        assert_eq!(retrieved.ml_dsa87_sig.len(), crate::ML_DSA87_SIG_LEN);
        assert_eq!(retrieved.slh_dsa_sig.len(), crate::SLH_DSA_256S_SIG_LEN);
    }

    #[test]
    fn get_missing_returns_none() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(99);
        let result = tier.get(&hash).expect("no sled error");
        assert!(result.is_none());
    }

    #[test]
    fn remove_deletes_entry() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(2);
        tier.insert(hash, &make_sig_entry(2, 1)).expect("insert");
        assert!(tier.contains(&hash));
        tier.remove(&hash).expect("remove");
        assert!(!tier.contains(&hash));
    }

    #[test]
    fn promote_returns_sig_entry() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(3);
        let entry = make_sig_entry(3, 999);
        tier.insert(hash, &entry).expect("insert");
        let promoted = tier.promote(&hash).expect("promote").expect("some");
        assert_eq!(promoted.fee_per_gas, 999);
        // Cold copy is still there.
        assert!(tier.contains(&hash));
    }

    #[test]
    fn approx_len_tracks_inserts() {
        let (tier, _dir) = open_temp();
        assert_eq!(tier.approx_len(), 0);
        for seed in 0u8..5 {
            tier.insert(make_tx_hash(seed), &make_sig_entry(seed, 1)).unwrap();
        }
        assert_eq!(tier.approx_len(), 5);
    }

    #[test]
    fn insert_overwrites_existing() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(4);
        tier.insert(hash, &make_sig_entry(4, 100)).unwrap();
        tier.insert(hash, &make_sig_entry(4, 999)).unwrap();
        let entry = tier.get(&hash).unwrap().unwrap();
        assert_eq!(entry.fee_per_gas, 999, "overwrite should update fee_per_gas");
    }

    #[test]
    fn roundtrip_preserves_sig_bytes() {
        let (tier, _dir) = open_temp();
        let hash = make_tx_hash(5);
        let original = make_sig_entry(42, 777);
        let ml_first_byte = original.ml_dsa87_sig[0];
        let slh_first_byte = original.slh_dsa_sig[0];
        tier.insert(hash, &original).unwrap();
        let cold = tier.get(&hash).unwrap().unwrap();
        assert_eq!(cold.ml_dsa87_sig[0], ml_first_byte);
        assert_eq!(cold.slh_dsa_sig[0], slh_first_byte);
    }
}
