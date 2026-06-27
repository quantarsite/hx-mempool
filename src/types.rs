//! Core data types for the HYDRA-X mempool.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::{
    ADDRESS_LEN, ML_DSA87_SIG_LEN, SLH_DSA_256S_SIG_LEN, TX_HASH_LEN,
};

// ── Primitive aliases ─────────────────────────────────────────────────────────

/// 32-byte Blake3 transaction hash.
pub type TxHash = [u8; TX_HASH_LEN];

/// 32-byte on-chain address (= BLAKE3(ml_pk || slh_pk)[0..32]).
pub type Address = [u8; ADDRESS_LEN];

// ── now_ms ────────────────────────────────────────────────────────────────────

/// Returns the current wall-clock time as milliseconds since the Unix epoch.
///
/// # Panics
///
/// Panics only if the system clock is set before the Unix epoch — a condition
/// that cannot arise on any production system.  The panic is therefore
/// considered infallible in practice.
#[inline]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // SAFETY: system clock before epoch is impossible on production hardware.
        .expect("system clock is before Unix epoch")
        .as_millis() as u64
}

// ── HydraXSignature ───────────────────────────────────────────────────────────

/// AND-composed post-quantum signature carried by every HYDRA-X transaction.
///
/// Both legs must verify against the same signing bytes; the AND-gate is
/// enforced in [`crate::ingestion::crypto::HydraXVerifier::verify_hydra_x`].
#[derive(Debug, Clone)]
pub struct HydraXSignature {
    /// ML-DSA-87 (Dilithium5, round-3) detached signature — exactly 4 595 bytes.
    pub ml_dsa87: Vec<u8>,
    /// SLH-DSA-SHA2-256s (SPHINCS+-SHA2-256s-simple) detached signature — exactly 29 792 bytes.
    pub slh_dsa: Vec<u8>,
}

impl HydraXSignature {
    /// Constructs a `HydraXSignature`, validating byte lengths.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidMlDsa87SigLen`] or
    /// [`CryptoError::InvalidSlhDsaSigLen`] if either slice has the wrong length.
    pub fn new(ml_dsa87: Vec<u8>, slh_dsa: Vec<u8>) -> Result<Self, CryptoError> {
        if ml_dsa87.len() != ML_DSA87_SIG_LEN {
            return Err(CryptoError::InvalidMlDsa87SigLen {
                expected: ML_DSA87_SIG_LEN,
                got: ml_dsa87.len(),
            });
        }
        if slh_dsa.len() != SLH_DSA_256S_SIG_LEN {
            return Err(CryptoError::InvalidSlhDsaSigLen {
                expected: SLH_DSA_256S_SIG_LEN,
                got: slh_dsa.len(),
            });
        }
        Ok(Self { ml_dsa87, slh_dsa })
    }

    /// Constructs a `HydraXSignature` **without** length validation.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `ml_dsa87.len() == ML_DSA87_SIG_LEN`
    /// and `slh_dsa.len() == SLH_DSA_256S_SIG_LEN`.  Passing wrong-length
    /// buffers will cause verification to fail with an opaque length error
    /// from pqcrypto.  Only use this in tests or when lengths have already
    /// been checked externally.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new_unchecked(ml_dsa87: Vec<u8>, slh_dsa: Vec<u8>) -> Self {
        Self { ml_dsa87, slh_dsa }
    }
}

// ── SigEntry ──────────────────────────────────────────────────────────────────

/// Cached signature entry stored in the hot tier.
///
/// `SigEntry` is intentionally **not** `Clone` because it contains
/// `AtomicU64`/`AtomicU32` fields that cannot be cheaply and correctly
/// duplicated.  Callers wrap entries in `Arc<SigEntry>` when shared
/// ownership is needed.
pub struct SigEntry {
    /// ML-DSA-87 detached signature bytes.
    pub ml_dsa87_sig: Vec<u8>,
    /// SLH-DSA-SHA2-256s detached signature bytes.
    pub slh_dsa_sig: Vec<u8>,
    /// Milliseconds-since-epoch timestamp when this entry was first inserted.
    pub inserted_at_ms: u64,
    /// Milliseconds-since-epoch timestamp of the most recent cache access.
    /// Updated atomically on every [`HotTier::get`][crate::sig_cache::hot::HotTier::get].
    pub last_access_ms: AtomicU64,
    /// Number of times this entry has been retrieved from the hot tier.
    pub access_count: AtomicU32,
    /// Fee-per-gas unit offered by the corresponding transaction.
    /// Used by the [`FeePressureLru`][crate::sig_cache::policy::EvictionPolicy::FeePressureLru] policy.
    pub fee_per_gas: u64,
}

impl SigEntry {
    /// Creates a new `SigEntry` with access counters zeroed.
    pub fn new(
        ml_dsa87_sig: Vec<u8>,
        slh_dsa_sig: Vec<u8>,
        fee_per_gas: u64,
    ) -> Self {
        let now = now_ms();
        Self {
            ml_dsa87_sig,
            slh_dsa_sig,
            inserted_at_ms: now,
            last_access_ms: AtomicU64::new(now),
            access_count: AtomicU32::new(0),
            fee_per_gas,
        }
    }

    /// Returns the timestamp of the last cache access (milliseconds since epoch).
    #[inline]
    pub fn last_access_ms(&self) -> u64 {
        self.last_access_ms.load(Ordering::Relaxed)
    }

    /// Returns the total number of cache hits for this entry.
    #[inline]
    pub fn access_count(&self) -> u32 {
        self.access_count.load(Ordering::Relaxed)
    }

    /// Records a cache hit: bumps `access_count` and updates `last_access_ms`.
    #[inline]
    pub fn record_access(&self) {
        self.last_access_ms.store(now_ms(), Ordering::Relaxed);
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Approximate heap size of this entry in bytes.
    ///
    /// Used by the hot tier to track `current_bytes`.
    #[inline]
    pub fn approx_heap_bytes(&self) -> u64 {
        (self.ml_dsa87_sig.len() + self.slh_dsa_sig.len() + std::mem::size_of::<Self>()) as u64
    }
}

impl std::fmt::Debug for SigEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigEntry")
            .field("ml_dsa87_sig_len", &self.ml_dsa87_sig.len())
            .field("slh_dsa_sig_len", &self.slh_dsa_sig.len())
            .field("inserted_at_ms", &self.inserted_at_ms)
            .field("last_access_ms", &self.last_access_ms())
            .field("access_count", &self.access_count())
            .field("fee_per_gas", &self.fee_per_gas)
            .finish()
    }
}

// ── ColdSigEntry ─────────────────────────────────────────────────────────────

/// Serialisable version of [`SigEntry`] for cold-tier (sled) persistence.
///
/// All atomic fields are replaced with plain `u64`/`u32` so that
/// `postcard` can encode and decode the struct without unsafe code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdSigEntry {
    /// ML-DSA-87 detached signature bytes.
    pub ml_dsa87_sig: Vec<u8>,
    /// SLH-DSA-SHA2-256s detached signature bytes.
    pub slh_dsa_sig: Vec<u8>,
    /// Milliseconds-since-epoch timestamp when first inserted.
    pub inserted_at_ms: u64,
    /// Milliseconds-since-epoch timestamp of the last hot-tier access.
    pub last_access_ms: u64,
    /// Number of hot-tier cache hits before demotion to cold.
    pub access_count: u32,
    /// Fee-per-gas unit offered by the transaction.
    pub fee_per_gas: u64,
}

impl From<&SigEntry> for ColdSigEntry {
    fn from(e: &SigEntry) -> Self {
        Self {
            ml_dsa87_sig: e.ml_dsa87_sig.clone(),
            slh_dsa_sig: e.slh_dsa_sig.clone(),
            inserted_at_ms: e.inserted_at_ms,
            last_access_ms: e.last_access_ms(),
            access_count: e.access_count(),
            fee_per_gas: e.fee_per_gas,
        }
    }
}

impl From<ColdSigEntry> for SigEntry {
    fn from(c: ColdSigEntry) -> Self {
        Self {
            ml_dsa87_sig: c.ml_dsa87_sig,
            slh_dsa_sig: c.slh_dsa_sig,
            inserted_at_ms: c.inserted_at_ms,
            last_access_ms: AtomicU64::new(c.last_access_ms),
            access_count: AtomicU32::new(c.access_count),
            fee_per_gas: c.fee_per_gas,
        }
    }
}

// ── SigStatus ─────────────────────────────────────────────────────────────────

/// Tracks whether a transaction's signatures are available and verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    /// Both signature legs have been verified and are in the hot cache.
    Verified,
    /// Signatures have been demoted to the cold tier (sled).
    Cold,
    /// Signatures were evicted from both tiers and not persisted.
    Missing,
    /// Signature verification is queued but not yet complete.
    Pending,
}

// ── PooledTx ─────────────────────────────────────────────────────────────────

/// A transaction that has been admitted to the HYDRA-X mempool.
///
/// Stored in [`TxPool`][crate::pool::TxPool] keyed by `hash`.
#[derive(Debug, Clone)]
pub struct PooledTx {
    /// Blake3 hash of the signing bytes.
    pub hash: TxHash,
    /// Sender nonce (replay-protection counter).
    pub nonce: u64,
    /// Sending address (BLAKE3 key hash).
    pub sender: Address,
    /// Recipient address.
    pub recipient: Address,
    /// Transfer value in the smallest denomination.
    pub value: u128,
    /// Fee the sender offers per gas unit (for block-proposer ordering).
    pub fee_per_gas: u64,
    /// Maximum gas units the sender is willing to consume.
    pub gas_limit: u64,
    /// Arbitrary transaction payload.
    pub data: Bytes,
    /// Current signature availability in the two-tier cache.
    pub sig_status: SigStatus,
    /// Milliseconds-since-epoch when this transaction first entered the pool.
    pub first_seen_ms: u64,
}

impl PooledTx {
    /// Creates a `PooledTx` from a [`RawTransaction`], setting
    /// `sig_status = SigStatus::Pending` and recording the current time.
    pub fn from_raw(raw: &RawTransaction) -> Self {
        Self {
            hash: raw.hash(),
            nonce: raw.nonce,
            sender: raw.sender,
            recipient: raw.recipient,
            value: raw.value,
            fee_per_gas: raw.fee_per_gas,
            gas_limit: raw.gas_limit,
            data: Bytes::copy_from_slice(&raw.data),
            sig_status: SigStatus::Pending,
            first_seen_ms: now_ms(),
        }
    }
}

// ── RawTransaction ────────────────────────────────────────────────────────────

/// An unverified transaction as received from the network layer.
///
/// `RawTransaction` carries the full public keys so that address derivation
/// and both signature legs can be verified without additional lookups.
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// Sender nonce.
    pub nonce: u64,
    /// Sender address.  Must equal BLAKE3(ml_pk || slh_pk)[0..32].
    pub sender: Address,
    /// ML-DSA-87 (Dilithium5) public key of the sender — must be 2 592 bytes.
    pub sender_ml_dsa_pk: Vec<u8>,
    /// SLH-DSA-SHA2-256s (SPHINCS+) public key of the sender — must be 64 bytes.
    pub sender_slh_dsa_pk: Vec<u8>,
    /// Recipient address.
    pub recipient: Address,
    /// Transfer value.
    pub value: u128,
    /// Fee per gas unit.
    pub fee_per_gas: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Arbitrary payload.
    pub data: Vec<u8>,
}

impl RawTransaction {
    /// Produces the canonical signing bytes for this transaction.
    ///
    /// Layout (fixed-width fields are little-endian):
    /// ```text
    /// nonce(8) || sender(32) || recipient(32) || value(16) || fee_per_gas(8)
    /// || gas_limit(8) || data_len(8) || data
    /// ```
    ///
    /// Public keys are **not** included in the signing bytes — they are
    /// part of the verification context, not the signed payload.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            8 + 32 + 32 + 16 + 8 + 8 + 8 + self.data.len(),
        );
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.recipient);
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&self.fee_per_gas.to_le_bytes());
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Computes the BLAKE3 hash of the signing bytes.
    ///
    /// This is the canonical transaction identifier used throughout the pool
    /// and cache layers.
    pub fn hash(&self) -> TxHash {
        *blake3::hash(&self.signing_bytes()).as_bytes()
    }

    /// Derives the expected sender address from the concatenated public keys.
    ///
    /// `expected_sender = BLAKE3(ml_pk || slh_pk)[0..32]`
    pub fn derived_sender(&self) -> Address {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.sender_ml_dsa_pk);
        hasher.update(&self.sender_slh_dsa_pk);
        *hasher.finalize().as_bytes()
    }
}

// ── Arc-wrapped SigEntry builder helper ──────────────────────────────────────

/// Wraps a freshly created [`SigEntry`] in an `Arc`.
///
/// Convenience for call sites that immediately need shared ownership.
pub fn arc_sig_entry(entry: SigEntry) -> Arc<SigEntry> {
    Arc::new(entry)
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::{ML_DSA87_SIG_LEN, SLH_DSA_256S_SIG_LEN};

    /// Creates a deterministic `TxHash` from a single seed byte.
    pub fn make_tx_hash(seed: u8) -> TxHash {
        [seed; TX_HASH_LEN]
    }

    /// Creates a deterministic `Address` from a single seed byte.
    pub fn make_address(seed: u8) -> Address {
        [seed; ADDRESS_LEN]
    }

    /// Creates a `HydraXSignature` filled with `seed` bytes (for testing only —
    /// will NOT pass real verification).
    pub fn make_hydra_x_sig(seed: u8) -> crate::types::HydraXSignature {
        HydraXSignature::new_unchecked(
            vec![seed; ML_DSA87_SIG_LEN],
            vec![seed; SLH_DSA_256S_SIG_LEN],
        )
    }

    /// Creates a minimal `RawTransaction` where `sender` is set to the BLAKE3
    /// key hash so that address derivation passes the `MockVerifier`.
    pub fn make_raw_tx(seed: u8) -> RawTransaction {
        use crate::{ML_DSA87_PK_LEN, SLH_DSA_256S_PK_LEN};

        let ml_pk = vec![seed; ML_DSA87_PK_LEN];
        let slh_pk = vec![seed; SLH_DSA_256S_PK_LEN];

        // Derive a consistent address so `verify_address_derivation` passes.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&ml_pk);
        hasher.update(&slh_pk);
        let derived: Address = *hasher.finalize().as_bytes();

        RawTransaction {
            nonce: seed as u64,
            sender: derived,
            sender_ml_dsa_pk: ml_pk,
            sender_slh_dsa_pk: slh_pk,
            recipient: make_address(seed.wrapping_add(1)),
            value: seed as u128 * 1_000,
            fee_per_gas: seed as u64 * 100 + 1,
            gas_limit: 21_000,
            data: vec![],
        }
    }

    /// Creates a `SigEntry` filled with `seed` bytes.
    pub fn make_sig_entry(seed: u8, fee_per_gas: u64) -> SigEntry {
        SigEntry::new(
            vec![seed; ML_DSA87_SIG_LEN],
            vec![seed; SLH_DSA_256S_SIG_LEN],
            fee_per_gas,
        )
    }
}
