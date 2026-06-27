//! Eviction policies for the HYDRA-X hot signature cache.

use crate::types::SigEntry;

// ── EvictionPolicy ────────────────────────────────────────────────────────────

/// Determines which entry the CLOCK algorithm should evict when the hot tier
/// is over capacity.
#[derive(Debug, Clone)]
pub enum EvictionPolicy {
    /// Pure LRU approximation: the entry that was least recently accessed
    /// (and whose second-chance bit is not set) is evicted first.
    Lru,

    /// Hybrid policy blending recency and fee pressure.
    ///
    /// `fee_weight = 0.0` is identical to [`Lru`][EvictionPolicy::Lru];
    /// `fee_weight = 1.0` evicts purely by ascending fee (lowest fee evicted
    /// first, regardless of recency).  Values in between linearly interpolate.
    FeePressureLru {
        /// Blend weight in `[0.0, 1.0]`.
        fee_weight: f32,
    },

    /// Block-finalisation policy: entries belonging to finalised transactions
    /// are immediately removed before consulting recency or fee ordering.
    ///
    /// For entries not yet finalised, falls back to [`Lru`][EvictionPolicy::Lru].
    FinalizedFirst,
}

// ── eviction_score ────────────────────────────────────────────────────────────

/// Computes an eviction score for `entry` under `policy`.
///
/// **Higher score → evict first.**
///
/// The CLOCK walk in [`HotTier`][crate::sig_cache::hot::HotTier] uses this
/// score only for entries whose second-chance bit is already clear (i.e. whose
/// `last_access_ms` is outside the hot window).  Within a single CLOCK tick
/// the walk pops one candidate and checks its bit; this function is called
/// afterward to break ties or as a tiebreaker for the `FeePressureLru` variant.
pub fn eviction_score(entry: &SigEntry, now_ms: u64, policy: &EvictionPolicy) -> f64 {
    match policy {
        EvictionPolicy::Lru | EvictionPolicy::FinalizedFirst => {
            // Pure recency: older entries score higher.
            //
            // We invert last_access_ms relative to now so that
            // "last accessed a long time ago" → high score → evict first.
            let age_ms = now_ms.saturating_sub(entry.last_access_ms()) as f64;
            age_ms
        }

        EvictionPolicy::FeePressureLru { fee_weight } => {
            let w = fee_weight.clamp(0.0, 1.0) as f64;

            // Recency component (0.0 = just accessed, higher = older)
            let max_age_ms = 3_600_000.0_f64; // cap at 1 hour for normalisation
            let age_ms =
                now_ms.saturating_sub(entry.last_access_ms()) as f64;
            let recency_score = (age_ms / max_age_ms).clamp(0.0, 1.0);

            // Fee component: lower fee → higher eviction pressure.
            //
            // We map fee_per_gas through a log scale so the score is
            // meaningful across the full u64 range without clamping away
            // discrimination at the extremes.
            //
            // score = 1 - log(1 + fee) / log(1 + u64::MAX)
            //
            // This gives:
            //   fee = 0       → score ≈ 1.0  (evict first)
            //   fee = u64::MAX → score ≈ 0.0  (keep)
            let log_max = (1.0_f64 + u64::MAX as f64).ln();
            let fee = entry.fee_per_gas as f64;
            let fee_score = 1.0 - ((1.0 + fee).ln() / log_max).clamp(0.0, 1.0);

            (1.0 - w) * recency_score + w * fee_score
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigEntry;
    use crate::{ML_DSA87_SIG_LEN, SLH_DSA_256S_SIG_LEN};

    fn make_entry(last_access_ms: u64, fee_per_gas: u64) -> SigEntry {
        use std::sync::atomic::{AtomicU32, AtomicU64};
        SigEntry {
            ml_dsa87_sig: vec![0u8; ML_DSA87_SIG_LEN],
            slh_dsa_sig: vec![0u8; SLH_DSA_256S_SIG_LEN],
            inserted_at_ms: last_access_ms,
            last_access_ms: AtomicU64::new(last_access_ms),
            access_count: AtomicU32::new(0),
            fee_per_gas,
        }
    }

    #[test]
    fn lru_older_scores_higher() {
        let now = 10_000u64;
        let old = make_entry(1_000, 100);
        let new = make_entry(9_000, 100);
        let score_old = eviction_score(&old, now, &EvictionPolicy::Lru);
        let score_new = eviction_score(&new, now, &EvictionPolicy::Lru);
        assert!(score_old > score_new, "older entry should score higher under Lru");
    }

    #[test]
    fn fee_pressure_low_fee_scores_higher() {
        let now = 10_000u64;
        // Same age, different fee
        let cheap = make_entry(9_000, 1);
        let expensive = make_entry(9_000, 1_000_000_000);
        let policy = EvictionPolicy::FeePressureLru { fee_weight: 1.0 };
        let cheap_score = eviction_score(&cheap, now, &policy);
        let expensive_score = eviction_score(&expensive, now, &policy);
        assert!(cheap_score > expensive_score,
            "cheap tx should score higher (evict first) under full fee pressure");
    }

    #[test]
    fn fee_pressure_zero_weight_behaves_like_lru() {
        let now = 10_000u64;
        let old = make_entry(1_000, 1_000_000_000);
        let new = make_entry(9_500, 1);
        // With fee_weight=0 the fee component is ignored; only recency matters
        let policy = EvictionPolicy::FeePressureLru { fee_weight: 0.0 };
        assert!(eviction_score(&old, now, &policy) > eviction_score(&new, now, &policy));
    }

    #[test]
    fn finalized_first_falls_back_to_lru() {
        let now = 10_000u64;
        let old = make_entry(500, 1);
        let new = make_entry(9_800, 1);
        let policy = EvictionPolicy::FinalizedFirst;
        assert!(eviction_score(&old, now, &policy) > eviction_score(&new, now, &policy));
    }
}
