//! Post-quantum cryptographic verifier for HYDRA-X transactions.
//!
//! Defines the [`HydraXVerifier`] trait, the production [`PqCryptoVerifier`]
//! backed by `pqcrypto-dilithium` and `pqcrypto-sphincsplus`, and a
//! `MockVerifier` for tests.

use rayon::join;

use crate::error::CryptoError;
use crate::types::HydraXSignature;
use crate::{ML_DSA87_PK_LEN, ML_DSA87_SIG_LEN, SLH_DSA_256S_PK_LEN, SLH_DSA_256S_SIG_LEN};

// ── HydraXVerifier trait ──────────────────────────────────────────────────────

/// Abstraction over the two post-quantum verification algorithms used by
/// HYDRA-X.
///
/// The default [`verify_hydra_x`][Self::verify_hydra_x] implementation runs
/// both legs in parallel with `rayon::join` and AND-gates the results.
/// Implementations may override this for testing or specialised hardware.
pub trait HydraXVerifier: Send + Sync {
    /// Verifies an ML-DSA-87 (FIPS 204) detached signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsa87VerificationFailed`] on failure,
    /// [`CryptoError::InvalidMlDsa87PkLen`] / [`CryptoError::InvalidMlDsa87SigLen`]
    /// on wrong buffer sizes, and [`CryptoError::PublicKeyDecodeError`] /
    /// [`CryptoError::SignatureDecodeError`] on pqcrypto parse errors.
    fn verify_ml_dsa87(
        &self,
        msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError>;

    /// Verifies an SLH-DSA-SHA2-256s (SPHINCS+-SHA2-256s-simple) detached signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SlhDsa256sVerificationFailed`] on failure and
    /// analogous length/parse errors.
    fn verify_slh_dsa_256s(
        &self,
        msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError>;

    /// AND-composition: verifies both legs in parallel via `rayon::join`.
    ///
    /// Both legs run simultaneously.  If **either** fails, the method returns
    /// an error.  If **both** fail, returns [`CryptoError::BothLegsFailed`].
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`CryptoError`] variant depending on which legs
    /// failed.
    fn verify_hydra_x(
        &self,
        msg: &[u8],
        sig: &HydraXSignature,
        ml_pk: &[u8],
        slh_pk: &[u8],
    ) -> Result<(), CryptoError> {
        // rayon::join runs both closures on potentially different threads.
        let (ml_result, slh_result) = join(
            || self.verify_ml_dsa87(msg, &sig.ml_dsa87, ml_pk),
            || self.verify_slh_dsa_256s(msg, &sig.slh_dsa, slh_pk),
        );

        match (ml_result, slh_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(_), Err(_)) => Err(CryptoError::BothLegsFailed),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Err(e)) => Err(e),
        }
    }
}

// ── PqCryptoVerifier ──────────────────────────────────────────────────────────

/// Production verifier using `pqcrypto-mldsa` and `pqcrypto-sphincsplus`.
///
/// Stateless and cheap to clone (zero-size struct).
#[derive(Debug, Default, Clone, Copy)]
pub struct PqCryptoVerifier;

impl HydraXVerifier for PqCryptoVerifier {
    fn verify_ml_dsa87(
        &self,
        msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError> {
        use pqcrypto_mldsa::mldsa87;
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

        if pk.len() != ML_DSA87_PK_LEN {
            return Err(CryptoError::InvalidMlDsa87PkLen {
                expected: ML_DSA87_PK_LEN,
                got: pk.len(),
            });
        }
        if sig.len() != ML_DSA87_SIG_LEN {
            return Err(CryptoError::InvalidMlDsa87SigLen {
                expected: ML_DSA87_SIG_LEN,
                got: sig.len(),
            });
        }

        let public_key = mldsa87::PublicKey::from_bytes(pk)
            .map_err(|e| CryptoError::PublicKeyDecodeError {
                reason: e.to_string(),
            })?;
        let detached_sig = mldsa87::DetachedSignature::from_bytes(sig)
            .map_err(|e| CryptoError::SignatureDecodeError {
                reason: e.to_string(),
            })?;

        mldsa87::verify_detached_signature(&detached_sig, msg, &public_key)
            .map_err(|_| CryptoError::MlDsa87VerificationFailed)
    }

    fn verify_slh_dsa_256s(
        &self,
        msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError> {
        use pqcrypto_sphincsplus::sphincssha2256ssimple;
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

        if pk.len() != SLH_DSA_256S_PK_LEN {
            return Err(CryptoError::InvalidSlhDsaPkLen {
                expected: SLH_DSA_256S_PK_LEN,
                got: pk.len(),
            });
        }
        if sig.len() != SLH_DSA_256S_SIG_LEN {
            return Err(CryptoError::InvalidSlhDsaSigLen {
                expected: SLH_DSA_256S_SIG_LEN,
                got: sig.len(),
            });
        }

        let public_key = sphincssha2256ssimple::PublicKey::from_bytes(pk)
            .map_err(|e| CryptoError::PublicKeyDecodeError {
                reason: e.to_string(),
            })?;
        let detached_sig = sphincssha2256ssimple::DetachedSignature::from_bytes(sig)
            .map_err(|e| CryptoError::SignatureDecodeError {
                reason: e.to_string(),
            })?;

        sphincssha2256ssimple::verify_detached_signature(&detached_sig, msg, &public_key)
            .map_err(|_| CryptoError::SlhDsa256sVerificationFailed)
    }
}

// ── MockVerifier ──────────────────────────────────────────────────────────────

/// Test double for [`HydraXVerifier`].
///
/// Verification succeeds unless `fail_ml_dsa` or `fail_slh_dsa` is set.
/// An optional `latency_ms` simulates signing latency for benchmarks.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone)]
pub struct MockVerifier {
    /// If `true`, ML-DSA-87 verification always returns
    /// [`CryptoError::MlDsa87VerificationFailed`].
    pub fail_ml_dsa: bool,
    /// If `true`, SLH-DSA-256s verification always returns
    /// [`CryptoError::SlhDsa256sVerificationFailed`].
    pub fail_slh_dsa: bool,
    /// Milliseconds to sleep before returning (simulates crypto latency).
    pub latency_ms: u64,
}

#[cfg(any(test, feature = "test-helpers"))]
impl Default for MockVerifier {
    fn default() -> Self {
        Self {
            fail_ml_dsa: false,
            fail_slh_dsa: false,
            latency_ms: 0,
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl HydraXVerifier for MockVerifier {
    fn verify_ml_dsa87(
        &self,
        _msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError> {
        if self.latency_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(self.latency_ms));
        }
        if pk.len() != ML_DSA87_PK_LEN {
            return Err(CryptoError::InvalidMlDsa87PkLen {
                expected: ML_DSA87_PK_LEN,
                got: pk.len(),
            });
        }
        if sig.len() != ML_DSA87_SIG_LEN {
            return Err(CryptoError::InvalidMlDsa87SigLen {
                expected: ML_DSA87_SIG_LEN,
                got: sig.len(),
            });
        }
        if self.fail_ml_dsa {
            return Err(CryptoError::MlDsa87VerificationFailed);
        }
        Ok(())
    }

    fn verify_slh_dsa_256s(
        &self,
        _msg: &[u8],
        sig: &[u8],
        pk: &[u8],
    ) -> Result<(), CryptoError> {
        if self.latency_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(self.latency_ms));
        }
        if pk.len() != SLH_DSA_256S_PK_LEN {
            return Err(CryptoError::InvalidSlhDsaPkLen {
                expected: SLH_DSA_256S_PK_LEN,
                got: pk.len(),
            });
        }
        if sig.len() != SLH_DSA_256S_SIG_LEN {
            return Err(CryptoError::InvalidSlhDsaSigLen {
                expected: SLH_DSA_256S_SIG_LEN,
                got: sig.len(),
            });
        }
        if self.fail_slh_dsa {
            return Err(CryptoError::SlhDsa256sVerificationFailed);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_helpers::make_hydra_x_sig;

    fn mock() -> MockVerifier {
        MockVerifier::default()
    }

    fn make_pk_ml() -> Vec<u8> {
        vec![0u8; ML_DSA87_PK_LEN]
    }
    fn make_pk_slh() -> Vec<u8> {
        vec![0u8; SLH_DSA_256S_PK_LEN]
    }

    #[test]
    fn mock_verifier_accepts_valid() {
        let v = mock();
        let sig = make_hydra_x_sig(1);
        assert!(v.verify_hydra_x(b"msg", &sig, &make_pk_ml(), &make_pk_slh()).is_ok());
    }

    #[test]
    fn mock_verifier_fail_ml_dsa() {
        let v = MockVerifier { fail_ml_dsa: true, ..Default::default() };
        let sig = make_hydra_x_sig(1);
        let err = v.verify_hydra_x(b"msg", &sig, &make_pk_ml(), &make_pk_slh()).unwrap_err();
        // Should be either MlDsa87VerificationFailed or BothLegsFailed.
        assert!(
            matches!(
                err,
                CryptoError::MlDsa87VerificationFailed | CryptoError::BothLegsFailed
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn mock_verifier_fail_slh_dsa() {
        let v = MockVerifier { fail_slh_dsa: true, ..Default::default() };
        let sig = make_hydra_x_sig(1);
        let err = v.verify_hydra_x(b"msg", &sig, &make_pk_ml(), &make_pk_slh()).unwrap_err();
        assert!(
            matches!(
                err,
                CryptoError::SlhDsa256sVerificationFailed | CryptoError::BothLegsFailed
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn mock_verifier_both_fail() {
        let v = MockVerifier { fail_ml_dsa: true, fail_slh_dsa: true, ..Default::default() };
        let sig = make_hydra_x_sig(1);
        let err = v.verify_hydra_x(b"msg", &sig, &make_pk_ml(), &make_pk_slh()).unwrap_err();
        assert_eq!(err, CryptoError::BothLegsFailed);
    }

    #[test]
    fn mock_verifier_rejects_wrong_pk_len() {
        let v = mock();
        let sig = make_hydra_x_sig(1);
        let short_pk = vec![0u8; 10];
        let err = v.verify_ml_dsa87(b"msg", &sig.ml_dsa87, &short_pk).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidMlDsa87PkLen { .. }));
    }

    #[test]
    fn mock_verifier_rejects_wrong_sig_len() {
        let v = mock();
        let short_sig = vec![0u8; 10];
        let err = v.verify_slh_dsa_256s(b"msg", &short_sig, &make_pk_slh()).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSlhDsaSigLen { .. }));
    }
}
