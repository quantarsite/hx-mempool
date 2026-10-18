//! Prova de que a migração para ML-DSA-87 (FIPS 204) está correta:
//! gera chave real, assina, confere o tamanho da assinatura e verifica
//! pela mesma rota do verificador de produção.

use hx_mempool::ingestion::crypto::{HydraXVerifier, PqCryptoVerifier};
use hx_mempool::{ML_DSA87_PK_LEN, ML_DSA87_SIG_LEN};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

#[test]
fn mldsa87_sizes_match_fips204() {
    assert_eq!(mldsa87::public_key_bytes(), ML_DSA87_PK_LEN);
    assert_eq!(mldsa87::signature_bytes(), ML_DSA87_SIG_LEN);
    assert_eq!(ML_DSA87_SIG_LEN, 4627);
    assert_eq!(ML_DSA87_PK_LEN, 2592);
}

#[test]
fn mldsa87_real_sign_verify_roundtrip() {
    let msg = b"HYDRA-X: transacao de teste";
    let (pk, sk) = mldsa87::keypair();
    let sig = mldsa87::detached_sign(msg, &sk);

    // o tamanho real tem que bater com a constante corrigida
    assert_eq!(sig.as_bytes().len(), ML_DSA87_SIG_LEN);
    assert_eq!(pk.as_bytes().len(), ML_DSA87_PK_LEN);

    // a rota de produção aceita a assinatura boa
    let verifier = PqCryptoVerifier;
    verifier
        .verify_ml_dsa87(msg, sig.as_bytes(), pk.as_bytes())
        .expect("assinatura valida deve passar");

    // mensagem adulterada tem que falhar (fail-closed)
    let res = verifier.verify_ml_dsa87(b"outra mensagem", sig.as_bytes(), pk.as_bytes());
    assert!(res.is_err(), "mensagem trocada deve ser rejeitada");
}
