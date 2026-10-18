//! HYDRA-X v2: a perna SLH-DSA verifica com FIPS 205 de verdade e o payload
//! assinado carrega a separação de domínio com o chain id.

use fips205::slh_dsa_sha2_256s;
use fips205::traits::{SerDes, Signer};
use hx_mempool::ingestion::crypto::{HydraXVerifier, PqCryptoVerifier};
use hx_mempool::types::{signing_domain_prefix, RawTransaction, CHAIN_ID, SIGNING_DOMAIN};
use hx_mempool::{SLH_DSA_256S_PK_LEN, SLH_DSA_256S_SIG_LEN};

#[test]
fn slh_dsa_fips205_real_sign_verify_roundtrip() {
    let msg = b"HYDRA-X v2: perna SLH-DSA";
    let (pk, sk) = slh_dsa_sha2_256s::try_keygen().expect("keygen");
    let sig = sk.try_sign(msg, &[], false).expect("sign");
    let pk_bytes = pk.into_bytes();

    assert_eq!(pk_bytes.len(), SLH_DSA_256S_PK_LEN);
    assert_eq!(sig.len(), SLH_DSA_256S_SIG_LEN);

    let verifier = PqCryptoVerifier;
    verifier
        .verify_slh_dsa_256s(msg, &sig, &pk_bytes)
        .expect("assinatura FIPS 205 valida deve passar");

    let res = verifier.verify_slh_dsa_256s(b"outra mensagem", &sig, &pk_bytes);
    assert!(res.is_err(), "mensagem trocada deve ser rejeitada");
}

#[test]
fn signing_bytes_start_with_domain_and_chain_id() {
    let tx = RawTransaction {
        nonce: 7,
        sender: [1u8; 32],
        sender_ml_dsa_pk: vec![],
        sender_slh_dsa_pk: vec![],
        recipient: [2u8; 32],
        value: 100,
        fee_per_gas: 0,
        gas_limit: 21_000,
        data: vec![],
    };
    let prefix = signing_domain_prefix();
    let bytes = tx.signing_bytes();

    assert_eq!(CHAIN_ID, "quantar-testnet-2");
    assert!(prefix.starts_with(SIGNING_DOMAIN));
    assert_eq!(prefix[SIGNING_DOMAIN.len()] as usize, CHAIN_ID.len());
    assert!(bytes.starts_with(&prefix));
    assert_eq!(bytes.len(), prefix.len() + 8 + 32 + 32 + 16 + 8 + 8 + 8);
    assert_eq!(&bytes[prefix.len()..prefix.len() + 8], &7u64.to_le_bytes());
}
