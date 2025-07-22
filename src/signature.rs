//! Manages the creation and verification of digital signatures within the handshake.
//!
//! This module centralizes the logic for signing and verifying ephemeral keys,
//! ensuring that the data format is consistent on both client and server sides.
//!
//! 管理握手过程中的数字签名的创建和验证。
//!
//! 该模块集中了对临时密钥进行签名和验证的逻辑，
//! 确保了客户端和服务器端数据格式的一致性。

use crate::error::{HandshakeError, Result};
use seal_flow::crypto::{
    bincode,
    prelude::*,
    traits::SignatureAlgorithmTrait,
    wrappers::asymmetric::signature::{SignatureAlgorithmWrapper, SignatureWrapper},
};

/// Prepares the data payload for signing or verification.
///
/// The payload is a concatenation of the serialized KEM public key and,
/// if present, the key agreement public key.
fn prepare_key_payload(
    kem_pk: &TypedKemPublicKey,
    key_agreement_pk: &Option<TypedKeyAgreementPublicKey>,
) -> Result<Vec<u8>> {
    let kem_pk_bytes =
        bincode::encode_to_vec(kem_pk, bincode::config::standard()).map_err(HandshakeError::from)?;

    if let Some(ka_pk) = key_agreement_pk {
        let mut combined = kem_pk_bytes;
        let ka_pk_bytes =
            bincode::encode_to_vec(ka_pk, bincode::config::standard()).map_err(HandshakeError::from)?;
        combined.extend_from_slice(&ka_pk_bytes);
        Ok(combined)
    } else {
        Ok(kem_pk_bytes)
    }
}

/// Signs the server's ephemeral public keys.
///
/// This is called by the server to prove its identity.
pub fn sign_ephemeral_keys(
    signer: &SignatureAlgorithmWrapper,
    kem_pk: &TypedKemPublicKey,
    key_agreement_pk: &Option<TypedKeyAgreementPublicKey>,
    identity_sk: &TypedSignaturePrivateKey,
) -> Result<SignatureWrapper> {
    let payload = prepare_key_payload(kem_pk, key_agreement_pk)?;
    signer.sign(&payload, identity_sk).map_err(Into::into)
}

/// Verifies the signature on the server's ephemeral public keys.
///
/// This is called by the client to authenticate the server.
pub fn verify_ephemeral_keys(
    verifier: &SignatureAlgorithmWrapper,
    kem_pk: &TypedKemPublicKey,
    key_agreement_pk: &Option<TypedKeyAgreementPublicKey>,
    signature: &SignatureWrapper,
    identity_pk: &TypedSignaturePublicKey,
) -> Result<()> {
    let payload = prepare_key_payload(kem_pk, key_agreement_pk)?;
    verifier
        .verify(&payload, identity_pk, signature)
        .map_err(|_| HandshakeError::InvalidSignature)
} 