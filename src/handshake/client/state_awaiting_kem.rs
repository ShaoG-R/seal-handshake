use super::{HandshakeClient, SignaturePresence};
use crate::crypto::keys::{derive_session_keys, SessionKeysAndMaster};
use crate::crypto::signature::verify_ephemeral_keys;
use crate::crypto::suite::{WithSignature, WithoutSignature};
use crate::error::{HandshakeError, Result};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{AwaitingKemPublicKey, ClientAwaitingKemPublicKey, ClientEstablished, Established},
    transcript::Transcript,
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        prelude::*,
        traits::{KemAlgorithmTrait},
        wrappers::asymmetric::signature::SignatureWrapper,
    },
    prelude::EncryptionConfigurator,
    rand::{rngs::OsRng, TryRngCore},
};
use std::{borrow::Cow, marker::PhantomData};

impl HandshakeClient<AwaitingKemPublicKey, ClientAwaitingKemPublicKey, WithSignature> {
    /// This function handles the `ServerHello` message, verifies its signature, derives session keys, and transitions to
    /// the established state.
    ///
    /// 此函数处理 `ServerHello` 消息，验证其签名，派生会话密钥，并转换到 `Established` 状态。
    pub fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, ClientEstablished, WithSignature>,
    )> {
        let (server_kem_pk, server_key_agreement_pk, signature) =
            common_server_hello_processing(&self.transcript, &message)?;

        // Verify the signature.
        let verifier = self.suite.signature();
        let sig_to_verify = signature.ok_or(HandshakeError::InvalidSignature)?;
        verify_ephemeral_keys(
            verifier,
            &server_kem_pk,
            &server_key_agreement_pk,
            &sig_to_verify,
            &self.server_signature_public_key,
        )?;

        // Delegate to the common logic for key derivation and message creation.
        complete_server_hello_processing(
            self,
            server_kem_pk,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

impl HandshakeClient<AwaitingKemPublicKey, ClientAwaitingKemPublicKey, WithoutSignature> {
    /// This function handles the `ServerHello` message without a signature, derives session keys, and transitions to the
    /// established state.
    ///
    /// 此函数处理不带签名的 `ServerHello` 消息，派生会话密钥，并转换到 `Established` 状态。
    pub fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, ClientEstablished, WithoutSignature>,
    )> {
        let (server_kem_pk, server_key_agreement_pk, _) =
            common_server_hello_processing(&self.transcript, &message)?;

        // Delegate to the common logic for key derivation and message creation.
        complete_server_hello_processing(
            self,
            server_kem_pk,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

/// Helper to perform common processing of the `ServerHello` message.
fn common_server_hello_processing(
    transcript: &Transcript,
    message: &HandshakeMessage,
) -> Result<(
    TypedKemPublicKey,
    Option<TypedKeyAgreementPublicKey>,
    Option<SignatureWrapper>,
)> {
    let mut new_transcript = transcript.clone();
    new_transcript.update(message);

    match message {
        HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key,
            signature,
        } => Ok((
            kem_public_key.clone(),
            key_agreement_public_key.clone(),
            signature.clone(),
        )),
        _ => Err(HandshakeError::InvalidMessage),
    }
}

/// Helper to complete the handshake after processing `ServerHello`.
/// This involves key derivation, creating the `ClientKeyExchange` message,
/// and transitioning to the `Established` state.
fn complete_server_hello_processing<S: SignaturePresence>(
    client: HandshakeClient<AwaitingKemPublicKey, ClientAwaitingKemPublicKey, S>,
    server_kem_pk: TypedKemPublicKey,
    server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    initial_payload: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<(HandshakeMessage, HandshakeClient<Established, ClientEstablished, S>)> {
    let (session_keys, encapsulated_key) =
        derive_session_keys_from_server_hello(&client, server_kem_pk, server_key_agreement_pk)?;

    // Create the `ClientKeyExchange` message, which includes the encapsulated key
    // and the encrypted initial payload (if any).
    let encrypted_message = if let Some(plaintext) = initial_payload {
        let aad = aad.unwrap_or_default();
        let kdf_params = KdfParams {
            algorithm: client.suite.kdf(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-c2s".to_vec()),
        };

        let aead = client.suite.aead();
        let params = AeadParamsBuilder::new(aead, 4096)
            .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let header = EncryptedHeader {
            params,
            kdf_params,
            signature_algorithm: None,
            signed_transcript_hash: None,
            transcript_signature: None,
        };

        let ciphertext = EncryptionConfigurator::new(
            header,
            Cow::Borrowed(&session_keys.encryption_key),
            Some(aad.to_vec()),
        )
        .into_writer(Vec::new())?
        .encrypt_ordinary_to_vec(plaintext)?;
        Some(ciphertext)
    } else {
        None
    };

    let client_key_exchange = HandshakeMessage::ClientKeyExchange {
        encrypted_message: encrypted_message.unwrap_or_default(),
        encapsulated_key,
    };

    let HandshakeClient {
        state: _,
        state_data: _,
        mut transcript,
        suite,
        server_signature_public_key,
    } = client;

    transcript.update(&client_key_exchange);

    // Transition to the established state.
    let established_client = HandshakeClient {
        state: PhantomData,
        state_data: ClientEstablished {
            encryption_key: session_keys.encryption_key,
            decryption_key: session_keys.decryption_key,
            master_secret: session_keys.master_secret,
            new_session_ticket: None,
        },
        suite,
        transcript,
        server_signature_public_key,
    };

    Ok((client_key_exchange, established_client))
}

/// Derives session keys based on the server's hello message and the client's state.
fn derive_session_keys_from_server_hello<Sig: SignaturePresence>(
    client: &HandshakeClient<AwaitingKemPublicKey, ClientAwaitingKemPublicKey, Sig>,
    server_kem_pk: TypedKemPublicKey,
    server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
) -> Result<(SessionKeysAndMaster, EncapsulatedKey)> {
    let kem = client.suite.kem_wrapper();

    // KEM: Encapsulate a new shared secret against the server's public KEM key.
    let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

    // Key Agreement: If negotiated, compute the shared secret.
    let shared_secret_agreement = if let Some(engine) = client.state_data.key_agreement_engine.as_ref() {
        engine.agree(server_key_agreement_pk.as_ref())?
    } else {
        None
    };

    // KDF: Derive session keys.
    let session_keys = derive_session_keys(
        shared_secret_kem,
        shared_secret_agreement,
        client.state_data.resumption_master_secret.clone(), // Use the resumption secret
        true,                                             // is_client = true
        client.suite.kdf(),
        client.suite.aead(),
    )?;

    Ok((session_keys, encapsulated_key))
}
