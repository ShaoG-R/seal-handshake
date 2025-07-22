use super::{
    AwaitingKemPublicKey, EncapsulatedKey, Established, HandshakeClient, SessionKeysAndMaster,
    SignaturePresence, WithSignature, WithoutSignature,
};
use crate::{
    crypto::{
        keys::derive_session_keys,
        suite::{KeyAgreementPresence, WithKeyAgreement, WithoutKeyAgreement},
    },
    error::{HandshakeError, Result},
    protocol::{
        message::{EncryptedHeader, HandshakeMessage, KdfParams},
        transcript::Transcript,
    },
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        prelude::*,
        traits::{AeadAlgorithmTrait, KemAlgorithmTrait},
        wrappers::asymmetric::signature::SignatureWrapper,
    },
    prelude::EncryptionConfigurator,
    rand::{TryRngCore, rngs::OsRng},
};
use std::{borrow::Cow, marker::PhantomData};

/// A trait to encapsulate state-specific operations for the `AwaitingKemPublicKey` state.
pub trait AwaitingKemStateOperations<Sig: SignaturePresence, Ka: KeyAgreementPresence> {
    fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established, Sig, Ka>)>;
}

impl<Ka: KeyAgreementPresence> AwaitingKemStateOperations<WithSignature, Ka>
    for HandshakeClient<AwaitingKemPublicKey, WithSignature, Ka>
where
    Self: DeriveKeys<Sig = WithSignature, Ka = Ka>,
{
    fn process_server_hello(
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, WithSignature, Ka>,
    )> {
        let (server_kem_pk, server_key_agreement_pk, signature) =
            common_server_hello_processing(&mut self.transcript, &message)?;

        let verifier = self.suite.signature();
        let sig_to_verify = signature.ok_or(HandshakeError::InvalidSignature)?;
        crate::crypto::signature::verify_ephemeral_keys(
            verifier,
            &server_kem_pk,
            &server_key_agreement_pk,
            &sig_to_verify,
            &self.server_signature_public_key,
        )?;

        complete_server_hello_processing(
            self,
            server_kem_pk,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

impl<Ka: KeyAgreementPresence> AwaitingKemStateOperations<WithoutSignature, Ka>
    for HandshakeClient<AwaitingKemPublicKey, WithoutSignature, Ka>
where
    Self: DeriveKeys<Sig = WithoutSignature, Ka = Ka>,
{
    fn process_server_hello(
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, WithoutSignature, Ka>,
    )> {
        let (server_kem_pk, server_key_agreement_pk, _) =
            common_server_hello_processing(&mut self.transcript, &message)?;

        complete_server_hello_processing(
            self,
            server_kem_pk,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence>
    HandshakeClient<AwaitingKemPublicKey, Sig, Ka>
where
    Self: AwaitingKemStateOperations<Sig, Ka>,
{
    pub fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established, Sig, Ka>)> {
        AwaitingKemStateOperations::process_server_hello(self, message, initial_payload, aad)
    }
}


/// Parses the ServerHello and updates the transcript.
///
/// 解析 ServerHello 并更新握手记录。
fn common_server_hello_processing(
    transcript: &mut Transcript,
    message: &HandshakeMessage,
) -> Result<(
    TypedKemPublicKey,
    Option<TypedKeyAgreementPublicKey>,
    Option<SignatureWrapper>,
)> {
    transcript.update(message);

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

/// Completes the handshake logic after `ServerHello` has been processed.
/// This includes key derivation, encryption of initial payload, and state transition.
///
/// 在 `ServerHello` 处理完毕后完成握手逻辑。
/// 这包括密钥派生、初始有效载荷的加密以及状态转换。
fn complete_server_hello_processing<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    mut client: HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    server_kem_pk: TypedKemPublicKey,
    server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    initial_payload: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<(HandshakeMessage, HandshakeClient<Established, Sig, Ka>)>
where
    HandshakeClient<AwaitingKemPublicKey, Sig, Ka>: DeriveKeys<Sig = Sig, Ka = Ka>,
{
    // --- Key Derivation ---
    let (session_keys, encapsulated_key) =
        <HandshakeClient<AwaitingKemPublicKey, Sig, Ka> as DeriveKeys>::derive_session_keys(
            &client,
            server_kem_pk,
            server_key_agreement_pk,
        )?;

    // --- Create ClientKeyExchange ---
    let key_exchange_msg = create_client_key_exchange(
        &client,
        &session_keys.encryption_key,
        encapsulated_key,
        initial_payload,
        aad,
    )?;

    client.transcript.update(&key_exchange_msg);

    // Transition to the `Established` state.
    let established_client = HandshakeClient {
        state: PhantomData,
        suite: client.suite,
        transcript: client.transcript,
        key_agreement_engine: client.key_agreement_engine,
        server_signature_public_key: client.server_signature_public_key,
        encryption_key: Some(session_keys.encryption_key),
        decryption_key: Some(session_keys.decryption_key),
        established_master_secret: Some(session_keys.master_secret),
        new_session_ticket: None,
        resumption_master_secret: None, // Consumed
        session_ticket_to_send: None,   // Consumed
    };

    Ok((key_exchange_msg, established_client))
}

/// A trait for deriving session keys, specialized by key agreement presence.
pub trait DeriveKeys {
    type Sig: SignaturePresence;
    type Ka: KeyAgreementPresence;

    fn derive_session_keys(
        client: &HandshakeClient<AwaitingKemPublicKey, Self::Sig, Self::Ka>,
        server_kem_pk: TypedKemPublicKey,
        server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)>;
}

impl<Sig: SignaturePresence> DeriveKeys for HandshakeClient<AwaitingKemPublicKey, Sig, WithKeyAgreement> {
    type Sig = Sig;
    type Ka = WithKeyAgreement;

    fn derive_session_keys(
        client: &HandshakeClient<AwaitingKemPublicKey, Sig, WithKeyAgreement>,
        server_kem_pk: TypedKemPublicKey,
        server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)> {
        let kem = client.suite.kem();
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        let server_pk =
            server_key_agreement_pk.ok_or(HandshakeError::MissingKeyAgreementPublicKey)?;
        let shared_secret_agreement = client
            .key_agreement_engine
            .as_ref()
            .unwrap()
            .agree(&server_pk)?;

        let session_keys = derive_session_keys(
            &client.suite,
            shared_secret_kem,
            Some(shared_secret_agreement),
            client.resumption_master_secret.clone(),
            true,
        )?;

        Ok((session_keys, encapsulated_key))
    }
}

impl<Sig: SignaturePresence> DeriveKeys
    for HandshakeClient<AwaitingKemPublicKey, Sig, WithoutKeyAgreement>
{
    type Sig = Sig;
    type Ka = WithoutKeyAgreement;

    fn derive_session_keys(
        client: &HandshakeClient<AwaitingKemPublicKey, Sig, WithoutKeyAgreement>,
        server_kem_pk: TypedKemPublicKey,
        _server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)> {
        let kem = client.suite.kem();
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        let session_keys = derive_session_keys(
            &client.suite,
            shared_secret_kem,
            None,
            client.resumption_master_secret.clone(),
            true,
        )?;

        Ok((session_keys, encapsulated_key))
    }
}

/// Creates the `ClientKeyExchange` message, encrypting the initial payload.
fn create_client_key_exchange<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    client: &HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    encryption_key: &TypedAeadKey,
    encapsulated_key: EncapsulatedKey,
    initial_payload: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<HandshakeMessage> {
    let aad = aad.unwrap_or(b"seal-handshake-aad");
    let aead = client.suite.aead();
    let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
        .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
        .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
        .build();

    let kdf_params = KdfParams {
        algorithm: client.suite.kdf().algorithm(),
        salt: Some(b"seal-handshake-salt".to_vec()),
        info: Some(b"seal-handshake-c2s".to_vec()),
    };

    let header = EncryptedHeader {
        params,
        kdf_params,
        signature_algorithm: None,
        signed_transcript_hash: None,
        transcript_signature: None,
    };

    let encrypted_message =
        EncryptionConfigurator::new(header, Cow::Borrowed(encryption_key), Some(aad.to_vec()))
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(initial_payload.unwrap_or(&[]))?;

    // Create the `ClientKeyExchange` message.
    Ok(HandshakeMessage::ClientKeyExchange {
        encrypted_message,
        encapsulated_key,
    })
}
