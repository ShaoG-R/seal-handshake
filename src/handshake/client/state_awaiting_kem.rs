use super::{
    AwaitingKemPublicKey, Established, HandshakeClient, SessionKeysAndMaster, SignaturePresence,
    WithSignature, WithoutSignature,
};
use crate::{
    crypto::{
        keys::derive_session_keys,
        suite::{KeyAgreementPresence, WithKeyAgreement, WithoutKeyAgreement},
    },
    error::{HandshakeError, Result},
    handshake::server::AsPublicKeyOption,
    protocol::{
        message::{
            ClientKeyExchangePayload, EncryptedHeader, HandshakeMessage, KdfParams,
        },
    },
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        keys::asymmetric::kem::EncapsulatedKey,
        prelude::*,
        traits::{AeadAlgorithmTrait, KemAlgorithmTrait},
        wrappers::asymmetric::signature::SignatureWrapper,
    },
    prelude::EncryptionConfigurator,
    rand::{rngs::OsRng, TryRngCore},
};
use std::{borrow::Cow, marker::PhantomData};

pub trait ClientSignatureVerifier<S: SignaturePresence, K: KeyAgreementPresence> {
    fn verify_server_signature(
        &self,
        kem_pk: &TypedKemPublicKey,
        ka_pk: &K::MessagePublicKey,
        signature: &S::MessageSignature,
    ) -> Result<()>;
}

impl<K: KeyAgreementPresence> ClientSignatureVerifier<WithSignature, K>
    for HandshakeClient<AwaitingKemPublicKey, WithSignature, K>
where
    K::MessagePublicKey: AsPublicKeyOption,
{
    fn verify_server_signature(
        &self,
        kem_pk: &TypedKemPublicKey,
        ka_pk: &K::MessagePublicKey,
        signature: &SignatureWrapper,
    ) -> Result<()> {
        crate::crypto::signature::verify_ephemeral_keys(
            &self.suite.signature(),
            kem_pk,
            &ka_pk.as_ref_option().cloned(),
            signature,
            &self.server_signature_public_key,
        )
    }
}

impl<K: KeyAgreementPresence> ClientSignatureVerifier<WithoutSignature, K>
    for HandshakeClient<AwaitingKemPublicKey, WithoutSignature, K>
{
    fn verify_server_signature(
        &self,
        _kem_pk: &TypedKemPublicKey,
        _ka_pk: &K::MessagePublicKey,
        _signature: &(),
    ) -> Result<()> {
        Ok(())
    }
}

pub trait KeyDeriver<K: KeyAgreementPresence> {
    fn derive_keys(
        &self,
        server_kem_pk: TypedKemPublicKey,
        server_ka_pk: K::MessagePublicKey,
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)>;
}

impl<S: SignaturePresence> KeyDeriver<WithKeyAgreement>
    for HandshakeClient<AwaitingKemPublicKey, S, WithKeyAgreement>
{
    fn derive_keys(
        &self,
        server_kem_pk: TypedKemPublicKey,
        server_ka_pk: TypedKeyAgreementPublicKey,
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)> {
        let kem = self.suite.kem();
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        let shared_secret_agreement = self
            .key_agreement_engine
            .as_ref()
            .unwrap()
            .agree(&server_ka_pk)?;

        let session_keys = derive_session_keys(
            &self.suite,
            shared_secret_kem,
            Some(shared_secret_agreement),
            self.resumption_master_secret.clone(),
            true,
        )?;

        Ok((session_keys, encapsulated_key))
    }
}

impl<S: SignaturePresence> KeyDeriver<WithoutKeyAgreement>
    for HandshakeClient<AwaitingKemPublicKey, S, WithoutKeyAgreement>
{
    fn derive_keys(
        &self,
        server_kem_pk: TypedKemPublicKey,
        _server_ka_pk: (),
    ) -> Result<(SessionKeysAndMaster, EncapsulatedKey)> {
        let kem = self.suite.kem();
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        let session_keys = derive_session_keys(
            &self.suite,
            shared_secret_kem,
            None,
            self.resumption_master_secret.clone(),
            true,
        )?;

        Ok((session_keys, encapsulated_key))
    }
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence>
    HandshakeClient<AwaitingKemPublicKey, Sig, Ka>
{
    pub fn process_server_hello(
        mut self,
        message: HandshakeMessage<Sig, Ka>,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage<Sig, Ka>,
        HandshakeClient<Established, Sig, Ka>,
    )>
    where
        Self: ClientSignatureVerifier<Sig, Ka> + KeyDeriver<Ka>,
        Ka::MessagePublicKey: AsPublicKeyOption,
    {
        self.transcript.update(&message);

        let server_hello = match message {
            HandshakeMessage::ServerHello(payload) => payload,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        ClientSignatureVerifier::verify_server_signature(
            &self,
            &server_hello.kem_public_key,
            &server_hello.key_agreement_public_key,
            &server_hello.signature,
        )?;

        let (session_keys, encapsulated_key) = KeyDeriver::derive_keys(
            &self,
            server_hello.kem_public_key,
            server_hello.key_agreement_public_key,
        )?;

        let key_exchange_msg = create_client_key_exchange(
            &self,
            &session_keys.encryption_key,
            encapsulated_key,
            initial_payload,
            aad,
        )?;

        self.transcript.update(&key_exchange_msg);

        let established_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            key_agreement_engine: self.key_agreement_engine,
            server_signature_public_key: self.server_signature_public_key,
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
            established_master_secret: Some(session_keys.master_secret),
            new_session_ticket: None,
            resumption_master_secret: None,
            session_ticket_to_send: None,
        };

        Ok((key_exchange_msg, established_client))
    }
}

fn create_client_key_exchange<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    client: &HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    encryption_key: &TypedAeadKey,
    encapsulated_key: EncapsulatedKey,
    initial_payload: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<HandshakeMessage<Sig, Ka>> {
    let aad_bytes = aad.unwrap_or(b"seal-handshake-aad");
    let aead = client.suite.aead();
    let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
        .aad_hash(
            aad_bytes,
            &HashAlgorithm::Sha256.into_wrapper(),
        )
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

    let encrypted_message = EncryptionConfigurator::new(
        header,
        Cow::Borrowed(encryption_key),
        Some(aad_bytes.to_vec()),
    )
    .into_writer(Vec::new())?
    .encrypt_ordinary_to_vec(initial_payload.unwrap_or(&[]))?;

    Ok(HandshakeMessage::ClientKeyExchange(
        ClientKeyExchangePayload {
            encrypted_message,
            encapsulated_key,
        },
    ))
}
