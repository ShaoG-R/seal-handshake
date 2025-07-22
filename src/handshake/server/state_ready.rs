use super::{
    AsPublicKeyOption, AwaitingKeyExchange, HandshakeServer, HandshakeServerBuilder,
    KeyAgreementEngine, Missing, Ready, SignaturePresence,
};
use crate::{
    crypto::{
        signature::sign_ephemeral_keys,
        suite::{KeyAgreementPresence, WithKeyAgreement, WithSignature, WithoutKeyAgreement, WithoutSignature},
    },
    error::{HandshakeError, Result},
    protocol::message::{HandshakeMessage, ServerHelloPayload, SessionTicket},
};
use seal_flow::crypto::{
    keys::asymmetric::kem::SharedSecret,
    prelude::{TypedKeyAgreementPublicKey, TypedKemPublicKey},
    wrappers::asymmetric::signature::SignatureWrapper,
};
use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{bincode, protocol::message::EncryptedHeader};

pub trait KeyAgreementHandler<K: KeyAgreementPresence>: Sized {
    fn process_key_agreement(
        &mut self,
        client_pk: <K as KeyAgreementPresence>::MessagePublicKey,
    ) -> Result<<K as KeyAgreementPresence>::MessagePublicKey>;
}

impl<S: SignaturePresence> KeyAgreementHandler<WithKeyAgreement>
    for HandshakeServer<Ready, S, WithKeyAgreement>
{
    fn process_key_agreement(
        &mut self,
        client_pk: TypedKeyAgreementPublicKey,
    ) -> Result<TypedKeyAgreementPublicKey> {
        let (engine, shared_secret) =
            KeyAgreementEngine::new_for_server(&self.suite.key_agreement(), &client_pk)?;
        let ka_pk = engine.public_key().clone();
        self.key_agreement_engine = Some(engine);
        self.agreement_shared_secret = Some(shared_secret);
        Ok(ka_pk)
    }
}

impl<S: SignaturePresence> KeyAgreementHandler<WithoutKeyAgreement>
    for HandshakeServer<Ready, S, WithoutKeyAgreement>
{
    fn process_key_agreement(&mut self, _client_pk: ()) -> Result<()> {
        Ok(())
    }
}

pub trait SignatureHandler<S: SignaturePresence, K: KeyAgreementPresence> {
    fn generate_signature(
        &self,
        kem_pk: &TypedKemPublicKey,
        ka_pk: &K::MessagePublicKey,
    ) -> Result<S::MessageSignature>;
}

impl<K: KeyAgreementPresence> SignatureHandler<WithSignature, K>
    for HandshakeServer<Ready, WithSignature, K>
where
    K::MessagePublicKey: AsPublicKeyOption,
{
    fn generate_signature(
        &self,
        kem_pk: &TypedKemPublicKey,
        ka_pk: &K::MessagePublicKey,
    ) -> Result<SignatureWrapper> {
        sign_ephemeral_keys(
            &self.suite.signature(),
            kem_pk,
            &ka_pk.as_ref_option().cloned(),
            self.signature_key_pair.private_key(),
        )
    }
}

impl<K: KeyAgreementPresence> SignatureHandler<WithoutSignature, K>
    for HandshakeServer<Ready, WithoutSignature, K>
{
    fn generate_signature(
        &self,
        _kem_pk: &TypedKemPublicKey,
        _ka_pk: &K::MessagePublicKey,
    ) -> Result<()> {
        Ok(())
    }
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeServer<Ready, Sig, Ka> {
    pub fn builder() -> HandshakeServerBuilder<Missing, Missing, Sig, Ka> {
        HandshakeServerBuilder::new()
    }

    pub fn process_client_hello(
        mut self,
        message: HandshakeMessage<Sig, Ka>,
    ) -> Result<(
        HandshakeMessage<Sig, Ka>,
        HandshakeServer<AwaitingKeyExchange, Sig, Ka>,
    )>
    where
        Self: KeyAgreementHandler<Ka> + SignatureHandler<Sig, Ka>,
        Ka::MessagePublicKey: AsPublicKeyOption,
    {
        self.transcript.update(&message);

        let payload = match message {
            HandshakeMessage::ClientHello(payload) => payload,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        if payload.kem_algorithm != self.suite.kem().algorithm() {
            return Err(HandshakeError::InvalidKemAlgorithm);
        }

        self.resumption_master_secret = self.try_decode_ticket(payload.session_ticket)?;

        let kem = self.suite.kem();
        let kem_key_pair = kem.generate_keypair()?;
        let kem_pk = kem_key_pair.public_key().clone();
        self.kem_key_pair = Some(kem_key_pair);

        let ka_pk = KeyAgreementHandler::process_key_agreement(&mut self, payload.key_agreement_public_key)?;
        let signature = SignatureHandler::generate_signature(&self, &kem_pk, &ka_pk)?;

        let server_hello_payload = ServerHelloPayload {
            kem_public_key: kem_pk,
            key_agreement_public_key: ka_pk,
            signature,
        };

        let server_hello = HandshakeMessage::ServerHello(server_hello_payload);
        self.transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: self.kem_key_pair,
            key_agreement_engine: self.key_agreement_engine,
            agreement_shared_secret: self.agreement_shared_secret,
            encryption_key: self.encryption_key,
            decryption_key: self.decryption_key,
            master_secret: self.master_secret,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: self.resumption_master_secret,
        };

        Ok((server_hello, next_server))
    }

    fn try_decode_ticket(&self, encrypted_ticket: Option<Vec<u8>>) -> Result<Option<SharedSecret>> {
        let (tek, encrypted_ticket) = match (self.ticket_encryption_key.as_ref(), encrypted_ticket)
        {
            (Some(tek), Some(ticket)) => (tek, ticket),
            _ => return Ok(None),
        };

        let pending_decryption =
            seal_flow::prelude::prepare_decryption_from_slice::<EncryptedHeader>(
                &encrypted_ticket,
                None,
            )?;

        let serialized_ticket =
            pending_decryption.decrypt_ordinary(std::borrow::Cow::Borrowed(tek), None)?;

        let ticket: SessionTicket =
            bincode::decode_from_slice(&serialized_ticket, bincode::config::standard())?.0;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HandshakeError::InvalidState)?
            .as_secs();

        if ticket.expiry_timestamp <= now {
            return Ok(None);
        }

        Ok(Some(ticket.master_secret))
    }
}
