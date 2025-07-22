use super::{
    AwaitingKeyExchange, HandshakeServer, HandshakeServerBuilder, KeyAgreementEngine, Missing,
    Ready, SignaturePresence,
};
use crate::{
    crypto::{
        signature::sign_ephemeral_keys,
        suite::{
            KeyAgreementPresence, WithKeyAgreement, WithSignature, WithoutKeyAgreement,
            WithoutSignature,
        },
    },
    error::{HandshakeError, Result},
    protocol::message::{HandshakeMessage, SessionTicket},
};
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{bincode, protocol::message::EncryptedHeader};

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeServer<Ready, Sig, Ka> {
    /// Creates a new `HandshakeServerBuilder` to construct a `HandshakeServer`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeServer` 的构建器。
    pub fn builder() -> HandshakeServerBuilder<Missing, Missing, Sig, Ka> {
        HandshakeServerBuilder::new()
    }
}

pub trait ReadyStateOperations<Sig: SignaturePresence, Ka: KeyAgreementPresence> {
    fn process_client_hello(
        self,
        message: HandshakeMessage,
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange, Sig, Ka>)>;
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeServer<Ready, Sig, Ka> {
    pub fn process_client_hello(
        self,
        message: HandshakeMessage,
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange, Sig, Ka>)>
    where
        Self: ReadyStateOperations<Sig, Ka>,
    {
        ReadyStateOperations::process_client_hello(self, message)
    }

    /// Attempts to decrypt and validate a session ticket.
    ///
    /// Returns the master secret if the ticket is valid, otherwise returns `None`.
    ///
    /// 尝试解密并验证会话票据。
    ///
    /// 如果票据有效，则返回主密钥，否则返回 `None`。
    fn try_decode_ticket(&self, encrypted_ticket: Option<Vec<u8>>) -> Result<Option<SharedSecret>> {
        let (tek, encrypted_ticket) = match (self.ticket_encryption_key.as_ref(), encrypted_ticket)
        {
            (Some(tek), Some(ticket)) => (tek, ticket),
            _ => return Ok(None),
        };

        let pending_decryption = seal_flow::prelude::prepare_decryption_from_slice::<
            EncryptedHeader,
        >(&encrypted_ticket, None)?;

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

// Common logic to process ClientHello and generate KEM keys.
fn process_and_generate_kem(
    server: &mut HandshakeServer<Ready, impl SignaturePresence, impl KeyAgreementPresence>,
    message: &HandshakeMessage,
) -> Result<(
    Option<seal_flow::crypto::keys::asymmetric::key_agreement::TypedKeyAgreementPublicKey>,
    Option<SharedSecret>,
)> {
    server.transcript.update(message);

    let (client_pk, session_ticket) = match message {
        HandshakeMessage::ClientHello {
            key_agreement_public_key,
            session_ticket,
            kem_algorithm,
        } => {
            if *kem_algorithm != server.suite.kem().algorithm() {
                return Err(HandshakeError::InvalidKemAlgorithm);
            }
            (key_agreement_public_key.clone(), session_ticket.clone())
        }
        _ => return Err(HandshakeError::InvalidMessage),
    };

    let resumption_secret = server.try_decode_ticket(session_ticket)?;
    server.resumption_master_secret = resumption_secret;

    let kem = server.suite.kem();
    let kem_key_pair = kem.generate_keypair()?;
    server.kem_key_pair = Some(kem_key_pair);

    Ok((client_pk, server.resumption_master_secret.clone()))
}

// Logic for WithKeyAgreement
fn handle_with_key_agreement<Sig: SignaturePresence>(
    server: &mut HandshakeServer<Ready, Sig, WithKeyAgreement>,
    client_pk: Option<
        seal_flow::crypto::keys::asymmetric::key_agreement::TypedKeyAgreementPublicKey,
    >,
) -> Result<()> {
    let client_pk = client_pk.ok_or(HandshakeError::MissingKeyAgreementPublicKey)?;
    let (engine, shared_secret) =
        KeyAgreementEngine::new_for_server(server.suite.key_agreement(), &client_pk)?;
    server.key_agreement_engine = Some(engine);
    server.agreement_shared_secret = Some(shared_secret);
    Ok(())
}

// Logic for WithoutKeyAgreement
fn handle_without_key_agreement<Sig: SignaturePresence>(
    _server: &mut HandshakeServer<Ready, Sig, WithoutKeyAgreement>,
    _client_pk: Option<
        seal_flow::crypto::keys::asymmetric::key_agreement::TypedKeyAgreementPublicKey,
    >,
) -> Result<()> {
    Ok(()) // No-op
}

fn finalize_handshake<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    server: HandshakeServer<Ready, Sig, Ka>,
    signature: Option<seal_flow::crypto::wrappers::asymmetric::signature::SignatureWrapper>,
) -> Result<(
    HandshakeMessage,
    HandshakeServer<AwaitingKeyExchange, Sig, Ka>,
)> {
    let kem_pk = server.kem_key_pair.as_ref().unwrap().public_key().clone();
    let ka_pk = server
        .key_agreement_engine
        .as_ref()
        .map(|e| e.public_key().clone());

    let server_hello = HandshakeMessage::ServerHello {
        kem_public_key: kem_pk,
        key_agreement_public_key: ka_pk,
        signature,
    };

    let mut transcript = server.transcript;
    transcript.update(&server_hello);

    let next_server = HandshakeServer {
        state: PhantomData,
        suite: server.suite,
        transcript,
        signature_key_pair: server.signature_key_pair,
        kem_key_pair: server.kem_key_pair,
        key_agreement_engine: server.key_agreement_engine,
        agreement_shared_secret: server.agreement_shared_secret,
        encryption_key: server.encryption_key,
        decryption_key: server.decryption_key,
        master_secret: server.master_secret,
        ticket_encryption_key: server.ticket_encryption_key,
        resumption_master_secret: server.resumption_master_secret,
    };

    Ok((server_hello, next_server))
}

impl ReadyStateOperations<WithSignature, WithKeyAgreement>
    for HandshakeServer<Ready, WithSignature, WithKeyAgreement>
{
    fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, WithSignature, WithKeyAgreement>,
    )> {
        let (client_pk, _) = process_and_generate_kem(&mut self, &message)?;
        handle_with_key_agreement(&mut self, client_pk)?;

        let ka_pk = self
            .key_agreement_engine
            .as_ref()
            .map(|e| e.public_key().clone());

        let signature = sign_ephemeral_keys(
            self.suite.signature(),
            self.kem_key_pair.as_ref().unwrap().public_key(),
            &ka_pk,
            self.signature_key_pair.private_key(),
        )?;

        finalize_handshake(self, Some(signature))
    }
}

impl ReadyStateOperations<WithSignature, WithoutKeyAgreement>
    for HandshakeServer<Ready, WithSignature, WithoutKeyAgreement>
{
    fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, WithSignature, WithoutKeyAgreement>,
    )> {
        let (client_pk, _) = process_and_generate_kem(&mut self, &message)?;
        handle_without_key_agreement(&mut self, client_pk)?;

        let signature = sign_ephemeral_keys(
            self.suite.signature(),
            self.kem_key_pair.as_ref().unwrap().public_key(),
            &None,
            self.signature_key_pair.private_key(),
        )?;

        finalize_handshake(self, Some(signature))
    }
}

impl ReadyStateOperations<WithoutSignature, WithKeyAgreement>
    for HandshakeServer<Ready, WithoutSignature, WithKeyAgreement>
{
    fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, WithoutSignature, WithKeyAgreement>,
    )> {
        let (client_pk, _) = process_and_generate_kem(&mut self, &message)?;
        handle_with_key_agreement(&mut self, client_pk)?;
        finalize_handshake(self, None)
    }
}

impl ReadyStateOperations<WithoutSignature, WithoutKeyAgreement>
    for HandshakeServer<Ready, WithoutSignature, WithoutKeyAgreement>
{
    fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, WithoutSignature, WithoutKeyAgreement>,
    )> {
        let (client_pk, _) = process_and_generate_kem(&mut self, &message)?;
        handle_without_key_agreement(&mut self, client_pk)?;
        finalize_handshake(self, None)
    }
}
