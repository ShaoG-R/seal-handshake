use super::{
    HandshakeServer, HandshakeServerBuilder, KeyAgreementEngine, Missing, Ready,
    SignaturePresence,
};
use crate::crypto::{
    signature::sign_ephemeral_keys,
    suite::{WithSignature, WithoutSignature},
};
use crate::error::{HandshakeError, Result};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, SessionTicket},
    state::{AwaitingKeyExchange, ServerAwaitingKeyExchange, ServerReady},
};
use seal_flow::crypto::{keys::asymmetric::kem::SharedSecret, prelude::TypedAeadKey};
use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::bincode;

impl<Sig: SignaturePresence> HandshakeServer<Ready, ServerReady, Sig> {
    /// Creates a new `HandshakeServerBuilder` to construct a `HandshakeServer`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeServer` 的构建器。
    pub fn builder() -> HandshakeServerBuilder<Missing, Missing, Sig> {
        HandshakeServerBuilder::new()
    }
}

// --- `process_client_hello` implementations ---

impl HandshakeServer<Ready, ServerReady, WithSignature> {
    /// Processes a `ClientHello` message when a signature scheme is configured.
    ///
    /// It generates ephemeral keys, signs them, and sends a `ServerHello`.
    ///
    /// 当配置了签名方案时，处理 `ClientHello` 消息。
    ///
    /// 它会生成临时密钥，对其进行签名，并发送 `ServerHello`。
    pub fn process_client_hello(
        self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, ServerAwaitingKeyExchange, WithSignature>,
    )> {
        let HandshakeServer {
            state: _,
            state_data: _,
            mut transcript,
            suite,
            signature_key_pair,
            ticket_encryption_key,
        } = self;

        transcript.update(&message);

        let (client_key_agreement_pk, resumption_master_secret) = match message {
            HandshakeMessage::ClientHello {
                key_agreement_public_key,
                session_ticket,
                kem_algorithm,
            } => {
                if kem_algorithm != suite.kem().algorithm() {
                    return Err(HandshakeError::InvalidKemAlgorithm);
                }
                (
                    key_agreement_public_key,
                    try_decode_ticket(ticket_encryption_key.as_ref(), session_ticket)?,
                )
            }
            _ => return Err(HandshakeError::InvalidMessage),
        };

        // KEM key generation
        let kem = suite.kem();
        let kem_key_pair = kem.generate_keypair()?;
        let kem_public_key = kem_key_pair.public_key().clone();

        // Key Agreement
        let (server_key_agreement_pk, key_agreement_engine, agreement_shared_secret) =
            if let (Some(client_pk), Some(key_agreement)) =
                (client_key_agreement_pk, suite.key_agreement())
            {
                let (engine, shared_secret) =
                    KeyAgreementEngine::new_for_server(key_agreement, &client_pk)?;
                (
                    Some(engine.public_key().clone()),
                    Some(engine),
                    Some(shared_secret),
                )
            } else {
                (None, None, None)
            };

        // Sign the ephemeral keys.
        let signer = suite.signature();
        let signature = sign_ephemeral_keys(
            signer,
            &kem_public_key,
            &server_key_agreement_pk,
            &signature_key_pair.private_key(),
        )?;

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key: server_key_agreement_pk,
            signature: Some(signature),
        };

        transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            state_data: ServerAwaitingKeyExchange {
                kem_key_pair,
                key_agreement_engine,
                agreement_shared_secret,
                resumption_master_secret,
            },
            suite,
            transcript,
            signature_key_pair,
            ticket_encryption_key,
        };

        Ok((server_hello, next_server))
    }
}

impl HandshakeServer<Ready, ServerReady, WithoutSignature> {
    /// Processes a `ClientHello` message when no signature scheme is configured.
    ///
    /// It generates ephemeral keys and sends a `ServerHello` without a signature.
    ///
    /// 当未配置签名方案时，处理 `ClientHello` 消息。
    ///
    /// 它会生成临时密钥，并发送不带签名的 `ServerHello`。
    pub fn process_client_hello(
        self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, ServerAwaitingKeyExchange, WithoutSignature>,
    )> {
        let HandshakeServer {
            state: _,
            state_data: _,
            mut transcript,
            suite,
            signature_key_pair,
            ticket_encryption_key,
        } = self;

        transcript.update(&message);

        let (client_key_agreement_pk, resumption_master_secret) = match message {
            HandshakeMessage::ClientHello {
                key_agreement_public_key,
                session_ticket,
                kem_algorithm,
            } => {
                if kem_algorithm != suite.kem().algorithm() {
                    return Err(HandshakeError::InvalidKemAlgorithm);
                }
                (
                    key_agreement_public_key,
                    try_decode_ticket(ticket_encryption_key.as_ref(), session_ticket)?,
                )
            }
            _ => return Err(HandshakeError::InvalidMessage),
        };

        // KEM key generation
        let kem = suite.kem();
        let kem_key_pair = kem.generate_keypair()?;
        let kem_public_key = kem_key_pair.public_key().clone();

        // Key Agreement
        let (server_key_agreement_pk, key_agreement_engine, agreement_shared_secret) =
            if let (Some(client_pk), Some(key_agreement)) =
                (client_key_agreement_pk, suite.key_agreement())
            {
                let (engine, shared_secret) =
                    KeyAgreementEngine::new_for_server(key_agreement, &client_pk)?;
                (
                    Some(engine.public_key().clone()),
                    Some(engine),
                    Some(shared_secret),
                )
            } else {
                (None, None, None)
            };

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key: server_key_agreement_pk,
            signature: None,
        };

        transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            state_data: ServerAwaitingKeyExchange {
                kem_key_pair,
                key_agreement_engine,
                agreement_shared_secret,
                resumption_master_secret,
            },
            suite,
            transcript,
            signature_key_pair,
            ticket_encryption_key,
        };

        Ok((server_hello, next_server))
    }
}

/// Attempts to decrypt and validate a session ticket.
///
/// Returns the master secret if the ticket is valid, otherwise returns `None`.
///
/// 尝试解密并验证会话票据。
///
/// 如果票据有效，则返回主密钥，否则返回 `None`。
fn try_decode_ticket(
    ticket_encryption_key: Option<&TypedAeadKey>,
    encrypted_ticket: Option<Vec<u8>>,
) -> Result<Option<SharedSecret>> {
    let (tek, encrypted_ticket) = match (ticket_encryption_key, encrypted_ticket) {
        (Some(tek), Some(ticket)) => (tek, ticket),
        // If no key or no ticket, we can't resume.
        _ => return Ok(None),
    };

    // Decrypt the ticket.
    let pending_decryption =
        seal_flow::prelude::prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_ticket, None)?;

    let serialized_ticket =
        pending_decryption.decrypt_ordinary(std::borrow::Cow::Borrowed(tek), None)?;

    // Deserialize and validate the ticket.
    let ticket: SessionTicket =
        bincode::decode_from_slice(&serialized_ticket, bincode::config::standard())?.0;

    // Check for expiry.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HandshakeError::InvalidState)?
        .as_secs();

    if ticket.expiry_timestamp <= now {
        // Ticket has expired.
        return Ok(None);
    }

    Ok(Some(ticket.master_secret))
}
