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
    transcript::Transcript,
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
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, ServerAwaitingKeyExchange, WithSignature>,
    )> {
        let (
            kem_public_key,
            server_key_agreement_pk,
            next_state_data,
            mut transcript,
        ) = process_client_hello_common(&mut self, message)?;

        // Sign the ephemeral keys.
        let signature = sign_ephemeral_keys(
            &kem_public_key,
            &server_key_agreement_pk,
            &self.signature_key_pair.private_key(),
        )?;

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key: server_key_agreement_pk,
            signature: Some(signature),
        };

        transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            preset_suite: self.preset_suite,
            state_data: next_state_data,
            transcript,
            signature_key_pair: self.signature_key_pair,
            ticket_encryption_key: self.ticket_encryption_key,
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
        mut self,
        message: HandshakeMessage,
    ) -> Result<(
        HandshakeMessage,
        HandshakeServer<AwaitingKeyExchange, ServerAwaitingKeyExchange, WithoutSignature>,
    )> {
        let (
            kem_public_key,
            server_key_agreement_pk,
            next_state_data,
            mut transcript,
        ) = process_client_hello_common(&mut self, message)?;

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key: server_key_agreement_pk,
            signature: None,
        };

        transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            preset_suite: self.preset_suite,
            state_data: next_state_data,
            transcript,
            signature_key_pair: self.signature_key_pair,
            ticket_encryption_key: self.ticket_encryption_key,
        };

        Ok((server_hello, next_server))
    }
}

/// Helper function to process the common logic of `ClientHello`.
fn process_client_hello_common<Sig: SignaturePresence>(
    server: &mut HandshakeServer<Ready, ServerReady, Sig>,
    message: HandshakeMessage,
) -> Result<(
    seal_flow::crypto::prelude::TypedKemPublicKey,
    Option<seal_flow::crypto::prelude::TypedKeyAgreementPublicKey>,
    ServerAwaitingKeyExchange,
    Transcript,
)> {
    server.transcript.update(&message);

    let (client_key_agreement_pk, resumption_master_secret, kem_algorithm, aead_algorithm, kdf_algorithm) = match message {
        HandshakeMessage::ClientHello {
            key_agreement_public_key,
            session_ticket,
            kem_algorithm,
            aead_algorithm,
            kdf_algorithm,
        } => {
            if let Some(suite) = server.preset_suite.as_ref() {
                if suite.kem() != kem_algorithm {
                    return Err(HandshakeError::InvalidKemAlgorithm);
                }
                if suite.aead() != aead_algorithm {
                    return Err(HandshakeError::InvalidAeadAlgorithm);
                }
                if suite.kdf() != kdf_algorithm {
                    return Err(HandshakeError::InvalidKdfAlgorithm);
                }
            }

            (
                key_agreement_public_key,
                try_decode_ticket(server.ticket_encryption_key.as_ref(), session_ticket)?,
                kem_algorithm,
                aead_algorithm,
                kdf_algorithm,
            )
        }
        _ => return Err(HandshakeError::InvalidMessage),
    };

    // KEM key generation
    let kem_key_pair = kem_algorithm.into_wrapper().generate_keypair()?;
    let kem_public_key = kem_key_pair.public_key().clone();

    // Key Agreement
    let (key_agreement_engine, agreement_shared_secret, server_key_agreement_pk) =
        if let Some((engine, secret)) =
            KeyAgreementEngine::new_for_server(client_key_agreement_pk.as_ref())?
        {
            let pk = engine.public_key().clone();
            (Some(engine), Some(secret), Some(pk))
        } else {
            (None, None, None)
        };

    let next_state_data = ServerAwaitingKeyExchange {
        kem_key_pair,
        key_agreement_engine,
        agreement_shared_secret,
        resumption_master_secret,
        aead_algorithm,
        kdf_algorithm,
    };

    Ok((kem_public_key, server_key_agreement_pk, next_state_data, server.transcript.clone()))
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
