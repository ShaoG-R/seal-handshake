use super::{
    HandshakeServer, KeyAgreementEngine, Ready,
    SuiteProvider,
};
use crate::crypto::{
    signature::sign_ephemeral_keys,
    suite::{ProtocolSuiteBuilder, WithSignature, WithoutSignature},
};
use crate::error::{HandshakeError, Result};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, SessionTicket},
    state::{AwaitingKeyExchange, ServerAwaitingKeyExchange, ServerReady},
};
use seal_flow::crypto::{
    keys::asymmetric::kem::SharedSecret, prelude::{TypedAeadKey, TypedAsymmetricKeyTrait},
};
use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::bincode;

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
        self.transcript.update(&message);

        let (
            client_key_agreement_pk,
            resumption_master_secret,
            kem_algorithm,
            aead_algorithm,
            kdf_algorithm,
        ) = if let HandshakeMessage::ClientHello {
            key_agreement_public_key,
            session_ticket,
            kem_algorithm,
            aead_algorithm,
            kdf_algorithm,
        } = message
        {
            (
                key_agreement_public_key,
                try_decode_ticket(self.ticket_encryption_key.as_ref(), session_ticket)?,
                kem_algorithm,
                aead_algorithm,
                kdf_algorithm,
            )
        } else {
            return Err(HandshakeError::InvalidMessage);
        };

        // Handle suite negotiation or verification
        match &mut self.preset_suite {
            SuiteProvider::Preset(suite) => {
                if suite.kem() != kem_algorithm
                    || suite.aead() != aead_algorithm
                    || suite.kdf() != kdf_algorithm
                    || suite.signature() != self.signature_key_pair.get_algorithm()
                {
                    return Err(HandshakeError::MismatchedAlgorithms);
                }
            }
            SuiteProvider::Negotiated(negotiated_suite) => {
                let new_suite = ProtocolSuiteBuilder::new()
                    .with_kem(
                        kem_algorithm,
                        client_key_agreement_pk.as_ref().map(|k| k.algorithm()),
                    )
                    .with_signature(self.signature_key_pair.get_algorithm())
                    .with_aead(aead_algorithm)
                    .with_kdf(kdf_algorithm)
                    .build();
                *negotiated_suite = Some(new_suite);
            }
        }

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

        self.transcript.update(&server_hello);

        let next_state_data = ServerAwaitingKeyExchange {
            kem_key_pair,
            key_agreement_engine,
            agreement_shared_secret,
            resumption_master_secret,
        };

        let next_server = HandshakeServer {
            state: PhantomData,
            preset_suite: self.preset_suite,
            state_data: next_state_data,
            transcript: self.transcript,
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
        self.transcript.update(&message);

        let (
            client_key_agreement_pk,
            resumption_master_secret,
            kem_algorithm,
            aead_algorithm,
            kdf_algorithm,
        ) = if let HandshakeMessage::ClientHello {
            key_agreement_public_key,
            session_ticket,
            kem_algorithm,
            aead_algorithm,
            kdf_algorithm,
        } = message
        {
            (
                key_agreement_public_key,
                try_decode_ticket(self.ticket_encryption_key.as_ref(), session_ticket)?,
                kem_algorithm,
                aead_algorithm,
                kdf_algorithm,
            )
        } else {
            return Err(HandshakeError::InvalidMessage);
        };

        // Handle suite negotiation or verification
        match &mut self.preset_suite {
            SuiteProvider::Preset(suite) => {
                if suite.kem() != kem_algorithm
                    || suite.aead() != aead_algorithm
                    || suite.kdf() != kdf_algorithm
                {
                    return Err(HandshakeError::MismatchedAlgorithms);
                }
            }
            SuiteProvider::Negotiated(negotiated_suite) => {
                let new_suite = ProtocolSuiteBuilder::new()
                    .with_kem(
                        kem_algorithm,
                        client_key_agreement_pk.as_ref().map(|k| k.algorithm()),
                    )
                    .without_signature()
                    .with_aead(aead_algorithm)
                    .with_kdf(kdf_algorithm)
                    .build();
                *negotiated_suite = Some(new_suite);
            }
        }

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

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            key_agreement_public_key: server_key_agreement_pk,
            signature: None,
        };

        self.transcript.update(&server_hello);

        let next_state_data = ServerAwaitingKeyExchange {
            kem_key_pair,
            key_agreement_engine,
            agreement_shared_secret,
            resumption_master_secret,
        };

        let next_server = HandshakeServer {
            state: PhantomData,
            preset_suite: self.preset_suite,
            state_data: next_state_data,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            ticket_encryption_key: self.ticket_encryption_key,
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
