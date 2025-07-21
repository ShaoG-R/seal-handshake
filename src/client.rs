//! Implements the client-side of the handshake protocol state machine.

use crate::error::{HandshakeError, Result};
use crate::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use crate::state::{AwaitingKemPublicKey, Established, Ready};
use crate::suite::{ProtocolSuite, ProtocolSuiteBuilder};
use seal_flow::common::header::SymmetricParamsBuilder;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{KemAlgorithmTrait, SymmetricAlgorithmTrait};
use seal_flow::crypto::wrappers::asymmetric::kem::KemAlgorithmWrapper;
use seal_flow::crypto::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;
use seal_flow::crypto::wrappers::kdf::key::KdfKeyWrapper;
use seal_flow::crypto::wrappers::symmetric::SymmetricAlgorithmWrapper;
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::marker::PhantomData;

/// The client-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
#[derive(Debug)]
pub struct HandshakeClient<S> {
    state: PhantomData<S>,
    suite: ProtocolSuite,
    // Derived keys for encryption (client-to-server) and decryption (server-to-client).
    // These are established after the key exchange.
    encryption_key: Option<TypedSymmetricKey>,
    decryption_key: Option<TypedSymmetricKey>,
}

/// A builder for constructing and configuring a `HandshakeClient`.
#[derive(Default)]
pub struct HandshakeClientBuilder {
    suite_builder: ProtocolSuiteBuilder,
}

impl HandshakeClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kem(mut self, kem: KemAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_kem(kem);
        self
    }

    pub fn with_key_agreement(mut self, ka: KeyAgreementAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_key_agreement(ka);
        self
    }

    pub fn with_aead(mut self, aead: SymmetricAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_aead(aead);
        self
    }

    pub fn with_kdf(mut self, kdf: KdfKeyWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_kdf(kdf);
        self
    }

    /// Builds the `HandshakeClient` in its initial `Ready` state.
    pub fn build(self) -> HandshakeClient<Ready> {
        HandshakeClient {
            state: PhantomData,
            suite: self.suite_builder.build(),
            encryption_key: None,
            decryption_key: None,
        }
    }
}

impl<S> HandshakeClient<S> {
    /// Returns a builder for the `HandshakeClient`.
    pub fn builder() -> HandshakeClientBuilder {
        HandshakeClientBuilder::new()
    }
}

impl HandshakeClient<Ready> {
    /// Starts the handshake by creating a `ClientHello` message.
    pub fn start_handshake(self) -> (HandshakeMessage, HandshakeClient<AwaitingKemPublicKey>) {
        let client_hello = HandshakeMessage::ClientHello;

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            encryption_key: None,
            decryption_key: None,
        };

        (client_hello, next_client)
    }
}

impl HandshakeClient<AwaitingKemPublicKey> {
    /// Processes the `ServerHello` message, generates session keys,
    /// and creates a `ClientKeyExchange` message.
    pub fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established>)> {
        let (server_pk, kem_algorithm) = match message {
            HandshakeMessage::ServerHello {
                public_key,
                kem_algorithm,
            } => (public_key, kem_algorithm),
            _ => return Err(HandshakeError::InvalidMessage),
        };

        let aead = self.suite.aead();
        let kdf = self.suite.kdf();
        let kem = kem_algorithm.into_asymmetric_wrapper();

        // KEM: Encapsulate a shared secret.
        let (shared_secret, encapsulated_key) = kem.encapsulate_key(&server_pk)?;

        // KDF: Define parameters for client-to-server key derivation.
        let kdf_params = KdfParams {
            algorithm: kdf.algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-c2s".to_vec()),
        };

        // KDF: Derive encryption and decryption keys.
        let encryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(), // c2s info
            aead.algorithm(),
        )?;
        let decryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            Some(b"seal-handshake-s2c"), // s2c info
            aead.algorithm(),
        )?;

        // DEM: Encrypt the initial payload using seal-flow.
        let aad = b"seal-handshake-aad";
        let params = SymmetricParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let header = EncryptedHeader {
            params,
            kem_algorithm,
            kdf_params,
        };

        let encrypted_message = EncryptionConfigurator::new(
            header,
            Cow::Borrowed(&encryption_key),
            Some(aad.to_vec()),
        )
        .into_writer(Vec::new())?
        .encrypt_ordinary_to_vec(initial_payload.unwrap_or(&[]))?;

        let key_exchange_msg = HandshakeMessage::ClientKeyExchange {
            encrypted_message,
            encapsulated_key,
        };

        let established_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            encryption_key: Some(encryption_key),
            decryption_key: Some(decryption_key),
        };

        Ok((key_exchange_msg, established_client))
    }
}

impl HandshakeClient<Established> {
    /// Encrypts application data using the established session key.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        let aead = self.suite.aead();
        let params = SymmetricParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        // In a real application, the header would be part of a larger protocol message.
        // For simplicity, we create a dummy header here.
        let kdf_params = KdfParams {
            algorithm: self.suite.kdf().algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-c2s".to_vec()),
        };
        let header = EncryptedHeader {
            params,
            kem_algorithm: self.suite.kem().algorithm(),
            kdf_params,
        };

        EncryptionConfigurator::new(header, Cow::Borrowed(key), Some(aad.to_vec()))
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(plaintext)
            .map_err(Into::into)
    }

    /// Decrypts a `ServerFinished` message.
    pub fn decrypt(&self, message: HandshakeMessage, aad: &[u8]) -> Result<Vec<u8>> {
        let encrypted_message = match message {
            HandshakeMessage::ServerFinished {
                encrypted_message,
            } => encrypted_message,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message)?;

        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}