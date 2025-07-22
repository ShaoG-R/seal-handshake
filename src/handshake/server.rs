//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。


use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{AwaitingKeyExchange, Established, Ready},
    transcript::Transcript,
};
use crate::error::{HandshakeError, Result};
use crate::crypto::{
    keys::{derive_session_keys, SessionKeysAndMaster},
    signature::sign_ephemeral_keys,
    suite::{
        KeyAgreementEngine, ProtocolSuite, SignaturePresence, WithSignature, WithoutSignature,
    },
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        algorithms::asymmetric::signature::SignatureAlgorithm,
        wrappers::asymmetric::signature::SignatureWrapper,
    }, prelude::PendingDecryption,
};
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, SignatureAlgorithmTrait, KdfKeyAlgorithmTrait,
};
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::bincode;

// --- State Markers ---
// (State markers are now imported from `crate::state`)

/// The server-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
/// This ensures that methods can only be called in the correct sequence,
/// preventing logical errors in the protocol's implementation.
///
/// 服务器端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
/// 这确保了方法只能按正确的顺序调用，防止了协议实现中的逻辑错误。
#[derive(Debug)]
pub struct HandshakeServer<State, Sig: SignaturePresence> {
    /// Zero-sized marker to hold the current state `S`.
    /// This doesn't take up space but allows the type system to track the machine's state.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    /// 它不占用空间，但允许类型系统跟踪机器的状态。
    state: PhantomData<State>,
    /// The cryptographic suite used for the handshake.
    /// This defines the set of algorithms (KEM, AEAD, KDF, etc.) to be used.
    ///
    /// 握手过程中使用的密码套件。
    /// 这定义了要使用的算法集（KEM、AEAD、KDF 等）。
    suite: ProtocolSuite<Sig>,
    /// A running hash of the handshake transcript for integrity checks.
    /// It accumulates all messages exchanged, and its final hash is signed by the server.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    /// 它累积所有交换的消息，其最终哈希值由服务器签名。
    transcript: Transcript,
    /// The server's long-term identity key pair for signing.
    /// This key proves the server's identity to the client.
    ///
    /// 服务器用于签名的长期身份密钥对。
    /// 此密钥向客户端证明服务器的身份。
    signature_key_pair: Sig::ServerKey,
    /// The server's ephemeral KEM key pair, generated for this session.
    /// It is used once to decapsulate the shared secret from the client and then discarded.
    /// Stored as an `Option` because it only exists during a specific phase of the handshake.
    ///
    /// 服务器为此会话生成的临时 KEM 密钥对。
    /// 它用于从客户端解封装共享密钥一次，然后被丢弃。
    /// 存储为 `Option`，因为它只在握手的特定阶段存在。
    kem_key_pair: Option<TypedKemKeyPair>,
    /// The server's ephemeral key agreement engine, if used.
    /// This is part of an optional Diffie-Hellman style key agreement for Perfect Forward Secrecy.
    ///
    /// 服务器的临时密钥协商引擎（如果使用）。
    /// 这是可选的 Diffie-Hellman 风格密钥协商的一部分，用于实现前向保密。
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The shared secret derived from key agreement, if used.
    /// This secret is combined with the KEM secret to derive session keys.
    ///
    /// 从密钥协商中派生的共享密钥（如果使用）。
    /// 该密钥与 KEM 密钥结合以派生会话密钥。
    agreement_shared_secret: Option<SharedSecret>,
    /// Derived key for encryption (server-to-client).
    /// Established after a successful key exchange.
    ///
    /// 用于加密（服务器到客户端）的派生密钥。
    /// 在密钥交换成功后建立。
    encryption_key: Option<TypedAeadKey>,
    /// Derived key for decryption (client-to-server).
    /// Established after a successful key exchange.
    ///
    /// 用于解密（客户端到服务器）的派生密钥。
    /// 在密钥交换成功后建立。
    decryption_key: Option<TypedAeadKey>,
    /// The master secret for this session, used for creating session tickets.
    ///
    /// 当前会话的主密钥，用于创建会话票据。
    master_secret: Option<SharedSecret>,
    /// A long-term symmetric key used to encrypt session tickets.
    /// If not set, the server will not issue tickets.
    ///
    /// 用于加密会话票据的长期对称密钥。
    /// 如果未设置，服务器将不会签发票据。
    ticket_encryption_key: Option<TypedAeadKey>,
    /// The master secret recovered from a session ticket, if any.
    /// This is stored temporarily during the handshake.
    ///
    /// 从会话票据中恢复的主密钥（如果有）。
    /// 这在握手期间临时存储。
    resumption_master_secret: Option<SharedSecret>,
}

/// A builder for creating a `HandshakeServer`.
///
/// This builder ensures that all required fields are provided before constructing the server.
///
/// 用于创建 `HandshakeServer` 的构建器。
///
/// 此构建器确保在构造服务器之前提供了所有必需的字段。
#[derive(Default)]
pub struct HandshakeServerBuilder<Sig: SignaturePresence> {
    suite: Option<ProtocolSuite<Sig>>,
    signature_key_pair: Option<Sig::ServerKey>,
    ticket_encryption_key: Option<TypedAeadKey>,
}

impl<Sig: SignaturePresence> HandshakeServerBuilder<Sig> {
    /// Creates a new `HandshakeServerBuilder`.
    pub fn new() -> Self {
        Self {
            suite: None,
            signature_key_pair: None,
            ticket_encryption_key: None,
        }
    }

    /// Sets the protocol suite for the handshake.
    ///
    /// 设置握手所用的协议套件。
    pub fn suite(mut self, suite: ProtocolSuite<Sig>) -> Self {
        self.suite = Some(suite);
        self
    }

    /// Sets the server's long-term identity key pair for signing.
    ///
    /// This is required to authenticate the server.
    ///
    /// 设置用于签名的服务器长期身份密钥对。
    ///
    /// 这是验证服务器身份所必需的。
    pub fn signature_key_pair(mut self, key_pair: Sig::ServerKey) -> Self {
        self.signature_key_pair = Some(key_pair);
        self
    }

    /// Sets the key for encrypting session tickets.
    /// If not provided, the server will not be able to issue tickets for resumption.
    ///
    /// 设置用于加密会话票据的密钥。
    /// 如果不提供，服务器将无法为会话恢复签发票据。
    pub fn ticket_encryption_key(mut self, key: TypedAeadKey) -> Self {
        self.ticket_encryption_key = Some(key);
        self
    }

    /// Builds the `HandshakeServer`.
    ///
    /// Returns an error if any required fields are missing.
    ///
    /// 构建 `HandshakeServer`。
    ///
    /// 如果任何必需字段缺失，则返回错误。
    pub fn build(self) -> Result<HandshakeServer<Ready, Sig>> {
        let suite = self
            .suite
            .ok_or(HandshakeError::BuilderMissingField("suite"))?;
        let signature_key_pair = self.signature_key_pair.ok_or(
            HandshakeError::BuilderMissingField("signature_key_pair"),
        )?;

        Ok(HandshakeServer {
            state: PhantomData,
            suite,
            transcript: Transcript::new(),
            signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: None,
            agreement_shared_secret: None,
            encryption_key: None,
            decryption_key: None,
            master_secret: None,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: None,
        })
    }
}


impl<Sig: SignaturePresence> HandshakeServer<Ready, Sig> {
    /// Creates a new `HandshakeServerBuilder` to construct a `HandshakeServer`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeServer` 的构建器。
    pub fn builder() -> HandshakeServerBuilder<Sig> {
        HandshakeServerBuilder::new()
    }
}

// --- `process_client_hello` implementations ---

impl HandshakeServer<Ready, WithSignature> {
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
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange, WithSignature>)> {
        self.transcript.update(&message);

        let (client_key_agreement_pk, resumption_master_secret) =
            match message {
                HandshakeMessage::ClientHello {
                    key_agreement_public_key,
                    session_ticket,
                } => (
                    key_agreement_public_key,
                    self.try_decode_ticket(session_ticket)?,
                ),
                _ => return Err(HandshakeError::InvalidMessage),
            };
        
        self.resumption_master_secret = resumption_master_secret;

        // KEM key generation
        let kem = self.suite.kem();
        let kem_key_pair = kem.generate_keypair()?;
        let kem_public_key = kem_key_pair.public_key().clone();

        // Key Agreement
        let (server_key_agreement_pk, key_agreement_engine, agreement_shared_secret) =
            if let (Some(client_pk), Some(key_agreement)) =
                (client_key_agreement_pk, self.suite.key_agreement())
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
        let signer = self.suite.signature();
        let signature = sign_ephemeral_keys(
            signer,
            &kem_public_key,
            &server_key_agreement_pk,
            &self.signature_key_pair.private_key(),
        )?;

        let server_hello = HandshakeMessage::ServerHello {
            kem_public_key,
            kem_algorithm: kem.algorithm(),
            key_agreement_public_key: server_key_agreement_pk,
            signature: Some(signature),
        };

        self.transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: Some(kem_key_pair),
            key_agreement_engine,
            agreement_shared_secret,
            encryption_key: None,
            decryption_key: None,
            master_secret: None,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: self.resumption_master_secret,
        };

        Ok((server_hello, next_server))
    }
}

impl HandshakeServer<Ready, WithoutSignature> {
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
        HandshakeServer<AwaitingKeyExchange, WithoutSignature>,
    )> {
        self.transcript.update(&message);

        let (client_key_agreement_pk, resumption_master_secret) =
            match message {
                HandshakeMessage::ClientHello {
                    key_agreement_public_key,
                    session_ticket,
                } => (
                    key_agreement_public_key,
                    self.try_decode_ticket(session_ticket)?,
                ),
                _ => return Err(HandshakeError::InvalidMessage),
            };
        
        self.resumption_master_secret = resumption_master_secret;

        // KEM key generation
        let kem = self.suite.kem();
        let kem_key_pair = kem.generate_keypair()?;
        let kem_public_key = kem_key_pair.public_key().clone();

        // Key Agreement
        let (server_key_agreement_pk, key_agreement_engine, agreement_shared_secret) =
            if let (Some(client_pk), Some(key_agreement)) =
                (client_key_agreement_pk, self.suite.key_agreement())
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
            kem_algorithm: kem.algorithm(),
            key_agreement_public_key: server_key_agreement_pk,
            signature: None,
        };

        self.transcript.update(&server_hello);

        let next_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: Some(kem_key_pair),
            key_agreement_engine,
            agreement_shared_secret,
            encryption_key: None,
            decryption_key: None,
            master_secret: None,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: self.resumption_master_secret,
        };

        Ok((server_hello, next_server))
    }
}

impl<Sig: SignaturePresence> HandshakeServer<AwaitingKeyExchange, Sig> {
    /// Processes a `ClientKeyExchange` message.
    ///
    /// This method performs the core server-side key exchange:
    /// 1. Receives the encapsulated key and encrypted payload from the client.
    /// 2. Uses its ephemeral private KEM key to decapsulate the shared secret.
    /// 3. Combines the KEM secret with the key agreement secret (if any) and derives session keys using a KDF.
    /// 4. Uses the derived client-to-server key to decrypt the initial payload.
    /// 5. Transitions to the `Established` state, now ready for secure application data exchange.
    ///
    /// 处理 `ClientKeyExchange` 消息。
    ///
    /// 此方法执行服务器端的核心密钥交换：
    /// 1. 从客户端接收封装的密钥和加密的负载。
    /// 2. 使用其临时的私有 KEM 密钥来解封装共享密钥。
    /// 3. 将 KEM 密钥与密钥协商密钥（如果有）结合，并使用 KDF 派生会话密钥。
    /// 4. 使用派生的客户端到服务器密钥来解密初始负载。
    /// 5. 转换到 `Established` 状态，此时可以进行安全的应用数据交换。
    pub fn process_client_key_exchange(
        mut self,
        message: HandshakeMessage,
        aad: &[u8],
    ) -> Result<(Vec<u8>, HandshakeServer<Established, Sig>)> {
        self.transcript.update(&message);

        let (encrypted_message, encapsulated_key) =
            extract_client_key_exchange(&message)?;

        let kem_key_pair = self
            .kem_key_pair
            .take()
            .ok_or(HandshakeError::InvalidState)?;

        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message, None)?;

        let session_keys = derive_session_keys_from_client_exchange(
            &self,
            &kem_key_pair,
            &encapsulated_key,
            pending_decryption.header(),
        )?;

        let initial_payload = decrypt_initial_payload(
            pending_decryption,
            &session_keys.decryption_key,
            aad,
        )?;

        let established_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: self.key_agreement_engine,
            agreement_shared_secret: None,
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
            master_secret: Some(session_keys.master_secret),
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: None,
        };

        Ok((initial_payload, established_server))
    }
}

/// Extracts the contents of a `ClientKeyExchange` message.
fn extract_client_key_exchange(
    message: &HandshakeMessage,
) -> Result<(Vec<u8>, EncapsulatedKey)> {
    match message {
        HandshakeMessage::ClientKeyExchange {
            encrypted_message,
            encapsulated_key,
        } => Ok((encrypted_message.clone(), encapsulated_key.clone())),
        _ => Err(HandshakeError::InvalidMessage),
    }
}

/// Derives session keys from the client's key exchange data.
fn derive_session_keys_from_client_exchange<Sig: SignaturePresence>(
    server: &HandshakeServer<AwaitingKeyExchange, Sig>,
    kem_key_pair: &TypedKemKeyPair,
    encapsulated_key: &EncapsulatedKey,
    header: &EncryptedHeader,
) -> Result<SessionKeysAndMaster> {
    let kem = header.kem_algorithm.into_wrapper();
    let shared_secret =
        kem.decapsulate_key(&kem_key_pair.private_key(), encapsulated_key)?;

    derive_session_keys(
        &server.suite,
        shared_secret,
        server.agreement_shared_secret.clone(),
        server.resumption_master_secret.clone(),
        false, // is_client = false
    )
}

/// Decrypts the initial payload from the client.
fn decrypt_initial_payload(
    pending_decryption: PendingDecryption<&[u8], EncryptedHeader>,
    decryption_key: &TypedAeadKey,
    aad: &[u8],
) -> Result<Vec<u8>> {
    pending_decryption
        .decrypt_ordinary(Cow::Borrowed(decryption_key), Some(aad.to_vec()))
        .map_err(Into::into)
}

impl<Sig: SignaturePresence> HandshakeServer<Ready, Sig> {
    /// Attempts to decrypt and validate a session ticket.
    ///
    /// Returns the master secret if the ticket is valid, otherwise returns `None`.
    ///
    /// 尝试解密并验证会话票据。
    ///
    /// 如果票据有效，则返回主密钥，否则返回 `None`。
    fn try_decode_ticket(
        &self,
        encrypted_ticket: Option<Vec<u8>>,
    ) -> Result<Option<SharedSecret>> {
        let (tek, encrypted_ticket) =
            match (self.ticket_encryption_key.as_ref(), encrypted_ticket) {
                (Some(tek), Some(ticket)) => (tek, ticket),
                // If no key or no ticket, we can't resume.
                _ => return Ok(None),
            };

        // Decrypt the ticket.
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_ticket, None)?;

        let serialized_ticket = pending_decryption.decrypt_ordinary(Cow::Borrowed(tek), None)?;

        // Deserialize and validate the ticket.
        let ticket: crate::protocol::message::SessionTicket =
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
}


// --- `encrypt` and `decrypt` implementations ---

impl<Sig: SignaturePresence> HandshakeServer<Established, Sig> {
    /// Issues a new session ticket for the client to use for resumption.
    ///
    /// This method can only be called after the handshake is established. It encrypts
    /// the session's master secret with a long-term ticket encryption key.
    ///
    /// 为客户端签发一个新的会话票据，用于会话恢复。
    ///
    /// 此方法只能在握手建立后调用。它使用一个长期的票据加密密钥
    /// 来加密会话的主密钥。
    pub fn issue_session_ticket(&self) -> Result<HandshakeMessage> {
        let tek = self
            .ticket_encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Create the ticket with a 1-hour expiry.
        let expiry = SystemTime::now()
            .checked_add(Duration::from_secs(3600))
            .ok_or(HandshakeError::InvalidState)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HandshakeError::InvalidState)?
            .as_secs();

        let ticket_data = crate::protocol::message::SessionTicket {
            master_secret: master_secret.clone(),
            expiry_timestamp: expiry,
        };

        let serialized_ticket = bincode::encode_to_vec(ticket_data, bincode::config::standard())?;

        // Encrypt the ticket using the server's TEK.
        // We use the AEAD algorithm from the current suite for consistency.
        let aead = self.suite.aead();
        let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let header = EncryptedHeader {
                params,
                // These fields are not relevant for ticket encryption but are part of the struct.
            kem_algorithm: self.suite.kem().algorithm(),
            kdf_params: KdfParams {
                algorithm: self.suite.kdf().algorithm(),
                salt: None,
                info: None,
            },
            signature_algorithm: None,
            signed_transcript_hash: None,
            transcript_signature: None,
        };

        // Note: The AAD is empty here as there's no additional data to authenticate.
        let encrypted_ticket =
            EncryptionConfigurator::new(header, Cow::Borrowed(tek), None)
                .into_writer(Vec::new())?
                .encrypt_ordinary_to_vec(&serialized_ticket)?;

        Ok(HandshakeMessage::NewSessionTicket {
            ticket: encrypted_ticket,
        })
    }
}

impl HandshakeServer<Established, WithSignature> {
    /// Encrypts data and signs the transcript when a signature scheme is configured.
    ///
    /// 当配置了签名方案时，加密数据并对握手记录进行签名。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Sign the transcript.
        let signer = self.suite.signature();
        let transcript_hash = self.transcript.current_hash();
        let signature = signer.sign(&transcript_hash, &self.signature_key_pair.private_key())?;

        // Encrypt with the signature.
        common_encrypt(
            self,
            plaintext,
            aad,
            key,
            Some(signer.algorithm()),
            Some(transcript_hash),
            Some(signature.into()),
        )
    }
}

impl HandshakeServer<Established, WithoutSignature> {
    /// Encrypts data without signing when no signature scheme is configured.
    ///
    /// 当未配置签名方案时，加密数据而不进行签名。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Encrypt without a signature.
        common_encrypt(self, plaintext, aad, key, None, None, None)
    }
}

/// Helper function for the common encryption logic.
///
/// 用于通用加密逻辑的辅助函数。
fn common_encrypt<Sig: SignaturePresence>(
    server: &HandshakeServer<Established, Sig>,
    plaintext: &[u8],
    aad: &[u8],
    key: &TypedAeadKey,
    signature_algorithm: Option<SignatureAlgorithm>,
    signed_transcript_hash: Option<Vec<u8>>,
    transcript_signature: Option<SignatureWrapper>,
) -> Result<Vec<u8>> {
    let aead = server.suite.aead();
    let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
        .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
        .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
        .build();

    let kdf_params = KdfParams {
        algorithm: server.suite.kdf().algorithm(),
        salt: Some(b"seal-handshake-salt".to_vec()),
        info: Some(b"seal-handshake-s2c".to_vec()),
    };
    let header = EncryptedHeader {
        params,
        kem_algorithm: server.suite.kem().algorithm(),
        kdf_params,
        signature_algorithm,
        signed_transcript_hash,
        transcript_signature,
    };

    EncryptionConfigurator::new(header, Cow::Borrowed(key), Some(aad.to_vec()))
        .into_writer(Vec::new())?
        .encrypt_ordinary_to_vec(plaintext)
        .map_err(Into::into)
}

impl<Sig: SignaturePresence> HandshakeServer<Established, Sig> {
    /// Decrypts application data from the client using the established client-to-server session key.
    ///
    /// This method is used to process secure data sent by the client after the handshake is complete.
    ///
    /// 使用已建立的客户端到服务器的会话密钥来解密来自客户端的应用数据。
    ///
    /// 此方法用于处理握手完成后客户端发送的安全数据。
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Prepare the decryption by parsing the header from the encrypted message.
        // For application data from the client, there is no transcript signature to verify,
        // so `verify_key` is `None`. The integrity of the message is protected by the AEAD tag.
        //
        // 通过从加密消息中解析头部来准备解密。
        // 对于来自客户端的应用数据，没有需要验证的握手记录签名，
        // 因此 `verify_key` 为 `None`。消息的完整性由 AEAD 标签保护。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(ciphertext, None)?;

        // Perform the decryption. The AEAD algorithm will simultaneously decrypt the data and
        // verify its authenticity and integrity using the key and the AAD.
        //
        // 执行解密。AEAD 算法将同时解密数据并使用密钥和 AAD
        // 验证其真实性和完整性。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}
