//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。

use crate::error::{HandshakeError, Result};
use crate::keys::derive_session_keys;
use crate::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use crate::suite::{KeyAgreementEngine, ProtocolSuite};
use crate::state::{AwaitingKeyExchange, Established, Ready};
use crate::transcript::Transcript;
use seal_flow::common::header::AeadParamsBuilder;
use seal_flow::crypto::bincode;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, SignatureAlgorithmTrait,
};
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::marker::PhantomData;

// --- State Markers ---
// (State markers are now imported from `crate::state`)

/// The server-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
///
/// 服务器端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
#[derive(Debug)]
pub struct HandshakeServer<S> {
    /// Zero-sized marker to hold the current state `S`.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    state: PhantomData<S>,
    /// The cryptographic suite used for the handshake.
    ///
    /// 握手过程中使用的密码套件。
    suite: ProtocolSuite,
    /// A running hash of the handshake transcript for integrity checks.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    transcript: Transcript,
    /// The server's long-term identity key pair for signing.
    ///
    /// 服务器用于签名的长期身份密钥对。
    signature_key_pair: TypedSignatureKeyPair,
    /// The server's ephemeral KEM key pair, generated for this session.
    /// It is consumed after the key exchange.
    ///
    /// 服务器为此会话生成的临时 KEM 密钥对。
    /// 它在密钥交换后被消耗。
    kem_key_pair: Option<TypedKemKeyPair>,
    /// The server's ephemeral key agreement key pair, if used.
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The shared secret derived from key agreement, if used.
    agreement_shared_secret: Option<SharedSecret>,
    /// Derived key for encryption (server-to-client).
    ///
    /// 用于加密（服务器到客户端）的派生密钥。
    encryption_key: Option<TypedAeadKey>,
    /// Derived key for decryption (client-to-server).
    ///
    /// 用于解密（客户端到服务器）的派生密钥。
    decryption_key: Option<TypedAeadKey>,
}


impl HandshakeServer<Ready> {
    /// Creates a new `HandshakeServer` in the `Ready` state.
    ///
    /// This constructor takes the protocol suite and the server's identity key.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeServer`。
    ///
    /// 此构造函数接收协议套件和服务器的身份密钥。
    pub fn new(suite: ProtocolSuite, signature_key_pair: TypedSignatureKeyPair) -> Self {
        Self {
            state: PhantomData,
            suite,
            transcript: Transcript::new(),
            signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: None,
            agreement_shared_secret: None,
            encryption_key: None,
            decryption_key: None,
        }
    }
}

impl HandshakeServer<Ready> {
    /// Processes a `ClientHello` message.
    ///
    /// On receiving `ClientHello`, the server generates an ephemeral KEM key pair
    /// and responds with a `ServerHello` containing the public key.
    /// It then transitions to the `AwaitingKeyExchange` state.
    ///
    /// 处理 `ClientHello` 消息。
    ///
    /// 收到 `ClientHello` 后，服务器会生成一个临时的 KEM 密钥对，
    /// 并用包含公钥的 `ServerHello` 进行响应。
    /// 然后它转换到 `AwaitingKeyExchange` 状态。
    pub fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange>)> {
        // Update transcript with ClientHello before processing.
        // 在处理之前，使用 ClientHello 更新握手记录。
        self.transcript.update(&message);

        match message {
            HandshakeMessage::ClientHello {
                key_agreement_public_key: client_key_agreement_pk,
            } => {
                // KEM key generation (always happens)
                let kem = self.suite.kem();
                let kem_key_pair = kem.generate_keypair()?;
                let kem_public_key = kem_key_pair.public_key().clone();

                // Key Agreement, if requested by the client and supported by the server.
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

                // Sign the ephemeral public keys with the long-term identity key.
                let signature = if let Some(signer) = self.suite.signature() {
                    let data_to_sign = {
                        let kem_pk_bytes =
                            bincode::encode_to_vec(&kem_public_key, bincode::config::standard())
                                .map_err(HandshakeError::from)?;
                        if let Some(key_agreement_pk) = &server_key_agreement_pk {
                            let mut combined = kem_pk_bytes;
                            let key_agreement_pk_bytes = bincode::encode_to_vec(
                                key_agreement_pk,
                                bincode::config::standard(),
                            )
                            .map_err(HandshakeError::from)?;
                            combined.extend_from_slice(&key_agreement_pk_bytes);
                            combined
                        } else {
                            kem_pk_bytes
                        }
                    };
                    Some(signer.sign(&data_to_sign, &self.signature_key_pair.private_key())?)
                } else {
                    None
                };

                let server_hello = HandshakeMessage::ServerHello {
                    kem_public_key,
                    kem_algorithm: kem.algorithm(),
                    key_agreement_public_key: server_key_agreement_pk,
                    signature,
                };

                // Update transcript with ServerHello before sending.
                // 在发送之前，使用 ServerHello 更新握手记录。
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
                };

                Ok((server_hello, next_server))
            }
            _ => Err(HandshakeError::InvalidMessage),
        }
    }
}

impl HandshakeServer<AwaitingKeyExchange> {
    /// Processes a `ClientKeyExchange` message.
    ///
    /// This method performs the server-side key exchange:
    /// 1. Decapsulates the shared secret using its private key.
    /// 2. Derives session keys (for encryption and decryption).
    /// 3. Decrypts the initial payload from the client.
    ///
    /// Upon success, it returns the decrypted payload and transitions to the `Established` state.
    ///
    /// 处理 `ClientKeyExchange` 消息。
    ///
    /// 此方法执行服务器端的密钥交换：
    /// 1. 使用其私钥解封装共享密钥。
    /// 2. 派生会话密钥（用于加密和解密）。
    /// 3. 解密来自客户端的初始负载。
    ///
    /// 成功后，它返回解密的负载并转换到 `Established` 状态。
    pub fn process_client_key_exchange(
        mut self,
        message: HandshakeMessage,
        aad: &[u8],
    ) -> Result<(Vec<u8>, HandshakeServer<Established>)> {
        // Update transcript with ClientKeyExchange before processing.
        // 在处理之前，使用 ClientKeyExchange 更新握手记录。
        self.transcript.update(&message);

        // Extract the encrypted message and encapsulated key from the client's message.
        // 从客户端消息中提取加密消息和封装的密钥。
        let (encrypted_message, encapsulated_key) = match message {
            HandshakeMessage::ClientKeyExchange {
                encrypted_message,
                encapsulated_key,
            } => (encrypted_message, encapsulated_key),
            _ => return Err(HandshakeError::InvalidMessage),
        };

        // The KEM key pair must be present in this state.
        // 在此状态下，KEM 密钥对必须存在。
        let kem_key_pair = self
            .kem_key_pair
            .take()
            .ok_or(HandshakeError::InvalidState)?;

        // Parse the header from the encrypted message to get KDF/AEAD parameters.
        // The client does not send a transcript signature, so `verify_key` is `None`.
        //
        // 从加密消息中解析头部以获取 KDF/AEAD 参数。
        // 客户端不发送握手记录签名，因此 `verify_key` 为 `None`。
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message, None)?;
        let header = pending_decryption.header().clone();

        // KEM: Decapsulate the shared secret using the server's private key.
        // KEM：使用服务器的私钥解封装共享密钥。
        let kem = header.kem_algorithm.into_wrapper();
        let shared_secret =
            kem.decapsulate_key(&kem_key_pair.private_key(), &encapsulated_key)?;

        // KDF: Derive session keys from the shared secrets.
        let session_keys = derive_session_keys(
            &self.suite,
            shared_secret,
            self.agreement_shared_secret.take(),
            false, // is_client = false
        )?;

        // DEM: Decrypt the initial payload sent by the client.
        // DEM：解密客户端发送的初始负载。
        let initial_payload = pending_decryption
            .decrypt_ordinary(Cow::Borrowed(&session_keys.decryption_key), Some(aad.to_vec()))?;

        // Transition to the `Established` state with the derived session keys.
        // 使用派生的会话密钥转换到 `Established` 状态。
        let established_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: None, // Consumed
            key_agreement_engine: self.key_agreement_engine,
            agreement_shared_secret: None, // Consumed
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
        };

        Ok((initial_payload, established_server))
    }
}

impl HandshakeServer<Established> {
    /// Encrypts application data using the established server-to-client session key.
    /// If a signature scheme is configured, it will also sign the handshake transcript
    /// and include the signature in the header of the first encrypted message.
    ///
    /// 使用已建立的服务器到客户端的会话密钥来加密应用数据。
    /// 如果配置了签名方案，它还将对握手记录进行签名，并将签名包含在第一个加密消息的头部。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        let (signature_algorithm, signed_transcript_hash, transcript_signature) =
            if let Some(signer) = self.suite.signature() {
                // Finalize the transcript hash.
                let transcript_hash = self.transcript.current_hash();

                // Sign the hash.
                let signature =
                    signer.sign(&transcript_hash, &self.signature_key_pair.private_key())?;

                (
                    Some(signer.algorithm()),
                    Some(transcript_hash),
                    Some(signature),
                )
            } else {
                (None, None, None)
            };

        let aead = self.suite.aead();
        let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        // The header contains parameters needed by the recipient for decryption.
        // 头部包含接收方解密所需的参数。
        let kdf_params = KdfParams {
            algorithm: self.suite.kdf().algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-s2c".to_vec()), // s2c context
        };
        let header = EncryptedHeader {
            params,
            kem_algorithm: self.suite.kem().algorithm(),
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

    /// Decrypts application data from the client using the established client-to-server session key.
    ///
    /// 使用已建立的客户端到服务器的会话密钥来解密来自客户端的应用数据。
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Prepare the decryption by parsing the header from the encrypted message.
        // Client application data does not have a transcript signature, so `verify_key` is `None`.
        //
        // 通过从加密消息中解析头部来准备解密。
        // 客户端应用数据没有握手记录签名，因此 `verify_key` 为 `None`。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(ciphertext, None)?;

        // Perform the decryption and authentication.
        // 执行解密和身份验证。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}
