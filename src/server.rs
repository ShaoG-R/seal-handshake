//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。

use crate::error::{HandshakeError, Result};
use crate::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use crate::suite::{ProtocolSuite, ProtocolSuiteBuilder};
use seal_flow::common::header::SymmetricParamsBuilder;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{KemAlgorithmTrait, SymmetricAlgorithmTrait};
use seal_flow::crypto::wrappers::asymmetric::kem::KemAlgorithmWrapper;
use seal_flow::crypto::wrappers::asymmetric::key_agreement::KeyAgreementAlgorithmWrapper;
use seal_flow::crypto::wrappers::kdf::key::KdfKeyWrapper;
use seal_flow::crypto::wrappers::symmetric::SymmetricAlgorithmWrapper;
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator, SealFlowHeader};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::marker::PhantomData;

// --- State Markers ---

/// Represents the initial `Ready` state of the server.
/// In this state, the server is waiting for a `ClientHello`.
///
/// 表示服务器的初始 `Ready` 状态。
/// 在此状态下，服务器正在等待 `ClientHello`。
#[derive(Debug)]
pub struct Ready;

/// Represents the `AwaitingKeyExchange` state of the server.
/// In this state, the server has sent its `ServerHello` and is waiting for the client's key exchange message.
///
/// 表示服务器的 `AwaitingKeyExchange` 状态。
/// 在此状态下，服务器已发送其 `ServerHello` 并等待客户端的密钥交换消息。
#[derive(Debug)]
pub struct AwaitingKeyExchange;

/// Represents the `Established` state of the server.
/// In this state, the handshake is complete, and secure communication can begin.
///
/// 表示服务器的 `Established` 状态。
/// 在此状态下，握手完成，可以开始安全通信。
#[derive(Debug)]
pub struct Established;

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
    /// The server's ephemeral KEM key pair, generated for this session.
    /// It is consumed after the key exchange.
    ///
    /// 服务器为此会话生成的临时 KEM 密钥对。
    /// 它在密钥交换后被消耗。
    kem_key_pair: Option<TypedKemKeyPair>,
    /// Derived key for encryption (server-to-client).
    ///
    /// 用于加密（服务器到客户端）的派生密钥。
    encryption_key: Option<TypedSymmetricKey>,
    /// Derived key for decryption (client-to-server).
    ///
    /// 用于解密（客户端到服务器）的派生密钥。
    decryption_key: Option<TypedSymmetricKey>,
}

/// A builder for constructing and configuring a `HandshakeServer`.
///
/// 用于构建和配置 `HandshakeServer` 的构建器。
#[derive(Default)]
pub struct HandshakeServerBuilder {
    suite_builder: ProtocolSuiteBuilder,
}

impl HandshakeServerBuilder {
    /// Creates a new `HandshakeServerBuilder`.
    ///
    /// 创建一个新的 `HandshakeServerBuilder`。
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Key Encapsulation Mechanism (KEM) for the protocol suite.
    ///
    /// 为协议套件设置密钥封装机制 (KEM)。
    pub fn with_kem(mut self, kem: KemAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_kem(kem);
        self
    }

    /// Sets the Key Agreement algorithm for the protocol suite.
    ///
    /// 为协议套件设置密钥协商算法。
    pub fn with_key_agreement(mut self, ka: KeyAgreementAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_key_agreement(ka);
        self
    }

    /// Sets the Authenticated Encryption with Associated Data (AEAD) algorithm.
    ///
    /// 设置带有关联数据的认证加密 (AEAD) 算法。
    pub fn with_aead(mut self, aead: SymmetricAlgorithmWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_aead(aead);
        self
    }

    /// Sets the Key Derivation Function (KDF).
    ///
    /// 设置密钥派生函数 (KDF)。
    pub fn with_kdf(mut self, kdf: KdfKeyWrapper) -> Self {
        self.suite_builder = self.suite_builder.with_kdf(kdf);
        self
    }

    /// Builds the `HandshakeServer` in its initial `Ready` state.
    ///
    /// 构建处于初始 `Ready` 状态的 `HandshakeServer`。
    pub fn build(self) -> HandshakeServer<Ready> {
        HandshakeServer {
            state: PhantomData,
            suite: self.suite_builder.build(),
            kem_key_pair: None,
            encryption_key: None,
            decryption_key: None,
        }
    }
}

impl<S> HandshakeServer<S> {
    /// Returns a builder for the `HandshakeServer`.
    ///
    /// 返回一个 `HandshakeServer` 的构建器。
    pub fn builder() -> HandshakeServerBuilder {
        HandshakeServerBuilder::new()
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
        self,
        message: HandshakeMessage,
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange>)> {
        match message {
            HandshakeMessage::ClientHello => {
                let kem = self.suite.kem();
                let kem_key_pair = kem.generate_keypair()?;
                let public_key = kem_key_pair.public_key();

                let server_hello = HandshakeMessage::ServerHello {
                    public_key,
                    kem_algorithm: kem.algorithm(),
                };

                let next_server = HandshakeServer {
                    state: PhantomData,
                    suite: self.suite,
                    kem_key_pair: Some(kem_key_pair),
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
        // 从加密消息中解析头部以获取 KDF/AEAD 参数。
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message)?;
        let header = pending_decryption.header().clone();

        // KEM: Decapsulate the shared secret using the server's private key.
        // KEM：使用服务器的私钥解封装共享密钥。
        let kem = header.kem_algorithm.into_asymmetric_wrapper();
        let shared_secret =
            kem.decapsulate_key(&kem_key_pair.private_key(), &encapsulated_key)?;

        // KDF: Derive the client-to-server decryption key using parameters from the client.
        // KDF：使用来自客户端的参数派生客户端到服务器的解密密钥。
        let kdf_params = &header.kdf_params;
        let decryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(), // Uses "c2s" info from client
            header.symmetric_params().algorithm(),
        )?;

        // DEM: Decrypt the initial payload sent by the client.
        // DEM：解密客户端发送的初始负载。
        let initial_payload =
            pending_decryption.decrypt_ordinary(Cow::Borrowed(&decryption_key), Some(aad.to_vec()))?;

        // KDF: Derive the server-to-client encryption key with a different "info" parameter.
        // KDF：使用不同的 "info" 参数派生服务器到客户端的加密密钥。
        let encryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            Some(b"seal-handshake-s2c"), // "s2c" (server-to-client) info
            header.symmetric_params().algorithm(),
        )?;

        // Transition to the `Established` state with the derived session keys.
        // 使用派生的会话密钥转换到 `Established` 状态。
        let established_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            kem_key_pair: None, // Consumed
            encryption_key: Some(encryption_key),
            decryption_key: Some(decryption_key),
        };

        Ok((initial_payload, established_server))
    }
}

impl HandshakeServer<Established> {
    /// Encrypts application data using the established server-to-client session key.
    ///
    /// 使用已建立的服务器到客户端的会话密钥来加密应用数据。
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
        // 通过从加密消息中解析头部来准备解密。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(ciphertext)?;

        // Perform the decryption and authentication.
        // 执行解密和身份验证。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}
