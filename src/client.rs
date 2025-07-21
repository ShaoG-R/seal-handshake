//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::error::{HandshakeError, Result};
use crate::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use crate::state::{AwaitingKemPublicKey, Established, Ready};
use crate::suite::ProtocolSuite;
use seal_flow::common::header::SymmetricParamsBuilder;
use seal_flow::crypto::bincode;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    KemAlgorithmTrait, SignatureAlgorithmTrait, SymmetricAlgorithmTrait,
};
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::marker::PhantomData;

/// The client-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
///
/// 客户端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
#[derive(Debug)]
pub struct HandshakeClient<S> {
    /// Zero-sized marker to hold the current state `S`.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    state: PhantomData<S>,
    /// The cryptographic suite used for the handshake.
    ///
    /// 握手过程中使用的密码套件。
    suite: ProtocolSuite,
    /// The server's long-term public key for verifying signatures.
    ///
    /// 用于验证签名的服务器长期公钥。
    server_signature_public_key: TypedSignaturePublicKey,
    /// Derived keys for encryption (client-to-server) and decryption (server-to-client).
    /// These are established after the key exchange.
    ///
    /// 用于加密（客户端到服务器）和解密（服务器到客户端）的派生密钥。
    /// 这些密钥在密钥交换后建立。
    encryption_key: Option<TypedSymmetricKey>,
    decryption_key: Option<TypedSymmetricKey>,
}

impl HandshakeClient<Ready> {
    /// Creates a new `HandshakeClient` in the `Ready` state.
    ///
    /// This constructor takes the protocol suite and the server's public key for signature verification.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeClient`。
    ///
    /// 此构造函数接收协议套件和用于签名验证的服务器公钥。
    pub fn new(
        suite: ProtocolSuite,
        server_signature_public_key: TypedSignaturePublicKey,
    ) -> Self {
        Self {
            state: PhantomData,
            suite,
            server_signature_public_key,
            encryption_key: None,
            decryption_key: None,
        }
    }
}

impl HandshakeClient<Ready> {
    /// Starts the handshake by creating a `ClientHello` message.
    /// This transitions the client to the `AwaitingKemPublicKey` state,
    /// waiting for the server's public key.
    ///
    /// 通过创建 `ClientHello` 消息来启动握手。
    /// 这会将客户端转换到 `AwaitingKemPublicKey` 状态，等待服务器的公钥。
    pub fn start_handshake(self) -> (HandshakeMessage, HandshakeClient<AwaitingKemPublicKey>) {
        let client_hello = HandshakeMessage::ClientHello;

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            server_signature_public_key: self.server_signature_public_key,
            encryption_key: None,
            decryption_key: None,
        };

        (client_hello, next_client)
    }
}

impl HandshakeClient<AwaitingKemPublicKey> {
    /// Processes the `ServerHello` message, generates session keys,
    /// and creates a `ClientKeyExchange` message.
    /// This method performs the client-side key exchange.
    ///
    /// It encapsulates a shared secret using the server's public key,
    /// derives encryption and decryption keys, and sends the encapsulated
    /// key to the server along with an optional initial encrypted payload.
    ///
    /// Upon successful completion, the client transitions to the `Established` state.
    ///
    /// 处理 `ServerHello` 消息，生成会话密钥，并创建 `ClientKeyExchange` 消息。
    /// 此方法执行客户端的密钥交换。
    ///
    /// 它使用服务器的公钥封装共享密钥，派生加密和解密密钥，
    /// 并将封装的密钥连同一个可选的初始加密负载一起发送到服务器。
    ///
    /// 成功完成后，客户端转换到 `Established` 状态。
    pub fn process_server_hello(
        self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established>)> {
        // Extract the server's public key and KEM algorithm from the message.
        // 从消息中提取服务器的公钥和 KEM 算法。
        let (server_pk, kem_algorithm, signature) = match message {
            HandshakeMessage::ServerHello {
                public_key,
                kem_algorithm,
                signature,
            } => (public_key, kem_algorithm, signature),
            // Return an error if the message is not a `ServerHello`.
            // 如果消息不是 `ServerHello`，则返回错误。
            _ => return Err(HandshakeError::InvalidMessage),
        };

        // Verify the signature of the ephemeral KEM public key, if one is provided.
        // This ensures the server owns the long-term private key corresponding
        // to the public key we have.
        //
        // 如果提供了签名，则验证临时 KEM 公钥的签名。
        // 这确保了服务器拥有我们持有的公钥所对应的长期私钥。
        if let Some(signature) = signature {
            let data_to_verify = bincode::encode_to_vec(&server_pk, bincode::config::standard())
                .map_err(HandshakeError::from)?;
            if let Some(verifier) = self.suite.signature() {
                verifier
                    .verify(
                        &data_to_verify,
                        &self.server_signature_public_key,
                        &signature,
                    )
                    .map_err(|_| HandshakeError::InvalidSignature)?;
            } else {
                // The server provided a signature, but we don't have a verification key/algorithm.
                // This could be a configuration mismatch.
                // 服务器提供了签名，但我们没有验证密钥/算法。
                // 这可能是配置不匹配。
                return Err(HandshakeError::InvalidSignature);
            }
        }

        let aead = self.suite.aead();
        let kdf = self.suite.kdf();
        let kem = kem_algorithm.into_asymmetric_wrapper();

        // KEM: Encapsulate a shared secret using the server's public key.
        // This generates a `shared_secret` (known only to the client for now)
        // and an `encapsulated_key` (which will be sent to the server).
        //
        // KEM：使用服务器的公钥封装一个共享密钥。
        // 这会生成一个 `shared_secret` (目前只有客户端知道)
        // 和一个 `encapsulated_key` (将被发送到服务器)。
        let (shared_secret, encapsulated_key) = kem.encapsulate_key(&server_pk)?;

        // KDF: Define parameters for client-to-server key derivation.
        // These parameters ensure that the derived keys are unique to this session.
        //
        // KDF：为客户端到服务器的密钥派生定义参数。
        // 这些参数确保派生的密钥对于此会话是唯一的。
        let kdf_params = KdfParams {
            algorithm: kdf.algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-c2s".to_vec()),
        };

        // KDF: Derive encryption and decryption keys from the shared secret.
        // The `info` parameter is varied ("c2s" vs "s2c") to produce
        // different keys for each direction (client-to-server and server-to-client).
        //
        // KDF：从共享密钥中派生加密和解密密钥。
        // 通过改变 `info` 参数 ("c2s" vs "s2c")，为每个方向（客户端到服务器和服务器到客户端）
        // 生成不同的密钥。
        let encryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(), // "c2s" (client-to-server) info
            aead.algorithm(),
        )?;
        let decryption_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            Some(b"seal-handshake-s2c"), // "s2c" (server-to-client) info
            aead.algorithm(),
        )?;

        // DEM: Encrypt the initial payload using the derived encryption key and `seal-flow`.
        // This demonstrates sending initial data securely immediately after key exchange.
        //
        // DEM：使用派生的加密密钥和 `seal-flow` 加密初始负载。
        // 这演示了在密钥交换后立即安全地发送初始数据。
        let aad = aad.unwrap_or(b"seal-handshake-aad");
        let params = SymmetricParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            // A unique nonce is required for each encryption.
            // 每次加密都需要一个唯一的 nonce。
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

        // Create the `ClientKeyExchange` message containing the encrypted payload and the encapsulated key.
        //
        // 创建 `ClientKeyExchange` 消息，其中包含加密的负载和封装的密钥。
        let key_exchange_msg = HandshakeMessage::ClientKeyExchange {
            encrypted_message,
            encapsulated_key,
        };

        // Transition to the `Established` state, storing the derived keys.
        //
        // 转换到 `Established` 状态，并存储派生的密钥。
        let established_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            server_signature_public_key: self.server_signature_public_key,
            encryption_key: Some(encryption_key),
            decryption_key: Some(decryption_key),
        };

        Ok((key_exchange_msg, established_client))
    }
}

impl HandshakeClient<Established> {
    /// Encrypts application data using the established client-to-server session key.
    ///
    /// This method should be called after the handshake is established to send secure data to the server.
    ///
    /// 使用已建立的客户端到服务器的会话密钥来加密应用数据。
    ///
    /// 此方法应在握手建立后调用，以向服务器发送安全数据。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            // This error indicates a logic flaw, as this method should not be callable
            // without an encryption key.
            //
            // 这个错误表示存在逻辑缺陷，因为在没有加密密钥的情况下不应能调用此方法。
            .ok_or(HandshakeError::InvalidState)?;

        let aead = self.suite.aead();
        let params = SymmetricParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        // In a real application, the header would be part of a larger protocol message.
        // For simplicity, we create a dummy header here to structure the encrypted data.
        //
        // 在实际应用中，头部将是更大协议消息的一部分。
        // 为简单起见，我们在这里创建一个虚拟头部来构造加密数据。
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

    /// Decrypts a message from the server (e.g., `ServerFinished`) using the
    /// established server-to-client session key.
    ///
    /// 使用已建立的服务器到客户端的会话密钥来解密来自服务器的消息（例如 `ServerFinished`）。
    pub fn decrypt(&self, message: HandshakeMessage, aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let encrypted_message = match message {
            HandshakeMessage::ServerFinished {
                encrypted_message,
            } => encrypted_message,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        let aad = aad.unwrap_or(b"seal-handshake-aad");

        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Prepare the decryption by parsing the header from the encrypted message.
        //
        // 通过从加密消息中解析头部来准备解密。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message)?;

        // Perform the decryption and authentication.
        //
        // 执行解密和身份验证。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}