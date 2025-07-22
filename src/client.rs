//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::error::{HandshakeError, Result};
use crate::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use crate::state::{AwaitingKemPublicKey, Established, Ready};
use crate::suite::{KeyAgreementEngine, ProtocolSuite};
use seal_flow::common::header::AeadParamsBuilder;
use seal_flow::crypto::bincode;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, KeyAgreementAlgorithmTrait, SignatureAlgorithmTrait,
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
    /// A running hash of the handshake transcript for integrity checks.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    transcript_hasher: Sha256,
    /// The client's ephemeral key agreement key pair, if used.
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The server's long-term public key for verifying signatures.
    ///
    /// 用于验证签名的服务器长期公钥。
    server_signature_public_key: TypedSignaturePublicKey,
    /// Derived keys for encryption (client-to-server) and decryption (server-to-client).
    /// These are established after the key exchange.
    ///
    /// 用于加密（客户端到服务器）和解密（服务器到客户端）的派生密钥。
    /// 这些密钥在密钥交换后建立。
    encryption_key: Option<TypedAeadKey>,
    decryption_key: Option<TypedAeadKey>,
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
            transcript_hasher: Sha256::new(),
            key_agreement_engine: None,
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
    pub fn start_handshake(mut self) -> (HandshakeMessage, HandshakeClient<AwaitingKemPublicKey>) {
        // If a key agreement algorithm is specified, generate a key pair for it.
        let (key_agreement_public_key, key_agreement_engine) =
            if let Some(key_agreement) = self.suite.key_agreement() {
                let key_pair = key_agreement.generate_keypair().unwrap();
                let public_key = key_pair.public_key().clone();
                let engine = KeyAgreementEngine {
                    key_pair,
                    wrapper: key_agreement.clone(),
                };
                (Some(public_key), Some(engine))
            } else {
                (None, None)
            };

        let client_hello = HandshakeMessage::ClientHello {
            key_agreement_public_key,
        };

        // Update the transcript with the ClientHello message.
        // 使用 ClientHello 消息更新握手记录。
        let client_hello_bytes =
            bincode::encode_to_vec(&client_hello, bincode::config::standard()).unwrap();
        self.transcript_hasher.update(&client_hello_bytes);

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript_hasher: self.transcript_hasher,
            key_agreement_engine,
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
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established>)> {
        // Update the transcript with the ServerHello message before processing it.
        // 在处理 ServerHello 消息之前，先用它更新握手记录。
        let server_hello_bytes =
            bincode::encode_to_vec(&message, bincode::config::standard()).unwrap();
        self.transcript_hasher.update(&server_hello_bytes);

        // Extract the server's public key and KEM algorithm from the message.
        // 从消息中提取服务器的公钥和 KEM 算法。
        let (server_kem_pk, kem_algorithm, server_key_agreement_pk, signature) = match message {
            HandshakeMessage::ServerHello {
                kem_public_key,
                kem_algorithm,
                key_agreement_public_key,
                signature,
            } => (
                kem_public_key,
                kem_algorithm,
                key_agreement_public_key,
                signature,
            ),
            // Return an error if the message is not a `ServerHello`.
            // 如果消息不是 `ServerHello`，则返回错误。
            _ => return Err(HandshakeError::InvalidMessage),
        };

        // Verify the signature of the ephemeral keys, if provided.
        if let Some(signature) = signature {
            let data_to_verify = {
                let kem_pk_bytes =
                    bincode::encode_to_vec(&server_kem_pk, bincode::config::standard())
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

            if let Some(verifier) = self.suite.signature() {
                verifier
                    .verify(
                        &data_to_verify,
                        &self.server_signature_public_key,
                        &signature,
                    )
                    .map_err(|_| HandshakeError::InvalidSignature)?;
            } else {
                return Err(HandshakeError::InvalidSignature);
            }
        }

        // --- Key Derivation ---
        let aead = self.suite.aead();
        let kdf = self.suite.kdf();
        let kem = kem_algorithm.into_wrapper();

        // KEM: Encapsulate a shared secret.
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        // Key Agreement: If negotiated, compute the other part of the shared secret.
        let shared_secret_agreement = if let (Some(engine), Some(server_pk)) =
            (self.key_agreement_engine.as_ref(), server_key_agreement_pk)
        {
            let private_key = engine.key_pair.private_key();
            Some(engine.wrapper.agree(&private_key, &server_pk)?)
        } else {
            None
        };

        // Combine secrets: [agreement_secret || kem_secret]
        let final_shared_secret = if let Some(agreement_secret) = shared_secret_agreement {
            let mut combined = agreement_secret.to_vec();
            combined.extend_from_slice(shared_secret_kem.as_ref());
            SharedSecret(combined.into())
        } else {
            shared_secret_kem
        };

        // KDF: Define parameters for client-to-server key derivation.
        let kdf_params = KdfParams {
            algorithm: kdf.algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            info: Some(b"seal-handshake-c2s".to_vec()),
        };

        // KDF: Derive encryption and decryption keys from the final shared secret.
        let encryption_key = final_shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(), // "c2s"
            aead.algorithm(),
        )?;
        let decryption_key = final_shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            Some(b"seal-handshake-s2c"), // "s2c"
            aead.algorithm(),
        )?;

        // DEM: Encrypt the initial payload using the derived encryption key and `seal-flow`.
        // This demonstrates sending initial data securely immediately after key exchange.
        //
        // DEM：使用派生的加密密钥和 `seal-flow` 加密初始负载。
        // 这演示了在密钥交换后立即安全地发送初始数据。
        let aad = aad.unwrap_or(b"seal-handshake-aad");
        let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, Sha256::new())
            // A unique nonce is required for each encryption.
            // 每次加密都需要一个唯一的 nonce。
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let header = EncryptedHeader {
            params,
            kem_algorithm,
            kdf_params,
            signature_algorithm: None,
            signed_transcript_hash: None,
            transcript_signature: None,
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

        // Update the transcript with the ClientKeyExchange message before transitioning state.
        // 在转换状态之前，使用 ClientKeyExchange 消息更新握手记录。
        let key_exchange_bytes =
            bincode::encode_to_vec(&key_exchange_msg, bincode::config::standard()).unwrap();
        self.transcript_hasher.update(&key_exchange_bytes);

        // Transition to the `Established` state, storing the derived keys.
        //
        // 转换到 `Established` 状态，并存储派生的密钥。
        let established_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript_hasher: self.transcript_hasher,
            key_agreement_engine: self.key_agreement_engine,
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
        let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
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
            signature_algorithm: None,
            signed_transcript_hash: None,
            transcript_signature: None,
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
        // This will now also trigger the `verify_signature` check within the header.
        //
        // 通过从加密消息中解析头部来准备解密。
        // 这也将触发头部内的 `verify_signature` 检查。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(
            &encrypted_message,
            Some(&self.server_signature_public_key),
        )?;

        // Perform the decryption and authentication.
        //
        // 执行解密和身份验证。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}