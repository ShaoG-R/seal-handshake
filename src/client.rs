//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::error::{HandshakeError, Result};
use crate::crypto::{
    keys::derive_session_keys,
    signature::verify_ephemeral_keys,
    suite::{KeyAgreementEngine, ProtocolSuite},
};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{AwaitingKemPublicKey, Established, Ready},
    transcript::Transcript,
};
use seal_flow::common::header::AeadParamsBuilder;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, 
};
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use std::borrow::Cow;
use std::marker::PhantomData;

/// The client-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
/// This prevents out-of-order operations, such as trying to encrypt data before keys are established.
///
/// 客户端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
/// 这可以防止乱序操作，例如在密钥建立之前尝试加密数据。
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
    /// This ensures that the messages negotiated are the same ones the server signs.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    /// 这确保了协商的消息与服务器签名的消息是相同的。
    transcript: Transcript,
    /// The client's ephemeral key agreement engine, if used.
    /// It's kept for the duration of the handshake to compute the shared secret.
    ///
    /// 客户端的临时密钥协商引擎（如果使用）。
    /// 它在握手期间保留，用于计算共享密钥。
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The server's long-term public key for verifying signatures.
    /// This is a crucial part of authenticating the server.
    ///
    /// 用于验证签名的服务器长期公钥。
    /// 这是验证服务器身份的关键部分。
    server_signature_public_key: TypedSignaturePublicKey,
    /// Derived key for encryption (client-to-server).
    /// Available only in the `Established` state.
    ///
    /// 用于加密（客户端到服务器）的派生密钥。
    /// 仅在 `Established` 状态下可用。
    encryption_key: Option<TypedAeadKey>,
    /// Derived key for decryption (server-to-client).
    /// Available only in the `Established` state.
    ///
    /// 用于解密（服务器到客户端）的派生密钥。
    /// 仅在 `Established` 状态下可用。
    decryption_key: Option<TypedAeadKey>,
}

impl HandshakeClient<Ready> {
    /// Creates a new `HandshakeClient` in the `Ready` state.
    ///
    /// The client must be initialized with the server's trusted public signature key
    /// to authenticate the server during the handshake.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeClient`。
    ///
    /// 客户端必须使用服务器受信任的公共签名密钥进行初始化，
    /// 以便在握手期间验证服务器。
    pub fn new(
        suite: ProtocolSuite,
        server_signature_public_key: TypedSignaturePublicKey,
    ) -> Self {
        Self {
            state: PhantomData,
            suite,
            transcript: Transcript::new(),
            key_agreement_engine: None,
            server_signature_public_key,
            encryption_key: None,
            decryption_key: None,
        }
    }
}

impl HandshakeClient<Ready> {
    /// Starts the handshake by creating a `ClientHello` message.
    ///
    /// This message signals the client's intent to start a handshake and optionally includes
    /// a public key for key agreement if the suite supports it.
    /// It then transitions the client to the `AwaitingKemPublicKey` state.
    ///
    /// 通过创建 `ClientHello` 消息来启动握手。
    ///
    /// 此消息表示客户端打算开始握手，如果套件支持，还可以选择性地包含
    /// 用于密钥协商的公钥。
    /// 然后它会将客户端转换到 `AwaitingKemPublicKey` 状态。
    pub fn start_handshake(mut self) -> (HandshakeMessage, HandshakeClient<AwaitingKemPublicKey>) {
        // If a key agreement algorithm is specified, generate an ephemeral key pair for it.
        // This is the client's contribution to the Diffie-Hellman exchange.
        //
        // 如果指定了密钥协商算法，则为其生成一个临时密钥对。
        // 这是客户端对 Diffie-Hellman 交换的贡献。
        let (key_agreement_public_key, key_agreement_engine) =
            if let Some(key_agreement) = self.suite.key_agreement() {
                let engine = KeyAgreementEngine::new_for_client(key_agreement).unwrap();
                (Some(engine.public_key().clone()), Some(engine))
            } else {
                (None, None)
            };

        let client_hello = HandshakeMessage::ClientHello {
            key_agreement_public_key,
        };

        // Update the transcript with the ClientHello message. The transcript must begin here
        // to ensure all exchanged messages are eventually verified by the server's signature.
        //
        // 使用 ClientHello 消息更新握手记录。握手记录必须从这里开始，
        // 以确保所有交换的消息最终都由服务器的签名进行验证。
        self.transcript.update(&client_hello);

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
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
    ///
    /// This is the most critical client-side step:
    /// 1. Verifies the server's signature on its ephemeral keys, authenticating the server.
    /// 2. Performs a KEM encapsulation to generate a shared secret that only the server can decapsulate.
    /// 3. Computes a key agreement secret if applicable.
    /// 4. Derives symmetric session keys from the combined secrets using a KDF.
    /// 5. Encrypts an initial payload and sends it with the encapsulated key.
    /// 6. Transitions to the `Established` state.
    ///
    /// 处理 `ServerHello` 消息，生成会话密钥，并创建 `ClientKeyExchange` 消息。
    ///
    /// 这是最关键的客户端步骤：
    /// 1. 验证服务器对其临时密钥的签名，从而对服务器进行身份验证。
    /// 2. 执行 KEM 封装，生成只有服务器才能解封装的共享密钥。
    /// 3. 如果适用，计算密钥协商密钥。
    /// 4. 使用 KDF 从组合的密钥中派生对称会话密钥。
    /// 5. 加密初始负载并将其与封装的密钥一起发送。
    /// 6. 转换到 `Established` 状态。
    pub fn process_server_hello(
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(HandshakeMessage, HandshakeClient<Established>)> {
        // Update the transcript with the ServerHello message before processing it.
        // This ensures the server's contribution is part of the final signed transcript.
        //
        // 在处理 ServerHello 消息之前，先用它更新握手记录。
        // 这确保了服务器的贡献是最终签名握手记录的一部分。
        self.transcript.update(&message);

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

        // Verify the signature of the server's ephemeral keys using its long-term public key.
        // This is a crucial security step: it confirms that the ephemeral keys were generated by the
        // legitimate server, preventing an attacker from injecting their own keys (MITM attack).
        //
        // 使用服务器的长期公钥验证其临时密钥的签名。
        // 这是一个关键的安全步骤：它确认临时密钥是由合法服务器生成的，
        // 防止攻击者注入自己的密钥（中间人攻击）。
        if let (Some(signature), Some(verifier)) = (signature, self.suite.signature()) {
            verify_ephemeral_keys(
                verifier,
                &server_kem_pk,
                &server_key_agreement_pk,
                &signature,
                &self.server_signature_public_key,
            )?;
        }

        // --- Key Derivation ---
        let kem = kem_algorithm.into_wrapper();

        // KEM: Encapsulate a new shared secret against the server's public KEM key.
        // The result is a `shared_secret` (kept by the client) and an `encapsulated_key`
        // (sent to the server). Only the server, with its private key, can derive the same secret.
        //
        // KEM: 针对服务器的公共 KEM 密钥封装一个新的共享密钥。
        // 结果是一个 `shared_secret`（由客户端保留）和一个 `encapsulated_key`
        // （发送到服务器）。只有拥有私钥的服务器才能派生出相同的密钥。
        let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

        // Key Agreement: If negotiated, compute the shared secret using the client's private key
        // and the server's public key. This contributes to the final session key.
        //
        // 密钥协商：如果已协商，则使用客户端的私钥和服务器的公钥计算共享密钥。
        // 这构成了最终会话密钥的一部分。
        let shared_secret_agreement =
            if let (Some(engine), Some(server_pk)) =
                (self.key_agreement_engine.as_ref(), &server_key_agreement_pk)
            {
                Some(engine.agree(server_pk)?)
            } else {
                None
            };

        // KDF: Derive encryption and decryption keys from the combined shared secrets.
        // The `is_client` flag is true, ensuring the client derives the correct set of keys.
        //
        // KDF：从组合的共享密钥中派生加密和解密密钥。
        // `is_client` 标志为 true，确保客户端派生正确的密钥集。
        let session_keys = derive_session_keys(
            &self.suite,
            shared_secret_kem,
            shared_secret_agreement,
            true, // is_client = true
        )?;

        // DEM: Encrypt the initial payload using the newly derived client-to-server key.
        // This confirms to the server that the key exchange was successful on the client side.
        //
        // DEM：使用新派生的客户端到服务器密钥加密初始负载。
        // 这向服务器确认密钥交换在客户端已成功。
        let aad = aad.unwrap_or(b"seal-handshake-aad");
        let aead = self.suite.aead();
        let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
            .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
            // A unique nonce is required for each encryption operation.
            // 每次加密操作都需要一个唯一的 nonce。
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let kdf_params = KdfParams {
            algorithm: self.suite.kdf().algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            // The "info" context string ensures key separation between c2s and s2c directions.
            // "info" 上下文字符串确保了 c2s 和 s2c 方向之间的密钥分离。
            info: Some(b"seal-handshake-c2s".to_vec()),
        };

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
            Cow::Borrowed(&session_keys.encryption_key),
            Some(aad.to_vec()),
        )
        .into_writer(Vec::new())?
        .encrypt_ordinary_to_vec(initial_payload.unwrap_or(&[]))?;

        // Create the `ClientKeyExchange` message containing the encrypted payload and the encapsulated key.
        // This is the client's final message in the core handshake.
        //
        // 创建 `ClientKeyExchange` 消息，其中包含加密的负载和封装的密钥。
        // 这是客户端在核心握手中的最后一条消息。
        let key_exchange_msg = HandshakeMessage::ClientKeyExchange {
            encrypted_message,
            encapsulated_key,
        };

        // Update the transcript with the ClientKeyExchange message. After this, the client's view
        // of the transcript is complete.
        //
        // 使用 ClientKeyExchange 消息更新握手记录。此后，客户端的
        // 握手记录视图就完成了。
        self.transcript.update(&key_exchange_msg);

        // Transition to the `Established` state, storing the derived keys for secure communication.
        // The client is now ready to send and receive encrypted application data.
        //
        // 转换到 `Established` 状态，并存储派生的密钥以进行安全通信。
        // 客户端现在已准备好发送和接收加密的应用数据。
        let established_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            key_agreement_engine: self.key_agreement_engine,
            server_signature_public_key: self.server_signature_public_key,
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
        };

        Ok((key_exchange_msg, established_client))
    }
}

impl HandshakeClient<Established> {
    /// Encrypts application data using the established client-to-server session key.
    ///
    /// This method is used for sending secure data after the handshake has successfully completed.
    ///
    /// 使用已建立的客户端到服务器的会话密钥来加密应用数据。
    ///
    /// 此方法用于在握手成功完成后发送安全数据。
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
            .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        // In a real application, the header would be part of a larger protocol message.
        // For simplicity, we create a header here to structure the encrypted data.
        //
        // 在实际应用中，头部将是更大协议消息的一部分。
        // 为简单起见，我们在这里创建一个头部来构造加密数据。
        let kdf_params = KdfParams {
            algorithm: self.suite.kdf().algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            // The "info" context string ensures key separation between c2s and s2c directions.
            // "info" 上下文字符串确保了 c2s 和 s2c 方向之间的密钥分离。
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

    /// Decrypts a message from the server (e.g., a "Finished" message or application data)
    /// using the established server-to-client session key.
    ///
    /// This method also verifies the server's signature over the entire handshake transcript,
    /// providing full authentication and integrity for the negotiation.
    ///
    /// 使用已建立的服务器到客户端的会话密钥来解密来自服务器的消息（例如“Finished”消息或应用数据）。
    ///
    /// 此方法还会验证服务器对整个握手记录的签名，
    /// 为协商提供完全的身份验证和完整性。
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
        // `prepare_decryption_from_slice` is configured to verify the transcript signature
        // using the server's public key. This is the final and crucial check that confirms
        // the server we talked to is the one we intended, and that the handshake was not tampered with.
        //
        // 通过从加密消息中解析头部来准备解密。
        // `prepare_decryption_from_slice` 被配置为使用服务器的公钥来验证握手记录签名。
        // 这是最后也是最关键的检查，确认与我们通信的服务器是我们预期的服务器，并且握手未被篡改。
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(
            &encrypted_message,
            Some(&self.server_signature_public_key),
        )?;

        // Perform the decryption and authentication.
        // If the signature was invalid, `prepare_decryption_from_slice` would have already returned an error.
        //
        // 执行解密和身份验证。
        // 如果签名无效，`prepare_decryption_from_slice` 已经返回错误了。
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}