//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。


use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{AwaitingKeyExchange, Established, Ready},
    transcript::Transcript,
};
use crate::error::{HandshakeError, Result};
use crate::crypto::{
    keys::derive_session_keys,
    signature::sign_ephemeral_keys,
    suite::{KeyAgreementEngine, ProtocolSuite},
};
use seal_flow::common::header::AeadParamsBuilder;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, SignatureAlgorithmTrait,
};
use seal_flow::prelude::{prepare_decryption_from_slice, EncryptionConfigurator};
use seal_flow::rand::rngs::OsRng;
use seal_flow::rand::TryRngCore;
use std::borrow::Cow;
use std::marker::PhantomData;

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
pub struct HandshakeServer<S> {
    /// Zero-sized marker to hold the current state `S`.
    /// This doesn't take up space but allows the type system to track the machine's state.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    /// 它不占用空间，但允许类型系统跟踪机器的状态。
    state: PhantomData<S>,
    /// The cryptographic suite used for the handshake.
    /// This defines the set of algorithms (KEM, AEAD, KDF, etc.) to be used.
    ///
    /// 握手过程中使用的密码套件。
    /// 这定义了要使用的算法集（KEM、AEAD、KDF 等）。
    suite: ProtocolSuite,
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
    signature_key_pair: TypedSignatureKeyPair,
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
}


impl HandshakeServer<Ready> {
    /// Creates a new `HandshakeServer` in the `Ready` state.
    ///
    /// This is the entry point for initiating a server-side handshake.
    /// It requires the server's long-term identity and the desired cryptographic algorithms.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeServer`。
    ///
    /// 这是发起服务器端握手的入口点。
    /// 它需要服务器的长期身份和期望的密码学算法。
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
    /// On receiving `ClientHello`, the server:
    /// 1. Generates ephemeral key pairs (KEM and optional key agreement).
    /// 2. Signs the ephemeral public keys with its long-term identity key. This binds the ephemeral keys
    ///    to this specific server for this session, preventing man-in-the-middle attacks.
    /// 3. Responds with a `ServerHello` containing its ephemeral public keys and the signature.
    /// 4. Transitions to the `AwaitingKeyExchange` state, ready for the client's response.
    ///
    /// 处理 `ClientHello` 消息。
    ///
    /// 收到 `ClientHello` 后，服务器会：
    /// 1. 生成临时密钥对（KEM 和可选的密钥协商）。
    /// 2. 用其长期身份密钥对临时公钥进行签名。这将临时密钥与本次会话的特定服务器绑定，
    ///    防止中间人攻击。
    /// 3. 用包含其临时公钥和签名的 `ServerHello` 进行响应。
    /// 4. 转换到 `AwaitingKeyExchange` 状态，准备接收客户端的响应。
    pub fn process_client_hello(
        mut self,
        message: HandshakeMessage,
    ) -> Result<(HandshakeMessage, HandshakeServer<AwaitingKeyExchange>)> {
        // Update transcript with ClientHello. It's crucial to include all messages in the
        // transcript for the final integrity check (the server's signature).
        //
        // 使用 ClientHello 更新握手记录。将所有消息包含在握手记录中对于最终的
        // 完整性检查（服务器签名）至关重要。
        self.transcript.update(&message);

        match message {
            HandshakeMessage::ClientHello {
                key_agreement_public_key: client_key_agreement_pk,
            } => {
                // KEM key generation is mandatory for key establishment. An ephemeral key pair is
                // generated for each new session.
                //
                // KEM 密钥生成对于密钥建立是强制性的。每个新会话都会生成一个临时的密钥对。
                let kem = self.suite.kem();
                let kem_key_pair = kem.generate_keypair()?;
                let kem_public_key = kem_key_pair.public_key().clone();

                // Key Agreement is optional. If the client provided a public key and the server
                // suite supports key agreement, a shared secret is computed. This adds a layer of
                // security (PFS).
                //
                // 密钥协商是可选的。如果客户端提供了公钥且服务器套件支持密钥协商，
                // 则会计算一个共享密钥。这增加了一层安全性（PFS）。
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

                // Sign the ephemeral public keys (KEM and optional key agreement) with the server's
                // long-term identity key. This signature proves to the client that the ephemeral keys
                // are authentic and belong to the intended server.
                //
                // 使用服务器的长期身份密钥对临时公钥（KEM 和可选的密钥协商）进行签名。
                // 这个签名向客户端证明，临时密钥是真实的，并且属于预期的服务器。
                let signature = if let Some(signer) = self.suite.signature() {
                    Some(sign_ephemeral_keys(
                        signer,
                        &kem_public_key,
                        &server_key_agreement_pk,
                        &self.signature_key_pair.private_key(),
                    )?)
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
                // This ensures the server's own message is part of the signed transcript.
                //
                // 在发送之前，使用 ServerHello 更新握手记录。
                // 这确保了服务器自己的消息也是已签名的握手记录的一部分。
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
    ) -> Result<(Vec<u8>, HandshakeServer<Established>)> {
        // Update transcript with the client's key exchange message.
        // 使用客户端的密钥交换消息更新握手记录。
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

        // The KEM key pair must exist in this state. `take()` consumes it, ensuring it's used only once.
        // This is a critical security property to prevent reuse of ephemeral keys.
        //
        // 在此状态下，KEM 密钥对必须存在。`take()` 会消耗它，确保它只被使用一次。
        // 这是防止临时密钥重用的关键安全属性。
        let kem_key_pair = self
            .kem_key_pair
            .take()
            .ok_or(HandshakeError::InvalidState)?;

        // Parse the header from the encrypted message to get KDF/AEAD parameters.
        // The client does not send a transcript signature in this message, so `verify_key` is `None`.
        // The header is authenticated as part of the AEAD tag.
        //
        // 从加密消息中解析头部以获取 KDF/AEAD 参数。
        // 客户端在此消息中不发送握手记录签名，因此 `verify_key` 为 `None`。
        // 头部作为 AEAD 标签的一部分进行认证。
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message, None)?;
        let header = pending_decryption.header().clone();

        // KEM: Decapsulate the shared secret using the server's private KEM key and the
        // encapsulated key from the client. This recovers the secret only the client could have generated.
        //
        // KEM：使用服务器的私有 KEM 密钥和来自客户端的封装密钥来解封装共享密钥。
        // 这恢复了只有客户端才能生成的密钥。
        let kem = header.kem_algorithm.into_wrapper();
        let shared_secret =
            kem.decapsulate_key(&kem_key_pair.private_key(), &encapsulated_key)?;

        // KDF: Derive session keys from the shared secrets (KEM and optional key agreement).
        // The `is_client` flag is false, ensuring the server derives the correct set of keys
        // (server_write_key, client_write_key).
        //
        // KDF：从共享密钥（KEM 和可选的密钥协商）派生会话密钥。
        // `is_client` 标志为 false，确保服务器派生正确的密钥集
        // (server_write_key, client_write_key)。
        let session_keys = derive_session_keys(
            &self.suite,
            shared_secret,
            self.agreement_shared_secret.take(),
            false, // is_client = false
        )?;

        // DEM: Decrypt the initial payload sent by the client using the newly derived decryption key.
        // This verifies that the client has successfully derived the same keys.
        //
        // DEM：使用新派生的解密密钥解密客户端发送的初始负载。
        // 这验证了客户端已成功派生出相同的密钥。
        let initial_payload = pending_decryption
            .decrypt_ordinary(Cow::Borrowed(&session_keys.decryption_key), Some(aad.to_vec()))?;

        // Transition to the `Established` state with the derived session keys.
        // The ephemeral keys (KEM pair, agreement secret) have been consumed and are now gone.
        //
        // 使用派生的会话密钥转换到 `Established` 状态。
        // 临时密钥（KEM 密钥对、协商密钥）已被消耗且不复存在。
        let established_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: None, // Consumed and discarded
            key_agreement_engine: self.key_agreement_engine,
            agreement_shared_secret: None, // Consumed and discarded
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
        };

        Ok((initial_payload, established_server))
    }
}

impl HandshakeServer<Established> {
    /// Encrypts application data using the established server-to-client session key.
    ///
    /// For the first message sent in the `Established` state, this method also signs
    /// the entire handshake transcript and includes the signature in the encrypted message's header.
    /// This proves to the client that the server successfully completed the handshake and provides
    /// tamper-resistance for the entire exchange.
    ///
    /// 使用已建立的服务器到客户端的会话密钥来加密应用数据。
    ///
    /// 对于在 `Established` 状态下发送的第一条消息，此方法还会对整个握手记录进行签名，
    /// 并将签名包含在加密消息的头部。这向客户端证明服务器已成功完成握手，并为整个交换
    /// 提供了抗篡改能力。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // The transcript signature is calculated and included only once, typically with the first
        // application data message from the server (often a "Finished" message).
        // This signature covers all handshake messages, providing integrity for the entire negotiation.
        //
        // 握手记录签名只计算和包含一次，通常与服务器的第一条应用数据消息（通常是 "Finished" 消息）一起发送。
        // 该签名覆盖所有握手消息，为整个协商过程提供完整性。
        let (signature_algorithm, signed_transcript_hash, transcript_signature) =
            if let Some(signer) = self.suite.signature() {
                // Finalize the transcript hash.
                let transcript_hash = self.transcript.current_hash();

                // Sign the hash with the server's long-term private key.
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
            // AAD (Additional Associated Data) is authenticated but not encrypted. Hashing it
            // allows for arbitrary length AAD to be used without significant overhead.
            //
            // AAD（附加关联数据）经过身份验证但未加密。对其进行哈希处理
            // 允许使用任意长度的 AAD 而不会产生显著开销。
            .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
            // A unique nonce (or IV) must be used for each encryption with the same key.
            // Using a random nonce is a safe and common practice.
            //
            // 对于使用相同密钥的每次加密，都必须使用唯一的 nonce（或 IV）。
            // 使用随机 nonce 是一种安全且常见的做法。
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        // The header contains parameters needed by the recipient for decryption.
        // This includes cryptographic choices and the transcript signature for verification.
        //
        // 头部包含接收方解密所需的参数。
        // 这包括密码学选择和用于验证的握手记录签名。
        let kdf_params = KdfParams {
            algorithm: self.suite.kdf().algorithm(),
            salt: Some(b"seal-handshake-salt".to_vec()),
            // The "info" context string ensures that client-to-server and server-to-client keys are different.
            // "info" 上下文字符串确保客户端到服务器和服务器到客户端的密钥是不同的。
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

        // Encrypt the plaintext using the established session key and the constructed header.
        // The `seal-flow` library handles the details of AEAD encryption.
        //
        // 使用已建立的会话密钥和构造的头部来加密明文。
        // `seal-flow` 库处理 AEAD 加密的细节。
        EncryptionConfigurator::new(header, Cow::Borrowed(key), Some(aad.to_vec()))
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(plaintext)
            .map_err(Into::into)
    }

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
