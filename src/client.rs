//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::error::{HandshakeError, Result};
use crate::crypto::{
    keys::derive_session_keys,
    signature::verify_ephemeral_keys,
    suite::{KeyAgreementEngine, ProtocolSuite, SignaturePresence, WithSignature, WithoutSignature},
};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{AwaitingKemPublicKey, Established, Ready},
    transcript::Transcript,
};
use seal_flow::common::header::AeadParamsBuilder;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::{
    AeadAlgorithmTrait, KemAlgorithmTrait, 
};
use seal_flow::crypto::wrappers::asymmetric::kem::KemAlgorithmWrapper;
use seal_flow::crypto::wrappers::asymmetric::signature::SignatureWrapper;
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
pub struct HandshakeClient<State, Sig: SignaturePresence> {
    /// Zero-sized marker to hold the current state `S`.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    state: PhantomData<State>,
    /// The cryptographic suite used for the handshake.
    ///
    /// 握手过程中使用的密码套件。
    suite: ProtocolSuite<Sig>,
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
    server_signature_public_key: Sig::ClientKey,
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
    /// The master secret for this session, used for session resumption.
    ///
    /// 当前会话的主密钥，用于会话恢复。
    established_master_secret: Option<SharedSecret>,
    /// The new session ticket received from the server for the next session.
    ///
    /// 从服务器收到的用于下一次会话的新会话票据。
    new_session_ticket: Option<Vec<u8>>,

    // --- Data for starting a new handshake with resumption ---
    /// The master secret from a previous session, used to resume.
    ///
    /// 来自前一个会话的主密钥，用于恢复。
    resumption_master_secret: Option<SharedSecret>,
    /// The ticket from a previous session, sent to the server to resume.
    ///
    /// 来自前一个会话的票据，发送给服务器以进行恢复。
    session_ticket_to_send: Option<Vec<u8>>,
}

/// A builder for creating a `HandshakeClient`.
///
/// This builder ensures that all required fields are provided before constructing the client.
///
/// 用于创建 `HandshakeClient` 的构建器。
///
/// 此构建器确保在构造客户端之前提供了所有必需的字段。
#[derive(Default)]
pub struct HandshakeClientBuilder<Sig: SignaturePresence> {
    suite: Option<ProtocolSuite<Sig>>,
    server_signature_public_key: Option<Sig::ClientKey>,
    resumption_master_secret: Option<SharedSecret>,
    session_ticket: Option<Vec<u8>>,
}

impl<Sig: SignaturePresence> HandshakeClientBuilder<Sig> {
    /// Creates a new `HandshakeClientBuilder`.
    pub fn new() -> Self {
        Self {
            suite: None,
            server_signature_public_key: None,
            resumption_master_secret: None,
            session_ticket: None,
        }
    }

    /// Sets the protocol suite for the handshake.
    ///
    /// 设置握手所用的协议套件。
    pub fn suite(mut self, suite: ProtocolSuite<Sig>) -> Self {
        self.suite = Some(suite);
        self
    }

    /// Sets the server's public key for verifying signatures.
    ///
    /// This is required to authenticate the server.
    ///
    /// 设置用于验证签名的服务器公钥。
    ///
    /// 这是验证服务器身份所必需的。
    pub fn server_signature_public_key(mut self, key: Sig::ClientKey) -> Self {
        self.server_signature_public_key = Some(key);
        self
    }

    /// Provides resumption data (the master secret and the opaque ticket) from a
    /// previous session to attempt session resumption.
    ///
    /// 提供来自前一个会话的恢复数据（主密钥和不透明票据）以尝试会话恢复。
    pub fn resumption_data(mut self, master_secret: SharedSecret, ticket: Vec<u8>) -> Self {
        self.resumption_master_secret = Some(master_secret);
        self.session_ticket = Some(ticket);
        self
    }

    /// Builds the `HandshakeClient`.
    ///
    /// Returns an error if any required fields are missing.
    ///
    /// 构建 `HandshakeClient`。
    ///
    /// 如果任何必需字段缺失，则返回错误。
    pub fn build(self) -> Result<HandshakeClient<Ready, Sig>> {
        let suite = self
            .suite
            .ok_or(HandshakeError::BuilderMissingField("suite"))?;
        let server_signature_public_key = self
            .server_signature_public_key
            .ok_or(HandshakeError::BuilderMissingField(
                "server_signature_public_key",
            ))?;

        Ok(HandshakeClient {
            state: PhantomData,
            suite,
            transcript: Transcript::new(),
            key_agreement_engine: None,
            server_signature_public_key,
            encryption_key: None,
            decryption_key: None,
            established_master_secret: None,
            new_session_ticket: None,
            resumption_master_secret: self.resumption_master_secret,
            session_ticket_to_send: self.session_ticket,
        })
    }
}


impl<Sig: SignaturePresence> HandshakeClient<Ready, Sig> {
    /// Creates a new `HandshakeClientBuilder` to construct a `HandshakeClient`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeClient` 的构建器。
    pub fn builder() -> HandshakeClientBuilder<Sig> {
        HandshakeClientBuilder::new()
    }
}

impl<Sig: SignaturePresence> HandshakeClient<Ready, Sig> {
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
    pub fn start_handshake(
        mut self,
    ) -> (
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, Sig>,
    ) {
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
            session_ticket: self.session_ticket_to_send.take(),
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
            established_master_secret: None,
            new_session_ticket: None,
            resumption_master_secret: self.resumption_master_secret.take(),
            session_ticket_to_send: None,
        };

        (client_hello, next_client)
    }
}

impl HandshakeClient<AwaitingKemPublicKey, WithSignature> {
    /// Processes `ServerHello` for a suite with a signature scheme.
    ///
    /// It verifies the server's signature on its ephemeral keys before proceeding.
    ///
    /// 为带有签名方案的套件处理 `ServerHello`。
    ///
    /// 在继续之前，它会验证服务器对其临时密钥的签名。
    pub fn process_server_hello(
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, WithSignature>,
    )> {
        let (server_kem_pk, kem_algorithm, server_key_agreement_pk, signature) =
            common_server_hello_processing(&mut self.transcript, &message)?;

        // Verify the signature.
        let verifier = self.suite.signature();
        let sig_to_verify = signature.ok_or(HandshakeError::InvalidSignature)?;
        verify_ephemeral_keys(
            verifier,
            &server_kem_pk,
            &server_key_agreement_pk,
            &sig_to_verify,
            &self.server_signature_public_key,
        )?;

        // Delegate to the common logic for key derivation and message creation.
        complete_server_hello_processing(
            self,
            server_kem_pk,
            kem_algorithm,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

impl HandshakeClient<AwaitingKemPublicKey, WithoutSignature> {
    /// Processes `ServerHello` for a suite without a signature scheme.
    ///
    /// Skips signature verification.
    ///
    /// 为不带签名方案的套件处理 `ServerHello`。
    ///
    /// 跳过签名验证。
    pub fn process_server_hello(
        mut self,
        message: HandshakeMessage,
        initial_payload: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<Established, WithoutSignature>,
    )> {
        let (server_kem_pk, kem_algorithm, server_key_agreement_pk, _) =
            common_server_hello_processing(&mut self.transcript, &message)?;

        // Delegate to the common logic for key derivation and message creation.
        complete_server_hello_processing(
            self,
            server_kem_pk,
            kem_algorithm,
            server_key_agreement_pk,
            initial_payload,
            aad,
        )
    }
}

/// Parses the ServerHello and updates the transcript.
///
/// 解析 ServerHello 并更新握手记录。
fn common_server_hello_processing(
    transcript: &mut Transcript,
    message: &HandshakeMessage,
) -> Result<(
    TypedKemPublicKey,
    KemAlgorithmWrapper,
    Option<TypedKeyAgreementPublicKey>,
    Option<SignatureWrapper>,
)> {
    transcript.update(message);

    match message {
        HandshakeMessage::ServerHello {
            kem_public_key,
            kem_algorithm,
            key_agreement_public_key,
            signature,
        } => Ok((
            kem_public_key.clone(),
            kem_algorithm.clone().into_wrapper(),
            key_agreement_public_key.clone(),
            signature.clone(),
        )),
        _ => Err(HandshakeError::InvalidMessage),
    }
}

/// Completes the handshake logic after `ServerHello` has been processed.
/// This includes key derivation, encryption of initial payload, and state transition.
///
/// 在 `ServerHello` 处理完毕后完成握手逻辑。
/// 这包括密钥派生、初始有效载荷的加密以及状态转换。
fn complete_server_hello_processing<Sig: SignaturePresence>(
    mut client: HandshakeClient<AwaitingKemPublicKey, Sig>,
    server_kem_pk: TypedKemPublicKey,
    kem_algorithm: KemAlgorithmWrapper,
    server_key_agreement_pk: Option<TypedKeyAgreementPublicKey>,
    initial_payload: Option<&[u8]>,
    aad: Option<&[u8]>,
) -> Result<(HandshakeMessage, HandshakeClient<Established, Sig>)> {
    // --- Key Derivation ---
    let kem = kem_algorithm;

    // KEM: Encapsulate a new shared secret against the server's public KEM key.
    let (shared_secret_kem, encapsulated_key) = kem.encapsulate_key(&server_kem_pk)?;

    // Key Agreement: If negotiated, compute the shared secret.
    let shared_secret_agreement = if let (Some(engine), Some(server_pk)) =
        (client.key_agreement_engine.as_ref(), &server_key_agreement_pk)
    {
        Some(engine.agree(server_pk)?)
    } else {
        None
    };

    // KDF: Derive session keys.
    let session_keys = derive_session_keys(
        &client.suite,
        shared_secret_kem,
        shared_secret_agreement,
        client.resumption_master_secret.take(), // Use the resumption secret
        true, // is_client = true
    )?;

    // DEM: Encrypt the initial payload.
    let aad = aad.unwrap_or(b"seal-handshake-aad");
    let aead = client.suite.aead();
    let params = AeadParamsBuilder::new(aead.algorithm(), 4096)
        .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
        .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
        .build();

    let kdf_params = KdfParams {
        algorithm: client.suite.kdf().algorithm(),
        salt: Some(b"seal-handshake-salt".to_vec()),
        info: Some(b"seal-handshake-c2s".to_vec()),
    };

    let header = EncryptedHeader {
        params,
        kem_algorithm: kem.algorithm(),
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

    // Create the `ClientKeyExchange` message.
    let key_exchange_msg = HandshakeMessage::ClientKeyExchange {
        encrypted_message,
        encapsulated_key,
    };

    client.transcript.update(&key_exchange_msg);

    // Transition to the `Established` state.
    let established_client = HandshakeClient {
        state: PhantomData,
        suite: client.suite,
        transcript: client.transcript,
        key_agreement_engine: client.key_agreement_engine,
        server_signature_public_key: client.server_signature_public_key,
        encryption_key: Some(session_keys.encryption_key),
        decryption_key: Some(session_keys.decryption_key),
        established_master_secret: Some(session_keys.master_secret),
        new_session_ticket: None,
        resumption_master_secret: None, // Consumed
        session_ticket_to_send: None,   // Consumed
    };

    Ok((key_exchange_msg, established_client))
}

impl<Sig: SignaturePresence> HandshakeClient<Established, Sig> {
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

    /// Processes a `NewSessionTicket` message from the server.
    ///
    /// The client should store this ticket alongside the master secret for future resumption.
    ///
    /// 处理来自服务器的 `NewSessionTicket` 消息。
    ///
    /// 客户端应将此票据与主密钥一起存储，以备将来恢复之用。
    pub fn process_new_session_ticket(&mut self, message: HandshakeMessage) -> Result<()> {
        match message {
            HandshakeMessage::NewSessionTicket { ticket } => {
                self.new_session_ticket = Some(ticket);
                Ok(())
            }
            _ => Err(HandshakeError::InvalidMessage),
        }
    }

    /// Returns the master secret established in this session.
    ///
    /// This should be stored securely by the application and used for future session resumption.
    ///
    /// 返回在此会话中建立的主密钥。
    ///
    /// 应用程序应安全地存储此密钥，并将其用于将来的会话恢复。
    pub fn master_secret(&self) -> Option<&SharedSecret> {
        self.established_master_secret.as_ref()
    }

    /// Returns the new session ticket received from the server, if any.
    ///
    /// This opaque ticket should be stored by the application and used for future session resumption.
    ///
    /// 返回从服务器收到的新会话票据（如果有）。
    ///
    /// 应用程序应存储此不透明票据，并将其用于将来的会话恢复。
    pub fn session_ticket(&self) -> Option<&Vec<u8>> {
        self.new_session_ticket.as_ref()
    }
}

impl HandshakeClient<Established, WithSignature> {
    /// Decrypts a message from the server and verifies the handshake transcript signature.
    ///
    /// This method is specific to suites `WithSignature`.
    ///
    /// 解密来自服务器的消息并验证握手记录签名。
    ///
    /// 此方法专用于 `WithSignature` 的套件。
    pub fn decrypt(&self, message: HandshakeMessage, aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let encrypted_message = match message {
            HandshakeMessage::ServerFinished { encrypted_message } => encrypted_message,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        let aad = aad.unwrap_or(b"seal-handshake-aad");

        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Prepare decryption and verify the transcript signature using the server's public key.
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(
            &encrypted_message,
            Some(&self.server_signature_public_key),
        )?;

        // Perform the decryption.
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}

impl HandshakeClient<Established, WithoutSignature> {
    /// Decrypts a message from the server.
    ///
    /// This method is specific to suites `WithoutSignature` and does not perform transcript verification.
    ///
    /// 解密来自服务器的消息。
    ///
    /// 此方法专用于 `WithoutSignature` 的套件，不执行握手记录验证。
    pub fn decrypt(&self, message: HandshakeMessage, aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let encrypted_message = match message {
            HandshakeMessage::ServerFinished { encrypted_message } => encrypted_message,
            _ => return Err(HandshakeError::InvalidMessage),
        };

        let aad = aad.unwrap_or(b"seal-handshake-aad");

        let key = self
            .decryption_key
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;

        // Prepare decryption without verifying a transcript signature.
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message, None)?;

        // Perform the decryption.
        pending_decryption
            .decrypt_ordinary(Cow::Borrowed(key), Some(aad.to_vec()))
            .map_err(Into::into)
    }
}