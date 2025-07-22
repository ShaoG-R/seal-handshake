
use super::{Established, HandshakeClient, SignaturePresence, WithSignature, WithoutSignature};
use crate::error::{HandshakeError, Result};
use crate::protocol::message::{EncryptedHeader, HandshakeMessage, KdfParams};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        keys::asymmetric::kem::SharedSecret,
        prelude::*,
        traits::{AeadAlgorithmTrait},
    },
    prelude::{prepare_decryption_from_slice, EncryptionConfigurator},
    rand::{rngs::OsRng, TryRngCore},
};
use std::borrow::Cow;


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