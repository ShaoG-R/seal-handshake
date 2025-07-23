use super::{HandshakeClient, SignaturePresence};
use crate::{
    crypto::suite::{ProtocolSuite, WithSignature, WithoutSignature},
    error::{HandshakeError, Result},
    protocol::{
        message::{EncryptedHeader, HandshakeMessage, KdfParams},
        state::{ClientEstablished, Established},
    },
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        keys::asymmetric::kem::SharedSecret,
        prelude::*,
    },
    prelude::{prepare_decryption_from_slice, EncryptionConfigurator},
    rand::{rngs::OsRng, TryRngCore},
};
use std::borrow::Cow;

impl<Sig: SignaturePresence> HandshakeClient<Established, ClientEstablished, Sig> {
    /// Encrypts application data to be sent to the server.
    ///
    /// This method uses the derived client-to-server key to secure the payload.
    ///
    /// 加密要发送到服务器的应用程序数据。
    ///
    /// 此方法使用派生的客户端到服务器密钥来保护有效载荷。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        common_encrypt(
            &self.suite,
            &self.state_data.encryption_key,
            plaintext,
            aad,
        )
    }
}

impl HandshakeClient<Established, ClientEstablished, WithoutSignature> {
    /// Decrypts application data received from the server.
    ///
    /// This method uses the derived server-to-client key to decrypt the payload.
    /// It also performs an integrity check using the associated data (AAD).
    ///
    /// 解密从服务器接收的应用程序数据。
    ///
    /// 此方法使用派生的服务器到客户端密钥来解密有效载荷。
    /// 它还使用关联数据（AAD）执行完整性检查。
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(ciphertext, None)?;
        pending_decryption
            .decrypt_ordinary(
                Cow::Borrowed(&self.state_data.decryption_key),
                Some(aad.to_vec()),
            )
            .map_err(Into::into)
    }
}

impl HandshakeClient<Established, ClientEstablished, WithSignature> {
    /// Decrypts application data received from the server.
    ///
    /// This method uses the derived server-to-client key to decrypt the payload.
    /// It also performs an integrity check using the associated data (AAD).
    ///
    /// 解密从服务器接收的应用程序数据。
    ///
    /// 此方法使用派生的服务器到客户端密钥来解密有效载荷。
    /// 它还使用关联数据（AAD）执行完整性检查。
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let pending_decryption = prepare_decryption_from_slice::<EncryptedHeader>(
            ciphertext,
            Some(&self.server_signature_public_key),
        )?;
        pending_decryption
            .decrypt_ordinary(
                Cow::Borrowed(&self.state_data.decryption_key),
                Some(aad.to_vec()),
            )
            .map_err(Into::into)
    }
}

impl<Sig: SignaturePresence> HandshakeClient<Established, ClientEstablished, Sig> {
    /// Processes a `NewSessionTicket` message from the server.
    ///
    /// This saves the ticket for potential use in a future session's resumption.
    ///
    /// 处理来自服务器的 `NewSessionTicket` 消息。
    ///
    /// 这会保存票据，以便在将来的会话恢复中使用。
    pub fn process_new_session_ticket(&mut self, message: HandshakeMessage) -> Result<()> {
        if let HandshakeMessage::NewSessionTicket { ticket } = message {
            self.state_data.new_session_ticket = Some(ticket);
            Ok(())
        } else {
            Err(HandshakeError::InvalidMessage)
        }
    }

    /// Returns the established session's master secret and the new session ticket,
    /// if available. This data can be stored by the application and used for
    /// session resumption in a future connection.
    ///
    /// 返回已建立会话的主密钥和新的会话票据（如果可用）。
    /// 应用程序可以存储这些数据，并在将来的连接中用于会话恢复。
    pub fn resumption_data(&self) -> (SharedSecret, Option<Vec<u8>>) {
        (
            self.state_data.master_secret.clone(),
            self.state_data.new_session_ticket.clone(),
        )
    }
}

/// A common encryption function used by the established client.
/// It configures the AEAD parameters and encrypts the plaintext.
///
/// 客户端在连接建立后使用的通用加密函数。
/// 它配置 AEAD 参数并加密明文。
fn common_encrypt<S: SignaturePresence>(
    suite: &ProtocolSuite<S>,
    key: &TypedAeadKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let params = AeadParamsBuilder::new(suite.aead(), 4096)
        .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
        .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
        .build();

    let kdf_params = KdfParams {
        algorithm: suite.kdf(),
        salt: Some(b"seal-handshake-salt".to_vec()),
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
