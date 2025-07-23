use super::{HandshakeServer, SignaturePresence};
use crate::bincode;
use crate::crypto::suite::{WithSignature, WithoutSignature};
use crate::error::{HandshakeError, Result};
use crate::protocol::{
    message::{EncryptedHeader, HandshakeMessage, KdfParams},
    state::{Established, ServerEstablished},
};
use seal_flow::{
    common::header::AeadParamsBuilder,
    crypto::{
        algorithms::asymmetric::signature::SignatureAlgorithm,
        prelude::*,
        traits::SignatureAlgorithmTrait,
        wrappers::asymmetric::signature::SignatureWrapper,
    },
    prelude::{EncryptionConfigurator, prepare_decryption_from_slice},
    rand::{rngs::OsRng, TryRngCore},
};
use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// --- `encrypt` and `decrypt` implementations ---

impl<Sig: SignaturePresence> HandshakeServer<Established, ServerEstablished, Sig> {
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
        let master_secret = &self.state_data.master_secret;

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
        let params = AeadParamsBuilder::new(aead, 4096)
            .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
            .build();

        let header = EncryptedHeader {
            params,
            // These fields are not relevant for ticket encryption but are part of the struct.
            kdf_params: KdfParams {
                algorithm: self.suite.kdf(),
                salt: None,
                info: None,
            },
            signature_algorithm: None,
            signed_transcript_hash: None,
            transcript_signature: None,
        };

        // Note: The AAD is empty here as there's no additional data to authenticate.
        let encrypted_ticket = EncryptionConfigurator::new(header, Cow::Borrowed(tek), None)
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(&serialized_ticket)?;

        Ok(HandshakeMessage::NewSessionTicket {
            ticket: encrypted_ticket,
        })
    }
}

impl HandshakeServer<Established, ServerEstablished, WithSignature> {
    /// Encrypts data and signs the transcript when a signature scheme is configured.
    ///
    /// 当配置了签名方案时，加密数据并对握手记录进行签名。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = &self.state_data.encryption_key;

        // Sign the transcript.
        let signer = self.suite.signature();
        let transcript_hash = self.transcript.current_hash();
        let signature = signer.into_wrapper().sign(&transcript_hash, &self.signature_key_pair.private_key())?;

        // Encrypt with the signature.
        common_encrypt(
            self,
            plaintext,
            aad,
            key,
            Some(signer),
            Some(transcript_hash),
            Some(signature.into()),
        )
    }
}

impl HandshakeServer<Established, ServerEstablished, WithoutSignature> {
    /// Encrypts data without signing when no signature scheme is configured.
    ///
    /// 当未配置签名方案时，加密数据而不进行签名。
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = &self.state_data.encryption_key;

        // Encrypt without a signature.
        common_encrypt(self, plaintext, aad, key, None, None, None)
    }
}

/// Helper function for the common encryption logic.
///
/// 用于通用加密逻辑的辅助函数。
fn common_encrypt<Sig: SignaturePresence>(
    server: &HandshakeServer<Established, ServerEstablished, Sig>,
    plaintext: &[u8],
    aad: &[u8],
    key: &TypedAeadKey,
    signature_algorithm: Option<SignatureAlgorithm>,
    signed_transcript_hash: Option<Vec<u8>>,
    transcript_signature: Option<SignatureWrapper>,
) -> Result<Vec<u8>> {
    let aead = server.suite.aead();
    let params = AeadParamsBuilder::new(aead, 4096)
        .aad_hash(aad, &HashAlgorithm::Sha256.into_wrapper())
        .base_nonce(|nonce| OsRng.try_fill_bytes(nonce).map_err(Into::into))?
        .build();

    let kdf_params = KdfParams {
        algorithm: server.suite.kdf(),
        salt: Some(b"seal-handshake-salt".to_vec()),
        info: Some(b"seal-handshake-s2c".to_vec()),
    };
    let header = EncryptedHeader {
        params,
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

impl<Sig: SignaturePresence> HandshakeServer<Established, ServerEstablished, Sig> {
    /// Decrypts application data from the client using the established client-to-server session key.
    ///
    /// This method is used to process secure data sent by the client after the handshake is complete.
    ///
    /// 使用已建立的客户端到服务器的会话密钥来解密来自客户端的应用数据。
    ///
    /// 此方法用于处理握手完成后客户端发送的安全数据。
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = &self.state_data.decryption_key;

        // Prepare the decryption by parsing the header from the encrypted message.
        // For application data from the client, there is no transcript signature to verify,
        // so `verify_key` is `None`. The integrity of the message is protected by the AEAD tag.
        //
        // 通过从加密消息中解析头部来准备解密。
        // 对于来自客户端的应用数据，没有需要验证的握手记录签名，
        // 因此 `verify_key` 为 `None`。消息的完整性由 AEAD 标签保护。
        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(ciphertext, None)?;

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
