use super::{AwaitingKeyExchange, Established, HandshakeServer, SignaturePresence};
use crate::{
    crypto::{
        keys::{derive_session_keys, SessionKeysAndMaster},
        suite::KeyAgreementPresence,
    },
    error::{HandshakeError, Result},
    protocol::message::{ClientKeyExchangePayload, EncryptedHeader, HandshakeMessage},
};
use seal_flow::{
    crypto::{keys::asymmetric::kem::EncapsulatedKey, prelude::*, traits::KemAlgorithmTrait},
    prelude::{PendingDecryption, prepare_decryption_from_slice},
};
use std::{borrow::Cow, marker::PhantomData};

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeServer<AwaitingKeyExchange, Sig, Ka> {
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
        message: HandshakeMessage<Sig, Ka>,
        aad: &[u8],
    ) -> Result<(Vec<u8>, HandshakeServer<Established, Sig, Ka>)> {
        self.transcript.update(&message);

        let (encrypted_message, encapsulated_key) = extract_client_key_exchange(&message)?;

        let kem_key_pair = self
            .kem_key_pair
            .take()
            .ok_or(HandshakeError::InvalidState)?;

        let pending_decryption =
            prepare_decryption_from_slice::<EncryptedHeader>(&encrypted_message, None)?;

        let session_keys =
            derive_session_keys_from_client_exchange(&self, &kem_key_pair, &encapsulated_key)?;

        let initial_payload =
            decrypt_initial_payload(pending_decryption, &session_keys.decryption_key, aad)?;

        let established_server = HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: self.key_agreement_engine,
            agreement_shared_secret: None,
            encryption_key: Some(session_keys.encryption_key),
            decryption_key: Some(session_keys.decryption_key),
            master_secret: Some(session_keys.master_secret),
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: None,
        };

        Ok((initial_payload, established_server))
    }
}

/// Extracts the contents of a `ClientKeyExchange` message.
fn extract_client_key_exchange<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    message: &HandshakeMessage<Sig, Ka>,
) -> Result<(Vec<u8>, EncapsulatedKey)> {
    match message {
        HandshakeMessage::ClientKeyExchange(ClientKeyExchangePayload {
            encrypted_message,
            encapsulated_key,
        }) => Ok((encrypted_message.clone(), encapsulated_key.clone())),
        _ => Err(HandshakeError::InvalidMessage),
    }
}

/// Derives session keys from the client's key exchange data.
fn derive_session_keys_from_client_exchange<Sig: SignaturePresence, Ka: KeyAgreementPresence>(
    server: &HandshakeServer<AwaitingKeyExchange, Sig, Ka>,
    kem_key_pair: &TypedKemKeyPair,
    encapsulated_key: &EncapsulatedKey,
) -> Result<SessionKeysAndMaster> {
    let kem = kem_key_pair.algorithm().into_wrapper();
    let shared_secret = kem.decapsulate_key(&kem_key_pair.private_key(), encapsulated_key)?;

    derive_session_keys(
        &server.suite,
        shared_secret,
        server.agreement_shared_secret.clone(),
        server.resumption_master_secret.clone(),
        false, // is_client = false
    )
}

/// Decrypts the initial payload from the client.
fn decrypt_initial_payload(
    pending_decryption: PendingDecryption<&[u8], EncryptedHeader>,
    decryption_key: &TypedAeadKey,
    aad: &[u8],
) -> Result<Vec<u8>> {
    pending_decryption
        .decrypt_ordinary(Cow::Borrowed(decryption_key), Some(aad.to_vec()))
        .map_err(Into::into)
}
