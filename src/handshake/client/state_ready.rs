use super::{
    AwaitingKemPublicKey, HandshakeClient, HandshakeClientBuilder, KeyAgreementEngine, Missing,
    Ready, SignaturePresence,
};
use crate::{
    crypto::suite::{KeyAgreementPresence, WithKeyAgreement, WithoutKeyAgreement},
    protocol::message::HandshakeMessage,
};
use std::marker::PhantomData;

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeClient<Ready, Sig, Ka> {
    /// Creates a new `HandshakeClientBuilder` to construct a `HandshakeClient`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeClient` 的构建器。
    pub fn builder() -> HandshakeClientBuilder<Missing, Missing, Sig, Ka> {
        HandshakeClientBuilder::new()
    }

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
        self,
    ) -> (
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    )
    where
        Self: ReadyStateOperations<Sig, Ka>,
    {
        ReadyStateOperations::start_handshake(self)
    }
}

/// A trait to encapsulate state-specific operations for the `Ready` state.
/// This allows for different implementations based on whether key agreement is used.
pub trait ReadyStateOperations<Sig: SignaturePresence, Ka: KeyAgreementPresence> {
    fn start_handshake(
        self,
    ) -> (
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    );
}

impl<Sig: SignaturePresence> ReadyStateOperations<Sig, WithKeyAgreement>
    for HandshakeClient<Ready, Sig, WithKeyAgreement>
{
    fn start_handshake(
        mut self,
    ) -> (
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, Sig, WithKeyAgreement>,
    ) {
        let engine = KeyAgreementEngine::new_for_client(self.suite.key_agreement()).unwrap();
        let key_agreement_public_key = Some(engine.public_key().clone());

        let client_hello = HandshakeMessage::ClientHello {
            key_agreement_public_key,
            session_ticket: self.session_ticket_to_send.take(),
            kem_algorithm: self.suite.kem().algorithm(),
        };

        self.transcript.update(&client_hello);

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            key_agreement_engine: Some(engine),
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

impl<Sig: SignaturePresence> ReadyStateOperations<Sig, WithoutKeyAgreement>
    for HandshakeClient<Ready, Sig, WithoutKeyAgreement>
{
    fn start_handshake(
        mut self,
    ) -> (
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, Sig, WithoutKeyAgreement>,
    ) {
        let client_hello = HandshakeMessage::ClientHello {
            key_agreement_public_key: None,
            session_ticket: self.session_ticket_to_send.take(),
            kem_algorithm: self.suite.kem().algorithm(),
        };

        self.transcript.update(&client_hello);

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            key_agreement_engine: None,
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
