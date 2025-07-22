use super::{
    AwaitingKemPublicKey, HandshakeClient, HandshakeClientBuilder, KeyAgreementEngine, Missing,
    Ready, SignaturePresence,
};
use crate::{
    crypto::suite::{KeyAgreementPresence, WithKeyAgreement, WithoutKeyAgreement},
    protocol::message::{ClientHelloPayload, HandshakeMessage},
};
use seal_flow::crypto::prelude::TypedKeyAgreementPublicKey;
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
        mut self,
    ) -> (
        HandshakeMessage<Sig, Ka>,
        HandshakeClient<AwaitingKemPublicKey, Sig, Ka>,
    )
    where
        Self: ClientKeyAgreementHandler<Ka>,
    {
        let (ka_pk, ka_engine) = self.generate_key_agreement_part().unwrap();

        let client_hello_payload = ClientHelloPayload {
            key_agreement_public_key: ka_pk,
            session_ticket: self.session_ticket_to_send.take(),
            kem_algorithm: self.suite.kem().algorithm(),
        };

        let client_hello = HandshakeMessage::ClientHello(client_hello_payload);
        self.transcript.update(&client_hello);

        let next_client = HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: self.transcript,
            key_agreement_engine: ka_engine,
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

pub trait ClientKeyAgreementHandler<K: KeyAgreementPresence> {
    fn generate_key_agreement_part(
        &self,
    ) -> crate::error::Result<(K::MessagePublicKey, Option<KeyAgreementEngine>)>;
}

impl<S: SignaturePresence> ClientKeyAgreementHandler<WithKeyAgreement>
    for HandshakeClient<Ready, S, WithKeyAgreement>
{
    fn generate_key_agreement_part(
        &self,
    ) -> crate::error::Result<(TypedKeyAgreementPublicKey, Option<KeyAgreementEngine>)> {
        let engine = KeyAgreementEngine::new_for_client(&self.suite.key_agreement())?;
        let public_key = engine.public_key().clone();
        Ok((public_key, Some(engine)))
    }
}

impl<S: SignaturePresence> ClientKeyAgreementHandler<WithoutKeyAgreement>
    for HandshakeClient<Ready, S, WithoutKeyAgreement>
{
    fn generate_key_agreement_part(&self) -> crate::error::Result<((), Option<KeyAgreementEngine>)> {
        Ok(((), None))
    }
}
