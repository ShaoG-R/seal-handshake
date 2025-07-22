use super::{AwaitingKemPublicKey, HandshakeClient, HandshakeClientBuilder, KeyAgreementEngine, Missing, Ready, SignaturePresence};
use crate::protocol::message::HandshakeMessage;
use std::marker::PhantomData;


impl<Sig: SignaturePresence> HandshakeClient<Ready, Sig> {
    /// Creates a new `HandshakeClientBuilder` to construct a `HandshakeClient`.
    ///
    /// 在 `Ready` 状态下创建一个新的 `HandshakeClient` 的构建器。
    pub fn builder() -> HandshakeClientBuilder<Missing, Missing, Sig> {
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
            kem_algorithm: self.suite.kem().algorithm(),
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