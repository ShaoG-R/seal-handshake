use super::{HandshakeClient, ProtocolSuite, Ready, SignaturePresence};
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use std::marker::PhantomData;

/// Marker type for a missing field in the builder.
///
/// 用于在构建器中标记缺失字段的类型。
pub struct Missing;

/// A builder for creating a `HandshakeClient`.
///
/// This builder ensures that all required fields are provided before constructing the client.
///
/// 用于创建 `HandshakeClient` 的构建器。
///
/// 此构建器确保在构造客户端之前提供了所有必需的字段。
pub struct HandshakeClientBuilder<Suite, ServerKey, Sig: SignaturePresence> {
    suite: Suite,
    server_signature_public_key: ServerKey,
    resumption_master_secret: Option<SharedSecret>,
    session_ticket: Option<Vec<u8>>,
    _sig: PhantomData<Sig>,
}

impl<Sig: SignaturePresence> HandshakeClientBuilder<Missing, Missing, Sig> {
    /// Creates a new `HandshakeClientBuilder`.
    pub fn new() -> Self {
        Self {
            suite: Missing,
            server_signature_public_key: Missing,
            resumption_master_secret: None,
            session_ticket: None,
            _sig: PhantomData,
        }
    }
}

impl<S, K, Sig: SignaturePresence> HandshakeClientBuilder<S, K, Sig> {
    /// Sets the protocol suite for the handshake.
    ///
    /// 设置握手所用的协议套件。
    pub fn suite(
        self,
        suite: ProtocolSuite<Sig>,
    ) -> HandshakeClientBuilder<ProtocolSuite<Sig>, K, Sig> {
        HandshakeClientBuilder {
            suite,
            server_signature_public_key: self.server_signature_public_key,
            resumption_master_secret: self.resumption_master_secret,
            session_ticket: self.session_ticket,
            _sig: PhantomData,
        }
    }

    /// Sets the server's public key for verifying signatures.
    ///
    /// This is required to authenticate the server.
    ///
    /// 设置用于验证签名的服务器公钥。
    ///
    /// 这是验证服务器身份所必需的。
    pub fn server_signature_public_key(
        self,
        key: Sig::ClientKey,
    ) -> HandshakeClientBuilder<S, Sig::ClientKey, Sig> {
        HandshakeClientBuilder {
            suite: self.suite,
            server_signature_public_key: key,
            resumption_master_secret: self.resumption_master_secret,
            session_ticket: self.session_ticket,
            _sig: PhantomData,
        }
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
}

impl<Sig: SignaturePresence> HandshakeClientBuilder<ProtocolSuite<Sig>, Sig::ClientKey, Sig> {
    /// Builds the `HandshakeClient`.
    ///
    /// This method is only available when all required fields have been provided.
    ///
    /// 构建 `HandshakeClient`。
    ///
    /// 此方法仅在提供了所有必需字段时可用。
    pub fn build(self) -> HandshakeClient<Ready, Sig> {
        HandshakeClient {
            state: PhantomData,
            suite: self.suite,
            transcript: crate::protocol::transcript::Transcript::new(),
            key_agreement_engine: None,
            server_signature_public_key: self.server_signature_public_key,
            encryption_key: None,
            decryption_key: None,
            established_master_secret: None,
            new_session_ticket: None,
            resumption_master_secret: self.resumption_master_secret,
            session_ticket_to_send: self.session_ticket,
        }
    }
}
