
use super::{HandshakeClient, ProtocolSuite, Ready, SignaturePresence};
use crate::error::{HandshakeError, Result};
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use std::marker::PhantomData;

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
            transcript: crate::protocol::transcript::Transcript::new(),
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