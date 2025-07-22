
use super::{HandshakeServer, ProtocolSuite, Ready, SignaturePresence};
use crate::{error::{HandshakeError, Result}, protocol::transcript::Transcript};
use seal_flow::crypto::prelude::*;
use std::marker::PhantomData;

/// A builder for creating a `HandshakeServer`.
///
/// This builder ensures that all required fields are provided before constructing the server.
///
/// 用于创建 `HandshakeServer` 的构建器。
///
/// 此构建器确保在构造服务器之前提供了所有必需的字段。
#[derive(Default)]
pub struct HandshakeServerBuilder<Sig: SignaturePresence> {
    suite: Option<ProtocolSuite<Sig>>,
    signature_key_pair: Option<Sig::ServerKey>,
    ticket_encryption_key: Option<TypedAeadKey>,
}

impl<Sig: SignaturePresence> HandshakeServerBuilder<Sig> {
    /// Creates a new `HandshakeServerBuilder`.
    pub fn new() -> Self {
        Self {
            suite: None,
            signature_key_pair: None,
            ticket_encryption_key: None,
        }
    }

    /// Sets the protocol suite for the handshake.
    ///
    /// 设置握手所用的协议套件。
    pub fn suite(mut self, suite: ProtocolSuite<Sig>) -> Self {
        self.suite = Some(suite);
        self
    }

    /// Sets the server's long-term identity key pair for signing.
    ///
    /// This is required to authenticate the server.
    ///
    /// 设置用于签名的服务器长期身份密钥对。
    ///
    /// 这是验证服务器身份所必需的。
    pub fn signature_key_pair(mut self, key_pair: Sig::ServerKey) -> Self {
        self.signature_key_pair = Some(key_pair);
        self
    }

    /// Sets the key for encrypting session tickets.
    /// If not provided, the server will not be able to issue tickets for resumption.
    ///
    /// 设置用于加密会话票据的密钥。
    /// 如果不提供，服务器将无法为会话恢复签发票据。
    pub fn ticket_encryption_key(mut self, key: TypedAeadKey) -> Self {
        self.ticket_encryption_key = Some(key);
        self
    }

    /// Builds the `HandshakeServer`.
    ///
    /// Returns an error if any required fields are missing.
    ///
    /// 构建 `HandshakeServer`。
    ///
    /// 如果任何必需字段缺失，则返回错误。
    pub fn build(self) -> Result<HandshakeServer<Ready, Sig>> {
        let suite = self
            .suite
            .ok_or(HandshakeError::BuilderMissingField("suite"))?;
        let signature_key_pair = self.signature_key_pair.ok_or(
            HandshakeError::BuilderMissingField("signature_key_pair"),
        )?;

        Ok(HandshakeServer {
            state: PhantomData,
            suite,
            transcript: Transcript::new(),
            signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: None,
            agreement_shared_secret: None,
            encryption_key: None,
            decryption_key: None,
            master_secret: None,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: None,
        })
    }
} 