use super::{HandshakeServer, ProtocolSuite, Ready, SignaturePresence};
use crate::{crypto::suite::KeyAgreementPresence, protocol::transcript::Transcript};
use seal_flow::crypto::prelude::*;
use std::marker::PhantomData;

/// Marker type for a missing field in the builder.
///
/// 用于在构建器中标记缺失字段的类型。
pub struct Missing;

/// A builder for creating a `HandshakeServer`.
///
/// This builder ensures that all required fields are provided before constructing the server.
///
/// 用于创建 `HandshakeServer` 的构建器。
///
/// 此构建器确保在构造服务器之前提供了所有必需的字段。
pub struct HandshakeServerBuilder<Suite, Key, Sig: SignaturePresence, Ka: KeyAgreementPresence> {
    suite: Suite,
    signature_key_pair: Key,
    ticket_encryption_key: Option<TypedAeadKey>,
    _sig: PhantomData<Sig>,
    _ka: PhantomData<Ka>,
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence>
    HandshakeServerBuilder<Missing, Missing, Sig, Ka>
{
    /// Creates a new `HandshakeServerBuilder`.
    pub fn new() -> Self {
        Self {
            suite: Missing,
            signature_key_pair: Missing,
            ticket_encryption_key: None,
            _sig: PhantomData,
            _ka: PhantomData,
        }
    }
}

impl<S, K, Sig: SignaturePresence, Ka: KeyAgreementPresence> HandshakeServerBuilder<S, K, Sig, Ka> {
    /// Sets the protocol suite for the handshake.
    ///
    /// 设置握手所用的协议套件。
    pub fn suite(
        self,
        suite: ProtocolSuite<Sig, Ka>,
    ) -> HandshakeServerBuilder<ProtocolSuite<Sig, Ka>, K, Sig, Ka> {
        HandshakeServerBuilder {
            suite,
            signature_key_pair: self.signature_key_pair,
            ticket_encryption_key: self.ticket_encryption_key,
            _sig: PhantomData,
            _ka: PhantomData,
        }
    }

    /// Sets the server's long-term identity key pair for signing.
    ///
    /// This is required to authenticate the server.
    ///
    /// 设置用于签名的服务器长期身份密钥对。
    ///
    /// 这是验证服务器身份所必需的。
    pub fn signature_key_pair(
        self,
        key_pair: Sig::ServerKey,
    ) -> HandshakeServerBuilder<S, Sig::ServerKey, Sig, Ka> {
        HandshakeServerBuilder {
            suite: self.suite,
            signature_key_pair: key_pair,
            ticket_encryption_key: self.ticket_encryption_key,
            _sig: PhantomData,
            _ka: PhantomData,
        }
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
}

impl<Sig: SignaturePresence, Ka: KeyAgreementPresence>
    HandshakeServerBuilder<ProtocolSuite<Sig, Ka>, Sig::ServerKey, Sig, Ka>
{
    /// Builds the `HandshakeServer`.
    ///
    /// This method is only available when all required fields have been provided.
    ///
    /// 构建 `HandshakeServer`。
    ///
    /// 此方法仅在提供了所有必需字段时可用。
    pub fn build(self) -> HandshakeServer<Ready, Sig, Ka> {
        HandshakeServer {
            state: PhantomData,
            suite: self.suite,
            transcript: Transcript::new(),
            signature_key_pair: self.signature_key_pair,
            kem_key_pair: None,
            key_agreement_engine: None,
            agreement_shared_secret: None,
            encryption_key: None,
            decryption_key: None,
            master_secret: None,
            ticket_encryption_key: self.ticket_encryption_key,
            resumption_master_secret: None,
        }
    }
}
