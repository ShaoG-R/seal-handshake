use super::{HandshakeServer, ProtocolSuite, Ready, SignaturePresence, SuiteProvider};
use crate::crypto::suite::{WithSignature, WithoutSignature};
use crate::protocol::{state::ServerReady, transcript::Transcript};
use seal_flow::crypto::prelude::*;
use std::marker::PhantomData;

// --- Builder Typestate Markers ---

/// Marker for when the protocol suite has not been set.
///
/// 标记协议套件尚未设置。
pub struct SuiteNotSet;

/// Marker for when the protocol suite has been set.
///
/// 标记协议套件已设置。
pub struct SuiteSet<S: SignaturePresence>(ProtocolSuite<S>);

/// Marker for when the signature key has not been set.
///
/// 标记签名密钥尚未设置。
pub struct KeyNotSet;

/// Marker for when the signature key has been set.
///
/// 标记签名密钥已设置。
pub struct KeySet<S: SignaturePresence>(S::ServerKey);

/// A builder for creating a `HandshakeServer`.
///
/// This builder uses the typestate pattern to ensure that all required fields
/// are provided before constructing the server.
///
/// 用于创建 `HandshakeServer` 的构建器。
///
/// 此构建器使用类型状态模式来确保在构造服务器之前提供了所有必需的字段。
pub struct HandshakeServerBuilder<Suite, Key> {
    suite: Suite,
    key: Key,
    ticket_encryption_key: Option<TypedAeadKey>,
}

impl HandshakeServerBuilder<SuiteNotSet, KeyNotSet> {
    /// Creates a new `HandshakeServerBuilder`.
    pub fn new() -> Self {
        Self {
            suite: SuiteNotSet,
            key: KeyNotSet,
            ticket_encryption_key: None,
        }
    }
}

impl<Suite, Key> HandshakeServerBuilder<Suite, Key> {
    /// Sets the protocol suite for the handshake.
    /// If not set, the server will dynamically negotiate algorithms with the client.
    ///
    /// 设置握手所用的协议套件。
    /// 如果未设置，服务器将与客户端动态协商算法。
    pub fn suite<S: SignaturePresence>(
        self,
        suite: ProtocolSuite<S>,
    ) -> HandshakeServerBuilder<SuiteSet<S>, Key> {
        HandshakeServerBuilder {
            suite: SuiteSet(suite),
            key: self.key,
            ticket_encryption_key: self.ticket_encryption_key,
        }
    }

    /// Sets the server's long-term identity key pair for signing.
    /// This version is for when a signature algorithm IS used.
    ///
    /// 设置用于签名的服务器长期身份密钥对。
    /// 此版本用于使用签名算法的情况。
    pub fn signature_key_pair(
        self,
        key_pair: TypedSignatureKeyPair,
    ) -> HandshakeServerBuilder<Suite, KeySet<WithSignature>> {
        HandshakeServerBuilder {
            suite: self.suite,
            key: KeySet(key_pair),
            ticket_encryption_key: self.ticket_encryption_key,
        }
    }

    /// Sets the server's identity for an anonymous handshake.
    /// This version is for when a signature algorithm IS NOT used.
    ///
    /// 为匿名握手设置服务器身份。
    /// 此版本用于不使用签名算法的情况。
    pub fn without_signature(self) -> HandshakeServerBuilder<Suite, KeySet<WithoutSignature>> {
        HandshakeServerBuilder {
            suite: self.suite,
            key: KeySet(()),
            ticket_encryption_key: self.ticket_encryption_key,
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

// --- Build method implementations ---

// Build with a preset suite.
impl<S: SignaturePresence> HandshakeServerBuilder<SuiteSet<S>, KeySet<S>> {
    /// Builds the `HandshakeServer`.
    ///
    /// This method is only available when all required fields have been provided.
    ///
    /// 构建 `HandshakeServer`。
    ///
    /// 此方法仅在提供了所有必需字段时可用。
    pub fn build(self) -> HandshakeServer<Ready, ServerReady, S> {
        HandshakeServer {
            state: PhantomData,
            preset_suite: SuiteProvider::Preset(self.suite.0),
            state_data: ServerReady {},
            transcript: Transcript::new(),

            signature_key_pair: self.key.0,
            ticket_encryption_key: self.ticket_encryption_key,
        }
    }
}

// Build without a preset suite (negotiated).
impl<S: SignaturePresence> HandshakeServerBuilder<SuiteNotSet, KeySet<S>> {
    /// Builds the `HandshakeServer`.
    ///
    /// This method is only available when all required fields have been provided.
    ///
    /// 构建 `HandshakeServer`。
    ///
    /// 此方法仅在提供了所有必需字段时可用。
    pub fn build(self) -> HandshakeServer<Ready, ServerReady, S> {
        HandshakeServer {
            state: PhantomData,
            preset_suite: SuiteProvider::Negotiated(None),
            state_data: ServerReady {},
            transcript: Transcript::new(),

            signature_key_pair: self.key.0,
            ticket_encryption_key: self.ticket_encryption_key,
        }
    }
}
