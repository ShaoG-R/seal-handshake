//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。

use crate::crypto::suite::{KeyAgreementEngine, ProtocolSuite, SignaturePresence};
use crate::protocol::{
    state::{AwaitingKeyExchange, Established, Ready},
    transcript::Transcript,
};
use std::marker::PhantomData;

mod builder;
mod state_awaiting_key_exchange;
mod state_established;
mod state_ready;

pub use builder::HandshakeServerBuilder;
use builder::Missing;
use seal_flow::crypto::{
    keys::asymmetric::kem::SharedSecret,
    prelude::{TypedAeadKey, TypedKemKeyPair},
};

// --- State Markers ---
// (State markers are now imported from `crate::state`)

/// The server-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
/// This ensures that methods can only be called in the correct sequence,
/// preventing logical errors in the protocol's implementation.
///
/// 服务器端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
/// 这确保了方法只能按正确的顺序调用，防止了协议实现中的逻辑错误。
#[derive(Debug)]
pub struct HandshakeServer<State, Sig: SignaturePresence> {
    /// Zero-sized marker to hold the current state `S`.
    /// This doesn't take up space but allows the type system to track the machine's state.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    /// 它不占用空间，但允许类型系统跟踪机器的状态。
    state: PhantomData<State>,
    /// The cryptographic suite used for the handshake.
    /// This defines the set of algorithms (KEM, AEAD, KDF, etc.) to be used.
    ///
    /// 握手过程中使用的密码套件。
    /// 这定义了要使用的算法集（KEM、AEAD、KDF 等）。
    suite: ProtocolSuite<Sig>,
    /// A running hash of the handshake transcript for integrity checks.
    /// It accumulates all messages exchanged, and its final hash is signed by the server.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    /// 它累积所有交换的消息，其最终哈希值由服务器签名。
    transcript: Transcript,
    /// The server's long-term identity key pair for signing.
    /// This key proves the server's identity to the client.
    ///
    /// 服务器用于签名的长期身份密钥对。
    /// 此密钥向客户端证明服务器的身份。
    signature_key_pair: Sig::ServerKey,
    /// The server's ephemeral KEM key pair, generated for this session.
    /// It is used once to decapsulate the shared secret from the client and then discarded.
    /// Stored as an `Option` because it only exists during a specific phase of the handshake.
    ///
    /// 服务器为此会话生成的临时 KEM 密钥对。
    /// 它用于从客户端解封装共享密钥一次，然后被丢弃。
    /// 存储为 `Option`，因为它只在握手的特定阶段存在。
    kem_key_pair: Option<TypedKemKeyPair>,
    /// The server's ephemeral key agreement engine, if used.
    /// This is part of an optional Diffie-Hellman style key agreement for Perfect Forward Secrecy.
    ///
    /// 服务器的临时密钥协商引擎（如果使用）。
    /// 这是可选的 Diffie-Hellman 风格密钥协商的一部分，用于实现前向保密。
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The shared secret derived from key agreement, if used.
    /// This secret is combined with the KEM secret to derive session keys.
    ///
    /// 从密钥协商中派生的共享密钥（如果使用）。
    /// 该密钥与 KEM 密钥结合以派生会话密钥。
    agreement_shared_secret: Option<SharedSecret>,
    /// Derived key for encryption (server-to-client).
    /// Established after a successful key exchange.
    ///
    /// 用于加密（服务器到客户端）的派生密钥。
    /// 在密钥交换成功后建立。
    encryption_key: Option<TypedAeadKey>,
    /// Derived key for decryption (client-to-server).
    /// Established after a successful key exchange.
    ///
    /// 用于解密（客户端到服务器）的派生密钥。
    /// 在密钥交换成功后建立。
    decryption_key: Option<TypedAeadKey>,
    /// The master secret for this session, used for creating session tickets.
    ///
    /// 当前会话的主密钥，用于创建会话票据。
    master_secret: Option<SharedSecret>,
    /// A long-term symmetric key used to encrypt session tickets.
    /// If not set, the server will not issue tickets.
    ///
    /// 用于加密会话票据的长期对称密钥。
    /// 如果未设置，服务器将不会签发票据。
    ticket_encryption_key: Option<TypedAeadKey>,
    /// The master secret recovered from a session ticket, if any.
    /// This is stored temporarily during the handshake.
    ///
    /// 从会话票据中恢复的主密钥（如果有）。
    /// 这在握手期间临时存储。
    resumption_master_secret: Option<SharedSecret>,
}
