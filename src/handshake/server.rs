//! Implements the server-side of the handshake protocol state machine.
//! 实现握手协议状态机的服务器端。

use crate::crypto::suite::{KeyAgreementEngine, ProtocolSuite, SignaturePresence};
use crate::protocol::{
    state::Ready,
    transcript::Transcript,
};
use std::marker::PhantomData;

mod builder;
mod state_awaiting_key_exchange;
mod state_established;
mod state_ready;

pub use builder::HandshakeServerBuilder;
use builder::Missing;
use seal_flow::crypto::prelude::TypedAeadKey;

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
pub struct HandshakeServer<S, StateData, Sig: SignaturePresence> {
    /// Zero-sized marker to hold the current state `S`.
    /// This doesn't take up space but allows the type system to track the machine's state.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    /// 它不占用空间，但允许类型系统跟踪机器的状态。
    state: PhantomData<S>,
    /// The actual data associated with the current state.
    ///
    /// 与当前状态关联的实际数据。
    state_data: StateData,
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
    /// A long-term symmetric key used to encrypt session tickets.
    /// If not set, the server will not issue tickets.
    ///
    /// 用于加密会话票据的长期对称密钥。
    /// 如果未设置，服务器将不会签发票据。
    ticket_encryption_key: Option<TypedAeadKey>,
}
