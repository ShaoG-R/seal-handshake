//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::crypto::suite::{ProtocolSuite, SignaturePresence};
use crate::protocol::{
    state::Ready,
    transcript::Transcript,
};
use std::marker::PhantomData;

mod builder;
mod state_awaiting_kem;
mod state_established;
mod state_ready;

pub use builder::HandshakeClientBuilder;

/// The client-side handshake state machine.
///
/// Generic over the state `S` to enforce protocol flow at compile time.
/// This prevents out-of-order operations, such as trying to encrypt data before keys are established.
///
/// 客户端握手协议状态机。
///
/// 通过泛型状态 `S` 在编译时强制执行协议流程。
/// 这可以防止乱序操作，例如在密钥建立之前尝试加密数据。
#[derive(Debug)]
pub struct HandshakeClient<S, StateData, Sig: SignaturePresence> {
    /// Zero-sized marker to hold the current state `S`.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    state: PhantomData<S>,
    /// The cryptographic suite used for the handshake.
    ///
    /// 握手过程中使用的密码套件。
    suite: ProtocolSuite<Sig>,
    state_data: StateData,
    /// A running hash of the handshake transcript for integrity checks.
    /// This ensures that the messages negotiated are the same ones the server signs.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    /// 这确保了协商的消息与服务器签名的消息是相同的。
    transcript: Transcript,
    /// The server's long-term public key for verifying signatures.
    /// This is a crucial part of authenticating the server.
    ///
    /// 用于验证签名的服务器长期公钥。
    /// 这是验证服务器身份的关键部分。
    server_signature_public_key: Sig::ClientKey,
}
