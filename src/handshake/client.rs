//! Implements the client-side of the handshake protocol state machine.
//！ 实现握手协议状态机的客户端。

use crate::crypto::{
    keys::SessionKeysAndMaster,
    suite::{
        KeyAgreementEngine, KeyAgreementPresence, ProtocolSuite, SignaturePresence, WithSignature,
        WithoutSignature,
    },
};
use crate::protocol::{
    state::{AwaitingKemPublicKey, Established, Ready},
    transcript::Transcript,
};
use builder::Missing;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
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
pub struct HandshakeClient<State, Sig: SignaturePresence, Ka: KeyAgreementPresence> {
    /// Zero-sized marker to hold the current state `S`.
    ///
    /// 零大小标记，用于持有当前状态 `S`。
    state: PhantomData<State>,
    /// The cryptographic suite used for the handshake.
    ///
    /// 握手过程中使用的密码套件。
    suite: ProtocolSuite<Sig, Ka>,
    /// A running hash of the handshake transcript for integrity checks.
    /// This ensures that the messages negotiated are the same ones the server signs.
    ///
    /// 用于完整性检查的握手记录的运行哈希。
    /// 这确保了协商的消息与服务器签名的消息是相同的。
    transcript: Transcript,
    /// The client's ephemeral key agreement engine, if used.
    /// It's kept for the duration of the handshake to compute the shared secret.
    ///
    /// 客户端的临时密钥协商引擎（如果使用）。
    /// 它在握手期间保留，用于计算共享密钥。
    key_agreement_engine: Option<KeyAgreementEngine>,
    /// The server's long-term public key for verifying signatures.
    /// This is a crucial part of authenticating the server.
    ///
    /// 用于验证签名的服务器长期公钥。
    /// 这是验证服务器身份的关键部分。
    server_signature_public_key: Sig::ClientKey,
    /// Derived key for encryption (client-to-server).
    /// Available only in the `Established` state.
    ///
    /// 用于加密（客户端到服务器）的派生密钥。
    /// 仅在 `Established` 状态下可用。
    encryption_key: Option<TypedAeadKey>,
    /// Derived key for decryption (server-to-client).
    /// Available only in the `Established` state.
    ///
    /// 用于解密（服务器到客户端）的派生密钥。
    /// 仅在 `Established` 状态下可用。
    decryption_key: Option<TypedAeadKey>,
    /// The master secret for this session, used for session resumption.
    ///
    /// 当前会话的主密钥，用于会话恢复。
    established_master_secret: Option<SharedSecret>,
    /// The new session ticket received from the server for the next session.
    ///
    /// 从服务器收到的用于下一次会话的新会话票据。
    new_session_ticket: Option<Vec<u8>>,

    // --- Data for starting a new handshake with resumption ---
    /// The master secret from a previous session, used to resume.
    ///
    /// 来自前一个会话的主密钥，用于恢复。
    resumption_master_secret: Option<SharedSecret>,
    /// The ticket from a previous session, sent to the server to resume.
    ///
    /// 来自前一个会话的票据，发送给服务器以进行恢复。
    session_ticket_to_send: Option<Vec<u8>>,
}
