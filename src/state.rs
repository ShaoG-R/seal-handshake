//! Defines the various states of the handshake protocol state machine.
//!
//! These are typically zero-sized types (marker structs) used to enforce
//! the protocol flow at compile time. Each state represents a specific point
//! in the handshake process, and only valid transitions are exposed in the API.

/// The initial state of a handshake, client or server.
///
/// In this state, the handshake can be initiated.
///
/// 握手前的初始状态。
///
/// 在此状态下，可以发起握手。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready;

/// A client state indicating that it has sent a public key request
/// and is now awaiting the server's public key.
///
/// 客户端状态，表示已发送公钥请求，正在等待服务端的公钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwaitingKemPublicKey;

/// A client state indicating that it has initiated a key agreement
/// by sending its public key and is awaiting the server's response.
///
/// 客户端状态，表示已通过发送其公钥来发起密钥协商，并正在等待服务端的响应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwaitingKeyAgreementResponse;

/// The final state of a successful handshake.
///
/// In this state, both parties have a shared secret and can
/// securely exchange encrypted application data.
///
/// 成功握手的最终状态。
///
/// 在此状态下，双方拥有共享密钥，可以安全地交换加密的应用数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Established;
