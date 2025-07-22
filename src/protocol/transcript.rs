//! Manages the hashing of the handshake transcript.
//!
//! This struct centralizes the logic for updating and finalizing the transcript hash,
//! ensuring consistency between the client and server.
//!
//! 管理握手记录的哈希计算。
//!
//! 此结构体集中了更新和最终确定握手记录哈希的逻辑，
//! 确保了客户端和服务器之间的一致性。
use crate::protocol::message::HandshakeMessage;
use seal_flow::crypto::bincode;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    /// Creates a new, empty transcript.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Updates the transcript with a handshake message.
    ///
    /// The message is serialized to bytes before being added to the hash.
    ///
    /// 使用握手消息更新握手记录。
    ///
    /// 在添加到哈希之前，消息被序列化为字节。
    pub fn update(&mut self, message: &HandshakeMessage) {
        // Serialization can't fail with standard bincode config, so unwrap is safe.
        // 使用标准的 bincode 配置，序列化不会失败，因此 unwrap 是安全的。
        let bytes = bincode::encode_to_vec(message, bincode::config::standard()).unwrap();
        self.hasher.update(&bytes);
    }

    /// Returns the current hash state for operations like signing,
    /// without consuming the transcript.
    ///
    /// 返回当前的哈希状态用于签名等操作，而不会消耗握手记录。
    pub fn current_hash(&self) -> Vec<u8> {
        self.hasher.clone().finalize().to_vec()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
