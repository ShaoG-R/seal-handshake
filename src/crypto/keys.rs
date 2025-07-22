//! Manages the derivation of session keys from shared secrets.
//!
//! This module centralizes the key derivation logic (KDF) used by both the client
//! and the server after the initial key exchange is complete. It ensures that both
//! parties derive the same session keys using the same parameters.
//!
//! 管理从共享密钥派生会话密钥的过程。
//!
//! 该模块集中了客户端和服务器在初始密钥交换完成后使用的密钥派生逻辑（KDF）。
//! 它确保双方使用相同的参数派生出相同的会话密钥。

use crate::error::Result;
use crate::crypto::suite::ProtocolSuite;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::AeadAlgorithmTrait;

/// Holds the derived keys for an established session.
///
/// 保存已建立会话的派生密钥。
pub struct SessionKeys {
    pub encryption_key: TypedAeadKey,
    pub decryption_key: TypedAeadKey,
}

/// Derives session keys for either the client or the server.
///
/// This function combines the KEM secret and an optional key agreement secret,
/// then uses the KDF specified in the protocol suite to generate two keys:
/// one for client-to-server communication ("c2s") and one for server-to-client ("s2c").
///
/// The `is_client` flag determines which key is assigned for encryption and which for decryption.
///
/// 为客户端或服务器派生会话密钥。
///
/// 此函数结合了 KEM 密钥和可选的密钥协商密钥，
/// 然后使用协议套件中指定的 KDF 生成两个密钥：
/// 一个用于客户端到服务器的通信（"c2s"），另一个用于服务器到客户端的通信（"s2c"）。
///
/// `is_client` 标志决定了哪个密钥用于加密，哪个用于解密。
pub fn derive_session_keys(
    suite: &ProtocolSuite,
    kem_secret: SharedSecret,
    agreement_secret: Option<SharedSecret>,
    is_client: bool,
) -> Result<SessionKeys> {
    // 1. Combine secrets: [agreement_secret || kem_secret]
    // 1. 合并密钥：[协商密钥 || KEM密钥]
    let final_shared_secret = if let Some(agreement_secret) = agreement_secret {
        let mut combined = agreement_secret.to_vec();
        combined.extend_from_slice(kem_secret.as_ref());
        SharedSecret(combined.into())
    } else {
        kem_secret
    };

    let kdf = suite.kdf();
    let aead_algo = suite.aead().algorithm();
    let salt = Some(b"seal-handshake-salt".as_ref());

    // 2. Derive client-to-server key.
    // 2. 派生客户端到服务器的密钥。
    let c2s_key = final_shared_secret.derive_key(
        kdf.algorithm(),
        salt,
        Some(b"seal-handshake-c2s"), // "c2s" context
        aead_algo,
    )?;

    // 3. Derive server-to-client key.
    // 3. 派生服务器到客户端的密钥。
    let s2c_key = final_shared_secret.derive_key(
        kdf.algorithm(),
        salt,
        Some(b"seal-handshake-s2c"), // "s2c" context
        aead_algo,
    )?;

    // 4. Assign encryption/decryption keys based on the role (client or server).
    // 4. 根据角色（客户端或服务器）分配加密/解密密钥。
    if is_client {
        Ok(SessionKeys {
            encryption_key: c2s_key,
            decryption_key: s2c_key,
        })
    } else {
        Ok(SessionKeys {
            encryption_key: s2c_key,
            decryption_key: c2s_key,
        })
    }
} 