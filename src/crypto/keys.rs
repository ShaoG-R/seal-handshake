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

use crate::crypto::suite::{KeyAgreementPresence, ProtocolSuite, SignaturePresence};
use crate::error::Result;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::*;
use seal_flow::crypto::traits::AeadAlgorithmTrait;

/// Holds the derived keys and the master secret for an established session.
///
/// 保存已建立会话的派生密钥和主密钥。
pub struct SessionKeysAndMaster {
    pub encryption_key: TypedAeadKey,
    pub decryption_key: TypedAeadKey,
    pub master_secret: SharedSecret,
}

/// Derives session keys and a master secret.
///
/// It combines the current handshake's secret with an optional resumption secret
/// to generate a new master secret, which is then used to derive session keys.
///
/// 派生会话密钥和主密钥。
///
/// 它将当前握手的密钥与一个可选的恢复密钥结合起来
/// 以生成一个新的主密钥，然后用该主密钥派生会话密钥。
pub fn derive_session_keys<S: SignaturePresence, K: KeyAgreementPresence>(
    suite: &ProtocolSuite<S, K>,
    kem_secret: SharedSecret,
    agreement_secret: Option<SharedSecret>,
    resumption_master_secret: Option<SharedSecret>,
    is_client: bool,
) -> Result<SessionKeysAndMaster> {
    // 1. Combine secrets for this handshake: [agreement_secret || kem_secret]
    // 1. 合并本次握手的密钥：[协商密钥 || KEM密钥]
    let handshake_secret = if let Some(agreement_secret) = agreement_secret {
        let mut combined = agreement_secret;
        combined.extend_from_slice(kem_secret.as_ref());
        combined
    } else {
        kem_secret
    };

    // 2. Create the input for the KDF to derive the new master secret.
    //    If resuming, combine the old master secret with the new handshake secret.
    //    [resumption_master_secret || handshake_secret]
    //
    // 2. 创建用于派生新主密钥的 KDF 输入。
    //    如果正在恢复会话，将旧的主密钥与新的握手密钥结合。
    //    [恢复主密钥 || 握手密钥]
    let master_kdf_input = if let Some(resumption_secret) = resumption_master_secret {
        let mut combined = resumption_secret;
        combined.extend_from_slice(&handshake_secret);
        SharedSecret::from(combined)
    } else {
        handshake_secret
    };

    let kdf = suite.kdf();
    let aead_algo = suite.aead().algorithm();
    let salt = Some(b"seal-handshake-salt".as_ref());

    // 3. Derive the new master secret.
    // 3. 派生新的主密钥。
    let raw_master_secret = kdf.derive(
        &master_kdf_input,
        salt,
        Some(b"seal-handshake-master"), // "master" context
        32,                             // Assuming a 32-byte master secret length
    )?;
    let master_secret = SharedSecret(raw_master_secret);

    // 4. Derive client-to-server key from the new master secret.
    // 4. 从新的主密钥派生客户端到服务器的密钥。
    let c2s_key = master_secret.derive_key(
        kdf.algorithm(),
        salt,
        Some(b"seal-handshake-c2s"), // "c2s" context
        aead_algo,
    )?;

    // 5. Derive server-to-client key from the new master secret.
    // 5. 从新的主密钥派生服务器到客户端的密钥。
    let s2c_key = master_secret.derive_key(
        kdf.algorithm(),
        salt,
        Some(b"seal-handshake-s2c"), // "s2c" context
        aead_algo,
    )?;

    // 6. Assign encryption/decryption keys based on the role.
    // 6. 根据角色分配加密/解密密钥。
    if is_client {
        Ok(SessionKeysAndMaster {
            encryption_key: c2s_key,
            decryption_key: s2c_key,
            master_secret,
        })
    } else {
        Ok(SessionKeysAndMaster {
            encryption_key: s2c_key,
            decryption_key: c2s_key,
            master_secret,
        })
    }
}
