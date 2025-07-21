//! Integration test for the complete handshake protocol.
//! 对完整握手协议的集成测试。

use seal_handshake::client::HandshakeClientBuilder;
use seal_handshake::error::Result;
use seal_handshake::server::HandshakeServerBuilder;
use seal_flow::crypto::algorithms::{
    asymmetric::{kem::KemAlgorithm, signature::SignatureAlgorithm},
    kdf::key::KdfKeyAlgorithm,
    symmetric::SymmetricAlgorithm,
};
use seal_flow::crypto::traits::SignatureAlgorithmTrait;
use seal_handshake::message::HandshakeMessage;

#[test]
fn test_full_handshake_and_data_exchange() -> Result<()> {
    // --- 1. Setup: Ciphersuites and Keys ---
    // --- 1. 设置：密码套件和密钥 ---

    println!("--- Setting up ciphersuites and keys ---");

    // Define the cryptographic algorithms for the protocol suite.
    // 为协议套件定义加密算法。
    let kem = KemAlgorithm::build().kyber1024();
    let signature_algorithm = SignatureAlgorithm::build().dilithium5();
    let aead = SymmetricAlgorithm::build().aes256_gcm();
    let kdf = KdfKeyAlgorithm::build().hkdf_sha256();

    // Generate the server's long-term identity key pair.
    // The client needs to know and trust this public key.
    // 生成服务器的长期身份密钥对。
    // 客户端需要知道并信任这个公钥。
    let server_identity_key_pair = signature_algorithm
        .into_signature_wrapper()
        .generate_keypair()?;
    let server_identity_public_key = server_identity_key_pair.public_key().clone();

    // --- 2. Server and Client Initialization ---
    // --- 2. 服务器和客户端初始化 ---

    println!("--- Initializing server and client ---");

    // Build the server with its cryptographic suite and long-term key.
    // 使用其密码套件和长期密钥构建服务器。
    let server_builder = HandshakeServerBuilder::new()
        .with_kem(kem.into_asymmetric_wrapper())
        .with_aead(aead.into_symmetric_wrapper())
        .with_kdf(kdf.into_kdf_key_wrapper())
        .with_signature(signature_algorithm.into_signature_wrapper())
        .with_signature_key_pair(server_identity_key_pair);

    // Build the client with the same suite and the server's trusted public key.
    // 使用相同的套件和服务器的受信任公钥构建客户端。
    let client = HandshakeClientBuilder::new()
        .with_kem(kem.into_asymmetric_wrapper())
        .with_aead(aead.into_symmetric_wrapper())
        .with_kdf(kdf.into_kdf_key_wrapper())
        .with_signature(signature_algorithm.into_signature_wrapper())
        .with_server_signature_public_key(server_identity_public_key)
        .build();

    // --- 3. Handshake ---
    // --- 3. 握手 ---

    println!("--- Starting handshake ---");

    // C -> S: ClientHello
    let (client_hello, client) = client.start_handshake();
    println!("C -> S: ClientHello");

    // S: Process ClientHello, create ServerHello
    let server = server_builder.build();
    let (server_hello, server) = server.process_client_hello(
        client_hello,
    )?;
    println!("S -> C: ServerHello (with signature)");

    // C: Process ServerHello, create ClientKeyExchange
    let initial_payload = b"client's initial data";
    let aad = b"handshake aad";
    let (client_key_exchange, client) =
        client.process_server_hello(server_hello, Some(initial_payload), Some(aad))?;
    println!("C -> S: ClientKeyExchange (with encrypted initial payload)");

    // S: Process ClientKeyExchange, establish session
    let (decrypted_payload, server) =
        server.process_client_key_exchange(client_key_exchange, aad)?;
    println!("S: Decrypted initial payload: '{}'", String::from_utf8_lossy(&decrypted_payload));

    // Verify the initial payload was correctly received.
    // 验证初始负载是否已正确接收。
    assert_eq!(initial_payload, decrypted_payload.as_slice());
    println!("--- Handshake successful, session established ---");

    // --- 4. Post-Handshake Data Exchange ---
    // --- 4. 握手后数据交换 ---

    println!("--- Testing post-handshake data exchange ---");

    // C -> S: Encrypt and send application data
    let client_message = b"some application data from client";
    let client_ciphertext = client.encrypt(client_message, aad)?;
    println!("C -> S: Sending encrypted message");

    // S: Decrypt application data
    let decrypted_client_message = server.decrypt(&client_ciphertext, aad)?;
    println!("S: Decrypted message: '{}'", String::from_utf8_lossy(&decrypted_client_message));
    assert_eq!(client_message, decrypted_client_message.as_slice());

    // S -> C: Encrypt and send application data
    let server_message = b"a response from the server";
    let server_ciphertext = server.encrypt(server_message, aad)?;
    println!("S -> C: Sending encrypted response");

    // C: Decrypt application data
    let server_finished_message = HandshakeMessage::ServerFinished {
        encrypted_message: server_ciphertext,
    };
    let decrypted_server_message = client.decrypt(server_finished_message, Some(aad))?;
    println!(
        "C: Decrypted response: '{}'",
        String::from_utf8_lossy(&decrypted_server_message)
    );
    assert_eq!(server_message, decrypted_server_message.as_slice());

    println!("--- Data exchange successful ---");

    Ok(())
} 