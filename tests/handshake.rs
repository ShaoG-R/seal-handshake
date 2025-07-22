//! Integration test for the complete handshake protocol.
//! 对完整握手协议的集成测试。

use seal_handshake::client::HandshakeClient;
use seal_handshake::error::Result;
use seal_handshake::server::HandshakeServer;
use seal_handshake::suite::ProtocolSuite;
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
    println!("--- Setting up ciphersuites and keys ---");

    let kem = KemAlgorithm::build().kyber1024();
    let signature_algorithm = SignatureAlgorithm::build().dilithium5();
    let aead = SymmetricAlgorithm::build().aes256_gcm();
    let kdf = KdfKeyAlgorithm::build().hkdf_sha256();

    let server_identity_key_pair = signature_algorithm
        .into_signature_wrapper()
        .generate_keypair()?;
    let server_identity_public_key = server_identity_key_pair.public_key().clone();

    // --- 2. Protocol Suite Initialization ---
    println!("--- Initializing protocol suite ---");

    let suite = ProtocolSuite::builder()
        .with_algorithms(
            kem.into_asymmetric_wrapper(),
            Some(signature_algorithm.into_signature_wrapper()),
            None,
        )
        .with_aead(aead.into_symmetric_wrapper())
        .with_kdf(kdf.into_kdf_key_wrapper())
        .build();

    // --- 3. Server and Client Initialization ---
    println!("--- Initializing server and client ---");

    let server = HandshakeServer::new(suite.clone(), server_identity_key_pair);
    let client = HandshakeClient::new(suite, server_identity_public_key);

    // --- 4. Handshake ---
    println!("--- Starting handshake ---");

    // C -> S: ClientHello
    let (client_hello, client) = client.start_handshake();
    println!("C -> S: ClientHello");

    // S: Process ClientHello, create ServerHello
    let (server_hello, server) = server.process_client_hello(client_hello)?;
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
    println!(
        "S: Decrypted initial payload: '{}'",
        String::from_utf8_lossy(&decrypted_payload)
    );

    assert_eq!(initial_payload, decrypted_payload.as_slice());
    println!("--- Handshake successful, session established ---");

    // --- 5. Post-Handshake Data Exchange ---
    println!("--- Testing post-handshake data exchange ---");

    // C -> S: Encrypt and send application data
    let client_message = b"some application data from client";
    let client_ciphertext = client.encrypt(client_message, aad)?;
    println!("C -> S: Sending encrypted message");

    // S: Decrypt application data
    let decrypted_client_message = server.decrypt(&client_ciphertext, aad)?;
    println!(
        "S: Decrypted message: '{}'",
        String::from_utf8_lossy(&decrypted_client_message)
    );
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