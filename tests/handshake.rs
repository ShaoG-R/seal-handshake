//! Integration test for the complete handshake protocol.
//! 对完整握手协议的集成测试。

use seal_handshake::client::HandshakeClient;
use seal_handshake::error::Result;
use seal_handshake::server::HandshakeServer;
use seal_handshake::crypto::suite::ProtocolSuiteBuilder;
use seal_flow::crypto::algorithms::{
    asymmetric::{kem::KemAlgorithm, signature::SignatureAlgorithm},
    kdf::key::KdfKeyAlgorithm,
    aead::AeadAlgorithm,
};
use seal_flow::crypto::traits::SignatureAlgorithmTrait;
use seal_handshake::protocol::message::HandshakeMessage;

#[test]
fn test_full_handshake_and_data_exchange() -> Result<()> {
    // --- 1. Setup: Ciphersuites and Keys ---
    println!("--- Setting up ciphersuites and keys ---");

    let kem = KemAlgorithm::build().kyber1024();
    let signature_algorithm = SignatureAlgorithm::build().dilithium5();
    let aead = AeadAlgorithm::build().aes256_gcm();
    let kdf = KdfKeyAlgorithm::build().hkdf_sha256();

    let server_identity_key_pair = signature_algorithm
        .into_wrapper()
        .generate_keypair()?;
    let server_identity_public_key = server_identity_key_pair.public_key().clone();

    // --- 2. Protocol Suite Initialization ---
    println!("--- Initializing protocol suite ---");

    let suite = ProtocolSuiteBuilder::new()
        .with_kem(kem.into_wrapper(), None)
        .with_signature(signature_algorithm.into_wrapper())
        .with_aead(aead.into_wrapper())
        .with_kdf(kdf.into_wrapper())
        .build();

    // --- 3. Server and Client Initialization ---
    println!("--- Initializing server and client ---");

    let server = HandshakeServer::builder()
        .suite(suite.clone())
        .signature_key_pair(server_identity_key_pair)
        .build()?;
    let client = HandshakeClient::builder()
        .suite(suite)
        .server_signature_public_key(server_identity_public_key)
        .build()?;

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

#[test]
fn test_kem_only_handshake() -> Result<()> {
    // --- 1. Setup: Ciphersuites ---
    println!("--- Setting up ciphersuites for KEM-only handshake ---");

    let kem = KemAlgorithm::build().kyber1024();
    let aead = AeadAlgorithm::build().aes256_gcm();
    let kdf = KdfKeyAlgorithm::build().hkdf_sha256();

    // --- 2. Protocol Suite Initialization (KEM-only) ---
    println!("--- Initializing KEM-only protocol suite ---");

    let suite = ProtocolSuiteBuilder::new()
        .with_kem(kem.into_wrapper(), None)
        .without_signature()
        .with_aead(aead.into_wrapper())
        .with_kdf(kdf.into_wrapper())
        .build();

    // --- 3. Server and Client Initialization (No Keys) ---
    println!("--- Initializing server and client without signature keys ---");

    let server = HandshakeServer::builder()
        .suite(suite.clone())
        .signature_key_pair(())
        .build()?;
    let client = HandshakeClient::builder()
        .suite(suite)
        .server_signature_public_key(())
        .build()?;

    // --- 4. Handshake ---
    println!("--- Starting KEM-only handshake ---");

    // C -> S: ClientHello
    let (client_hello, client) = client.start_handshake();
    println!("C -> S: ClientHello");

    // S: Process ClientHello, create ServerHello
    let (server_hello, server) = server.process_client_hello(client_hello)?;
    println!("S -> C: ServerHello (without signature)");

    // C: Process ServerHello, create ClientKeyExchange
    let initial_payload = b"client's initial data (KEM-only)";
    let aad = b"kem only handshake aad";
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
    println!("--- KEM-only handshake successful, session established ---");

    // --- 5. Post-Handshake Data Exchange ---
    println!("--- Testing post-handshake data exchange (KEM-only) ---");

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

    println!("--- KEM-only data exchange successful ---");

    Ok(())
}

#[test]
fn test_handshake_with_resumption() -> Result<()> {
    // --- 1. Setup: Ciphersuites, Keys, and a Ticket Encryption Key (TEK) ---
    println!("--- Setting up for handshake with resumption ---");
    let kem = KemAlgorithm::build().kyber1024();
    let signature_algorithm = SignatureAlgorithm::build().dilithium5();
    let aead = AeadAlgorithm::build().aes256_gcm();
    let kdf = KdfKeyAlgorithm::build().hkdf_sha256();

    let server_identity_key_pair = signature_algorithm
        .clone()
        .into_wrapper()
        .generate_keypair()?;
    let server_identity_public_key = server_identity_key_pair.public_key().clone();

    // The server needs a long-term key to encrypt tickets.
    let ticket_encryption_key = aead.clone().into_wrapper().generate_typed_key()?;

    let suite = ProtocolSuiteBuilder::new()
        .with_kem(kem.into_wrapper(), None)
        .with_signature(signature_algorithm.into_wrapper())
        .with_aead(aead.into_wrapper())
        .with_kdf(kdf.into_wrapper())
        .build();

    // --- 2. First Handshake (Full) ---
    println!("--- Performing initial full handshake ---");
    let initial_server = HandshakeServer::builder()
        .suite(suite.clone())
        .signature_key_pair(server_identity_key_pair.clone())
        .ticket_encryption_key(ticket_encryption_key.clone())
        .build()?;
    let initial_client = HandshakeClient::builder()
        .suite(suite.clone())
        .server_signature_public_key(server_identity_public_key.clone())
        .build()?;

    let (client_hello, initial_client) = initial_client.start_handshake();
    let (server_hello, initial_server) = initial_server.process_client_hello(client_hello)?;
    let (key_exchange, mut initial_client) = initial_client.process_server_hello(server_hello, None, None)?;
    let (_, initial_server) = initial_server.process_client_key_exchange(key_exchange, b"")?;

    println!("--- Initial handshake successful ---");

    // --- 3. Server issues a ticket, Client stores it ---
    println!("--- Server issuing session ticket ---");
    let ticket_message = initial_server.issue_session_ticket()?;
    initial_client.process_new_session_ticket(ticket_message)?;

    let master_secret_for_resumption = initial_client.master_secret().cloned().unwrap();
    let ticket_for_resumption = initial_client.session_ticket().cloned().unwrap();
    println!("--- Client stored ticket and master secret for resumption ---");

    // --- 4. Second Handshake (with Resumption) ---
    println!("--- Performing second handshake with resumption data ---");
    let resumption_server = HandshakeServer::builder()
        .suite(suite.clone())
        .signature_key_pair(server_identity_key_pair)
        .ticket_encryption_key(ticket_encryption_key)
        .build()?;
    let resumption_client = HandshakeClient::builder()
        .suite(suite)
        .server_signature_public_key(server_identity_public_key)
        .resumption_data(master_secret_for_resumption, ticket_for_resumption)
        .build()?;

    let (client_hello_resume, resumption_client) = resumption_client.start_handshake();
    let (server_hello_resume, resumption_server) =
        resumption_server.process_client_hello(client_hello_resume)?;
    let (key_exchange_resume, resumption_client) =
        resumption_client.process_server_hello(server_hello_resume, None, None)?;
    let (_, resumption_server) =
        resumption_server.process_client_key_exchange(key_exchange_resume, b"")?;

    println!("--- Resumption handshake successful ---");

    // --- 5. Final Data Exchange Test ---
    let aad = b"resumption test aad";
    let client_message = b"Final test message from client";
    let encrypted = resumption_client.encrypt(client_message, aad)?;
    let decrypted = resumption_server.decrypt(&encrypted, aad)?;
    assert_eq!(client_message, decrypted.as_slice());

    println!("--- Data exchange after resumption successful ---");

    Ok(())
} 