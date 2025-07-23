//! Defines the various states of the handshake protocol state machine.
//!
//! These are typically zero-sized types (marker structs) used to enforce
//! the protocol flow at compile time. Each state represents a specific point
//! in the handshake process, and only valid transitions are exposed in the API.

use crate::crypto::suite::KeyAgreementEngine;
use seal_flow::crypto::{
    algorithms::{aead::AeadAlgorithm, kdf::key::KdfKeyAlgorithm},
    keys::asymmetric::kem::{SharedSecret, TypedKemKeyPair},
    prelude::TypedAeadKey,
};

// --- Generic States (Markers) ---
/// The initial state of a handshake, client or server.
#[derive(Debug)]
pub struct Ready;

/// A client state indicating that it is awaiting the server's public key.
#[derive(Debug)]
pub struct AwaitingKemPublicKey;

/// A server state indicating it is waiting for the client's key exchange message.
#[derive(Debug)]
pub struct AwaitingKeyExchange;

/// The final state of a successful handshake.
#[derive(Debug)]
pub struct Established;

// --- Role-Specific State Data ---

// --- Client States ---
/// Data held by the client in the `Ready` state.
#[derive(Debug)]
pub struct ClientReady {
    pub resumption_master_secret: Option<SharedSecret>,
    pub session_ticket_to_send: Option<Vec<u8>>,
}

/// Data held by the client in the `AwaitingKemPublicKey` state.
#[derive(Debug)]
pub struct ClientAwaitingKemPublicKey {
    pub key_agreement_engine: Option<KeyAgreementEngine>,
    pub resumption_master_secret: Option<SharedSecret>,
}

/// Data held by the client in the `Established` state.
#[derive(Debug)]
pub struct ClientEstablished {
    pub encryption_key: TypedAeadKey,
    pub decryption_key: TypedAeadKey,
    pub master_secret: SharedSecret,
    pub new_session_ticket: Option<Vec<u8>>,
}

// --- Server States ---
/// Data held by the server in the `Ready` state.
#[derive(Debug)]
pub struct ServerReady {
    // This state is currently empty for the server, but defined for consistency.
}

/// Data held by the server in the `AwaitingKeyExchange` state.
#[derive(Debug)]
pub struct ServerAwaitingKeyExchange {
    pub kem_key_pair: TypedKemKeyPair,
    pub key_agreement_engine: Option<KeyAgreementEngine>,
    pub agreement_shared_secret: Option<SharedSecret>,
    pub resumption_master_secret: Option<SharedSecret>,
    pub aead_algorithm: AeadAlgorithm,
    pub kdf_algorithm: KdfKeyAlgorithm,
}

/// Data held by the server in the `Established` state.
#[derive(Debug)]
pub struct ServerEstablished {
    pub encryption_key: TypedAeadKey,
    pub decryption_key: TypedAeadKey,
    pub master_secret: SharedSecret,

    
    pub aead_algorithm: AeadAlgorithm,
    pub kdf_algorithm: KdfKeyAlgorithm,
}
