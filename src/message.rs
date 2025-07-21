use crate::bincode;
use seal_flow::common::header::{SealFlowHeader, SymmetricParams};
use seal_flow::crypto::algorithms::asymmetric::kem::KemAlgorithm;
use seal_flow::crypto::algorithms::kdf::key::KdfKeyAlgorithm;
use seal_flow::crypto::prelude::{EncapsulatedKey, TypedKemPublicKey};
use serde::{Deserialize, Serialize};

/// Defines the messages exchanged during the handshake protocol.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub enum HandshakeMessage {
    /// Client -> Server: Initiates handshake, requesting the server's public key.
    ClientHello,

    /// Server -> Client: Provides the server's public key and supported algorithms.
    ServerHello {
        public_key: TypedKemPublicKey,
        kem_algorithm: KemAlgorithm,
        /// The signature of the server's ephemeral public key, signed by its long-term identity key.
        ///
        /// 服务器临时公钥的签名，由其长期身份密钥签署。
        signature: Vec<u8>,
    },

    /// Client -> Server: Contains the KEM encapsulated key and an encrypted payload.
    /// The payload is a full `seal-flow` encrypted message (header + ciphertext).
    ClientKeyExchange {
        encrypted_message: Vec<u8>,
        encapsulated_key: EncapsulatedKey,
    },

    /// Server -> Client: An encrypted response message.
    /// The payload is a full `seal-flow` encrypted message (header + ciphertext).
    ServerFinished { encrypted_message: Vec<u8> },
}

/// A custom header for `seal-flow` that includes the KEM-specific information
/// needed for the recipient to derive the symmetric key.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct EncryptedHeader {
    pub params: SymmetricParams,
    pub kem_algorithm: KemAlgorithm,
    pub kdf_params: KdfParams,
}

impl SealFlowHeader for EncryptedHeader {
    fn symmetric_params(&self) -> &SymmetricParams {
        &self.params
    }

    fn extra_data(&self) -> Option<&[u8]> {
        None
    }
}

/// Parameters for Key Derivation Function (KDF).
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct KdfParams {
    pub algorithm: KdfKeyAlgorithm,
    pub salt: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
}