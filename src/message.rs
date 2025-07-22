use crate::bincode;
use seal_flow::common::header::{SealFlowHeader, AeadParams};
use seal_flow::crypto::algorithms::asymmetric::kem::KemAlgorithm;
use seal_flow::crypto::algorithms::asymmetric::signature::SignatureAlgorithm;
use seal_flow::crypto::algorithms::kdf::key::KdfKeyAlgorithm;
use seal_flow::crypto::prelude::{EncapsulatedKey, TypedKemPublicKey, TypedSignaturePublicKey, TypedAsymmetricKeyTrait};
use seal_flow::crypto::traits::SignatureAlgorithmTrait;
use seal_flow::crypto::wrappers::asymmetric::signature::SignatureWrapper;
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
        signature: Option<SignatureWrapper>,
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
    pub params: AeadParams,
    pub kem_algorithm: KemAlgorithm,
    pub kdf_params: KdfParams,

    // --- New fields for handshake integrity ---
    /// The algorithm used for the transcript signature.
    pub signature_algorithm: Option<SignatureAlgorithm>,
    /// The signed hash of the handshake transcript.
    pub signed_transcript_hash: Option<Vec<u8>>,
    /// The signature of the handshake transcript.
    pub transcript_signature: Option<SignatureWrapper>,
}

impl SealFlowHeader for EncryptedHeader {
    fn aead_params(&self) -> &AeadParams {
        &self.params
    }

    fn extra_data(&self) -> Option<&[u8]> {
        None
    }

    /// Verifies the handshake transcript signature within the header.
    ///
    /// This check is performed automatically during decryption if a `verify_key` is provided.
    /// It ensures the integrity of the entire handshake process.
    fn verify_signature<'a>(&self, verify_key: Option<&'a TypedSignaturePublicKey>) -> seal_flow::Result<()> {
        match (
            &self.transcript_signature,
            &self.signed_transcript_hash,
            &self.signature_algorithm,
            verify_key,
        ) {
            // Case 1: All required parts for verification are present.
            (Some(signature), Some(hash), Some(sig_algo), Some(public_key)) => {
                // Ensure the algorithm specified in the header matches the one in the provided key.
                if sig_algo != &public_key.algorithm() {
                    return Err(seal_flow::Error::Format(seal_flow::error::FormatError::InvalidAlgorithm));
                }

                let verifier = sig_algo.into_wrapper();
                verifier
                    .verify(hash, public_key, signature)
                    .map_err(|_| seal_flow::Error::Format(seal_flow::error::FormatError::InvalidSignature))
            }
            // Case 2: No signature was provided in the header. This is valid; we do nothing.
            (None, None, None, _) => Ok(()),
            // Case 3: The header is malformed (e.g., signature present but hash or algo missing).
            // This indicates a protocol violation or a bug.
            _ => Err(seal_flow::Error::Format(seal_flow::error::FormatError::InvalidMessage)),
        }
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