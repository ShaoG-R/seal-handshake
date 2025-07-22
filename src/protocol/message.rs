use crate::bincode;
use seal_flow::common::header::{AeadParams, SealFlowHeader};
use seal_flow::crypto::algorithms::asymmetric::kem::KemAlgorithm;
use seal_flow::crypto::algorithms::asymmetric::signature::SignatureAlgorithm;
use seal_flow::crypto::algorithms::kdf::key::KdfKeyAlgorithm;
use seal_flow::crypto::keys::asymmetric::kem::SharedSecret;
use seal_flow::crypto::prelude::{
    EncapsulatedKey, TypedAsymmetricKeyTrait, TypedKemPublicKey, 
    TypedSignaturePublicKey,
};
use seal_flow::crypto::traits::SignatureAlgorithmTrait;
use seal_flow::crypto::wrappers::asymmetric::signature::SignatureWrapper;
use serde::{Deserialize, Serialize};

use crate::crypto::suite::{KeyAgreementPresence, SignaturePresence};

/// A session ticket used for resumption. It contains the master secret
/// and an expiration timestamp, all encrypted by the server.
///
/// 用于会话恢复的会话票据。它包含主密钥和过期时间戳，
/// 全部由服务器加密。
#[derive(Serialize, Deserialize, Debug, Clone, bincode::Encode, bincode::Decode)]
#[bincode(crate = "bincode")]
pub struct SessionTicket {
    pub master_secret: SharedSecret,
    pub expiry_timestamp: u64,
}

/// Client -> Server: Initiates handshake.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct ClientHelloPayload<K: KeyAgreementPresence> {
    #[bincode(with_serde)]
    pub key_agreement_public_key: K::MessagePublicKey,
    pub session_ticket: Option<Vec<u8>>,
    pub kem_algorithm: KemAlgorithm,
}

/// Server -> Client: Provides the server's public key and supported algorithms.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct ServerHelloPayload<S: SignaturePresence, K: KeyAgreementPresence> {
    pub kem_public_key: TypedKemPublicKey,
    #[bincode(with_serde)]
    pub key_agreement_public_key: K::MessagePublicKey,
    /// The signature of the server's ephemeral public keys (KEM and KeyAgreement),
    /// signed by its long-term identity key.
    #[bincode(with_serde)]
    pub signature: S::MessageSignature,
}

/// Client -> Server: Contains the KEM encapsulated key and an encrypted payload.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct ClientKeyExchangePayload {
    pub encrypted_message: Vec<u8>,
    pub encapsulated_key: EncapsulatedKey,
}

/// Server -> Client: An encrypted response message.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct ServerFinishedPayload {
    pub encrypted_message: Vec<u8>,
}

/// Server -> Client: A new session ticket for the client to use in future handshakes.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct NewSessionTicketPayload {
    /// The encrypted and authenticated session ticket.
    pub ticket: Vec<u8>,
}

/// Defines the messages exchanged during the handshake protocol.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub enum HandshakeMessage<S: SignaturePresence, K: KeyAgreementPresence>
where
    S: SignaturePresence,
    K: KeyAgreementPresence,
{
    /// Client -> Server: Initiates handshake.
    ClientHello(ClientHelloPayload<K>),
    /// Server -> Client: Provides the server's public key and supported algorithms.
    ServerHello(ServerHelloPayload<S, K>),
    /// Client -> Server: Contains the KEM encapsulated key and an encrypted payload.
    ClientKeyExchange(ClientKeyExchangePayload),
    /// Server -> Client: An encrypted response message.
    ServerFinished(ServerFinishedPayload),
    /// Server -> Client: A new session ticket for the client to use in future handshakes.
    NewSessionTicket(NewSessionTicketPayload),
}

/// A custom header for `seal-flow` that includes the KEM-specific information
/// needed for the recipient to derive the symmetric key.
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
#[bincode(crate = "bincode")]
pub struct EncryptedHeader {
    pub params: AeadParams,
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

    /// Verifies the handshake transcript signature within the header.
    ///
    /// This check is performed automatically during decryption if a `verify_key` is provided.
    /// It ensures the integrity of the entire handshake process.
    fn verify_signature<'a>(
        &self,
        verify_key: Option<&'a TypedSignaturePublicKey>,
    ) -> seal_flow::Result<()> {
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
                    return Err(seal_flow::Error::Format(
                        seal_flow::error::FormatError::InvalidAlgorithm,
                    ));
                }

                let verifier = sig_algo.into_wrapper();
                verifier.verify(hash, public_key, signature).map_err(|_| {
                    seal_flow::Error::Format(seal_flow::error::FormatError::InvalidSignature)
                })
            }
            // Case 2: No signature was provided in the header. This is valid; we do nothing.
            (None, None, None, _) => Ok(()),
            // Case 3: The header is malformed (e.g., signature present but hash or algo missing).
            // This indicates a protocol violation or a bug.
            _ => Err(seal_flow::Error::Format(
                seal_flow::error::FormatError::InvalidMessage,
            )),
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
