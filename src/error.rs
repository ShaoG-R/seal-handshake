use crate::bincode;
use thiserror::Error;

/// An error related to `bincode` serialization or deserialization.
///
/// This is a wrapper around `bincode`'s own error types to provide a more
/// consistent error handling experience within this crate.
///
/// 与 `bincode` 序列化或反序列化相关的错误。
///
/// 这是对 `bincode` 自身错误类型的包装，以便在此 crate 中提供更一致的错误处理体验。
#[derive(Error, Debug)]
pub enum BincodeError {
    /// An error occurred during serialization (encoding).
    ///
    /// 在序列化（编码）过程中发生错误。
    #[error("Encode error: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),
    /// An error occurred during deserialization (decoding).
    ///
    /// 在反序列化（解码）过程中发生错误。
    #[error("Decode error: {0}")]
    Dec(#[source] Box<bincode::error::DecodeError>),
}

impl From<bincode::error::EncodeError> for BincodeError {
    fn from(err: bincode::error::EncodeError) -> Self {
        BincodeError::Enc(Box::from(err))
    }
}

impl From<bincode::error::DecodeError> for BincodeError {
    fn from(err: bincode::error::DecodeError) -> Self {
        BincodeError::Dec(Box::from(err))
    }
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("cryptographic operation failed: {0}")]
    FlowError(#[from] seal_flow::error::Error),

    #[error("serialization or deserialization failed: {0}")]
    SerializationError(#[from] BincodeError),

    #[error("invalid state for the requested operation")]
    InvalidState,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("received an unexpected or invalid message for the current state")]
    InvalidMessage,

    #[error("invalid kem algorithm")]
    InvalidKemAlgorithm,

    #[error("the server did not provide a public key for key agreement when it was required")]
    MissingKeyAgreementPublicKey,

    #[error("a required cryptographic component was not configured in the protocol suite")]
    ComponentMissing,

    #[error("an error occurred during the signing process")]
    SigningError,

    #[error("builder is missing required field: {0}")]
    BuilderMissingField(&'static str),
}

impl From<seal_flow::crypto::error::Error> for HandshakeError {
    fn from(err: seal_flow::crypto::error::Error) -> Self {
        HandshakeError::FlowError(err.into())
    }
}

impl From<bincode::error::EncodeError> for HandshakeError {
    fn from(err: bincode::error::EncodeError) -> Self {
        HandshakeError::SerializationError(err.into())
    }
}

impl From<bincode::error::DecodeError> for HandshakeError {
    fn from(err: bincode::error::DecodeError) -> Self {
        HandshakeError::SerializationError(err.into())
    }
}
pub type Result<T> = std::result::Result<T, HandshakeError>;
