use crate::bincode;
use seal_flow::crypto::{
    algorithms::asymmetric::{key_agreement::KeyAgreementAlgorithm, signature::SignatureAlgorithm}, keys::asymmetric::{
        kem::SharedSecret,
        key_agreement::{TypedKeyAgreementKeyPair, TypedKeyAgreementPublicKey},
        signature::{TypedSignatureKeyPair, TypedSignaturePublicKey},
    }, wrappers::{
        aead::AeadAlgorithmWrapper,
        asymmetric::{
            kem::KemAlgorithmWrapper, key_agreement::KeyAgreementAlgorithmWrapper,
            signature::SignatureAlgorithmWrapper,
        },
        kdf::key::KdfKeyWrapper,
    }
};
use seal_flow::crypto::wrappers::asymmetric::signature::SignatureWrapper;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// A helper struct to carry the key agreement key pair during the handshake.
#[derive(Debug)]
pub struct KeyAgreementEngine {
    key_pair: TypedKeyAgreementKeyPair,
    wrapper: KeyAgreementAlgorithmWrapper,
}

impl KeyAgreementEngine {
    /// 为客户端创建一个新的引擎，生成一个临时的密钥对。
    pub fn new_for_client(wrapper: &KeyAgreementAlgorithmWrapper) -> crate::error::Result<Self> {
        let key_pair = wrapper.generate_keypair()?;
        Ok(Self {
            key_pair,
            wrapper: wrapper.clone(),
        })
    }

    /// 为服务器创建一个新的引擎，生成一个临时的密钥对，
    /// 并与客户端的公钥计算共享密钥。
    pub fn new_for_server(
        wrapper: &KeyAgreementAlgorithmWrapper,
        client_pk: &TypedKeyAgreementPublicKey,
    ) -> crate::error::Result<(Self, SharedSecret)> {
        let key_pair = wrapper.generate_keypair()?;
        let shared_secret = wrapper.agree(&key_pair.private_key(), client_pk)?;
        let engine = Self {
            key_pair,
            wrapper: wrapper.clone(),
        };
        Ok((engine, SharedSecret(shared_secret.into())))
    }

    /// 使用此引擎的私钥和对方的公钥计算共享密钥。
    pub fn agree(
        &self,
        other_party_pk: &TypedKeyAgreementPublicKey,
    ) -> crate::error::Result<SharedSecret> {
        self.wrapper
            .agree(&self.key_pair.private_key(), other_party_pk)
            .map(|s| SharedSecret(s.into()))
            .map_err(Into::into)
    }

    pub fn public_key(&self) -> &TypedKeyAgreementPublicKey {
        self.key_pair.public_key()
    }

    pub fn key_pair(&self) -> &TypedKeyAgreementKeyPair {
        &self.key_pair
    }
}

// --- Signature Presence Marker ---

/// A trait to mark whether a signature scheme is included in the protocol suite.
/// This allows for compile-time checks for required keys.
///
/// 一个 trait，用于标记协议套件中是否包含签名方案。
/// 这允许对所需的密钥进行编译时检查。
pub trait SignaturePresence:
    std::fmt::Debug + Clone + Send + Sync + 'static + bincode::Encode + bincode::Decode<()>
{
    /// The type of key the server needs for this configuration (key pair or nothing).
    /// 服务器在此配置下需要的密钥类型（密钥对或无）。
    type ServerKey;
    /// The type of key the client needs for this configuration (public key or nothing).
    /// 客户端在此配置下需要的密钥类型（公钥或无）。
    type ClientKey;
    /// The signature type used in the `ServerHello` message.
    /// `ServerHello` 消息中使用的签名类型。
    type MessageSignature: Serialize
        + for<'a> Deserialize<'a>
        + std::fmt::Debug
        + Clone
        + Send
        + Sync
        + 'static
        + bincode::Encode
        + bincode::Decode<()>;
}

/// Marker struct for when a signature algorithm is present.
///
/// 当签名算法存在时的标记结构体。
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct WithSignature(pub SignatureAlgorithm);

impl SignaturePresence for WithSignature {
    type ServerKey = TypedSignatureKeyPair;
    type ClientKey = TypedSignaturePublicKey;
    type MessageSignature = SignatureWrapper;
}

/// Marker struct for when no signature algorithm is used.
///
/// 当不使用签名算法时的标记结构体。
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct WithoutSignature;

impl SignaturePresence for WithoutSignature {
    type ServerKey = ();
    type ClientKey = ();
    type MessageSignature = ();
}

// --- Key Agreement Presence Marker ---
/// A trait to mark whether a key agreement scheme is included in the protocol suite.
/// This allows for compile-time checks.
///
/// 一个 trait，用于标记协议套件中是否包含密钥协商方案。
/// 这允许进行编译时检查。
pub trait KeyAgreementPresence:
    std::fmt::Debug + Clone + Send + Sync + 'static + bincode::Encode + bincode::Decode<()>
{
    /// The public key type used in `ClientHello` and `ServerHello`.
    /// `ClientHello` 和 `ServerHello` 中使用的公钥类型。
    type MessagePublicKey: Serialize
        + for<'a> Deserialize<'a>
        + std::fmt::Debug
        + Clone
        + Send
        + Sync
        + 'static
        + bincode::Encode
        + bincode::Decode<()>;
}

/// Marker struct for when a key agreement algorithm is present.
///
/// 当存在密钥协商算法时的标记结构体。
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct WithKeyAgreement(pub KeyAgreementAlgorithm);

impl KeyAgreementPresence for WithKeyAgreement {
    type MessagePublicKey = TypedKeyAgreementPublicKey;
}

/// Marker struct for when no key agreement algorithm is used.
///
/// 当不使用密钥协商算法时的标记结构体。
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct WithoutKeyAgreement;

impl KeyAgreementPresence for WithoutKeyAgreement {
    type MessagePublicKey = ();
}

// --- Final ProtocolSuite ---
#[derive(Debug, Clone)]
pub struct ProtocolSuite<S: SignaturePresence, K: KeyAgreementPresence> {
    kem: KemAlgorithmWrapper,
    key_agreement: K,
    signature: S,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
}

impl<S: SignaturePresence, K: KeyAgreementPresence> ProtocolSuite<S, K> {
    pub fn kem(&self) -> &KemAlgorithmWrapper {
        &self.kem
    }

    pub fn aead(&self) -> &AeadAlgorithmWrapper {
        &self.aead
    }

    pub fn kdf(&self) -> &KdfKeyWrapper {
        &self.kdf
    }
}

impl<S: SignaturePresence> ProtocolSuite<S, WithKeyAgreement> {
    pub fn key_agreement(&self) -> KeyAgreementAlgorithmWrapper {
        self.key_agreement.0.into_wrapper()
    }
}

impl<K: KeyAgreementPresence> ProtocolSuite<WithSignature, K> {
    pub fn signature(&self) -> SignatureAlgorithmWrapper {
        self.signature.0.into_wrapper()
    }
}

// --- Typestate Builder using Concrete Structs ---

/// The entry point for the builder.
pub struct ProtocolSuiteBuilder;

impl ProtocolSuiteBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self
    }

    /// Sets the KEM and moves to the key agreement configuration state.
    pub fn with_kem(self, kem: KemAlgorithmWrapper) -> BuilderWithKem {
        BuilderWithKem { kem }
    }
}

/// State after KEM is set. Requires key agreement configuration.
pub struct BuilderWithKem {
    kem: KemAlgorithmWrapper,
}

impl BuilderWithKem {
    /// Configures the suite with a key agreement algorithm.
    pub fn with_key_agreement(
        self,
        key_agreement: KeyAgreementAlgorithmWrapper,
    ) -> BuilderWithKeyAgreement<WithKeyAgreement> {
        BuilderWithKeyAgreement {
            kem: self.kem,
            key_agreement: WithKeyAgreement(key_agreement.algorithm()),
        }
    }

    /// Configures the suite without a key agreement algorithm.
    pub fn without_key_agreement(self) -> BuilderWithKeyAgreement<WithoutKeyAgreement> {
        BuilderWithKeyAgreement {
            kem: self.kem,
            key_agreement: WithoutKeyAgreement,
        }
    }
}

/// State after key agreement is set. Requires signature configuration.
pub struct BuilderWithKeyAgreement<K: KeyAgreementPresence> {
    kem: KemAlgorithmWrapper,
    key_agreement: K,
}

impl<K: KeyAgreementPresence> BuilderWithKeyAgreement<K> {
    /// Configures the suite with a signature algorithm.
    pub fn with_signature(
        self,
        signature: SignatureAlgorithmWrapper,
    ) -> BuilderWithAsymmetric<WithSignature, K> {
        BuilderWithAsymmetric {
            kem: self.kem,
            key_agreement: self.key_agreement,
            signature: WithSignature(signature.algorithm()),
        }
    }

    /// Configures the suite without a signature algorithm.
    pub fn without_signature(self) -> BuilderWithAsymmetric<WithoutSignature, K> {
        BuilderWithAsymmetric {
            kem: self.kem,
            key_agreement: self.key_agreement,
            signature: WithoutSignature,
        }
    }
}

/// State after asymmetric algorithms are set. Requires AEAD.
pub struct BuilderWithAsymmetric<S: SignaturePresence, K: KeyAgreementPresence> {
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: K,
}

impl<S: SignaturePresence, K: KeyAgreementPresence> BuilderWithAsymmetric<S, K> {
    /// Sets the AEAD algorithm and moves to the next state.
    pub fn with_aead(self, aead: AeadAlgorithmWrapper) -> BuilderWithAead<S, K> {
        BuilderWithAead {
            kem: self.kem,
            signature: self.signature,
            key_agreement: self.key_agreement,
            aead,
        }
    }
}

/// State after AEAD is set. Requires KDF.
pub struct BuilderWithAead<S: SignaturePresence, K: KeyAgreementPresence> {
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: K,
    aead: AeadAlgorithmWrapper,
}

impl<S: SignaturePresence, K: KeyAgreementPresence> BuilderWithAead<S, K> {
    /// Sets the KDF algorithm and moves to the final, buildable state.
    pub fn with_kdf(self, kdf: KdfKeyWrapper) -> ReadyToBuild<S, K> {
        ReadyToBuild {
            kem: self.kem,
            signature: self.signature,
            key_agreement: self.key_agreement,
            aead: self.aead,
            kdf,
            _phantom: PhantomData,
        }
    }
}

/// The final state where the builder can construct a `ProtocolSuite`.
pub struct ReadyToBuild<S: SignaturePresence, K: KeyAgreementPresence> {
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: K,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
    _phantom: PhantomData<(S, K)>,
}

impl<S: SignaturePresence, K: KeyAgreementPresence> ReadyToBuild<S, K> {
    /// Builds the `ProtocolSuite`.
    pub fn build(self) -> ProtocolSuite<S, K> {
        ProtocolSuite {
            kem: self.kem,
            key_agreement: self.key_agreement,
            signature: self.signature,
            aead: self.aead,
            kdf: self.kdf,
        }
    }
}
