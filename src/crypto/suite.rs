use seal_flow::crypto::{
    algorithms::{asymmetric::{kem::KemAlgorithm, key_agreement::KeyAgreementAlgorithm, signature::SignatureAlgorithm}, kdf::key::KdfKeyAlgorithm}, keys::asymmetric::{
        kem::SharedSecret,
        key_agreement::{TypedKeyAgreementKeyPair, TypedKeyAgreementPublicKey},
        signature::{TypedSignatureKeyPair, TypedSignaturePublicKey},
    }, prelude::AeadAlgorithm, wrappers::{
        aead::AeadAlgorithmWrapper,
        asymmetric::{
            kem::KemAlgorithmWrapper, key_agreement::KeyAgreementAlgorithmWrapper,
        },
        kdf::key::KdfKeyWrapper,
    }
};
use std::marker::PhantomData;

/// A helper struct to carry the key agreement key pair during the handshake.
#[derive(Debug)]
pub struct KeyAgreementEngine {
    key_pair: TypedKeyAgreementKeyPair,
    wrapper: KeyAgreementAlgorithmWrapper,
}

impl KeyAgreementEngine {
    /// 为客户端创建一个新的引擎，生成一个临时的密钥对。
    pub fn new_for_client(
        wrapper: Option<&KeyAgreementAlgorithmWrapper>,
    ) -> crate::error::Result<Option<Self>> {
        if let Some(wrapper) = wrapper {
            let key_pair = wrapper.generate_keypair()?;
            Ok(Some(Self {
                key_pair,
                wrapper: wrapper.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    /// 为服务器创建一个新的引擎，生成一个临时的密钥对，
    /// 并与客户端的公钥计算共享密钥。
    pub fn new_for_server(
        wrapper: Option<&KeyAgreementAlgorithmWrapper>,
        client_pk: Option<&TypedKeyAgreementPublicKey>,
    ) -> crate::error::Result<Option<(Self, SharedSecret)>> {
        if let (Some(wrapper), Some(client_pk)) = (wrapper, client_pk) {
            let key_pair = wrapper.generate_keypair()?;
            let shared_secret = wrapper.agree(&key_pair.private_key(), client_pk)?;
            let engine = Self {
                key_pair,
                wrapper: wrapper.clone(),
            };
            Ok(Some((engine, SharedSecret(shared_secret.into()))))
        } else {
            Ok(None)
        }
    }

    /// 使用此引擎的私钥和对方的公钥计算共享密钥。
    pub fn agree(
        &self,
        other_party_pk: Option<&TypedKeyAgreementPublicKey>,
    ) -> crate::error::Result<Option<SharedSecret>> {
        if let Some(other_party_pk) = other_party_pk {
            self.wrapper
                .agree(&self.key_pair.private_key(), other_party_pk)
                .map(|s| Some(SharedSecret(s.into())))
                .map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    pub fn public_key(&self) -> &TypedKeyAgreementPublicKey {
        self.key_pair.public_key()
    }
}

// --- Signature Presence Marker ---

/// A trait to mark whether a signature scheme is included in the protocol suite.
/// This allows for compile-time checks for required keys.
///
/// 一个 trait，用于标记协议套件中是否包含签名方案。
/// 这允许对所需的密钥进行编译时检查。
pub trait SignaturePresence: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The type of key the server needs for this configuration (key pair or nothing).
    /// 服务器在此配置下需要的密钥类型（密钥对或无）。
    type ServerKey;
    /// The type of key the client needs for this configuration (public key or nothing).
    /// 客户端在此配置下需要的密钥类型（公钥或无）。
    type ClientKey;
}

/// Marker struct for when a signature algorithm is present.
///
/// 当签名算法存在时的标记结构体。
#[derive(Debug, Clone)]
pub struct WithSignature(pub SignatureAlgorithm);

impl SignaturePresence for WithSignature {
    type ServerKey = TypedSignatureKeyPair;
    type ClientKey = TypedSignaturePublicKey;
}

/// Marker struct for when no signature algorithm is used.
///
/// 当不使用签名算法时的标记结构体。
#[derive(Debug, Clone)]
pub struct WithoutSignature;

impl SignaturePresence for WithoutSignature {
    type ServerKey = ();
    type ClientKey = ();
}

// --- Final ProtocolSuite ---
#[derive(Debug, Clone)]
pub struct ProtocolSuite<S: SignaturePresence> {
    kem: KemAlgorithm,
    key_agreement: Option<KeyAgreementAlgorithm>,
    signature: S,
    aead: AeadAlgorithm,
    kdf: KdfKeyAlgorithm,
}

impl<S: SignaturePresence> ProtocolSuite<S> {
    pub fn kem(&self) -> KemAlgorithm {
        self.kem
    }

    pub fn kem_wrapper(&self) -> KemAlgorithmWrapper {
        self.kem.into_wrapper()
    }

    pub fn key_agreement(&self) -> Option<KeyAgreementAlgorithm> {
        self.key_agreement
    }

    pub fn key_agreement_wrapper(&self) -> Option<KeyAgreementAlgorithmWrapper> {
        self.key_agreement.as_ref().map(|a| a.into_wrapper())
    }

    pub fn aead(&self) -> AeadAlgorithm {
        self.aead
    }

    pub fn aead_wrapper(&self) -> AeadAlgorithmWrapper {
        self.aead.into_wrapper()
    }

    pub fn kdf(&self) -> KdfKeyAlgorithm {
        self.kdf
    }

    pub fn kdf_wrapper(&self) -> KdfKeyWrapper {
        self.kdf.into_wrapper()
    }
}

impl ProtocolSuite<WithSignature> {
    pub fn signature(&self) -> SignatureAlgorithm {
        self.signature.0
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

    /// Sets the KEM and optional key agreement algorithm, moving to the next state.
    pub fn with_kem(
        self,
        kem: KemAlgorithm,
        key_agreement: Option<KeyAgreementAlgorithm>,
    ) -> BuilderWithKem {
        BuilderWithKem { kem, key_agreement }
    }
}

/// State after KEM configuration is set. Requires Signature.
pub struct BuilderWithKem {
    kem: KemAlgorithm,
    key_agreement: Option<KeyAgreementAlgorithm>,
}

impl BuilderWithKem {
    /// Configures the suite with a signature algorithm.
    pub fn with_signature(
        self,
        signature: SignatureAlgorithm,
    ) -> BuilderWithAlgorithms<WithSignature> {
        BuilderWithAlgorithms {
            kem: self.kem,
            signature: WithSignature(signature),
            key_agreement: self.key_agreement,
        }
    }

    /// Configures the suite without a signature algorithm.
    pub fn without_signature(self) -> BuilderWithAlgorithms<WithoutSignature> {
        BuilderWithAlgorithms {
            kem: self.kem,
            signature: WithoutSignature,
            key_agreement: self.key_agreement,
        }
    }
}

/// State after asymmetric algorithms are set. Requires AEAD.
pub struct BuilderWithAlgorithms<S: SignaturePresence> {
    kem: KemAlgorithm,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithm>,
}

impl<S: SignaturePresence> BuilderWithAlgorithms<S> {
    /// Sets the AEAD algorithm and moves to the next state.
    pub fn with_aead(self, aead: AeadAlgorithm) -> BuilderWithAead<S> {
        BuilderWithAead {
            kem: self.kem,
            signature: self.signature,
            key_agreement: self.key_agreement,
            aead,
        }
    }
}

/// State after AEAD is set. Requires KDF.
pub struct BuilderWithAead<S: SignaturePresence> {
    kem: KemAlgorithm,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithm>,
    aead: AeadAlgorithm,
}

impl<S: SignaturePresence> BuilderWithAead<S> {
    /// Sets the KDF algorithm and moves to the final, buildable state.
    pub fn with_kdf(self, kdf: KdfKeyAlgorithm) -> ReadyToBuild<S> {
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
pub struct ReadyToBuild<S: SignaturePresence> {
    kem: KemAlgorithm,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithm>,
    aead: AeadAlgorithm,
    kdf: KdfKeyAlgorithm,
    _phantom: PhantomData<S>,
}

impl<S: SignaturePresence> ReadyToBuild<S> {
    /// Builds the `ProtocolSuite`.
    pub fn build(self) -> ProtocolSuite<S> {
        ProtocolSuite {
            kem: self.kem,
            key_agreement: self.key_agreement,
            signature: self.signature,
            aead: self.aead,
            kdf: self.kdf,
        }
    }
}
