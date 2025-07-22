use seal_flow::crypto::{
    keys::asymmetric::{
        kem::SharedSecret,
        key_agreement::{TypedKeyAgreementKeyPair, TypedKeyAgreementPublicKey},
        signature::{TypedSignatureKeyPair, TypedSignaturePublicKey},
    },
    wrappers::{
        aead::AeadAlgorithmWrapper,
        asymmetric::{
            kem::KemAlgorithmWrapper, key_agreement::KeyAgreementAlgorithmWrapper,
            signature::SignatureAlgorithmWrapper,
        },
        kdf::key::KdfKeyWrapper,
    },
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
pub struct WithSignature(pub SignatureAlgorithmWrapper);

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
    kem: KemAlgorithmWrapper,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    signature: S,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
}

impl<S: SignaturePresence> ProtocolSuite<S> {
    pub fn kem(&self) -> &KemAlgorithmWrapper {
        &self.kem
    }

    pub fn key_agreement(&self) -> &Option<KeyAgreementAlgorithmWrapper> {
        &self.key_agreement
    }

    pub fn aead(&self) -> &AeadAlgorithmWrapper {
        &self.aead
    }

    pub fn kdf(&self) -> &KdfKeyWrapper {
        &self.kdf
    }
}

impl ProtocolSuite<WithSignature> {
    pub fn signature(&self) -> &SignatureAlgorithmWrapper {
        &self.signature.0
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
        kem: KemAlgorithmWrapper,
        key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    ) -> BuilderWithKem {
        BuilderWithKem {
            kem,
            key_agreement,
        }
    }
}

/// State after KEM configuration is set. Requires Signature.
pub struct BuilderWithKem {
    kem: KemAlgorithmWrapper,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
}

impl BuilderWithKem {
    /// Configures the suite with a signature algorithm.
    pub fn with_signature(
        self,
        signature: SignatureAlgorithmWrapper,
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
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
}

impl<S: SignaturePresence> BuilderWithAlgorithms<S> {
    /// Sets the AEAD algorithm and moves to the next state.
    pub fn with_aead(self, aead: AeadAlgorithmWrapper) -> BuilderWithAead<S> {
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
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    aead: AeadAlgorithmWrapper,
}

impl<S: SignaturePresence> BuilderWithAead<S> {
    /// Sets the KDF algorithm and moves to the final, buildable state.
    pub fn with_kdf(self, kdf: KdfKeyWrapper) -> ReadyToBuild<S> {
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
    kem: KemAlgorithmWrapper,
    signature: S,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
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