use seal_flow::crypto::{
    keys::asymmetric::kem::SharedSecret, prelude::{TypedKeyAgreementKeyPair, TypedKeyAgreementPublicKey}, wrappers::{
        aead::AeadAlgorithmWrapper,
        asymmetric::{
            kem::KemAlgorithmWrapper, key_agreement::KeyAgreementAlgorithmWrapper, signature::SignatureAlgorithmWrapper
        },
        kdf::key::KdfKeyWrapper,
    }
};

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

// --- Final ProtocolSuite ---
#[derive(Debug, Clone)]
pub struct ProtocolSuite {
    kem: KemAlgorithmWrapper,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    signature: Option<SignatureAlgorithmWrapper>,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
}

impl ProtocolSuite {
    /// Starts building a new ProtocolSuite.
    pub fn builder() -> ProtocolSuiteBuilder {
        ProtocolSuiteBuilder
    }

    pub fn kem(&self) -> &KemAlgorithmWrapper {
        &self.kem
    }

    pub fn key_agreement(&self) -> &Option<KeyAgreementAlgorithmWrapper> {
        &self.key_agreement
    }

    pub fn signature(&self) -> &Option<SignatureAlgorithmWrapper> {
        &self.signature
    }

    pub fn aead(&self) -> &AeadAlgorithmWrapper {
        &self.aead
    }

    pub fn kdf(&self) -> &KdfKeyWrapper {
        &self.kdf
    }
}

// --- Typestate Builder using Concrete Structs ---

/// The entry point for the builder.
pub struct ProtocolSuiteBuilder;

impl ProtocolSuiteBuilder {
    /// Sets the core asymmetric algorithms and moves to the next state.
    pub fn with_algorithms(
        self,
        kem: KemAlgorithmWrapper,
        signature: Option<SignatureAlgorithmWrapper>,
        key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    ) -> BuilderWithAlgorithms {
        BuilderWithAlgorithms {
            kem,
            signature,
            key_agreement,
        }
    }
}

/// State after asymmetric algorithms are set. Requires AEAD.
pub struct BuilderWithAlgorithms {
    kem: KemAlgorithmWrapper,
    signature: Option<SignatureAlgorithmWrapper>,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
}

impl BuilderWithAlgorithms {
    /// Sets the AEAD algorithm and moves to the next state.
    pub fn with_aead(self, aead: AeadAlgorithmWrapper) -> BuilderWithAead {
        BuilderWithAead {
            kem: self.kem,
            signature: self.signature,
            key_agreement: self.key_agreement,
            aead,
        }
    }
}

/// State after AEAD is set. Requires KDF.
pub struct BuilderWithAead {
    kem: KemAlgorithmWrapper,
    signature: Option<SignatureAlgorithmWrapper>,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    aead: AeadAlgorithmWrapper,
}

impl BuilderWithAead {
    /// Sets the KDF algorithm and moves to the final, buildable state.
    pub fn with_kdf(self, kdf: KdfKeyWrapper) -> ReadyToBuild {
        ReadyToBuild {
            kem: self.kem,
            signature: self.signature,
            key_agreement: self.key_agreement,
            aead: self.aead,
            kdf,
        }
    }
}

/// The final state where the builder can construct a `ProtocolSuite`.
pub struct ReadyToBuild {
    kem: KemAlgorithmWrapper,
    signature: Option<SignatureAlgorithmWrapper>,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    aead: AeadAlgorithmWrapper,
    kdf: KdfKeyWrapper,
}

impl ReadyToBuild {
    /// Builds the `ProtocolSuite`.
    pub fn build(self) -> ProtocolSuite {
        ProtocolSuite {
            kem: self.kem,
            key_agreement: self.key_agreement,
            signature: self.signature,
            aead: self.aead,
            kdf: self.kdf,
        }
    }
}