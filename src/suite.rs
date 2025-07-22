use seal_flow::crypto::wrappers::{
    asymmetric::kem::KemAlgorithmWrapper,
    asymmetric::key_agreement::KeyAgreementAlgorithmWrapper,
    asymmetric::signature::SignatureAlgorithmWrapper,
    kdf::key::KdfKeyWrapper,
    symmetric::SymmetricAlgorithmWrapper,
};

// --- Final ProtocolSuite ---
#[derive(Debug, Clone)]
pub struct ProtocolSuite {
    kem: KemAlgorithmWrapper,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    signature: Option<SignatureAlgorithmWrapper>,
    aead: SymmetricAlgorithmWrapper,
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

    pub fn aead(&self) -> &SymmetricAlgorithmWrapper {
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
    pub fn with_aead(self, aead: SymmetricAlgorithmWrapper) -> BuilderWithAead {
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
    aead: SymmetricAlgorithmWrapper,
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
    aead: SymmetricAlgorithmWrapper,
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