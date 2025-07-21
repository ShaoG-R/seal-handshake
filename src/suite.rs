use seal_flow::crypto::wrappers::{
    asymmetric::kem::KemAlgorithmWrapper,
    asymmetric::key_agreement::KeyAgreementAlgorithmWrapper,
    asymmetric::signature::SignatureAlgorithmWrapper,
    kdf::key::KdfKeyWrapper,
    symmetric::SymmetricAlgorithmWrapper,
};


// 伪代码：定义协议所需的加密组件
#[derive(Debug, Clone)]
pub struct ProtocolSuite {
    kem: KemAlgorithmWrapper,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    signature: Option<SignatureAlgorithmWrapper>,
    aead: SymmetricAlgorithmWrapper,
    kdf: KdfKeyWrapper,
}

#[derive(Debug, Default)]
pub struct ProtocolSuiteBuilder {
    kem: Option<KemAlgorithmWrapper>,
    key_agreement: Option<KeyAgreementAlgorithmWrapper>,
    signature: Option<SignatureAlgorithmWrapper>,
    aead: Option<SymmetricAlgorithmWrapper>,
    kdf: Option<KdfKeyWrapper>,
}

impl ProtocolSuiteBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kem(mut self, kem: KemAlgorithmWrapper) -> Self {
        self.kem = Some(kem);
        self
    }

    pub fn with_key_agreement(mut self, ka: KeyAgreementAlgorithmWrapper) -> Self {
        self.key_agreement = Some(ka);
        self
    }

    pub fn with_signature(mut self, signature: SignatureAlgorithmWrapper) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn with_aead(mut self, aead: SymmetricAlgorithmWrapper) -> Self {
        self.aead = Some(aead);
        self
    }

    pub fn with_kdf(mut self, kdf: KdfKeyWrapper) -> Self {
        self.kdf = Some(kdf);
        self
    }

    pub fn build(self) -> ProtocolSuite {
        ProtocolSuite {
            kem: self.kem.expect("KEM algorithm must be set"),
            key_agreement: self.key_agreement,
            signature: self.signature,
            aead: self.aead.expect("AEAD algorithm must be set"),
            kdf: self.kdf.expect("KDF algorithm must be set"),
        }
    }
}

impl ProtocolSuite {
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