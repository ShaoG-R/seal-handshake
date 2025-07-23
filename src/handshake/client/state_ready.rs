use super::{HandshakeClient, Ready, SignaturePresence};
use crate::crypto::suite::KeyAgreementEngine;
use crate::{
    error::Result,
    protocol::{
        message::HandshakeMessage,
        state::{AwaitingKemPublicKey, ClientAwaitingKemPublicKey, ClientReady},
    },
};

impl<Sig: SignaturePresence> HandshakeClient<Ready, ClientReady, Sig> {
    /// This initiates the handshake by creating a `ClientHello` message.
    ///
    /// 通过创建 `ClientHello` 消息来启动握手。
    pub fn start(
        self,
    ) -> Result<(
        HandshakeMessage,
        HandshakeClient<AwaitingKemPublicKey, ClientAwaitingKemPublicKey, Sig>,
    )> {
        let HandshakeClient {
            state: _,
            state_data,
            mut transcript,
            suite,
            server_signature_public_key,
        } = self;

        // If key agreement is supported, generate ephemeral keys for it.
        let (key_agreement_public_key, key_agreement_engine) =
            if let Some(key_agreement) = suite.key_agreement() {
                let engine = KeyAgreementEngine::new_for_client(key_agreement)?;
                (Some(engine.public_key().clone()), Some(engine))
            } else {
                (None, None)
            };

        let client_hello = HandshakeMessage::ClientHello {
            kem_algorithm: suite.kem().algorithm(),
            key_agreement_public_key,
            session_ticket: state_data.session_ticket_to_send,
        };

        transcript.update(&client_hello);

        let next_client = HandshakeClient {
            state: std::marker::PhantomData,
            state_data: ClientAwaitingKemPublicKey {
                key_agreement_engine,
                resumption_master_secret: state_data.resumption_master_secret,
            },
            suite,
            transcript,
            server_signature_public_key,
        };

        Ok((client_hello, next_client))
    }
}
