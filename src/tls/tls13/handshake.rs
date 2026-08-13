//! In-memory TLS 1.3 server handshake preparation.
//!
//! This composes ClientHello parsing, X25519 key_share, key schedule,
//! certificate signing, ServerHello synthesis, and encrypted server flight
//! assembly. Socket I/O, client Finished verification, and HTTP handoff are
//! handled by the nginx-profile backend state machine.

use subtle::ConstantTimeEq;

use crate::tls::cert::{CertificateVerifyError, CertifiedIdentity, SignatureScheme};
use crate::tls::client_hello::{ClientHello, ParseError};

use super::KeySchedule;
use super::flight::{
    FlightError, ServerHandshakeFlight, SynthesizedServerHello, build_server_handshake_flight,
    synthesize_server_hello,
};
use super::keyshare::{KeyShareError, generate_server_keyshare};
use super::messages::{HS_FINISHED, encrypted_extensions_with_alpn, find_server_keyshare};
use super::record::RecordKeys;

#[derive(Debug, Clone)]
pub struct PreparedServerHandshake {
    pub client: ClientHello,
    pub selected_alpn: Option<String>,
    pub server_hello: SynthesizedServerHello,
    pub flight: ServerHandshakeFlight,
    pub client_handshake_read: RecordKeys,
    pub transcript_hash_to_client_finished: Vec<u8>,
    schedule: KeySchedule,
    expected_client_finished: Vec<u8>,
}

impl PreparedServerHandshake {
    pub fn verify_client_finished_message(
        &self,
        message: &[u8],
    ) -> Result<(), ClientFinishedError> {
        if message.len() != 4 + self.expected_client_finished.len()
            || message.first().copied() != Some(HS_FINISHED)
        {
            return Err(ClientFinishedError::Malformed);
        }
        let len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
        if len != self.expected_client_finished.len() {
            return Err(ClientFinishedError::Malformed);
        }
        if self
            .expected_client_finished
            .ct_eq(&message[4..])
            .unwrap_u8()
            != 1
        {
            return Err(ClientFinishedError::VerifyDataMismatch);
        }
        Ok(())
    }

    pub fn application_record_keys(&self) -> ApplicationRecordKeys {
        let (client_secret, server_secret) = self
            .schedule
            .application_traffic_secrets(&self.transcript_hash_to_client_finished);
        let suite = self.server_hello.suite;
        let client_keys = self.schedule.traffic_keys(&client_secret, suite.key_len());
        let server_keys = self.schedule.traffic_keys(&server_secret, suite.key_len());
        ApplicationRecordKeys {
            client_read: RecordKeys::new(suite, client_keys.key, client_keys.iv),
            server_write: RecordKeys::new(suite, server_keys.key, server_keys.iv),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationRecordKeys {
    pub client_read: RecordKeys,
    pub server_write: RecordKeys,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientFinishedError {
    #[error("malformed client Finished message")]
    Malformed,
    #[error("client Finished verify_data mismatch")]
    VerifyDataMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("ClientHello: {0}")]
    ClientHello(#[from] ParseError),
    #[error("ServerHello template has no usable key_share")]
    MissingTemplateKeyShare,
    #[error("ClientHello did not offer key_share group 0x{0:04x}")]
    MissingClientKeyShare(u16),
    #[error("ClientHello omitted signature_algorithms")]
    MissingSignatureAlgorithms,
    #[error("key_share: {0}")]
    KeyShare(#[from] KeyShareError),
    #[error("server flight: {0}")]
    Flight(#[from] FlightError),
    #[error("CertificateVerify: {0}")]
    CertificateVerify(#[from] CertificateVerifyError),
}

pub fn prepare_server_handshake(
    client_hello_message: &[u8],
    server_hello_template: &[u8],
    identity: &CertifiedIdentity,
    alpn_protocols: &[String],
) -> Result<PreparedServerHandshake, PrepareError> {
    let client = ClientHello::parse_message(client_hello_message)?;
    if client.signature_schemes.is_empty() {
        return Err(PrepareError::MissingSignatureAlgorithms);
    }

    let (group, _, _) =
        find_server_keyshare(server_hello_template).ok_or(PrepareError::MissingTemplateKeyShare)?;
    let client_keyshare = client
        .key_shares
        .iter()
        .find(|share| share.group == group)
        .ok_or(PrepareError::MissingClientKeyShare(group))?;
    let keyshare = generate_server_keyshare(group, &client_keyshare.data)?;
    let server_hello =
        synthesize_server_hello(server_hello_template, &client, &keyshare.public_key)?;

    let selected_alpn = select_alpn(&client, alpn_protocols);
    let encrypted_extensions = encrypted_extensions_with_alpn(selected_alpn.as_deref());
    let certificate = identity.certificate_message();

    let mut transcript_to_certificate = Vec::with_capacity(
        client.raw_message.len()
            + server_hello.message.len()
            + encrypted_extensions.len()
            + certificate.len(),
    );
    transcript_to_certificate.extend_from_slice(&client.raw_message);
    transcript_to_certificate.extend_from_slice(&server_hello.message);
    transcript_to_certificate.extend_from_slice(&encrypted_extensions);
    transcript_to_certificate.extend_from_slice(&certificate);
    let transcript_hash_to_certificate = server_hello.suite.hash().hash(&transcript_to_certificate);
    let signature_schemes = signature_schemes(&client);
    let certificate_verify =
        identity.sign_certificate_verify(&transcript_hash_to_certificate, &signature_schemes)?;

    let mut transcript_ch_sh =
        Vec::with_capacity(client.raw_message.len() + server_hello.message.len());
    transcript_ch_sh.extend_from_slice(&client.raw_message);
    transcript_ch_sh.extend_from_slice(&server_hello.message);
    let transcript_hash_ch_sh = server_hello.suite.hash().hash(&transcript_ch_sh);
    let schedule = KeySchedule::new(
        server_hello.suite.hash(),
        &keyshare.shared_secret,
        &transcript_hash_ch_sh,
    );
    let client_hs_keys = schedule.traffic_keys(
        schedule.client_handshake_traffic_secret(),
        server_hello.suite.key_len(),
    );
    let client_handshake_read =
        RecordKeys::new(server_hello.suite, client_hs_keys.key, client_hs_keys.iv);
    let flight = build_server_handshake_flight(
        &server_hello,
        &schedule,
        &client.raw_message,
        &encrypted_extensions,
        &certificate,
        &certificate_verify,
    )?;
    let mut transcript_to_client_finished = transcript_to_certificate;
    transcript_to_client_finished.extend_from_slice(&certificate_verify);
    transcript_to_client_finished.extend_from_slice(&flight.server_finished);
    let transcript_hash_to_client_finished = server_hello
        .suite
        .hash()
        .hash(&transcript_to_client_finished);
    let expected_client_finished = schedule.finished_verify_data(
        schedule.client_handshake_traffic_secret(),
        &transcript_hash_to_client_finished,
    );

    Ok(PreparedServerHandshake {
        client,
        selected_alpn,
        server_hello,
        flight,
        client_handshake_read,
        transcript_hash_to_client_finished,
        schedule,
        expected_client_finished,
    })
}

fn select_alpn(client: &ClientHello, alpn_protocols: &[String]) -> Option<String> {
    alpn_protocols
        .iter()
        .find(|candidate| client.alpn.iter().any(|offered| offered == *candidate))
        .cloned()
}

fn signature_schemes(client: &ClientHello) -> Vec<SignatureScheme> {
    client
        .signature_schemes
        .iter()
        .copied()
        .map(SignatureScheme::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use x25519_dalek::{PublicKey, StaticSecret};

    use super::super::keyshare::GROUP_X25519;
    use super::super::messages::{
        HS_SERVER_HELLO, find_server_keyshare, finished_message, handshake_message,
    };
    use super::super::record::RECORD_HANDSHAKE;
    use super::*;
    use crate::tls::cert::{CertificateDer, SignError, SignatureAlgorithm, Signer, SigningKey};

    #[test]
    fn prepares_decryptable_server_handshake() {
        let client_secret = StaticSecret::from([0x11; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let client_hello = client_hello(
            &[0x99; 32],
            &[0x1301],
            &[(GROUP_X25519, client_public.as_slice())],
            &["h2", "http/1.1"],
            &[0x0403],
        );
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x33; 32]);
        let identity = CertifiedIdentity::new(
            vec![CertificateDer::from(vec![1, 2, 3])],
            Arc::new(FakeSigningKey),
        )
        .unwrap();

        let prepared =
            prepare_server_handshake(&client_hello, &template, &identity, &["h2".into()]).unwrap();

        assert_eq!(prepared.client.raw_message, client_hello);
        assert_eq!(prepared.selected_alpn.as_deref(), Some("h2"));
        assert_eq!(
            prepared.server_hello.suite,
            super::super::CipherSuite::Aes128GcmSha256
        );
        assert_eq!(prepared.server_hello.key_share_group, GROUP_X25519);

        let (_, offset, len) = find_server_keyshare(&prepared.server_hello.message).unwrap();
        let server_public: [u8; 32] = prepared.server_hello.message[offset..offset + len]
            .try_into()
            .unwrap();
        let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
        let transcript_ch_sh = [
            client_hello.as_slice(),
            prepared.server_hello.message.as_slice(),
        ]
        .concat();
        let schedule = KeySchedule::new(
            prepared.server_hello.suite.hash(),
            shared.as_bytes(),
            &prepared.server_hello.suite.hash().hash(&transcript_ch_sh),
        );

        let traffic_keys = schedule.traffic_keys(
            schedule.server_handshake_traffic_secret(),
            prepared.server_hello.suite.key_len(),
        );
        let mut server_read = RecordKeys::new(
            prepared.server_hello.suite,
            traffic_keys.key,
            traffic_keys.iv,
        );
        let (content_type, plaintext) = server_read
            .open(&prepared.flight.encrypted_handshake_record)
            .expect("decrypt server flight");
        assert_eq!(content_type, RECORD_HANDSHAKE);
        assert_eq!(plaintext, prepared.flight.encrypted_handshake_plaintext);
        assert!(plaintext.windows(2).any(|window| window == b"h2"));

        let client_keys = schedule.traffic_keys(
            schedule.client_handshake_traffic_secret(),
            prepared.server_hello.suite.key_len(),
        );
        let mut client_write =
            RecordKeys::new(prepared.server_hello.suite, client_keys.key, client_keys.iv);
        let client_finished = client_write.seal(RECORD_HANDSHAKE, b"client finished");
        let mut server_client_read = prepared.client_handshake_read.clone();
        assert_eq!(
            server_client_read.open(&client_finished).unwrap().1,
            b"client finished"
        );

        let verify_data = schedule.finished_verify_data(
            schedule.client_handshake_traffic_secret(),
            &prepared.transcript_hash_to_client_finished,
        );
        let client_finished = finished_message(&verify_data);
        assert!(
            prepared
                .verify_client_finished_message(&client_finished)
                .is_ok()
        );
        let mut tampered = client_finished;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            prepared.verify_client_finished_message(&tampered),
            Err(ClientFinishedError::VerifyDataMismatch)
        );
    }

    #[test]
    fn rejects_missing_signature_algorithms() {
        let client_secret = StaticSecret::from([0x11; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let client_hello = client_hello(
            &[],
            &[0x1301],
            &[(GROUP_X25519, client_public.as_slice())],
            &[],
            &[],
        );
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x33; 32]);
        let identity = CertifiedIdentity::new(
            vec![CertificateDer::from(vec![1, 2, 3])],
            Arc::new(FakeSigningKey),
        )
        .unwrap();

        assert!(matches!(
            prepare_server_handshake(&client_hello, &template, &identity, &[]),
            Err(PrepareError::MissingSignatureAlgorithms)
        ));
    }

    fn client_hello(
        session_id: &[u8],
        ciphers: &[u16],
        key_shares: &[(u16, &[u8])],
        alpn: &[&str],
        signature_schemes: &[u16],
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x002b, &[2, 0x03, 0x04]);

        let mut key_share_entries = Vec::new();
        for (group, data) in key_shares {
            key_share_entries.extend_from_slice(&group.to_be_bytes());
            key_share_entries.extend_from_slice(&(data.len() as u16).to_be_bytes());
            key_share_entries.extend_from_slice(data);
        }
        let mut key_share_body = Vec::new();
        key_share_body.extend_from_slice(&(key_share_entries.len() as u16).to_be_bytes());
        key_share_body.extend_from_slice(&key_share_entries);
        push_ext(&mut extensions, 0x0033, &key_share_body);

        if !alpn.is_empty() {
            let mut list = Vec::new();
            for protocol in alpn {
                list.push(protocol.len() as u8);
                list.extend_from_slice(protocol.as_bytes());
            }
            let mut body = Vec::new();
            body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            body.extend_from_slice(&list);
            push_ext(&mut extensions, 0x0010, &body);
        }

        if !signature_schemes.is_empty() {
            let mut list = Vec::new();
            for scheme in signature_schemes {
                list.extend_from_slice(&scheme.to_be_bytes());
            }
            let mut body = Vec::new();
            body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            body.extend_from_slice(&list);
            push_ext(&mut extensions, 0x000d, &body);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for cipher in ciphers {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        handshake_message(1, &body)
    }

    fn server_hello_template(cipher: u16, group: u16, keyshare: &[u8]) -> Vec<u8> {
        let mut key_share_ext = Vec::new();
        key_share_ext.extend_from_slice(&group.to_be_bytes());
        key_share_ext.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
        key_share_ext.extend_from_slice(keyshare);

        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0033, &key_share_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        handshake_message(HS_SERVER_HELLO, &body)
    }

    fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }

    #[derive(Debug)]
    struct FakeSigningKey;

    impl SigningKey for FakeSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
                .then(|| Box::new(FakeSigner) as Box<dyn Signer>)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ecdsa
        }
    }

    #[derive(Debug)]
    struct FakeSigner;

    impl Signer for FakeSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
            Ok(message.to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ECDSA_NISTP256_SHA256
        }
    }
}
