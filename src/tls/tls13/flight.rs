//! Server-side TLS 1.3 handshake flight assembly.

use rand::RngCore;

use crate::tls::client_hello::ClientHello;

use super::messages::{
    HS_SERVER_HELLO, find_server_keyshare, finished_message, server_hello_cipher_suite,
};
use super::record::{RECORD_HANDSHAKE, RecordKeys, change_cipher_spec_record};
use super::{CipherSuite, KeySchedule};

#[derive(Debug, Clone)]
pub struct SynthesizedServerHello {
    pub message: Vec<u8>,
    pub suite: CipherSuite,
    pub key_share_group: u16,
}

#[derive(Debug, Clone)]
pub struct ServerHandshakeFlight {
    pub server_hello: Vec<u8>,
    pub change_cipher_spec: [u8; 6],
    pub encrypted_handshake_plaintext: Vec<u8>,
    pub encrypted_handshake_record: Vec<u8>,
    pub server_finished: Vec<u8>,
    pub transcript_hash_to_server_finished: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FlightError {
    #[error("malformed ServerHello template")]
    MalformedServerHello,
    #[error("ClientHello does not offer TLS 1.3")]
    Tls13NotOffered,
    #[error("ClientHello legacy session id is too long for TLS 1.3 ServerHello echo")]
    SessionIdTooLong,
    #[error("ServerHello cipher suite 0x{0:04x} is unsupported")]
    UnsupportedCipherSuite(u16),
    #[error("ClientHello did not offer cipher suite 0x{0:04x}")]
    CipherNotOffered(u16),
    #[error("ClientHello did not offer key share group 0x{0:04x}")]
    KeyShareGroupNotOffered(u16),
    #[error(
        "server key share length mismatch for group 0x{group:04x}: expected {expected}, actual {actual}"
    )]
    KeyShareLengthMismatch {
        group: u16,
        expected: usize,
        actual: usize,
    },
    #[error("KeySchedule hash does not match selected cipher suite")]
    CipherHashMismatch,
}

pub fn synthesize_server_hello(
    template: &[u8],
    client: &ClientHello,
    server_keyshare: &[u8],
) -> Result<SynthesizedServerHello, FlightError> {
    synthesize_server_hello_with_rng(template, client, server_keyshare, &mut rand::rngs::OsRng)
}

pub fn synthesize_server_hello_with_rng(
    template: &[u8],
    client: &ClientHello,
    server_keyshare: &[u8],
    rng: &mut impl RngCore,
) -> Result<SynthesizedServerHello, FlightError> {
    validate_server_hello_template(template)?;
    if !client.offers_tls13 {
        return Err(FlightError::Tls13NotOffered);
    }
    if client.session_id.len() > 32 {
        return Err(FlightError::SessionIdTooLong);
    }

    let cipher_id = server_hello_cipher_suite(template).ok_or(FlightError::MalformedServerHello)?;
    let suite =
        CipherSuite::from_u16(cipher_id).ok_or(FlightError::UnsupportedCipherSuite(cipher_id))?;
    if !client.cipher_offered(cipher_id) {
        return Err(FlightError::CipherNotOffered(cipher_id));
    }

    let (group, _, template_keyshare_len) =
        find_server_keyshare(template).ok_or(FlightError::MalformedServerHello)?;
    if !client.keyshare_group_offered(group) {
        return Err(FlightError::KeyShareGroupNotOffered(group));
    }
    if template_keyshare_len != server_keyshare.len() {
        return Err(FlightError::KeyShareLengthMismatch {
            group,
            expected: template_keyshare_len,
            actual: server_keyshare.len(),
        });
    }

    let mut message = rewrite_random_and_session_id(template, &client.session_id, rng)?;
    let (_, offset, len) =
        find_server_keyshare(&message).ok_or(FlightError::MalformedServerHello)?;
    message[offset..offset + len].copy_from_slice(server_keyshare);

    Ok(SynthesizedServerHello {
        message,
        suite,
        key_share_group: group,
    })
}

pub fn build_server_handshake_flight(
    selected: &SynthesizedServerHello,
    schedule: &KeySchedule,
    transcript_before_server_hello: &[u8],
    encrypted_extensions: &[u8],
    certificate: &[u8],
    certificate_verify: &[u8],
) -> Result<ServerHandshakeFlight, FlightError> {
    if schedule.hash() != selected.suite.hash() {
        return Err(FlightError::CipherHashMismatch);
    }

    let mut transcript = Vec::with_capacity(
        transcript_before_server_hello.len()
            + selected.message.len()
            + encrypted_extensions.len()
            + certificate.len()
            + certificate_verify.len(),
    );
    transcript.extend_from_slice(transcript_before_server_hello);
    transcript.extend_from_slice(&selected.message);
    transcript.extend_from_slice(encrypted_extensions);
    transcript.extend_from_slice(certificate);
    transcript.extend_from_slice(certificate_verify);
    let transcript_hash_to_server_finished = schedule.hash().hash(&transcript);
    let verify_data = schedule.finished_verify_data(
        schedule.server_handshake_traffic_secret(),
        &transcript_hash_to_server_finished,
    );
    let server_finished = finished_message(&verify_data);

    let mut encrypted_handshake_plaintext = Vec::with_capacity(
        encrypted_extensions.len()
            + certificate.len()
            + certificate_verify.len()
            + server_finished.len(),
    );
    encrypted_handshake_plaintext.extend_from_slice(encrypted_extensions);
    encrypted_handshake_plaintext.extend_from_slice(certificate);
    encrypted_handshake_plaintext.extend_from_slice(certificate_verify);
    encrypted_handshake_plaintext.extend_from_slice(&server_finished);

    let traffic_keys = schedule.traffic_keys(
        schedule.server_handshake_traffic_secret(),
        selected.suite.key_len(),
    );
    let mut record_keys = RecordKeys::new(selected.suite, traffic_keys.key, traffic_keys.iv);
    let encrypted_handshake_record =
        record_keys.seal(RECORD_HANDSHAKE, &encrypted_handshake_plaintext);

    Ok(ServerHandshakeFlight {
        server_hello: selected.message.clone(),
        change_cipher_spec: change_cipher_spec_record(),
        encrypted_handshake_plaintext,
        encrypted_handshake_record,
        server_finished,
        transcript_hash_to_server_finished,
    })
}

fn validate_server_hello_template(template: &[u8]) -> Result<(), FlightError> {
    let body_len = server_hello_body_len(template)?;
    if body_len != template.len() - 4 {
        return Err(FlightError::MalformedServerHello);
    }
    find_server_keyshare(template).ok_or(FlightError::MalformedServerHello)?;
    server_hello_cipher_suite(template).ok_or(FlightError::MalformedServerHello)?;
    Ok(())
}

fn rewrite_random_and_session_id(
    template: &[u8],
    session_id: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, FlightError> {
    let _body_len = server_hello_body_len(template)?;
    let body_start = 4;
    let random_start = body_start + 2;
    let random_end = random_start + 32;
    let sid_len_index = random_end;
    let old_sid_len = *template
        .get(sid_len_index)
        .ok_or(FlightError::MalformedServerHello)? as usize;
    let old_sid_end = sid_len_index
        .checked_add(1 + old_sid_len)
        .ok_or(FlightError::MalformedServerHello)?;
    if old_sid_end > template.len() {
        return Err(FlightError::MalformedServerHello);
    }

    let mut out = Vec::with_capacity(template.len() - old_sid_len + session_id.len());
    out.extend_from_slice(&template[..random_start]);
    let random_out_start = out.len();
    out.resize(random_out_start + 32, 0);
    rng.fill_bytes(&mut out[random_out_start..random_out_start + 32]);
    out.push(session_id.len() as u8);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&template[old_sid_end..]);

    let body_len = out.len() - 4;
    out[1..4].copy_from_slice(&[
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ]);
    Ok(out)
}

fn server_hello_body_len(template: &[u8]) -> Result<usize, FlightError> {
    if template.len() < 4 || template[0] != HS_SERVER_HELLO {
        return Err(FlightError::MalformedServerHello);
    }
    Ok(u32::from_be_bytes([0, template[1], template[2], template[3]]) as usize)
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::super::messages::{
        HS_SERVER_HELLO, encrypted_extensions_with_alpn, find_server_keyshare, handshake_message,
    };
    use super::super::record::{RECORD_HANDSHAKE, RecordKeys};
    use super::*;
    use crate::tls::cert::{
        CertificateDer, SignatureScheme, certificate_message, certificate_verify_message,
    };
    use crate::tls::client_hello::{ClientHello, HANDSHAKE_TYPE_CLIENT_HELLO};

    const GROUP_X25519: u16 = 0x001d;

    #[test]
    fn synthesizes_server_hello_from_template() {
        let client_msg = client_hello(&[0x99; 32], &[0x1301], &[(GROUP_X25519, &[1; 32])]);
        let client = ClientHello::parse_message(&client_msg).unwrap();
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x22; 32], &[0x11; 8]);
        let selected =
            synthesize_server_hello_with_rng(&template, &client, &[0x44; 32], &mut FixedRng(0xab))
                .unwrap();

        assert_eq!(selected.suite, CipherSuite::Aes128GcmSha256);
        assert_eq!(selected.key_share_group, GROUP_X25519);
        assert_eq!(selected.message[0], HS_SERVER_HELLO);
        assert_eq!(&selected.message[6..38], &[0xab; 32]);
        assert_eq!(selected.message[38], 32);
        assert_eq!(&selected.message[39..71], &[0x99; 32]);
        let (_, offset, len) = find_server_keyshare(&selected.message).unwrap();
        assert_eq!(len, 32);
        assert_eq!(&selected.message[offset..offset + len], &[0x44; 32]);
    }

    #[test]
    fn rejects_unoffered_cipher_or_keyshare() {
        let client_msg = client_hello(&[], &[0x1302], &[(GROUP_X25519, &[1; 32])]);
        let client = ClientHello::parse_message(&client_msg).unwrap();
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x22; 32], &[]);
        assert!(matches!(
            synthesize_server_hello_with_rng(&template, &client, &[0x44; 32], &mut FixedRng(0)),
            Err(FlightError::CipherNotOffered(0x1301))
        ));

        let client_msg = client_hello(&[], &[0x1301], &[(0x0017, &[1; 32])]);
        let client = ClientHello::parse_message(&client_msg).unwrap();
        assert!(matches!(
            synthesize_server_hello_with_rng(&template, &client, &[0x44; 32], &mut FixedRng(0)),
            Err(FlightError::KeyShareGroupNotOffered(GROUP_X25519))
        ));
    }

    #[test]
    fn rejects_keyshare_length_mismatch() {
        let client_msg = client_hello(&[], &[0x1301], &[(GROUP_X25519, &[1; 32])]);
        let client = ClientHello::parse_message(&client_msg).unwrap();
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x22; 32], &[]);
        assert!(matches!(
            synthesize_server_hello_with_rng(&template, &client, &[0x44; 31], &mut FixedRng(0)),
            Err(FlightError::KeyShareLengthMismatch {
                group: GROUP_X25519,
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn builds_decryptable_server_handshake_flight() {
        let client_msg = client_hello(&[0x99; 32], &[0x1301], &[(GROUP_X25519, &[1; 32])]);
        let client = ClientHello::parse_message(&client_msg).unwrap();
        let template = server_hello_template(0x1301, GROUP_X25519, &[0x22; 32], &[]);
        let selected =
            synthesize_server_hello_with_rng(&template, &client, &[0x44; 32], &mut FixedRng(0xab))
                .unwrap();
        let transcript_ch_sh =
            [client.raw_message.as_slice(), selected.message.as_slice()].concat();
        let schedule = KeySchedule::new(
            selected.suite.hash(),
            &[0x55; 32],
            &selected.suite.hash().hash(&transcript_ch_sh),
        );
        let ee = encrypted_extensions_with_alpn(Some("h2"));
        let cert = certificate_message(&[CertificateDer::from(vec![1, 2, 3])]);
        let cv = certificate_verify_message(SignatureScheme::ECDSA_NISTP256_SHA256, &[4, 5, 6]);

        let flight = build_server_handshake_flight(
            &selected,
            &schedule,
            &client.raw_message,
            &ee,
            &cert,
            &cv,
        )
        .unwrap();

        assert_eq!(flight.server_hello, selected.message);
        assert_eq!(flight.change_cipher_spec, change_cipher_spec_record());
        assert_eq!(
            flight.server_finished[0],
            super::super::messages::HS_FINISHED
        );
        let mut expected_transcript = transcript_ch_sh;
        expected_transcript.extend_from_slice(&ee);
        expected_transcript.extend_from_slice(&cert);
        expected_transcript.extend_from_slice(&cv);
        assert_eq!(
            flight.transcript_hash_to_server_finished,
            selected.suite.hash().hash(&expected_transcript)
        );

        let traffic_keys = schedule.traffic_keys(
            schedule.server_handshake_traffic_secret(),
            selected.suite.key_len(),
        );
        let mut read_keys = RecordKeys::new(selected.suite, traffic_keys.key, traffic_keys.iv);
        let (content_type, plaintext) = read_keys
            .open(&flight.encrypted_handshake_record)
            .expect("decrypt server flight");
        assert_eq!(content_type, RECORD_HANDSHAKE);
        assert_eq!(plaintext, flight.encrypted_handshake_plaintext);
        assert!(plaintext.starts_with(&ee));
        assert!(plaintext.ends_with(&flight.server_finished));
    }

    fn client_hello(session_id: &[u8], ciphers: &[u16], key_shares: &[(u16, &[u8])]) -> Vec<u8> {
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
        handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, &body)
    }

    fn server_hello_template(
        cipher: u16,
        group: u16,
        keyshare: &[u8],
        session_id: &[u8],
    ) -> Vec<u8> {
        let mut key_share_ext = Vec::new();
        key_share_ext.extend_from_slice(&group.to_be_bytes());
        key_share_ext.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
        key_share_ext.extend_from_slice(keyshare);

        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0033, &key_share_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
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

    struct FixedRng(u8);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_be_bytes([self.0; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_be_bytes([self.0; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}
