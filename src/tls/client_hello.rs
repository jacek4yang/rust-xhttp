//! TLS ClientHello parser for the nginx-profile TLS backend.
//!
//! It extracts only negotiation fields needed by the future self-contained TLS
//! server: SNI, ALPN, TLS 1.3 support, offered cipher suites, session id, and
//! key shares. The parser is bounds-checked and panic-free for malformed input.

use std::hash::{Hash, Hasher};

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    pub group: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub server_name: Option<String>,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub key_shares: Vec<KeyShare>,
    pub signature_schemes: Vec<u16>,
    pub offers_tls13: bool,
    pub alpn: Vec<String>,
    pub raw_message: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("truncated ClientHello")]
    Truncated,
    #[error("not a TLS handshake record")]
    NotHandshakeRecord,
    #[error("not a ClientHello handshake message")]
    NotClientHello,
    #[error("malformed ClientHello")]
    Malformed,
}

pub struct ClientHelloRecordBuffer {
    payload: Vec<u8>,
    max_payload: usize,
}

impl ClientHelloRecordBuffer {
    pub fn new(max_payload: usize) -> Self {
        Self {
            payload: Vec::new(),
            max_payload,
        }
    }

    pub fn append_record(
        &mut self,
        record: &[u8],
    ) -> Result<Option<Vec<u8>>, ClientHelloBufferError> {
        if record.len() < 5 {
            return Err(ClientHelloBufferError::TruncatedRecord);
        }
        if record[0] != TLS_RECORD_HANDSHAKE {
            return Err(ClientHelloBufferError::NotHandshakeRecord);
        }
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        let body = record
            .get(5..5 + len)
            .ok_or(ClientHelloBufferError::TruncatedRecord)?;
        if record.len() != 5 + len {
            return Err(ClientHelloBufferError::TrailingRecordBytes);
        }
        if self.payload.len() + body.len() > self.max_payload {
            return Err(ClientHelloBufferError::PayloadTooLarge);
        }
        self.payload.extend_from_slice(body);
        self.try_message()
    }

    fn try_message(&self) -> Result<Option<Vec<u8>>, ClientHelloBufferError> {
        if self.payload.len() < 4 {
            return Ok(None);
        }
        if self.payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(ClientHelloBufferError::NotClientHello);
        }
        let len =
            u32::from_be_bytes([0, self.payload[1], self.payload[2], self.payload[3]]) as usize;
        let total = 4 + len;
        if total > self.max_payload {
            return Err(ClientHelloBufferError::PayloadTooLarge);
        }
        if self.payload.len() < total {
            return Ok(None);
        }
        if self.payload.len() != total {
            return Err(ClientHelloBufferError::TrailingHandshakeBytes);
        }
        Ok(Some(self.payload.clone()))
    }
}

impl Default for ClientHelloRecordBuffer {
    fn default() -> Self {
        Self::new(1 << 16)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientHelloBufferError {
    #[error("truncated TLS record")]
    TruncatedRecord,
    #[error("not a TLS handshake record")]
    NotHandshakeRecord,
    #[error("TLS record has trailing bytes")]
    TrailingRecordBytes,
    #[error("not a ClientHello handshake message")]
    NotClientHello,
    #[error("ClientHello payload is too large")]
    PayloadTooLarge,
    #[error("extra handshake bytes after ClientHello")]
    TrailingHandshakeBytes,
}

impl ClientHello {
    pub fn parse_record(record: &[u8]) -> Result<Self, ParseError> {
        if record.len() < 5 {
            return Err(ParseError::Truncated);
        }
        if record[0] != TLS_RECORD_HANDSHAKE {
            return Err(ParseError::NotHandshakeRecord);
        }
        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        let body = record.get(5..5 + body_len).ok_or(ParseError::Truncated)?;
        Self::parse_message(body)
    }

    pub fn parse_message(message: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(message);
        if reader.u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(ParseError::NotClientHello);
        }
        let len = reader.u24()? as usize;
        if len != message.len().saturating_sub(4) {
            return Err(ParseError::Malformed);
        }

        let _legacy_version = reader.u16()?;
        let random = reader
            .take(32)?
            .try_into()
            .map_err(|_| ParseError::Truncated)?;
        let session_id_len = reader.u8()? as usize;
        let session_id = reader.take(session_id_len)?.to_vec();

        let cipher_len = reader.u16()? as usize;
        if cipher_len % 2 != 0 {
            return Err(ParseError::Malformed);
        }
        let cipher_bytes = reader.take(cipher_len)?;
        let cipher_suites = cipher_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();

        let compression_len = reader.u8()? as usize;
        reader.take(compression_len)?;

        let mut server_name = None;
        let mut key_shares = Vec::new();
        let mut signature_schemes = Vec::new();
        let mut offers_tls13 = false;
        let mut alpn = Vec::new();

        if !reader.is_empty() {
            let extensions_len = reader.u16()? as usize;
            let extensions = reader.take(extensions_len)?;
            parse_extensions(
                extensions,
                &mut server_name,
                &mut key_shares,
                &mut signature_schemes,
                &mut offers_tls13,
                &mut alpn,
            )?;
        }
        if !reader.is_empty() {
            return Err(ParseError::Malformed);
        }

        Ok(Self {
            server_name,
            random,
            session_id,
            cipher_suites,
            key_shares,
            signature_schemes,
            offers_tls13,
            alpn,
            raw_message: message.to_vec(),
        })
    }

    pub fn cipher_offered(&self, id: u16) -> bool {
        self.cipher_suites.contains(&id)
    }

    pub fn keyshare_group_offered(&self, group: u16) -> bool {
        self.key_shares
            .iter()
            .any(|share| share.group == group && !is_grease(group))
    }

    pub fn alpn_offer_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.alpn.len().hash(&mut hasher);
        for protocol in &self.alpn {
            protocol.hash(&mut hasher);
        }
        hasher.finish()
    }
}

pub fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn parse_extensions(
    bytes: &[u8],
    server_name: &mut Option<String>,
    key_shares: &mut Vec<KeyShare>,
    signature_schemes: &mut Vec<u16>,
    offers_tls13: &mut bool,
    alpn: &mut Vec<String>,
) -> Result<(), ParseError> {
    let mut reader = Reader::new(bytes);
    while !reader.is_empty() {
        let ext_type = reader.u16()?;
        let ext_len = reader.u16()? as usize;
        let ext_data = reader.take(ext_len)?;
        match ext_type {
            EXT_SERVER_NAME => *server_name = parse_sni(ext_data),
            EXT_SUPPORTED_VERSIONS => *offers_tls13 = parse_supported_versions(ext_data),
            EXT_SIGNATURE_ALGORITHMS => *signature_schemes = parse_signature_schemes(ext_data)?,
            EXT_ALPN => *alpn = parse_alpn(ext_data),
            EXT_KEY_SHARE => parse_key_shares(ext_data, key_shares)?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_signature_schemes(data: &[u8]) -> Result<Vec<u16>, ParseError> {
    let mut reader = Reader::new(data);
    let list_len = reader.u16()? as usize;
    if list_len % 2 != 0 {
        return Err(ParseError::Malformed);
    }
    let list = reader.take(list_len)?;
    if !reader.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok(list
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut reader = Reader::new(data);
    let list_len = reader.u16().ok()? as usize;
    let list = reader.take(list_len).ok()?;
    let mut names = Reader::new(list);
    while !names.is_empty() {
        let name_type = names.u8().ok()?;
        let name_len = names.u16().ok()? as usize;
        let name = names.take(name_len).ok()?;
        if name_type == 0 {
            return std::str::from_utf8(name).ok().map(str::to_string);
        }
    }
    None
}

fn parse_supported_versions(data: &[u8]) -> bool {
    let mut reader = Reader::new(data);
    let Ok(list_len) = reader.u8() else {
        return false;
    };
    let Ok(list) = reader.take(list_len as usize) else {
        return false;
    };
    let mut versions = Reader::new(list);
    while !versions.is_empty() {
        match versions.u16() {
            Ok(0x0304) => return true,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    false
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    let mut reader = Reader::new(data);
    let Ok(list_len) = reader.u16() else {
        return protocols;
    };
    let Ok(list) = reader.take(list_len as usize) else {
        return protocols;
    };
    let mut names = Reader::new(list);
    while !names.is_empty() {
        let Ok(name_len) = names.u8() else {
            break;
        };
        let Ok(name) = names.take(name_len as usize) else {
            break;
        };
        if let Ok(protocol) = std::str::from_utf8(name) {
            protocols.push(protocol.to_string());
        }
    }
    protocols
}

fn parse_key_shares(data: &[u8], key_shares: &mut Vec<KeyShare>) -> Result<(), ParseError> {
    let mut reader = Reader::new(data);
    let list_len = reader.u16()? as usize;
    let list = reader.take(list_len)?;
    let mut entries = Reader::new(list);
    while !entries.is_empty() {
        let group = entries.u16()?;
        let data_len = entries.u16()? as usize;
        let data = entries.take(data_len)?.to_vec();
        key_shares.push(KeyShare { group, data });
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(len).ok_or(ParseError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<u32, ParseError> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP_X25519: u16 = 0x001d;

    #[test]
    fn parses_sni_alpn_tls13_ciphers_and_keyshare() {
        let random = [7u8; 32];
        let session_id = [9u8; 32];
        let key_share = [0x42u8; 32];
        let msg = build_client_hello(
            &random,
            &session_id,
            "example.com",
            &["h2", "http/1.1"],
            &[(GROUP_X25519, key_share.as_slice())],
        );

        let hello = ClientHello::parse_message(&msg).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.random, random);
        assert_eq!(hello.session_id, session_id);
        assert!(hello.offers_tls13);
        assert_eq!(hello.alpn, ["h2", "http/1.1"]);
        assert_eq!(hello.signature_schemes, [0x0403, 0x0804]);
        assert!(hello.cipher_offered(0x1301));
        assert!(hello.keyshare_group_offered(GROUP_X25519));
        assert_eq!(hello.key_shares[0].data, key_share);
    }

    #[test]
    fn parses_from_record_wrapper() {
        let msg = build_client_hello(&[0u8; 32], &[], "x.test", &["h2"], &[]);
        let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&msg);

        let hello = ClientHello::parse_record(&record).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("x.test"));
        assert_eq!(hello.alpn, ["h2"]);
    }

    #[test]
    fn record_buffer_reassembles_fragmented_client_hello() {
        let msg = build_client_hello(&[0u8; 32], &[1, 2, 3], "x.test", &["h2"], &[]);
        let first = tls_record(&msg[..12]);
        let second = tls_record(&msg[12..]);
        let mut buffer = ClientHelloRecordBuffer::default();

        assert_eq!(buffer.append_record(&first).unwrap(), None);
        let reassembled = buffer.append_record(&second).unwrap().unwrap();
        assert_eq!(reassembled, msg);
        let hello = ClientHello::parse_message(&reassembled).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("x.test"));
    }

    #[test]
    fn record_buffer_rejects_bad_records_or_extra_handshake_bytes() {
        let msg = build_client_hello(&[0u8; 32], &[], "x.test", &[], &[]);
        let mut not_handshake = tls_record(&msg);
        not_handshake[0] = 0x15;
        assert!(matches!(
            ClientHelloRecordBuffer::default().append_record(&not_handshake),
            Err(ClientHelloBufferError::NotHandshakeRecord)
        ));

        let mut with_extra = msg.clone();
        with_extra.extend_from_slice(&[0x14, 0, 0, 0]);
        assert!(matches!(
            ClientHelloRecordBuffer::default().append_record(&tls_record(&with_extra)),
            Err(ClientHelloBufferError::TrailingHandshakeBytes)
        ));
    }

    #[test]
    fn rejects_wrong_record_or_handshake_type() {
        assert!(matches!(
            ClientHello::parse_record(&[0x17, 0x03, 0x03, 0, 0]),
            Err(ParseError::NotHandshakeRecord)
        ));
        let mut msg = build_client_hello(&[0u8; 32], &[], "x.test", &[], &[]);
        msg[0] = 0x02;
        assert!(matches!(
            ClientHello::parse_message(&msg),
            Err(ParseError::NotClientHello)
        ));
    }

    #[test]
    fn malformed_alpn_is_best_effort_not_fatal() {
        let msg = build_client_hello_with_extra_ext(&[0u8; 32], "x.test", |exts| {
            let body = [0x00, 0x0a, 0x02, b'h'];
            push_ext(exts, EXT_ALPN, &body);
        });
        let hello = ClientHello::parse_message(&msg).unwrap();
        assert!(hello.alpn.is_empty());
    }

    #[test]
    fn malformed_signature_algorithms_is_rejected() {
        let msg = build_client_hello_with_extra_ext(&[0u8; 32], "x.test", |exts| {
            push_ext(exts, EXT_SIGNATURE_ALGORITHMS, &[0, 3, 0x04, 0x03, 0x08]);
        });
        assert!(matches!(
            ClientHello::parse_message(&msg),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn grease_is_not_keyshare_offer() {
        let msg = build_client_hello(&[0u8; 32], &[], "x.test", &[], &[(0x0a0a, &[1, 2, 3])]);
        let hello = ClientHello::parse_message(&msg).unwrap();
        assert!(!hello.keyshare_group_offered(0x0a0a));
        assert!(is_grease(0x0a0a));
        assert!(!is_grease(GROUP_X25519));
    }

    #[test]
    fn alpn_hash_is_order_sensitive() {
        let a = build_client_hello(&[0u8; 32], &[], "x.test", &["h2", "http/1.1"], &[]);
        let b = build_client_hello(&[0u8; 32], &[], "x.test", &["http/1.1", "h2"], &[]);
        assert_ne!(
            ClientHello::parse_message(&a).unwrap().alpn_offer_hash(),
            ClientHello::parse_message(&b).unwrap().alpn_offer_hash()
        );
    }

    fn build_client_hello(
        random: &[u8; 32],
        session_id: &[u8],
        sni: &str,
        alpn: &[&str],
        key_shares: &[(u16, &[u8])],
    ) -> Vec<u8> {
        build_client_hello_with_extra_ext(random, sni, |exts| {
            if !alpn.is_empty() {
                let mut list = Vec::new();
                for protocol in alpn {
                    list.push(protocol.len() as u8);
                    list.extend_from_slice(protocol.as_bytes());
                }
                let mut body = Vec::new();
                body.extend_from_slice(&(list.len() as u16).to_be_bytes());
                body.extend_from_slice(&list);
                push_ext(exts, EXT_ALPN, &body);
            }
            if !key_shares.is_empty() {
                let mut entries = Vec::new();
                for (group, data) in key_shares {
                    entries.extend_from_slice(&group.to_be_bytes());
                    entries.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    entries.extend_from_slice(data);
                }
                let mut body = Vec::new();
                body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
                body.extend_from_slice(&entries);
                push_ext(exts, EXT_KEY_SHARE, &body);
            }
            let mut sigalgs = Vec::new();
            sigalgs.extend_from_slice(&0x0403u16.to_be_bytes());
            sigalgs.extend_from_slice(&0x0804u16.to_be_bytes());
            let mut sigalg_body = Vec::new();
            sigalg_body.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
            sigalg_body.extend_from_slice(&sigalgs);
            push_ext(exts, EXT_SIGNATURE_ALGORITHMS, &sigalg_body);
        })
        .with_random_and_session(random, session_id)
    }

    trait ClientHelloFixture {
        fn with_random_and_session(self, random: &[u8; 32], session_id: &[u8]) -> Vec<u8>;
    }

    impl ClientHelloFixture for Vec<u8> {
        fn with_random_and_session(mut self, random: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
            self[6..38].copy_from_slice(random);
            let sid_len_index = 38;
            let old_sid_len = self[sid_len_index] as usize;
            let old_sid_start = sid_len_index + 1;
            self.splice(
                sid_len_index..old_sid_start + old_sid_len,
                std::iter::once(session_id.len() as u8).chain(session_id.iter().copied()),
            );
            let body_len = self.len() - 4;
            self[1..4].copy_from_slice(&[
                (body_len >> 16) as u8,
                (body_len >> 8) as u8,
                body_len as u8,
            ]);
            self
        }
    }

    fn build_client_hello_with_extra_ext(
        random: &[u8; 32],
        sni: &str,
        extra: impl FnOnce(&mut Vec<u8>),
    ) -> Vec<u8> {
        let mut exts = Vec::new();
        let mut sni_list = Vec::new();
        sni_list.push(0);
        sni_list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(sni.as_bytes());
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(&sni_list);
        push_ext(&mut exts, EXT_SERVER_NAME, &sni_body);
        push_ext(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        extra(&mut exts);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(random);
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = body.len();
        msg.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        msg.extend_from_slice(&body);
        msg
    }

    fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }

    fn tls_record(body: &[u8]) -> Vec<u8> {
        let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(body);
        record
    }
}
