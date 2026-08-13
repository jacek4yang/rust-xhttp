//! TLS 1.3 AEAD record layer (RFC 8446 section 5.2).

use aes_gcm::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use std::fmt;

use super::CipherSuite;

pub const RECORD_HANDSHAKE: u8 = 22;
pub const RECORD_APPLICATION_DATA: u8 = 23;
pub const RECORD_ALERT: u8 = 21;
pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 20;

const OUTER_TYPE: u8 = 0x17;
const OUTER_VERSION: [u8; 2] = [0x03, 0x03];
const TAG_LEN: usize = 16;

#[derive(Clone)]
enum RecordAead {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl fmt::Debug for RecordAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Aes128Gcm(_) => "Aes128Gcm",
            Self::Aes256Gcm(_) => "Aes256Gcm",
            Self::ChaCha20Poly1305(_) => "ChaCha20Poly1305",
        })
    }
}

impl RecordAead {
    fn new(suite: CipherSuite, key: &[u8]) -> Self {
        match suite {
            CipherSuite::Aes128GcmSha256 => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("AES-128 key"),
            )),
            CipherSuite::Aes256GcmSha384 => Self::Aes256Gcm(Box::new(
                Aes256Gcm::new_from_slice(key).expect("AES-256 key"),
            )),
            CipherSuite::ChaCha20Poly1305Sha256 => Self::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20-Poly1305 key"),
            )),
        }
    }

    fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut Vec<u8>,
        body_offset: usize,
    ) {
        let tag = match self {
            Self::Aes128Gcm(cipher) => {
                cipher.encrypt_in_place_detached(nonce.into(), aad, &mut buffer[body_offset..])
            }
            Self::Aes256Gcm(cipher) => {
                cipher.encrypt_in_place_detached(nonce.into(), aad, &mut buffer[body_offset..])
            }
            Self::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_in_place_detached(nonce.into(), aad, &mut buffer[body_offset..])
            }
        }
        .expect("AEAD encrypt");
        buffer.extend_from_slice(&tag);
    }

    fn decrypt_detached_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Option<()> {
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::Aes128Gcm(cipher) => {
                cipher.decrypt_in_place_detached(nonce.into(), aad, body, tag)
            }
            Self::Aes256Gcm(cipher) => {
                cipher.decrypt_in_place_detached(nonce.into(), aad, body, tag)
            }
            Self::ChaCha20Poly1305(cipher) => {
                cipher.decrypt_in_place_detached(nonce.into(), aad, body, tag)
            }
        }
        .ok()
    }
}

#[derive(Debug, Clone)]
pub struct RecordKeys {
    aead: RecordAead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    pub fn new(suite: CipherSuite, key: Vec<u8>, iv: [u8; 12]) -> Self {
        Self {
            aead: RecordAead::new(suite, &key),
            iv,
            seq: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq[i];
        }
        nonce
    }

    pub fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        self.seal_with_padding(content_type, plaintext, 0)
    }

    pub fn seal_with_padding(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        pad_len: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        self.seal_into(content_type, plaintext, pad_len, &mut out);
        out
    }

    #[inline]
    pub fn seal_into(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        pad_len: usize,
        out: &mut Vec<u8>,
    ) {
        let inner_len = plaintext.len() + 1 + pad_len;
        let ct_len = inner_len + TAG_LEN;
        let header = [
            OUTER_TYPE,
            OUTER_VERSION[0],
            OUTER_VERSION[1],
            (ct_len >> 8) as u8,
            ct_len as u8,
        ];

        let nonce = self.nonce();
        out.clear();
        out.reserve(5 + ct_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(plaintext);
        out.push(content_type);
        out.resize(5 + inner_len, 0);
        self.aead.encrypt_in_place(&nonce, &header, out, 5);
        self.seq += 1;
    }

    pub fn open(&mut self, record: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut buf = record.to_vec();
        let (content_type, end) = self.open_in_place(&mut buf)?;
        Some((content_type, buf[5..end].to_vec()))
    }

    #[inline]
    pub fn open_in_place(&mut self, buf: &mut [u8]) -> Option<(u8, usize)> {
        if buf.len() < 5 {
            return None;
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len || len < TAG_LEN {
            return None;
        }
        let header = [buf[0], buf[1], buf[2], buf[3], buf[4]];
        let nonce = self.nonce();
        let split = len - TAG_LEN;
        let (body, tag) = buf[5..5 + len].split_at_mut(split);
        self.aead
            .decrypt_detached_in_place(&nonce, &header, body, tag)?;
        self.seq += 1;

        let mut end = 5 + split;
        while end > 5 && buf[end - 1] == 0 {
            end -= 1;
        }
        if end == 5 {
            return None;
        }
        Some((buf[end - 1], end - 1))
    }
}

pub fn change_cipher_spec_record() -> [u8; 6] {
    [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(suite: CipherSuite) -> (RecordKeys, RecordKeys) {
        let key = vec![0x2bu8; suite.key_len()];
        let iv = [0x5au8; 12];
        (
            RecordKeys::new(suite, key.clone(), iv),
            RecordKeys::new(suite, key, iv),
        )
    }

    #[test]
    fn seal_open_roundtrip_all_suites() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let (mut write, mut read) = keys(suite);
            for msg in [b"".as_slice(), b"hello", &[0u8; 4000]] {
                let record = write.seal(RECORD_HANDSHAKE, msg);
                assert_eq!(record[0], OUTER_TYPE);
                let (content_type, plaintext) = read.open(&record).expect("open record");
                assert_eq!(content_type, RECORD_HANDSHAKE);
                assert_eq!(plaintext, msg);
            }
        }
    }

    #[test]
    fn sequence_numbers_advance() {
        let (mut write, mut read) = keys(CipherSuite::Aes128GcmSha256);
        let first = write.seal(RECORD_APPLICATION_DATA, b"one");
        let second = write.seal(RECORD_APPLICATION_DATA, b"two");
        assert_ne!(first, second);
        assert_eq!(read.open(&first).unwrap().1, b"one");
        assert_eq!(read.open(&second).unwrap().1, b"two");
    }

    #[test]
    fn tamper_fails_open() {
        let (mut write, mut read) = keys(CipherSuite::Aes128GcmSha256);
        let mut record = write.seal(RECORD_HANDSHAKE, b"secret");
        let last = record.len() - 1;
        record[last] ^= 0xff;
        assert!(read.open(&record).is_none());
    }

    #[test]
    fn out_of_order_fails() {
        let (mut write, mut read) = keys(CipherSuite::Aes128GcmSha256);
        let _first = write.seal(RECORD_HANDSHAKE, b"first");
        let second = write.seal(RECORD_HANDSHAKE, b"second");
        assert!(read.open(&second).is_none());
    }

    #[test]
    fn seal_into_matches_seal() {
        let (mut a, _) = keys(CipherSuite::Aes128GcmSha256);
        let (mut b, _) = keys(CipherSuite::Aes128GcmSha256);
        let expected = a.seal(RECORD_APPLICATION_DATA, b"hello world");
        let mut actual = Vec::new();
        b.seal_into(RECORD_APPLICATION_DATA, b"hello world", 0, &mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn seal_into_with_padding_matches() {
        let (mut a, _) = keys(CipherSuite::Aes128GcmSha256);
        let (mut b, _) = keys(CipherSuite::Aes128GcmSha256);
        let expected = a.seal_with_padding(RECORD_APPLICATION_DATA, b"padded data", 100);
        let mut actual = Vec::new();
        b.seal_into(RECORD_APPLICATION_DATA, b"padded data", 100, &mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn seal_into_reuses_buffer() {
        let (mut write, _) = keys(CipherSuite::Aes128GcmSha256);
        let mut out = Vec::new();
        for i in 0..10 {
            let msg = vec![i as u8; 100];
            write.seal_into(RECORD_APPLICATION_DATA, &msg, 0, &mut out);
            assert_eq!(out[0], OUTER_TYPE);
        }
    }

    #[test]
    fn open_in_place_roundtrip() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let (mut write, mut read) = keys(suite);
            for msg in [b"".as_slice(), b"hello", &[0u8; 4000]] {
                let record = write.seal(RECORD_APPLICATION_DATA, msg);
                let mut buf = record.clone();
                let (content_type, end) = read.open_in_place(&mut buf).expect("open in place");
                assert_eq!(content_type, RECORD_APPLICATION_DATA);
                assert_eq!(&buf[5..end], msg);
            }
        }
    }

    #[test]
    fn open_in_place_tamper_fails() {
        let (mut write, mut read) = keys(CipherSuite::Aes128GcmSha256);
        let mut buf = write.seal(RECORD_APPLICATION_DATA, b"secret");
        let last = buf.len() - 1;
        buf[last] ^= 0xff;
        assert!(read.open_in_place(&mut buf).is_none());
    }

    #[test]
    fn open_in_place_matches_open() {
        let (mut write, mut a) = keys(CipherSuite::Aes256GcmSha384);
        let (_, mut b) = keys(CipherSuite::Aes256GcmSha384);
        for msg in [b"short".as_slice(), b"medium message", &[0xabu8; 8000]] {
            let record = write.seal(RECORD_APPLICATION_DATA, msg);
            let (content_type_a, plaintext_a) = a.open(&record).expect("open");
            let mut buf = record.clone();
            let (content_type_b, end) = b.open_in_place(&mut buf).expect("open in place");
            assert_eq!(content_type_a, content_type_b);
            assert_eq!(plaintext_a, &buf[5..end]);
        }
    }
}
