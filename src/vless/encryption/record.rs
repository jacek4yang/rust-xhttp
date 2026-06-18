use super::derive_key;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

pub const MAX_NONCE: [u8; 12] = [0xff; 12];
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub(crate) struct AeadState {
    kind: CipherKind,
    key: Zeroizing<[u8; 32]>,
    united_key: Zeroizing<Vec<u8>>,
    nonce: [u8; 12],
}

impl AeadState {
    pub(crate) fn new(context: &[u8], united_key: &[u8], kind: CipherKind) -> Self {
        Self {
            kind,
            key: Zeroizing::new(derive_key(context, united_key)),
            united_key: Zeroizing::new(united_key.to_vec()),
            nonce: [0; 12],
        }
    }

    pub(crate) fn seal_raw(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        explicit_nonce: Option<[u8; 12]>,
    ) -> Result<Vec<u8>, RecordError> {
        let nonce = if let Some(nonce) = explicit_nonce {
            nonce
        } else {
            increment_nonce(&mut self.nonce);
            self.nonce
        };
        self.encrypt(&nonce, plaintext, aad)
    }

    pub(crate) fn open_raw(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        explicit_nonce: Option<[u8; 12]>,
    ) -> Result<Vec<u8>, RecordError> {
        let nonce = if let Some(nonce) = explicit_nonce {
            nonce
        } else {
            increment_nonce(&mut self.nonce);
            self.nonce
        };
        self.decrypt(&nonce, ciphertext, aad)
    }

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self.kind {
            CipherKind::Aes256Gcm => Aes256Gcm::new_from_slice(self.key.as_ref())
                .unwrap()
                .encrypt(nonce.into(), payload),
            CipherKind::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(self.key.as_ref())
                .unwrap()
                .encrypt(nonce.into(), payload),
        }
        .map_err(|_| RecordError::Authentication)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self.kind {
            CipherKind::Aes256Gcm => Aes256Gcm::new_from_slice(self.key.as_ref())
                .unwrap()
                .decrypt(nonce.into(), payload),
            CipherKind::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(self.key.as_ref())
                .unwrap()
                .decrypt(nonce.into(), payload),
        }
        .map_err(|_| RecordError::Authentication)
    }
}

pub struct RecordCipher {
    state: AeadState,
}

impl RecordCipher {
    pub fn new(context: &[u8], united_key: &[u8], kind: CipherKind) -> Self {
        Self {
            state: AeadState::new(context, united_key, kind),
        }
    }

    pub(crate) fn from_state(state: AeadState) -> Self {
        Self { state }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        if plaintext.len() > 8192 {
            return Err(RecordError::PlaintextTooLarge(plaintext.len()));
        }
        let mut header = [0u8; 5];
        encode_header(&mut header, plaintext.len() + TAG_LEN)?;
        let rekey = self.state.nonce == MAX_NONCE;
        let ciphertext = self.state.seal_raw(plaintext, &header, None)?;
        let mut out = Vec::with_capacity(5 + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        if rekey {
            *self.state.key = derive_key(&out, &self.state.united_key);
        }
        Ok(out)
    }

    pub fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<Vec<u8>, RecordError> {
        let len = decode_header(header)?;
        if len != ciphertext.len() {
            return Err(RecordError::LengthMismatch);
        }
        let rekey = self.state.nonce == MAX_NONCE;
        let mut context = Vec::new();
        if rekey {
            context.reserve(5 + ciphertext.len());
            context.extend_from_slice(header);
            context.extend_from_slice(ciphertext);
        }
        let plaintext = self.state.open_raw(ciphertext, header, None)?;
        if rekey {
            *self.state.key = derive_key(&context, &self.state.united_key);
        }
        Ok(plaintext)
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.state.nonce
    }

    #[cfg(test)]
    fn set_nonce(&mut self, nonce: [u8; 12]) {
        self.state.nonce = nonce;
    }
}

pub fn encode_header(header: &mut [u8; 5], length: usize) -> Result<(), RecordError> {
    if !(17..=16640).contains(&length) {
        return Err(RecordError::InvalidLength(length));
    }
    header[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
    header[3..].copy_from_slice(&(length as u16).to_be_bytes());
    Ok(())
}

pub fn decode_header(header: &[u8; 5]) -> Result<usize, RecordError> {
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[..3] != [0x17, 0x03, 0x03] || !(17..=16640).contains(&length) {
        return Err(RecordError::InvalidHeader(*header));
    }
    Ok(length)
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("invalid record header: {0:?}")]
    InvalidHeader([u8; 5]),
    #[error("invalid record length: {0}")]
    InvalidLength(usize),
    #[error("record plaintext exceeds 8192 bytes: {0}")]
    PlaintextTooLarge(usize),
    #[error("record length does not match ciphertext")]
    LengthMismatch,
    #[error("record authentication failed")]
    Authentication,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ciphers_roundtrip() {
        for kind in [CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305] {
            let mut sender = RecordCipher::new(b"\xffctx", b"united key", kind);
            let mut receiver = RecordCipher::new(b"\xffctx", b"united key", kind);
            let record = sender.seal(b"hello").unwrap();
            let header: &[u8; 5] = record[..5].try_into().unwrap();
            assert_eq!(receiver.open(header, &record[5..]).unwrap(), b"hello");
            assert_eq!(sender.nonce(), &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
    }

    #[test]
    fn header_bounds() {
        let mut header = [0; 5];
        assert!(encode_header(&mut header, 16).is_err());
        encode_header(&mut header, 17).unwrap();
        assert_eq!(decode_header(&header).unwrap(), 17);
        encode_header(&mut header, 16640).unwrap();
        assert_eq!(decode_header(&header).unwrap(), 16640);
        assert!(encode_header(&mut header, 16641).is_err());
    }

    #[test]
    fn rekeys_after_max_nonce() {
        for kind in [CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305] {
            let mut sender = RecordCipher::new(b"context", b"united", kind);
            let mut receiver = RecordCipher::new(b"context", b"united", kind);
            sender.set_nonce(MAX_NONCE);
            receiver.set_nonce(MAX_NONCE);
            let first = sender.seal(b"first").unwrap();
            let first_header = first[..5].try_into().unwrap();
            assert_eq!(receiver.open(first_header, &first[5..]).unwrap(), b"first");
            let second = sender.seal(b"second").unwrap();
            let second_header = second[..5].try_into().unwrap();
            assert_eq!(
                receiver.open(second_header, &second[5..]).unwrap(),
                b"second"
            );
        }
    }
}
