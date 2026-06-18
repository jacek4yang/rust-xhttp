use super::{decode_header, derive_key};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// AES-CTR transform for only TLS-style record headers, matching Xray `XorConn`.
pub struct HeaderXor {
    cipher: Aes256Ctr,
    skip: usize,
    header: Vec<u8>,
    decrypt: bool,
}

impl HeaderXor {
    pub fn outbound(united_key: &[u8], iv: &[u8; 16], skip: usize) -> Self {
        Self::new(united_key, iv, skip, false)
    }

    pub fn inbound(united_key: &[u8], iv: &[u8; 16], skip: usize) -> Self {
        Self::new(united_key, iv, skip, true)
    }

    fn new(united_key: &[u8], iv: &[u8; 16], skip: usize, decrypt: bool) -> Self {
        let key = Zeroizing::new(derive_key(b"VLESS", united_key));
        Self {
            cipher: Aes256Ctr::new((&*key).into(), iv.into()),
            skip,
            header: Vec::with_capacity(5),
            decrypt,
        }
    }

    /// Apply the transform in place. The same operation encrypts and decrypts.
    pub fn apply(&mut self, bytes: &mut [u8]) -> Result<(), XorError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let skipped = self.skip.min(bytes.len() - offset);
            self.skip -= skipped;
            offset += skipped;
            if offset == bytes.len() {
                break;
            }

            let needed = 5 - self.header.len();
            let take = needed.min(bytes.len() - offset);
            if !self.decrypt {
                self.header.extend_from_slice(&bytes[offset..offset + take]);
            }
            self.cipher
                .apply_keystream(&mut bytes[offset..offset + take]);
            if self.decrypt {
                self.header.extend_from_slice(&bytes[offset..offset + take]);
            }
            offset += take;
            if self.header.len() == 5 {
                let header: [u8; 5] = self.header.as_slice().try_into().unwrap();
                self.skip = decode_header(&header)?;
                self.header.clear();
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum XorError {
    #[error("record: {0}")]
    Record(#[from] super::record::RecordError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_roundtrip_only_changes_headers() {
        let mut wire = vec![
            0x17, 0x03, 0x03, 0x00, 0x11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        ];
        let original = wire.clone();
        let mut encoder = HeaderXor::outbound(b"united", &[3; 16], 0);
        encoder.apply(&mut wire[..2]).unwrap();
        encoder.apply(&mut wire[2..8]).unwrap();
        encoder.apply(&mut wire[8..]).unwrap();
        assert_ne!(&wire[..5], &original[..5]);
        assert_eq!(&wire[5..], &original[5..]);

        let mut decoder = HeaderXor::inbound(b"united", &[3; 16], 0);
        decoder.apply(&mut wire[..1]).unwrap();
        decoder.apply(&mut wire[1..6]).unwrap();
        decoder.apply(&mut wire[6..]).unwrap();
        assert_eq!(wire, original);
    }
}
