//! TLS 1.3 key schedule (RFC 8446 section 7.1) over SHA-256 / SHA-384.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub fn empty_hash(self) -> Vec<u8> {
        self.hash(&[])
    }

    pub fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            Self::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    pub fn expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let info = hkdf_label(label, context, length);
        let mut out = vec![0u8; length];
        match self {
            Self::Sha256 => Hkdf::<Sha256>::from_prk(secret)
                .expect("valid SHA-256 PRK length")
                .expand(&info, &mut out)
                .expect("valid HKDF output length"),
            Self::Sha384 => Hkdf::<Sha384>::from_prk(secret)
                .expect("valid SHA-384 PRK length")
                .expand(&info, &mut out)
                .expect("valid HKDF output length"),
        }
        out
    }

    pub fn derive_secret(self, secret: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
        let context = self.hash(transcript);
        self.expand_label(secret, label, &context, self.output_len())
    }

    pub fn derive_secret_with_hash(
        self,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.output_len())
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn hkdf_label(label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut out = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.push(full_label.len() as u8);
    out.extend_from_slice(full_label.as_bytes());
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

#[derive(Debug, Clone)]
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
}

#[derive(Debug, Clone)]
pub struct KeySchedule {
    hash: HashAlg,
    master_secret: Vec<u8>,
    client_hs_traffic: Vec<u8>,
    server_hs_traffic: Vec<u8>,
}

impl KeySchedule {
    pub fn new(hash: HashAlg, ecdhe: &[u8], transcript_hash_ch_sh: &[u8]) -> Self {
        let zero = vec![0u8; hash.output_len()];
        let early_secret = hash.hkdf_extract(&zero, &zero);
        let derived = hash.derive_secret(&early_secret, "derived", &[]);
        let handshake_secret = hash.hkdf_extract(&derived, ecdhe);

        let client_hs_traffic =
            hash.derive_secret_with_hash(&handshake_secret, "c hs traffic", transcript_hash_ch_sh);
        let server_hs_traffic =
            hash.derive_secret_with_hash(&handshake_secret, "s hs traffic", transcript_hash_ch_sh);

        let derived2 = hash.derive_secret(&handshake_secret, "derived", &[]);
        let master_secret = hash.hkdf_extract(&derived2, &zero);

        Self {
            hash,
            master_secret,
            client_hs_traffic,
            server_hs_traffic,
        }
    }

    pub fn hash(&self) -> HashAlg {
        self.hash
    }

    pub fn client_handshake_traffic_secret(&self) -> &[u8] {
        &self.client_hs_traffic
    }

    pub fn server_handshake_traffic_secret(&self) -> &[u8] {
        &self.server_hs_traffic
    }

    pub fn traffic_keys(&self, secret: &[u8], key_len: usize) -> TrafficKeys {
        let key = self.hash.expand_label(secret, "key", &[], key_len);
        let iv_vec = self.hash.expand_label(secret, "iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        TrafficKeys { key, iv }
    }

    pub fn finished_verify_data(
        &self,
        base_traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Vec<u8> {
        let finished_key =
            self.hash
                .expand_label(base_traffic_secret, "finished", &[], self.hash.output_len());
        self.hash.hmac(&finished_key, transcript_hash)
    }

    pub fn application_traffic_secrets(
        &self,
        transcript_hash_to_server_finished: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let client = self.hash.derive_secret_with_hash(
            &self.master_secret,
            "c ap traffic",
            transcript_hash_to_server_finished,
        );
        let server = self.hash.derive_secret_with_hash(
            &self.master_secret,
            "s ap traffic",
            transcript_hash_to_server_finished,
        );
        (client, server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_known() {
        assert_eq!(
            HashAlg::Sha256.empty_hash(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            HashAlg::Sha384.empty_hash(),
            [
                0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
                0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
                0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
                0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
            ]
        );
    }

    #[test]
    fn expand_label_reference_vector() {
        let secret = [0x0bu8; 32];
        let out = HashAlg::Sha256.expand_label(&secret, "key", &[], 16);
        assert_eq!(
            out,
            [
                0x4a, 0xe1, 0x37, 0x37, 0x2e, 0x85, 0x02, 0xa1, 0x2c, 0x72, 0x48, 0x42, 0x0c, 0xf5,
                0xa9, 0x32,
            ]
        );
    }

    #[test]
    fn derive_secret_reference_vector() {
        let secret = [0x0bu8; 32];
        let out = HashAlg::Sha256.derive_secret(&secret, "derived", &[]);
        assert_eq!(
            out,
            [
                0x4b, 0x4d, 0xd8, 0x21, 0x58, 0x50, 0xa5, 0x8b, 0x63, 0xdd, 0x1c, 0xe6, 0x1f, 0xc5,
                0xd0, 0x0c, 0x9c, 0x4d, 0x92, 0xe7, 0xdd, 0x99, 0x6d, 0x5d, 0x9c, 0xab, 0x41, 0x65,
                0xea, 0xd5, 0xe7, 0x58,
            ]
        );
    }

    #[test]
    fn full_schedule_consistency_finished() {
        let hash = HashAlg::Sha256;
        let ecdhe = [0x22u8; 32];
        let transcript = hash.hash(b"ClientHello||ServerHello");
        let schedule = KeySchedule::new(hash, &ecdhe, &transcript);
        let finished_transcript = hash.hash(b"...up to server cert verify...");

        let a = schedule.finished_verify_data(
            schedule.server_handshake_traffic_secret(),
            &finished_transcript,
        );
        let b = schedule.finished_verify_data(
            schedule.server_handshake_traffic_secret(),
            &finished_transcript,
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn traffic_key_lengths_match_suite_needs() {
        let hash = HashAlg::Sha256;
        let schedule = KeySchedule::new(hash, &[0u8; 32], &hash.empty_hash());
        let keys = schedule.traffic_keys(schedule.server_handshake_traffic_secret(), 16);
        assert_eq!(keys.key.len(), 16);
        assert_eq!(keys.iv.len(), 12);
    }
}
