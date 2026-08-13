//! TLS 1.3 primitives used by the self-contained nginx-profile backend.
//!
//! Exact nginx/OpenSSL fidelity remains gated on the ignored differential
//! harness; see `docs/tls-fidelity-analysis.md`.

pub mod flight;
pub mod handshake;
pub mod keyschedule;
pub mod keyshare;
pub mod messages;
pub mod record;

pub use keyschedule::{HashAlg, KeySchedule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn hash(self) -> HashAlg {
        match self {
            Self::Aes256GcmSha384 => HashAlg::Sha384,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashAlg::Sha256,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_ids_round_trip() {
        for (id, suite) in [
            (0x1301, CipherSuite::Aes128GcmSha256),
            (0x1302, CipherSuite::Aes256GcmSha384),
            (0x1303, CipherSuite::ChaCha20Poly1305Sha256),
        ] {
            assert_eq!(CipherSuite::from_u16(id), Some(suite));
            assert_eq!(suite.to_u16(), id);
        }
        assert_eq!(CipherSuite::from_u16(0x0a0a), None);
    }
}
