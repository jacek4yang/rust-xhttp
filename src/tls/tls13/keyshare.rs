//! TLS 1.3 key_share handling for the nginx-profile backend.

use rand::RngCore;
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const GROUP_X25519: u16 = 0x001d;

#[derive(Debug, Clone)]
pub struct ServerKeyShare {
    pub group: u16,
    pub public_key: Vec<u8>,
    pub shared_secret: Zeroizing<Vec<u8>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyShareError {
    #[error("unsupported TLS key_share group 0x{0:04x}")]
    UnsupportedGroup(u16),
    #[error(
        "invalid key_share length for group 0x{group:04x}: expected {expected}, actual {actual}"
    )]
    InvalidLength {
        group: u16,
        expected: usize,
        actual: usize,
    },
    #[error("X25519 shared secret is non-contributory")]
    NonContributory,
}

pub fn generate_server_keyshare(
    group: u16,
    peer_key: &[u8],
) -> Result<ServerKeyShare, KeyShareError> {
    generate_server_keyshare_with_rng(group, peer_key, rand::rngs::OsRng)
}

pub fn generate_server_keyshare_with_rng(
    group: u16,
    peer_key: &[u8],
    rng: impl RngCore + CryptoRng,
) -> Result<ServerKeyShare, KeyShareError> {
    match group {
        GROUP_X25519 => x25519_with_secret(peer_key, StaticSecret::random_from_rng(rng)),
        _ => Err(KeyShareError::UnsupportedGroup(group)),
    }
}

fn x25519_with_secret(
    peer_key: &[u8],
    secret: StaticSecret,
) -> Result<ServerKeyShare, KeyShareError> {
    if peer_key.len() != 32 {
        return Err(KeyShareError::InvalidLength {
            group: GROUP_X25519,
            expected: 32,
            actual: peer_key.len(),
        });
    }
    let peer_key: [u8; 32] = peer_key.try_into().unwrap();
    let shared = secret.diffie_hellman(&PublicKey::from(peer_key));
    if !shared.was_contributory() {
        return Err(KeyShareError::NonContributory);
    }
    Ok(ServerKeyShare {
        group: GROUP_X25519,
        public_key: PublicKey::from(&secret).to_bytes().to_vec(),
        shared_secret: Zeroizing::new(shared.as_bytes().to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keyshare_derives_same_secret_as_client() {
        let client_secret = StaticSecret::from([0x11; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let server_secret = StaticSecret::from([0x22; 32]);

        let keyshare = x25519_with_secret(&client_public, server_secret).unwrap();
        let server_public: [u8; 32] = keyshare.public_key.as_slice().try_into().unwrap();
        let expected = client_secret
            .diffie_hellman(&PublicKey::from(server_public))
            .to_bytes();

        assert_eq!(keyshare.group, GROUP_X25519);
        assert_eq!(keyshare.public_key.len(), 32);
        assert_eq!(&*keyshare.shared_secret, expected.as_slice());
    }

    #[test]
    fn rejects_wrong_group_or_length() {
        assert!(matches!(
            generate_server_keyshare(0x0017, &[0u8; 32]),
            Err(KeyShareError::UnsupportedGroup(0x0017))
        ));
        assert!(matches!(
            x25519_with_secret(&[0u8; 31], StaticSecret::from([0x22; 32])),
            Err(KeyShareError::InvalidLength {
                group: GROUP_X25519,
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn rejects_non_contributory_x25519_peer_key() {
        assert!(matches!(
            x25519_with_secret(&[0u8; 32], StaticSecret::from([0x22; 32])),
            Err(KeyShareError::NonContributory)
        ));
    }
}
