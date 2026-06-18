use super::KeySeed;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub enum ServerKey {
    X25519 {
        secret: StaticSecret,
        public: [u8; 32],
    },
    MlKem768 {
        // Boxed: an ML-KEM-768 decapsulation key is ~3 KiB, far larger than the X25519
        // variant, so box it to keep `ServerKey` (and its `Vec`) compact.
        secret: Box<ml_kem::kem::DecapsulationKey<MlKem768Params>>,
        public: Vec<u8>,
    },
}

impl ServerKey {
    pub fn public_key(&self) -> &[u8] {
        match self {
            Self::X25519 { public, .. } => public,
            Self::MlKem768 { public, .. } => public,
        }
    }

    pub fn relay_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => 32,
            Self::MlKem768 { .. } => 1088,
        }
    }

    pub fn decapsulate(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        match self {
            Self::X25519 { secret, .. } => {
                let public: [u8; 32] = peer.try_into().map_err(|_| KeyError::PeerKey)?;
                if public[31] > 127 {
                    return Err(KeyError::X25519HighBit);
                }
                let shared = secret.diffie_hellman(&PublicKey::from(public));
                if shared.was_contributory() {
                    Ok(Zeroizing::new(shared.to_bytes()))
                } else {
                    Err(KeyError::NonContributory)
                }
            }
            Self::MlKem768 { secret, .. } => {
                let ciphertext: Ciphertext<MlKem768> =
                    Array::try_from(peer).map_err(|_| KeyError::PeerKey)?;
                let shared = secret
                    .decapsulate(&ciphertext)
                    .map_err(|_| KeyError::Decapsulation)?;
                Ok(Zeroizing::new(shared.into()))
            }
        }
    }
}

pub struct ServerKeys {
    keys: Vec<ServerKey>,
    relay_len: usize,
}

impl ServerKeys {
    pub fn from_seeds(seeds: &[KeySeed]) -> Self {
        let mut keys = Vec::with_capacity(seeds.len());
        for seed in seeds {
            match seed {
                KeySeed::X25519(seed) => {
                    let secret = StaticSecret::from(**seed);
                    let public = PublicKey::from(&secret).to_bytes();
                    keys.push(ServerKey::X25519 { secret, public });
                }
                KeySeed::MlKem768(seed) => {
                    let d: B32 = Array::try_from(&seed[..32]).unwrap();
                    let z: B32 = Array::try_from(&seed[32..]).unwrap();
                    let (secret, public) = MlKem768::generate_deterministic(&d, &z);
                    keys.push(ServerKey::MlKem768 {
                        secret: Box::new(secret),
                        public: public.as_bytes().to_vec(),
                    });
                }
            }
        }
        let relay_len = keys
            .iter()
            .map(|key| key.relay_len() + 32)
            .sum::<usize>()
            .saturating_sub(32);
        Self { keys, relay_len }
    }

    pub fn keys(&self) -> &[ServerKey] {
        &self.keys
    }

    pub fn relay_len(&self) -> usize {
        self.relay_len
    }
}

pub fn generate_pfs_response(
    client_mlkem_public: &[u8],
    client_x25519_public: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 64]>), KeyError> {
    type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
    let encoded: Encoded<EncapsulationKey> =
        Array::try_from(client_mlkem_public).map_err(|_| KeyError::PeerKey)?;
    let mlkem_public = EncapsulationKey::from_bytes(&encoded);
    let (ciphertext, mlkem_shared) = mlkem_public
        .encapsulate(&mut OsRng)
        .map_err(|_| KeyError::Encapsulation)?;

    let peer: [u8; 32] = client_x25519_public
        .try_into()
        .map_err(|_| KeyError::PeerKey)?;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    let x25519_shared = secret.diffie_hellman(&PublicKey::from(peer));
    if !x25519_shared.was_contributory() {
        return Err(KeyError::NonContributory);
    }

    let mut response = Vec::with_capacity(1120);
    response.extend_from_slice(ciphertext.as_slice());
    response.extend_from_slice(&public);
    let mut shared = Zeroizing::new([0u8; 64]);
    shared[..32].copy_from_slice(&mlkem_shared);
    shared[32..].copy_from_slice(x25519_shared.as_bytes());
    Ok((response, shared))
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid peer key encoding")]
    PeerKey,
    #[error("X25519 peer key has the high bit set")]
    X25519HighBit,
    #[error("X25519 shared secret is non-contributory")]
    NonContributory,
    #[error("ML-KEM decapsulation failed")]
    Decapsulation,
    #[error("ML-KEM encapsulation failed")]
    Encapsulation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_seed_matches_go_public_key_hash() {
        let seed = Zeroizing::new([0x42; 64]);
        let keys = ServerKeys::from_seeds(&[KeySeed::MlKem768(seed)]);
        assert_eq!(
            blake3::hash(keys.keys()[0].public_key()).to_hex().as_str(),
            "fa88246c20b3b266f6dd762098c644f8758af78f1214964c87e50ac969082eb3"
        );
    }
}
