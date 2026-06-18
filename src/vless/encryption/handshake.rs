use super::config::{EncryptionConfig, EncryptionMode};
use super::keys::{ServerKeys, generate_pfs_response};
use super::record::{AeadState, CipherKind, MAX_NONCE, RecordCipher};
use super::{HeaderXor, derive_key};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

struct TicketSession {
    pfs_key: Zeroizing<[u8; 64]>,
    replay_keys: HashSet<[u8; 32]>,
    expires: Instant,
}

pub struct Server {
    config: EncryptionConfig,
    keys: ServerKeys,
    tickets: Mutex<HashMap<[u8; 16], TicketSession>>,
}

pub struct HandshakeResult {
    pub decrypt: RecordCipher,
    pub encrypt: RecordCipher,
    pub inbound_xor: Option<HeaderXor>,
    pub outbound_xor: Option<HeaderXor>,
    pub zero_rtt: bool,
}

impl Server {
    pub fn new(config: EncryptionConfig) -> Arc<Self> {
        let keys = ServerKeys::from_seeds(&config.keys);
        Arc::new(Self {
            config,
            keys,
            tickets: Mutex::new(HashMap::new()),
        })
    }

    pub async fn handshake<R, Send, SendFuture>(
        &self,
        reader: &mut R,
        mut send: Send,
    ) -> Result<HandshakeResult, HandshakeError>
    where
        R: AsyncRead + Unpin,
        Send: FnMut(Vec<u8>) -> SendFuture,
        SendFuture: Future<Output = Result<(), HandshakeError>>,
    {
        let mut iv_and_relays = vec![0u8; 16 + self.keys.relay_len()];
        reader.read_exact(&mut iv_and_relays).await?;
        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();
        let nfs_key = self.process_relays(&iv, &mut iv_and_relays[16..])?;

        let mut encrypted_length = [0u8; 18];
        reader.read_exact(&mut encrypted_length).await?;
        let (mut nfs_aead, kind, length_bytes) =
            open_first_length(&iv, &nfs_key, &encrypted_length)?;
        let length = u16::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
        if length == 32 {
            return self
                .handshake_zero_rtt(reader, send, iv, nfs_key, nfs_aead, kind)
                .await;
        }
        if length < 1184 + 32 + 16 {
            return Err(HandshakeError::PfsLength(length));
        }

        let mut encrypted_pfs = vec![0u8; length];
        reader.read_exact(&mut encrypted_pfs).await?;
        let pfs_plain = nfs_aead.open_raw(&encrypted_pfs, &[], None)?;
        if pfs_plain.len() < 1216 {
            return Err(HandshakeError::PfsLength(pfs_plain.len()));
        }
        let (pfs_response, pfs_key) =
            generate_pfs_response(&pfs_plain[..1184], &pfs_plain[1184..1216])?;
        let mut united_key = Zeroizing::new(Vec::with_capacity(96));
        united_key.extend_from_slice(&*pfs_key);
        united_key.extend_from_slice(&*nfs_key);

        let mut encrypt_state = AeadState::new(&pfs_plain[..1216], &united_key, kind);
        let decrypt_state = AeadState::new(&pfs_plain[..1216], &united_key, kind);
        let mut server_hello = nfs_aead.seal_raw(&pfs_response, &[], Some(MAX_NONCE))?;

        let (ticket, lifetime) = self.create_ticket(pfs_key);
        server_hello.extend_from_slice(&encrypt_state.seal_raw(&ticket, &[], None)?);

        let padding_len = 111usize;
        server_hello.extend_from_slice(&encrypt_state.seal_raw(
            &((padding_len - 18) as u16).to_be_bytes(),
            &[],
            None,
        )?);
        server_hello.extend_from_slice(&encrypt_state.seal_raw(
            &vec![0u8; padding_len - 34],
            &[],
            None,
        )?);
        debug_assert_eq!(server_hello.len(), 1136 + 32 + padding_len);
        send(server_hello).await?;

        let mut client_padding_length = [0u8; 18];
        reader.read_exact(&mut client_padding_length).await?;
        let length = nfs_aead.open_raw(&client_padding_length, &[], None)?;
        if length.len() != 2 {
            return Err(HandshakeError::Padding);
        }
        let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
        let mut encrypted_padding = vec![0u8; length];
        reader.read_exact(&mut encrypted_padding).await?;
        nfs_aead.open_raw(&encrypted_padding, &[], None)?;

        let (inbound_xor, outbound_xor) = if self.config.mode == EncryptionMode::Random {
            (
                Some(HeaderXor::inbound(&united_key, &iv, 0)),
                Some(HeaderXor::outbound(&united_key, &ticket, 0)),
            )
        } else {
            (None, None)
        };
        let _ = lifetime;
        Ok(HandshakeResult {
            decrypt: RecordCipher::from_state(decrypt_state),
            encrypt: RecordCipher::from_state(encrypt_state),
            inbound_xor,
            outbound_xor,
            zero_rtt: false,
        })
    }

    fn process_relays(
        &self,
        iv: &[u8; 16],
        relays: &mut [u8],
    ) -> Result<Zeroizing<[u8; 32]>, HandshakeError> {
        let mut offset = 0usize;
        let mut previous_ctr: Option<Aes256Ctr> = None;
        let mut nfs_key = Zeroizing::new([0u8; 32]);
        for (index, key) in self.keys.keys().iter().enumerate() {
            let relay_len = key.relay_len();
            let relay = relays
                .get_mut(offset..offset + relay_len)
                .ok_or(HandshakeError::Relay)?;
            if let Some(ctr) = previous_ctr.as_mut() {
                ctr.apply_keystream(&mut relay[..32]);
            }
            if self.config.mode != EncryptionMode::Native {
                let mut ctr = new_ctr(key.public_key(), iv);
                ctr.apply_keystream(relay);
            }
            nfs_key = key.decapsulate(relay)?;
            offset += relay_len;
            if index + 1 < self.keys.keys().len() {
                let hash = relays
                    .get_mut(offset..offset + 32)
                    .ok_or(HandshakeError::Relay)?;
                let mut ctr = new_ctr(&*nfs_key, iv);
                ctr.apply_keystream(hash);
                if hash != blake3::hash(self.keys.keys()[index + 1].public_key()).as_bytes() {
                    return Err(HandshakeError::RelayHash);
                }
                offset += 32;
                previous_ctr = Some(ctr);
            }
        }
        Ok(nfs_key)
    }

    async fn handshake_zero_rtt<R, Send, SendFuture>(
        &self,
        reader: &mut R,
        mut send: Send,
        iv: [u8; 16],
        nfs_key: Zeroizing<[u8; 32]>,
        mut nfs_aead: AeadState,
        kind: CipherKind,
    ) -> Result<HandshakeResult, HandshakeError>
    where
        R: AsyncRead + Unpin,
        Send: FnMut(Vec<u8>) -> SendFuture,
        SendFuture: Future<Output = Result<(), HandshakeError>>,
    {
        if self.config.lifetime_from == 0 && self.config.lifetime_to == 0 {
            return Err(HandshakeError::ZeroRttDisabled);
        }
        let mut encrypted_ticket = [0u8; 32];
        reader.read_exact(&mut encrypted_ticket).await?;
        let ticket_plain = nfs_aead.open_raw(&encrypted_ticket, &[], None)?;
        let ticket: [u8; 16] = ticket_plain
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::Ticket)?;

        self.cleanup_tickets();
        let pfs_key = {
            let mut tickets = self.tickets.lock().unwrap();
            match tickets.get_mut(&ticket) {
                Some(session) => Some(if session.replay_keys.insert(*nfs_key) {
                    Ok(session.pfs_key.clone())
                } else {
                    Err(HandshakeError::Replay)
                }),
                None => None,
            }
        };
        let pfs_key = match pfs_key {
            Some(result) => result?,
            None => {
                self.send_expired_decoy(send).await?;
                return Err(HandshakeError::ExpiredTicket);
            }
        };

        let mut united_key = Zeroizing::new(Vec::with_capacity(96));
        united_key.extend_from_slice(&*pfs_key);
        united_key.extend_from_slice(&*nfs_key);
        let mut server_random = [0u8; 16];
        OsRng.fill_bytes(&mut server_random);
        send(server_random.to_vec()).await?;

        let encrypt_state = AeadState::new(&server_random, &united_key, kind);
        let decrypt_state = AeadState::new(&encrypted_ticket, &united_key, kind);
        let (inbound_xor, outbound_xor) = if self.config.mode == EncryptionMode::Random {
            (
                Some(HeaderXor::inbound(&united_key, &iv, 0)),
                Some(HeaderXor::outbound(&united_key, &server_random, 0)),
            )
        } else {
            (None, None)
        };
        Ok(HandshakeResult {
            decrypt: RecordCipher::from_state(decrypt_state),
            encrypt: RecordCipher::from_state(encrypt_state),
            inbound_xor,
            outbound_xor,
            zero_rtt: true,
        })
    }

    async fn send_expired_decoy<Send, SendFuture>(
        &self,
        mut send: Send,
    ) -> Result<(), HandshakeError>
    where
        Send: FnMut(Vec<u8>) -> SendFuture,
        SendFuture: Future<Output = Result<(), HandshakeError>>,
    {
        let mut decoy = vec![0u8; OsRng.gen_range(1279..=2279)];
        OsRng.fill_bytes(&mut decoy);
        send(decoy).await?;
        Ok(())
    }

    fn create_ticket(&self, pfs_key: Zeroizing<[u8; 64]>) -> ([u8; 16], u16) {
        let lifetime = if self.config.lifetime_to != 0 {
            OsRng.gen_range(self.config.lifetime_from..=self.config.lifetime_to)
        } else if self.config.lifetime_from != 0 {
            OsRng.gen_range(self.config.lifetime_from / 2..=self.config.lifetime_from)
        } else {
            0
        };
        let mut ticket = [0u8; 16];
        OsRng.fill_bytes(&mut ticket);
        ticket[..2].copy_from_slice(&lifetime.to_be_bytes());
        if lifetime != 0 {
            self.tickets.lock().unwrap().insert(
                ticket,
                TicketSession {
                    pfs_key,
                    replay_keys: HashSet::new(),
                    expires: Instant::now() + Duration::from_secs(u64::from(lifetime)),
                },
            );
        }
        (ticket, lifetime)
    }

    fn cleanup_tickets(&self) {
        let now = Instant::now();
        self.tickets
            .lock()
            .unwrap()
            .retain(|_, session| session.expires > now);
    }
}

fn open_first_length(
    iv: &[u8; 16],
    nfs_key: &[u8; 32],
    ciphertext: &[u8; 18],
) -> Result<(AeadState, CipherKind, Vec<u8>), HandshakeError> {
    for kind in [CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305] {
        let mut aead = AeadState::new(iv, nfs_key, kind);
        if let Ok(plain) = aead.open_raw(ciphertext, &[], None) {
            return Ok((aead, kind, plain));
        }
    }
    Err(HandshakeError::Authentication)
}

fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let key = Zeroizing::new(derive_key(b"VLESS", key));
    Aes256Ctr::new((&*key).into(), iv.into())
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("record: {0}")]
    Record(#[from] super::record::RecordError),
    #[error("key exchange: {0}")]
    Key(#[from] super::keys::KeyError),
    #[error("relay chain is malformed")]
    Relay,
    #[error("relay chain hash mismatch")]
    RelayHash,
    #[error("unable to authenticate handshake")]
    Authentication,
    #[error("invalid PFS payload length: {0}")]
    PfsLength(usize),
    #[error("invalid handshake padding")]
    Padding,
    #[error("0-RTT is disabled")]
    ZeroRttDisabled,
    #[error("invalid ticket")]
    Ticket,
    #[error("expired ticket")]
    ExpiredTicket,
    #[error("ticket replay detected")]
    Replay,
    #[error("download stream closed")]
    Send,
}
