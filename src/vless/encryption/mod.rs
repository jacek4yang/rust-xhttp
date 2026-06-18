//! Server-side VLESS-Encryption primitives.

mod config;
mod handshake;
mod kdf;
mod keys;
mod record;
mod stream;
mod xor;

pub use config::{EncryptionConfig, EncryptionMode, KeySeed};
pub use handshake::{HandshakeError, HandshakeResult, Server};
pub use kdf::derive_key;
pub use keys::{ServerKey, ServerKeys};
pub use record::{CipherKind, MAX_NONCE, RecordCipher, RecordError, decode_header, encode_header};
pub use stream::EncryptedReader;
pub use xor::{HeaderXor, XorError};
