use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    Native,
    XorPublic,
    Random,
}

#[derive(Clone)]
pub enum KeySeed {
    X25519(Zeroizing<[u8; 32]>),
    MlKem768(Zeroizing<[u8; 64]>),
}

#[derive(Clone)]
pub struct EncryptionConfig {
    pub mode: EncryptionMode,
    pub lifetime_from: u16,
    pub lifetime_to: u16,
    pub padding: String,
    pub keys: Vec<KeySeed>,
}

impl EncryptionConfig {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let mut parts = value.split('.');
        if parts.next() != Some("mlkem768x25519plus") {
            return Err(ConfigError::Scheme);
        }
        let mode = match parts.next() {
            Some("native") => EncryptionMode::Native,
            Some("xorpub") => EncryptionMode::XorPublic,
            Some("random") => EncryptionMode::Random,
            _ => return Err(ConfigError::Mode),
        };
        let lifetime = parts.next().ok_or(ConfigError::Lifetime)?;
        let lifetime = lifetime.strip_suffix('s').ok_or(ConfigError::Lifetime)?;
        let (lifetime_from, lifetime_to) = match lifetime.split_once('-') {
            Some((from, to)) => (parse_lifetime(from)?, parse_lifetime(to)?),
            None => (parse_lifetime(lifetime)?, 0),
        };

        let mut padding = Vec::new();
        let mut keys = Vec::new();
        for part in parts {
            if part.len() < 20 {
                if !keys.is_empty() {
                    return Err(ConfigError::PaddingAfterKey);
                }
                padding.push(part);
                continue;
            }
            let decoded = URL_SAFE_NO_PAD.decode(part).map_err(|_| ConfigError::Key)?;
            match decoded.len() {
                32 => keys.push(KeySeed::X25519(Zeroizing::new(decoded.try_into().unwrap()))),
                64 => keys.push(KeySeed::MlKem768(Zeroizing::new(
                    decoded.try_into().unwrap(),
                ))),
                _ => return Err(ConfigError::Key),
            }
        }
        if keys.is_empty() {
            return Err(ConfigError::Key);
        }
        Ok(Self {
            mode,
            lifetime_from,
            lifetime_to,
            padding: padding.join("."),
            keys,
        })
    }
}

fn parse_lifetime(value: &str) -> Result<u16, ConfigError> {
    value.parse().map_err(|_| ConfigError::Lifetime)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unsupported VLESS-Encryption scheme")]
    Scheme,
    #[error("unsupported VLESS-Encryption mode")]
    Mode,
    #[error("invalid ticket lifetime")]
    Lifetime,
    #[error("invalid server key seed")]
    Key,
    #[error("padding parameters must precede keys")]
    PaddingAfterKey,
}
