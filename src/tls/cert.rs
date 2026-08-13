//! Certificate-chain and signing helpers for the self-contained TLS 1.3 backend.

use std::fmt;
use std::fs;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::TlsConfig;

const SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl AsRef<[u8]> for CertificateDer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for CertificateDer {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateKeyDer {
    Pkcs1(Vec<u8>),
    Sec1(Vec<u8>),
    Pkcs8(Vec<u8>),
}

#[derive(Clone)]
pub struct CertifiedIdentity {
    cert_chain: Arc<[CertificateDer]>,
    signing_key: Arc<dyn SigningKey>,
}

impl CertifiedIdentity {
    pub fn from_config(config: &TlsConfig) -> Result<Self, super::Error> {
        let cert_chain = load_cert_chain(config)?;
        let private_key = load_private_key(config)?;
        let signing_key = RingSigningKey::from_private_key(&private_key)?;
        let (_, leaf) = X509Certificate::from_der(cert_chain[0].as_ref())
            .map_err(|_| super::Error::InvalidCertificate)?;
        if leaf.public_key().subject_public_key.data.as_ref() != signing_key.public_key() {
            return Err(super::Error::CertificateKeyMismatch);
        }
        Self::new(cert_chain, signing_key)
    }

    pub fn new(
        cert_chain: Vec<CertificateDer>,
        signing_key: Arc<dyn SigningKey>,
    ) -> Result<Self, super::Error> {
        if cert_chain.is_empty() {
            return Err(super::Error::MissingCertificate);
        }
        Ok(Self {
            cert_chain: Arc::from(cert_chain),
            signing_key,
        })
    }

    pub fn cert_chain(&self) -> &[CertificateDer] {
        &self.cert_chain
    }

    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signing_key.algorithm()
    }

    pub fn certificate_message(&self) -> Vec<u8> {
        certificate_message(&self.cert_chain)
    }

    pub fn sign_certificate_verify(
        &self,
        transcript_hash: &[u8],
        offered_schemes: &[SignatureScheme],
    ) -> Result<Vec<u8>, CertificateVerifyError> {
        let signer = self
            .signing_key
            .choose_scheme(offered_schemes)
            .ok_or(CertificateVerifyError::NoSupportedSignatureScheme)?;
        let to_sign = certificate_verify_content(transcript_hash);
        let signature = signer
            .sign(&to_sign)
            .map_err(CertificateVerifyError::Signing)?;
        Ok(certificate_verify_message(signer.scheme(), &signature))
    }
}

pub trait SigningKey: fmt::Debug + Send + Sync {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;
    fn algorithm(&self) -> SignatureAlgorithm;
    fn public_key(&self) -> &[u8];
}

pub trait Signer: fmt::Debug + Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
    fn scheme(&self) -> SignatureScheme;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Rsa,
    Ecdsa,
    Ed25519,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureScheme(u16);

impl SignatureScheme {
    pub const ECDSA_NISTP256_SHA256: Self = Self(0x0403);
    pub const ECDSA_NISTP384_SHA384: Self = Self(0x0503);
    pub const RSA_PSS_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);

    pub fn to_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::ECDSA_NISTP256_SHA256 => "ECDSA_NISTP256_SHA256",
            Self::ECDSA_NISTP384_SHA384 => "ECDSA_NISTP384_SHA384",
            Self::RSA_PSS_SHA256 => "RSA_PSS_SHA256",
            Self::RSA_PSS_SHA384 => "RSA_PSS_SHA384",
            Self::RSA_PSS_SHA512 => "RSA_PSS_SHA512",
            Self::ED25519 => "ED25519",
            _ => return write!(f, "SignatureScheme(0x{:04x})", self.0),
        };
        f.write_str(name)
    }
}

impl From<u16> for SignatureScheme {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<SignatureScheme> for u16 {
    fn from(value: SignatureScheme) -> Self {
        value.0
    }
}

#[derive(Debug)]
enum RingSigningKey {
    Rsa(Arc<RsaKeyPair>),
    EcdsaP256(Arc<EcdsaKeyPair>),
    EcdsaP384(Arc<EcdsaKeyPair>),
    Ed25519(Arc<Ed25519KeyPair>),
}

impl RingSigningKey {
    fn from_private_key(key: &PrivateKeyDer) -> Result<Arc<dyn SigningKey>, SignError> {
        if let Some(key_pair) = parse_rsa_key(key) {
            return Ok(Arc::new(Self::Rsa(Arc::new(key_pair))));
        }
        if let PrivateKeyDer::Pkcs8(pkcs8) = key {
            let rng = SystemRandom::new();
            if let Ok(key_pair) =
                EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
            {
                return Ok(Arc::new(Self::EcdsaP256(Arc::new(key_pair))));
            }
            if let Ok(key_pair) =
                EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rng)
            {
                return Ok(Arc::new(Self::EcdsaP384(Arc::new(key_pair))));
            }
            if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(pkcs8) {
                return Ok(Arc::new(Self::Ed25519(Arc::new(key_pair))));
            }
        }
        Err(SignError::UnsupportedPrivateKey)
    }
}

impl SigningKey for RingSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        match self {
            Self::Rsa(key) => choose_first(
                offered,
                &[
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                ],
            )
            .map(|scheme| {
                Box::new(RsaSigner {
                    key: key.clone(),
                    scheme,
                }) as Box<dyn Signer>
            }),
            Self::EcdsaP256(key) => offered
                .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
                .then(|| {
                    Box::new(EcdsaSigner {
                        key: key.clone(),
                        scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                    }) as Box<dyn Signer>
                }),
            Self::EcdsaP384(key) => offered
                .contains(&SignatureScheme::ECDSA_NISTP384_SHA384)
                .then(|| {
                    Box::new(EcdsaSigner {
                        key: key.clone(),
                        scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
                    }) as Box<dyn Signer>
                }),
            Self::Ed25519(key) => offered
                .contains(&SignatureScheme::ED25519)
                .then(|| Box::new(Ed25519Signer { key: key.clone() }) as Box<dyn Signer>),
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Rsa(_) => SignatureAlgorithm::Rsa,
            Self::EcdsaP256(_) | Self::EcdsaP384(_) => SignatureAlgorithm::Ecdsa,
            Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    fn public_key(&self) -> &[u8] {
        match self {
            Self::Rsa(key) => key.public_key().as_ref(),
            Self::EcdsaP256(key) | Self::EcdsaP384(key) => key.public_key().as_ref(),
            Self::Ed25519(key) => key.public_key().as_ref(),
        }
    }
}

fn parse_rsa_key(key: &PrivateKeyDer) -> Option<RsaKeyPair> {
    match key {
        PrivateKeyDer::Pkcs1(pkcs1) => RsaKeyPair::from_der(pkcs1).ok(),
        PrivateKeyDer::Pkcs8(pkcs8) => RsaKeyPair::from_pkcs8(pkcs8).ok(),
        PrivateKeyDer::Sec1(_) => None,
    }
}

fn choose_first(
    offered: &[SignatureScheme],
    allowed: &[SignatureScheme],
) -> Option<SignatureScheme> {
    offered
        .iter()
        .copied()
        .find(|scheme| allowed.contains(scheme))
}

#[derive(Debug)]
struct RsaSigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let algorithm = match self.scheme {
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => return Err(SignError::UnsupportedSignatureScheme(self.scheme)),
        };
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(algorithm, &rng, message, &mut signature)
            .map_err(|_| SignError::SigningFailed)?;
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct EcdsaSigner {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let rng = SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| SignError::SigningFailed)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct Ed25519Signer {
    key: Arc<Ed25519KeyPair>,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.key.sign(message).as_ref().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    #[error("unsupported TLS private key format or algorithm")]
    UnsupportedPrivateKey,
    #[error("unsupported TLS signature scheme {0:?}")]
    UnsupportedSignatureScheme(SignatureScheme),
    #[error("TLS signature generation failed")]
    SigningFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateVerifyError {
    #[error("no supported TLS 1.3 signature scheme for configured key")]
    NoSupportedSignatureScheme,
    #[error("certificate verify signing failed: {0}")]
    Signing(#[source] SignError),
}

pub fn load_cert_chain(config: &TlsConfig) -> Result<Vec<CertificateDer>, super::Error> {
    let sections = pem_sections(&fs::read(&config.cert)?)?;
    let cert_chain: Vec<CertificateDer> = sections
        .into_iter()
        .filter(|section| section.label == "CERTIFICATE")
        .map(|section| CertificateDer::from(section.der))
        .collect();
    if cert_chain.is_empty() {
        return Err(super::Error::MissingCertificate);
    }
    Ok(cert_chain)
}

pub fn load_private_key(config: &TlsConfig) -> Result<PrivateKeyDer, super::Error> {
    for section in pem_sections(&fs::read(&config.key)?)? {
        match section.label.as_str() {
            "RSA PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs1(section.der)),
            "EC PRIVATE KEY" => return Ok(PrivateKeyDer::Sec1(section.der)),
            "PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs8(section.der)),
            _ => {}
        }
    }
    Err(super::Error::MissingPrivateKey)
}

pub fn default_tls13_signature_schemes() -> &'static [SignatureScheme] {
    &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ]
}

pub fn certificate_message(cert_chain: &[CertificateDer]) -> Vec<u8> {
    let mut cert_list = Vec::new();
    for cert in cert_chain {
        push_u24(&mut cert_list, cert.as_ref().len());
        cert_list.extend_from_slice(cert.as_ref());
        cert_list.extend_from_slice(&0u16.to_be_bytes());
    }

    let mut body = Vec::with_capacity(1 + 3 + cert_list.len());
    body.push(0); // certificate_request_context length
    push_u24(&mut body, cert_list.len());
    body.extend_from_slice(&cert_list);
    super::tls13::messages::handshake_message(super::tls13::messages::HS_CERTIFICATE, &body)
}

pub fn certificate_verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(64 + SERVER_CERT_VERIFY_CONTEXT.len() + 1 + transcript_hash.len());
    out.extend_from_slice(&[0x20; 64]);
    out.extend_from_slice(SERVER_CERT_VERIFY_CONTEXT);
    out.push(0);
    out.extend_from_slice(transcript_hash);
    out
}

pub fn certificate_verify_message(scheme: SignatureScheme, signature: &[u8]) -> Vec<u8> {
    let scheme_id = u16::from(scheme);
    let mut body = Vec::with_capacity(4 + signature.len());
    body.extend_from_slice(&scheme_id.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    super::tls13::messages::handshake_message(super::tls13::messages::HS_CERTIFICATE_VERIFY, &body)
}

fn push_u24(out: &mut Vec<u8>, len: usize) {
    let len = len as u32;
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
}

#[derive(Debug)]
struct PemSection {
    label: String,
    der: Vec<u8>,
}

fn pem_sections(input: &[u8]) -> Result<Vec<PemSection>, super::Error> {
    let text = std::str::from_utf8(input).map_err(|_| super::Error::Pem)?;
    let mut sections = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|value| value.strip_suffix("-----"))
        else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut found_end = false;
        for line in lines.by_ref() {
            if line == end {
                found_end = true;
                break;
            }
            body.extend(line.chars().filter(|ch| !ch.is_ascii_whitespace()));
        }
        if !found_end {
            return Err(super::Error::Pem);
        }
        let der = STANDARD.decode(body).map_err(|_| super::Error::Pem)?;
        sections.push(PemSection {
            label: label.to_string(),
            der,
        });
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_message_encodes_tls13_certificate_list() {
        let cert_a = CertificateDer::from(vec![1, 2, 3]);
        let cert_b = CertificateDer::from(vec![4, 5]);
        let msg = certificate_message(&[cert_a, cert_b]);

        assert_eq!(msg[0], super::super::tls13::messages::HS_CERTIFICATE);
        assert_eq!(&msg[1..4], &[0, 0, 19]);
        assert_eq!(msg[4], 0);
        assert_eq!(&msg[5..8], &[0, 0, 15]);
        assert_eq!(&msg[8..11], &[0, 0, 3]);
        assert_eq!(&msg[11..14], &[1, 2, 3]);
        assert_eq!(&msg[14..16], &[0, 0]);
        assert_eq!(&msg[16..19], &[0, 0, 2]);
        assert_eq!(&msg[19..21], &[4, 5]);
        assert_eq!(&msg[21..23], &[0, 0]);
    }

    #[test]
    fn certificate_verify_content_matches_tls13_context_string() {
        let content = certificate_verify_content(&[0xaa; 32]);
        assert_eq!(&content[..64], &[0x20; 64]);
        assert_eq!(
            &content[64..64 + SERVER_CERT_VERIFY_CONTEXT.len()],
            SERVER_CERT_VERIFY_CONTEXT
        );
        assert_eq!(content[64 + SERVER_CERT_VERIFY_CONTEXT.len()], 0);
        assert_eq!(
            &content[65 + SERVER_CERT_VERIFY_CONTEXT.len()..],
            &[0xaa; 32]
        );
    }

    #[test]
    fn certificate_verify_message_wraps_scheme_and_signature() {
        let msg = certificate_verify_message(SignatureScheme::ECDSA_NISTP256_SHA256, &[9, 8, 7]);
        assert_eq!(msg[0], super::super::tls13::messages::HS_CERTIFICATE_VERIFY);
        assert_eq!(&msg[1..4], &[0, 0, 7]);
        assert_eq!(&msg[4..6], &[0x04, 0x03]);
        assert_eq!(&msg[6..8], &[0, 3]);
        assert_eq!(&msg[8..], &[9, 8, 7]);
    }

    #[test]
    fn certified_identity_signs_certificate_verify() {
        let identity = CertifiedIdentity::new(
            vec![CertificateDer::from(vec![1, 2, 3])],
            Arc::new(FakeSigningKey),
        )
        .unwrap();
        let msg = identity
            .sign_certificate_verify(&[0x55; 32], &[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();

        assert_eq!(msg[0], super::super::tls13::messages::HS_CERTIFICATE_VERIFY);
        assert_eq!(&msg[4..6], &[0x04, 0x03]);
        assert!(msg.windows(3).any(|window| window == [0x55, 0x55, 0x55]));
    }

    #[test]
    fn certified_identity_rejects_empty_chain() {
        match CertifiedIdentity::new(Vec::new(), Arc::new(FakeSigningKey)) {
            Ok(_) => panic!("empty certificate chain was accepted"),
            Err(err) => assert!(matches!(err, super::super::Error::MissingCertificate)),
        }
    }

    #[derive(Debug)]
    struct FakeSigningKey;

    impl SigningKey for FakeSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
                .then(|| Box::new(FakeSigner) as Box<dyn Signer>)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ecdsa
        }

        fn public_key(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Debug)]
    struct FakeSigner;

    impl Signer for FakeSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
            Ok(message.to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ECDSA_NISTP256_SHA256
        }
    }
}
