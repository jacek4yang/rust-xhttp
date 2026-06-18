//! VLESS request/response header codec.
//!
//! Port of `proxy/vless/encoding/encoding.go` (DecodeRequestHeader / EncodeResponseHeader).
//! Request wire layout (version 0):
//!   `version(1)=0x00 | uuid(16) | addonsLen(1) | addons(body) | command(1) | [port+addr]`
//! where port+addr is present only for TCP/UDP commands. Response layout:
//!   `version(1) | addonsLen(1) | addons(body)` — the server sends empty addons (`00 00`).

use super::addons::{Addons, AddonsError, decode_addons_body, encode_addons};
use super::address::{AddrError, Address, parse_port_then_address};
use super::validator::{User, Validator};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
    Reverse,
}

impl Command {
    fn from_byte(b: u8) -> Option<Command> {
        match b {
            0x01 => Some(Command::Tcp),
            0x02 => Some(Command::Udp),
            0x03 => Some(Command::Mux),
            0x04 => Some(Command::Reverse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub version: u8,
    pub raw_id: [u8; 16],
    pub command: Command,
    /// Present for TCP/UDP; None for Mux/Reverse.
    pub address: Option<Address>,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid request version: {0}")]
    BadVersion(u8),
    #[error("authentication failed")]
    AuthFailed,
    #[error("unknown command byte: {0}")]
    BadCommand(u8),
    #[error("reverse command not supported")]
    ReverseUnsupported,
    #[error("addons: {0}")]
    Addons(#[from] AddonsError),
    #[error("address: {0}")]
    Address(#[from] AddrError),
}

/// Decode and authenticate a VLESS request header from `reader`.
/// Returns the matched user, the parsed header, and the request addons.
///
/// Authentication failure is surfaced as a single `AuthFailed` (no distinction between
/// "user unknown" and other reasons) so callers can take one uniform, cheap reject path.
pub async fn decode_request_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    validator: &Validator,
) -> Result<(User, RequestHeader, Addons), HeaderError> {
    let version = reader.read_u8().await?;
    if version != VERSION {
        return Err(HeaderError::BadVersion(version));
    }

    let mut raw_id = [0u8; 16];
    reader.read_exact(&mut raw_id).await?;
    let user = validator.get(&raw_id).ok_or(HeaderError::AuthFailed)?;

    let addons_len = reader.read_u8().await? as usize;
    let addons = if addons_len != 0 {
        let mut body = vec![0u8; addons_len];
        reader.read_exact(&mut body).await?;
        decode_addons_body(&body)?
    } else {
        Addons::default()
    };

    let cmd_byte = reader.read_u8().await?;
    let command = Command::from_byte(cmd_byte).ok_or(HeaderError::BadCommand(cmd_byte))?;
    if command == Command::Reverse {
        return Err(HeaderError::ReverseUnsupported);
    }

    let (address, port) = match command {
        Command::Tcp | Command::Udp => {
            let (port, addr) = read_address_port(reader).await?;
            (Some(addr), port)
        }
        // Mux target is the v1.mux.cool placeholder; no address on the wire.
        Command::Mux | Command::Reverse => (None, 0),
    };

    Ok((
        user,
        RequestHeader {
            version,
            raw_id,
            command,
            address,
            port,
        },
        addons,
    ))
}

/// Read a port-then-address, pulling exactly as many bytes as the type requires.
async fn read_address_port<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(u16, Address), HeaderError> {
    // port(2) + type(1)
    let mut head = [0u8; 3];
    reader.read_exact(&mut head).await?;
    let extra = match head[2] {
        super::address::ADDR_TYPE_IPV4 => 4,
        super::address::ADDR_TYPE_IPV6 => 16,
        super::address::ADDR_TYPE_DOMAIN => {
            let dlen = reader.read_u8().await? as usize;
            // re-buffer: we already consumed the domain length byte; read domain then assemble
            let mut domain = vec![0u8; dlen];
            reader.read_exact(&mut domain).await?;
            let mut full = Vec::with_capacity(3 + 1 + dlen);
            full.extend_from_slice(&head);
            full.push(dlen as u8);
            full.extend_from_slice(&domain);
            let (port, addr, _n) = parse_port_then_address(&full)?;
            return Ok((port, addr));
        }
        other => return Err(HeaderError::Address(AddrError::UnknownType(other))),
    };
    let mut rest = vec![0u8; extra];
    reader.read_exact(&mut rest).await?;
    let mut full = Vec::with_capacity(3 + extra);
    full.extend_from_slice(&head);
    full.extend_from_slice(&rest);
    let (port, addr, _n) = parse_port_then_address(&full)?;
    Ok((port, addr))
}

/// Encode the VLESS response header: `version | addons`. The server always sends empty addons.
pub fn encode_response_header(version: u8, addons: &Addons) -> Result<Vec<u8>, HeaderError> {
    let mut out = Vec::with_capacity(2);
    out.push(version);
    out.extend_from_slice(&encode_addons(addons)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::addons::XRV;
    use std::io::Cursor;

    fn validator_with(id: [u8; 16], flow: &str) -> Validator {
        Validator::new([User {
            id,
            email: "t".into(),
            flow: flow.into(),
        }])
    }

    #[tokio::test]
    async fn decode_tcp_ipv4() {
        let id = [7u8; 16];
        let v = validator_with(id, "");
        // build: version, uuid, addons(0), cmd TCP(1), port 443, type ipv4, 1.2.3.4
        let mut wire = vec![0u8];
        wire.extend_from_slice(&id);
        wire.push(0); // addons len
        wire.push(0x01); // TCP
        wire.extend_from_slice(&443u16.to_be_bytes());
        wire.push(0x01); // ipv4
        wire.extend_from_slice(&[1, 2, 3, 4]);
        wire.extend_from_slice(b"payload"); // trailing body, must be left unread

        let mut cur = Cursor::new(wire);
        let (user, hdr, addons) = decode_request_header(&mut cur, &v).await.unwrap();
        assert_eq!(user.email, "t");
        assert_eq!(hdr.command, Command::Tcp);
        assert_eq!(hdr.port, 443);
        assert_eq!(
            hdr.address,
            Some(Address::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(addons, Addons::default());
        // ensure body remains
        let pos = cur.position() as usize;
        assert_eq!(&cur.into_inner()[pos..], b"payload");
    }

    #[tokio::test]
    async fn decode_vision_domain() {
        let id = [9u8; 16];
        let v = validator_with(id, XRV);
        let mut wire = vec![0u8];
        wire.extend_from_slice(&id);
        // addons: vision
        let enc = encode_addons(&Addons {
            flow: XRV.into(),
            seed: vec![],
        })
        .unwrap();
        wire.extend_from_slice(&enc);
        wire.push(0x01); // TCP
        wire.extend_from_slice(&80u16.to_be_bytes());
        wire.push(0x02); // domain
        wire.push(11);
        wire.extend_from_slice(b"example.com");

        let mut cur = Cursor::new(wire);
        let (_u, hdr, addons) = decode_request_header(&mut cur, &v).await.unwrap();
        assert_eq!(addons.flow, XRV);
        assert_eq!(hdr.address, Some(Address::Domain("example.com".into())));
        assert_eq!(hdr.port, 80);
    }

    #[tokio::test]
    async fn auth_failure_uniform() {
        let v = validator_with([1u8; 16], "");
        let mut wire = vec![0u8];
        wire.extend_from_slice(&[2u8; 16]); // wrong user
        let mut cur = Cursor::new(wire);
        let err = decode_request_header(&mut cur, &v).await.unwrap_err();
        assert!(matches!(err, HeaderError::AuthFailed));
    }

    #[test]
    fn response_header_is_two_zero_bytes() {
        let out = encode_response_header(0, &Addons::default()).unwrap();
        assert_eq!(out, vec![0u8, 0u8]);
    }
}
