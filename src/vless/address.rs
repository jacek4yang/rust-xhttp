//! VLESS address+port codec (`PortThenAddress`).
//!
//! Port of `common/protocol/address.go` for the VLESS `addrParser`:
//!   wire order = port(2 BE), addrType(1), address.
//!   addrType: 1=IPv4(4), 2=Domain(len(1)+bytes), 3=IPv6(16).

use std::net::{Ipv4Addr, Ipv6Addr};

pub const ADDR_TYPE_IPV4: u8 = 1;
pub const ADDR_TYPE_DOMAIN: u8 = 2;
pub const ADDR_TYPE_IPV6: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl Address {
    /// Render as a `host:port` string suitable for tokio connect / resolution.
    pub fn connect_target(&self, port: u16) -> String {
        match self {
            Address::Ipv4(ip) => format!("{ip}:{port}"),
            Address::Ipv6(ip) => format!("[{ip}]:{port}"),
            Address::Domain(d) => format!("{d}:{port}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddrError {
    #[error("buffer underrun while parsing address")]
    Underrun,
    #[error("unknown address type: {0}")]
    UnknownType(u8),
    #[error("invalid domain length 0")]
    EmptyDomain,
    #[error("domain not valid utf-8")]
    BadDomainUtf8,
}

/// Parse port+address from a byte slice, returning the parsed value and bytes consumed.
pub fn parse_port_then_address(buf: &[u8]) -> Result<(u16, Address, usize), AddrError> {
    if buf.len() < 3 {
        return Err(AddrError::Underrun);
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let atype = buf[2];
    let mut off = 3;
    let addr = match atype {
        ADDR_TYPE_IPV4 => {
            if buf.len() < off + 4 {
                return Err(AddrError::Underrun);
            }
            let a = Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
            off += 4;
            Address::Ipv4(a)
        }
        ADDR_TYPE_IPV6 => {
            if buf.len() < off + 16 {
                return Err(AddrError::Underrun);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            Address::Ipv6(Ipv6Addr::from(o))
        }
        ADDR_TYPE_DOMAIN => {
            if buf.len() < off + 1 {
                return Err(AddrError::Underrun);
            }
            let dlen = buf[off] as usize;
            off += 1;
            if dlen == 0 {
                return Err(AddrError::EmptyDomain);
            }
            if buf.len() < off + dlen {
                return Err(AddrError::Underrun);
            }
            let d = std::str::from_utf8(&buf[off..off + dlen])
                .map_err(|_| AddrError::BadDomainUtf8)?
                .to_string();
            off += dlen;
            Address::Domain(d)
        }
        other => return Err(AddrError::UnknownType(other)),
    };
    Ok((port, addr, off))
}

/// Serialize port+address (used when re-encoding for XUDP targets / tests).
pub fn write_port_then_address(out: &mut Vec<u8>, port: u16, addr: &Address) {
    out.extend_from_slice(&port.to_be_bytes());
    match addr {
        Address::Ipv4(ip) => {
            out.push(ADDR_TYPE_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            out.push(ADDR_TYPE_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(d) => {
            out.push(ADDR_TYPE_DOMAIN);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ipv4() {
        let mut b = Vec::new();
        write_port_then_address(&mut b, 443, &Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));
        let (p, a, n) = parse_port_then_address(&b).unwrap();
        assert_eq!(p, 443);
        assert_eq!(a, Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(n, b.len());
    }

    #[test]
    fn roundtrip_domain() {
        let mut b = Vec::new();
        write_port_then_address(&mut b, 8080, &Address::Domain("example.com".into()));
        let (p, a, n) = parse_port_then_address(&b).unwrap();
        assert_eq!(p, 8080);
        assert_eq!(a, Address::Domain("example.com".into()));
        assert_eq!(n, b.len());
    }

    #[test]
    fn roundtrip_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut b = Vec::new();
        write_port_then_address(&mut b, 53, &Address::Ipv6(ip));
        let (p, a, _n) = parse_port_then_address(&b).unwrap();
        assert_eq!(p, 53);
        assert_eq!(a, Address::Ipv6(ip));
    }

    #[test]
    fn rejects_unknown_type() {
        let b = [0u8, 80, 9, 1, 2, 3];
        assert!(matches!(
            parse_port_then_address(&b),
            Err(AddrError::UnknownType(9))
        ));
    }

    #[test]
    fn underrun() {
        assert!(matches!(
            parse_port_then_address(&[0, 80, 1, 1, 2]),
            Err(AddrError::Underrun)
        ));
    }
}
