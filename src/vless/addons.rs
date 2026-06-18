//! VLESS header Addons (protobuf message `Addons { string Flow = 1; bytes Seed = 2; }`).
//!
//! Port of `proxy/vless/encoding/addons.go` (EncodeHeaderAddons / DecodeHeaderAddons).
//! We hand-encode/decode the two fields rather than pull a protobuf codegen step — the message
//! is trivial and stable. Encoding rule from the Go source: when `Flow == "xtls-rprx-vision"`
//! the full message is marshalled and prefixed with a 1-byte length; otherwise a single `0x00`
//! length byte is written (empty addons).

pub const XRV: &str = "xtls-rprx-vision";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
    pub seed: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum AddonsError {
    #[error("addons protobuf truncated")]
    Truncated,
    #[error("addons length {0} exceeds 255")]
    TooLong(usize),
    #[error("invalid protobuf wire data")]
    BadWire,
    #[error("flow not utf-8")]
    BadUtf8,
}

/// Decode an Addons message body of `len` bytes (the bytes after the 1-byte length prefix).
/// Only fields 1 (Flow, LEN) and 2 (Seed, LEN) are recognized; unknown fields are skipped.
pub fn decode_addons_body(body: &[u8]) -> Result<Addons, AddonsError> {
    let mut addons = Addons::default();
    let mut i = 0;
    while i < body.len() {
        let tag = body[i];
        i += 1;
        let field = tag >> 3;
        let wire = tag & 0x7;
        match (field, wire) {
            (1, 2) | (2, 2) => {
                let (len, adv) = read_varint(&body[i..]).ok_or(AddonsError::BadWire)?;
                i += adv;
                let len = len as usize;
                if i + len > body.len() {
                    return Err(AddonsError::Truncated);
                }
                let slice = &body[i..i + len];
                i += len;
                if field == 1 {
                    addons.flow = std::str::from_utf8(slice)
                        .map_err(|_| AddonsError::BadUtf8)?
                        .to_string();
                } else {
                    addons.seed = slice.to_vec();
                }
            }
            // skip other wire types defensively
            (_, 0) => {
                let (_v, adv) = read_varint(&body[i..]).ok_or(AddonsError::BadWire)?;
                i += adv;
            }
            (_, 2) => {
                let (len, adv) = read_varint(&body[i..]).ok_or(AddonsError::BadWire)?;
                i += adv + len as usize;
            }
            _ => return Err(AddonsError::BadWire),
        }
    }
    Ok(addons)
}

/// Encode the addons as Go does: returns the bytes to write *after* the version/uuid, i.e.
/// `len(1) | body`. For non-Vision flow this is just `[0x00]`.
pub fn encode_addons(addons: &Addons) -> Result<Vec<u8>, AddonsError> {
    if addons.flow != XRV {
        return Ok(vec![0u8]);
    }
    let mut body = Vec::new();
    // field 1: Flow (string)
    body.push((1 << 3) | 2);
    write_varint(&mut body, addons.flow.len() as u64);
    body.extend_from_slice(addons.flow.as_bytes());
    // field 2: Seed (bytes) — only if present
    if !addons.seed.is_empty() {
        body.push((2 << 3) | 2);
        write_varint(&mut body, addons.seed.len() as u64);
        body.extend_from_slice(&addons.seed);
    }
    if body.len() > 255 {
        return Err(AddonsError::TooLong(body.len()));
    }
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, &byte) in b.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vision_roundtrip() {
        let a = Addons {
            flow: XRV.into(),
            seed: vec![],
        };
        let enc = encode_addons(&a).unwrap();
        // length-prefixed body: field1 tag(0x0a) len(16) "xtls-rprx-vision"
        assert_eq!(enc[0] as usize, enc.len() - 1);
        assert_eq!(enc[1], 0x0a);
        assert_eq!(enc[2], 16);
        let dec = decode_addons_body(&enc[1..]).unwrap();
        assert_eq!(dec, a);
    }

    #[test]
    fn empty_flow_is_single_zero() {
        let a = Addons::default();
        assert_eq!(encode_addons(&a).unwrap(), vec![0u8]);
    }

    #[test]
    fn decode_empty_body() {
        assert_eq!(decode_addons_body(&[]).unwrap(), Addons::default());
    }
}
