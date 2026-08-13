//! XUDP Mux frame and plain VLESS UDP codecs.

use crate::vless::Address;
use crate::vless::address::parse_port_then_address;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const STATUS_NEW: u8 = 1;
pub const STATUS_KEEP: u8 = 2;
pub const STATUS_END: u8 = 3;
pub const STATUS_KEEP_ALIVE: u8 = 4;
pub const OPTION_DATA: u8 = 1;
pub const NETWORK_UDP: u8 = 2;
pub const MAX_METADATA_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: Address,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    pub target: Option<Target>,
    pub global_id: Option<[u8; 8]>,
    pub payload: Bytes,
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, XudpError> {
    let metadata_len = reader.read_u16().await? as usize;
    if !(4..=MAX_METADATA_LEN).contains(&metadata_len) {
        return Err(XudpError::MetadataLength(metadata_len));
    }
    let mut metadata = vec![0u8; metadata_len];
    reader.read_exact(&mut metadata).await?;
    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let option = metadata[3];
    if !matches!(
        status,
        STATUS_NEW | STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE
    ) {
        return Err(XudpError::Status(status));
    }

    let mut target = None;
    let mut global_id = None;
    let has_target = status == STATUS_NEW
        || (status == STATUS_KEEP && metadata.get(4).copied() == Some(NETWORK_UDP));
    if has_target {
        if metadata.get(4).copied() != Some(NETWORK_UDP) {
            return Err(XudpError::Network(metadata.get(4).copied().unwrap_or(0)));
        }
        let (port, address, consumed) = parse_port_then_address(&metadata[5..])?;
        let tail = &metadata[5 + consumed..];
        target = Some(Target { address, port });
        if status == STATUS_NEW && option & OPTION_DATA != 0 && tail.len() >= 8 {
            let mut id = [0u8; 8];
            id.copy_from_slice(&tail[..8]);
            global_id = Some(id);
        }
    }

    let payload = if option & OPTION_DATA != 0 {
        let payload_len = reader.read_u16().await? as usize;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        Bytes::from(payload)
    } else {
        Bytes::new()
    };
    Ok(Frame {
        session_id,
        status,
        option,
        target,
        global_id,
        payload,
    })
}

pub fn encode_frame(frame: &Frame) -> Result<Bytes, XudpError> {
    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&frame.session_id.to_be_bytes());
    metadata.push(frame.status);
    metadata.push(frame.option);
    if let Some(target) = &frame.target {
        metadata.push(NETWORK_UDP);
        crate::vless::address::write_port_then_address(&mut metadata, target.port, &target.address);
        if frame.status == STATUS_NEW
            && let Some(global_id) = frame.global_id
        {
            metadata.extend_from_slice(&global_id);
        }
    }
    if metadata.len() > MAX_METADATA_LEN {
        return Err(XudpError::MetadataLength(metadata.len()));
    }
    if frame.payload.len() > u16::MAX as usize {
        return Err(XudpError::PayloadLength(frame.payload.len()));
    }
    let mut out = Vec::with_capacity(metadata.len() + frame.payload.len() + 4);
    out.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    out.extend_from_slice(&metadata);
    if frame.option & OPTION_DATA != 0 {
        out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&frame.payload);
    }
    Ok(Bytes::from(out))
}

pub async fn read_plain_datagram<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Bytes, XudpError> {
    let len = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Bytes::from(payload))
}

pub fn encode_plain_datagram(payload: &[u8]) -> Result<Bytes, XudpError> {
    if payload.len() > u16::MAX as usize {
        return Err(XudpError::PayloadLength(payload.len()));
    }
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(Bytes::from(out))
}

#[derive(Debug, thiserror::Error)]
pub enum XudpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("metadata length is invalid: {0}")]
    MetadataLength(usize),
    #[error("payload length exceeds u16: {0}")]
    PayloadLength(usize),
    #[error("unknown session status: {0}")]
    Status(u8),
    #[error("unsupported target network: {0}")]
    Network(u8),
    #[error("address: {0}")]
    Address(#[from] crate::vless::address::AddrError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn new_udp_frame_roundtrip() {
        let frame = Frame {
            session_id: 0,
            status: STATUS_NEW,
            option: OPTION_DATA,
            target: Some(Target {
                address: Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 53,
            }),
            global_id: Some([9; 8]),
            payload: Bytes::from_static(b"dns"),
        };
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), 20);
        let decoded = read_frame(&mut Cursor::new(encoded)).await.unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn keep_with_ipv6_target_roundtrip() {
        let frame = Frame {
            session_id: 42,
            status: STATUS_KEEP,
            option: OPTION_DATA,
            target: Some(Target {
                address: Address::Ipv6(Ipv6Addr::LOCALHOST),
                port: 5353,
            }),
            global_id: None,
            payload: Bytes::from_static(b"x"),
        };
        let decoded = read_frame(&mut Cursor::new(encode_frame(&frame).unwrap()))
            .await
            .unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn plain_udp_roundtrip() {
        let encoded = encode_plain_datagram(b"hello").unwrap();
        assert_eq!(
            read_plain_datagram(&mut Cursor::new(encoded))
                .await
                .unwrap(),
            Bytes::from_static(b"hello")
        );
    }
}
