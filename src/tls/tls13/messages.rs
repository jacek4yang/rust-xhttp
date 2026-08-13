//! TLS 1.3 handshake message helpers for the nginx-profile backend.

use rand::RngCore;

pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;

const EXT_ALPN: u16 = 0x0010;
const EXT_KEY_SHARE: u16 = 0x0033;

pub fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(body);
    out
}

pub fn encrypted_extensions() -> Vec<u8> {
    handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00])
}

pub fn encrypted_extensions_with_alpn(alpn: Option<&str>) -> Vec<u8> {
    let Some(protocol) = alpn else {
        return encrypted_extensions();
    };
    let mut protocol_name_list = Vec::with_capacity(1 + protocol.len());
    protocol_name_list.push(protocol.len() as u8);
    protocol_name_list.extend_from_slice(protocol.as_bytes());

    let mut alpn_body = Vec::with_capacity(2 + protocol_name_list.len());
    alpn_body.extend_from_slice(&(protocol_name_list.len() as u16).to_be_bytes());
    alpn_body.extend_from_slice(&protocol_name_list);

    let mut extensions = Vec::with_capacity(4 + alpn_body.len());
    extensions.extend_from_slice(&EXT_ALPN.to_be_bytes());
    extensions.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&alpn_body);

    let mut body = Vec::with_capacity(2 + extensions.len());
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake_message(HS_ENCRYPTED_EXTENSIONS, &body)
}

pub fn finished_message(verify_data: &[u8]) -> Vec<u8> {
    handshake_message(HS_FINISHED, verify_data)
}

pub fn new_session_ticket(ticket_len: usize) -> Vec<u8> {
    let ticket_len = ticket_len.max(1);
    let mut body = Vec::with_capacity(4 + 4 + 1 + 2 + ticket_len + 2);
    body.extend_from_slice(&7200u32.to_be_bytes());
    body.extend_from_slice(&rand::rngs::OsRng.next_u32().to_be_bytes());
    body.push(0); // ticket_nonce length
    body.extend_from_slice(&(ticket_len as u16).to_be_bytes());
    let start = body.len();
    body.resize(start + ticket_len, 0);
    rand::rngs::OsRng.fill_bytes(&mut body[start..]);
    body.extend_from_slice(&[0x00, 0x00]); // extensions length
    handshake_message(HS_NEW_SESSION_TICKET, &body)
}

pub fn find_server_keyshare(server_hello: &[u8]) -> Option<(u16, usize, usize)> {
    let mut pos = 1 + 3 + 2 + 32;
    let sid_len = *server_hello.get(pos)? as usize;
    pos += 1 + sid_len;
    pos += 2; // cipher_suite
    pos += 1; // compression_method
    let ext_total =
        u16::from_be_bytes([*server_hello.get(pos)?, *server_hello.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([server_hello[pos], server_hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([server_hello[pos + 2], server_hello[pos + 3]]) as usize;
        let ext_data = pos + 4;
        if ext_type == EXT_KEY_SHARE {
            let group = u16::from_be_bytes([
                *server_hello.get(ext_data)?,
                *server_hello.get(ext_data + 1)?,
            ]);
            let kx_len = u16::from_be_bytes([
                *server_hello.get(ext_data + 2)?,
                *server_hello.get(ext_data + 3)?,
            ]) as usize;
            let kx_offset = ext_data + 4;
            server_hello.get(kx_offset..kx_offset + kx_len)?;
            return Some((group, kx_offset, kx_len));
        }
        pos = ext_data + ext_len;
    }
    None
}

pub fn server_hello_cipher_suite(server_hello: &[u8]) -> Option<u16> {
    let mut pos = 1 + 3 + 2 + 32;
    let sid_len = *server_hello.get(pos)? as usize;
    pos += 1 + sid_len;
    Some(u16::from_be_bytes([
        *server_hello.get(pos)?,
        *server_hello.get(pos + 1)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_message_wraps_type_and_length() {
        let msg = handshake_message(HS_FINISHED, &[1, 2, 3]);
        assert_eq!(msg, vec![HS_FINISHED, 0, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn encrypted_extensions_can_be_empty_or_alpn() {
        assert_eq!(
            encrypted_extensions(),
            vec![HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0]
        );
        let msg = encrypted_extensions_with_alpn(Some("h2"));
        assert_eq!(msg[0], HS_ENCRYPTED_EXTENSIONS);
        assert!(msg.windows(2).any(|window| window == b"h2"));
        assert_eq!(encrypted_extensions_with_alpn(None), encrypted_extensions());
    }

    #[test]
    fn new_session_ticket_has_stable_shape_but_random_body() {
        let a = new_session_ticket(32);
        let b = new_session_ticket(32);
        assert_eq!(a[0], HS_NEW_SESSION_TICKET);
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b);
    }

    #[test]
    fn finished_message_wraps_verify_data() {
        let msg = finished_message(&[0xaa; 32]);
        assert_eq!(msg[0], HS_FINISHED);
        assert_eq!(&msg[1..4], &[0, 0, 32]);
        assert_eq!(&msg[4..], &[0xaa; 32]);
    }

    #[test]
    fn server_hello_helpers_find_cipher_and_keyshare() {
        let server_hello = fake_server_hello(0x1301, 0x001d, &[0x55; 32]);
        assert_eq!(server_hello_cipher_suite(&server_hello), Some(0x1301));
        let (group, offset, len) = find_server_keyshare(&server_hello).unwrap();
        assert_eq!(group, 0x001d);
        assert_eq!(len, 32);
        assert_eq!(&server_hello[offset..offset + len], &[0x55; 32]);
    }

    fn fake_server_hello(cipher: u16, group: u16, keyshare: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&group.to_be_bytes());
        ext.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
        ext.extend_from_slice(keyshare);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        handshake_message(HS_SERVER_HELLO, &body)
    }
}
