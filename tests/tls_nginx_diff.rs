use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use rust_xhttp::tls::client_hello::TLS_RECORD_HANDSHAKE;
use rust_xhttp::tls::tls13::keyshare::GROUP_X25519;
use rust_xhttp::tls::tls13::messages::handshake_message;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
#[ignore = "requires RXHTTP_DIFF_NGINX_ADDR, RXHTTP_DIFF_CANDIDATE_ADDR, and RXHTTP_DIFF_SNI"]
fn nginx_profile_server_flight_matches_reference_shape() {
    let Some(nginx_addr) = env_addr("RXHTTP_DIFF_NGINX_ADDR") else {
        eprintln!("RXHTTP_DIFF_NGINX_ADDR is not set");
        return;
    };
    let Some(candidate_addr) = env_addr("RXHTTP_DIFF_CANDIDATE_ADDR") else {
        eprintln!("RXHTTP_DIFF_CANDIDATE_ADDR is not set");
        return;
    };
    let sni = std::env::var("RXHTTP_DIFF_SNI").unwrap_or_else(|_| "localhost".into());
    let probe = client_hello_probe(&sni);

    let nginx = collect_server_flight(nginx_addr, &probe);
    let candidate = collect_server_flight(candidate_addr, &probe);
    let nginx_shape = record_shape(&nginx);
    let candidate_shape = record_shape(&candidate);

    assert!(!nginx_shape.is_empty(), "nginx did not return TLS records");
    assert_eq!(
        candidate_shape, nginx_shape,
        "candidate TLS record shape differs from nginx/OpenSSL"
    );
}

fn env_addr(name: &str) -> Option<SocketAddr> {
    std::env::var(name).ok()?.parse().ok()
}

fn collect_server_flight(addr: SocketAddr, probe: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream.write_all(probe).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => panic!("read from {addr}: {error}"),
        }
    }
    out
}

fn record_shape(bytes: &[u8]) -> Vec<(u8, u16, usize)> {
    let mut pos = 0;
    let mut shape = Vec::new();
    while pos + 5 <= bytes.len() {
        let record_type = bytes[pos];
        let version = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]);
        let len = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as usize;
        if pos + 5 + len > bytes.len() {
            break;
        }
        shape.push((record_type, version, len));
        pos += 5 + len;
    }
    shape
}

fn client_hello_probe(sni: &str) -> Vec<u8> {
    let secret = StaticSecret::from([0x42; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let mut extensions = Vec::new();
    push_ext(&mut extensions, 0x0000, &sni_ext(sni));
    push_ext(&mut extensions, 0x000a, &supported_groups_ext());
    push_ext(&mut extensions, 0x000d, &signature_algorithms_ext());
    push_ext(&mut extensions, 0x0010, &alpn_ext(&["h2", "http/1.1"]));
    push_ext(&mut extensions, 0x002b, &[2, 0x03, 0x04]);
    push_ext(
        &mut extensions,
        0x0033,
        &key_share_ext(GROUP_X25519, &public),
    );

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(32);
    body.extend_from_slice(&[0x99; 32]);
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.extend_from_slice(&0x1302u16.to_be_bytes());
    body.extend_from_slice(&0x1303u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let msg = handshake_message(1, &body);
    let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    record.extend_from_slice(&msg);
    record
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn sni_ext(sni: &str) -> Vec<u8> {
    let mut name = Vec::new();
    name.push(0);
    name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    name.extend_from_slice(sni.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(&name);
    out
}

fn supported_groups_ext() -> Vec<u8> {
    let groups = [GROUP_X25519, 0x0017, 0x0018];
    let mut out = Vec::new();
    out.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for group in groups {
        out.extend_from_slice(&group.to_be_bytes());
    }
    out
}

fn signature_algorithms_ext() -> Vec<u8> {
    let schemes = [0x0403u16, 0x0503, 0x0804, 0x0805, 0x0806];
    let mut out = Vec::new();
    out.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for scheme in schemes {
        out.extend_from_slice(&scheme.to_be_bytes());
    }
    out
}

fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(protocol.len() as u8);
        list.extend_from_slice(protocol.as_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

fn key_share_ext(group: u16, public: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&group.to_be_bytes());
    entry.extend_from_slice(&(public.len() as u16).to_be_bytes());
    entry.extend_from_slice(public);
    let mut out = Vec::new();
    out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry);
    out
}
