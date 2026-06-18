//! End-to-end integration tests that drive the real session table → dispatcher →
//! VLESS path the way `runtime::serve` wires it, without standing up the HTTP origin.
//!
//! These exercise the public crate API across module boundaries: an uplink VLESS
//! request fed through [`SessionTable::push_uplink`] (the exact call `origin.rs`
//! makes for a `packet-up` POST) must reach the dispatcher, connect to a target,
//! and stream the echo back through the downlink that a `stream-down` GET drains.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rust_xhttp::dispatcher::Dispatcher;
use rust_xhttp::metrics::Metrics;
use rust_xhttp::session::{Handler, OpenDownload, PushResult, SessionConfig, SessionTable};
use rust_xhttp::vless::{User, Validator};

fn build_table(id: [u8; 16], flow: &str) -> Arc<SessionTable> {
    let validator = Validator::new([User {
        id,
        email: "it".into(),
        flow: flow.into(),
    }]);
    let metrics = Metrics::new();
    let dispatcher = Dispatcher::new(
        validator,
        metrics.clone(),
        16,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let handler: Handler = Arc::new(move |conn| dispatcher.spawn(conn));
    SessionTable::new(SessionConfig::default(), handler, metrics)
}

/// A VLESS TCP request: version | uuid | addons(0) | cmd TCP | port | ipv4 | payload.
fn vless_tcp_request(id: [u8; 16], port: u16, payload: &[u8]) -> Bytes {
    let mut wire = vec![0u8];
    wire.extend_from_slice(&id);
    wire.push(0); // addons length
    wire.push(1); // TCP
    wire.extend_from_slice(&port.to_be_bytes());
    wire.push(1); // ipv4
    wire.extend_from_slice(&[127, 0, 0, 1]);
    wire.extend_from_slice(payload);
    Bytes::from(wire)
}

#[tokio::test]
async fn packet_up_then_download_echoes_through_vless_tcp() {
    // Echo target.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = stream.split();
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let id = [3u8; 16];
    let table = build_table(id, "");
    let session = "integration-session";

    // Open the download first (a GET arriving before the upload is normal) — this is
    // what `origin.rs` does for a `stream-down` request.
    let mut downlink = match table.open_download(session) {
        OpenDownload::Opened(reader) => reader,
        other => panic!("expected download to open, got {:?}", DebugOpen(&other)),
    };

    // Upload the VLESS request as packet-up seq 0.
    let request = vless_tcp_request(id, target.port(), b"ping");
    assert_eq!(
        table.push_uplink(session, 0, request).await,
        Some(PushResult::Accepted)
    );

    // VLESS response header (version=0, empty addons) then the echoed payload.
    let header = downlink.recv().await.expect("response header");
    assert_eq!(header.as_ref(), &[0, 0]);
    let echoed = downlink.recv().await.expect("echo");
    assert_eq!(echoed.as_ref(), b"ping");

    assert_eq!(table.active_sessions(), 1);
    table.remove(session);
    assert_eq!(table.active_sessions(), 0);
}

#[tokio::test]
async fn out_of_order_uploads_are_reordered_before_vless_parse() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = stream.split();
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let id = [4u8; 16];
    let table = build_table(id, "");
    let session = "reorder-session";
    let mut downlink = match table.open_download(session) {
        OpenDownload::Opened(reader) => reader,
        _ => panic!("download did not open"),
    };

    // Split the VLESS request across two packets delivered out of order: the tail
    // (seq 1) arrives before the head (seq 0). The reorder buffer must serialize them
    // so the VLESS parser sees one contiguous, correctly-ordered byte stream.
    let request = vless_tcp_request(id, target.port(), b"reordered");
    let (head, tail) = request.split_at(10);
    assert_eq!(
        table
            .push_uplink(session, 1, Bytes::copy_from_slice(tail))
            .await,
        Some(PushResult::Accepted)
    );
    assert_eq!(
        table
            .push_uplink(session, 0, Bytes::copy_from_slice(head))
            .await,
        Some(PushResult::Accepted)
    );

    assert_eq!(downlink.recv().await.expect("header").as_ref(), &[0, 0]);
    assert_eq!(downlink.recv().await.expect("echo").as_ref(), b"reordered");
}

#[tokio::test]
async fn second_download_for_same_session_conflicts() {
    let id = [5u8; 16];
    let table = build_table(id, "");
    let session = "dup-download";
    let _first = match table.open_download(session) {
        OpenDownload::Opened(reader) => reader,
        _ => panic!("first download did not open"),
    };
    // A second concurrent GET for the same session must not steal the stream.
    assert!(matches!(
        table.open_download(session),
        OpenDownload::Conflict
    ));
}

// Small helper so the `OpenDownload` (which is not `Debug`) can be named in a panic.
struct DebugOpen<'a>(&'a OpenDownload);
impl std::fmt::Debug for DebugOpen<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            OpenDownload::Opened(_) => f.write_str("Opened"),
            OpenDownload::Conflict => f.write_str("Conflict"),
            OpenDownload::Capacity => f.write_str("Capacity"),
        }
    }
}
