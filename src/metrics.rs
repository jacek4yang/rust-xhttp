//! Low-overhead process metrics: a flat struct of atomics, shared via `Arc`.
//!
//! Deliberately dependency-free and lock-free. No per-packet work beyond a relaxed
//! atomic add. Never holds secret/plaintext material. A Prometheus/text exporter can be
//! layered on top by reading `snapshot()`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    // gauges (can go up and down)
    pub active_sessions: AtomicI64,
    pub active_h2_connections: AtomicI64,
    pub active_h2_streams: AtomicI64,
    pub pending_packets: AtomicI64,
    pub pending_bytes: AtomicI64,
    pub active_target_conns: AtomicI64,

    // counters (monotonic)
    pub upload_bytes: AtomicU64,
    pub download_bytes: AtomicU64,
    pub vless_auth_failures: AtomicU64,
    pub encryption_handshake_failures: AtomicU64,
    pub ticket_replay_rejections: AtomicU64,
    pub target_connect_failures: AtomicU64,
    pub session_timeouts: AtomicU64,
    pub request_header_rejections: AtomicU64,
    pub request_body_rejections: AtomicU64,
    pub memory_limit_rejections: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn add_gauge(g: &AtomicI64, delta: i64) {
        g.fetch_add(delta, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            active_h2_connections: self.active_h2_connections.load(Ordering::Relaxed),
            active_h2_streams: self.active_h2_streams.load(Ordering::Relaxed),
            pending_packets: self.pending_packets.load(Ordering::Relaxed),
            pending_bytes: self.pending_bytes.load(Ordering::Relaxed),
            active_target_conns: self.active_target_conns.load(Ordering::Relaxed),
            upload_bytes: self.upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.download_bytes.load(Ordering::Relaxed),
            vless_auth_failures: self.vless_auth_failures.load(Ordering::Relaxed),
            encryption_handshake_failures: self
                .encryption_handshake_failures
                .load(Ordering::Relaxed),
            ticket_replay_rejections: self.ticket_replay_rejections.load(Ordering::Relaxed),
            target_connect_failures: self.target_connect_failures.load(Ordering::Relaxed),
            session_timeouts: self.session_timeouts.load(Ordering::Relaxed),
            request_header_rejections: self.request_header_rejections.load(Ordering::Relaxed),
            request_body_rejections: self.request_body_rejections.load(Ordering::Relaxed),
            memory_limit_rejections: self.memory_limit_rejections.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time copy for exporters/logging.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub active_sessions: i64,
    pub active_h2_connections: i64,
    pub active_h2_streams: i64,
    pub pending_packets: i64,
    pub pending_bytes: i64,
    pub active_target_conns: i64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub vless_auth_failures: u64,
    pub encryption_handshake_failures: u64,
    pub ticket_replay_rejections: u64,
    pub target_connect_failures: u64,
    pub session_timeouts: u64,
    pub request_header_rejections: u64,
    pub request_body_rejections: u64,
    pub memory_limit_rejections: u64,
}

impl Snapshot {
    /// Prometheus text exposition format.
    pub fn to_prometheus(&self) -> String {
        let mut s = String::with_capacity(1024);
        macro_rules! line {
            ($name:expr, $val:expr) => {
                s.push_str(concat!("rxhttp_", $name, " "));
                s.push_str(&$val.to_string());
                s.push('\n');
            };
        }
        line!("active_sessions", self.active_sessions);
        line!("active_h2_connections", self.active_h2_connections);
        line!("active_h2_streams", self.active_h2_streams);
        line!("pending_packets", self.pending_packets);
        line!("pending_bytes", self.pending_bytes);
        line!("active_target_conns", self.active_target_conns);
        line!("upload_bytes", self.upload_bytes);
        line!("download_bytes", self.download_bytes);
        line!("vless_auth_failures", self.vless_auth_failures);
        line!(
            "encryption_handshake_failures",
            self.encryption_handshake_failures
        );
        line!("ticket_replay_rejections", self.ticket_replay_rejections);
        line!("target_connect_failures", self.target_connect_failures);
        line!("session_timeouts", self.session_timeouts);
        line!("request_header_rejections", self.request_header_rejections);
        line!("request_body_rejections", self.request_body_rejections);
        line!("memory_limit_rejections", self.memory_limit_rejections);
        s
    }
}
