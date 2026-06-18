//! XHTTP session layer: sharded session table + bounded uplink reorder + bounded downlink.
//!
//! A *session* is the logical VLESS connection multiplexed over many short HTTP requests:
//!   * `packet-up` POSTs (each carrying one seq'd packet) feed the uplink reorder buffer.
//!   * one long-lived `stream-down` GET drains the downlink.
//!
//! Mirrors `xray-core/transport/internet/splithttp/hub.go` session lifecycle:
//!   * lazy creation on first request,
//!   * a grace TTL (default 30s) during which an un-GET'd session may be reaped,
//!   * once the GET opens, the session lives as long as that GET.

mod downlink;
mod reorder;

pub use downlink::{DownlinkReader, DownlinkSink, channel as downlink_channel};
pub use reorder::{PushResult, UplinkReader, UplinkSink, channel as uplink_channel};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The duplex handed to the protocol stack when a session is created.
pub struct SessionConn {
    /// Ordered uplink bytes (client → server).
    pub reader: UplinkReader,
    /// Downlink sink (server → client). Bounded; awaits when the GET is slow/absent.
    pub writer: DownlinkSink,
    /// Stable 64-bit hash of the session id (safe for logs/sharding; never the raw id).
    pub id_hash: u64,
}

/// Spawns the protocol task for a new session. Provided by the server crate to avoid a
/// dependency cycle (session layer must not know about VLESS).
pub type Handler = Arc<dyn Fn(SessionConn) + Send + Sync>;

struct Session {
    uplink: UplinkSink,
    downlink_reader: Mutex<Option<DownlinkReader>>,
    fully_connected: AtomicBool,
}

pub struct SessionConfig {
    pub shards: usize,
    pub max_sessions: usize,
    pub max_pending_packets: usize,
    pub max_pending_bytes: usize,
    pub downlink_capacity: usize,
    pub grace: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            shards: 64,
            max_sessions: 65536,
            max_pending_packets: 30,
            max_pending_bytes: 16 * 1024 * 1024,
            downlink_capacity: 32,
            grace: Duration::from_secs(30),
        }
    }
}

struct Shard {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

pub struct SessionTable {
    shards: Vec<Shard>,
    handler: Handler,
    cfg: SessionConfig,
    active: AtomicUsize,
    metrics: Arc<crate::metrics::Metrics>,
}

pub enum OpenDownload {
    Opened(DownlinkReader),
    Conflict,
    Capacity,
}

/// FNV-1a 64 over the raw id bytes. Used only to pick a shard and to derive a loggable id
/// hash; per-shard `HashMap` still uses std SipHash, so collisions here do not enable HashDoS.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl SessionTable {
    pub fn new(
        cfg: SessionConfig,
        handler: Handler,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Arc<Self> {
        let n = cfg.shards.max(1);
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            shards.push(Shard {
                map: Mutex::new(HashMap::new()),
            });
        }
        Arc::new(Self {
            shards,
            handler,
            cfg,
            active: AtomicUsize::new(0),
            metrics,
        })
    }

    fn shard_for(&self, id: &str) -> &Shard {
        let idx = (fnv1a(id.as_bytes()) as usize) % self.shards.len();
        &self.shards[idx]
    }

    /// Push an uplink packet for `session_id`, creating the session if needed.
    /// Returns the push result; `None` if the global session cap is hit.
    pub async fn push_uplink(
        self: &Arc<Self>,
        session_id: &str,
        seq: u64,
        payload: bytes::Bytes,
    ) -> Option<PushResult> {
        let session = self.upsert(session_id)?;
        let r = session.uplink.push(seq, payload).await;
        // keep gauges roughly current (best-effort; exact accounting in reader)
        self.metrics
            .pending_packets
            .store(session.uplink.pending_packets() as i64, Ordering::Relaxed);
        Some(r)
    }

    /// Take the downlink reader for the `stream-down` GET. Marks the session fully connected
    /// (cancels grace reaping). Returns None if there is no such session or the GET already
    /// took it.
    pub fn open_download(self: &Arc<Self>, session_id: &str) -> OpenDownload {
        let Some(session) = self.upsert(session_id) else {
            return OpenDownload::Capacity;
        };
        session.fully_connected.store(true, Ordering::Release);
        let reader = session.downlink_reader.lock().unwrap().take();
        match reader {
            Some(reader) => OpenDownload::Opened(reader),
            None => OpenDownload::Conflict,
        }
    }

    /// Remove a session (called when the download GET ends, or on tear-down).
    pub fn remove(self: &Arc<Self>, session_id: &str) {
        let shard = self.shard_for(session_id);
        let removed = shard.map.lock().unwrap().remove(session_id);
        if let Some(s) = removed {
            s.uplink.close();
            self.active.fetch_sub(1, Ordering::AcqRel);
            crate::metrics::Metrics::add_gauge(&self.metrics.active_sessions, -1);
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn upsert(self: &Arc<Self>, session_id: &str) -> Option<Arc<Session>> {
        // fast path
        {
            let map = self.shard_for(session_id).map.lock().unwrap();
            if let Some(s) = map.get(session_id) {
                return Some(s.clone());
            }
        }
        // slow path
        let shard = self.shard_for(session_id);
        let mut map = shard.map.lock().unwrap();
        if let Some(s) = map.get(session_id) {
            return Some(s.clone());
        }
        if self.active.load(Ordering::Relaxed) >= self.cfg.max_sessions {
            return None;
        }

        // out-of-order bound = max_pending_packets; in-order channel depth bounds in-flight
        // chunks (backpressure). Depth is capped so a flood cannot pre-buffer unboundedly.
        let depth = self.cfg.max_pending_packets.clamp(1, 256);
        let (sink, reader) = reorder::channel(
            self.cfg.max_pending_packets,
            self.cfg.max_pending_bytes,
            depth,
        );
        let (dl_sink, dl_reader) = downlink::channel(self.cfg.downlink_capacity);
        let session = Arc::new(Session {
            uplink: sink,
            downlink_reader: Mutex::new(Some(dl_reader)),
            fully_connected: AtomicBool::new(false),
        });
        map.insert(session_id.to_string(), session.clone());
        self.active.fetch_add(1, Ordering::AcqRel);
        crate::metrics::Metrics::add_gauge(&self.metrics.active_sessions, 1);
        drop(map);

        // hand the duplex to the protocol stack
        (self.handler)(SessionConn {
            reader,
            writer: dl_sink,
            id_hash: fnv1a(session_id.as_bytes()),
        });

        // grace reaper: if the GET never opens within `grace`, evict.
        let table = self.clone();
        let id = session_id.to_string();
        let weak = Arc::downgrade(&session);
        let grace = self.cfg.grace;
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if let Some(s) = weak.upgrade() {
                if !s.fully_connected.load(Ordering::Acquire) {
                    table
                        .metrics
                        .session_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    table.remove(&id);
                }
            }
        });

        Some(session)
    }
}
