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
    id: Arc<str>,
    id_hash: u64,
    uplink: UplinkSink,
    downlink_reader: Mutex<Option<DownlinkReader>>,
    fully_connected: AtomicBool,
    grace_reaper: Mutex<Option<tokio::task::AbortHandle>>,
}

pub struct SessionConfig {
    pub shards: usize,
    pub max_sessions: usize,
    pub max_pending_packets: usize,
    pub max_pending_bytes: usize,
    pub global_buffer_budget: Option<crate::buffer::MemoryBudget>,
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
            global_buffer_budget: None,
            downlink_capacity: 32,
            grace: Duration::from_secs(30),
        }
    }
}

struct Shard {
    map: Mutex<HashMap<Arc<str>, Arc<Session>>>,
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

    /// Push an uplink packet for `session_id`, creating the session if needed.
    /// Returns the push result; `None` if the global session cap is hit.
    pub async fn push_uplink(
        self: &Arc<Self>,
        session_id: &str,
        seq: u64,
        payload: bytes::Bytes,
    ) -> Option<PushResult> {
        let session = self.upsert(session_id, false)?;
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
        let Some(session) = self.upsert(session_id, true) else {
            return OpenDownload::Capacity;
        };
        session.fully_connected.store(true, Ordering::Release);
        if let Some(reaper) = session.grace_reaper.lock().unwrap().take() {
            reaper.abort();
        }
        let reader = session.downlink_reader.lock().unwrap().take();
        match reader {
            Some(mut reader) => {
                reader.set_session_key(session.id.clone(), session.id_hash);
                OpenDownload::Opened(reader)
            }
            None => OpenDownload::Conflict,
        }
    }

    /// Remove a session (called when the download GET ends, or on tear-down).
    pub fn remove(self: &Arc<Self>, session_id: &str) {
        self.remove_inner(session_id, fnv1a(session_id.as_bytes()), None, true);
    }

    fn remove_inner(
        &self,
        session_id: &str,
        id_hash: u64,
        expected: Option<&Arc<Session>>,
        cancel_reaper: bool,
    ) {
        let shard = &self.shards[(id_hash as usize) % self.shards.len()];
        let removed = {
            let mut map = shard.map.lock().unwrap();
            if expected.is_some_and(|expected| {
                map.get(session_id)
                    .is_none_or(|current| !Arc::ptr_eq(current, expected))
            }) {
                return;
            }
            map.remove(session_id)
        };
        if let Some(s) = removed {
            if cancel_reaper && let Some(reaper) = s.grace_reaper.lock().unwrap().take() {
                reaper.abort();
            }
            s.uplink.close();
            self.active.fetch_sub(1, Ordering::AcqRel);
            crate::metrics::Metrics::add_gauge(&self.metrics.active_sessions, -1);
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub(crate) fn remove_hashed(self: &Arc<Self>, session_id: &str, id_hash: u64) {
        self.remove_inner(session_id, id_hash, None, true);
    }

    fn upsert(
        self: &Arc<Self>,
        session_id: &str,
        fully_connected_on_create: bool,
    ) -> Option<Arc<Session>> {
        let id_hash = fnv1a(session_id.as_bytes());
        let shard = &self.shards[(id_hash as usize) % self.shards.len()];
        // A single lookup covers both existing and new sessions. Acquiring the same lock
        // twice added pure overhead for every new session.
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
        let (sink, reader) = reorder::channel_with_budget(
            self.cfg.max_pending_packets,
            self.cfg.max_pending_bytes,
            depth,
            self.cfg.global_buffer_budget.clone(),
        );
        let (dl_sink, dl_reader) = downlink::channel(self.cfg.downlink_capacity);
        let id: Arc<str> = Arc::from(session_id);
        let session = Arc::new(Session {
            id: id.clone(),
            id_hash,
            uplink: sink,
            downlink_reader: Mutex::new(Some(dl_reader)),
            fully_connected: AtomicBool::new(fully_connected_on_create),
            grace_reaper: Mutex::new(None),
        });
        map.insert(id.clone(), session.clone());
        self.active.fetch_add(1, Ordering::AcqRel);
        crate::metrics::Metrics::add_gauge(&self.metrics.active_sessions, 1);
        drop(map);

        // hand the duplex to the protocol stack
        (self.handler)(SessionConn {
            reader,
            writer: dl_sink,
            id_hash: session.id_hash,
        });

        // A download-created session is already fully connected and never needs a grace
        // timer. This is the normal Xray request order and avoids one task/timer per session.
        if fully_connected_on_create {
            return Some(session);
        }

        // Upload-created sessions need a grace reaper until their GET opens.
        let table = self.clone();
        let weak = Arc::downgrade(&session);
        let grace = self.cfg.grace;
        let task = tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if let Some(s) = weak.upgrade()
                && !s.fully_connected.load(Ordering::Acquire)
            {
                table
                    .metrics
                    .session_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                table.remove_inner(&id, s.id_hash, Some(&s), false);
            }
        });
        let reaper = task.abort_handle();
        *session.grace_reaper.lock().unwrap() = Some(reaper.clone());
        if session.fully_connected.load(Ordering::Acquire)
            || shard
                .map
                .lock()
                .unwrap()
                .get(session_id)
                .is_none_or(|current| !Arc::ptr_eq(current, &session))
        {
            reaper.abort();
            session.grace_reaper.lock().unwrap().take();
        }

        Some(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(grace: Duration) -> (Arc<SessionTable>, Arc<crate::metrics::Metrics>) {
        let metrics = crate::metrics::Metrics::new();
        let handler: Handler = Arc::new(|_| {});
        let table = SessionTable::new(
            SessionConfig {
                grace,
                ..SessionConfig::default()
            },
            handler,
            metrics.clone(),
        );
        (table, metrics)
    }

    #[tokio::test(start_paused = true)]
    async fn grace_reaper_expires_unconnected_session() {
        let (table, metrics) = table(Duration::from_secs(30));
        table
            .push_uplink("expires", 0, bytes::Bytes::from_static(b"x"))
            .await;
        assert_eq!(table.active_sessions(), 1);

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert_eq!(table.active_sessions(), 0);
        assert_eq!(metrics.session_timeouts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn opening_download_cancels_grace_reaper() {
        let (table, metrics) = table(Duration::from_secs(30));
        table
            .push_uplink("connected", 0, bytes::Bytes::from_static(b"x"))
            .await;
        assert!(matches!(
            table.open_download("connected"),
            OpenDownload::Opened(_)
        ));

        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert_eq!(table.active_sessions(), 1);
        assert_eq!(metrics.session_timeouts.load(Ordering::Relaxed), 0);
        table.remove("connected");
        assert_eq!(table.active_sessions(), 0);
    }
}
