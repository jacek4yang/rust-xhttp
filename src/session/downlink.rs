//! Downlink: the server→client byte stream carried by the long-lived `stream-down` GET.
//!
//! Bounded by construction. The protocol writer (`DownlinkSink`) awaits on a full channel,
//! providing backpressure all the way back to the target connection; the GET handler
//! (`DownlinkReader`) drains and flushes each chunk. No `data:`/SSE text framing is added —
//! the bytes are the raw protocol stream (the SSE *content-type* is only a middlebox hint).

use bytes::Bytes;
use tokio::sync::mpsc;

/// Writer side, held by the dispatcher / VLESS writer.
#[derive(Clone)]
pub struct DownlinkSink {
    tx: mpsc::Sender<Bytes>,
}

/// Reader side, taken once by the GET (download) handler.
pub struct DownlinkReader {
    rx: mpsc::Receiver<Bytes>,
}

/// `capacity` is the number of in-flight chunks before the writer blocks.
pub fn channel(capacity: usize) -> (DownlinkSink, DownlinkReader) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (DownlinkSink { tx }, DownlinkReader { rx })
}

impl DownlinkSink {
    /// Send a chunk downstream, awaiting if the bounded buffer is full. Returns Err if the
    /// download side is gone (client disconnected) so the writer can stop.
    pub async fn send(&self, b: Bytes) -> Result<(), ()> {
        if b.is_empty() {
            return Ok(());
        }
        self.tx.send(b).await.map_err(|_| ())
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl DownlinkReader {
    /// Next chunk to flush, or None when the writer side is dropped (target EOF/close).
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}
