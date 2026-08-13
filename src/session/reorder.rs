//! Bounded sequence reordering for XHTTP `packet-up` uploads.
//!
//! Port of the observable behavior of `xray-core/transport/internet/splithttp/upload_queue.go`
//! (NewUploadQueue / Push / Read). Implementation differs internally:
//!   * Go uses a buffered channel + binary heap and re-pushes partial reads.
//!   * We keep out-of-order packets in a `BTreeMap` and forward in-order chunks through a
//!     bounded `mpsc` channel, so the reader is a plain `AsyncRead`.
//!
//! Wire-equivalent guarantees interop relies on:
//!   * `next_seq` starts at 0, advances by 1 per delivered packet.
//!   * seq < next_seq → duplicate/old → dropped idempotently.
//!   * seq already pending → duplicate → dropped.
//!   * seq > next_seq → buffered; if pending count reaches `max_packets` → tear down
//!     (Go: "packet queue is too large").
//!   * a missing seq blocks the consumer until it arrives or the session closes.
//!   * a slow consumer applies backpressure all the way to the uploading POST (bounded mpsc).

use bytes::Bytes;
use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    Accepted,
    Duplicate,
    TooManyPending,
    TooManyPendingBytes,
    GlobalBufferExceeded,
    Closed,
}

struct BudgetedBytes {
    bytes: Bytes,
    _reservation: Option<crate::buffer::Reservation>,
}

impl BudgetedBytes {
    fn new(bytes: Bytes, reservation: Option<crate::buffer::Reservation>) -> Self {
        Self {
            bytes,
            _reservation: reservation,
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

struct State {
    next_seq: u64,
    sequence_exhausted: bool,
    pending: BTreeMap<u64, BudgetedBytes>,
    tx: mpsc::Sender<BudgetedBytes>,
}

struct Shared {
    state: AsyncMutex<State>,
    max_packets: usize,
    max_bytes: usize,
    budget: Option<crate::buffer::MemoryBudget>,
    pending_bytes: AtomicUsize,
    pending_count: AtomicUsize,
}

#[derive(Clone)]
pub struct UplinkSink {
    shared: Arc<Shared>,
}

pub struct UplinkReader {
    rx: mpsc::Receiver<BudgetedBytes>,
    cur: Option<BudgetedBytes>,
}

/// `max_packets` and `max_bytes` bound the out-of-order buffer.
/// `channel_depth` bounds in-flight in-order chunks (backpressure toward the uploader).
pub fn channel(
    max_packets: usize,
    max_bytes: usize,
    channel_depth: usize,
) -> (UplinkSink, UplinkReader) {
    channel_with_budget(max_packets, max_bytes, channel_depth, None)
}

pub fn channel_with_budget(
    max_packets: usize,
    max_bytes: usize,
    channel_depth: usize,
    budget: Option<crate::buffer::MemoryBudget>,
) -> (UplinkSink, UplinkReader) {
    let (tx, rx) = mpsc::channel(channel_depth.max(1));
    let shared = Arc::new(Shared {
        state: AsyncMutex::new(State {
            next_seq: 0,
            sequence_exhausted: false,
            pending: BTreeMap::new(),
            tx,
        }),
        max_packets: max_packets.max(1),
        max_bytes,
        budget,
        pending_bytes: AtomicUsize::new(0),
        pending_count: AtomicUsize::new(0),
    });
    (UplinkSink { shared }, UplinkReader { rx, cur: None })
}

impl UplinkSink {
    /// Push a seq'd packet. Awaits if the in-order channel is full (backpressure). Sends happen
    /// while holding the state lock, which serializes producers and guarantees the consumer sees
    /// bytes in strict seq order.
    pub async fn push(&self, seq: u64, payload: Bytes) -> PushResult {
        let mut st = self.shared.state.lock().await;
        if st.sequence_exhausted || seq < st.next_seq {
            return PushResult::Duplicate;
        }
        if seq > st.next_seq {
            if st.pending.contains_key(&seq) {
                return PushResult::Duplicate;
            }
            if st.pending.len() >= self.shared.max_packets {
                return PushResult::TooManyPending;
            }
            let current_bytes = self.shared.pending_bytes.load(Ordering::Relaxed);
            let Some(next_bytes) = current_bytes.checked_add(payload.len()) else {
                return PushResult::TooManyPendingBytes;
            };
            if self.shared.max_bytes != 0 && next_bytes > self.shared.max_bytes {
                return PushResult::TooManyPendingBytes;
            }
            let Ok(payload) = self.reserve_payload(payload) else {
                return PushResult::GlobalBufferExceeded;
            };
            self.shared
                .pending_bytes
                .store(next_bytes, Ordering::Relaxed);
            self.shared.pending_count.fetch_add(1, Ordering::Relaxed);
            st.pending.insert(seq, payload);
            return PushResult::Accepted;
        }

        // seq == next_seq: deliver this and any contiguous followers, in order.
        let Ok(payload) = self.reserve_payload(payload) else {
            return PushResult::GlobalBufferExceeded;
        };
        if let Err(_e) = send_in_order(&mut st, payload).await {
            return PushResult::Closed;
        }
        if st.next_seq == u64::MAX {
            st.sequence_exhausted = true;
            return PushResult::Accepted;
        }
        st.next_seq += 1;
        loop {
            let nxt = st.next_seq;
            match st.pending.remove(&nxt) {
                Some(b) => {
                    self.shared
                        .pending_bytes
                        .fetch_sub(b.len(), Ordering::Relaxed);
                    self.shared.pending_count.fetch_sub(1, Ordering::Relaxed);
                    if send_in_order(&mut st, b).await.is_err() {
                        return PushResult::Closed;
                    }
                    if st.next_seq == u64::MAX {
                        st.sequence_exhausted = true;
                        break;
                    }
                    st.next_seq += 1;
                }
                None => break,
            }
        }
        PushResult::Accepted
    }

    /// Close the uplink: drop the sender so the reader observes EOF after draining.
    pub fn close(&self) {
        // Replace the channel with a closed one by dropping all senders. We can't easily drop the
        // tx held inside the mutex synchronously, so signal close by sending nothing and letting
        // the Arc<Shared> drop. Instead, close by taking the lock in a blocking-friendly way:
        if let Ok(mut st) = self.shared.state.try_lock() {
            // Replace tx with a fresh closed channel (receiver dropped immediately).
            let (dead_tx, _dead_rx) = mpsc::channel::<BudgetedBytes>(1);
            st.tx = dead_tx; // old tx dropped → reader sees EOF
            st.pending.clear();
        }
        // If we couldn't get the lock (a push is in flight), that push will finish and the
        // session-level removal drops Arc<Shared>; the reader still ends when all senders drop.
    }

    pub fn pending_packets(&self) -> usize {
        self.shared.pending_count.load(Ordering::Relaxed)
    }

    pub fn pending_bytes(&self) -> usize {
        self.shared.pending_bytes.load(Ordering::Relaxed)
    }

    fn reserve_payload(&self, payload: Bytes) -> Result<BudgetedBytes, ()> {
        let reservation = match &self.shared.budget {
            Some(budget) => Some(budget.try_reserve(payload.len() as u64).ok_or(())?),
            None => None,
        };
        Ok(BudgetedBytes::new(payload, reservation))
    }
}

async fn send_in_order(st: &mut State, payload: BudgetedBytes) -> Result<(), ()> {
    if payload.is_empty() {
        return Ok(());
    }
    st.tx.send(payload).await.map_err(|_| ())
}

impl AsyncRead for UplinkReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cur.as_ref().is_none_or(BudgetedBytes::is_empty) {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => self.cur = Some(b),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(cur) = self.cur.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let n = cur.len().min(buf.remaining());
        buf.put_slice(&cur.bytes[..n]);
        let _ = cur.bytes.split_to(n);
        if cur.is_empty() {
            self.cur = None;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn in_order_delivery() {
        let (sink, mut reader) = channel(30, usize::MAX, 64);
        assert_eq!(
            sink.push(0, Bytes::from_static(b"hello")).await,
            PushResult::Accepted
        );
        assert_eq!(
            sink.push(1, Bytes::from_static(b"world")).await,
            PushResult::Accepted
        );
        let mut out = [0u8; 10];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"helloworld");
    }

    #[tokio::test]
    async fn reorders_out_of_order() {
        let (sink, mut reader) = channel(30, usize::MAX, 64);
        sink.push(2, Bytes::from_static(b"C")).await;
        sink.push(0, Bytes::from_static(b"A")).await;
        sink.push(1, Bytes::from_static(b"B")).await;
        let mut out = [0u8; 3];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ABC");
    }

    #[tokio::test]
    async fn duplicate_and_old_dropped() {
        let (sink, mut reader) = channel(30, usize::MAX, 64);
        sink.push(0, Bytes::from_static(b"A")).await;
        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"A");
        assert_eq!(
            sink.push(0, Bytes::from_static(b"X")).await,
            PushResult::Duplicate
        );
        sink.push(3, Bytes::from_static(b"D")).await;
        assert_eq!(
            sink.push(3, Bytes::from_static(b"Z")).await,
            PushResult::Duplicate
        );
        sink.push(1, Bytes::from_static(b"B")).await;
        reader.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"B");
    }

    #[tokio::test]
    async fn too_many_pending_tears_down() {
        let (sink, _reader) = channel(3, usize::MAX, 64);
        assert_eq!(
            sink.push(1, Bytes::from_static(b"a")).await,
            PushResult::Accepted
        );
        assert_eq!(
            sink.push(2, Bytes::from_static(b"b")).await,
            PushResult::Accepted
        );
        assert_eq!(
            sink.push(3, Bytes::from_static(b"c")).await,
            PushResult::Accepted
        );
        assert_eq!(
            sink.push(4, Bytes::from_static(b"d")).await,
            PushResult::TooManyPending
        );
    }

    #[tokio::test]
    async fn missing_seq_blocks_until_close() {
        let (sink, mut reader) = channel(30, usize::MAX, 64);
        sink.push(0, Bytes::from_static(b"A")).await;
        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.unwrap();
        let h = tokio::spawn(async move {
            let mut b = [0u8; 4];
            reader.read(&mut b).await.unwrap()
        });
        tokio::task::yield_now().await;
        sink.close();
        assert_eq!(h.await.unwrap(), 0, "clean EOF after close");
    }

    #[tokio::test]
    async fn empty_payload_advances_seq() {
        let (sink, mut reader) = channel(30, usize::MAX, 64);
        sink.push(0, Bytes::new()).await;
        sink.push(1, Bytes::from_static(b"X")).await;
        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"X");
    }

    #[tokio::test]
    async fn pending_bytes_are_bounded() {
        let (sink, _reader) = channel(30, 3, 64);
        assert_eq!(
            sink.push(2, Bytes::from_static(b"abc")).await,
            PushResult::Accepted
        );
        assert_eq!(
            sink.push(1, Bytes::from_static(b"x")).await,
            PushResult::TooManyPendingBytes
        );
        assert_eq!(sink.pending_bytes(), 3);
        assert_eq!(sink.pending_packets(), 1);
    }

    #[tokio::test]
    async fn global_budget_is_released_after_read() {
        let budget = crate::buffer::MemoryBudget::new(3);
        let (sink, mut reader) = channel_with_budget(30, usize::MAX, 64, Some(budget.clone()));
        assert_eq!(
            sink.push(0, Bytes::from_static(b"abc")).await,
            PushResult::Accepted
        );
        assert_eq!(budget.used(), 3);
        assert_eq!(
            sink.push(1, Bytes::from_static(b"x")).await,
            PushResult::GlobalBufferExceeded
        );

        let mut out = [0u8; 3];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"abc");
        assert_eq!(budget.used(), 0);
        assert_eq!(
            sink.push(1, Bytes::from_static(b"x")).await,
            PushResult::Accepted
        );
    }
}
