//! Global byte-budget accounting for backpressure.
//!
//! This is intentionally small: a single process-wide atomic counter that all bounded
//! buffers charge against. It does not pool allocations (Rust's allocator + `Bytes`
//! reference counting handle that well); its job is to enforce the *global* memory ceiling
//! from the spec so the server fails fast instead of OOMing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide buffered-byte budget. Cloneable handle around a shared atomic.
#[derive(Clone)]
pub struct MemoryBudget {
    inner: Arc<BudgetInner>,
}

struct BudgetInner {
    used: AtomicU64,
    limit: u64,
}

/// RAII reservation. The bytes are released when this guard is dropped.
pub struct Reservation {
    inner: Arc<BudgetInner>,
    bytes: u64,
}

impl MemoryBudget {
    /// `limit_bytes == 0` means "unlimited" (reservations always succeed).
    pub fn new(limit_bytes: u64) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                used: AtomicU64::new(0),
                limit: limit_bytes,
            }),
        }
    }

    /// Try to reserve `bytes`. Returns `None` if it would exceed the global limit.
    /// Uses a CAS loop so concurrent callers cannot collectively overshoot the ceiling.
    pub fn try_reserve(&self, bytes: u64) -> Option<Reservation> {
        if self.inner.limit != 0 {
            let mut cur = self.inner.used.load(Ordering::Relaxed);
            loop {
                let next = cur.saturating_add(bytes);
                if next > self.inner.limit {
                    return None;
                }
                match self.inner.used.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        } else {
            self.inner.used.fetch_add(bytes, Ordering::AcqRel);
        }
        Some(Reservation {
            inner: self.inner.clone(),
            bytes,
        })
    }

    pub fn used(&self) -> u64 {
        self.inner.used.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> u64 {
        self.inner.limit
    }
}

impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.inner.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_release() {
        let b = MemoryBudget::new(100);
        let r1 = b.try_reserve(60).unwrap();
        assert_eq!(b.used(), 60);
        assert!(b.try_reserve(50).is_none(), "would exceed limit");
        let r2 = b.try_reserve(40).unwrap();
        assert_eq!(b.used(), 100);
        drop(r1);
        assert_eq!(b.used(), 40);
        drop(r2);
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn unlimited_budget() {
        let b = MemoryBudget::new(0);
        let r = b.try_reserve(u64::MAX / 2).unwrap();
        assert!(b.try_reserve(1000).is_some());
        drop(r);
    }
}
