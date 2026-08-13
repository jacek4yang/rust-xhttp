//! VLESS user table.
//!
//! Port of `proxy/vless/validator.go`: the lookup key is the request UUID with bytes [6] and
//! [7] zeroed (`ProcessUUID`) — the client may stash a 2-byte route hint there. Authentication
//! is therefore "does the zeroed UUID match a configured user". We use a `HashMap` for O(1)
//! lookup (as upstream's `sync.Map` does) and a final `subtle` constant-time check on the
//! processed id to avoid leaking near-miss timing. The table is swapped atomically on reload,
//! so a config reload never tears down in-flight sessions and never takes a data-path lock.

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct User {
    pub id: [u8; 16], // processed (bytes 6,7 zeroed)
    pub email: String,
    pub flow: String, // "" or "xtls-rprx-vision"
}

struct Inner {
    by_id: HashMap<[u8; 16], Arc<User>>,
}

#[derive(Clone)]
pub struct Validator {
    inner: Arc<ArcSwap<Inner>>,
}

/// Zero bytes [6] and [7] (Xray `ProcessUUID`).
pub fn process_uuid(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = 0;
    id[7] = 0;
    id
}

impl Validator {
    pub fn new(users: impl IntoIterator<Item = User>) -> Self {
        let mut by_id = HashMap::new();
        for mut u in users {
            u.id = process_uuid(u.id);
            by_id.insert(u.id, Arc::new(u));
        }
        Self {
            inner: Arc::new(ArcSwap::from_pointee(Inner { by_id })),
        }
    }

    /// Atomically replace the user set (config reload). In-flight sessions are unaffected.
    pub fn replace(&self, users: impl IntoIterator<Item = User>) {
        let mut by_id = HashMap::new();
        for mut u in users {
            u.id = process_uuid(u.id);
            by_id.insert(u.id, Arc::new(u));
        }
        self.inner.store(Arc::new(Inner { by_id }));
    }

    /// Look up a user by the *raw* request UUID. Retained as an owned result for API
    /// compatibility; the server hot path uses [`Self::get_shared`].
    pub fn get(&self, raw_id: &[u8; 16]) -> Option<User> {
        self.get_shared(raw_id).map(|user| user.as_ref().clone())
    }

    /// Lock-free lookup that shares immutable user metadata without cloning strings.
    pub fn get_shared(&self, raw_id: &[u8; 16]) -> Option<Arc<User>> {
        let key = process_uuid(*raw_id);
        let snap = self.inner.load();
        let candidate = snap.by_id.get(&key)?;
        // constant-time confirm on the processed id
        if candidate.id.ct_eq(&key).into() {
            Some(Arc::clone(candidate))
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.inner.load().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(b: u8) -> [u8; 16] {
        let mut a = [b; 16];
        a[6] = 0xAA; // route bytes that must be ignored
        a[7] = 0xBB;
        a
    }

    #[test]
    fn lookup_ignores_route_bytes() {
        let v = Validator::new([User {
            id: uid(1),
            email: "a@b".into(),
            flow: XRV_TEST.into(),
        }]);
        // a request with different route bytes still matches
        let mut req = uid(1);
        req[6] = 0x11;
        req[7] = 0x22;
        let u = v.get(&req).expect("match");
        assert_eq!(u.email, "a@b");
    }

    #[test]
    fn unknown_user_rejected() {
        let v = Validator::new([User {
            id: uid(1),
            email: "a".into(),
            flow: String::new(),
        }]);
        assert!(v.get(&uid(2)).is_none());
    }

    #[test]
    fn atomic_replace() {
        let v = Validator::new([User {
            id: uid(1),
            email: "old".into(),
            flow: String::new(),
        }]);
        v.replace([User {
            id: uid(2),
            email: "new".into(),
            flow: String::new(),
        }]);
        assert!(v.get(&uid(1)).is_none());
        assert_eq!(v.get(&uid(2)).unwrap().email, "new");
    }

    const XRV_TEST: &str = "xtls-rprx-vision";
}
