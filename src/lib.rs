//! rust-xhttp — a pure-Rust server that is wire-compatible with the official
//! Xray-core client for the XHTTP transport stack:
//!
//! ```text
//! XHTTP (packet-up) + VLESS + VLESS-Encryption + xtls-rprx-vision + XUDP
//! ```
//!
//! It is **not** a general Xray-core replacement: it implements exactly the
//! server side of the official `packet-up` XHTTP mode and the VLESS protocols
//! that ride on top of it, deployable either directly (Xray → Rust over TLS/H2)
//! or behind Cloudflare. Every wire behaviour is derived from local Xray
//! sources under `local/references/Xray-core`; see the `docs/` directory for
//! the per-protocol notes.
//!
//! Module layout (one logical protocol layer per module):
//!
//! - [`config`] — TOML schema, validation, safe defaults.
//! - [`buffer`] — global byte-budget accounting for backpressure.
//! - [`metrics`] — lock-free process counters.
//! - [`origin`] — hyper HTTP/1.1+H2 origin (the XHTTP front door).
//! - [`tls`] — in-tree TLS 1.3 termination backend with nginx-profile shaping.
//! - [`xhttp`] — XHTTP request parsing/classification + padding rules.
//! - [`session`] — sharded session table + bounded uplink reorder + downlink.
//! - [`dispatcher`] — VLESS dispatch to TCP/UDP/XUDP targets.
//! - [`vless`] — VLESS header/addons/address/auth, plus [`vless::vision`] and [`vless::encryption`].
//! - [`xudp`] — XUDP Mux-frame and plain VLESS-UDP codecs.

pub mod buffer;
pub mod config;
pub mod dispatcher;
pub mod logging;
pub mod metrics;
pub mod net;
pub mod origin;
pub mod runtime;
pub mod session;
mod site;
pub mod tls;
pub mod vless;
pub mod xhttp;
pub mod xudp;
