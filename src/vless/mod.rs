//! VLESS protocol (inbound side) for the Rust XHTTP server.
//!
//! Clean-room-by-spec port of `xray-core/proxy/vless` (MPL-2.0). Implements only what the
//! official inbound path needs: request/response header codec, the user table (`ProcessUUID`
//! auth), addons, and address parsing. The `xtls-rprx-vision` padding flow lives in
//! [`vision`]; the VLESS-Encryption handshake/AEAD lives in [`encryption`]. UDP/XUDP packet
//! framing lives in the top-level [`crate::xudp`] module.

pub mod addons;
pub mod address;
pub mod encryption;
pub mod header;
pub mod validator;
pub mod vision;

pub use addons::{Addons, XRV};
pub use address::Address;
pub use header::{
    Command, HeaderError, RequestHeader, decode_request_header, decode_request_header_shared,
    encode_response_header,
};
pub use validator::{User, Validator, process_uuid};
