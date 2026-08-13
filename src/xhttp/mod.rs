//! XHTTP request-layer parsing for the official `packet-up` mode (default placements).
//!
//! Pure functions over `http` types so they can be unit-tested without a running server.
//! Ground truth: `xray-core/transport/internet/splithttp/{hub.go,config.go,xpadding.go}`.
//!
//! Default placements used by the stock client (which we must accept unmodified):
//!   * session id  = first path segment after the base path  (`config.go` ExtractMetaFromRequest)
//!   * seq         = second path segment                       (uint64)
//!   * x_padding   = `x_padding` query inside the `Referer` header, or the request query
//!     (`xpadding.go` ExtractXPaddingFromRequest, obfsMode=false)

use http::{HeaderMap, Method, Uri};

mod padding;
pub use padding::{
    ResponsePadding, extract_padding, extract_padding_len, generate_response_padding,
    is_padding_len_valid, is_padding_valid,
};

/// What the server should do with a request, after host/path/padding validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    /// `packet-up` upload: a single seq'd packet. Body must be read (bounded).
    PacketUpload { session_id: String, seq: u64 },
    /// `stream-down` download GET: open the long-lived response stream.
    StreamDownload { session_id: String },
    /// `stream-up` single long POST (session, no seq). Not the official mode → 400 by policy,
    /// but classified so the server can answer precisely.
    StreamUp { session_id: String },
    /// `stream-one` (no session). Not the official mode.
    StreamOne,
    /// CORS preflight.
    Options,
    /// Method we do not serve on the XHTTP path.
    Unsupported,
}

/// Result of meta extraction (before classification).
pub struct Meta {
    pub session_id: String,
    pub seq_str: String,
}

/// Extract session id and seq from the path, given the normalized base `path` (ends with '/').
/// Default = both in the path (`/<base>/<session>/<seq>`).
pub fn extract_meta_from_path(base: &str, uri: &Uri) -> Meta {
    let meta = extract_meta_from_path_borrowed(base, uri);
    Meta {
        session_id: meta.session_id.to_owned(),
        seq_str: meta.seq_str.to_owned(),
    }
}

/// Borrowed hot-path metadata. This avoids allocating session and sequence strings while
/// retaining the original owned [`Meta`] API for library callers.
pub struct BorrowedMeta<'a> {
    pub session_id: &'a str,
    pub seq_str: &'a str,
}

pub fn extract_meta_from_path_borrowed<'a>(base: &str, uri: &'a Uri) -> BorrowedMeta<'a> {
    let full = uri.path();
    let rest = full.strip_prefix(base).unwrap_or("");
    let mut segs = rest.split('/');
    let session_id = segs.next().unwrap_or("");
    let seq_str = segs.next().unwrap_or("");
    BorrowedMeta {
        session_id,
        seq_str,
    }
}

/// True if the request path is under the configured base.
pub fn path_matches(base: &str, uri: &Uri) -> bool {
    uri.path().starts_with(base)
}

/// Validate the `Host` header against a configured host (empty config = accept any).
/// Mirrors `internet.IsValidHTTPHost`: compares host portion, ignoring port.
pub fn host_matches(configured: &str, headers: &HeaderMap, uri: &Uri) -> bool {
    if configured.is_empty() {
        return true;
    }
    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.host())
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    let want = configured.split(':').next().unwrap_or(configured);
    host.eq_ignore_ascii_case(want)
}

/// Classify the request after meta extraction.
///
/// From `hub.go` ServeHTTP:
///   * GET  → uplink iff seq present; otherwise download (with session) or stream-one (no session)
///   * other methods → uplink request
pub fn classify(method: &Method, meta: &Meta) -> RequestKind {
    match classify_borrowed(
        method,
        &BorrowedMeta {
            session_id: &meta.session_id,
            seq_str: &meta.seq_str,
        },
    ) {
        BorrowedRequestKind::PacketUpload { session_id, seq } => RequestKind::PacketUpload {
            session_id: session_id.to_owned(),
            seq,
        },
        BorrowedRequestKind::StreamDownload { session_id } => RequestKind::StreamDownload {
            session_id: session_id.to_owned(),
        },
        BorrowedRequestKind::StreamUp { session_id } => RequestKind::StreamUp {
            session_id: session_id.to_owned(),
        },
        BorrowedRequestKind::StreamOne => RequestKind::StreamOne,
        BorrowedRequestKind::Options => RequestKind::Options,
        BorrowedRequestKind::Unsupported => RequestKind::Unsupported,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowedRequestKind<'a> {
    PacketUpload { session_id: &'a str, seq: u64 },
    StreamDownload { session_id: &'a str },
    StreamUp { session_id: &'a str },
    StreamOne,
    Options,
    Unsupported,
}

pub fn classify_borrowed<'a>(method: &Method, meta: &BorrowedMeta<'a>) -> BorrowedRequestKind<'a> {
    if method == Method::OPTIONS {
        return BorrowedRequestKind::Options;
    }
    let has_session = !meta.session_id.is_empty();
    let has_seq = !meta.seq_str.is_empty();

    let is_uplink = if method == Method::GET { has_seq } else { true };

    if is_uplink && has_session {
        if has_seq {
            match meta.seq_str.parse::<u64>() {
                Ok(seq) => BorrowedRequestKind::PacketUpload {
                    session_id: meta.session_id,
                    seq,
                },
                // Go returns 500 on ParseUint failure; surface as Unsupported→ caller maps to 500.
                Err(_) => BorrowedRequestKind::Unsupported,
            }
        } else {
            BorrowedRequestKind::StreamUp {
                session_id: meta.session_id,
            }
        }
    } else if method == Method::GET || !has_session {
        if has_session {
            BorrowedRequestKind::StreamDownload {
                session_id: meta.session_id,
            }
        } else {
            BorrowedRequestKind::StreamOne
        }
    } else {
        BorrowedRequestKind::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn meta_from_path_default() {
        let target = uri("/yourpath/SESSION123/7");
        let m = extract_meta_from_path("/yourpath/", &target);
        assert_eq!(m.session_id, "SESSION123");
        assert_eq!(m.seq_str, "7");
    }

    #[test]
    fn meta_download_no_seq() {
        let target = uri("/yourpath/SESSION123");
        let m = extract_meta_from_path("/yourpath/", &target);
        assert_eq!(m.session_id, "SESSION123");
        assert_eq!(m.seq_str, "");
    }

    #[test]
    fn classify_packet_upload() {
        let m = Meta {
            session_id: "s".into(),
            seq_str: "42".into(),
        };
        assert_eq!(
            classify(&Method::POST, &m),
            RequestKind::PacketUpload {
                session_id: "s".into(),
                seq: 42
            }
        );
    }

    #[test]
    fn classify_download_get() {
        let m = Meta {
            session_id: "s".into(),
            seq_str: "".into(),
        };
        assert_eq!(
            classify(&Method::GET, &m),
            RequestKind::StreamDownload {
                session_id: "s".into()
            }
        );
    }

    #[test]
    fn classify_get_with_seq_is_upload() {
        let m = Meta {
            session_id: "s".into(),
            seq_str: "3".into(),
        };
        assert_eq!(
            classify(&Method::GET, &m),
            RequestKind::PacketUpload {
                session_id: "s".into(),
                seq: 3
            }
        );
    }

    #[test]
    fn classify_stream_one_no_session() {
        let m = Meta {
            session_id: "".into(),
            seq_str: "".into(),
        };
        assert_eq!(classify(&Method::GET, &m), RequestKind::StreamOne);
    }

    #[test]
    fn host_matches_ignores_port() {
        let mut h = HeaderMap::new();
        h.insert(http::header::HOST, "example.com:443".parse().unwrap());
        assert!(host_matches("example.com", &h, &uri("/")));
        assert!(!host_matches("other.com", &h, &uri("/")));
        assert!(host_matches("", &h, &uri("/")));
    }
}
