//! X-Padding extraction & validation (non-obfs / default mode).
//!
//! Port of `xpadding.go` ExtractXPaddingFromRequest(obfsMode=false) and IsPaddingValid for the
//! default method (length-based). The stock client places padding as `x_padding=<value>` in the
//! query of the `Referer` header (`config.go` FillPacketRequest, PlacementQueryInHeader). The
//! server reads `Referer` first; if absent, it reads the request URL query.
//!
//! Validation: empty → invalid (Go returns 400). Default method compares the raw character
//! length against the configured `[from, to]` byte range (default 100..=1000).

use http::{HeaderMap, Uri};
use rand::Rng;

/// Pull the padding value the client sent, mirroring the non-obfs branch.
/// Returns the value (possibly empty) — the caller validates length.
pub fn extract_padding(headers: &HeaderMap, uri: &Uri) -> String {
    if let Some(referer) = headers
        .get(http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        && !referer.is_empty()
    {
        return query_value(referer, "x_padding").unwrap_or_default();
    }
    // no Referer → look at the request URI query directly
    if let Some(q) = uri.query() {
        return query_param(q, "x_padding").unwrap_or_default();
    }
    String::new()
}

/// Default-method validity: non-empty and raw length within `[from, to]`.
pub fn is_padding_valid(value: &str, from: u32, to: u32) -> bool {
    if value.is_empty() {
        return false;
    }
    let n = value.len() as u32;
    n >= from && n <= to
}

/// Generate default response padding, mirroring Xray's non-obfs `X-Padding`
/// response header placement and repeat-x padding method.
pub fn generate_response_padding(from: u32, to: u32) -> String {
    let len = if from >= to {
        from
    } else {
        rand::thread_rng().gen_range(from..=to)
    };
    "X".repeat(len as usize)
}

/// Parse a full URL string and return the value of query `key`.
fn query_value(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?').map(|(_, q)| q)?;
    // strip a possible fragment
    let q = q.split('#').next().unwrap_or(q);
    query_param(q, key)
}

/// Find `key` in a raw `a=b&c=d` query string, with minimal percent-decoding.
fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Minimal percent-decode (enough for padding values, which are X/Z/base62 + maybe '%').
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn padding_from_referer_query() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::REFERER,
            "https://example.com/p/?x_padding=XXXXXXXXXX"
                .parse()
                .unwrap(),
        );
        let v = extract_padding(&h, &uri("/p/s/1"));
        assert_eq!(v, "XXXXXXXXXX");
        assert!(is_padding_valid(&v, 5, 20));
        assert!(!is_padding_valid(&v, 50, 100));
    }

    #[test]
    fn padding_from_request_query_when_no_referer() {
        let h = HeaderMap::new();
        let v = extract_padding(&h, &uri("/p/s/1?x_padding=YYYY"));
        assert_eq!(v, "YYYY");
    }

    #[test]
    fn empty_padding_invalid() {
        assert!(!is_padding_valid("", 100, 1000));
    }

    #[test]
    fn response_padding_uses_configured_range() {
        for _ in 0..32 {
            let v = generate_response_padding(4, 8);
            assert!(v.len() >= 4 && v.len() <= 8, "len={}", v.len());
            assert!(v.bytes().all(|b| b == b'X'));
        }
        assert_eq!(generate_response_padding(5, 5), "XXXXX");
    }
}
