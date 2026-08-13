//! X-Padding extraction & validation (non-obfs / default mode).
//!
//! Port of `xpadding.go` ExtractXPaddingFromRequest(obfsMode=false) and IsPaddingValid for the
//! default method (length-based). The stock client places padding as `x_padding=<value>` in the
//! query of the `Referer` header (`config.go` FillPacketRequest, PlacementQueryInHeader). The
//! server reads `Referer` first; if absent, it reads the request URL query.
//!
//! Validation: empty → invalid (Go returns 400). Default method compares the raw character
//! length against the configured `[from, to]` byte range (default 100..=1000).

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Uri};
use rand::Rng;
use std::sync::OnceLock;

const MAX_CACHED_LENGTHS: usize = 2048;

/// Lazily cached response-padding header values.
///
/// The default XHTTP range has 901 possible lengths. Caching each value after its first
/// use removes both the padding allocation and HeaderValue parsing from the request path,
/// while retaining Xray's uniform random length distribution. Very wide custom ranges use
/// a one-allocation fallback to keep startup and resident memory bounded.
pub struct ResponsePadding {
    from: u32,
    to: u32,
    cache: Option<Box<[OnceLock<HeaderValue>]>>,
}

impl ResponsePadding {
    pub fn new(from: u32, to: u32) -> Self {
        let width = to.saturating_sub(from) as usize + 1;
        let cache =
            (width <= MAX_CACHED_LENGTHS).then(|| (0..width).map(|_| OnceLock::new()).collect());
        Self { from, to, cache }
    }

    #[inline]
    pub fn header_value(&self) -> HeaderValue {
        let len = random_length(self.from, self.to);
        if let Some(cache) = &self.cache {
            return cache[(len - self.from) as usize]
                .get_or_init(|| padding_header_value(len))
                .clone();
        }
        padding_header_value(len)
    }
}

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

/// Return the percent-decoded padding byte length without allocating the padding value.
/// The request path only needs this length for validation.
pub fn extract_padding_len(headers: &HeaderMap, uri: &Uri) -> Option<usize> {
    if let Some(referer) = headers
        .get(http::header::REFERER)
        .and_then(|value| value.to_str().ok())
        && !referer.is_empty()
    {
        return query_value_ref(referer, "x_padding").map(percent_decoded_len);
    }
    uri.query()
        .and_then(|query| query_param_ref(query, "x_padding"))
        .map(percent_decoded_len)
}

/// Default-method validity: non-empty and raw length within `[from, to]`.
pub fn is_padding_valid(value: &str, from: u32, to: u32) -> bool {
    if value.is_empty() {
        return false;
    }
    let n = value.len() as u32;
    n >= from && n <= to
}

#[inline]
pub fn is_padding_len_valid(value: Option<usize>, from: u32, to: u32) -> bool {
    value.is_some_and(|len| len != 0 && len >= from as usize && len <= to as usize)
}

/// Generate default response padding, mirroring Xray's non-obfs `X-Padding`
/// response header placement and repeat-x padding method.
pub fn generate_response_padding(from: u32, to: u32) -> String {
    let len = random_length(from, to);
    "X".repeat(len as usize)
}

#[inline]
fn random_length(from: u32, to: u32) -> u32 {
    if from >= to {
        from
    } else {
        rand::thread_rng().gen_range(from..=to)
    }
}

fn padding_header_value(len: u32) -> HeaderValue {
    let bytes = Bytes::from(vec![b'X'; len as usize]);
    HeaderValue::from_maybe_shared(bytes).expect("X padding is always a valid header value")
}

/// Parse a full URL string and return the value of query `key`.
fn query_value(url: &str, key: &str) -> Option<String> {
    query_value_ref(url, key).map(percent_decode)
}

/// Find `key` in a raw `a=b&c=d` query string, with minimal percent-decoding.
fn query_param(query: &str, key: &str) -> Option<String> {
    query_param_ref(query, key).map(percent_decode)
}

fn query_value_ref<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query = url.split_once('?').map(|(_, query)| query)?;
    let query = query.split('#').next().unwrap_or(query);
    query_param_ref(query, key)
}

fn query_param_ref<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v);
        }
    }
    None
}

fn percent_decoded_len(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut decoded_len = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && hex_value(bytes[index + 1]).is_some()
            && hex_value(bytes[index + 2]).is_some()
        {
            index += 3;
        } else {
            index += 1;
        }
        decoded_len += 1;
    }
    decoded_len
}

#[inline]
fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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
        assert_eq!(extract_padding_len(&h, &uri("/p/s/1")), Some(10));
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

    #[test]
    fn padding_length_decodes_without_materializing_value() {
        let h = HeaderMap::new();
        let target = uri("/p/s/1?before=x&x_padding=X%58+Z&after=y");
        assert_eq!(extract_padding_len(&h, &target), Some(4));
        assert!(is_padding_len_valid(Some(4), 4, 4));
        assert!(!is_padding_len_valid(None, 1, 4));
        assert!(!is_padding_len_valid(Some(0), 0, 4));
    }

    #[test]
    fn response_padding_cache_preserves_range() {
        let padding = ResponsePadding::new(4, 8);
        for _ in 0..64 {
            let value = padding.header_value();
            assert!((4..=8).contains(&value.as_bytes().len()));
            assert!(value.as_bytes().iter().all(|byte| *byte == b'X'));
        }
    }
}
