use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderMap, Method, Uri};
use rust_xhttp::vless::{User, Validator, process_uuid};
use rust_xhttp::xhttp::{
    BorrowedMeta, ResponsePadding, classify_borrowed, extract_meta_from_path_borrowed,
    extract_padding, extract_padding_len, generate_response_padding, host_matches,
    is_padding_len_valid, is_padding_valid, path_matches,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;

fn bench_xhttp_path_classification(c: &mut Criterion) {
    let uri: Uri = "/xhttp/session-123/184467440737095516".parse().unwrap();
    c.bench_function("xhttp path meta classify", |b| {
        b.iter(|| {
            let meta = extract_meta_from_path_borrowed("/xhttp/", &uri);
            classify_borrowed(&Method::POST, &meta)
        })
    });
    c.bench_function("xhttp allocating path reference", |b| {
        b.iter(|| allocating_path_reference("/xhttp/", &uri))
    });
}

fn bench_xhttp_host_and_path(c: &mut Criterion) {
    let uri: Uri = "https://example.com/xhttp/session-123".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "example.com:443".parse().unwrap());
    let meta = BorrowedMeta {
        session_id: "session-123",
        seq_str: "",
    };

    c.bench_function("xhttp host path download classify", |b| {
        b.iter(|| {
            (
                path_matches("/xhttp/", &uri),
                host_matches("example.com", &headers, &uri),
                classify_borrowed(&Method::GET, &meta),
            )
        })
    });
}

fn bench_xhttp_padding(c: &mut Criterion) {
    let uri: Uri = "/xhttp/session-123/0".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::REFERER,
        format!("https://example.com/?x_padding={}", "X".repeat(100))
            .parse()
            .unwrap(),
    );
    c.bench_function("xhttp request padding validate", |b| {
        b.iter(|| is_padding_len_valid(extract_padding_len(&headers, &uri), 100, 1000))
    });
    c.bench_function("xhttp allocating padding reference", |b| {
        b.iter(|| {
            let padding = extract_padding(&headers, &uri);
            is_padding_valid(&padding, 100, 1000)
        })
    });

    let response_padding = ResponsePadding::new(100, 1000);
    c.bench_function("xhttp cached response padding", |b| {
        b.iter(|| response_padding.header_value())
    });
    c.bench_function("xhttp allocating response padding reference", |b| {
        b.iter(|| {
            let value = generate_response_padding(100, 1000);
            value.parse::<http::HeaderValue>().unwrap()
        })
    });
}

fn bench_vless_user_lookup(c: &mut Criterion) {
    let id = [7u8; 16];
    let validator = Validator::new([User {
        id,
        email: "bench@example.com".into(),
        flow: String::new(),
    }]);
    c.bench_function("vless lock-free user lookup", |b| {
        b.iter(|| validator.get_shared(&id).unwrap())
    });

    let mut users = HashMap::new();
    users.insert(process_uuid(id), validator.get(&id).unwrap());
    let locked = RwLock::new(Arc::new(users));
    c.bench_function("vless rwlock cloning lookup reference", |b| {
        b.iter(|| {
            let key = process_uuid(id);
            let users = locked.read().unwrap().clone();
            let candidate = users.get(&key).unwrap();
            assert!(bool::from(candidate.id.ct_eq(&key)));
            candidate.clone()
        })
    });
}

fn allocating_path_reference(base: &str, uri: &Uri) -> (String, u64) {
    let rest = uri.path().strip_prefix(base).unwrap_or("");
    let mut segments = rest.split('/');
    let session_id = segments.next().unwrap_or("").to_string();
    let seq_string = segments.next().unwrap_or("").to_string();
    let seq = seq_string.parse().unwrap_or_default();
    (session_id.clone(), seq)
}

criterion_group!(
    benches,
    bench_xhttp_path_classification,
    bench_xhttp_host_and_path,
    bench_xhttp_padding,
    bench_vless_user_lookup
);
criterion_main!(benches);
