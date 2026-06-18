use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderMap, Method, Uri};
use rust_xhttp::xhttp::{Meta, classify, extract_meta_from_path, host_matches, path_matches};

fn bench_xhttp_path_classification(c: &mut Criterion) {
    let uri: Uri = "/xhttp/session-123/184467440737095516".parse().unwrap();
    c.bench_function("xhttp path meta classify", |b| {
        b.iter(|| {
            let meta = extract_meta_from_path("/xhttp/", &uri);
            classify(&Method::POST, &meta)
        })
    });
}

fn bench_xhttp_host_and_path(c: &mut Criterion) {
    let uri: Uri = "https://example.com/xhttp/session-123".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "example.com:443".parse().unwrap());
    let meta = Meta {
        session_id: "session-123".into(),
        seq_str: String::new(),
    };

    c.bench_function("xhttp host path download classify", |b| {
        b.iter(|| {
            (
                path_matches("/xhttp/", &uri),
                host_matches("example.com", &headers, &uri),
                classify(&Method::GET, &meta),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_xhttp_path_classification,
    bench_xhttp_host_and_path
);
criterion_main!(benches);
