//! HTTP/1.1, HTTP/2 and TLS origin for XHTTP packet-up.

use crate::config::{FallbackConfig, TlsConfig, UplinkDataPlacement, XhttpConfig};
use crate::metrics::Metrics;
use crate::session::{OpenDownload, PushResult, SessionTable};
use crate::site;
use crate::xhttp::{BorrowedRequestKind, path_matches};
use crate::xhttp::{
    ResponsePadding, classify_borrowed, extract_meta_from_path_borrowed, extract_padding_len,
    host_matches, is_padding_len_valid,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Bytes, BytesMut};
use futures::stream;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

type Body = BoxBody<Bytes, Infallible>;

#[derive(Clone)]
pub struct Origin {
    xhttp: Arc<XhttpConfig>,
    sessions: Arc<SessionTable>,
    metrics: Arc<Metrics>,
    site: Arc<site::StaticSite>,
    response_padding: Arc<ResponsePadding>,
    tls: Option<crate::tls::Server>,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
    handshake_timeout: Duration,
    graceful_shutdown: Duration,
}

impl Origin {
    pub fn new(
        xhttp: XhttpConfig,
        sessions: Arc<SessionTable>,
        metrics: Arc<Metrics>,
        tls: Option<&TlsConfig>,
        fallback: &FallbackConfig,
        tcp_nodelay: bool,
        tcp_keepalive: Option<Duration>,
    ) -> Result<Self, OriginError> {
        let tls = tls.map(crate::tls::Server::from_config).transpose()?;
        let site = Arc::new(site::StaticSite::from_config(fallback)?);
        let response_padding = Arc::new(ResponsePadding::new(xhttp.padding_from, xhttp.padding_to));
        Ok(Self {
            xhttp: Arc::new(xhttp),
            sessions,
            metrics,
            site,
            response_padding,
            tls,
            tcp_nodelay,
            tcp_keepalive,
            handshake_timeout: Duration::from_secs(10),
            graceful_shutdown: Duration::from_secs(30),
        })
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn with_graceful_shutdown(mut self, timeout: Duration) -> Self {
        self.graceful_shutdown = timeout;
        self
    }

    pub fn tls_server(&self) -> Option<crate::tls::Server> {
        self.tls.clone()
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), OriginError> {
        let this = Arc::new(self);
        let mut shutdown = Box::pin(shutdown_signal());
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!(active_connections = connections.len(), "shutdown requested; draining connections");
                    break;
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "origin connection task ended unexpectedly");
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) if is_transient_accept_error(&error) => {
                            tracing::warn!(%error, "transient accept failure; applying backoff");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                        Err(error) => return Err(OriginError::Io(error)),
                    };
                    let this = this.clone();
                    connections.spawn(async move {
                        if let Err(error) = this.serve_connection(stream).await {
                            tracing::debug!(%error, "origin connection ended");
                        }
                    });
                }
            }
        }

        drop(listener);
        let drained = tokio::time::timeout(this.graceful_shutdown, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            let remaining = connections.len();
            tracing::warn!(
                remaining,
                "graceful shutdown deadline reached; aborting connections"
            );
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        Ok(())
    }

    async fn serve_connection(self: Arc<Self>, stream: TcpStream) -> Result<(), OriginError> {
        crate::net::tune_stream(&stream, self.tcp_nodelay, self.tcp_keepalive);
        let stream = match &self.tls {
            Some(tls) => tokio::time::timeout(self.handshake_timeout, tls.accept(stream))
                .await
                .map_err(|_| OriginError::TlsHandshakeTimeout)??,
            None => crate::tls::AcceptedStream::Plain(stream),
        };
        self.serve_io(TokioIo::new(stream)).await
    }

    async fn serve_io<I>(self: Arc<Self>, io: TokioIo<I>) -> Result<(), OriginError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(
                io,
                service_fn(move |request| {
                    let this = self.clone();
                    async move { Ok::<_, Infallible>(this.handle(request).await) }
                }),
            )
            .await
            .map_err(|error| OriginError::Hyper(error.to_string()))
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Body> {
        if request_header_bytes(&request) > self.xhttp.max_header_bytes {
            self.metrics
                .request_header_rejections
                .fetch_add(1, Ordering::Relaxed);
            return empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        if request.uri().path() == "/healthz" {
            return response(
                StatusCode::OK,
                Full::new(Bytes::from_static(b"ok\n")).boxed(),
            );
        }
        if request.uri().path() == "/readyz" {
            return response(
                StatusCode::OK,
                Full::new(Bytes::from_static(b"ready\n")).boxed(),
            );
        }
        if !path_matches(&self.xhttp.path, request.uri())
            || !host_matches(&self.xhttp.host, request.headers(), request.uri())
        {
            return self.site_response(&request);
        }
        if request.method() == Method::OPTIONS {
            let mut response = empty(StatusCode::OK);
            self.add_xhttp_response_padding(&mut response);
            return response;
        }
        let padding_len = extract_padding_len(request.headers(), request.uri());
        if !is_padding_len_valid(padding_len, self.xhttp.padding_from, self.xhttp.padding_to) {
            return self.site_response(&request);
        }
        let (parts, body) = request.into_parts();
        let meta = extract_meta_from_path_borrowed(&self.xhttp.path, &parts.uri);
        let mut response = match classify_borrowed(&parts.method, &meta) {
            BorrowedRequestKind::PacketUpload { session_id, seq } => {
                self.upload(&parts.headers, body, session_id, seq).await
            }
            BorrowedRequestKind::StreamDownload { session_id } => self.download(session_id),
            BorrowedRequestKind::Unsupported => empty(StatusCode::INTERNAL_SERVER_ERROR),
            BorrowedRequestKind::StreamUp { .. } | BorrowedRequestKind::StreamOne => {
                empty(StatusCode::BAD_REQUEST)
            }
            BorrowedRequestKind::Options => empty(StatusCode::OK),
        };
        self.add_xhttp_response_padding(&mut response);
        response
    }

    async fn upload(
        &self,
        headers: &http::HeaderMap,
        mut body: Incoming,
        session_id: &str,
        seq: u64,
    ) -> Response<Body> {
        let mut payload = BytesMut::new();
        match self.decode_header_payload(headers) {
            Ok(header_payload) => payload.extend_from_slice(&header_payload),
            Err(UploadPayloadError::InvalidBase64) => return empty(StatusCode::BAD_REQUEST),
            Err(UploadPayloadError::TooLarge) => return self.reject_upload_too_large(),
        }
        match self.decode_cookie_payload(headers) {
            Ok(cookie_payload) => payload.extend_from_slice(&cookie_payload),
            Err(UploadPayloadError::InvalidBase64) => return empty(StatusCode::BAD_REQUEST),
            Err(UploadPayloadError::TooLarge) => return self.reject_upload_too_large(),
        }
        if should_read_body(self.xhttp.uplink_data_placement) {
            if body
                .size_hint()
                .upper()
                .is_some_and(|n| n > self.xhttp.max_each_post_bytes as u64)
            {
                return self.reject_upload_too_large();
            }
            let body_payload = match self.read_body_payload(&mut body).await {
                Ok(payload) => payload,
                Err(UploadPayloadError::InvalidBase64) => return empty(StatusCode::BAD_REQUEST),
                Err(UploadPayloadError::TooLarge) => return self.reject_upload_too_large(),
            };
            if payload.is_empty() {
                return self.finish_upload(session_id, seq, body_payload).await;
            }
            payload.extend_from_slice(&body_payload);
        }
        self.finish_upload(session_id, seq, payload.freeze()).await
    }

    async fn finish_upload(&self, session_id: &str, seq: u64, payload: Bytes) -> Response<Body> {
        if payload.len() > self.xhttp.max_each_post_bytes {
            return self.reject_upload_too_large();
        }
        self.metrics
            .upload_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        match self.sessions.push_uplink(session_id, seq, payload).await {
            Some(PushResult::Accepted | PushResult::Duplicate) => {
                let mut response = empty(StatusCode::OK);
                if self.xhttp.uplink_data_placement != UplinkDataPlacement::Body {
                    response
                        .headers_mut()
                        .insert(http::header::CACHE_CONTROL, "no-store".parse().unwrap());
                }
                response
            }
            Some(PushResult::TooManyPending | PushResult::TooManyPendingBytes) => {
                self.sessions.remove(session_id);
                empty(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Some(PushResult::GlobalBufferExceeded) => {
                self.metrics
                    .memory_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                empty(StatusCode::SERVICE_UNAVAILABLE)
            }
            Some(PushResult::Closed) => empty(StatusCode::CONFLICT),
            None => {
                self.metrics
                    .memory_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                empty(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }

    async fn read_body_payload(&self, body: &mut Incoming) -> Result<Bytes, UploadPayloadError> {
        let mut first: Option<Bytes> = None;
        let mut combined: Option<BytesMut> = None;
        let mut total = 0usize;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                return Err(UploadPayloadError::InvalidBase64);
            };
            if let Ok(data) = frame.into_data() {
                if data.is_empty() {
                    continue;
                }
                let Some(next_total) = total.checked_add(data.len()) else {
                    return Err(UploadPayloadError::TooLarge);
                };
                if next_total > self.xhttp.max_each_post_bytes {
                    return Err(UploadPayloadError::TooLarge);
                }
                total = next_total;
                if let Some(payload) = combined.as_mut() {
                    payload.extend_from_slice(&data);
                } else if let Some(initial) = first.take() {
                    let mut payload = BytesMut::with_capacity(total);
                    payload.extend_from_slice(&initial);
                    payload.extend_from_slice(&data);
                    combined = Some(payload);
                } else {
                    first = Some(data);
                }
            }
        }
        Ok(combined.map_or_else(|| first.unwrap_or_default(), BytesMut::freeze))
    }

    fn decode_header_payload(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Vec<u8>, UploadPayloadError> {
        if !matches!(
            self.xhttp.uplink_data_placement,
            UplinkDataPlacement::Header | UplinkDataPlacement::Auto
        ) {
            return Ok(Vec::new());
        }
        let mut encoded = String::new();
        for i in 0.. {
            let key = format!("{}-{i}", self.xhttp.uplink_data_key);
            let Some(value) = headers.get(&key) else {
                break;
            };
            encoded.push_str(
                value
                    .to_str()
                    .map_err(|_| UploadPayloadError::InvalidBase64)?,
            );
            if encoded.len() > encoded_len_limit(self.xhttp.max_each_post_bytes) {
                return Err(UploadPayloadError::TooLarge);
            }
        }
        decode_payload_chunks(&encoded, self.xhttp.max_each_post_bytes)
    }

    fn decode_cookie_payload(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Vec<u8>, UploadPayloadError> {
        if !matches!(
            self.xhttp.uplink_data_placement,
            UplinkDataPlacement::Cookie | UplinkDataPlacement::Auto
        ) {
            return Ok(Vec::new());
        }
        let mut encoded = String::new();
        for i in 0.. {
            let key = format!("{}_{i}", self.xhttp.uplink_data_key);
            let Some(value) = cookie_value(headers, &key) else {
                break;
            };
            encoded.push_str(&value);
            if encoded.len() > encoded_len_limit(self.xhttp.max_each_post_bytes) {
                return Err(UploadPayloadError::TooLarge);
            }
        }
        decode_payload_chunks(&encoded, self.xhttp.max_each_post_bytes)
    }

    fn reject_upload_too_large(&self) -> Response<Body> {
        self.metrics
            .request_body_rejections
            .fetch_add(1, Ordering::Relaxed);
        empty(StatusCode::PAYLOAD_TOO_LARGE)
    }

    fn download(&self, session_id: &str) -> Response<Body> {
        let mut reader = match self.sessions.open_download(session_id) {
            OpenDownload::Opened(reader) => reader,
            OpenDownload::Conflict => return empty(StatusCode::CONFLICT),
            OpenDownload::Capacity => return empty(StatusCode::SERVICE_UNAVAILABLE),
        };
        let (session_id, id_hash) = reader
            .take_session_key()
            .expect("session table attaches a download cleanup key");
        let state = DownloadState {
            reader,
            sessions: self.sessions.clone(),
            session_id,
            id_hash,
        };
        let body = StreamBody::new(stream::unfold(state, |mut state| async move {
            state
                .reader
                .recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Frame::data(bytes)), state))
        }))
        .boxed();
        let mut response = response(StatusCode::OK, body);
        response
            .headers_mut()
            .insert("x-accel-buffering", "no".parse().unwrap());
        response
            .headers_mut()
            .insert(http::header::CACHE_CONTROL, "no-store".parse().unwrap());
        if self.xhttp.sse_header {
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                "text/event-stream".parse().unwrap(),
            );
        }
        response
    }

    fn site_response(&self, request: &Request<Incoming>) -> Response<Body> {
        let reply = self.site.resolve(request.method(), request.uri().path());
        let not_modified = request
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .is_some_and(|value| value == reply.etag);
        let is_head = request.method() == Method::HEAD;
        let body = if is_head || not_modified {
            Empty::<Bytes>::new().boxed()
        } else {
            Full::new(reply.body.clone()).boxed()
        };
        let status = if not_modified {
            StatusCode::NOT_MODIFIED
        } else {
            reply.status
        };
        let mut response = response(status, body);
        let headers = response.headers_mut();
        headers.insert(http::header::CONTENT_TYPE, reply.content_type);
        if !not_modified {
            headers.insert(
                http::header::CONTENT_LENGTH,
                reply.body.len().to_string().parse().unwrap(),
            );
        }
        headers.insert(http::header::CACHE_CONTROL, reply.cache_control);
        headers.insert(http::header::ETAG, reply.etag);
        headers.insert(http::header::LAST_MODIFIED, reply.last_modified);
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        headers.insert(
            "referrer-policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );
        if let Some(allow) = reply.allow {
            headers.insert(http::header::ALLOW, allow);
        }
        response
    }

    fn add_xhttp_response_padding(&self, response: &mut Response<Body>) {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("x-padding"),
            self.response_padding.header_value(),
        );
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn is_transient_accept_error(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error().is_some_and(|code| {
            matches!(
                code,
                libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM
            )
        })
    }
    #[cfg(not(unix))]
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadPayloadError {
    InvalidBase64,
    TooLarge,
}

fn should_read_body(placement: UplinkDataPlacement) -> bool {
    matches!(
        placement,
        UplinkDataPlacement::Body | UplinkDataPlacement::Auto
    )
}

fn encoded_len_limit(decoded_limit: usize) -> usize {
    decoded_limit.saturating_mul(4).saturating_add(2) / 3 + 4
}

fn decode_payload_chunks(encoded: &str, limit: usize) -> Result<Vec<u8>, UploadPayloadError> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| UploadPayloadError::InvalidBase64)?;
    if decoded.len() > limit {
        return Err(UploadPayloadError::TooLarge);
    }
    Ok(decoded)
}

fn cookie_value(headers: &http::HeaderMap, key: &str) -> Option<String> {
    for value in headers.get_all(http::header::COOKIE) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for part in raw.split(';') {
            let part = part.trim();
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            if name == key {
                return Some(value.to_string());
            }
        }
    }
    None
}

struct DownloadState {
    reader: crate::session::DownlinkReader,
    sessions: Arc<SessionTable>,
    session_id: Arc<str>,
    id_hash: u64,
}

impl Drop for DownloadState {
    fn drop(&mut self) {
        self.sessions.remove_hashed(&self.session_id, self.id_hash);
    }
}

fn empty(status: StatusCode) -> Response<Body> {
    response(status, Empty::<Bytes>::new().boxed())
}

fn response(status: StatusCode, body: Body) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::SERVER,
        http::HeaderValue::from_static("nginx"),
    );
    response
}

fn request_header_bytes<B>(request: &Request<B>) -> usize {
    let request_target_len = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().len(), |path| path.as_str().len());
    let mut total = request.method().as_str().len() + request_target_len;
    for (name, value) in request.headers() {
        total = total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4);
    }
    total
}

#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] crate::tls::Error),
    #[error("TLS handshake timed out")]
    TlsHandshakeTimeout,
    #[error("fallback site: {0}")]
    Site(#[from] crate::site::SiteError),
    #[error("http connection: {0}")]
    Hyper(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Handler, SessionConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_origin() -> Origin {
        test_origin_with_placement(UplinkDataPlacement::Body)
    }

    fn test_origin_with_placement(placement: UplinkDataPlacement) -> Origin {
        let xhttp = XhttpConfig {
            path: "/xhttp/".into(),
            host: "example.com".into(),
            max_each_post_bytes: 1024,
            max_buffered_posts: 30,
            session_grace_secs: 30,
            sse_header: true,
            max_header_bytes: 512,
            padding_from: 100,
            padding_to: 100,
            uplink_data_placement: placement,
            uplink_data_key: match placement {
                UplinkDataPlacement::Body => String::new(),
                UplinkDataPlacement::Header
                | UplinkDataPlacement::Cookie
                | UplinkDataPlacement::Auto => "X-Data".into(),
            },
        };
        let metrics = Metrics::new();
        let handler: Handler = Arc::new(|_| {});
        let sessions = SessionTable::new(SessionConfig::default(), handler, metrics.clone());
        Origin::new(
            xhttp,
            sessions,
            metrics,
            None,
            &FallbackConfig::default(),
            true,
            None,
        )
        .unwrap()
    }

    async fn start_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = test_origin();
        let task = tokio::spawn(async move {
            let _ = origin.serve(listener).await;
        });
        (addr, task)
    }

    async fn raw_request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn non_xhttp_get_serves_blog_index() {
        let (addr, task) = start_origin().await;
        let response = raw_request(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was:\n{response}"
        );
        assert!(response.contains("server: nginx"));
        assert!(response.contains("content-type: text/html; charset=utf-8"));
        assert!(response.contains("Independent journal"));
        assert!(!response.contains("x-padding:"));
    }

    #[tokio::test]
    async fn invalid_xhttp_probe_falls_back_to_static_404() {
        let (addr, task) = start_origin().await;
        let response = raw_request(
            addr,
            "GET /xhttp/session HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "response was:\n{response}"
        );
        assert!(response.contains("Page not found"));
        assert!(!response.starts_with("HTTP/1.1 400"));
        assert!(!response.contains("x-padding:"));
    }

    #[tokio::test]
    async fn static_fallback_honors_etag_without_body() {
        let (addr, task) = start_origin().await;
        let first = raw_request(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        let etag = first
            .lines()
            .find_map(|line| line.strip_prefix("etag: "))
            .expect("fallback response has an ETag");
        let second = raw_request(
            addr,
            &format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        task.abort();

        assert!(
            second.starts_with("HTTP/1.1 304 Not Modified"),
            "response was:\n{second}"
        );
        assert!(second.ends_with("\r\n\r\n"), "304 included a body");
    }

    #[tokio::test]
    async fn static_fallback_rejects_write_methods() {
        let (addr, task) = start_origin().await;
        let response = raw_request(
            addr,
            "POST /notes HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "response was:\n{response}"
        );
        assert!(response.contains("allow: GET, HEAD"));
    }

    #[tokio::test]
    async fn valid_xhttp_options_gets_response_padding() {
        let (addr, task) = start_origin().await;
        let response = raw_request(
            addr,
            "OPTIONS /xhttp/session/0 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was:\n{response}"
        );
        assert!(response.contains(&format!("x-padding: {}", "X".repeat(100))));
    }

    #[tokio::test]
    async fn oversized_headers_are_rejected_before_routing() {
        let (addr, task) = start_origin().await;
        let response = raw_request(
            addr,
            &format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: {}\r\nConnection: close\r\n\r\n",
                "a".repeat(2048)
            ),
        )
        .await;
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
            "response was:\n{response}"
        );
    }

    #[test]
    fn decodes_header_payload_chunks() {
        let origin = test_origin_with_placement(UplinkDataPlacement::Header);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-data-0", "aGVs".parse().unwrap());
        headers.insert("x-data-1", "bG8".parse().unwrap());

        assert_eq!(
            origin.decode_header_payload(&headers).unwrap(),
            b"hello".to_vec()
        );
        assert!(origin.decode_cookie_payload(&headers).unwrap().is_empty());
    }

    #[test]
    fn decodes_cookie_payload_chunks() {
        let origin = test_origin_with_placement(UplinkDataPlacement::Cookie);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "other=1; X-Data_0=d29y; X-Data_1=bGQ".parse().unwrap(),
        );

        assert_eq!(
            origin.decode_cookie_payload(&headers).unwrap(),
            b"world".to_vec()
        );
        assert!(origin.decode_header_payload(&headers).unwrap().is_empty());
    }

    #[test]
    fn auto_payload_concatenates_header_cookie_and_body_layers() {
        let origin = test_origin_with_placement(UplinkDataPlacement::Auto);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-data-0", "aGVh".parse().unwrap());
        headers.insert(http::header::COOKIE, "X-Data_0=ZGVy".parse().unwrap());

        assert_eq!(
            origin.decode_header_payload(&headers).unwrap(),
            b"hea".to_vec()
        );
        assert_eq!(
            origin.decode_cookie_payload(&headers).unwrap(),
            b"der".to_vec()
        );
    }

    #[test]
    fn rejects_bad_encoded_payload_chunks() {
        let origin = test_origin_with_placement(UplinkDataPlacement::Header);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-data-0", "not valid base64!".parse().unwrap());

        assert_eq!(
            origin.decode_header_payload(&headers),
            Err(UploadPayloadError::InvalidBase64)
        );
    }
}
