//! HTTP/1.1, HTTP/2 and TLS origin for XHTTP packet-up.

use crate::config::{TlsConfig, XhttpConfig};
use crate::metrics::Metrics;
use crate::session::{OpenDownload, PushResult, SessionTable};
use crate::site;
use crate::xhttp::{RequestKind, path_matches};
use crate::xhttp::{
    classify, extract_meta_from_path, extract_padding, generate_response_padding, host_matches,
    is_padding_valid,
};
use bytes::{Bytes, BytesMut};
use futures::stream;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

type Body = BoxBody<Bytes, Infallible>;

#[derive(Clone)]
pub struct Origin {
    xhttp: Arc<XhttpConfig>,
    sessions: Arc<SessionTable>,
    metrics: Arc<Metrics>,
    tls: Option<TlsAcceptor>,
}

impl Origin {
    pub fn new(
        xhttp: XhttpConfig,
        sessions: Arc<SessionTable>,
        metrics: Arc<Metrics>,
        tls: Option<&TlsConfig>,
    ) -> Result<Self, OriginError> {
        let tls = tls.map(load_tls).transpose()?.map(TlsAcceptor::from);
        Ok(Self {
            xhttp: Arc::new(xhttp),
            sessions,
            metrics,
            tls,
        })
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), OriginError> {
        loop {
            let (stream, _) = listener.accept().await?;
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(error) = this.serve_connection(stream).await {
                    tracing::debug!(%error, "origin connection ended");
                }
            });
        }
    }

    async fn serve_connection(&self, stream: TcpStream) -> Result<(), OriginError> {
        if let Some(tls) = &self.tls {
            let stream = tls.accept(stream).await?;
            self.serve_io(TokioIo::new(stream)).await
        } else {
            self.serve_io(TokioIo::new(stream)).await
        }
    }

    async fn serve_io<I>(&self, io: TokioIo<I>) -> Result<(), OriginError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let this = self.clone();
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(
                io,
                service_fn(move |request| {
                    let this = this.clone();
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
            return self.site_response(request.method(), request.uri().path());
        }
        if request.method() == Method::OPTIONS {
            let mut response = empty(StatusCode::OK);
            self.add_xhttp_response_padding(&mut response);
            return response;
        }
        let padding = extract_padding(request.headers(), request.uri());
        if !is_padding_valid(&padding, self.xhttp.padding_from, self.xhttp.padding_to) {
            return self.site_response(request.method(), request.uri().path());
        }
        let meta = extract_meta_from_path(&self.xhttp.path, request.uri());
        let mut response = match classify(request.method(), &meta) {
            RequestKind::PacketUpload { session_id, seq } => {
                self.upload(request, &session_id, seq).await
            }
            RequestKind::StreamDownload { session_id } => self.download(&session_id),
            RequestKind::Unsupported => empty(StatusCode::INTERNAL_SERVER_ERROR),
            RequestKind::StreamUp { .. } | RequestKind::StreamOne => empty(StatusCode::BAD_REQUEST),
            RequestKind::Options => empty(StatusCode::OK),
        };
        self.add_xhttp_response_padding(&mut response);
        response
    }

    async fn upload(
        &self,
        request: Request<Incoming>,
        session_id: &str,
        seq: u64,
    ) -> Response<Body> {
        if request
            .body()
            .size_hint()
            .upper()
            .is_some_and(|n| n > self.xhttp.max_each_post_bytes as u64)
        {
            self.metrics
                .request_body_rejections
                .fetch_add(1, Ordering::Relaxed);
            return empty(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let mut body = request.into_body();
        let mut payload = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                return empty(StatusCode::BAD_REQUEST);
            };
            if let Ok(data) = frame.into_data() {
                let Some(total) = payload.len().checked_add(data.len()) else {
                    return empty(StatusCode::PAYLOAD_TOO_LARGE);
                };
                if total > self.xhttp.max_each_post_bytes {
                    self.metrics
                        .request_body_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    return empty(StatusCode::PAYLOAD_TOO_LARGE);
                }
                payload.extend_from_slice(&data);
            }
        }
        self.metrics
            .upload_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        match self
            .sessions
            .push_uplink(session_id, seq, payload.freeze())
            .await
        {
            Some(PushResult::Accepted | PushResult::Duplicate) => empty(StatusCode::OK),
            Some(PushResult::TooManyPending | PushResult::TooManyPendingBytes) => {
                self.sessions.remove(session_id);
                empty(StatusCode::INTERNAL_SERVER_ERROR)
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

    fn download(&self, session_id: &str) -> Response<Body> {
        let reader = match self.sessions.open_download(session_id) {
            OpenDownload::Opened(reader) => reader,
            OpenDownload::Conflict => return empty(StatusCode::CONFLICT),
            OpenDownload::Capacity => return empty(StatusCode::SERVICE_UNAVAILABLE),
        };
        let state = DownloadState {
            reader,
            sessions: self.sessions.clone(),
            session_id: session_id.to_string(),
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

    fn site_response(&self, method: &Method, path: &str) -> Response<Body> {
        let reply = site::resolve(method, path);
        let is_head = method == Method::HEAD;
        let body = if is_head {
            Empty::<Bytes>::new().boxed()
        } else {
            Full::new(Bytes::from_static(reply.body)).boxed()
        };
        let mut response = response(reply.status, body);
        let headers = response.headers_mut();
        headers.insert(
            http::header::CONTENT_TYPE,
            reply.content_type.parse().unwrap(),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            reply.body.len().to_string().parse().unwrap(),
        );
        headers.insert(
            http::header::CACHE_CONTROL,
            reply.cache_control.parse().unwrap(),
        );
        headers.insert(http::header::ETAG, reply.etag.parse().unwrap());
        headers.insert(
            http::header::LAST_MODIFIED,
            site::last_modified().parse().unwrap(),
        );
        headers.insert(http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        if let Some(allow) = reply.allow {
            headers.insert(http::header::ALLOW, allow.parse().unwrap());
        }
        response
    }

    fn add_xhttp_response_padding(&self, response: &mut Response<Body>) {
        let padding = generate_response_padding(self.xhttp.padding_from, self.xhttp.padding_to);
        response
            .headers_mut()
            .insert("x-padding", padding.parse().unwrap());
    }
}

struct DownloadState {
    reader: crate::session::DownlinkReader,
    sessions: Arc<SessionTable>,
    session_id: String,
}

impl Drop for DownloadState {
    fn drop(&mut self) {
        self.sessions.remove(&self.session_id);
    }
}

fn empty(status: StatusCode) -> Response<Body> {
    response(status, Empty::<Bytes>::new().boxed())
}

fn response(status: StatusCode, body: Body) -> Response<Body> {
    let mut response = Response::builder().status(status).body(body).unwrap();
    response
        .headers_mut()
        .insert(http::header::SERVER, "nginx".parse().unwrap());
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

fn load_tls(config: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, OriginError> {
    let mut cert_reader = BufReader::new(File::open(&config.cert)?);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    let mut key_reader = BufReader::new(File::open(&config.key)?);
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or(OriginError::MissingPrivateKey)?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = config
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(tls))
}

#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("http connection: {0}")]
    Hyper(String),
    #[error("TLS private key is missing")]
    MissingPrivateKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Handler, SessionConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_origin() -> Origin {
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
        };
        let metrics = Metrics::new();
        let handler: Handler = Arc::new(|_| {});
        let sessions = SessionTable::new(SessionConfig::default(), handler, metrics.clone());
        Origin::new(xhttp, sessions, metrics, None).unwrap()
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
        assert!(response.contains("Edge Notes"));
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
}
