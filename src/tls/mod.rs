//! TLS termination backend for the HTTP origin.
//!
//! The production backend is the in-tree TLS 1.3 nginx-profile implementation.
//! It stays behind this module boundary so XHTTP request handling remains
//! independent from TLS record and handshake mechanics.

pub mod cert;
pub mod client_hello;
mod nginx_backend;
pub mod tls13;

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::config::TlsConfig;

#[derive(Clone)]
pub enum Server {
    NginxProfile(nginx_backend::NginxProfileBackend),
}

pub enum AcceptedStream {
    Plain(TcpStream),
    NginxProfile(Box<nginx_backend::TlsStream<TcpStream>>),
}

impl Server {
    pub fn from_config(config: &TlsConfig) -> Result<Self, Error> {
        Ok(Self::NginxProfile(nginx_backend::NginxProfileBackend::new(
            config,
        )?))
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<AcceptedStream, Error> {
        match self {
            Self::NginxProfile(backend) => backend.accept(stream).await,
        }
    }
}

impl AsyncRead for AcceptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::NginxProfile(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AcceptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::NginxProfile(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::NginxProfile(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::NginxProfile(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS signing key: {0}")]
    SigningKey(#[from] cert::SignError),
    #[error("nginx-profile TLS: {0}")]
    NginxProfile(#[from] nginx_backend::Error),
    #[error("TLS certificate chain is empty")]
    MissingCertificate,
    #[error("TLS private key is missing")]
    MissingPrivateKey,
    #[error("invalid PEM file")]
    Pem,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn accepted_plain_stream_round_trips_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut out = [0u8; 4];
            stream.read_exact(&mut out).await.unwrap();
            out
        });

        let (stream, _) = listener.accept().await.unwrap();
        let mut accepted = AcceptedStream::Plain(stream);
        let mut buf = [0u8; 4];
        accepted.read_exact(&mut buf).await.unwrap();
        accepted.write_all(&buf).await.unwrap();

        assert_eq!(client.await.unwrap(), *b"ping");
    }
}
