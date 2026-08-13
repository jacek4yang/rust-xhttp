//! Self-contained TLS 1.3 backend with an nginx/OpenSSL-oriented wire shape.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::config::TlsConfig;

use super::cert::CertifiedIdentity;
use super::client_hello::{ClientHello, ClientHelloBufferError, ClientHelloRecordBuffer};
use super::tls13::CipherSuite;
use super::tls13::handshake::{ClientFinishedError, PrepareError, prepare_server_handshake};
use super::tls13::keyshare::GROUP_X25519;
use super::tls13::messages::{HS_SERVER_HELLO, handshake_message};
use super::tls13::record::{RECORD_ALERT, RECORD_APPLICATION_DATA, RECORD_HANDSHAKE, RecordKeys};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const MAX_TLS_RECORD: usize = 18 * 1024;
const MAX_APP_PLAINTEXT: usize = 16 * 1024;

#[derive(Clone)]
pub struct NginxProfileBackend {
    identity: CertifiedIdentity,
    alpn: Arc<[String]>,
}

impl NginxProfileBackend {
    pub fn new(config: &TlsConfig) -> Result<Self, super::Error> {
        Ok(Self {
            identity: CertifiedIdentity::from_config(config)?,
            alpn: Arc::from(config.alpn.clone()),
        })
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<super::AcceptedStream, super::Error> {
        let stream = self.handshake(stream).await?;
        Ok(super::AcceptedStream::NginxProfile(Box::new(stream)))
    }

    async fn handshake(&self, mut stream: TcpStream) -> Result<TlsStream<TcpStream>, Error> {
        let client_hello = read_client_hello(&mut stream).await?;
        let parsed = ClientHello::parse_message(&client_hello)?;
        let cipher = choose_cipher(&parsed).ok_or(Error::NoSharedCipherSuite)?;
        let template = server_hello_template(cipher, GROUP_X25519);
        let mut prepared =
            prepare_server_handshake(&client_hello, &template, &self.identity, &self.alpn)?;

        stream
            .write_all(&plain_record(
                TLS_RECORD_HANDSHAKE,
                &prepared.flight.server_hello,
            ))
            .await?;
        stream
            .write_all(&prepared.flight.change_cipher_spec)
            .await?;
        stream
            .write_all(&prepared.flight.encrypted_handshake_record)
            .await?;
        stream.flush().await?;

        loop {
            let record = read_tls_record(&mut stream).await?;
            if is_change_cipher_spec(&record) {
                continue;
            }
            let (content_type, message) = prepared
                .client_handshake_read
                .open(&record)
                .ok_or(Error::RecordAuthentication)?;
            if content_type != RECORD_HANDSHAKE {
                return Err(Error::UnexpectedInnerContentType(content_type));
            }
            prepared.verify_client_finished_message(&message)?;
            break;
        }

        let app_keys = prepared.application_record_keys();
        Ok(TlsStream::new(
            stream,
            app_keys.client_read,
            app_keys.server_write,
        ))
    }
}

pub struct TlsStream<T> {
    inner: T,
    read_keys: RecordKeys,
    write_keys: RecordKeys,
    encrypted: BytesMut,
    plaintext: Bytes,
    expected_record_len: Option<usize>,
    write_buf: Vec<u8>,
    write_pos: usize,
    close_sent: bool,
}

impl<T> TlsStream<T> {
    pub fn new(inner: T, read_keys: RecordKeys, write_keys: RecordKeys) -> Self {
        Self {
            inner,
            read_keys,
            write_keys,
            encrypted: BytesMut::new(),
            plaintext: Bytes::new(),
            expected_record_len: None,
            write_buf: Vec::new(),
            write_pos: 0,
            close_sent: false,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> TlsStream<T> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS socket write returned zero",
                )));
            }
            self.write_pos += n;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plaintext.is_empty() {
                let n = self.plaintext.len().min(output.remaining());
                output.put_slice(&self.plaintext[..n]);
                self.plaintext.advance(n);
                return Poll::Ready(Ok(()));
            }

            if self.expected_record_len.is_none() && self.encrypted.len() >= 5 {
                let len = u16::from_be_bytes([self.encrypted[3], self.encrypted[4]]) as usize;
                if len > MAX_TLS_RECORD {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS record is too large",
                    )));
                }
                self.expected_record_len = Some(len);
            }

            if let Some(len) = self.expected_record_len {
                if self.encrypted.len() >= 5 + len {
                    let record = self.encrypted.split_to(5 + len).freeze();
                    self.expected_record_len = None;
                    let (content_type, plaintext) =
                        self.read_keys.open(&record).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "TLS record authentication failed",
                            )
                        })?;
                    match content_type {
                        RECORD_APPLICATION_DATA => {
                            if plaintext.is_empty() {
                                continue;
                            }
                            self.plaintext = Bytes::from(plaintext);
                            continue;
                        }
                        RECORD_ALERT => return Poll::Ready(Ok(())),
                        other => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unexpected TLS inner content type {other}"),
                            )));
                        }
                    }
                }
            }

            let mut temporary = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    if self.encrypted.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS record truncated",
                    )));
                }
                Poll::Ready(Ok(())) => self.encrypted.extend_from_slice(read_buf.filled()),
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_flush_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_APP_PLAINTEXT);
        self.write_buf = self.write_keys.seal(RECORD_APPLICATION_DATA, &buf[..n]);
        self.write_pos = 0;
        let _ = self.poll_flush_pending(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush_pending(cx))?;
        if !self.close_sent {
            self.write_buf = self.write_keys.seal(RECORD_ALERT, &[1, 0]);
            self.write_pos = 0;
            self.close_sent = true;
            ready!(self.poll_flush_pending(cx))?;
        }
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_client_hello(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut buffer = ClientHelloRecordBuffer::default();
    loop {
        let record = read_tls_record(stream).await?;
        if is_change_cipher_spec(&record) {
            continue;
        }
        if let Some(message) = buffer.append_record(&record)? {
            return Ok(message);
        }
    }
}

async fn read_tls_record<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_TLS_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS record is too large",
        ));
    }
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

fn is_change_cipher_spec(record: &[u8]) -> bool {
    record == [TLS_RECORD_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]
}

fn plain_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(record_type);
    out.extend_from_slice(&TLS_LEGACY_VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn choose_cipher(client: &ClientHello) -> Option<CipherSuite> {
    [
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
        CipherSuite::Aes128GcmSha256,
    ]
    .into_iter()
    .find(|suite| client.cipher_offered(suite.to_u16()))
}

fn server_hello_template(cipher: CipherSuite, group: u16) -> Vec<u8> {
    let mut supported_versions = Vec::new();
    supported_versions.extend_from_slice(&0x0304u16.to_be_bytes());

    let mut key_share = Vec::new();
    key_share.extend_from_slice(&group.to_be_bytes());
    key_share.extend_from_slice(&32u16.to_be_bytes());
    key_share.extend_from_slice(&[0u8; 32]);

    let mut extensions = Vec::new();
    push_ext(&mut extensions, 0x002b, &supported_versions);
    push_ext(&mut extensions, 0x0033, &key_share);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&cipher.to_u16().to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake_message(HS_SERVER_HELLO, &body)
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("ClientHello buffer: {0}")]
    ClientHelloBuffer(#[from] ClientHelloBufferError),
    #[error("ClientHello: {0}")]
    ClientHello(#[from] super::client_hello::ParseError),
    #[error("no shared TLS 1.3 cipher suite")]
    NoSharedCipherSuite,
    #[error("handshake preparation: {0}")]
    Prepare(#[from] PrepareError),
    #[error("client Finished: {0}")]
    ClientFinished(#[from] ClientFinishedError),
    #[error("TLS record authentication failed")]
    RecordAuthentication,
    #[error("unexpected TLS inner content type {0}")]
    UnexpectedInnerContentType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn app_keys() -> (
        TlsStream<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        RecordKeys,
        RecordKeys,
    ) {
        let (client, server) = tokio::io::duplex(8192);
        let suite = CipherSuite::Aes128GcmSha256;
        let client_write = RecordKeys::new(suite, vec![0x11; suite.key_len()], [0x22; 12]);
        let server_read = RecordKeys::new(suite, vec![0x11; suite.key_len()], [0x22; 12]);
        let server_write = RecordKeys::new(suite, vec![0x33; suite.key_len()], [0x44; 12]);
        let client_read = RecordKeys::new(suite, vec![0x33; suite.key_len()], [0x44; 12]);
        (
            TlsStream::new(server, server_read, server_write),
            client,
            client_write,
            client_read,
        )
    }

    #[tokio::test]
    async fn tls_stream_decrypts_reads_and_encrypts_writes() {
        let (mut server, mut client, mut client_write, mut client_read) = app_keys();
        let client_task = tokio::spawn(async move {
            client
                .write_all(&client_write.seal(RECORD_APPLICATION_DATA, b"ping"))
                .await
                .unwrap();
            let record = read_tls_record(&mut client).await.unwrap();
            let (content_type, plaintext) = client_read.open(&record).unwrap();
            assert_eq!(content_type, RECORD_APPLICATION_DATA);
            assert_eq!(plaintext, b"pong");
        });

        let mut inbound = [0u8; 4];
        server.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"ping");
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client_task.await.unwrap();
    }
}
