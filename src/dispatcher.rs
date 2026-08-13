//! VLESS inbound dispatch to direct TCP targets.

use crate::metrics::Metrics;
use crate::session::{DownlinkSink, SessionConn, UplinkReader};
use crate::vless::{
    Addons, Command, Validator, XRV, decode_request_header, encode_response_header,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc};

#[derive(Clone)]
pub struct Dispatcher {
    validator: Validator,
    metrics: Arc<Metrics>,
    targets: Arc<Semaphore>,
    handshake_timeout: Duration,
    connect_timeout: Duration,
    udp_idle: Duration,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
    encryption: Option<Arc<crate::vless::encryption::Server>>,
}

impl Dispatcher {
    pub fn new(
        validator: Validator,
        metrics: Arc<Metrics>,
        max_targets: usize,
        connect_timeout: Duration,
        udp_idle: Duration,
    ) -> Self {
        Self {
            validator,
            metrics,
            targets: Arc::new(Semaphore::new(max_targets.max(1))),
            handshake_timeout: Duration::from_secs(10),
            connect_timeout,
            udp_idle,
            tcp_nodelay: true,
            tcp_keepalive: None,
            encryption: None,
        }
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn with_tcp_tuning(mut self, tcp_nodelay: bool, tcp_keepalive: Option<Duration>) -> Self {
        self.tcp_nodelay = tcp_nodelay;
        self.tcp_keepalive = tcp_keepalive;
        self
    }

    pub fn with_encryption(
        mut self,
        encryption: Option<Arc<crate::vless::encryption::Server>>,
    ) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn spawn(&self, conn: SessionConn) {
        let this = self.clone();
        let id_hash = conn.id_hash;
        tokio::spawn(async move {
            if let Err(error) = this.serve(conn).await {
                tracing::debug!(session = id_hash, %error, "session ended");
            }
        });
    }

    async fn serve(&self, conn: SessionConn) -> Result<(), DispatchError> {
        let SessionConn {
            mut reader,
            writer,
            id_hash: _,
        } = conn;
        let (mut reader, writer) = if let Some(server) = &self.encryption {
            let handshake = match tokio::time::timeout(
                self.handshake_timeout,
                server.handshake(&mut reader, |bytes| {
                    let writer = writer.clone();
                    async move {
                        writer
                            .send(bytes.into())
                            .await
                            .map_err(|_| crate::vless::encryption::HandshakeError::Send)
                    }
                }),
            )
            .await
            {
                Ok(Ok(handshake)) => handshake,
                Ok(Err(error)) => {
                    self.metrics
                        .encryption_handshake_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error.into());
                }
                Err(_) => {
                    self.metrics
                        .encryption_handshake_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(DispatchError::HandshakeTimeout);
                }
            };
            (
                ClientReader::Encrypted(Box::new(crate::vless::encryption::EncryptedReader::new(
                    reader,
                    handshake.decrypt,
                    handshake.inbound_xor,
                ))),
                ProtocolWriter::encrypted(writer, handshake.encrypt, handshake.outbound_xor),
            )
        } else {
            (ClientReader::Plain(reader), ProtocolWriter::Plain(writer))
        };
        let (user, header, addons) = match tokio::time::timeout(
            self.handshake_timeout,
            decode_request_header(&mut reader, &self.validator),
        )
        .await
        {
            Ok(Ok(parsed)) => parsed,
            Ok(Err(error)) => {
                self.metrics
                    .vless_auth_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
            Err(_) => {
                self.metrics
                    .vless_auth_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(DispatchError::HandshakeTimeout);
            }
        };
        if addons.flow != user.flow || (!addons.flow.is_empty() && addons.flow != XRV) {
            return Err(DispatchError::FlowMismatch);
        }
        let vision_uuid = (addons.flow == XRV).then_some(header.raw_id);
        writer
            .send(encode_response_header(header.version, &Addons::default())?.into())
            .await?;

        match header.command {
            Command::Tcp => {
                let address = header.address.ok_or(DispatchError::MissingAddress)?;
                self.serve_tcp(
                    reader,
                    writer,
                    address.connect_target(header.port),
                    vision_uuid,
                )
                .await
            }
            Command::Udp => {
                if vision_uuid.is_some() {
                    return Err(DispatchError::VisionUdpUnsupported);
                }
                let address = header.address.ok_or(DispatchError::MissingAddress)?;
                self.serve_udp(reader, writer, address.connect_target(header.port))
                    .await
            }
            Command::Mux if vision_uuid.is_none() => self.serve_xudp(reader, writer).await,
            Command::Mux => Err(DispatchError::VisionXudpUnavailable),
            command => Err(DispatchError::UnsupportedCommand(command)),
        }
    }

    async fn serve_tcp(
        &self,
        mut reader: ClientReader,
        writer: ProtocolWriter,
        target: String,
        vision_uuid: Option<[u8; 16]>,
    ) -> Result<(), DispatchError> {
        let _permit = self
            .targets
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DispatchError::ShuttingDown)?;
        let mut stream =
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    self.metrics
                        .target_connect_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error.into());
                }
                Err(_) => {
                    self.metrics
                        .target_connect_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(DispatchError::ConnectTimeout);
                }
            };
        crate::net::tune_stream(&stream, self.tcp_nodelay, self.tcp_keepalive);

        Metrics::add_gauge(&self.metrics.active_target_conns, 1);
        let result: Result<(), DispatchError> = async {
            let (mut target_read, mut target_write) = stream.split();
            if let Some(uuid) = vision_uuid {
                let reader = crate::vless::vision::VisionReader::new(&mut reader, uuid);
                pump_tcp(
                    reader,
                    &mut target_read,
                    &mut target_write,
                    &writer,
                    &self.metrics,
                    Some(crate::vless::vision::VisionWriter::new(uuid)),
                )
                .await
            } else {
                pump_tcp(
                    &mut reader,
                    &mut target_read,
                    &mut target_write,
                    &writer,
                    &self.metrics,
                    None,
                )
                .await
            }
        }
        .await;
        Metrics::add_gauge(&self.metrics.active_target_conns, -1);
        result
    }

    async fn serve_udp(
        &self,
        mut reader: ClientReader,
        writer: ProtocolWriter,
        target: String,
    ) -> Result<(), DispatchError> {
        let _permit = self
            .targets
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DispatchError::ShuttingDown)?;
        let mut resolved =
            tokio::time::timeout(self.connect_timeout, tokio::net::lookup_host(target))
                .await
                .map_err(|_| DispatchError::ConnectTimeout)??;
        let target = resolved.next().ok_or(DispatchError::MissingAddress)?;
        let bind = if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(target).await?;
        Metrics::add_gauge(&self.metrics.active_target_conns, 1);
        let result: Result<(), DispatchError> = async {
            let mut receive_buf = vec![0u8; u16::MAX as usize];
            loop {
                let operation = async {
                    tokio::select! {
                        datagram = crate::xudp::read_plain_datagram(&mut reader) => {
                            let datagram = datagram?;
                            socket.send(&datagram).await?;
                        }
                        received = socket.recv(&mut receive_buf) => {
                            let n = received?;
                            self.metrics.download_bytes.fetch_add(n as u64, Ordering::Relaxed);
                            writer.send(crate::xudp::encode_plain_datagram(&receive_buf[..n])?).await?;
                        }
                    }
                    Ok::<(), DispatchError>(())
                };
                tokio::time::timeout(self.udp_idle, operation)
                    .await
                    .map_err(|_| DispatchError::UdpIdle)??;
            }
        }
        .await;
        Metrics::add_gauge(&self.metrics.active_target_conns, -1);
        result
    }

    async fn serve_xudp(
        &self,
        mut reader: ClientReader,
        writer: ProtocolWriter,
    ) -> Result<(), DispatchError> {
        let mut associations: HashMap<u16, mpsc::Sender<AssociationMessage>> = HashMap::new();
        loop {
            let frame = tokio::time::timeout(self.udp_idle, crate::xudp::read_frame(&mut reader))
                .await
                .map_err(|_| DispatchError::UdpIdle)??;
            match frame.status {
                crate::xudp::STATUS_NEW => {
                    let target = frame.target.ok_or(DispatchError::MissingAddress)?;
                    let permit = self
                        .targets
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| DispatchError::ShuttingDown)?;
                    let (tx, rx) = mpsc::channel(32);
                    associations.insert(frame.session_id, tx.clone());
                    spawn_association(
                        frame.session_id,
                        target.clone(),
                        rx,
                        writer.clone(),
                        self.metrics.clone(),
                        self.udp_idle,
                        permit,
                    )
                    .await?;
                    if frame.option & crate::xudp::OPTION_DATA != 0 {
                        tx.send(AssociationMessage {
                            target,
                            payload: frame.payload,
                        })
                        .await
                        .map_err(|_| DispatchError::AssociationClosed)?;
                    }
                }
                crate::xudp::STATUS_KEEP => {
                    if frame.option & crate::xudp::OPTION_DATA == 0 {
                        continue;
                    }
                    let tx = associations
                        .get(&frame.session_id)
                        .ok_or(DispatchError::UnknownAssociation(frame.session_id))?;
                    let target = frame.target.ok_or(DispatchError::MissingAddress)?;
                    tx.send(AssociationMessage {
                        target,
                        payload: frame.payload,
                    })
                    .await
                    .map_err(|_| DispatchError::AssociationClosed)?;
                }
                crate::xudp::STATUS_END => {
                    associations.remove(&frame.session_id);
                }
                crate::xudp::STATUS_KEEP_ALIVE => {}
                _ => return Err(DispatchError::UnsupportedXudpStatus(frame.status)),
            }
        }
    }
}

enum ClientReader {
    Plain(UplinkReader),
    // Boxed: the encrypted reader carries the full record cipher + buffers and is much
    // larger than the plain variant, so keep `ClientReader` small.
    Encrypted(Box<crate::vless::encryption::EncryptedReader<UplinkReader>>),
}

impl AsyncRead for ClientReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(reader) => Pin::new(reader).poll_read(cx, buf),
            Self::Encrypted(reader) => Pin::new(&mut **reader).poll_read(cx, buf),
        }
    }
}

#[derive(Clone)]
enum ProtocolWriter {
    Plain(DownlinkSink),
    Encrypted {
        sink: DownlinkSink,
        state: Arc<AsyncMutex<EncryptState>>,
    },
}

struct EncryptState {
    cipher: crate::vless::encryption::RecordCipher,
    xor: Option<crate::vless::encryption::HeaderXor>,
}

impl ProtocolWriter {
    fn encrypted(
        sink: DownlinkSink,
        cipher: crate::vless::encryption::RecordCipher,
        xor: Option<crate::vless::encryption::HeaderXor>,
    ) -> Self {
        Self::Encrypted {
            sink,
            state: Arc::new(AsyncMutex::new(EncryptState { cipher, xor })),
        }
    }

    async fn send(&self, bytes: bytes::Bytes) -> Result<(), DispatchError> {
        match self {
            Self::Plain(sink) => sink
                .send(bytes)
                .await
                .map_err(|_| DispatchError::DownloadClosed),
            Self::Encrypted { sink, state } => {
                let mut state = state.lock().await;
                for chunk in bytes.chunks(8192) {
                    let mut record = state.cipher.seal(chunk)?;
                    if let Some(xor) = state.xor.as_mut() {
                        xor.apply(&mut record)?;
                    }
                    sink.send(record.into())
                        .await
                        .map_err(|_| DispatchError::DownloadClosed)?;
                }
                Ok(())
            }
        }
    }
}

async fn pump_tcp<R: AsyncRead + Unpin>(
    mut client_reader: R,
    target_read: &mut (impl AsyncRead + Unpin),
    target_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    client_writer: &ProtocolWriter,
    metrics: &Metrics,
    mut vision: Option<crate::vless::vision::VisionWriter>,
) -> Result<(), DispatchError> {
    let mut upload = Box::pin(copy_upload(&mut client_reader, target_write));
    let mut download = Box::pin(copy_download(
        target_read,
        client_writer,
        metrics,
        vision.as_mut(),
    ));
    tokio::select! {
        result = &mut download => result,
        result = &mut upload => {
            result?;
            download.await
        }
    }
}

struct AssociationMessage {
    target: crate::xudp::Target,
    payload: bytes::Bytes,
}

async fn spawn_association(
    session_id: u16,
    initial_target: crate::xudp::Target,
    mut rx: mpsc::Receiver<AssociationMessage>,
    writer: ProtocolWriter,
    metrics: Arc<Metrics>,
    idle: Duration,
    permit: OwnedSemaphorePermit,
) -> Result<(), DispatchError> {
    let target = resolve_target(&initial_target).await?;
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    tokio::spawn(async move {
        let _permit = permit;
        Metrics::add_gauge(&metrics.active_target_conns, 1);
        let result: Result<(), DispatchError> = async {
            let mut receive_buf = vec![0u8; u16::MAX as usize];
            loop {
                let operation = async {
                    tokio::select! {
                        message = rx.recv() => {
                            let Some(message) = message else {
                                return Err(DispatchError::AssociationClosed);
                            };
                            let target = resolve_target(&message.target).await?;
                            socket.send_to(&message.payload, target).await?;
                        }
                        received = socket.recv_from(&mut receive_buf) => {
                            let (n, source) = received?;
                            metrics.download_bytes.fetch_add(n as u64, Ordering::Relaxed);
                            let frame = crate::xudp::Frame {
                                session_id,
                                status: crate::xudp::STATUS_KEEP,
                                option: crate::xudp::OPTION_DATA,
                                target: Some(socket_target(source)),
                                global_id: None,
                                payload: bytes::Bytes::copy_from_slice(&receive_buf[..n]),
                            };
                            writer.send(crate::xudp::encode_frame(&frame)?).await?;
                        }
                    }
                    Ok::<(), DispatchError>(())
                };
                tokio::time::timeout(idle, operation)
                    .await
                    .map_err(|_| DispatchError::UdpIdle)??;
            }
        }
        .await;
        Metrics::add_gauge(&metrics.active_target_conns, -1);
        if let Err(error) = result {
            tracing::debug!(session_id, %error, "XUDP association ended");
        }
    });
    Ok(())
}

async fn resolve_target(target: &crate::xudp::Target) -> Result<SocketAddr, DispatchError> {
    let mut addresses = tokio::net::lookup_host(target.address.connect_target(target.port)).await?;
    addresses.next().ok_or(DispatchError::MissingAddress)
}

fn socket_target(address: SocketAddr) -> crate::xudp::Target {
    let address_value = match address.ip() {
        IpAddr::V4(ip) => crate::vless::Address::Ipv4(ip),
        IpAddr::V6(ip) => crate::vless::Address::Ipv6(ip),
    };
    crate::xudp::Target {
        address: address_value,
        port: address.port(),
    }
}

async fn copy_upload<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), DispatchError> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
    }
}

async fn copy_download<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &ProtocolWriter,
    metrics: &Metrics,
    mut vision: Option<&mut crate::vless::vision::VisionWriter>,
) -> Result<(), DispatchError> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        metrics
            .download_bytes
            .fetch_add(n as u64, Ordering::Relaxed);
        if let Some(vision) = vision.as_mut() {
            for frame in vision.encode(&buf[..n])? {
                writer.send(frame).await?;
            }
        } else {
            writer
                .send(bytes::Bytes::copy_from_slice(&buf[..n]))
                .await?;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("vless header: {0}")]
    Header(#[from] crate::vless::HeaderError),
    #[error("xudp: {0}")]
    Xudp(#[from] crate::xudp::XudpError),
    #[error("vision: {0}")]
    Vision(#[from] crate::vless::vision::VisionError),
    #[error("VLESS-Encryption handshake: {0}")]
    EncryptionHandshake(#[from] crate::vless::encryption::HandshakeError),
    #[error("VLESS-Encryption record: {0}")]
    EncryptionRecord(#[from] crate::vless::encryption::RecordError),
    #[error("VLESS-Encryption XOR: {0}")]
    EncryptionXor(#[from] crate::vless::encryption::XorError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("flow does not match configured user")]
    FlowMismatch,
    #[error("Vision does not support the plain UDP command")]
    VisionUdpUnsupported,
    #[error("Vision-wrapped XUDP is not available")]
    VisionXudpUnavailable,
    #[error("unsupported command: {0:?}")]
    UnsupportedCommand(Command),
    #[error("request has no target address")]
    MissingAddress,
    #[error("target connect timed out")]
    ConnectTimeout,
    #[error("protocol handshake timed out")]
    HandshakeTimeout,
    #[error("UDP association idle timeout")]
    UdpIdle,
    #[error("XUDP association is closed")]
    AssociationClosed,
    #[error("unknown XUDP association: {0}")]
    UnknownAssociation(u16),
    #[error("unsupported XUDP status: {0}")]
    UnsupportedXudpStatus(u8),
    #[error("download stream closed")]
    DownloadClosed,
    #[error("server is shutting down")]
    ShuttingDown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{downlink_channel, uplink_channel};
    use crate::vless::User;
    use bytes::Bytes;

    #[tokio::test]
    async fn incomplete_vless_header_times_out() {
        let id = [6u8; 16];
        let validator = Validator::new([User {
            id,
            email: "timeout".into(),
            flow: String::new(),
        }]);
        let metrics = Metrics::new();
        let dispatcher = Dispatcher::new(
            validator,
            metrics.clone(),
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .with_handshake_timeout(Duration::from_millis(10));
        let (_uplink, reader) = uplink_channel(30, 1 << 20, 32);
        let (writer, mut downlink) = downlink_channel(32);

        dispatcher.spawn(SessionConn {
            reader,
            writer,
            id_hash: 0,
        });

        assert!(
            tokio::time::timeout(Duration::from_secs(1), downlink.recv())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(metrics.vless_auth_failures.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn vless_tcp_echo() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });

        let id = [7u8; 16];
        let validator = Validator::new([User {
            id,
            email: "test".into(),
            flow: String::new(),
        }]);
        let metrics = Metrics::new();
        let dispatcher = Dispatcher::new(
            validator,
            metrics,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let (uplink, reader) = uplink_channel(30, 1 << 20, 32);
        let (writer, mut downlink) = downlink_channel(32);
        dispatcher.spawn(SessionConn {
            reader,
            writer,
            id_hash: 1,
        });

        let mut wire = vec![0];
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&[0, 1]);
        wire.extend_from_slice(&target.port().to_be_bytes());
        wire.push(1);
        wire.extend_from_slice(&[127, 0, 0, 1]);
        wire.extend_from_slice(b"hello");
        assert_eq!(
            uplink.push(0, Bytes::from(wire)).await,
            crate::session::PushResult::Accepted
        );

        let header = downlink.recv().await.unwrap();
        assert_eq!(header.as_ref(), &[0, 0]);
        let echoed = downlink.recv().await.unwrap();
        assert_eq!(echoed.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn vless_plain_udp_echo() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..n], peer).await.unwrap();
        });

        let id = [8u8; 16];
        let validator = Validator::new([User {
            id,
            email: "udp".into(),
            flow: String::new(),
        }]);
        let dispatcher = Dispatcher::new(
            validator,
            Metrics::new(),
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let (uplink, reader) = uplink_channel(30, 1 << 20, 32);
        let (writer, mut downlink) = downlink_channel(32);
        dispatcher.spawn(SessionConn {
            reader,
            writer,
            id_hash: 2,
        });

        let mut wire = vec![0];
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&[0, 2]);
        wire.extend_from_slice(&target.port().to_be_bytes());
        wire.push(1);
        wire.extend_from_slice(&[127, 0, 0, 1]);
        wire.extend_from_slice(&crate::xudp::encode_plain_datagram(b"dns").unwrap());
        uplink.push(0, Bytes::from(wire)).await;

        assert_eq!(downlink.recv().await.unwrap().as_ref(), &[0, 0]);
        assert_eq!(
            downlink.recv().await.unwrap(),
            crate::xudp::encode_plain_datagram(b"dns").unwrap()
        );
    }

    #[tokio::test]
    async fn vless_xudp_echo() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..n], peer).await.unwrap();
        });

        let id = [9u8; 16];
        let validator = Validator::new([User {
            id,
            email: "xudp".into(),
            flow: String::new(),
        }]);
        let dispatcher = Dispatcher::new(
            validator,
            Metrics::new(),
            2,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let (uplink, reader) = uplink_channel(30, 1 << 20, 32);
        let (writer, mut downlink) = downlink_channel(32);
        dispatcher.spawn(SessionConn {
            reader,
            writer,
            id_hash: 3,
        });

        let frame = crate::xudp::Frame {
            session_id: 7,
            status: crate::xudp::STATUS_NEW,
            option: crate::xudp::OPTION_DATA,
            target: Some(crate::xudp::Target {
                address: crate::vless::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                port: target.port(),
            }),
            global_id: Some([0; 8]),
            payload: Bytes::from_static(b"xudp"),
        };
        let mut wire = vec![0];
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&[0, 3]);
        wire.extend_from_slice(&crate::xudp::encode_frame(&frame).unwrap());
        uplink.push(0, Bytes::from(wire)).await;

        assert_eq!(downlink.recv().await.unwrap().as_ref(), &[0, 0]);
        let response = downlink.recv().await.unwrap();
        let response = crate::xudp::read_frame(&mut std::io::Cursor::new(response))
            .await
            .unwrap();
        assert_eq!(response.session_id, 7);
        assert_eq!(response.status, crate::xudp::STATUS_KEEP);
        assert_eq!(response.payload.as_ref(), b"xudp");
    }

    #[tokio::test]
    async fn vless_vision_tcp_echo() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });

        let id = [10u8; 16];
        let validator = Validator::new([User {
            id,
            email: "vision".into(),
            flow: XRV.into(),
        }]);
        let dispatcher = Dispatcher::new(
            validator,
            Metrics::new(),
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let (uplink, reader) = uplink_channel(30, 1 << 20, 32);
        let (writer, mut downlink) = downlink_channel(32);
        dispatcher.spawn(SessionConn {
            reader,
            writer,
            id_hash: 4,
        });

        let mut wire = vec![0];
        wire.extend_from_slice(&id);
        wire.extend_from_slice(
            &crate::vless::addons::encode_addons(&Addons {
                flow: XRV.into(),
                seed: Vec::new(),
            })
            .unwrap(),
        );
        wire.push(1);
        wire.extend_from_slice(&target.port().to_be_bytes());
        wire.push(1);
        wire.extend_from_slice(&[127, 0, 0, 1]);
        wire.extend_from_slice(
            &crate::vless::vision::encode_frame(
                b"vision",
                crate::vless::vision::COMMAND_END,
                Some(id),
                false,
            )
            .unwrap(),
        );
        uplink.push(0, Bytes::from(wire)).await;

        assert_eq!(downlink.recv().await.unwrap().as_ref(), &[0, 0]);
        let framed = downlink.recv().await.unwrap();
        let mut reader = crate::vless::vision::VisionReader::new(std::io::Cursor::new(framed), id);
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"vision");
    }
}
