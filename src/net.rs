//! Linux TCP socket tuning for the client-facing origin and outbound dials.
//!
//! The project targets x86_64 Linux servers, so we configure the options that
//! materially affect high-concurrency proxy workloads in one place.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpStream};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_RETRIES: u32 = 3;

pub fn bind_listener(addr: SocketAddr, reuse_port: bool, backlog: i32) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(backlog.max(1))?;
    TcpListener::from_std(socket.into())
}

pub fn tune_stream(stream: &TcpStream, tcp_nodelay: bool, keepalive_idle: Option<Duration>) {
    let socket = SockRef::from(stream);
    if tcp_nodelay {
        let _ = socket.set_tcp_nodelay(true);
    }
    if let Some(idle) = keepalive_idle {
        let keepalive = TcpKeepalive::new()
            .with_time(idle)
            .with_interval(KEEPALIVE_INTERVAL)
            .with_retries(KEEPALIVE_RETRIES);
        let _ = socket.set_tcp_keepalive(&keepalive);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_listener_accepts_connections() {
        let listener = bind_listener("127.0.0.1:0".parse().unwrap(), true, 128).unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        tune_stream(&client, true, Some(Duration::from_secs(60)));
        tune_stream(&server, true, None);
    }
}
