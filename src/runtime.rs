//! Server wiring: build the protocol stack from a validated [`Config`] and serve.
//!
//! All the cross-module assembly lives here so [`main`](crate) stays a thin
//! argv/runtime shell. One binary serves the three deployment shapes (direct /
//! Cloudflare / nginx) — they differ only in the TLS section and listen address,
//! never in the protocol stack built below.

use std::sync::Arc;

use crate::config::Config;
use crate::dispatcher::Dispatcher;
use crate::metrics::Metrics;
use crate::origin::Origin;
use crate::session::{Handler, SessionConfig, SessionTable};
use crate::vless::{self, User, Validator};

/// Build the stack and serve until the listener errors or the process exits.
pub async fn serve(cfg: Arc<Config>) -> Result<(), Box<dyn std::error::Error>> {
    let validator = Validator::new(cfg.vless.users.iter().map(|user| User {
        id: *user.id.as_bytes(),
        email: user.email.clone(),
        flow: user.flow.clone(),
    }));
    let metrics = Metrics::new();

    let encryption = match cfg.vless.decryption.as_str() {
        "" | "none" => None,
        value => Some(vless::encryption::Server::new(
            vless::encryption::EncryptionConfig::parse(value)?,
        )),
    };

    let dispatcher = Dispatcher::new(
        validator,
        metrics.clone(),
        cfg.limits.max_concurrent_target_conns,
        cfg.limits.target_connect(),
        cfg.limits.udp_idle(),
    )
    .with_handshake_timeout(cfg.limits.handshake_timeout())
    .with_tcp_tuning(cfg.listen.tcp_nodelay, cfg.listen.tcp_keepalive())
    .with_encryption(encryption);
    let handler: Handler = Arc::new(move |conn| dispatcher.spawn(conn));

    let sessions = SessionTable::new(
        SessionConfig {
            max_sessions: cfg.limits.max_sessions,
            max_pending_packets: cfg
                .limits
                .max_pending_packets_per_session
                .min(cfg.xhttp.max_buffered_posts),
            max_pending_bytes: cfg.limits.max_pending_bytes_per_session,
            global_buffer_budget: Some(crate::buffer::MemoryBudget::new(
                cfg.limits.global_buffer_bytes,
            )),
            grace: cfg.limits.session_grace(&cfg.xhttp),
            ..SessionConfig::default()
        },
        handler,
        metrics.clone(),
    );

    let origin = Origin::new(
        cfg.xhttp.clone(),
        sessions,
        metrics,
        cfg.tls.as_ref(),
        cfg.listen.tcp_nodelay,
        cfg.listen.tcp_keepalive(),
    )?
    .with_handshake_timeout(cfg.limits.handshake_timeout());
    let listener =
        crate::net::bind_listener(cfg.listen.addr, cfg.listen.reuse_port, cfg.listen.backlog)?;
    tracing::info!(
        address = %cfg.listen.addr,
        workers = cfg.listen.workers,
        reuse_port = cfg.listen.reuse_port,
        backlog = cfg.listen.backlog,
        "rust-xhttp listening"
    );
    origin.serve(listener).await?;
    Ok(())
}
