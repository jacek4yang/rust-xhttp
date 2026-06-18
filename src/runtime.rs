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
            grace: cfg.limits.session_grace(&cfg.xhttp),
            ..SessionConfig::default()
        },
        handler,
        metrics.clone(),
    );

    let origin = Origin::new(cfg.xhttp.clone(), sessions, metrics, cfg.tls.as_ref())?;
    let listener = tokio::net::TcpListener::bind(cfg.listen.addr).await?;
    tracing::info!(address = %cfg.listen.addr, "rust-xhttp listening");
    origin.serve(listener).await?;
    Ok(())
}
