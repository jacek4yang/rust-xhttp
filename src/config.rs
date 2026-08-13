//! Server configuration: TOML schema, validation, and safe defaults.
//!
//! One binary, three deployment shapes (direct / cloudflare / nginx) selected purely by
//! the TLS section and listen address — the protocol stack is identical. Every limit from
//! the spec lives here with a safe default.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub xhttp: XhttpConfig,
    pub vless: VlessConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub observability: Observability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// e.g. "0.0.0.0:443" (direct/CF) or "127.0.0.1:8080" (behind nginx, plaintext h2c).
    pub addr: SocketAddr,
    /// Tokio worker threads. 0 = available parallelism.
    #[serde(default)]
    pub workers: usize,
    /// Enable TCP_NODELAY on accepted client sockets and outbound target TCP sockets.
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
    /// Enable SO_REUSEPORT on the listening socket (Linux multi-worker friendly).
    #[serde(default = "default_true")]
    pub reuse_port: bool,
    /// listen(2) backlog. Clamped to at least 1 at bind time.
    #[serde(default = "default_backlog")]
    pub backlog: i32,
    /// Kernel TCP keepalive idle seconds for long-lived streams. 0 = disabled.
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

fn default_backlog() -> i32 {
    4096
}

fn default_tcp_keepalive_secs() -> u64 {
    300
}

impl ListenConfig {
    pub fn worker_threads(&self) -> usize {
        if self.workers != 0 {
            return self.workers;
        }
        std::thread::available_parallelism().map_or(1, usize::from)
    }

    pub fn tcp_keepalive(&self) -> Option<Duration> {
        (self.tcp_keepalive_secs != 0).then(|| Duration::from_secs(self.tcp_keepalive_secs))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// ALPN protocols offered, in preference order. Default: ["h2", "http/1.1"].
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

fn default_alpn() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpConfig {
    /// Base path the XHTTP transport is mounted on. Normalized to start and end with '/'.
    pub path: String,
    /// Optional Host validation (empty = accept any).
    #[serde(default)]
    pub host: String,
    /// Max bytes per single upload POST (Xray `scMaxEachPostBytes`, default 1_000_000).
    #[serde(default = "default_max_each_post_bytes")]
    pub max_each_post_bytes: usize,
    /// Max out-of-order buffered packets per session (Xray `scMaxBufferedPosts`, default 30).
    #[serde(default = "default_max_buffered_posts")]
    pub max_buffered_posts: usize,
    /// Seconds before an un-GET'd session is reaped (Xray uses 30s).
    #[serde(default = "default_session_grace_secs")]
    pub session_grace_secs: u64,
    /// Emit `Content-Type: text/event-stream` on the download stream (Xray default true).
    #[serde(default = "default_true")]
    pub sse_header: bool,
    /// Max request header bytes (Xray default 8192).
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Minimum accepted XHTTP padding length.
    #[serde(default = "default_padding_from")]
    pub padding_from: u32,
    /// Maximum accepted XHTTP padding length.
    #[serde(default = "default_padding_to")]
    pub padding_to: u32,
    /// Where packet-up payload bytes are carried. Mirrors Xray
    /// `uplinkDataPlacement`; default is body.
    #[serde(default)]
    pub uplink_data_placement: UplinkDataPlacement,
    /// Key prefix for header/cookie packet-up payload chunks. Required when
    /// `uplink_data_placement` is header, cookie, or auto.
    #[serde(default)]
    pub uplink_data_key: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UplinkDataPlacement {
    #[default]
    Body,
    Header,
    Cookie,
    Auto,
}

fn default_max_each_post_bytes() -> usize {
    1_000_000
}
fn default_max_buffered_posts() -> usize {
    30
}
fn default_session_grace_secs() -> u64 {
    30
}
fn default_max_header_bytes() -> usize {
    8192
}
fn default_padding_from() -> u32 {
    100
}
fn default_padding_to() -> u32 {
    1000
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    pub users: Vec<UserConfig>,
    /// VLESS Encryption "decryption" config string (mlkem768x25519plus...). Empty = disabled.
    #[serde(default)]
    pub decryption: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub id: Uuid,
    #[serde(default)]
    pub email: String,
    /// "" or "xtls-rprx-vision".
    #[serde(default)]
    pub flow: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "d_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "d_max_pending_packets")]
    pub max_pending_packets_per_session: usize,
    #[serde(default = "d_max_pending_bytes")]
    pub max_pending_bytes_per_session: usize,
    #[serde(default = "d_global_buffer_bytes")]
    pub global_buffer_bytes: u64,
    #[serde(default = "d_max_target_conns")]
    pub max_concurrent_target_conns: usize,
    #[serde(default = "d_handshake_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "d_connect_secs")]
    pub target_connect_secs: u64,
    #[serde(default = "d_udp_idle_secs")]
    pub udp_association_idle_secs: u64,
}

fn d_max_sessions() -> usize {
    65536
}
fn d_max_pending_packets() -> usize {
    30
}
fn d_max_pending_bytes() -> usize {
    16 * 1024 * 1024
}
fn d_global_buffer_bytes() -> u64 {
    1024 * 1024 * 1024
}
fn d_max_target_conns() -> usize {
    100_000
}
fn d_handshake_secs() -> u64 {
    10
}
fn d_connect_secs() -> u64 {
    10
}
fn d_udp_idle_secs() -> u64 {
    60
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: d_max_sessions(),
            max_pending_packets_per_session: d_max_pending_packets(),
            max_pending_bytes_per_session: d_max_pending_bytes(),
            global_buffer_bytes: d_global_buffer_bytes(),
            max_concurrent_target_conns: d_max_target_conns(),
            handshake_timeout_secs: d_handshake_secs(),
            target_connect_secs: d_connect_secs(),
            udp_association_idle_secs: d_udp_idle_secs(),
        }
    }
}

impl Limits {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }
    pub fn target_connect(&self) -> Duration {
        Duration::from_secs(self.target_connect_secs)
    }
    pub fn udp_idle(&self) -> Duration {
        Duration::from_secs(self.udp_association_idle_secs)
    }
    pub fn session_grace(&self, x: &XhttpConfig) -> Duration {
        Duration::from_secs(x.session_grace_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    /// tracing filter, e.g. "info,rust_xhttp=debug".
    #[serde(default = "d_log")]
    pub log: String,
}

fn d_log() -> String {
    "info".into()
}

impl Default for Observability {
    fn default() -> Self {
        Self { log: d_log() }
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(s)?;
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        Self::from_toml_str(&s)
    }

    fn normalize_and_validate(&mut self) -> Result<(), ConfigError> {
        // normalize XHTTP path like Xray GetNormalizedPath: leading + trailing '/'.
        let p = &mut self.xhttp.path;
        if p.is_empty() || !p.starts_with('/') {
            p.insert(0, '/');
        }
        if !p.ends_with('/') {
            p.push('/');
        }
        if self.vless.users.is_empty() {
            return Err(ConfigError::Invalid("vless.users must be non-empty".into()));
        }
        for u in &self.vless.users {
            if !u.flow.is_empty() && u.flow != "xtls-rprx-vision" {
                return Err(ConfigError::Invalid(format!(
                    "unsupported flow: {:?} (only \"\" or \"xtls-rprx-vision\")",
                    u.flow
                )));
            }
        }
        if self.xhttp.max_buffered_posts == 0 {
            self.xhttp.max_buffered_posts = default_max_buffered_posts();
        }
        if self.xhttp.padding_from == 0 || self.xhttp.padding_from > self.xhttp.padding_to {
            return Err(ConfigError::Invalid(
                "xhttp padding range must satisfy 0 < padding_from <= padding_to".into(),
            ));
        }
        if self.xhttp.uplink_data_placement != UplinkDataPlacement::Body
            && self.xhttp.uplink_data_key.is_empty()
        {
            return Err(ConfigError::Invalid(
                "xhttp.uplink_data_key is required unless uplink_data_placement is \"body\"".into(),
            ));
        }
        if self.listen.workers == 0 {
            self.listen.workers = self.listen.worker_threads();
        }
        if self.listen.backlog < 1 {
            return Err(ConfigError::Invalid(
                "listen.backlog must be greater than 0".into(),
            ));
        }
        if self.limits.handshake_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.handshake_timeout_secs must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [listen]
        addr = "0.0.0.0:443"
        [tls]
        cert = "/etc/x/cert.pem"
        key = "/etc/x/key.pem"
        [xhttp]
        path = "yourpath"
        [vless]
        [[vless.users]]
        id = "b831381d-6324-4d53-ad4f-8cda48b30811"
        flow = "xtls-rprx-vision"
    "#;

    #[test]
    fn parses_and_normalizes_path() {
        let cfg = Config::from_toml_str(SAMPLE).unwrap();
        assert_eq!(cfg.xhttp.path, "/yourpath/");
        assert_eq!(cfg.xhttp.max_each_post_bytes, 1_000_000);
        assert_eq!(cfg.xhttp.max_buffered_posts, 30);
        assert_eq!(cfg.xhttp.uplink_data_placement, UplinkDataPlacement::Body);
        assert_eq!(cfg.limits.handshake_timeout_secs, 10);
        assert_eq!(cfg.vless.users.len(), 1);
        assert!(cfg.listen.workers >= 1);
        assert!(cfg.listen.tcp_nodelay);
        assert!(cfg.listen.reuse_port);
        assert_eq!(cfg.listen.backlog, 4096);
        assert_eq!(cfg.listen.tcp_keepalive_secs, 300);
    }

    #[test]
    fn rejects_bad_flow() {
        let bad = SAMPLE.replace("xtls-rprx-vision", "xtls-rprx-direct");
        assert!(Config::from_toml_str(&bad).is_err());
    }

    #[test]
    fn rejects_empty_users() {
        let s = r#"
            [listen]
            addr = "0.0.0.0:443"
            [xhttp]
            path = "/p/"
            [vless]
            users = []
        "#;
        assert!(Config::from_toml_str(s).is_err());
    }

    #[test]
    fn parses_header_uplink_placement_with_key() {
        let s = SAMPLE.replace(
            "path = \"yourpath\"",
            "path = \"yourpath\"\nuplink_data_placement = \"header\"\nuplink_data_key = \"X-Data\"",
        );
        let cfg = Config::from_toml_str(&s).unwrap();
        assert_eq!(cfg.xhttp.uplink_data_placement, UplinkDataPlacement::Header);
        assert_eq!(cfg.xhttp.uplink_data_key, "X-Data");
    }

    #[test]
    fn rejects_non_body_uplink_without_key() {
        let s = SAMPLE.replace(
            "path = \"yourpath\"",
            "path = \"yourpath\"\nuplink_data_placement = \"cookie\"",
        );
        assert!(Config::from_toml_str(&s).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let s = SAMPLE.replace(
            "addr = \"0.0.0.0:443\"",
            "addr = \"0.0.0.0:443\"\ntyop = true",
        );
        let error = Config::from_toml_str(&s).unwrap_err().to_string();
        assert!(error.contains("unknown field `tyop`"), "{error}");
    }

    #[test]
    fn rejects_zero_handshake_timeout() {
        let s = format!("{SAMPLE}\n[limits]\nhandshake_timeout_secs = 0\n");
        assert!(Config::from_toml_str(&s).is_err());
    }
}
