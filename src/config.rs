//! Xray-shaped JSON configuration, validation, and safe runtime defaults.

use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Validated internal configuration consumed by the runtime.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: Option<TlsConfig>,
    pub xhttp: XhttpConfig,
    pub vless: VlessConfig,
    pub limits: Limits,
    pub observability: Observability,
    pub fallback: FallbackConfig,
}

#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub addr: SocketAddr,
    pub workers: usize,
    pub tcp_nodelay: bool,
    pub reuse_port: bool,
    pub backlog: i32,
    pub tcp_keepalive_secs: u64,
    pub graceful_shutdown_secs: u64,
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

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub alpn: Vec<String>,
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub email: String,
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    #[serde(default)]
    pub ca_certificate_file: Option<PathBuf>,
    #[serde(default = "default_acme_challenge_listen")]
    pub challenge_listen: SocketAddr,
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u64,
    #[serde(default = "default_renew_check_hours")]
    pub renew_check_hours: u64,
    #[serde(default)]
    pub accept_terms: bool,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".into()
}
fn default_acme_challenge_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 80))
}
fn default_acme_cache_dir() -> PathBuf {
    PathBuf::from("/var/lib/rust-xhttp/acme")
}
fn default_renew_before_days() -> u64 {
    30
}
fn default_renew_check_hours() -> u64 {
    12
}

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub host: String,
    pub max_each_post_bytes: usize,
    pub max_buffered_posts: usize,
    pub session_grace_secs: u64,
    pub sse_header: bool,
    pub max_header_bytes: usize,
    pub padding_from: u32,
    pub padding_to: u32,
    pub uplink_data_placement: UplinkDataPlacement,
    pub uplink_data_key: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UplinkDataPlacement {
    #[default]
    Body,
    Header,
    Cookie,
    Auto,
}

#[derive(Debug, Clone)]
pub struct VlessConfig {
    pub users: Vec<UserConfig>,
    pub decryption: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub id: Uuid,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub flow: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
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
    pub handshake_timeout_seconds: u64,
    #[serde(default = "d_connect_secs")]
    pub target_connect_seconds: u64,
    #[serde(default = "d_udp_idle_secs")]
    pub udp_association_idle_seconds: u64,
}

fn d_max_sessions() -> usize {
    65_536
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
            handshake_timeout_seconds: d_handshake_secs(),
            target_connect_seconds: d_connect_secs(),
            udp_association_idle_seconds: d_udp_idle_secs(),
        }
    }
}

impl Limits {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_seconds)
    }
    pub fn target_connect(&self) -> Duration {
        Duration::from_secs(self.target_connect_seconds)
    }
    pub fn udp_idle(&self) -> Duration {
        Duration::from_secs(self.udp_association_idle_seconds)
    }
    pub fn session_grace(&self, x: &XhttpConfig) -> Duration {
        Duration::from_secs(x.session_grace_secs)
    }
}

#[derive(Debug, Clone)]
pub struct Observability {
    pub log: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FallbackMode {
    #[default]
    Builtin,
    Directory,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FallbackConfig {
    #[serde(default)]
    pub mode: FallbackMode,
    #[serde(default)]
    pub dist: Option<PathBuf>,
    #[serde(default = "default_index_file")]
    pub index: String,
    #[serde(default)]
    pub not_found: Option<String>,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default = "default_max_site_bytes")]
    pub max_total_bytes: usize,
    #[serde(default)]
    pub site: SiteConfig,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            mode: FallbackMode::Builtin,
            dist: None,
            index: default_index_file(),
            not_found: None,
            max_file_bytes: default_max_file_bytes(),
            max_total_bytes: default_max_site_bytes(),
            site: SiteConfig::default(),
        }
    }
}

fn default_index_file() -> String {
    "index.html".into()
}
fn default_max_file_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_max_site_bytes() -> usize {
    128 * 1024 * 1024
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SiteConfig {
    #[serde(default)]
    pub seed: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub language: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonConfig {
    #[serde(default)]
    log: LogConfig,
    inbounds: Vec<InboundConfig>,
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    fallback: FallbackConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LogConfig {
    #[serde(default = "default_log_level")]
    loglevel: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            loglevel: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InboundConfig {
    #[serde(default)]
    tag: String,
    #[serde(default = "default_listen_ip")]
    listen: IpAddr,
    port: u16,
    protocol: String,
    settings: VlessInboundSettings,
    stream_settings: StreamSettings,
}

fn default_listen_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessInboundSettings {
    #[serde(alias = "users")]
    clients: Vec<UserConfig>,
    #[serde(default)]
    decryption: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StreamSettings {
    network: String,
    #[serde(default = "default_security")]
    security: String,
    #[serde(default)]
    tls_settings: Option<TlsSettings>,
    xhttp_settings: XhttpSettings,
}

fn default_security() -> String {
    "none".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TlsSettings {
    #[serde(default = "default_alpn")]
    alpn: Vec<String>,
    #[serde(default)]
    certificates: Vec<TlsCertificateConfig>,
    #[serde(default)]
    acme: Option<AcmeConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TlsCertificateConfig {
    certificate_file: PathBuf,
    key_file: PathBuf,
}

fn default_alpn() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct XhttpSettings {
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default = "default_max_each_post_bytes")]
    sc_max_each_post_bytes: usize,
    #[serde(default = "default_max_buffered_posts")]
    sc_max_buffered_posts: usize,
    #[serde(default = "default_session_grace_secs")]
    session_grace_seconds: u64,
    #[serde(default, rename = "noSSEHeader")]
    no_sse_header: bool,
    #[serde(default = "default_max_header_bytes")]
    server_max_header_bytes: usize,
    #[serde(default = "default_padding_range")]
    x_padding_bytes: String,
    #[serde(default)]
    uplink_data_placement: UplinkDataPlacement,
    #[serde(default)]
    uplink_data_key: String,
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
fn default_padding_range() -> String {
    "100-1000".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ServerConfig {
    #[serde(default)]
    workers: usize,
    #[serde(default = "default_true")]
    tcp_nodelay: bool,
    #[serde(default = "default_true")]
    reuse_port: bool,
    #[serde(default = "default_backlog")]
    backlog: i32,
    #[serde(default = "default_tcp_keepalive_secs")]
    tcp_keepalive_seconds: u64,
    #[serde(default = "default_graceful_shutdown_secs")]
    graceful_shutdown_seconds: u64,
    #[serde(default)]
    limits: Limits,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            workers: 0,
            tcp_nodelay: true,
            reuse_port: true,
            backlog: default_backlog(),
            tcp_keepalive_seconds: default_tcp_keepalive_secs(),
            graceful_shutdown_seconds: default_graceful_shutdown_secs(),
            limits: Limits::default(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_backlog() -> i32 {
    4096
}
fn default_tcp_keepalive_secs() -> u64 {
    300
}
fn default_graceful_shutdown_secs() -> u64 {
    30
}

impl Config {
    pub fn from_json_str(source: &str) -> Result<Self, ConfigError> {
        let raw: JsonConfig = serde_json::from_str(source)?;
        Self::try_from(raw)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let source = std::fs::read_to_string(path)?;
        Self::from_json_str(&source)
    }

    fn try_from(mut raw: JsonConfig) -> Result<Self, ConfigError> {
        if raw.inbounds.len() != 1 {
            return Err(ConfigError::Invalid(
                "exactly one VLESS/XHTTP inbound is supported".into(),
            ));
        }
        let inbound = raw.inbounds.remove(0);
        if !inbound.protocol.eq_ignore_ascii_case("vless") {
            return Err(ConfigError::Invalid(format!(
                "inbound {:?} uses unsupported protocol {:?}; expected \"vless\"",
                inbound.tag, inbound.protocol
            )));
        }
        if !inbound
            .stream_settings
            .network
            .eq_ignore_ascii_case("xhttp")
        {
            return Err(ConfigError::Invalid(
                "streamSettings.network must be \"xhttp\"".into(),
            ));
        }
        if inbound.port == 0 {
            return Err(ConfigError::Invalid("inbound port must be non-zero".into()));
        }

        let tls = parse_tls(&inbound.stream_settings)?;
        if tls
            .as_ref()
            .and_then(|value| value.acme.as_ref())
            .is_some_and(|acme| acme.challenge_listen.port() == inbound.port)
        {
            return Err(ConfigError::Invalid(
                "ACME challengeListen and the TLS inbound cannot use the same TCP port".into(),
            ));
        }
        let mut xhttp = parse_xhttp(inbound.stream_settings.xhttp_settings)?;
        let vless = VlessConfig {
            users: inbound.settings.clients,
            decryption: inbound.settings.decryption,
        };
        if vless.users.is_empty() {
            return Err(ConfigError::Invalid(
                "inbounds[0].settings.clients must be non-empty".into(),
            ));
        }
        for user in &vless.users {
            if !user.flow.is_empty() && user.flow != "xtls-rprx-vision" {
                return Err(ConfigError::Invalid(format!(
                    "unsupported flow {:?}; expected \"\" or \"xtls-rprx-vision\"",
                    user.flow
                )));
            }
        }

        normalize_xhttp(&mut xhttp)?;
        validate_server(&raw.server)?;
        validate_fallback(&mut raw.fallback, &xhttp)?;

        Ok(Self {
            listen: ListenConfig {
                addr: SocketAddr::new(inbound.listen, inbound.port),
                workers: raw.server.workers,
                tcp_nodelay: raw.server.tcp_nodelay,
                reuse_port: raw.server.reuse_port,
                backlog: raw.server.backlog,
                tcp_keepalive_secs: raw.server.tcp_keepalive_seconds,
                graceful_shutdown_secs: raw.server.graceful_shutdown_seconds,
            },
            tls,
            xhttp,
            vless,
            limits: raw.server.limits,
            observability: Observability {
                log: raw.log.loglevel,
            },
            fallback: raw.fallback,
        })
    }
}

fn parse_tls(stream: &StreamSettings) -> Result<Option<TlsConfig>, ConfigError> {
    match stream.security.to_ascii_lowercase().as_str() {
        "" | "none" => {
            if stream.tls_settings.is_some() {
                return Err(ConfigError::Invalid(
                    "tlsSettings requires streamSettings.security = \"tls\"".into(),
                ));
            }
            Ok(None)
        }
        "tls" => {
            let settings = stream.tls_settings.as_ref().ok_or_else(|| {
                ConfigError::Invalid(
                    "streamSettings.security = \"tls\" requires tlsSettings".into(),
                )
            })?;
            if settings.alpn.is_empty()
                || settings
                    .alpn
                    .iter()
                    .any(|value| value != "h2" && value != "http/1.1")
            {
                return Err(ConfigError::Invalid(
                    "tlsSettings.alpn must contain only h2 and/or http/1.1".into(),
                ));
            }
            match (settings.certificates.as_slice(), settings.acme.clone()) {
                ([manual], None) => Ok(Some(TlsConfig {
                    cert: manual.certificate_file.clone(),
                    key: manual.key_file.clone(),
                    alpn: settings.alpn.clone(),
                    acme: None,
                })),
                ([], Some(acme)) => {
                    validate_acme(&acme)?;
                    Ok(Some(TlsConfig {
                        cert: acme.cache_dir.join("current/certificate.pem"),
                        key: acme.cache_dir.join("current/private-key.pem"),
                        alpn: settings.alpn.clone(),
                        acme: Some(acme),
                    }))
                }
                _ => Err(ConfigError::Invalid(
                    "tlsSettings requires exactly one manual certificate or one acme object".into(),
                )),
            }
        }
        other => Err(ConfigError::Invalid(format!(
            "unsupported streamSettings.security {other:?}"
        ))),
    }
}

fn validate_acme(acme: &AcmeConfig) -> Result<(), ConfigError> {
    if !acme.accept_terms {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.acceptTerms must be true".into(),
        ));
    }
    if acme.domains.is_empty() {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.domains must be non-empty".into(),
        ));
    }
    if acme.challenge_listen.port() == 0 {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.challengeListen port must be non-zero".into(),
        ));
    }
    for domain in &acme.domains {
        if domain.is_empty()
            || !domain.is_ascii()
            || domain.starts_with("*.")
            || domain.contains(['/', ':', ' ', '\t', '\n'])
            || !domain.contains('.')
        {
            return Err(ConfigError::Invalid(format!(
                "invalid HTTP-01 ACME DNS name {domain:?}"
            )));
        }
    }
    if !acme.email.contains('@') {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.email must be a valid contact address".into(),
        ));
    }
    if !acme.directory_url.starts_with("https://") {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.directoryUrl must use https".into(),
        ));
    }
    if acme.renew_before_days == 0 || acme.renew_before_days >= 90 {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.renewBeforeDays must be between 1 and 89".into(),
        ));
    }
    if acme.renew_check_hours == 0 {
        return Err(ConfigError::Invalid(
            "tlsSettings.acme.renewCheckHours must be non-zero".into(),
        ));
    }
    Ok(())
}

fn parse_xhttp(raw: XhttpSettings) -> Result<XhttpConfig, ConfigError> {
    let (padding_from, padding_to) = parse_range(&raw.x_padding_bytes)?;
    Ok(XhttpConfig {
        path: raw.path,
        host: raw.host,
        max_each_post_bytes: raw.sc_max_each_post_bytes,
        max_buffered_posts: raw.sc_max_buffered_posts,
        session_grace_secs: raw.session_grace_seconds,
        sse_header: !raw.no_sse_header,
        max_header_bytes: raw.server_max_header_bytes,
        padding_from,
        padding_to,
        uplink_data_placement: raw.uplink_data_placement,
        uplink_data_key: raw.uplink_data_key,
    })
}

fn parse_range(value: &str) -> Result<(u32, u32), ConfigError> {
    let (from, to) = value.split_once('-').unwrap_or((value, value));
    let from = from
        .trim()
        .parse::<u32>()
        .map_err(|_| ConfigError::Invalid(format!("invalid xPaddingBytes range {value:?}")))?;
    let to = to
        .trim()
        .parse::<u32>()
        .map_err(|_| ConfigError::Invalid(format!("invalid xPaddingBytes range {value:?}")))?;
    if from == 0 || from > to {
        return Err(ConfigError::Invalid(
            "xPaddingBytes must satisfy 0 < minimum <= maximum".into(),
        ));
    }
    Ok((from, to))
}

fn normalize_xhttp(xhttp: &mut XhttpConfig) -> Result<(), ConfigError> {
    if xhttp.path.is_empty() || !xhttp.path.starts_with('/') {
        xhttp.path.insert(0, '/');
    }
    if !xhttp.path.ends_with('/') {
        xhttp.path.push('/');
    }
    if xhttp.max_each_post_bytes == 0 || xhttp.max_buffered_posts == 0 {
        return Err(ConfigError::Invalid(
            "XHTTP upload and buffered-post limits must be non-zero".into(),
        ));
    }
    if xhttp.uplink_data_placement != UplinkDataPlacement::Body && xhttp.uplink_data_key.is_empty()
    {
        return Err(ConfigError::Invalid(
            "xhttpSettings.uplinkDataKey is required for non-body placement".into(),
        ));
    }
    Ok(())
}

fn validate_server(server: &ServerConfig) -> Result<(), ConfigError> {
    if server.backlog < 1 {
        return Err(ConfigError::Invalid(
            "server.backlog must be greater than zero".into(),
        ));
    }
    if server.graceful_shutdown_seconds == 0 || server.graceful_shutdown_seconds > 300 {
        return Err(ConfigError::Invalid(
            "server.gracefulShutdownSeconds must be between 1 and 300".into(),
        ));
    }
    if server.limits.handshake_timeout_seconds == 0
        || server.limits.target_connect_seconds == 0
        || server.limits.max_sessions == 0
        || server.limits.max_concurrent_target_conns == 0
        || server.limits.global_buffer_bytes == 0
    {
        return Err(ConfigError::Invalid(
            "server limits for sessions, buffers, connections, and timeouts must be non-zero"
                .into(),
        ));
    }
    Ok(())
}

fn validate_fallback(
    fallback: &mut FallbackConfig,
    xhttp: &XhttpConfig,
) -> Result<(), ConfigError> {
    if fallback.index.is_empty()
        || fallback.index.contains('/')
        || fallback.index.contains('\\')
        || fallback.index == "."
        || fallback.index == ".."
    {
        return Err(ConfigError::Invalid(
            "fallback.index must be a single safe file name".into(),
        ));
    }
    if fallback.max_file_bytes == 0 || fallback.max_total_bytes < fallback.max_file_bytes {
        return Err(ConfigError::Invalid(
            "fallback byte limits must be non-zero and maxTotalBytes >= maxFileBytes".into(),
        ));
    }
    match fallback.mode {
        FallbackMode::Builtin if fallback.dist.is_some() => {
            return Err(ConfigError::Invalid(
                "fallback.dist is only valid when mode is \"directory\"".into(),
            ));
        }
        FallbackMode::Directory if fallback.dist.is_none() => {
            return Err(ConfigError::Invalid(
                "fallback.mode = \"directory\" requires fallback.dist".into(),
            ));
        }
        _ => {}
    }
    if fallback.site.seed.is_empty() {
        fallback.site.seed = if xhttp.host.is_empty() {
            xhttp.path.clone()
        } else {
            xhttp.host.clone()
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "log": { "loglevel": "info" },
      "inbounds": [{
        "tag": "vless-xhttp-in",
        "listen": "0.0.0.0",
        "port": 443,
        "protocol": "vless",
        "settings": {
          "clients": [{
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "flow": "xtls-rprx-vision"
          }],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "xhttp",
          "security": "tls",
          "tlsSettings": {
            "certificates": [{
              "certificateFile": "/etc/x/cert.pem",
              "keyFile": "/etc/x/key.pem"
            }]
          },
          "xhttpSettings": { "path": "yourpath" }
        }
      }]
    }"#;

    #[test]
    fn parses_xray_shaped_json_and_normalizes_path() {
        let cfg = Config::from_json_str(SAMPLE).unwrap();
        assert_eq!(cfg.listen.addr, "0.0.0.0:443".parse().unwrap());
        assert_eq!(cfg.xhttp.path, "/yourpath/");
        assert_eq!(cfg.xhttp.max_each_post_bytes, 1_000_000);
        assert_eq!(cfg.xhttp.max_buffered_posts, 30);
        assert_eq!(cfg.xhttp.uplink_data_placement, UplinkDataPlacement::Body);
        assert_eq!(cfg.limits.handshake_timeout_seconds, 10);
        assert_eq!(cfg.vless.users.len(), 1);
        assert!(cfg.listen.worker_threads() >= 1);
        assert!(cfg.listen.tcp_nodelay);
        assert!(cfg.listen.reuse_port);
        assert_eq!(cfg.listen.backlog, 4096);
        assert_eq!(cfg.listen.tcp_keepalive_secs, 300);
        assert_eq!(cfg.listen.graceful_shutdown_secs, 30);
        assert_eq!(cfg.fallback.mode, FallbackMode::Builtin);
    }

    #[test]
    fn parses_header_uplink_and_padding_range() {
        let source = SAMPLE.replace(
            "\"path\": \"yourpath\"",
            "\"path\": \"yourpath\", \"xPaddingBytes\": \"32-96\", \
             \"uplinkDataPlacement\": \"header\", \"uplinkDataKey\": \"X-Data\"",
        );
        let cfg = Config::from_json_str(&source).unwrap();
        assert_eq!(cfg.xhttp.padding_from, 32);
        assert_eq!(cfg.xhttp.padding_to, 96);
        assert_eq!(cfg.xhttp.uplink_data_placement, UplinkDataPlacement::Header);
    }

    #[test]
    fn parses_acme_certificate_mode() {
        let source = SAMPLE.replace(
            "\"certificates\": [{\n              \"certificateFile\": \"/etc/x/cert.pem\",\n              \"keyFile\": \"/etc/x/key.pem\"\n            }]",
            "\"acme\": {\n              \"domains\": [\"example.com\"],\n              \"email\": \"ops@example.com\",\n              \"cacheDir\": \"/tmp/acme\",\n              \"acceptTerms\": true\n            }",
        );
        let cfg = Config::from_json_str(&source).unwrap();
        let tls = cfg.tls.unwrap();
        assert_eq!(tls.cert, PathBuf::from("/tmp/acme/current/certificate.pem"));
        assert!(tls.acme.is_some());
    }

    #[test]
    fn rejects_unknown_fields() {
        let source = SAMPLE.replace(
            "\"listen\": \"0.0.0.0\"",
            "\"listen\": \"0.0.0.0\", \"typo\": true",
        );
        let error = Config::from_json_str(&source).unwrap_err().to_string();
        assert!(error.contains("unknown field `typo`"), "{error}");
    }

    #[test]
    fn rejects_multiple_inbounds_and_bad_flow() {
        let multiple = SAMPLE.replace("]\n    }", ", {\"protocol\":\"vless\"}]\n    }");
        assert!(Config::from_json_str(&multiple).is_err());
        let bad = SAMPLE.replace("xtls-rprx-vision", "xtls-rprx-direct");
        assert!(Config::from_json_str(&bad).is_err());
    }

    #[test]
    fn directory_fallback_requires_dist() {
        let source = SAMPLE.replace(
            "\n    }",
            ",\n      \"fallback\": { \"mode\": \"directory\" }\n    }",
        );
        assert!(Config::from_json_str(&source).is_err());
    }
}
