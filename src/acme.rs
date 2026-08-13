//! ACME HTTP-01 certificate provisioning and renewal.

use crate::config::{AcmeConfig, TlsConfig};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use x509_parser::prelude::{FromDer, X509Certificate};

const ISSUE_TIMEOUT: Duration = Duration::from_secs(300);
const RETRY_INITIAL: Duration = Duration::from_secs(300);
const RETRY_MAX: Duration = Duration::from_secs(6 * 60 * 60);

type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

/// A prepared ACME service. When no usable cached certificate exists,
/// preparation blocks until the first certificate has been issued.
#[derive(Clone)]
pub struct Manager {
    config: Arc<AcmeConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
    challenges: ChallengeMap,
    renew_immediately: bool,
}

impl Manager {
    pub async fn prepare(tls: &TlsConfig) -> Result<Option<Self>, AcmeError> {
        let Some(config) = tls.acme.clone() else {
            return Ok(None);
        };
        create_private_directory(&config.cache_dir)?;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        start_http01_server(&config, challenges.clone()).await?;

        let mut state = match certificate_state(&tls.cert, &tls.key, config.renew_before_days) {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(%error, "cached ACME certificate is unreadable; obtaining a replacement");
                CertificateState::Missing
            }
        };
        if matches!(state, CertificateState::Current | CertificateState::Renew)
            && let Err(error) = crate::tls::Server::from_config(tls)
        {
            tracing::warn!(%error, "cached ACME certificate pair is unusable; obtaining a replacement");
            state = CertificateState::Missing;
        }
        let manager = Self {
            config: Arc::new(config),
            cert_path: tls.cert.clone(),
            key_path: tls.key.clone(),
            challenges,
            renew_immediately: matches!(state, CertificateState::Renew),
        };
        if matches!(state, CertificateState::Missing | CertificateState::Expired) {
            tracing::info!("no usable cached ACME certificate; obtaining one before startup");
            manager.issue_with_timeout().await?;
        }
        Ok(Some(manager))
    }

    /// Start the renewal supervisor. Failed renewals keep the last valid
    /// identity in service and retry with bounded exponential backoff.
    pub fn spawn_renewal(self, server: crate::tls::Server, tls: TlsConfig) {
        tokio::spawn(async move {
            let normal_delay =
                Duration::from_secs(self.config.renew_check_hours.saturating_mul(60 * 60));
            let mut delay = if self.renew_immediately {
                Duration::from_secs(1)
            } else {
                normal_delay
            };
            let mut retry = RETRY_INITIAL;
            let mut activation_pending = false;
            loop {
                tokio::time::sleep(delay).await;
                if activation_pending {
                    match server.reload(&tls) {
                        Ok(()) => {
                            tracing::info!("pending ACME certificate activated");
                            activation_pending = false;
                            delay = normal_delay;
                            retry = RETRY_INITIAL;
                        }
                        Err(error) => {
                            tracing::error!(%error, "ACME certificate activation retry failed");
                            delay = retry;
                            retry = retry.saturating_mul(2).min(RETRY_MAX);
                        }
                    }
                    continue;
                }
                let due = match certificate_state(
                    &self.cert_path,
                    &self.key_path,
                    self.config.renew_before_days,
                ) {
                    Ok(CertificateState::Current) => false,
                    Ok(_) => true,
                    Err(error) => {
                        tracing::warn!(%error, "unable to inspect ACME certificate; attempting renewal");
                        true
                    }
                };
                if !due {
                    delay = normal_delay;
                    retry = RETRY_INITIAL;
                    continue;
                }

                match self.issue_with_timeout().await {
                    Ok(()) => match server.reload(&tls) {
                        Ok(()) => {
                            tracing::info!("ACME certificate renewed and activated");
                            delay = normal_delay;
                            retry = RETRY_INITIAL;
                        }
                        Err(error) => {
                            tracing::error!(%error, "renewed certificate was saved but could not be activated");
                            activation_pending = true;
                            delay = retry;
                            retry = retry.saturating_mul(2).min(RETRY_MAX);
                        }
                    },
                    Err(error) => {
                        tracing::warn!(%error, retry_seconds = retry.as_secs(), "ACME renewal failed; continuing with current certificate");
                        delay = retry;
                        retry = retry.saturating_mul(2).min(RETRY_MAX);
                    }
                }
            }
        });
    }

    async fn issue_with_timeout(&self) -> Result<(), AcmeError> {
        let result = tokio::time::timeout(ISSUE_TIMEOUT, self.issue()).await;
        self.challenges.write().await.clear();
        result.map_err(|_| AcmeError::Timeout)?
    }

    async fn issue(&self) -> Result<(), AcmeError> {
        let account = self.account().await?;
        let identifiers = self
            .config
            .domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(AcmeError::Protocol)?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result.map_err(AcmeError::Protocol)?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => return Err(AcmeError::Authorization(format!("{status:?}"))),
            }
            let identifier = challenge_identifier(&authorization);
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or(AcmeError::MissingHttpChallenge(identifier))?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_owned();
            self.challenges
                .write()
                .await
                .insert(token, key_authorization);
            challenge.set_ready().await.map_err(AcmeError::Protocol)?;
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(AcmeError::Protocol)?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Order(format!("{status:?}")));
        }
        let private_key = order.finalize().await.map_err(AcmeError::Protocol)?;
        let certificate = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(AcmeError::Protocol)?;
        validate_issued_pair(&certificate, &private_key)?;
        publish_certificate_pair(
            &self.config.cache_dir,
            certificate.as_bytes(),
            private_key.as_bytes(),
        )?;
        tracing::info!(
            domains = ?self.config.domains,
            certificate = %self.cert_path.display(),
            "ACME certificate obtained"
        );
        Ok(())
    }

    async fn account(&self) -> Result<Account, AcmeError> {
        let path = self.config.cache_dir.join("account.json");
        if path.exists() {
            let credentials: AccountCredentials = serde_json::from_slice(&fs::read(&path)?)?;
            return self
                .account_builder()?
                .from_credentials(credentials)
                .await
                .map_err(AcmeError::Protocol);
        }

        let contact = format!("mailto:{}", self.config.email);
        let (account, credentials) = self
            .account_builder()?
            .create(
                &NewAccount {
                    contact: &[contact.as_str()],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.config.directory_url.clone(),
                None,
            )
            .await
            .map_err(AcmeError::Protocol)?;
        let serialized = serde_json::to_vec_pretty(&credentials)?;
        atomic_write(&path, &serialized, true)?;
        Ok(account)
    }

    fn account_builder(&self) -> Result<instant_acme::AccountBuilder, AcmeError> {
        match &self.config.ca_certificate_file {
            Some(path) => Account::builder_with_root(path).map_err(AcmeError::Protocol),
            None => Account::builder().map_err(AcmeError::Protocol),
        }
    }
}

fn challenge_identifier(authorization: &instant_acme::AuthorizationHandle<'_>) -> String {
    authorization.identifier().to_string()
}

async fn start_http01_server(
    config: &AcmeConfig,
    challenges: ChallengeMap,
) -> Result<(), AcmeError> {
    let listener = TcpListener::bind(config.challenge_listen).await?;
    let address = listener.local_addr()?;
    let redirect_host = Arc::<str>::from(config.domains[0].clone());
    tracing::info!(%address, "ACME HTTP-01 listener ready");
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error, "ACME HTTP-01 listener stopped");
                    return;
                }
            };
            let challenges = challenges.clone();
            let redirect_host = redirect_host.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    serve_http01(request, challenges.clone(), redirect_host.clone())
                });
                if let Err(error) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(%peer, %error, "ACME HTTP connection ended");
                }
            });
        }
    });
    Ok(())
}

async fn serve_http01(
    request: Request<Incoming>,
    challenges: ChallengeMap,
    redirect_host: Arc<str>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    if request.method() == http::Method::GET
        && let Some(token) = request.uri().path().strip_prefix(PREFIX)
        && !token.is_empty()
        && !token.contains('/')
        && let Some(value) = challenges.read().await.get(token).cloned()
    {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CACHE_CONTROL, "no-store")
            .header(http::header::CONTENT_LENGTH, value.len())
            .body(Full::new(Bytes::from(value)))
            .expect("static response is valid");
        return Ok(response);
    }

    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let location = format!("https://{redirect_host}{target}");
    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(http::header::LOCATION, location)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .expect("validated domain produces a valid redirect"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateState {
    Current,
    Renew,
    Expired,
    Missing,
}

fn certificate_state(
    certificate: &Path,
    key: &Path,
    renew_before_days: u64,
) -> Result<CertificateState, AcmeError> {
    if !certificate.exists() || !key.exists() {
        return Ok(CertificateState::Missing);
    }
    if fs::metadata(key)?.len() == 0 {
        return Ok(CertificateState::Missing);
    }
    let input = fs::read(certificate)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&input)
        .map_err(|error| AcmeError::Certificate(error.to_string()))?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents)
        .map_err(|error| AcmeError::Certificate(error.to_string()))?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| AcmeError::Clock(error.to_string()))?
        .as_secs();
    let not_before = u64::try_from(certificate.validity().not_before.timestamp())
        .map_err(|_| AcmeError::Certificate("negative notBefore timestamp".into()))?;
    let not_after = u64::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| AcmeError::Certificate("negative notAfter timestamp".into()))?;
    if now < not_before {
        return Err(AcmeError::Certificate(
            "certificate is not valid yet; check the system clock".into(),
        ));
    }
    if now >= not_after {
        return Ok(CertificateState::Expired);
    }
    let renew_window = renew_before_days.saturating_mul(24 * 60 * 60);
    if now.saturating_add(renew_window) >= not_after {
        Ok(CertificateState::Renew)
    } else {
        Ok(CertificateState::Current)
    }
}

fn validate_issued_pair(certificate: &str, private_key: &str) -> Result<(), AcmeError> {
    if !certificate.contains("-----BEGIN CERTIFICATE-----") {
        return Err(AcmeError::Certificate(
            "ACME response did not contain a PEM certificate".into(),
        ));
    }
    if !private_key.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(AcmeError::Certificate(
            "ACME response did not contain a PKCS#8 private key".into(),
        ));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), AcmeError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<(), AcmeError> {
    let parent = path
        .parent()
        .ok_or_else(|| AcmeError::Certificate(format!("path has no parent: {}", path.display())))?;
    create_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".rust-xhttp-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(AcmeError::Io)
}

#[cfg(unix)]
fn publish_certificate_pair(
    cache_dir: &Path,
    certificate: &[u8],
    private_key: &[u8],
) -> Result<(), AcmeError> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let generation_name = format!("generation-{:016x}", rand::random::<u64>());
    let temporary_name = format!(".{generation_name}.tmp");
    let temporary = cache_dir.join(&temporary_name);
    let generation = cache_dir.join(&generation_name);
    fs::create_dir(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<(), AcmeError> {
        write_new_file(&temporary.join("private-key.pem"), private_key, 0o600)?;
        write_new_file(&temporary.join("certificate.pem"), certificate, 0o644)?;
        let candidate = TlsConfig {
            cert: temporary.join("certificate.pem"),
            key: temporary.join("private-key.pem"),
            alpn: vec!["h2".into(), "http/1.1".into()],
            acme: None,
        };
        crate::tls::Server::from_config(&candidate)
            .map_err(|error| AcmeError::Certificate(error.to_string()))?;

        fs::rename(&temporary, &generation)?;
        sync_directory(cache_dir)?;
        let previous = fs::read_link(cache_dir.join("current")).ok();
        let link = cache_dir.join(format!(
            ".current-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        symlink(&generation_name, &link)?;
        if let Err(error) = fs::rename(&link, cache_dir.join("current")) {
            let _ = fs::remove_file(&link);
            return Err(AcmeError::Io(error));
        }
        sync_directory(cache_dir)?;
        cleanup_generations(cache_dir, &generation_name, previous.as_deref());
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

#[cfg(unix)]
fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AcmeError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), AcmeError> {
    let directory = fs::File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn cleanup_generations(cache_dir: &Path, current: &str, previous: Option<&Path>) {
    let previous = previous.and_then(Path::file_name);
    let Ok(entries) = fs::read_dir(cache_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if !name_text.starts_with("generation-")
            || name_text == current
            || previous.is_some_and(|value| value == name)
        {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir()
            && let Err(error) = fs::remove_dir_all(entry.path())
        {
            tracing::debug!(%error, path = %entry.path().display(), "unable to remove old ACME generation");
        }
    }
}

#[cfg(not(unix))]
fn publish_certificate_pair(
    cache_dir: &Path,
    certificate: &[u8],
    private_key: &[u8],
) -> Result<(), AcmeError> {
    let current = cache_dir.join("current");
    create_private_directory(&current)?;
    atomic_write(&current.join("private-key.pem"), private_key, true)?;
    atomic_write(&current.join("certificate.pem"), certificate, false)
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("ACME protocol: {0}")]
    Protocol(instant_acme::Error),
    #[error("ACME account cache: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ACME server offered no HTTP-01 challenge for {0}")]
    MissingHttpChallenge(String),
    #[error("ACME authorization entered unexpected status {0}")]
    Authorization(String),
    #[error("ACME order entered unexpected status {0}")]
    Order(String),
    #[error("ACME issuance timed out after five minutes")]
    Timeout,
    #[error("invalid certificate: {0}")]
    Certificate(String),
    #[error("system clock: {0}")]
    Clock(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn validates_acme_output_shape() {
        assert!(
            validate_issued_pair(
                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"
            )
            .is_ok()
        );
        assert!(validate_issued_pair("bad", "bad").is_err());
    }

    #[tokio::test]
    async fn http01_server_serves_token_and_redirects_other_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let challenges: ChallengeMap = Arc::new(RwLock::new(HashMap::from([(
            "token".into(),
            "authorization".into(),
        )])));
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let challenges = challenges.clone();
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| {
                            serve_http01(
                                request,
                                challenges.clone(),
                                Arc::<str>::from("example.com"),
                            )
                        }),
                    )
                    .await
                    .unwrap();
            }
        });

        let challenge = raw_http(
            address,
            "GET /.well-known/acme-challenge/token HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(challenge.starts_with("HTTP/1.1 200 OK"), "{challenge}");
        assert!(challenge.ends_with("authorization"), "{challenge}");

        let redirect = raw_http(
            address,
            "GET /hello?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            redirect.starts_with("HTTP/1.1 308 Permanent Redirect"),
            "{redirect}"
        );
        assert!(
            redirect.contains("location: https://example.com/hello?q=1"),
            "{redirect}"
        );
        task.await.unwrap();
    }

    async fn raw_http(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        String::from_utf8(output).unwrap()
    }
}
