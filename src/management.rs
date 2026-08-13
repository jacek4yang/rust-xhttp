//! Installation and lifecycle management for the `rust-xhttpctl` companion binary.
//!
//! The network daemon deliberately does not depend on this module.  Administrative
//! operations live in a separate binary so interactive prompts, release downloads, and
//! systemd orchestration cannot affect the server data path.

use rand::RngCore;
use rust_xhttp::config::Config;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SERVICE: &str = "rust-xhttp";
const SERVICE_USER: &str = "rust-xhttp";
const REPOSITORY: &str = "jacek4yang/rust-xhttp";
const RELEASE_TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Clone, Debug)]
struct Layout {
    root: PathBuf,
}

impl Layout {
    fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    fn under(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            return Err(message("--root must be an absolute path"));
        }
        Ok(Self { root })
    }

    fn is_system(&self) -> bool {
        self.root == Path::new("/")
    }

    fn path(&self, absolute: &str) -> PathBuf {
        debug_assert!(absolute.starts_with('/'));
        if self.is_system() {
            PathBuf::from(absolute)
        } else {
            self.root.join(absolute.trim_start_matches('/'))
        }
    }

    fn server_binary(&self) -> PathBuf {
        self.path("/usr/local/bin/rust-xhttp")
    }

    fn ctl_binary(&self) -> PathBuf {
        self.path("/usr/local/bin/rust-xhttpctl")
    }

    fn config_dir(&self) -> PathBuf {
        self.path("/etc/rust-xhttp")
    }

    fn config(&self) -> PathBuf {
        self.path("/etc/rust-xhttp/config.json")
    }

    fn unit(&self) -> PathBuf {
        self.path("/etc/systemd/system/rust-xhttp.service")
    }

    fn state_dir(&self) -> PathBuf {
        self.path("/var/lib/rust-xhttp")
    }

    fn manager_dir(&self) -> PathBuf {
        self.path("/var/lib/rust-xhttp-manager")
    }

    fn rollback_dir(&self) -> PathBuf {
        self.manager_dir().join("rollback")
    }
}

#[derive(Debug)]
struct InstallOptions {
    server_binary: PathBuf,
    ctl_binary: PathBuf,
    config_source: Option<PathBuf>,
    layout: Layout,
    assume_yes: bool,
    no_start: bool,
}

#[derive(Debug)]
struct GeneratedConfig {
    source: String,
    host: String,
    port: u16,
    uuid: String,
    path: String,
    security: String,
    manual_tls: Option<(PathBuf, PathBuf)>,
    dist_source: Option<PathBuf>,
}

#[derive(Debug)]
struct FileRollback {
    target: PathBuf,
    backup: Option<PathBuf>,
    mode: u32,
}

#[derive(Debug)]
struct SiteRollback {
    target: PathBuf,
    backup: Option<PathBuf>,
}

pub fn run() -> Result<()> {
    let mut arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.is_empty() {
        print_help();
        return Ok(());
    }
    let command = arguments.remove(0);
    match command.to_string_lossy().as_ref() {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" | "version" => {
            println!("rust-xhttpctl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "install" => install(parse_install_options(arguments)?),
        "manage" => {
            reject_arguments(&arguments)?;
            interactive_manage()
        }
        "service" => service_command(arguments),
        "status" => {
            reject_arguments(&arguments)?;
            service_action("status")
        }
        "logs" => {
            reject_arguments(&arguments)?;
            service_action("logs")
        }
        "doctor" => {
            reject_arguments(&arguments)?;
            doctor(&Layout::system())
        }
        "edit" => {
            reject_arguments(&arguments)?;
            require_root()?;
            edit_config(&Layout::system())
        }
        "update" => update_command(arguments),
        "rollback" => {
            reject_arguments(&arguments)?;
            require_root()?;
            rollback(&Layout::system())
        }
        "repair" => repair_command(arguments),
        "uninstall" => uninstall_command(arguments),
        other => Err(message(format!(
            "unknown command {other:?}; run rust-xhttpctl --help"
        ))),
    }
}

fn print_help() {
    println!(
        "rust-xhttpctl {version}\n\
         \n\
         Install and manage a rust-xhttp systemd deployment.\n\
         \n\
         USAGE:\n\
             rust-xhttpctl install [OPTIONS]\n\
             rust-xhttpctl manage\n\
             rust-xhttpctl service <status|start|stop|restart|enable|disable|logs>\n\
             rust-xhttpctl doctor\n\
             rust-xhttpctl edit\n\
             rust-xhttpctl update [vVERSION] [--force]\n\
             rust-xhttpctl rollback\n\
             rust-xhttpctl repair [--no-restart]\n\
             rust-xhttpctl uninstall [--purge] [--yes]\n\
         \n\
         INSTALL OPTIONS:\n\
             --server-binary PATH  daemon binary to install\n\
             --ctl-binary PATH     manager binary to install\n\
             --config PATH         validated existing JSON instead of the wizard\n\
             --yes                 accept replacement prompts (requires --config)\n\
             --no-start            install files without enabling/starting systemd\n\
             --root PATH           stage into an alternate root (requires --no-start)\n\
         \n\
         Run mutating system commands with sudo. status, logs, and doctor are read-only.",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn parse_install_options(arguments: Vec<OsString>) -> Result<InstallOptions> {
    let current = env::current_exe()?;
    let sibling_server = current
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("rust-xhttp");
    let mut options = InstallOptions {
        server_binary: sibling_server,
        ctl_binary: current,
        config_source: None,
        layout: Layout::system(),
        assume_yes: false,
        no_start: false,
    };
    let mut position = 0;
    while position < arguments.len() {
        match arguments[position].to_string_lossy().as_ref() {
            "--server-binary" => {
                position += 1;
                options.server_binary = required_path(&arguments, position, "--server-binary")?;
            }
            "--ctl-binary" => {
                position += 1;
                options.ctl_binary = required_path(&arguments, position, "--ctl-binary")?;
            }
            "--config" => {
                position += 1;
                options.config_source = Some(required_path(&arguments, position, "--config")?);
            }
            "--root" => {
                position += 1;
                options.layout = Layout::under(required_path(&arguments, position, "--root")?)?;
            }
            "--yes" | "-y" => options.assume_yes = true,
            "--no-start" => options.no_start = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => return Err(message(format!("unknown install option {unknown:?}"))),
        }
        position += 1;
    }
    if options.assume_yes && options.config_source.is_none() && !options.layout.config().is_file() {
        return Err(message(
            "--yes requires --config unless an installed config already exists",
        ));
    }
    if !options.layout.is_system() && !options.no_start {
        return Err(message("--root requires --no-start"));
    }
    Ok(options)
}

fn install(options: InstallOptions) -> Result<()> {
    ensure_supported_platform()?;
    if options.layout.is_system() {
        require_root()?;
    }
    verify_binary(&options.server_binary, "rust-xhttp")?;
    verify_binary(&options.ctl_binary, "rust-xhttpctl")?;
    require_matching_versions(&options.server_binary, &options.ctl_binary, None)?;

    if options.layout.is_system() {
        ensure_system_user()?;
    }
    prepare_directories(&options.layout)?;

    let (config_source, generated) = select_config(&options)?;
    validate_config_source(&config_source)?;

    let mut file_rollbacks = Vec::new();
    let mut site_rollback = None;
    if let Some(details) = &generated {
        if let Some((certificate, private_key)) = &details.manual_tls {
            file_rollbacks = install_manual_tls(&options.layout, certificate, private_key)?;
        }
        if let Some(source) = &details.dist_source {
            match install_site(&options.layout, source) {
                Ok(rollback) => site_rollback = Some(rollback),
                Err(error) => {
                    restore_resources(&file_rollbacks, None)?;
                    return Err(error);
                }
            }
        }
    }

    let config_path = options.layout.config();
    let candidate = unique_path(&options.layout.config_dir(), ".config.candidate")?;
    if let Err(error) = atomic_write(&candidate, config_source.as_bytes(), 0o640) {
        restore_resources(&file_rollbacks, site_rollback.as_ref())?;
        return Err(error);
    }
    if let Err(error) = validate_config_file(&candidate) {
        let _ = fs::remove_file(&candidate);
        restore_resources(&file_rollbacks, site_rollback.as_ref())?;
        return Err(error);
    }
    if config_path.exists() {
        backup_config(&options.layout, &config_path)?;
    }
    fs::rename(&candidate, &config_path)?;
    sync_directory(&options.layout.config_dir())?;
    copy_atomic(
        &options.server_binary,
        &options.layout.server_binary(),
        0o755,
    )?;
    copy_atomic(&options.ctl_binary, &options.layout.ctl_binary(), 0o755)?;
    atomic_write(&options.layout.unit(), systemd_unit().as_bytes(), 0o644)?;

    if options.layout.is_system() {
        apply_ownership(&options.layout)?;
        validate_config_file(&config_path)?;
        run_checked(Command::new("systemctl").arg("daemon-reload"))?;
        if !options.no_start {
            run_checked(Command::new("systemctl").arg("enable").arg(SERVICE))?;
            run_checked(Command::new("systemctl").arg("restart").arg(SERVICE))?;
            run_checked(
                Command::new("systemctl")
                    .arg("is-active")
                    .arg("--quiet")
                    .arg(SERVICE),
            )?;
        }
    } else {
        validate_config_file(&config_path)?;
    }

    println!("\nInstallation completed successfully.");
    println!("  server:  {}", options.layout.server_binary().display());
    println!("  manager: {}", options.layout.ctl_binary().display());
    println!("  config:  {}", config_path.display());
    println!("  unit:    {}", options.layout.unit().display());
    if let Some(details) = generated {
        println!("\nClient connection values (store the UUID securely):");
        println!("  address/SNI: {}", details.host);
        println!("  port:        {}", details.port);
        println!("  UUID:        {}", details.uuid);
        println!("  XHTTP path:  {}", details.path);
        println!("  security:    {}", details.security);
    }
    if options.layout.is_system() && !options.no_start {
        println!("\nManage it with: sudo rust-xhttpctl manage");
        println!("Follow logs with: rust-xhttpctl logs");
    }
    Ok(())
}

fn select_config(options: &InstallOptions) -> Result<(String, Option<GeneratedConfig>)> {
    if let Some(source) = &options.config_source {
        let text = fs::read_to_string(source).map_err(|error| {
            message(format!("cannot read config {}: {error}", source.display()))
        })?;
        validate_config_source(&text)?;
        return Ok((text, None));
    }
    if options.layout.config().is_file()
        && (options.assume_yes
            || confirm(
                &format!(
                    "Reuse existing config {}?",
                    options.layout.config().display()
                ),
                true,
            )?)
    {
        return Ok((fs::read_to_string(options.layout.config())?, None));
    }
    let generated = interactive_config()?;
    Ok((generated.source.clone(), Some(generated)))
}

fn interactive_config() -> Result<GeneratedConfig> {
    println!("rust-xhttp interactive installation\n");
    println!("TLS mode:");
    println!("  1) Automatic Let's Encrypt certificate (recommended)");
    println!("  2) Existing PEM certificate and key");
    println!("  3) Plain HTTP behind Cloudflare/nginx/another TLS proxy");
    let mode = prompt("Choose TLS mode", Some("1"))?;
    if !matches!(mode.as_str(), "1" | "2" | "3") {
        return Err(message("TLS mode must be 1, 2, or 3"));
    }

    let host = required_prompt("Public domain name", None)?;
    let default_port = if mode == "3" { "8080" } else { "443" };
    let port = prompt("Listen port", Some(default_port))?
        .parse::<u16>()
        .map_err(|_| message("listen port must be an integer from 1 to 65535"))?;
    if port == 0 {
        return Err(message("listen port must not be zero"));
    }
    let default_listen = if mode == "3" { "127.0.0.1" } else { "0.0.0.0" };
    let listen = prompt("Listen address", Some(default_listen))?;
    let uuid = prompt("VLESS UUID", Some(&random_uuid()))?;
    let random_path = format!("/{}/", random_hex(8));
    let mut path = prompt("XHTTP path", Some(&random_path))?;
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    let email_label = prompt("Client label", Some("primary"))?;
    let vision = confirm("Enable xtls-rprx-vision flow?", false)?;
    let mut manual_tls = None;

    let mut stream = json!({
        "network": "xhttp",
        "security": if mode == "3" { "none" } else { "tls" },
        "xhttpSettings": {
            "path": path,
            "host": host,
            "scMaxEachPostBytes": 1_000_000,
            "scMaxBufferedPosts": 30,
            "sessionGraceSeconds": 30,
            "noSSEHeader": false,
            "serverMaxHeaderBytes": 8192,
            "xPaddingBytes": "100-1000",
            "uplinkDataPlacement": "body",
            "uplinkDataKey": ""
        }
    });
    if mode == "1" {
        let contact = required_prompt("ACME contact email", None)?;
        stream.as_object_mut().unwrap().insert(
            "tlsSettings".into(),
            json!({
                "alpn": ["h2", "http/1.1"],
                "acme": {
                    "domains": [host],
                    "email": contact,
                    "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
                    "challengeListen": "0.0.0.0:80",
                    "cacheDir": "/var/lib/rust-xhttp/acme",
                    "renewBeforeDays": 30,
                    "renewCheckHours": 12,
                    "acceptTerms": true
                }
            }),
        );
    } else if mode == "2" {
        let cert = PathBuf::from(required_prompt("Certificate chain PEM path", None)?);
        let key = PathBuf::from(required_prompt("Private key PEM path", None)?);
        if !cert.is_file() || !key.is_file() {
            return Err(message(
                "certificate and private key must be existing files",
            ));
        }
        manual_tls = Some((cert, key));
        stream.as_object_mut().unwrap().insert(
            "tlsSettings".into(),
            json!({
                "alpn": ["h2", "http/1.1"],
                "certificates": [{
                    "certificateFile": "/etc/rust-xhttp/tls/fullchain.pem",
                    "keyFile": "/etc/rust-xhttp/tls/privkey.pem"
                }]
            }),
        );
    }

    let use_dist = confirm(
        "Serve an existing dist directory instead of the generated blog?",
        false,
    )?;
    let dist_source = if use_dist {
        let source = PathBuf::from(required_prompt("Path to dist directory", None)?);
        if !source.is_dir() {
            return Err(message(format!("{} is not a directory", source.display())));
        }
        Some(source)
    } else {
        None
    };
    let fallback = if dist_source.is_some() {
        json!({
            "mode": "directory",
            "dist": "/var/lib/rust-xhttp/site",
            "index": "index.html",
            "maxFileBytes": 8388608,
            "maxTotalBytes": 134217728
        })
    } else {
        let language = prompt("Fallback blog language (en or zh-CN)", Some("en"))?;
        let title = prompt("Fallback blog title (blank = generated)", Some(""))?;
        let author = prompt("Fallback blog author (blank = generated)", Some(""))?;
        let description = prompt("Fallback blog description (blank = generated)", Some(""))?;
        json!({
            "mode": "builtin",
            "index": "index.html",
            "maxFileBytes": 8388608,
            "maxTotalBytes": 134217728,
            "site": {
                "seed": host,
                "title": title,
                "author": author,
                "description": description,
                "language": language
            }
        })
    };

    let value = json!({
        "log": { "loglevel": "info" },
        "inbounds": [{
            "tag": "vless-xhttp-in",
            "listen": listen,
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": uuid,
                    "email": email_label,
                    "flow": if vision { "xtls-rprx-vision" } else { "" }
                }],
                "decryption": "none"
            },
            "streamSettings": stream
        }],
        "server": {
            "workers": 0,
            "tcpNodelay": true,
            "reusePort": true,
            "backlog": 4096,
            "tcpKeepaliveSeconds": 300,
            "gracefulShutdownSeconds": 30,
            "limits": {
                "maxSessions": 65536,
                "maxPendingPacketsPerSession": 30,
                "maxPendingBytesPerSession": 16777216,
                "globalBufferBytes": 1073741824_u64,
                "maxConcurrentTargetConns": 100000,
                "handshakeTimeoutSeconds": 10,
                "targetConnectSeconds": 10,
                "udpAssociationIdleSeconds": 60
            }
        },
        "fallback": fallback
    });
    let mut source = serde_json::to_string_pretty(&value)?;
    source.push('\n');
    validate_config_source(&source)?;
    Ok(GeneratedConfig {
        source,
        host,
        port,
        uuid,
        path,
        security: if mode == "3" {
            "none (TLS proxy)".into()
        } else {
            "tls".into()
        },
        manual_tls,
        dist_source,
    })
}

fn validate_config_source(source: &str) -> Result<Config> {
    Config::from_json_str(source).map_err(|error| message(format!("invalid config: {error}")))
}

fn validate_config_file(path: &Path) -> Result<()> {
    let config = Config::load(path)
        .map_err(|error| message(format!("invalid config {}: {error}", path.display())))?;
    rust_xhttp::runtime::validate(&config).map_err(|error| {
        message(format!(
            "config resource validation failed for {}: {error}",
            path.display()
        ))
    })
}

fn prepare_directories(layout: &Layout) -> Result<()> {
    create_dir(&layout.config_dir(), 0o750)?;
    create_dir(&layout.config_dir().join("backups"), 0o700)?;
    create_dir(&layout.config_dir().join("tls"), 0o750)?;
    create_dir(&layout.state_dir(), 0o750)?;
    create_dir(&layout.state_dir().join("acme"), 0o700)?;
    create_dir(&layout.state_dir().join("site"), 0o750)?;
    create_dir(&layout.manager_dir(), 0o700)?;
    if let Some(parent) = layout.unit().parent() {
        create_dir(parent, 0o755)?;
    }
    if let Some(parent) = layout.server_binary().parent() {
        create_dir(parent, 0o755)?;
    }
    Ok(())
}

fn install_manual_tls(
    layout: &Layout,
    certificate: &Path,
    private_key: &Path,
) -> Result<Vec<FileRollback>> {
    let target = layout.config_dir().join("tls");
    create_dir(&target, 0o750)?;
    let mut rollbacks = Vec::new();
    let fullchain = target.join("fullchain.pem");
    rollbacks.push(snapshot_file(layout, &fullchain, "fullchain", 0o644)?);
    if let Err(error) = copy_atomic(certificate, &fullchain, 0o644) {
        restore_resources(&rollbacks, None)?;
        return Err(error);
    }
    let private_key_target = target.join("privkey.pem");
    match snapshot_file(layout, &private_key_target, "privkey", 0o640) {
        Ok(rollback) => rollbacks.push(rollback),
        Err(error) => {
            restore_resources(&rollbacks, None)?;
            return Err(error);
        }
    }
    if let Err(error) = copy_atomic(private_key, &private_key_target, 0o640) {
        restore_resources(&rollbacks, None)?;
        return Err(error);
    }
    Ok(rollbacks)
}

fn snapshot_file(layout: &Layout, target: &Path, label: &str, mode: u32) -> Result<FileRollback> {
    let backup = if target.is_file() {
        let backup = unique_path(
            &layout.config_dir().join("backups"),
            &format!("{label}.pem"),
        )?;
        copy_atomic(target, &backup, 0o600)?;
        println!("Previous {label} backup: {}", backup.display());
        Some(backup)
    } else {
        None
    };
    Ok(FileRollback {
        target: target.to_owned(),
        backup,
        mode,
    })
}

fn install_site(layout: &Layout, source: &Path) -> Result<SiteRollback> {
    let staging = unique_directory(&layout.manager_dir(), "site-new")?;
    if let Err(error) = copy_site_tree(source, &staging, 0) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let destination = layout.state_dir().join("site");
    let backup = layout.manager_dir().join(format!(
        "site-backup-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    ));
    let previous = if destination.exists() {
        fs::rename(&destination, &backup)?;
        Some(backup.clone())
    } else {
        None
    };
    if let Err(error) = fs::rename(&staging, &destination) {
        if previous.is_some() {
            let _ = fs::rename(&backup, &destination);
        }
        return Err(error.into());
    }
    println!("Installed static site from {}", source.display());
    if previous.is_some() {
        println!("Previous static site backup: {}", backup.display());
    }
    Ok(SiteRollback {
        target: destination,
        backup: previous,
    })
}

fn restore_resources(files: &[FileRollback], site: Option<&SiteRollback>) -> Result<()> {
    if let Some(site) = site {
        if site.target.exists() {
            fs::remove_dir_all(&site.target)?;
        }
        if let Some(backup) = &site.backup {
            fs::rename(backup, &site.target)?;
        }
    }
    for file in files.iter().rev() {
        if let Some(backup) = &file.backup {
            copy_atomic(backup, &file.target, file.mode)?;
        } else {
            remove_file_if_present(&file.target)?;
        }
    }
    Ok(())
}

fn copy_site_tree(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(message("dist directory nesting exceeds 32 levels"));
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(message(format!(
                "dist directory contains unsupported symlink: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;
            copy_site_tree(&entry.path(), &target, depth + 1)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o640))?;
        } else {
            return Err(message(format!(
                "dist directory contains unsupported file type: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn create_dir(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn ensure_system_user() -> Result<()> {
    let user_exists = Command::new("id")
        .args(["-u", SERVICE_USER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let group_exists = Command::new("getent")
        .args(["group", SERVICE_USER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if user_exists {
        if !group_exists {
            return Err(message(
                "existing rust-xhttp user has no matching group; refusing to repurpose it",
            ));
        }
        let output = run_output(Command::new("getent").args(["passwd", SERVICE_USER]))?;
        let record = String::from_utf8(output.stdout)?;
        let fields = record.trim().split(':').collect::<Vec<_>>();
        let managed_shell = fields
            .get(6)
            .is_some_and(|shell| shell.ends_with("/nologin") || shell.ends_with("/false"));
        if fields.get(5) != Some(&"/var/lib/rust-xhttp") || !managed_shell {
            return Err(message(
                "an unmanaged rust-xhttp account already exists; choose a clean host account name",
            ));
        }
        return Ok(());
    }
    if group_exists {
        return Err(message(
            "an unmanaged rust-xhttp group already exists; refusing to repurpose it",
        ));
    }
    let shell = ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .unwrap_or("/bin/false");
    run_checked(
        Command::new("useradd")
            .arg("--system")
            .arg("--user-group")
            .arg("--home-dir")
            .arg("/var/lib/rust-xhttp")
            .arg("--no-create-home")
            .arg("--shell")
            .arg(shell)
            .arg(SERVICE_USER),
    )
}

fn apply_ownership(layout: &Layout) -> Result<()> {
    run_checked(
        Command::new("chown")
            .arg("-R")
            .arg(format!("root:{SERVICE_USER}"))
            .arg(layout.config_dir()),
    )?;
    run_checked(
        Command::new("chown")
            .arg("-R")
            .arg(format!("{SERVICE_USER}:{SERVICE_USER}"))
            .arg(layout.state_dir()),
    )?;
    run_checked(
        Command::new("chown")
            .arg("-R")
            .arg("root:root")
            .arg(layout.manager_dir()),
    )
}

fn systemd_unit() -> String {
    include_str!("../ops/systemd/rust-xhttp.service").to_owned()
}

fn service_command(mut arguments: Vec<OsString>) -> Result<()> {
    if arguments.len() != 1 {
        return Err(message(
            "usage: rust-xhttpctl service <status|start|stop|restart|enable|disable|logs>",
        ));
    }
    service_action(&arguments.remove(0).to_string_lossy())
}

fn service_action(action: &str) -> Result<()> {
    match action {
        "status" => run_inherited(
            Command::new("systemctl")
                .arg("status")
                .arg("--no-pager")
                .arg("--full")
                .arg(SERVICE),
        ),
        "logs" => run_inherited(
            Command::new("journalctl")
                .arg("--unit")
                .arg(SERVICE)
                .arg("--lines")
                .arg("100")
                .arg("--follow"),
        ),
        "start" | "stop" | "restart" | "enable" | "disable" => {
            require_root()?;
            run_checked(Command::new("systemctl").arg(action).arg(SERVICE))
        }
        other => Err(message(format!("unsupported service action {other:?}"))),
    }
}

fn interactive_manage() -> Result<()> {
    loop {
        println!(
            "\nrust-xhttp management\n\
             1) Status\n\
             2) Follow logs\n\
             3) Diagnose installation\n\
             4) Validate and edit config\n\
             5) Restart service\n\
             6) Start service\n\
             7) Stop service\n\
             8) Update to latest release\n\
             9) Roll back previous binaries\n\
             10) Repair systemd integration\n\
             11) Uninstall (preserve data)\n\
             0) Exit"
        );
        match prompt("Select an action", Some("1"))?.as_str() {
            "1" => service_action("status")?,
            "2" => service_action("logs")?,
            "3" => doctor(&Layout::system())?,
            "4" => {
                require_root()?;
                edit_config(&Layout::system())?;
            }
            "5" => service_action("restart")?,
            "6" => service_action("start")?,
            "7" => service_action("stop")?,
            "8" => {
                require_root()?;
                update(&Layout::system(), None, false)?;
            }
            "9" => {
                require_root()?;
                rollback(&Layout::system())?;
            }
            "10" => {
                require_root()?;
                repair(&Layout::system(), true)?;
            }
            "11" => {
                require_root()?;
                uninstall(&Layout::system(), false, false)?;
                return Ok(());
            }
            "0" => return Ok(()),
            _ => println!("Unknown selection."),
        }
    }
}

fn doctor(layout: &Layout) -> Result<()> {
    let mut failures = 0;
    failures += check_path("server binary", &layout.server_binary(), true);
    failures += check_path("manager binary", &layout.ctl_binary(), true);
    failures += check_path("configuration", &layout.config(), false);
    failures += check_path("systemd unit", &layout.unit(), false);
    if layout.config().is_file() {
        match validate_config_file(&layout.config()) {
            Ok(()) => println!("[ok] config syntax and resources"),
            Err(error) => {
                println!("[fail] config syntax/resources: {error}");
                failures += 1;
            }
        }
    }
    failures += check_command("service enabled", "systemctl", &["is-enabled", SERVICE]);
    failures += check_command("service active", "systemctl", &["is-active", SERVICE]);
    if failures == 0 {
        println!("All installation checks passed.");
        Ok(())
    } else {
        Err(message(format!("{failures} installation check(s) failed")))
    }
}

fn check_path(label: &str, path: &Path, executable: bool) -> usize {
    let valid = fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && (!executable || metadata.permissions().mode() & 0o111 != 0)
    });
    if valid {
        println!("[ok] {label}: {}", path.display());
        0
    } else {
        println!("[fail] {label}: {}", path.display());
        1
    }
}

fn check_command(label: &str, command: &str, arguments: &[&str]) -> usize {
    let success = Command::new(command)
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if success {
        println!("[ok] {label}");
        0
    } else {
        println!("[fail] {label}");
        1
    }
}

fn edit_config(layout: &Layout) -> Result<()> {
    let config = layout.config();
    validate_config_file(&config)?;
    let temporary = unique_path(&layout.config_dir(), ".config.edit")?;
    fs::copy(&config, &temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    let editor = env::var_os("VISUAL")
        .or_else(|| env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"));
    let status = Command::new(&editor).arg(&temporary).status()?;
    if !status.success() {
        let _ = fs::remove_file(&temporary);
        return Err(message(format!("editor {:?} exited with {status}", editor)));
    }
    if let Err(error) = validate_config_file(&temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(message(format!(
            "edited config is invalid; installed config was not changed: {error}"
        )));
    }
    let backup = backup_config(layout, &config)?;
    fs::rename(&temporary, &config)?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640))?;
    sync_directory(&layout.config_dir())?;
    apply_ownership(layout)?;
    if let Err(error) = run_checked(Command::new("systemctl").arg("restart").arg(SERVICE)) {
        copy_atomic(&backup, &config, 0o640)?;
        apply_ownership(layout)?;
        let _ = run_checked(Command::new("systemctl").arg("restart").arg(SERVICE));
        return Err(message(format!(
            "restart failed; restored {}: {error}",
            backup.display()
        )));
    }
    println!("Config validated, installed, and service restarted.");
    println!("Backup: {}", backup.display());
    Ok(())
}

fn backup_config(layout: &Layout, source: &Path) -> Result<PathBuf> {
    let directory = layout.config_dir().join("backups");
    create_dir(&directory, 0o700)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut destination = directory.join(format!("config-{stamp}.json"));
    if destination.exists() {
        destination = directory.join(format!("config-{stamp}-{}.json", random_hex(3)));
    }
    copy_atomic(source, &destination, 0o600)?;
    Ok(destination)
}

fn update_command(arguments: Vec<OsString>) -> Result<()> {
    let mut tag = None;
    let mut force = false;
    for argument in arguments {
        match argument.to_string_lossy().as_ref() {
            "--force" => force = true,
            "--help" | "-h" => {
                println!("usage: rust-xhttpctl update [vVERSION] [--force]");
                return Ok(());
            }
            value if tag.is_none() => tag = Some(value.to_owned()),
            value => return Err(message(format!("unexpected update argument {value:?}"))),
        }
    }
    require_root()?;
    update(&Layout::system(), tag, force)
}

fn update(layout: &Layout, requested_tag: Option<String>, force: bool) -> Result<()> {
    ensure_supported_platform()?;
    let tag = match requested_tag {
        Some(tag) => validate_tag(&tag)?,
        None => latest_release_tag()?,
    };
    let installed_version = binary_version(&layout.server_binary())?;
    if !force && installed_version.split_whitespace().nth(1) == Some(tag.trim_start_matches('v')) {
        println!("Already running {installed_version}; use --force to reinstall.");
        return Ok(());
    }
    println!("Downloading rust-xhttp {tag}...");
    let downloaded = download_release(layout, &tag)?;
    validate_downloaded_release(
        layout,
        &downloaded.server,
        &downloaded.ctl,
        Some(tag.trim_start_matches('v')),
    )?;
    create_rollback(layout)?;

    let install_result = (|| -> Result<()> {
        copy_atomic(&downloaded.server, &layout.server_binary(), 0o755)?;
        copy_atomic(&downloaded.ctl, &layout.ctl_binary(), 0o755)?;
        run_checked(
            Command::new(layout.ctl_binary())
                .arg("repair")
                .arg("--no-restart"),
        )?;
        run_checked(Command::new("systemctl").arg("restart").arg(SERVICE))?;
        run_checked(
            Command::new("systemctl")
                .arg("is-active")
                .arg("--quiet")
                .arg(SERVICE),
        )
    })();
    if let Err(error) = install_result {
        restore_rollback(layout)?;
        let _ = run_checked(
            Command::new(layout.ctl_binary())
                .arg("repair")
                .arg("--no-restart"),
        );
        let _ = run_checked(Command::new("systemctl").arg("restart").arg(SERVICE));
        let _ = fs::remove_dir_all(&downloaded.temporary);
        return Err(message(format!(
            "update failed and previous binaries were restored: {error}"
        )));
    }
    let _ = fs::remove_dir_all(&downloaded.temporary);
    println!("Updated successfully to {tag}.");
    println!("Roll back with: sudo rust-xhttpctl rollback");
    Ok(())
}

struct DownloadedRelease {
    temporary: PathBuf,
    server: PathBuf,
    ctl: PathBuf,
}

fn latest_release_tag() -> Result<String> {
    let output = run_output(
        Command::new("curl")
            .arg("--proto")
            .arg("=https")
            .arg("--proto-redir")
            .arg("=https")
            .arg("--tlsv1.2")
            .arg("--fail")
            .arg("--silent")
            .arg("--show-error")
            .arg("--location")
            .arg("--output")
            .arg("/dev/null")
            .arg("--write-out")
            .arg("%{url_effective}")
            .arg(format!("https://github.com/{REPOSITORY}/releases/latest")),
    )?;
    let url = String::from_utf8(output.stdout)?;
    let tag = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .ok_or_else(|| message("GitHub latest release redirect did not contain a tag"))?;
    validate_tag(tag)
}

fn validate_tag(tag: &str) -> Result<String> {
    if tag.len() < 2
        || !tag.starts_with('v')
        || !tag[1..].chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
    {
        return Err(message(format!("invalid release tag {tag:?}")));
    }
    Ok(tag.to_owned())
}

fn download_release(layout: &Layout, tag: &str) -> Result<DownloadedRelease> {
    create_dir(&layout.manager_dir(), 0o700)?;
    let temporary = unique_directory(&layout.manager_dir(), "update")?;
    let archive_name = format!("rust-xhttp-{tag}-{RELEASE_TARGET}.tar.gz");
    let archive = temporary.join(&archive_name);
    let checksum = temporary.join(format!("{archive_name}.sha256"));
    let base = format!("https://github.com/{REPOSITORY}/releases/download/{tag}");
    curl_download(&format!("{base}/{archive_name}"), &archive)?;
    curl_download(&format!("{base}/{archive_name}.sha256"), &checksum)?;
    verify_checksum(&archive, &checksum, &archive_name)?;
    let prefix = format!("rust-xhttp-{tag}-{RELEASE_TARGET}");
    validate_archive_paths(&archive, &prefix)?;
    validate_regular_archive_member(&archive, &format!("{prefix}/rust-xhttp"))?;
    validate_regular_archive_member(&archive, &format!("{prefix}/rust-xhttpctl"))?;
    let root = temporary.join(&prefix);
    fs::create_dir(&root)?;
    run_checked(
        Command::new("tar")
            .arg("--extract")
            .arg("--gzip")
            .arg("--file")
            .arg(&archive)
            .arg("--directory")
            .arg(&temporary)
            .arg("--no-same-owner")
            .arg("--no-same-permissions")
            .arg(format!("{prefix}/rust-xhttp"))
            .arg(format!("{prefix}/rust-xhttpctl")),
    )?;
    let server = checked_release_file(&temporary, &root.join("rust-xhttp"))?;
    let ctl = checked_release_file(&temporary, &root.join("rust-xhttpctl"))?;
    Ok(DownloadedRelease {
        temporary,
        server,
        ctl,
    })
}

fn curl_download(url: &str, destination: &Path) -> Result<()> {
    run_checked(
        Command::new("curl")
            .arg("--proto")
            .arg("=https")
            .arg("--proto-redir")
            .arg("=https")
            .arg("--tlsv1.2")
            .arg("--fail")
            .arg("--silent")
            .arg("--show-error")
            .arg("--location")
            .arg("--output")
            .arg(destination)
            .arg(url),
    )
}

fn verify_checksum(archive: &Path, checksum: &Path, archive_name: &str) -> Result<()> {
    let source = fs::read_to_string(checksum)?;
    let mut fields = source.split_whitespace();
    let expected = fields
        .next()
        .ok_or_else(|| message("release checksum file is empty"))?;
    let named = fields
        .next()
        .ok_or_else(|| message("release checksum does not name its archive"))?
        .trim_start_matches('*');
    if named != archive_name || expected.len() != 64 {
        return Err(message("release checksum file has an unexpected format"));
    }
    let mut reader = BufReader::new(File::open(archive)?);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    let actual = format!("{:x}", digest.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(message(format!(
            "release SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn validate_archive_paths(archive: &Path, expected_root: &str) -> Result<()> {
    let output = run_output(
        Command::new("tar")
            .arg("--list")
            .arg("--gzip")
            .arg("--file")
            .arg(archive),
    )?;
    let listing = String::from_utf8(output.stdout)?;
    for entry in listing.lines() {
        let path = Path::new(entry);
        let mut components = path.components();
        if components.next() != Some(Component::Normal(OsStr::new(expected_root)))
            || components.any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(message(format!("unsafe release archive path {entry:?}")));
        }
    }
    Ok(())
}

fn validate_regular_archive_member(archive: &Path, member: &str) -> Result<()> {
    let output = run_output(
        Command::new("tar")
            .arg("--list")
            .arg("--verbose")
            .arg("--gzip")
            .arg("--file")
            .arg(archive)
            .arg(member),
    )?;
    let listing = String::from_utf8(output.stdout)?;
    let lines = listing.lines().collect::<Vec<_>>();
    if lines.len() != 1 || !lines[0].starts_with('-') {
        return Err(message(format!(
            "release member {member:?} must occur once as a regular file"
        )));
    }
    Ok(())
}

fn checked_release_file(temporary: &Path, path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(message(format!(
            "release member {} is not a regular file",
            path.display()
        )));
    }
    let canonical_temporary = temporary.canonicalize()?;
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(canonical_temporary) {
        return Err(message("release member escaped its temporary directory"));
    }
    Ok(canonical)
}

fn validate_downloaded_release(
    layout: &Layout,
    server: &Path,
    ctl: &Path,
    expected_version: Option<&str>,
) -> Result<()> {
    verify_binary(server, "rust-xhttp")?;
    verify_binary(ctl, "rust-xhttpctl")?;
    require_matching_versions(server, ctl, expected_version)?;
    run_checked(Command::new(server).arg("check").arg(layout.config()))
}

fn require_matching_versions(
    server: &Path,
    ctl: &Path,
    expected_version: Option<&str>,
) -> Result<()> {
    let server_output = binary_version(server)?;
    let ctl_output = binary_version(ctl)?;
    let server_version = server_output
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| message("rust-xhttp did not report a version number"))?;
    let ctl_version = ctl_output
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| message("rust-xhttpctl did not report a version number"))?;
    if server_version != ctl_version {
        return Err(message(format!(
            "daemon version {server_version} does not match manager version {ctl_version}"
        )));
    }
    if let Some(expected) = expected_version
        && server_version != expected
    {
        return Err(message(format!(
            "release tag requires version {expected}, but binaries report {server_version}"
        )));
    }
    Ok(())
}

fn create_rollback(layout: &Layout) -> Result<()> {
    let staging = unique_directory(&layout.manager_dir(), "rollback-new")?;
    copy_atomic(&layout.server_binary(), &staging.join("rust-xhttp"), 0o700)?;
    copy_atomic(&layout.ctl_binary(), &staging.join("rust-xhttpctl"), 0o700)?;
    atomic_write(
        &staging.join("version.txt"),
        format!("{}\n", binary_version(&layout.server_binary())?).as_bytes(),
        0o600,
    )?;
    let rollback = layout.rollback_dir();
    if rollback.exists() {
        fs::remove_dir_all(&rollback)?;
    }
    fs::rename(staging, rollback)?;
    Ok(())
}

fn restore_rollback(layout: &Layout) -> Result<()> {
    let rollback = layout.rollback_dir();
    copy_atomic(&rollback.join("rust-xhttp"), &layout.server_binary(), 0o755)?;
    copy_atomic(&rollback.join("rust-xhttpctl"), &layout.ctl_binary(), 0o755)?;
    Ok(())
}

fn rollback(layout: &Layout) -> Result<()> {
    let rollback_dir = layout.rollback_dir();
    let rollback_server = rollback_dir.join("rust-xhttp");
    let rollback_ctl = rollback_dir.join("rust-xhttpctl");
    if !rollback_server.is_file() || !rollback_ctl.is_file() {
        return Err(message("no previous binary set is available"));
    }
    validate_downloaded_release(layout, &rollback_server, &rollback_ctl, None)?;
    let current = unique_directory(&layout.manager_dir(), "rollback-current")?;
    copy_atomic(&layout.server_binary(), &current.join("rust-xhttp"), 0o700)?;
    copy_atomic(&layout.ctl_binary(), &current.join("rust-xhttpctl"), 0o700)?;
    atomic_write(
        &current.join("version.txt"),
        format!("{}\n", binary_version(&layout.server_binary())?).as_bytes(),
        0o600,
    )?;

    let result = (|| -> Result<()> {
        restore_rollback(layout)?;
        run_checked(
            Command::new(layout.ctl_binary())
                .arg("repair")
                .arg("--no-restart"),
        )?;
        run_checked(Command::new("systemctl").arg("restart").arg(SERVICE))?;
        run_checked(
            Command::new("systemctl")
                .arg("is-active")
                .arg("--quiet")
                .arg(SERVICE),
        )
    })();
    if let Err(error) = result {
        copy_atomic(&current.join("rust-xhttp"), &layout.server_binary(), 0o755)?;
        copy_atomic(&current.join("rust-xhttpctl"), &layout.ctl_binary(), 0o755)?;
        let _ = run_checked(
            Command::new(layout.ctl_binary())
                .arg("repair")
                .arg("--no-restart"),
        );
        let _ = run_checked(Command::new("systemctl").arg("restart").arg(SERVICE));
        let _ = fs::remove_dir_all(&current);
        return Err(message(format!(
            "rollback failed; current binaries were restored: {error}"
        )));
    }
    fs::remove_dir_all(&rollback_dir)?;
    fs::rename(current, rollback_dir)?;
    println!("Rollback completed. The replaced version is now the next rollback target.");
    Ok(())
}

fn repair_command(arguments: Vec<OsString>) -> Result<()> {
    let restart = match arguments.as_slice() {
        [] => true,
        [flag] if flag == "--no-restart" => false,
        [flag] if flag == "--help" || flag == "-h" => {
            println!("usage: rust-xhttpctl repair [--no-restart]");
            return Ok(());
        }
        _ => return Err(message("usage: rust-xhttpctl repair [--no-restart]")),
    };
    require_root()?;
    repair(&Layout::system(), restart)
}

fn repair(layout: &Layout, restart: bool) -> Result<()> {
    ensure_system_user()?;
    prepare_directories(layout)?;
    validate_config_file(&layout.config())?;
    verify_binary(&layout.server_binary(), "rust-xhttp")?;
    verify_binary(&layout.ctl_binary(), "rust-xhttpctl")?;
    atomic_write(&layout.unit(), systemd_unit().as_bytes(), 0o644)?;
    apply_ownership(layout)?;
    run_checked(Command::new("systemctl").arg("daemon-reload"))?;
    run_checked(Command::new("systemctl").arg("enable").arg(SERVICE))?;
    if restart {
        run_checked(Command::new("systemctl").arg("restart").arg(SERVICE))?;
    }
    println!("systemd integration repaired successfully.");
    Ok(())
}

fn uninstall_command(arguments: Vec<OsString>) -> Result<()> {
    let mut purge = false;
    let mut assume_yes = false;
    for argument in arguments {
        match argument.to_string_lossy().as_ref() {
            "--purge" => purge = true,
            "--yes" | "-y" => assume_yes = true,
            "--help" | "-h" => {
                println!("usage: rust-xhttpctl uninstall [--purge] [--yes]");
                return Ok(());
            }
            value => return Err(message(format!("unknown uninstall option {value:?}"))),
        }
    }
    require_root()?;
    uninstall(&Layout::system(), purge, assume_yes)
}

fn uninstall(layout: &Layout, purge: bool, assume_yes: bool) -> Result<()> {
    let question = if purge {
        "Remove service, binaries, configuration, certificates, website data, and rollback data?"
    } else {
        "Remove the service and binaries while preserving configuration and data?"
    };
    if !assume_yes && !confirm(question, false)? {
        println!("Uninstall cancelled.");
        return Ok(());
    }
    let _ = Command::new("systemctl")
        .args(["disable", "--now", SERVICE])
        .status();
    remove_file_if_present(&layout.unit())?;
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl")
        .args(["reset-failed", SERVICE])
        .status();
    remove_file_if_present(&layout.server_binary())?;
    remove_file_if_present(&layout.ctl_binary())?;
    if purge {
        remove_directory_if_present(&layout.config_dir())?;
        remove_directory_if_present(&layout.state_dir())?;
        remove_directory_if_present(&layout.manager_dir())?;
        let _ = Command::new("userdel").arg(SERVICE_USER).status();
        let _ = Command::new("groupdel").arg(SERVICE_USER).status();
        println!("rust-xhttp and all managed data were removed.");
    } else {
        println!("rust-xhttp binaries and service were removed.");
        println!("Preserved config: {}", layout.config_dir().display());
        println!("Preserved state:  {}", layout.state_dir().display());
        println!("Re-running the installer will reuse the preserved config.");
    }
    Ok(())
}

fn ensure_supported_platform() -> Result<()> {
    if env::consts::OS != "linux" {
        return Err(message(
            "the managed installer currently supports Linux only",
        ));
    }
    if env::consts::ARCH != "x86_64" {
        return Err(message(
            "official managed releases currently support x86_64 only; build from source for this architecture",
        ));
    }
    Ok(())
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(message("this operation requires root; run it with sudo"));
    }
    Ok(())
}

fn verify_binary(path: &Path, expected_name: &str) -> Result<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| message(format!("cannot access binary {}: {error}", path.display())))?;
    if !metadata.is_file() {
        return Err(message(format!("{} is not a file", path.display())));
    }
    let output = run_output(Command::new(path).arg("--version"))?;
    let version = String::from_utf8(output.stdout)?;
    if version.split_whitespace().next() != Some(expected_name) {
        return Err(message(format!(
            "{} identified as {:?}, expected {expected_name}",
            path.display(),
            version.trim()
        )));
    }
    Ok(())
}

fn binary_version(path: &Path) -> Result<String> {
    let output = run_output(Command::new(path).arg("--version"))?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn atomic_write(destination: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| message(format!("{} has no parent", destination.display())))?;
    let temporary = unique_path(parent, ".rust-xhttpctl-write")?;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, destination)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_atomic(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| message(format!("{} has no parent", destination.display())))?;
    if !parent.is_dir() {
        create_dir(parent, 0o755)?;
    }
    let temporary = unique_path(parent, ".rust-xhttpctl-copy")?;
    let result = (|| -> Result<()> {
        fs::copy(source, &temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn unique_path(parent: &Path, prefix: &str) -> Result<PathBuf> {
    for _ in 0..32 {
        let candidate = parent.join(format!("{prefix}.{}.{}", std::process::id(), random_hex(6)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(message("failed to allocate a unique temporary path"))
}

fn unique_directory(parent: &Path, prefix: &str) -> Result<PathBuf> {
    let path = unique_path(parent, prefix)?;
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn random_hex(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut random);
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(value) if !value.is_empty() => print!("{label} [{value}]: "),
        _ => print!("{label}: "),
    }
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_owned();
    if answer.is_empty() {
        Ok(default.unwrap_or_default().to_owned())
    } else {
        Ok(answer)
    }
}

fn required_prompt(label: &str, default: Option<&str>) -> Result<String> {
    let answer = prompt(label, default)?;
    if answer.is_empty() {
        Err(message(format!("{label} must not be empty")))
    } else {
        Ok(answer)
    }
}

fn confirm(label: &str, default: bool) -> Result<bool> {
    let marker = if default { "Y/n" } else { "y/N" };
    let answer = prompt(&format!("{label} ({marker})"), Some(""))?;
    if answer.is_empty() {
        return Ok(default);
    }
    match answer.to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Err(message("answer must be yes or no")),
    }
}

fn required_path(arguments: &[OsString], position: usize, option: &str) -> Result<PathBuf> {
    arguments
        .get(position)
        .map(PathBuf::from)
        .ok_or_else(|| message(format!("{option} requires a path")))
}

fn reject_arguments(arguments: &[OsString]) -> Result<()> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(message("unexpected arguments"))
    }
}

fn run_checked(command: &mut Command) -> Result<()> {
    let description = format!("{command:?}");
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(message(format!("command failed ({status}): {description}")))
    }
}

fn run_inherited(command: &mut Command) -> Result<()> {
    run_checked(command)
}

fn run_output(command: &mut Command) -> Result<Output> {
    let description = format!("{command:?}");
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(message(format!(
            "command failed ({}): {}: {}",
            output.status,
            description,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_directory_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn message(value: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(value.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternate_root_only_prefixes_host_paths() {
        let layout = Layout::under(PathBuf::from("/tmp/image")).unwrap();
        assert_eq!(
            layout.server_binary(),
            PathBuf::from("/tmp/image/usr/local/bin/rust-xhttp")
        );
        assert!(systemd_unit().contains("ExecStart=/usr/local/bin/rust-xhttp "));
    }

    #[test]
    fn release_tags_reject_path_and_option_injection() {
        assert_eq!(validate_tag("v0.2.0").unwrap(), "v0.2.0");
        assert!(validate_tag("../../etc/passwd").is_err());
        assert!(validate_tag("--output=x").is_err());
        assert!(validate_tag("0.2.0").is_err());
    }

    #[test]
    fn random_uuid_has_rfc4122_v4_shape() {
        let value = random_uuid();
        assert_eq!(value.len(), 36);
        assert_eq!(&value[14..15], "4");
        assert!(matches!(&value[19..20], "8" | "9" | "a" | "b"));
        assert!(uuid::Uuid::parse_str(&value).is_ok());
    }

    #[test]
    fn generated_unit_is_hardened_and_preflights_config() {
        let unit = systemd_unit();
        assert!(unit.contains("User=rust-xhttp"));
        assert!(unit.contains("ExecStartPre=/usr/local/bin/rust-xhttp check"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("ProtectSystem=strict"));
    }

    #[test]
    fn checksum_verification_binds_digest_and_name() {
        let root = unique_directory(&env::temp_dir(), "rust-xhttp-checksum-test").unwrap();
        let archive = root.join("release.tar.gz");
        let checksum = root.join("release.tar.gz.sha256");
        fs::write(&archive, b"release bytes").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"release bytes"));
        fs::write(&checksum, format!("{digest}  release.tar.gz\n")).unwrap();
        verify_checksum(&archive, &checksum, "release.tar.gz").unwrap();

        fs::write(&checksum, format!("{digest}  another.tar.gz\n")).unwrap();
        assert!(verify_checksum(&archive, &checksum, "release.tar.gz").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn site_copy_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = unique_directory(&env::temp_dir(), "rust-xhttp-site-test").unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("index.html"), b"hello").unwrap();
        copy_site_tree(&source, &destination, 0).unwrap();
        assert_eq!(fs::read(destination.join("index.html")).unwrap(), b"hello");

        symlink("index.html", source.join("link.html")).unwrap();
        assert!(copy_site_tree(&source, &destination, 0).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manual_tls_and_site_changes_can_be_restored() {
        let root = unique_directory(&env::temp_dir(), "rust-xhttp-resource-test").unwrap();
        let layout = Layout::under(root.join("image")).unwrap();
        prepare_directories(&layout).unwrap();

        let certificate = root.join("new-cert.pem");
        let private_key = root.join("new-key.pem");
        fs::write(&certificate, b"new certificate").unwrap();
        fs::write(&private_key, b"new key").unwrap();
        fs::write(
            layout.config_dir().join("tls/fullchain.pem"),
            b"old certificate",
        )
        .unwrap();
        fs::write(layout.config_dir().join("tls/privkey.pem"), b"old key").unwrap();
        let files = install_manual_tls(&layout, &certificate, &private_key).unwrap();
        assert_eq!(
            fs::read(layout.config_dir().join("tls/fullchain.pem")).unwrap(),
            b"new certificate"
        );

        fs::write(layout.state_dir().join("site/index.html"), b"old site").unwrap();
        let source_site = root.join("new-site");
        fs::create_dir(&source_site).unwrap();
        fs::write(source_site.join("index.html"), b"new site").unwrap();
        let site = install_site(&layout, &source_site).unwrap();
        restore_resources(&files, Some(&site)).unwrap();
        assert_eq!(
            fs::read(layout.config_dir().join("tls/fullchain.pem")).unwrap(),
            b"old certificate"
        );
        assert_eq!(
            fs::read(layout.config_dir().join("tls/privkey.pem")).unwrap(),
            b"old key"
        );
        assert_eq!(
            fs::read(layout.state_dir().join("site/index.html")).unwrap(),
            b"old site"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
