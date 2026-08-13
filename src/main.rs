//! rust-xhttp server entry point.
//!
//! Reads an Xray-shaped JSON config (path from argv[1], default `config.json`), initializes
//! logging, builds a multi-threaded Tokio runtime, and serves the XHTTP origin
//! until the process is signalled.

use std::path::PathBuf;
use std::sync::Arc;

use rust_xhttp::config::Config;
use rust_xhttp::runtime;

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}

fn run() -> Result<(), i32> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("--help")) {
        println!(
            "rust-xhttp {}\n\nUSAGE:\n    rust-xhttp [config.json]\n    rust-xhttp check [config.json]",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("rust-xhttp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let check_only = first.as_deref() == Some(std::ffi::OsStr::new("check"));
    let path = if check_only {
        arguments.next().map(PathBuf::from)
    } else {
        first.map(PathBuf::from)
    }
    .unwrap_or_else(|| PathBuf::from("config.json"));
    if arguments.next().is_some() {
        eprintln!("rust-xhttp: too many arguments; run with --help for usage");
        return Err(2);
    }

    let cfg = Config::load(&path).map_err(|e| {
        eprintln!("rust-xhttp: invalid config {path:?}: {e}");
        2
    })?;

    if check_only {
        runtime::validate(&cfg).map_err(|e| {
            eprintln!("rust-xhttp: config resource validation failed: {e}");
            2
        })?;
        println!("configuration is valid: {}", path.display());
        return Ok(());
    }

    rust_xhttp::logging::init(&cfg.observability.log).map_err(|e| {
        eprintln!("rust-xhttp: failed to initialize logging: {e}");
        2
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.listen.worker_threads())
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("rust-xhttp: failed to build runtime: {e}");
            2
        })?;

    let cfg = Arc::new(cfg);
    rt.block_on(async move { runtime::serve(cfg).await })
        .map_err(|e| {
            eprintln!("rust-xhttp: server error: {e}");
            1
        })?;
    Ok(())
}
