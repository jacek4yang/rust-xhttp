//! rust-xhttp server entry point.
//!
//! Reads a TOML config (path from argv[1], default `config.toml`), initializes
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
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let cfg = Config::load(&path).map_err(|e| {
        eprintln!("rust-xhttp: invalid config {path:?}: {e}");
        2
    })?;

    rust_xhttp::logging::init(&cfg.observability.log).map_err(|e| {
        eprintln!("rust-xhttp: failed to initialize logging: {e}");
        2
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("rust-xhttp: failed to build runtime: {e}");
            2
        })?;

    let cfg = Arc::new(cfg);
    rt.block_on(async move {
        if let Err(e) = runtime::serve(cfg).await {
            eprintln!("rust-xhttp: server error: {e}");
        }
    });
    Ok(())
}
