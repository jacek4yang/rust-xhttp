//! Logging initialization.
//!
//! The data path uses the `tracing` macros (`tracing::debug!`, `info!`, …); this
//! module wires them to a stderr subscriber filtered by the config `log` string
//! (an `EnvFilter` directive such as `"info"` or `"info,rust_xhttp=debug"`). The
//! `RUST_LOG` environment variable, if set, overrides the config value.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber from a filter directive. Called once
/// at startup; an invalid directive is reported to the caller rather than panicking.
pub fn init(filter: &str) -> Result<(), Box<dyn std::error::Error>> {
    let env = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(filter))?;
    tracing_subscriber::fmt().with_env_filter(env).init();
    Ok(())
}
