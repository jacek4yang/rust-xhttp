# rust-xhttp

[![CI](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jacek4yang/rust-xhttp)](https://github.com/jacek4yang/rust-xhttp/releases/latest)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)

A pure-Rust server that is **wire-compatible with the official Xray-core client** for the
XHTTP transport stack — no client modifications, no custom wire formats, no anti-detection
theatre. Every byte of behaviour is derived from the local Xray sources under
`local/references/Xray-core`.

Protocol stack (server side):

```
XHTTP (packet-up) + VLESS + VLESS-Encryption + xtls-rprx-vision + XUDP
```

> [!IMPORTANT]
> This is pre-1.0, security-sensitive networking software and has not received
> an independent security audit. The in-tree TLS 1.3 backend interoperates with
> OpenSSL clients, but exact nginx/OpenSSL fingerprint equivalence is not claimed;
> see [`docs/tls-fidelity-analysis.md`](docs/tls-fidelity-analysis.md).

It deploys the same wire protocol three ways, differing only in `[tls]` / listen address:

- **Direct** — `Xray client → Rust (in-tree TLS 1.3 / H2)`
- **Cloudflare** — `Xray client → Cloudflare → Rust (H2 to origin)`
- **Behind nginx** — `packet-up` only (HTTP/1.1 upstream); long-stream modes unsupported there.

## Layout

Single crate, one module per protocol layer (mirrors the sibling `rust-reality` project):

| Path | Responsibility |
|------|----------------|
| `src/main.rs`, `src/runtime.rs` | entry point + stack wiring |
| `src/config.rs` | TOML schema, validation, safe defaults |
| `src/origin.rs` | hyper 1.x origin over in-tree TLS 1.3/H2, HTTP/1.1, and h2c; health routes |
| `src/xhttp/` | request meta extraction, padding-first validation, packet-up/stream-down routing |
| `src/session/` | sharded session table, bounded seq reorder, idle TTL |
| `src/dispatcher.rs` | VLESS command → TCP/UDP/XUDP target, bounded bidirectional pumps |
| `src/site.rs` | built-in static blog fallback for non-XHTTP GET/HEAD traffic |
| `src/vless/` | VLESS header/addons/address/auth, `vision`, `encryption` |
| `src/xudp.rs` | XUDP (Mux) framing + plain VLESS-UDP |
| `src/buffer.rs`, `src/metrics.rs` | global memory budget + lock-free counters |

Per-protocol ground-truth maps and deployment notes live in [`docs/`](docs/).
The non-XHTTP static fallback is documented in
[`docs/static-fallback.md`](docs/static-fallback.md).

## Build & test

```bash
cargo build --release            # → target/release/rust-xhttp
cargo test                       # unit + reorder + crypto + integration
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Requires Rust 1.85+ (edition 2024).

Official Linux release binaries target `x86-64-v3` (Haswell/Zen or newer). Build
from source with an overridden `RUSTFLAGS` value for older CPUs; see
[`docs/production-hardening.md`](docs/production-hardening.md).

## Install

Download the current `x86_64-unknown-linux-gnu` archive from
[GitHub Releases](https://github.com/jacek4yang/rust-xhttp/releases/latest), or build locally:

```bash
git clone https://github.com/jacek4yang/rust-xhttp.git
cd rust-xhttp
cargo build --locked --release
```

## Run

```bash
cp config.example.toml config.toml      # edit users / TLS paths
./target/release/rust-xhttp config.toml
```

Logging is controlled by `[observability].log` or the `RUST_LOG` environment variable.

## Scope & non-claims

This is **not** a general Xray-core replacement: it implements exactly the server side of the
official `packet-up` XHTTP mode and the VLESS protocols that ride on it. It makes **no**
"undetectable / zero-fingerprint" claims and performs no browser or timing spoofing — every
behaviour maps to a cited Xray source. Items not yet green are tracked, with evidence, in
`docs/` rather than claimed done.

## License

MPL-2.0 — this crate is a clean-room-by-spec port of several MPL-2.0 Xray-core packages
(`proxy/vless`, `transport/internet/splithttp`, `common/xudp`).

Security reports should follow [`SECURITY.md`](SECURITY.md); contributions are
welcome under [`CONTRIBUTING.md`](CONTRIBUTING.md).
