# rust-xhttp

[![CI](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jacek4yang/rust-xhttp)](https://github.com/jacek4yang/rust-xhttp/releases/latest)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)

English | [简体中文](README.zh-CN.md)

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

It deploys the same wire protocol three ways, selected by the Xray-shaped JSON
`streamSettings.security` and listen address:

- **Direct** — `Xray client → Rust (in-tree TLS 1.3 / H2)`
- **Cloudflare** — `Xray client → Cloudflare → Rust (H2 to origin)`
- **Behind nginx** — `packet-up` only (HTTP/1.1 upstream); long-stream modes unsupported there.

## Performance snapshot

The committed v0.1.0 evidence compares the same byte-verified TCP echo workload
against Xray-core on one loopback host. In the official-Xray-client c32 runs,
rust-xhttp completed 1.22–1.28× as many operations with 0.42–0.53× the measured
server CPU per operation. The lower-level raw-server c64 run was throughput-neutral
(1.006×) while using 0.47× server CPU per operation.

| Workload | rust-xhttp ops/s | Xray-core ops/s | Rust/Xray | Rust CPU / Xray CPU |
| --- | ---: | ---: | ---: | ---: |
| Raw server, c64 | 1,568 | 1,558 | 1.006× | 0.47× |
| Official Xray client, c32 | 3,306 | 2,593 | **1.28×** | **0.42×** |
| Official client + VLESS-Encryption, c32 | 3,147 | 2,588 | **1.22×** | **0.53×** |

![rust-xhttp versus Xray-core operations per second](docs/assets/performance-ops-v0.1.0.svg)

These are exploratory, single-host measurements—not Internet throughput guarantees.
The p99/CPU charts, limitations, raw JSON evidence, and exact reproduction commands
are in the bilingual benchmark guide: [English](docs/benchmarks.md) |
[简体中文](docs/benchmarks.zh-CN.md).

## Layout

Single crate, one module per protocol layer (mirrors the sibling `rust-reality` project):

| Path | Responsibility |
|------|----------------|
| `src/main.rs`, `src/runtime.rs` | entry point + stack wiring |
| `src/config.rs` | strict Xray-shaped JSON schema, validation, safe defaults |
| `src/acme.rs` | HTTP-01 issuance, renewal backoff, atomic certificate activation |
| `src/origin.rs` | hyper 1.x origin over in-tree TLS 1.3/H2, HTTP/1.1, and h2c; health routes |
| `src/xhttp/` | request meta extraction, padding-first validation, packet-up/stream-down routing |
| `src/session/` | sharded session table, bounded seq reorder, grace TTL |
| `src/dispatcher.rs` | VLESS command → TCP/UDP/XUDP target, bounded bidirectional pumps |
| `src/site.rs` | generated blog or preloaded `dist` fallback for non-XHTTP traffic |
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

Requires Rust 1.88+ (edition 2024; required for the security-fixed `time` dependency).

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
cp config.acme.example.json config.json # edit UUID, domain, path, and email
./target/release/rust-xhttp check config.json
sudo ./target/release/rust-xhttp config.json
```

The config mirrors Xray's `inbounds/settings/streamSettings/xhttpSettings`
layout. Direct TLS can use user-managed PEM files or built-in ACME HTTP-01 with
background renewal and atomic activation. Ordinary traffic is a generated,
customizable blog by default, or a preloaded user `dist` directory. Logging is
controlled by `log.loglevel` or `RUST_LOG`. See the complete
[configuration guide](docs/configuration.md) and
[performance/availability analysis](docs/performance-and-availability.md).

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

## Documentation

| Guide | English | 简体中文 |
| --- | --- | --- |
| Documentation index | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| Configuration and deployment | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| Benchmarks and evidence | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| Performance and availability | [English](docs/performance-and-availability.md) | [简体中文](docs/performance-and-availability.zh-CN.md) |
| Hotspot optimization report | [English](docs/performance-hotspots.md) | [简体中文](docs/performance-hotspots.zh-CN.md) |
| Security policy | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |
