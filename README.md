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
| `src/bin/rust-xhttpctl.rs`, `src/management.rs` | interactive installer and lifecycle manager |
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

## One-command interactive installation

The managed installer currently targets **x86_64 Linux with systemd**. Before
running it, point an A/AAAA record at the server and allow inbound TCP 443. The
recommended automatic-certificate mode also needs inbound TCP 80 for ACME
HTTP-01. Then run:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/jacek4yang/rust-xhttp/releases/latest/download/install.sh | sudo sh
```

The shell file is only a small bootstrap: it resolves one immutable GitHub
release, downloads the archive and its published SHA-256 file, verifies them,
then starts the **Rust `rust-xhttpctl` wizard** on the terminal. If you prefer to
inspect every privileged instruction first:

```bash
curl --proto '=https' --tlsv1.2 -fLo install.sh \
  https://github.com/jacek4yang/rust-xhttp/releases/latest/download/install.sh
less install.sh
sudo sh install.sh
```

The wizard can configure:

- automatic Let's Encrypt issuance and renewal, existing PEM files, or
  plaintext behind Cloudflare/nginx/another TLS terminator;
- domain, listen address/port, generated or supplied UUID, randomized XHTTP
  path, and optional `xtls-rprx-vision` flow;
- a generated customizable blog, or a copied/preloaded user `dist` directory;
- a dedicated unprivileged `rust-xhttp` account and a hardened, enabled systemd
  service with only `CAP_NET_BIND_SERVICE`.

It validates syntax and referenced resources before systemd starts the service.
PEM keys are copied with restricted permissions; custom site content is copied
under the service-owned state directory. Existing configuration is backed up.

### Long-term management

The installed `rust-xhttpctl` binary owns the complete lifecycle:

| Task | Command |
| --- | --- |
| Interactive management menu | `sudo rust-xhttpctl manage` |
| Service status | `rust-xhttpctl status` |
| Follow the last 100 journal lines | `rust-xhttpctl logs` |
| Check files, config, systemd enablement and health | `rust-xhttpctl doctor` |
| Validate, edit, back up and atomically activate config | `sudo rust-xhttpctl edit` |
| Start/stop/restart | `sudo rust-xhttpctl service restart` |
| Verified update to the latest release | `sudo rust-xhttpctl update` |
| Install a specific release | `sudo rust-xhttpctl update v0.2.0` |
| Swap back to the previous binary set | `sudo rust-xhttpctl rollback` |
| Recreate permissions and the hardened unit | `sudo rust-xhttpctl repair` |
| Remove service/binaries but preserve config and data | `sudo rust-xhttpctl uninstall` |
| Remove service, config, ACME keys, site and rollback data | `sudo rust-xhttpctl uninstall --purge` |

Updates are transactional: the manager verifies the archive checksum, checks
the new daemon against the installed config, retains the current daemon and
manager as one rollback set, restarts systemd, and restores the previous set if
activation fails. `edit` follows the same validate-before-restart rule and
restores its timestamped backup after a failed restart.

Managed files use this stable layout:

```text
/usr/local/bin/rust-xhttp       # network daemon
/usr/local/bin/rust-xhttpctl    # installer and lifecycle manager
/etc/rust-xhttp/config.json     # Xray-shaped configuration
/etc/rust-xhttp/backups/        # configuration history
/etc/rust-xhttp/tls/            # copied manual PEM files
/var/lib/rust-xhttp/acme/       # ACME account, cert and renewal state
/var/lib/rust-xhttp/site/       # optional preloaded dist site
/var/lib/rust-xhttp-manager/    # update/rollback state (root-only)
```

Read the full [installation and management guide](docs/installation-management.md)
for firewall, reverse-proxy, recovery and trust details. Configuration mirrors
Xray's `inbounds/settings/streamSettings/xhttpSettings` layout; see the complete
[configuration guide](docs/configuration.md).

### Existing config, manual release, or source build

To install a reviewed existing config from an extracted release:

```bash
sudo ./rust-xhttpctl install \
  --server-binary ./rust-xhttp \
  --ctl-binary ./rust-xhttpctl \
  --config /path/to/config.json
```

To build both binaries yourself, install Rust 1.88+ and run:

```bash
git clone https://github.com/jacek4yang/rust-xhttp.git
cd rust-xhttp
cargo build --locked --release --bins
sudo target/release/rust-xhttpctl install \
  --server-binary target/release/rust-xhttp \
  --ctl-binary target/release/rust-xhttpctl
```

Official Linux binaries target `x86-64-v3` (Haswell/Zen or newer). Older CPUs
must build from source with a compatible `RUSTFLAGS` target. The daemon remains
usable without systemd for containers or custom supervisors:

```bash
rust-xhttp check /path/to/config.json
rust-xhttp /path/to/config.json
```

For development, run `cargo test`, `cargo clippy --all-targets -- -D warnings`,
and `cargo fmt --all -- --check`.

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
| Installation and management | [English](docs/installation-management.md) | [简体中文](docs/installation-management.zh-CN.md) |
| Benchmarks and evidence | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| Performance and availability | [English](docs/performance-and-availability.md) | [简体中文](docs/performance-and-availability.zh-CN.md) |
| Hotspot optimization report | [English](docs/performance-hotspots.md) | [简体中文](docs/performance-hotspots.zh-CN.md) |
| Security policy | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |
