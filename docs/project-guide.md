# rust-xhttp Project Guide

`rust-xhttp` is a single-crate, pure-Rust server compatible with the official
Xray-core client for this stack:

```text
XHTTP packet-up + VLESS + VLESS-Encryption + xtls-rprx-vision + XUDP
```

It is not a general Xray replacement. The implementation focuses on the server
side of XHTTP packet-up, with deployment either as a TLS/H2 origin, behind
Cloudflare, or behind an HTTP reverse proxy for packet-up only.

## Daily workflow

```bash
scripts/gate.sh
cargo build --release
scripts/bench.sh
```

Machine-local assets live under `local/`; reference source trees live under
`local/references/`.

## Main modules

| Path | Responsibility |
| --- | --- |
| `src/main.rs`, `src/runtime.rs` | CLI entry and runtime wiring |
| `src/config.rs` | Xray-shaped JSON schema and validation |
| `src/origin.rs` | hyper HTTP origin over plaintext or in-tree TLS |
| `src/xhttp/` | XHTTP request classification and padding validation |
| `src/session/` | session table, reorder, downlink |
| `src/dispatcher.rs` | VLESS TCP/UDP/XUDP dispatch |
| `src/vless/` | VLESS auth, addons, Vision, encryption |
| `src/xudp.rs` | XUDP and plain UDP codecs |

## Current gaps

Live Xray XHTTP A/B now exists in two forms:

- `scripts/m11_docker_xray_perf.sh` drives raw VLESS-over-XHTTP packet-up traffic
  against `rust-xhttp` and Xray-core server candidates.
- `scripts/m12_docker_xray_client_perf.sh` drives traffic through the official
  Xray-core SOCKS client and can enable VLESS-Encryption with
  `VLESS_ENCRYPTION=1`.

Remaining gaps are pcap/TLS differential automation beyond the ignored nginx
harness, network-emulation runs, and broader cancellation/backpressure stress.
