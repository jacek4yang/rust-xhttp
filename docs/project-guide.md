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
| `src/config.rs` | TOML schema and validation |
| `src/origin.rs` | hyper/rustls HTTP origin |
| `src/xhttp/` | XHTTP request classification and padding validation |
| `src/session/` | session table, reorder, downlink |
| `src/dispatcher.rs` | VLESS TCP/UDP/XUDP dispatch |
| `src/vless/` | VLESS auth, addons, Vision, encryption |
| `src/xudp.rs` | XUDP and plain UDP codecs |

## Current gaps

Live Xray XHTTP A/B, soak, pcap, and network-emulation harnesses are represented
by script entries for layout parity, but they intentionally exit until a real
XHTTP workload harness exists.
