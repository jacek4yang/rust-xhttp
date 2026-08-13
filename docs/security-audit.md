# Security Audit Notes

This document is the xhttp counterpart to the `rust-reality` audit entry. It is
currently a scoped checklist, not a completed external audit.

## Trust boundaries

- Inbound HTTP requests are untrusted until path, host, padding, session, and
  VLESS authentication checks pass.
- Config files and certificate paths are operator-controlled.
- Reference sources under `local/references/` are not part of the shipped
  binary.

## Current controls

- Bounded request body size for packet-up uploads.
- Bounded per-session reorder queue and byte accounting.
- Global buffer budget.
- The global buffer budget is wired into uplink reorder and in-order backpressure
  queues; buffered upload bytes hold an RAII reservation until the VLESS reader
  consumes them, and over-budget uploads are rejected with 503.
- Session grace timers and bounded TLS/VLESS handshake timeouts.
- Uniform VLESS auth failure handling.
- Optional direct TLS termination with the in-tree TLS 1.3 backend.
- VLESS-Encryption has unit coverage for the normal 1-RTT server handshake,
  ML-KEM/X25519 PFS response processing, and bidirectional encrypted record
  traffic after the handshake.
- `scripts/m12_docker_xray_client_perf.sh` runs the official Xray-core client
  through SOCKS into this server over VLESS/XHTTP, and
  `VLESS_ENCRYPTION=1 scripts/m12_docker_xray_client_perf.sh` verifies the same
  workload with Xray-generated VLESS-Encryption settings.

## Open audit work

- Fuzz/proptest coverage for XHTTP metadata and VLESS/VLESS-Encryption parsers.
- HTTP/H2 backpressure and cancellation stress tests.
