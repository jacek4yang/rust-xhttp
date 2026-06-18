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
- Session idle and grace timers.
- Uniform VLESS auth failure handling.
- Optional TLS termination with rustls.

## Open audit work

- Live Xray interop harness for packet-up under load.
- Fuzz/proptest coverage for XHTTP metadata and VLESS/VLESS-Encryption parsers.
- HTTP/H2 backpressure and cancellation stress tests.
