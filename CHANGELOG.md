# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-08-14

### Changed

- Reduced authenticated XHTTP hot-path allocation, locking, address-resolution,
  reference-count, and session teardown overhead using profile-guided changes.
- Cancelled orphan-session grace timers promptly and skipped them entirely for the
  normal download-first request order, substantially reducing transient RSS growth.
- Added a sustained PID-scoped `perf` driver, focused allocation reference
  microbenchmarks, and a bilingual hotspot optimization report.

## [0.1.0] - 2026-08-13

### Added

- XHTTP packet-up transport with body, header, cookie, and auto payload placement.
- VLESS TCP, UDP, XUDP, `xtls-rprx-vision`, and VLESS-Encryption server support.
- Direct in-tree TLS 1.3 termination with HTTP/2 and HTTP/1.1 ALPN.
- Cloudflare/nginx plaintext-origin deployment mode and nginx-shaped static fallback.
- Bounded session reorder queues, global upload-buffer accounting, socket tuning,
  operational scripts, protocol documentation, and compatibility benchmarks.
- English and Simplified Chinese operator documentation, a complete configuration
  tutorial, committed benchmark evidence, and reproducible comparison charts.
- Strict Xray-shaped JSON configuration, generated or preloaded `dist` website
  fallback, ACME HTTP-01 issuance/renewal with atomic TLS activation, config
  preflight checks, and graceful connection draining.

### Security

- Enforced TLS/VLESS handshake deadlines and strict rejection of unknown config keys.
- Added bounded request/session/target controls and fail-closed memory accounting.

[0.1.0]: https://github.com/jacek4yang/rust-xhttp/releases/tag/v0.1.0
[0.1.1]: https://github.com/jacek4yang/rust-xhttp/compare/v0.1.0...v0.1.1
[Unreleased]: https://github.com/jacek4yang/rust-xhttp/compare/v0.1.1...HEAD
