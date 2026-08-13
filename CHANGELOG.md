# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-14

### Added

- Added the separate Rust `rust-xhttpctl` interactive installer and lifecycle
  manager for systemd installation, status/log access, diagnosis, transactional
  config editing, repair, update, rollback, and preserve-or-purge uninstall.
- Added a version-pinned one-command bootstrap that verifies the GitHub Release
  SHA-256 before starting the Rust wizard.
- Added bilingual installation and long-term management documentation plus an
  alternate-root installer smoke test in the required quality gate.

### Changed

- Run managed deployments as a dedicated non-login user with stable `/etc`,
  `/usr/local/bin`, and `/var/lib` paths instead of a root-owned working tree.
- Package both the daemon and manager, the pinned bootstrap, configuration
  examples, and bilingual documentation in every Linux release archive.

### Security

- Hardened the canonical systemd unit with config preflight, a read-only system,
  home/device isolation, restricted address families, and only
  `CAP_NET_BIND_SERVICE`.
- Online updates enforce HTTPS-only redirects, validated tags/archive paths,
  matching binary versions, published SHA-256 verification, config preflight,
  atomic replacement, and automatic failed-activation rollback.

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
[0.2.0]: https://github.com/jacek4yang/rust-xhttp/compare/v0.1.1...v0.2.0
[Unreleased]: https://github.com/jacek4yang/rust-xhttp/compare/v0.2.0...HEAD
