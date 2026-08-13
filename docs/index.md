# rust-xhttp Documentation

English | [简体中文](index.zh-CN.md)

Start with the configuration guide: it covers installation, server and official
Xray-client configuration, strict JSON fields, ACME/manual TLS, website fallback,
VLESS-Encryption, verification, and troubleshooting.

For the one-command systemd wizard and ongoing updates, rollback, repair, and
uninstall, use the [installation and management guide](installation-management.md).

## Operator guides

| Guide | English | 简体中文 |
| --- | --- | --- |
| Project overview | [English](../README.md) | [简体中文](../README.zh-CN.md) |
| Configuration and deployment | [English](configuration.md) | [简体中文](configuration.zh-CN.md) |
| Installation and management | [English](installation-management.md) | [简体中文](installation-management.zh-CN.md) |
| Benchmarks and raw evidence | [English](benchmarks.md) | [简体中文](benchmarks.zh-CN.md) |
| Performance and availability | [English](performance-and-availability.md) | [简体中文](performance-and-availability.zh-CN.md) |
| Hotspot optimization report | [English](performance-hotspots.md) | [简体中文](performance-hotspots.zh-CN.md) |
| Security policy | [English](../SECURITY.md) | [简体中文](../SECURITY.zh-CN.md) |

## Engineering notes

- [Protocol notes](protocol-notes.md) — supported XHTTP/VLESS wire scope.
- [TLS fidelity analysis](tls-fidelity-analysis.md) — what the in-tree TLS backend
  does and does not claim.
- [Static fallback](static-fallback.md) — nginx-shaped non-XHTTP HTTP surface.
- [Session resumption analysis](session-resumption-analysis.md) — explicit no-ticket policy.
- [Security audit notes](security-audit.md) — implemented controls and open work.
- [Production hardening](production-hardening.md) — systemd, CPU target, sockets, and memory.
- [Installation and management](installation-management.md) — wizard and lifecycle operations.
- [Project guide](project-guide.md) — contributor workflow and module map.
- [Geo routing](geo-routing.md) — currently unsupported and reserved for future work.

The engineering notes record current evidence and gaps. They are deliberately more
conservative than marketing copy and should be read before production deployment.
