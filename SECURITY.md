# Security Policy

English | [简体中文](SECURITY.zh-CN.md)

## Supported versions

Only the latest `0.1.x` release receives security fixes. Users should upgrade to
the newest patch release before reporting an issue.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory flow: **Security → Advisories → Report a vulnerability** in
the [`jacek4yang/rust-xhttp`](https://github.com/jacek4yang/rust-xhttp/security/advisories/new)
repository.

Include the affected version, deployment mode, reproduction steps, impact, and
any suggested mitigation. Please allow a reasonable period for confirmation and
coordinated disclosure. Never include production credentials, private keys, or
user traffic in a report.

This project has not received an independent security audit. Review
[`docs/security-audit.md`](docs/security-audit.md) and
[`docs/tls-fidelity-analysis.md`](docs/tls-fidelity-analysis.md) before using the
direct TLS backend in a high-risk deployment.
