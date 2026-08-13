# 安全政策

[English](SECURITY.md) | 简体中文

## 支持版本

只有最新的 `0.1.x` 版本接收安全修复。报告问题前，请先升级到最新补丁版本。

## 报告漏洞

疑似漏洞不得提交为公开 Issue。请在
[`jacek4yang/rust-xhttp`](https://github.com/jacek4yang/rust-xhttp/security/advisories/new)
仓库使用 GitHub 私密安全公告流程：**Security → Advisories → Report a vulnerability**。

报告应包含受影响版本、部署模式、复现步骤、影响和可能的缓解方式。请给维护者合理
时间确认问题并协调披露。报告中绝不能包含生产凭据、私钥、真实 UUID、用户流量或
未脱敏抓包。

本项目尚未经过独立安全审计。在高风险环境使用直连 TLS 后端前，请阅读
[`docs/security-audit.md`](docs/security-audit.md) 与
[`docs/tls-fidelity-analysis.md`](docs/tls-fidelity-analysis.md)。如果部署者要求已经
成熟审计的 TLS 终止边界，应使用 nginx/Cloudflare 终止 TLS，并让 rust-xhttp 仅在
受信任回源网络监听。
