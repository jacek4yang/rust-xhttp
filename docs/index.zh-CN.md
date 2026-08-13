# rust-xhttp 文档

[English](index.md) | 简体中文

建议从配置指南开始：它包含安装、服务端与官方 Xray 客户端配置、严格 JSON、
ACME/手动证书、网站 fallback、VLESS-Encryption、验证和排错。

## 运维指南

| 指南 | English | 简体中文 |
| --- | --- | --- |
| 项目概览 | [English](../README.md) | [简体中文](../README.zh-CN.md) |
| 配置与部署 | [English](configuration.md) | [简体中文](configuration.zh-CN.md) |
| Benchmark 与原始证据 | [English](benchmarks.md) | [简体中文](benchmarks.zh-CN.md) |
| 性能与可用性 | [English](performance-and-availability.md) | [简体中文](performance-and-availability.zh-CN.md) |
| 热点优化报告 | [English](performance-hotspots.md) | [简体中文](performance-hotspots.zh-CN.md) |
| 安全政策 | [English](../SECURITY.md) | [简体中文](../SECURITY.zh-CN.md) |

## 工程说明

- [协议说明](protocol-notes.md) — 当前支持的 XHTTP/VLESS 线协议范围。
- [TLS 保真度分析](tls-fidelity-analysis.md) — 内置 TLS 后端实现与非声明。
- [静态 fallback](static-fallback.md) — 非 XHTTP 请求的 nginx 风格 HTTP 表面。
- [TLS 会话恢复分析](session-resumption-analysis.md) — 明确的不发 ticket 策略。
- [安全审计说明](security-audit.md) — 已实现控制与待完成工作。
- [生产加固](production-hardening.md) — systemd、CPU 目标、socket 与内存。
- [项目指南](project-guide.md) — 贡献流程与模块图。
- [Geo 路由](geo-routing.md) — 当前不支持，为未来工作保留。

工程说明以记录证据和缺口为目的，刻意比宣传文案保守；生产部署前应阅读。
