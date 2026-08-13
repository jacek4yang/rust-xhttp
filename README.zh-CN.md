# rust-xhttp

[![CI](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/rust-xhttp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jacek4yang/rust-xhttp)](https://github.com/jacek4yang/rust-xhttp/releases/latest)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)

[English](README.md) | 简体中文

`rust-xhttp` 是一个纯 Rust 服务端，与官方 Xray-core 客户端的 XHTTP 协议栈
线协议兼容：不需要修改客户端，不引入私有线格式，也不宣传所谓“零指纹”。实现行为
以 `local/references/Xray-core` 下的本地 Xray 源码为依据。

服务端协议栈：

```text
XHTTP (packet-up) + VLESS + VLESS-Encryption + xtls-rprx-vision + XUDP
```

> [!IMPORTANT]
> 这是 1.0 之前的安全敏感网络软件，尚未经过独立安全审计。内置 TLS 1.3 后端
> 已与 OpenSSL 客户端互操作，但不声称与 nginx/OpenSSL 的指纹完全等价；详见
> [`docs/tls-fidelity-analysis.md`](docs/tls-fidelity-analysis.md)。

同一个线协议支持三种部署方式，通过 Xray 风格 JSON 的
`streamSettings.security` 与监听地址选择：

- **直连** — `Xray 客户端 → Rust（内置 TLS 1.3 / H2）`
- **Cloudflare** — `Xray 客户端 → Cloudflare → Rust（H2 回源）`
- **nginx 前置** — 仅支持 `packet-up`（HTTP/1.1 回源）；不支持长上行模式。

## 性能快照

已提交的 v0.1.0 证据在同一台 loopback 主机上，以逐字节校验的 TCP echo 负载
对比 Xray-core。在官方 Xray 客户端 c32 场景中，rust-xhttp 完成操作数为
1.22–1.28 倍，服务端单操作 CPU 为 0.42–0.53 倍；底层 raw-server c64 场景
吞吐基本持平（1.006 倍），服务端单操作 CPU 为 0.47 倍。

| 工作负载 | rust-xhttp ops/s | Xray-core ops/s | Rust/Xray | Rust CPU / Xray CPU |
| --- | ---: | ---: | ---: | ---: |
| Raw server，c64 | 1,568 | 1,558 | 1.006× | 0.47× |
| 官方 Xray 客户端，c32 | 3,306 | 2,593 | **1.28×** | **0.42×** |
| 官方客户端 + VLESS-Encryption，c32 | 3,147 | 2,588 | **1.22×** | **0.53×** |

![rust-xhttp 与 Xray-core 每秒操作数对比](docs/assets/performance-ops-v0.1.0.svg)

这些是探索性的单机受控测量，不是公网速度保证。p99/CPU 图、限制、原始 JSON
证据和完整复现命令见双语 benchmark 指南：[English](docs/benchmarks.md) |
[简体中文](docs/benchmarks.zh-CN.md)。

## 代码结构

| 路径 | 职责 |
| --- | --- |
| `src/main.rs`, `src/runtime.rs` | 入口与协议栈装配 |
| `src/config.rs` | 严格 Xray 风格 JSON、校验与安全默认值 |
| `src/acme.rs` | HTTP-01 签发、续期退避与证书原子激活 |
| `src/origin.rs` | 内置 TLS 1.3/H2、HTTP/1.1 与 h2c 的 hyper 源站 |
| `src/xhttp/` | XHTTP 请求分类、padding 与 packet-up/stream-down |
| `src/session/` | 分片会话表、有界乱序重排与 grace TTL |
| `src/dispatcher.rs` | VLESS TCP/UDP/XUDP 目标连接与有界双向泵 |
| `src/tls/` | 自包含 TLS 1.3 与 nginx-profile shaping |
| `src/vless/` | VLESS、Vision 与 VLESS-Encryption |
| `src/xudp.rs` | XUDP 与普通 VLESS-UDP 编解码 |
| `src/site.rs` | 自动生成博客或预加载用户 `dist` 网站 |

## 构建、安装与运行

需要 Rust 1.88+（edition 2024，确保使用已修复安全问题的 `time` 依赖）。官方 Linux 发布包使用 `x86-64-v3`，要求
Haswell/Zen 或更新 CPU；旧 CPU 请参考
[`docs/production-hardening.md`](docs/production-hardening.md) 从源码构建。

```bash
git clone https://github.com/jacek4yang/rust-xhttp.git
cd rust-xhttp
cargo build --locked --release

cp config.acme.example.json config.json
# 修改 UUID、域名、路径和邮箱
./target/release/rust-xhttp check config.json
sudo ./target/release/rust-xhttp config.json
```

也可以从 [GitHub Releases](https://github.com/jacek4yang/rust-xhttp/releases/latest)
下载 `x86_64-unknown-linux-gnu` 压缩包。配置沿用 Xray 的
`inbounds/settings/streamSettings/xhttpSettings` 结构。直连 TLS 可选用户 PEM 或
内置 ACME HTTP-01 自动签发/续期；普通访问默认显示可定制的美观博客，也能预加载
用户 `dist` 目录。日志由 `log.loglevel` 或 `RUST_LOG` 控制。完整教学见
[配置指南](docs/configuration.zh-CN.md)与
[性能/可用性分析](docs/performance-and-availability.zh-CN.md)。

## 支持范围与非声明

本项目不是通用 Xray-core 替代品，只实现官方 `packet-up` XHTTP 服务端及其承载的
VLESS 协议。不支持 stream-up/stream-one，也不声称“不可检测”或“零指纹”。尚未
完成的项目以证据形式记录在 `docs/`，不会包装成已完成功能。

## 文档

| 指南 | English | 简体中文 |
| --- | --- | --- |
| 文档索引 | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| 配置与部署 | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| Benchmark 与证据 | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| 性能与可用性 | [English](docs/performance-and-availability.md) | [简体中文](docs/performance-and-availability.zh-CN.md) |
| 安全政策 | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |

## 许可证

MPL-2.0。本项目按规范洁净实现了部分 MPL-2.0 Xray-core 包的行为，包括
`proxy/vless`、`transport/internet/splithttp` 与 `common/xudp`。安全问题请按
[`SECURITY.zh-CN.md`](SECURITY.zh-CN.md) 私密报告；贡献方式见
[`CONTRIBUTING.md`](CONTRIBUTING.md)。
