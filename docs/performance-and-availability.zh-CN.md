# 性能与可用性分析

[English](performance-and-availability.md) · [简体中文](performance-and-availability.zh-CN.md)

本文说明当前热路径、资源模型、故障行为和测量边界；Xray 对比原始证据见
[Benchmark](benchmarks.zh-CN.md)。
采样方法、分配优化和当前微基准证据见[热点优化报告](performance-hotspots.zh-CN.md)。

## 热路径设计

- Tokio 默认每个可用 CPU 一个 worker；任务采用异步 I/O，连接任务不会主动执行
  文件系统阻塞操作；
- fallback 网站在启动时完整读取并验证。响应只克隆引用计数 `Bytes`，MIME、ETag、
  Last-Modified 和路由别名预先计算；条件 GET 无需读盘即可返回 304；
- session table 分片，计数器使用 relaxed atomic；目标并发通过 semaphore 限制，
  不会无限创建任务；
- request path/session 元数据直接借用已解析的 HTTP 值；单 frame body upload 保持为
  引用计数 `Bytes`，响应 padding 延迟缓存，用户表读取通过 `ArcSwap` 避免读锁；
- download 先到达时完全不创建孤立 session grace timer；upload 先到达时创建的 timer
  会在 download 打开或 session 结束时取消，已完成 session 不再滞留整个 TTL；
- packet 乱序队列和单 session/全局字节预算在接受 payload 内存前预留容量；
- 默认启用 TCP_NODELAY、keepalive、4096 listen backlog，以及受支持 Linux 上的
  `SO_REUSEPORT`；
- TLS 每连接使用独立 traffic key；证书续期只通过 `ArcSwap` 原子替换不可变签名
  identity，新握手不需要全局读锁。

## 资源核算

最大的显式内存区域可粗略写成：

```text
常驻上界区域 ≈ runtime/TLS 开销
             + fallback.maxTotalBytes
             + limits.globalBufferBytes
             + 单 session/单连接状态
```

`globalBufferBytes` 是已接受 XHTTP upload buffer 的硬共享预算，并不代表总 RSS 就
等于这个数字。每条连接、Hyper H2 状态、加密状态、目标 socket、task 和 allocator
都要额外占用内存。systemd 的 `MemoryHigh` 应高于正常峰值，`MemoryMax` 应在总和
之上留出故障余量。仓库 unit 在默认 1 GiB 协议 buffer 和 128 MiB 网站限制下使用
1.5/2 GiB。

`maxSessions` 与 `maxConcurrentTargetConns` 也必须符合文件描述符上限。一个代理
session 可能占多个 socket 与 HTTP stream，不能简单把它们都设为 `LimitNOFILE`。

## 过载与关闭行为

- header、body 与网站大小限制会尽早返回明确错误；
- session、目标连接或全局 buffer 耗尽时 fail closed，不接受无界内存；
- TLS/VLESS 握手、DNS/目标连接、UDP 空闲与孤立 XHTTP session 都有独立期限；
- `accept(2)` 瞬时压力（`EMFILE`、`ENFILE`、`ENOBUFS`、`ENOMEM`）会退避 250 ms，
  而不是让进程退出；
- SIGINT/SIGTERM 停止接受新连接，在 `gracefulShutdownSeconds` 内排空，随后中止
  剩余连接 task；systemd 停止期限略长于应用期限；
- ACME 失败不会替换已加载 identity。续期重试间隔上限为六小时；若启动时没有可用
  证书，五分钟内仍无法签发则启动失败。

## 当前测量证据

已提交的 2026-06-19 loopback 数据：

- Raw server c64：1,568 vs 1,558 ops/s（Xray 的 1.006×），CPU/op 为 0.47×；
- 官方 Xray 客户端 c32：3,306 vs 2,593 ops/s（1.28×），CPU/op 为 0.42×；
- 官方客户端 + VLESS Encryption c32：3,147 vs 2,588 ops/s（1.22×），CPU/op 为
  0.53×。

[原始 JSON 与图表](benchmarks.zh-CN.md)均已提交。这些测量早于 JSON/ACME/网站
改造。启动完成后，这些变化不位于认证数据热路径，但仍需对最终 release build 做
新的受控比较，才能声称数值完全保持。

2026-08-13 没有新增吞吐数字，因为共享的四核主机当时正运行无关的持续高负载
benchmark；在这种环境发布数字会产生误导。协议兼容测试仍然执行，因为它们验证
正确性而非容量。

## 正式测量清单

在空闲且固定 CPU 的机器运行官方客户端 harness：

```bash
cargo build --release --locked
bash scripts/m12_docker_xray_client_perf.sh \
  --operations 5000 --concurrency 32 --payload-bytes 4096
```

可信结果应记录 CPU 型号/governor、kernel、Rust/Xray 版本、binary hash、容器限制、
TLS 拓扑、预热、至少五次独立重复、median 和离散度、p50/p95/p99、CPU/op、peak
RSS、错误与完整配置。必须比较相同协议/安全模式并逐字节校验 payload；不要把 CDN
或公网延迟混入服务端实现 benchmark。

## 生产建议

1. 先使用默认值；小内存机器应降低 `globalBufferBytes`；
2. `LimitNOFILE`、内核 socket queue 和内存限制必须一起调整；
3. 监控 p99、错误率、CPU 饱和、RSS、打开 FD、session 拒绝、目标连接失败与 ACME
   续期日志；
4. 上线前用实际 `dist` 大小和 TLS 模式做压力测试；
5. 主机级高可用需要负载均衡后的多实例；活跃 XHTTP session 属于单进程状态，不应
   中途迁移。
