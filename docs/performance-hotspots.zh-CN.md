# 热点优化报告

[English](performance-hotspots.md) | 简体中文

本文记录 2026-08-14 的 profile-guided 优化，并把可重复的函数级证据与容易受主机
负载影响的端到端数字分开。

## 复现方法

先构建带符号的 release binary，再让 `perf` 只附加到临时启动的 rust-xhttp 子进程：

```bash
CARGO_PROFILE_RELEASE_DEBUG=1 \
CARGO_PROFILE_RELEASE_STRIP=false \
cargo build --release --locked

DURATION=15 CONCURRENCY=64 PAYLOAD_BYTES=4096 scripts/profile.sh
```

持续负载器逐字节验证每个 VLESS/XHTTP echo 响应。`profile.sh` 在已忽略的
`docs/profile/` 下写入 workload JSON、`perf.data` 和 flat top-symbol 报告。由于本机
`perf_event_paranoid` 禁止普通用户 attach，它使用
`sudo -n perf record --pid <rust-xhttp-pid>`；不会进行整机采样。

函数级 Criterion 测试：

```bash
cargo bench --bench geo -- --noplot
```

## 观测到的热点

最初 15 秒 raw XHTTP 采样的聚合热点包括 allocation/free、Hyper/Tokio 连接处理、
session 插入/删除、响应 padding 构造、query 解析与 timer wheel。短 HTTP/1.1 连接
天然以网络 syscall 为主，因此本轮针对可重复固定成本，不声称能消除这些 syscall。

本轮改动：

- XHTTP path 元数据直接借用 URI slice，不再分配两个 String，也不在分类时克隆
  session ID；
- padding 校验直接计算 decode 后字节长度，不构造 padding String；
- 响应 padding 保持 Xray 的均匀随机长度选择，普通范围的有效 `HeaderValue` 延迟
  缓存；
- 单 frame Hyper upload body 沿用原有 `Bytes`；只有 fragmented 或混合
  header/cookie/body placement 才做拼接；
- VLESS 用户快照改用 `ArcSwap`，服务端热路径 lookup 返回 `Arc<User>`，不再取得
  `RwLock` 并克隆 email/flow String；原有公开 owned lookup 接口保持兼容；
- IPv4/IPv6 target 直接以 `SocketAddr` connect，避免地址格式化和多余 resolver 路径；
- 新 session 只获取一次 shard lock，并在 download teardown 复用已计算的 session
  hash；
- 常见的 download-first 顺序不创建 grace task；upload-first timer 会在 download
  打开或 session 删除时立即 abort；
- Origin 与生产 Dispatcher task 共享单个外层 `Arc`，创建连接/session 时不再逐个
  clone 内部所有 `Arc` 字段。

## 函数级结果

在这台四核主机上，Criterion 得到以下同进程对比。reference 函数复现被替换的
allocation/locking 操作，因此基本排除了跨进程频率和后台负载偏差。

| 内核 | 优化后 | 被替换 reference | 变化 |
| --- | ---: | ---: | ---: |
| Path 提取与分类 | 62.7 ns | 103.2 ns | -39% |
| Request padding 提取与校验 | 149.3 ns | 383.7 ns | -61% |
| 随机响应 padding HeaderValue | 23.0 ns | 118.2 ns | -81% |
| VLESS 用户查找 | 73.2 ns | 90.3 ns | -19% |

在最终外层 `Arc` 优化之前，一组空闲窗口交替 A/B 显示 mean server CPU/op 降低
4.6%，workload 窗口 RSS 增长降低 81%。Python driver 已成为吞吐瓶颈，因此 median
throughput 只变化 0.4%，本文不把它当作容量结果。最终宏基准复测期间，共享主机上
无关的 release build 开始占用 CPU，所以该组结果已作废。

## 解释与后续工作

微基准支持这些局部固定成本改造，但不能替代 [Benchmark](benchmarks.zh-CN.md) 中的
官方 Xray 客户端对比。可发布的容量结论仍需要空闲并固定 CPU 的主机、至少五次
重复，以及双方完全相同的 TLS/encryption/client 模式。

剩余 flat sample 主要是 allocator、Hyper/Tokio poll、socket 建立，以及短 HTTP/1.1
连接产生的内核 TCP 工作。下一步应单独 profile 长连接官方 Xray HTTP/2 客户端；仅当
其中 allocation stack 仍明显时再评估 buffer reuse。不能只凭当前短连接负载引入
buffer pool，因为 pool contention 可能让真实 H2 路径退化。
