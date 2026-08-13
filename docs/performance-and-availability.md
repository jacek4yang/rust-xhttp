# Performance and Availability

[English](performance-and-availability.md) · [简体中文](performance-and-availability.zh-CN.md)

This note explains the current hot path, resource model, failure behavior, and
measurement limits. It complements the committed Xray comparison in
[Benchmarks](benchmarks.md).
The sampling method, allocation changes, and current microbenchmark evidence are
recorded in the [hotspot optimization report](performance-hotspots.md).

## Hot-path design

- Tokio uses one worker per available CPU by default; workloads are async and
  connection tasks never deliberately block on filesystem operations.
- The fallback site is fully read and validated at startup. Responses clone
  reference-counted `Bytes`; MIME, ETag, Last-Modified, and route aliases are
  precomputed. Conditional GETs return 304 without reading a file.
- The session table is sharded, and counters are relaxed atomics. Target
  concurrency uses a semaphore rather than unbounded task creation.
- Request path/session metadata is borrowed from parsed HTTP values. Single-frame
  body uploads remain reference-counted `Bytes`, response padding is lazily cached,
  and user-table reads use `ArcSwap` rather than a read lock.
- Download-created sessions skip orphan grace timers entirely; timers created for
  upload-first sessions are cancelled as soon as the download opens or the session
  ends. This prevents completed sessions from retaining timer tasks for the full TTL.
- Packet reorder queues and per-session/global byte budgets reserve capacity
  before accepting payload memory. Oversized work fails early.
- TCP_NODELAY, keepalive, a 4096 listen backlog, and `SO_REUSEPORT` are enabled
  by default on supported Linux hosts.
- TLS uses per-connection traffic keys; certificate renewal swaps only the
  immutable signing identity through `ArcSwap`, so new handshakes do not take a
  global read lock.

## Resource accounting

The largest explicit allocations are:

```text
resident upper region ≈ runtime/TLS overhead
                      + fallback.maxTotalBytes
                      + limits.globalBufferBytes
                      + per-session/per-connection state
```

`globalBufferBytes` is a hard shared budget for accepted XHTTP upload buffers,
not a promise that total RSS will equal that number. Each connection, Hyper H2
state, encryption state, target socket, task, and allocator also costs memory.
Keep the systemd `MemoryHigh` above normal peak usage and `MemoryMax` above the
sum with failure headroom. The supplied unit uses 1.5/2 GiB with a 1 GiB default
protocol buffer budget and a 128 MiB site limit.

`maxSessions` and `maxConcurrentTargetConns` also need to fit the process file
descriptor limit. A proxied session can consume multiple sockets and HTTP
streams, so do not set either equal to `LimitNOFILE` and assume it is safe.

## Overload and shutdown behavior

- Header/body/site size limits return or produce explicit early errors.
- Exhausted session, target, and global buffer budgets fail closed instead of
  accepting unbounded memory.
- TLS and VLESS handshakes, DNS/target connection, UDP idle state, and orphaned
  XHTTP sessions have independent deadlines.
- Transient `accept(2)` pressure (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) uses a
  250 ms backoff instead of terminating the process.
- SIGINT/SIGTERM stops accepting new traffic, waits up to
  `gracefulShutdownSeconds`, then aborts remaining connection tasks. systemd's
  stop deadline is set slightly above the application deadline.
- ACME failure never replaces a currently loaded identity. Renewal retries are
  capped at six hours. Startup fails if no usable certificate can be obtained
  within five minutes.

## Current measured evidence

The committed 2026-06-19 loopback runs show:

- Raw server c64: 1,568 vs 1,558 ops/s (1.006× Xray), 0.47× server CPU/op.
- Official Xray client c32: 3,306 vs 2,593 ops/s (1.28×), 0.42× CPU/op.
- Official client plus VLESS Encryption c32: 3,147 vs 2,588 ops/s (1.22×),
  0.53× CPU/op.

The [raw JSON and charts](benchmarks.md) are committed. These results predate
the JSON/ACME/site changes. Those changes are off the authenticated data path
after startup, but a new controlled comparison is still required before
claiming that the exact release build retains identical numbers.

No new throughput result was collected on 2026-08-13 because the shared
four-core host was already running an unrelated sustained benchmark at high
load. Publishing numbers from that environment would be misleading. Protocol
compatibility tests were still run because they assert correctness rather than
capacity.

## Production measurement checklist

Run the official-client harness on an otherwise idle, pinned machine:

```bash
cargo build --release --locked
bash scripts/m12_docker_xray_client_perf.sh \
  --operations 5000 --concurrency 32 --payload-bytes 4096
```

For a credible result, record CPU model/governor, kernel, Rust and Xray
versions, binary hashes, container limits, TLS topology, warm-up, at least five
independent repetitions, median and dispersion, p50/p95/p99, CPU/op, peak RSS,
errors, and exact config. Compare equal protocol/security modes and verify every
payload. Do not mix CDN/public-network latency into a server implementation
benchmark.

## Operational recommendations

1. Begin with defaults; reduce `globalBufferBytes` on small machines.
2. Raise `LimitNOFILE`, kernel socket queues, and memory limits together—not one
   in isolation.
3. Watch p99, error rate, CPU saturation, RSS, open FDs, session rejections,
   target-connect failures, and ACME renewal logs.
4. Load-test the real `dist` size and TLS mode before production.
5. Use multiple instances behind a load balancer for host-level availability;
   live XHTTP sessions are process-local and should not be migrated midstream.
