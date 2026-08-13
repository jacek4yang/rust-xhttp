# Benchmarks and Xray-core Comparison

English | [简体中文](benchmarks.zh-CN.md)

This page distinguishes committed evidence from claims. All selected v0.1.0
results are byte-verified, same-host loopback comparisons using the same workload
for both server candidates. They are useful implementation measurements, not
Internet speed guarantees or a substitute for testing on the deployment host.

## v0.1.0 evidence snapshot

| Workload | Metric | rust-xhttp | Xray-core | Rust/Xray |
| --- | --- | ---: | ---: | ---: |
| Raw server, c64, 5,000 ops, 4 KiB | ops/s | 1,567.84 | 1,558.39 | **1.006×** |
| | p99 latency | 63.45 ms | 60.47 ms | 1.049× |
| | server CPU/op | 0.246 ms | 0.528 ms | **0.466×** |
| | final server RSS | 27.2 MiB | 110.3 MiB | 0.246× |
| Official Xray client, c32, 1,000 ops, 4 KiB | ops/s | 3,305.59 | 2,592.52 | **1.275×** |
| | p99 latency | 20.75 ms | 46.57 ms | **0.446×** |
| | server CPU/op | 0.220 ms | 0.530 ms | **0.415×** |
| | final server RSS | 27.5 MiB | 139.7 MiB | 0.197× |
| Official client + VLESS-Encryption, c32, 1,000 ops, 4 KiB | ops/s | 3,147.01 | 2,587.61 | **1.216×** |
| | p99 latency | 27.19 ms | 36.89 ms | **0.737×** |
| | server CPU/op | 0.340 ms | 0.640 ms | **0.531×** |
| | final server RSS | 29.3 MiB | 154.8 MiB | 0.189× |

“Raw server” uses the repository's direct HTTP/VLESS harness. “Official Xray
client” puts an unmodified Xray SOCKS client in front of each server candidate,
so client-side XHTTP behavior is identical and only the server changes.

![Operations per second comparison](assets/performance-ops-v0.1.0.svg)

![p99 latency comparison](assets/performance-p99-v0.1.0.svg)

![Server CPU cost comparison](assets/performance-cpu-v0.1.0.svg)

Higher is better only for operations per second; lower is better for latency and
CPU cost. The chart generator uses only Python's standard library:

```bash
python3 scripts/render_benchmark_charts.py
git diff --exit-code -- docs/assets/
```

## Evidence files

The chart inputs are committed unchanged from the local harness output:

- [Raw server c64 JSON](../benchmarks/v0.1.0/raw-server-c64.json)
- [Official client c32 JSON](../benchmarks/v0.1.0/official-client-c32.json)
- [Official client + encryption c32 JSON](../benchmarks/v0.1.0/official-client-encryption-c32.json)

Each JSON file records workload size, concurrency, completed operations, wall
time, latency distribution, process CPU, RSS, protocol topology, and comparison
ratios. Ephemeral local ports in the evidence are not part of the result.

## Method and limitations

- Each operation creates one XHTTP session, sends a VLESS TCP request to a local
  echo/HTTP origin, and verifies the exact response payload.
- Payload MiB/s counts payload once uplink and once downlink. `ops/s` is the more
  useful metric for these short 4 KiB session-setup workloads.
- CPU is read from process accounting before and after the measured window; very
  short windows quantize heavily, which is why only the longer c32/c64 runs are
  highlighted.
- RSS is a point-in-time process reading, not peak or allocator-resident memory.
- The selected files are single benchmark runs dated 2026-06-19. Their embedded
  environment records container host networking and Python 3.13.13, but does not
  preserve exact CPU, kernel, Xray version/commit, binary SHA, thermal state, or
  repeated-sample dispersion.
- The host is currently also used for other development work. The project does
  not present these snapshots as publication-grade capacity numbers; a future
  release should replace them with isolated repeated samples and complete identity
  metadata.

The conservative conclusion is therefore narrow: in these recorded runs,
rust-xhttp was throughput-neutral with lower measured server CPU in the raw c64
path, and faster with lower measured CPU in both official-client c32 paths.

## Reproduce

Requirements: Docker, a local executable official `xray` binary, Linux host
networking, Python 3, and a release build-capable Rust toolchain.

Raw VLESS-over-XHTTP server comparison:

```bash
XRAY_BIN=/path/to/xray \
OPS=5000 WARMUP=200 CONCURRENCY=64 PAYLOAD_BYTES=4096 \
bash scripts/m11_docker_xray_perf.sh
```

Official Xray client in front of both server candidates:

```bash
XRAY_BIN=/path/to/xray \
OPS=1000 WARMUP=100 CONCURRENCY=32 PAYLOAD_BYTES=4096 \
bash scripts/m12_docker_xray_client_perf.sh
```

The same official-client comparison with a freshly generated matched
VLESS-Encryption pair:

```bash
XRAY_BIN=/path/to/xray VLESS_ENCRYPTION=1 \
OPS=1000 WARMUP=100 CONCURRENCY=32 PAYLOAD_BYTES=4096 \
bash scripts/m12_docker_xray_client_perf.sh
```

New reports are written under ignored `local/artifacts/`. Before publishing a
replacement result, run at least five interleaved samples per cell, record both
binary hashes and source commits, pin the Xray version, capture CPU/kernel/memory
and power policy, verify zero failures, and commit the raw evidence with the chart.

## Microbenchmarks

The Criterion suite measures XHTTP classification and XUDP/UDP framing kernels:

```bash
scripts/bench.sh
```

Criterion output is useful for detecting local regressions but is not directly
comparable to Xray-core's end-to-end server process.
