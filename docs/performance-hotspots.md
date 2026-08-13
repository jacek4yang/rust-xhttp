# Hotspot Optimization Report

English | [简体中文](performance-hotspots.zh-CN.md)

This report records the 2026-08-14 profile-guided optimization pass. It separates
repeatable function-level evidence from end-to-end measurements that are sensitive to
host load.

## Reproduction

Build a release binary with symbols, then attach `perf` only to the temporary
rust-xhttp child process:

```bash
CARGO_PROFILE_RELEASE_DEBUG=1 \
CARGO_PROFILE_RELEASE_STRIP=false \
cargo build --release --locked

DURATION=15 CONCURRENCY=64 PAYLOAD_BYTES=4096 scripts/profile.sh
```

The sustained driver verifies every VLESS/XHTTP echo response. `profile.sh` writes
ignored local artifacts under `docs/profile/`: workload JSON, `perf.data`, and a flat
top-symbol report. It uses `sudo -n perf record --pid <rust-xhttp-pid>` because this
host's `perf_event_paranoid` setting blocks unprivileged attachment; it never samples
the entire host.

Run the focused Criterion suite with:

```bash
cargo bench --bench geo -- --noplot
```

## Observed hotspots

The initial 15-second raw XHTTP sample attributed substantial aggregate cost to
allocation/free, Hyper/Tokio connection processing, session insertion/removal, response
padding construction, query parsing, and timer-wheel work. Network syscalls dominate
short HTTP/1.1 connections, so the application changes target repeated fixed costs rather
than claiming those syscalls can be removed.

The pass made these changes:

- XHTTP path metadata now borrows URI slices instead of allocating two strings and
  cloning the session ID during classification.
- Padding validation counts decoded bytes without constructing the padding string.
- Response padding keeps Xray's random uniform length selection but lazily caches valid
  `HeaderValue` instances for ordinary ranges.
- A single-frame Hyper upload body is forwarded as its existing `Bytes`; only fragmented
  or mixed header/cookie/body placement needs concatenation.
- VLESS user snapshots use `ArcSwap`; the server hot-path lookup returns `Arc<User>` without
  taking an `RwLock` or cloning email/flow strings, while the original public owned lookup
  remains compatible.
- IPv4/IPv6 targets connect directly as `SocketAddr`, avoiding address formatting and a
  redundant resolver path.
- New sessions acquire their shard once rather than using a redundant double-checked
  lock. The precomputed session hash is reused during download teardown.
- The normal download-first request order creates no grace task. Upload-first grace tasks
  are aborted immediately after the download opens or the session is removed.
- Origin and production Dispatcher tasks share one outer `Arc`; connection/session
  creation no longer clones every Arc-backed field separately.

## Focused results

On this four-core host, Criterion reported the following same-process comparisons. The
reference functions reproduce the replaced allocating/locking operations, which avoids
cross-run frequency and background-load bias.

| Kernel | Optimized | Replaced reference | Change |
| --- | ---: | ---: | ---: |
| Path extraction + classification | 62.7 ns | 103.2 ns | -39% |
| Request padding extraction + validation | 149.3 ns | 383.7 ns | -61% |
| Random response padding HeaderValue | 23.0 ns | 118.2 ns | -81% |
| VLESS user lookup | 73.2 ns | 90.3 ns | -19% |

An idle-window alternating A/B run made before the final outer-Arc reduction showed a
4.6% lower mean server CPU/op and an 81% reduction in workload-window RSS growth. The
Python driver was already the throughput bottleneck, so median throughput moved only
0.4%; this is not presented as a capacity result. The final macro rerun was rejected
because an unrelated release build began consuming the shared host during measurement.

## Interpretation and next work

The microbenchmarks support the local fixed-cost changes; they do not replace the
official Xray-client comparison in [Benchmarks](benchmarks.md). A publishable capacity
result still requires an otherwise idle pinned host, at least five repetitions, and the
same TLS/encryption/client mode for both candidates.

The remaining flat sample is dominated by allocator, Hyper/Tokio polling, socket setup,
and kernel TCP work from deliberately short HTTP/1.1 sessions. The next useful pass
should profile a long-lived official Xray HTTP/2 client separately, then evaluate buffer
reuse only if allocation stacks remain material there. A pool should not be introduced
solely from this short-connection workload because pool contention can regress the real
H2 path.
