# Benchmark Report

Current benchmark management mirrors `rust-reality`: `benches/kernels.rs`,
`benches/geo.rs`, and `scripts/bench.sh` are the canonical local entry points.

Run:

```bash
scripts/bench.sh
```

The script runs:

```bash
cargo bench --bench kernels --bench geo
```

and writes a short report to `docs/benchmark-latest.md`, with full Criterion
output under `local/artifacts/`.

The current benches cover XUDP frame encoding, plain UDP datagram encoding, and
XHTTP path/host classification.

For a deeper end-to-end comparison against Xray-core, run:

```bash
scripts/m11_docker_xray_perf.sh
```

That script builds `rust-xhttp` in release mode, starts a Docker container with
host networking, mounts the local `xray` binary, and drives the same VLESS over
XHTTP packet-up/stream-down TCP echo workload against both servers. It reports
ops/sec, payload MiB/sec, latency percentiles, server CPU seconds, CPU ms/op,
and RSS for each candidate, with JSON output under `local/artifacts/`.

For official-client coverage, run:

```bash
scripts/m12_docker_xray_client_perf.sh
VLESS_ENCRYPTION=1 scripts/m12_docker_xray_client_perf.sh
```

`m12` starts an Xray-core SOCKS client for each candidate and drives HTTP echo
traffic through that client, so the measured path includes Xray's VLESS outbound
and XHTTP dialer. The optional `VLESS_ENCRYPTION=1` mode generates a fresh
`xray vlessenc` pair and verifies the same workload with VLESS-Encryption
enabled on both the Xray client and the server candidate.

The runtime now binds the listener through the Linux socket tuning layer
(`SO_REUSEADDR`, optional `SO_REUSEPORT`, configured backlog) and applies
`TCP_NODELAY` plus optional kernel keepalive to accepted client sockets and TCP
targets. Throughput/latency benchmarks should record these `[listen]` values
alongside CPU model, kernel, `ulimit -n`, and CDN/proxy placement.
