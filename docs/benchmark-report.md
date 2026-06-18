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
XHTTP path/host classification. End-to-end Xray-core A/B benchmarks are not yet
implemented for the XHTTP transport.
