# Contributing

Thanks for helping improve `rust-xhttp`. Protocol changes should be grounded in
the official Xray-core wire behavior and should not introduce private extensions.

## Development

Use Rust 1.85 or newer. Fork the repository, create a focused branch, and run:

```bash
scripts/gate.sh
cargo deny check
bash scripts/m9_tls_h2_smoke.sh
```

Add tests for behavior changes, keep configuration examples and protocol notes in
sync, and avoid committing keys, certificates, runtime configs, benchmark output,
or anything under the ignored portions of `local/`.

## Pull requests

- Explain the user-visible behavior and compatibility impact.
- Link the relevant Xray-core source or protocol evidence when changing wire behavior.
- Call out security, memory-bound, or deployment implications.
- Keep commits reviewable; formatting, Clippy, tests, packaging, and dependency policy
  must pass in CI.

By contributing, you agree that your contribution is licensed under MPL-2.0.
