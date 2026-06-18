#!/usr/bin/env bash
# CPU-focused local microbenchmarks for rust-xhttp.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo bench --bench kernels
