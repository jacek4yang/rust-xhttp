#!/usr/bin/env bash
# gate.sh — run the project quality gate:
#   fmt · clippy · test
#
# Exits non-zero on the first failure. Live Xray interop is implementation
# specific and is not included until the xhttp harness is present.
#
# Usage:
#   scripts/gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n\033[1;34m=== %s ===\033[0m\n' "$1"; }

step "fmt"
cargo fmt --check

step "clippy"
cargo clippy --all-targets -- -D warnings

step "test"
cargo test --quiet -- --test-threads=1

printf '\n\033[1;32mGATE PASSED\033[0m\n'
