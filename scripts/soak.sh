#!/usr/bin/env bash
# Repeated local XHTTP E2E smoke test. Env: SOAK_RUNS (default 5).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${SOAK_RUNS:-5}"
for i in $(seq 1 "$RUNS"); do
  echo "=== soak iteration $i/$RUNS ==="
  "$ROOT/scripts/m7_e2e.sh"
done
