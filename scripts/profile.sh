#!/usr/bin/env bash
# Profile a sustained local rust-xhttp XHTTP workload with perf.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${OUTDIR:-$ROOT/docs/profile}"
mkdir -p "$OUTDIR"

if command -v perf >/dev/null 2>&1; then
  echo "recording perf for sustained local XHTTP traffic"
  python3 "$ROOT/scripts/hotspot_profile.py" \
    --rust-bin "$ROOT/target/release/rust-xhttp" \
    --duration "${DURATION:-10}" \
    --concurrency "${CONCURRENCY:-64}" \
    --payload-bytes "${PAYLOAD_BYTES:-4096}" \
    --perf-data "$OUTDIR/perf.data" | tee "$OUTDIR/workload.json"
  sudo -n perf report -i "$OUTDIR/perf.data" --stdio --no-children \
    --call-graph none --sort=overhead,symbol \
    2>/dev/null | grep -vE '^\s*#' | head -60 > "$OUTDIR/perf-top.txt" || true
  echo "perf data: $OUTDIR/perf.data"
  echo "top symbols: $OUTDIR/perf-top.txt"
else
  echo "perf not found; running sustained workload without sampling"
  python3 "$ROOT/scripts/hotspot_profile.py" \
    --rust-bin "$ROOT/target/release/rust-xhttp" \
    --duration "${DURATION:-10}" \
    --concurrency "${CONCURRENCY:-64}" \
    --payload-bytes "${PAYLOAD_BYTES:-4096}"
fi
