#!/usr/bin/env bash
# Profile the local rust-xhttp E2E smoke with perf when available.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${OUTDIR:-$ROOT/docs/profile}"
DURATION_NOTE="m7 local XHTTP E2E"
mkdir -p "$OUTDIR"

if command -v perf >/dev/null 2>&1; then
  echo "recording perf for: $DURATION_NOTE"
  perf record -g -o "$OUTDIR/perf.data" -- "$ROOT/scripts/m7_e2e.sh"
  perf report -i "$OUTDIR/perf.data" --stdio 2>/dev/null | grep -vE '^\s*#' | head -40 > "$OUTDIR/perf-top.txt" || true
  echo "perf data: $OUTDIR/perf.data"
  echo "top symbols: $OUTDIR/perf-top.txt"
else
  echo "perf not found; running local E2E without sampling"
  "$ROOT/scripts/m7_e2e.sh"
fi
