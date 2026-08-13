#!/usr/bin/env bash
# Docker-hosted rust-xhttp vs Xray-core XHTTP/VLESS performance comparison.
#
# Env:
#   IMAGE=python:3.13-slim
#   XRAY_BIN=/usr/bin/xray
#   OPS=200
#   WARMUP=20
#   CONCURRENCY=8
#   PAYLOAD_BYTES=4096
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-python:3.13-slim}"
XRAY_BIN="${XRAY_BIN:-$(command -v xray)}"
OPS="${OPS:-200}"
WARMUP="${WARMUP:-20}"
CONCURRENCY="${CONCURRENCY:-8}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-4096}"

if [ -z "$XRAY_BIN" ] || [ ! -x "$XRAY_BIN" ]; then
  echo "missing executable xray binary; set XRAY_BIN=/path/to/xray" >&2
  exit 1
fi

cargo build --release --quiet --bin rust-xhttp
mkdir -p "$ROOT/local/artifacts"
OUT="$ROOT/local/artifacts/docker-xray-perf-$(date -u +%Y%m%dT%H%M%SZ).json"

docker run --rm --network host \
  -e "OPS=$OPS" \
  -e "WARMUP=$WARMUP" \
  -e "CONCURRENCY=$CONCURRENCY" \
  -e "PAYLOAD_BYTES=$PAYLOAD_BYTES" \
  -v "$ROOT:/work:ro" \
  -v "$XRAY_BIN:/usr/local/bin/xray:ro" \
  -w /work \
  "$IMAGE" \
  python3 /work/scripts/docker_xray_perf.py \
  | tee "$OUT"

echo
echo "RESULT: SUCCESS - docker rust-xhttp vs xray-core performance comparison written to $OUT"
