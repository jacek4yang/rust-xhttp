#!/usr/bin/env bash
# Docker-hosted official-Xray-client benchmark.
#
# Env:
#   IMAGE=python:3.13-slim
#   XRAY_BIN=/usr/bin/xray
#   OPS=100
#   WARMUP=10
#   CONCURRENCY=8
#   PAYLOAD_BYTES=4096
#   VLESS_ENCRYPTION=0
#   RUST_LOG=warn
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-python:3.13-slim}"
XRAY_BIN="${XRAY_BIN:-$(command -v xray)}"
OPS="${OPS:-100}"
WARMUP="${WARMUP:-10}"
CONCURRENCY="${CONCURRENCY:-8}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-4096}"
VLESS_ENCRYPTION="${VLESS_ENCRYPTION:-0}"

if [ -z "$XRAY_BIN" ] || [ ! -x "$XRAY_BIN" ]; then
  echo "missing executable xray binary; set XRAY_BIN=/path/to/xray" >&2
  exit 1
fi

cargo build --release --quiet --bin rust-xhttp
mkdir -p "$ROOT/local/artifacts"
OUT="$ROOT/local/artifacts/docker-xray-client-perf-$(date -u +%Y%m%dT%H%M%SZ).json"

docker run --rm --network host \
  -e "OPS=$OPS" \
  -e "WARMUP=$WARMUP" \
  -e "CONCURRENCY=$CONCURRENCY" \
  -e "PAYLOAD_BYTES=$PAYLOAD_BYTES" \
  -e "VLESS_ENCRYPTION=$VLESS_ENCRYPTION" \
  -e "RUST_LOG=${RUST_LOG:-warn}" \
  -v "$ROOT:/work:ro" \
  -v "$XRAY_BIN:/usr/local/bin/xray:ro" \
  -w /work \
  "$IMAGE" \
  python3 /work/scripts/docker_xray_client_perf.py \
  | tee "$OUT"

echo
echo "RESULT: SUCCESS - docker official-Xray-client performance comparison written to $OUT"
