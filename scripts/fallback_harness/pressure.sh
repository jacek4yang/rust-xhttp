#!/usr/bin/env bash
# XHTTP stream pressure harness.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -lt 3 ]; then
  echo "usage: pressure.sh <server-binary> <config.toml> <flood-N> [nofile]" >&2
  exit 2
fi

BIN="$1"
CONFIG="$2"
N="$3"
NOFILE="${4:-0}"
PORT="$(sed -n 's/^[[:space:]]*addr[[:space:]]*=[[:space:]]*"127\.0\.0\.1:\([0-9][0-9]*\)".*/\1/p' "$CONFIG" | head -n1)"
if [ -z "$PORT" ]; then
  echo "config must contain listen addr = \"127.0.0.1:<port>\"" >&2
  exit 2
fi

measure() {
  local p=$1
  [ -d "/proc/$p" ] || { echo "  (pid $p gone)"; return; }
  echo "  fds=$(ls /proc/$p/fd 2>/dev/null | wc -l) sockets=$(ls -l /proc/$p/fd 2>/dev/null | grep -c socket) rss_kb=$(awk '/VmRSS/{print $2}' /proc/$p/status) threads=$(awk '/Threads/{print $2}' /proc/$p/status)"
}

wait_port() {
  local port=$1
  for _ in $(seq 1 100); do
    (exec 9<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 9>&-; return 0; }
    sleep 0.05
  done
  return 1
}

if [ "$NOFILE" != "0" ]; then
  bash -c "ulimit -n $NOFILE; exec '$BIN' '$CONFIG'" >/tmp/xh_pressure_server.log 2>&1 & SRV=$!
else
  "$BIN" "$CONFIG" >/tmp/xh_pressure_server.log 2>&1 & SRV=$!
fi
FLOOD=""
trap 'kill ${SRV:-} ${FLOOD:-} 2>/dev/null || true' EXIT

wait_port "$PORT"
echo "server pid=$SRV port=$PORT nofile=${NOFILE:-default}"
echo "baseline:"; measure "$SRV"

python3 "$HERE/flood.py" 127.0.0.1 "$PORT" "$N" 120 >/tmp/xh_pressure_flood.log 2>&1 & FLOOD=$!
sleep 3
echo "after flood of $N (held):"; cat /tmp/xh_pressure_flood.log; measure "$SRV"

python3 - "$PORT" <<'PY'
import http.client
import sys

port = int(sys.argv[1])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("GET", "/healthz")
resp = conn.getresponse()
body = resp.read()
conn.close()
print(f"fresh healthz: status={resp.status} body={body!r}")
if resp.status != 200:
    raise SystemExit(1)
PY
