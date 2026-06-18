#!/usr/bin/env bash
# Build rust-xhttp (optimized, x86_64) and deploy it to one or more remote
# hosts as a hardened systemd service. Idempotent: re-running upgrades the binary
# in place and restarts the service.
#
# Usage:
#   ops/deploy.sh <ssh-host> [<ssh-host> ...]
#
# Requirements on the REMOTE host (set up once, out of band):
#   - /root/xhttp/config.toml
# The script copies the freshly built binary and the systemd unit, (re)loads the
# unit, and enables + restarts the service. It does NOT touch your config or keys.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <ssh-host> [<ssh-host> ...]" >&2
  exit 2
fi

UNIT="ops/systemd/rust-xhttp.service"
REMOTE_DIR="/root/xhttp"
SERVICE="rust-xhttp"

echo "==> building release binary"
cargo build --release
BIN="target/release/$SERVICE"
test -x "$BIN"

TMP_GZ="$(mktemp --suffix=.gz)"
trap 'rm -f "$TMP_GZ"' EXIT
gzip -c "$BIN" > "$TMP_GZ"

for host in "$@"; do
  echo "==> deploying to $host"
  scp -q "$TMP_GZ" "$host:$REMOTE_DIR/$SERVICE.gz"
  scp -q "$UNIT" "$host:/etc/systemd/system/$SERVICE.service"
  ssh "$host" "SERVICE='$SERVICE' REMOTE_DIR='$REMOTE_DIR' bash -s" <<'REMOTE'
set -euo pipefail
cd "$REMOTE_DIR"
gunzip -c "$SERVICE.gz" > "$SERVICE.new"
rm -f "$SERVICE.gz"
[ -f "$SERVICE" ] && cp -f "$SERVICE" "$SERVICE.old" || true
mv -f "$SERVICE.new" "$SERVICE"
chmod +x "$SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" && echo "  [$(hostname)] active" || { echo "  [$(hostname)] FAILED"; journalctl -u "$SERVICE" -n 20 --no-pager; exit 1; }
ss -tlnH '( sport = :443 )' | grep -q . && echo "  [$(hostname)] listening on :443" || echo "  [$(hostname)] WARNING: not listening on :443"
REMOTE
done

echo "==> done. Tail logs with:  ssh <host> journalctl -u $SERVICE -f"
