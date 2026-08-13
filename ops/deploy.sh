#!/usr/bin/env bash
# Build and deploy both rust-xhttp binaries to one or more root SSH targets.
# Each target must already have /etc/rust-xhttp/config.json. The Rust manager
# validates that config, atomically installs the binaries, and manages systemd.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <ssh-host> [<ssh-host> ...]" >&2
  exit 2
fi

echo "==> building release binaries"
cargo build --locked --release --bins
test -x target/release/rust-xhttp
test -x target/release/rust-xhttpctl

local_stage=$(mktemp -d)
case "$local_stage" in
  /tmp/*) ;;
  *) echo "unexpected temporary directory: $local_stage" >&2; exit 1 ;;
esac
trap 'rm -r -- "$local_stage"' EXIT
gzip -c target/release/rust-xhttp > "$local_stage/rust-xhttp.gz"
gzip -c target/release/rust-xhttpctl > "$local_stage/rust-xhttpctl.gz"

for host in "$@"; do
  remote_stage="/tmp/rust-xhttp-deploy-$$"
  echo "==> deploying to $host"
  ssh "$host" "install -d -m 700 '$remote_stage'"
  scp -q "$local_stage/rust-xhttp.gz" "$local_stage/rust-xhttpctl.gz" \
    "$host:$remote_stage/"
  ssh "$host" "REMOTE_STAGE='$remote_stage' bash -s" <<'REMOTE'
set -euo pipefail
case "$REMOTE_STAGE" in
  /tmp/rust-xhttp-deploy-[0-9]*) ;;
  *) echo "unsafe remote staging path" >&2; exit 1 ;;
esac
cleanup() { rm -r -- "$REMOTE_STAGE"; }
trap cleanup EXIT
gzip -d "$REMOTE_STAGE/rust-xhttp.gz"
gzip -d "$REMOTE_STAGE/rust-xhttpctl.gz"
chmod 755 "$REMOTE_STAGE/rust-xhttp" "$REMOTE_STAGE/rust-xhttpctl"
test -f /etc/rust-xhttp/config.json
"$REMOTE_STAGE/rust-xhttpctl" install \
  --server-binary "$REMOTE_STAGE/rust-xhttp" \
  --ctl-binary "$REMOTE_STAGE/rust-xhttpctl" \
  --config /etc/rust-xhttp/config.json --yes
systemctl is-active --quiet rust-xhttp
echo "  [$(hostname)] active"
REMOTE
done

echo "==> done. Follow logs with: ssh <host> rust-xhttpctl logs"
