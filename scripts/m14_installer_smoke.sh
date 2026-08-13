#!/usr/bin/env bash
# Exercise the real Rust installer against an alternate root. No host users,
# /etc files, services, or sockets are touched.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --quiet --locked --bins
stage_root=$(mktemp -d -p /tmp rust-xhttp-installer-smoke.XXXXXX)
case "$stage_root" in
  /tmp/rust-xhttp-installer-smoke.*) ;;
  *) echo "unsafe staging path: $stage_root" >&2; exit 1 ;;
esac
cleanup() { rm -r -- "$stage_root"; }
trap cleanup EXIT

target/debug/rust-xhttpctl install \
  --root "$stage_root" --no-start --yes \
  --config config.acme.example.json \
  --server-binary target/debug/rust-xhttp \
  --ctl-binary target/debug/rust-xhttpctl >/dev/null

test -x "$stage_root/usr/local/bin/rust-xhttp"
test -x "$stage_root/usr/local/bin/rust-xhttpctl"
test -f "$stage_root/etc/rust-xhttp/config.json"
test -f "$stage_root/etc/systemd/system/rust-xhttp.service"
grep -q '^User=rust-xhttp$' "$stage_root/etc/systemd/system/rust-xhttp.service"
grep -q '^ExecStartPre=/usr/local/bin/rust-xhttp check ' \
  "$stage_root/etc/systemd/system/rust-xhttp.service"
"$stage_root/usr/local/bin/rust-xhttp" \
  check "$stage_root/etc/rust-xhttp/config.json" >/dev/null
"$stage_root/usr/local/bin/rust-xhttpctl" --version | grep -q '^rust-xhttpctl '

echo "managed installer staging smoke test passed"
