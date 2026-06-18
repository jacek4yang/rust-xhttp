#!/usr/bin/env bash
# Thin wrapper around tls_record_lens.py for local TLS capture inspection.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$#" -lt 2 ]; then
  cat >&2 <<'MSG'
usage: scripts/pcap_diff.sh <capture.pcap> <server-port> [server-ip]

Prints the server-to-client TLS record lengths from a classic pcap capture.
MSG
  exit 2
fi

PCAP="$1"
PORT="$2"
IP="${3:-}"
if [ -n "$IP" ]; then
  "$ROOT/scripts/tls_record_lens.py" "$PCAP" --server-port "$PORT" --server-ip "$IP"
else
  "$ROOT/scripts/tls_record_lens.py" "$PCAP" --server-port "$PORT"
fi
