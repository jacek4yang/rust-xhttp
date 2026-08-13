# XHTTP stream pressure harness

This directory keeps the same management slot as `rust-reality`'s fallback
harness, but the measured path is different because `rust-xhttp` does not have a
REALITY fallback splice.

- `flood.py <host> <port> <N> [hold_secs]` opens `N` HTTP stream-down requests
  against `XHTTP_PATH` (default `/xhttp/`) with valid padding and holds the
  sockets open.
- `pressure.sh <server-binary> <config.json> <N> [nofile]` starts the server,
  runs the flood, reports FD/socket/RSS/thread counts, and checks that `/healthz`
  still responds.

The config should use a plaintext local listener for this harness. If your XHTTP
base path is not `/xhttp/`, set `XHTTP_PATH=/yourpath/`.
