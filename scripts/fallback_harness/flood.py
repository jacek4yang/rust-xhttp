#!/usr/bin/env python3
"""Open N XHTTP stream-down requests and hold them.

Usage: flood.py <host> <port> <N> [hold_secs]
Env:   XHTTP_PATH=/xhttp/
"""

import os
import socket
import sys
import time

HOST, PORT, N = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
HOLD = float(sys.argv[4]) if len(sys.argv) > 4 else 120.0
BASE = os.environ.get("XHTTP_PATH", "/xhttp/")
if not BASE.startswith("/"):
    BASE = "/" + BASE
if not BASE.endswith("/"):
    BASE += "/"
PAD = "X" * 100

socks = []
ok = 0
for i in range(N):
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        req = (
            f"GET {BASE}pressure-{i} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Referer: https://example.test/?x_padding={PAD}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode()
        s.sendall(req)
        socks.append(s)
        ok += 1
    except OSError:
        pass

print(f"FLOOD_CONNECTED={ok}/{N}", flush=True)
time.sleep(HOLD)
