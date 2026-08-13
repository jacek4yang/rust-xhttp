#!/usr/bin/env bash
# Local XHTTP packet-up placement smoke:
#   header/cookie/auto payload placement -> rust-xhttp origin -> VLESS TCP echo
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build --quiet --bin rust-xhttp

ROOT="$ROOT" python3 - <<'PY'
import base64
import http.client
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = os.environ["ROOT"]
PAD = "X" * 100
USER = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
DATA_KEY = "X-Data"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


def echo_server(port, ready):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    with conn:
        data = conn.recv(4096)
        conn.sendall(data)
    srv.close()


def vless_tcp_request(target_port, payload):
    out = bytearray()
    out.append(0)
    out.extend(USER.bytes)
    out.append(0)
    out.append(1)
    out.extend(target_port.to_bytes(2, "big"))
    out.append(1)
    out.extend(bytes([127, 0, 0, 1]))
    out.extend(payload)
    return bytes(out)


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def start_origin(placement, listen_port):
    tmp = tempfile.TemporaryDirectory()
    config_path = os.path.join(tmp.name, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "log": {"loglevel": "warn"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": listen_port,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": str(USER),
                                    "email": "m10-local",
                                    "flow": "",
                                }
                            ],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "xhttp",
                            "security": "none",
                            "xhttpSettings": {
                                "path": "/xhttp/",
                                "xPaddingBytes": "100-1000",
                                "serverMaxHeaderBytes": 65536,
                                "uplinkDataPlacement": placement,
                                "uplinkDataKey": DATA_KEY,
                            },
                        },
                    }
                ],
            },
            f,
        )
    server = subprocess.Popen(
        [os.path.join(ROOT, "target", "debug", "rust-xhttp"), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_port(listen_port)
    return tmp, server


def stop_origin(tmp, server):
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
    tmp.cleanup()


def post_for_placement(port, session, placement, payload):
    headers = {"Referer": f"https://example.test/?x_padding={PAD}"}
    body = None
    if placement == "header":
        encoded = b64(payload)
        midpoint = max(1, len(encoded) // 2)
        headers[f"{DATA_KEY}-0"] = encoded[:midpoint]
        headers[f"{DATA_KEY}-1"] = encoded[midpoint:]
    elif placement == "cookie":
        encoded = b64(payload)
        midpoint = max(1, len(encoded) // 2)
        headers["Cookie"] = f"{DATA_KEY}_0={encoded[:midpoint]}; {DATA_KEY}_1={encoded[midpoint:]}"
    elif placement == "auto":
        a = len(payload) // 3
        b = (len(payload) * 2) // 3
        headers[f"{DATA_KEY}-0"] = b64(payload[:a])
        headers["Cookie"] = f"{DATA_KEY}_0={b64(payload[a:b])}"
        body = payload[b:]
        headers["Content-Length"] = str(len(body))
    else:
        raise RuntimeError(f"unsupported placement {placement}")

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", f"/xhttp/{session}/0", body=body, headers=headers)
    resp = conn.getresponse()
    x_padding_len = len(resp.getheader("X-Padding") or "")
    resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError(f"{placement}: POST status {resp.status}")
    if not (100 <= x_padding_len <= 1000):
        raise RuntimeError(f"{placement}: invalid X-Padding length {x_padding_len}")


def run_case(placement):
    listen_port = free_port()
    echo_port = free_port()
    ready = threading.Event()
    threading.Thread(target=echo_server, args=(echo_port, ready), daemon=True).start()
    ready.wait(2.0)

    tmp, server = start_origin(placement, listen_port)
    try:
        session = f"m10-{placement}"
        result = {}

        def download():
            conn = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=10)
            conn.request(
                "GET",
                f"/xhttp/{session}",
                headers={"Referer": f"https://example.test/?x_padding={PAD}"},
            )
            resp = conn.getresponse()
            result["status"] = resp.status
            result["header"] = resp.read(2)
            result["payload"] = resp.read(4)
            conn.close()

        t = threading.Thread(target=download)
        t.start()
        time.sleep(0.2)

        post_for_placement(
            listen_port,
            session,
            placement,
            vless_tcp_request(echo_port, b"ping"),
        )

        t.join(10)
        if t.is_alive():
            raise RuntimeError(f"{placement}: download did not complete")
        expected = {"status": 200, "header": b"\x00\x00", "payload": b"ping"}
        if result != expected:
            raise RuntimeError(f"{placement}: unexpected download result {result!r}")
    finally:
        stop_origin(tmp, server)


for placement in ("header", "cookie", "auto"):
    run_case(placement)

print("RESULT: SUCCESS - XHTTP header/cookie/auto packet-up placements passed")
PY
