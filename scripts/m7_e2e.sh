#!/usr/bin/env bash
# Local end-to-end XHTTP smoke test:
#   Python HTTP client -> rust-xhttp origin -> VLESS TCP -> local echo target
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build --quiet --bin rust-xhttp

ROOT="$ROOT" python3 - <<'PY'
import http.client
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = os.environ["ROOT"]
PAD = "X" * 100
SESSION = "m7-local-session"
USER = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")


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
    out.append(0)  # addons length
    out.append(1)  # TCP
    out.extend(target_port.to_bytes(2, "big"))
    out.append(1)  # IPv4
    out.extend(bytes([127, 0, 0, 1]))
    out.extend(payload)
    return bytes(out)


listen_port = free_port()
echo_port = free_port()
tmp = tempfile.TemporaryDirectory()
config_path = os.path.join(tmp.name, "config.toml")

with open(config_path, "w", encoding="utf-8") as f:
    f.write(f"""
[listen]
addr = "127.0.0.1:{listen_port}"

[xhttp]
path = "/xhttp/"
host = ""
padding_from = 100
padding_to = 1000
max_each_post_bytes = 1000000
max_buffered_posts = 30
session_grace_secs = 30
sse_header = true

[vless]
decryption = "none"

[[vless.users]]
id = "{USER}"
email = "m7-local"
flow = ""

[observability]
log = "warn"
""")

ready = threading.Event()
threading.Thread(target=echo_server, args=(echo_port, ready), daemon=True).start()
ready.wait(2.0)

server = subprocess.Popen(
    [os.path.join(ROOT, "target", "debug", "rust-xhttp"), config_path],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

try:
    wait_port(listen_port)
    result = {}

    def download():
        conn = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=10)
        conn.request(
            "GET",
            f"/xhttp/{SESSION}",
            headers={"Referer": f"https://example.test/?x_padding={PAD}"},
        )
        resp = conn.getresponse()
        result["status"] = resp.status
        result["download_x_padding_len"] = len(resp.getheader("X-Padding") or "")
        result["header"] = resp.read(2)
        result["payload"] = resp.read(4)
        conn.close()

    t = threading.Thread(target=download)
    t.start()
    time.sleep(0.2)

    body = vless_tcp_request(echo_port, b"ping")
    conn = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=10)
    conn.request(
        "POST",
        f"/xhttp/{SESSION}/0",
        body=body,
        headers={
            "Content-Length": str(len(body)),
            "Referer": f"https://example.test/?x_padding={PAD}",
        },
    )
    post = conn.getresponse()
    post_x_padding_len = len(post.getheader("X-Padding") or "")
    post_body = post.read()
    conn.close()
    if post.status != 200:
        raise RuntimeError(f"packet-up status {post.status}, body={post_body!r}")
    if not (100 <= post_x_padding_len <= 1000):
        raise RuntimeError(f"packet-up missing/invalid X-Padding length {post_x_padding_len}")

    t.join(10)
    if t.is_alive():
        raise RuntimeError("download did not complete")
    expected = {"status": 200, "header": b"\x00\x00", "payload": b"ping"}
    observed = {k: result.get(k) for k in expected}
    if observed != expected:
        raise RuntimeError(f"unexpected download result: {result!r}")
    if not (100 <= result["download_x_padding_len"] <= 1000):
        raise RuntimeError(
            f"download missing/invalid X-Padding length {result['download_x_padding_len']}"
        )
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
    tmp.cleanup()

print("RESULT: SUCCESS - local XHTTP packet-up/stream-down E2E passed")
PY
