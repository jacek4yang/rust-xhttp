#!/usr/bin/env bash
# Local TLS/H2 origin smoke:
#   curl --http2 -> rust-xhttp TLS origin
#
# This approximates the Cloudflare-to-origin leg that uses HTTPS with ALPN.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build --quiet --bin rust-xhttp

ROOT="$ROOT" python3 - <<'PY'
import os
import json
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = os.environ["ROOT"]
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


listen_port = free_port()
tmp = tempfile.TemporaryDirectory()
cert = os.path.join(tmp.name, "server.crt")
key = os.path.join(tmp.name, "server.key")
config_path = os.path.join(tmp.name, "config.json")

subprocess.run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=example.test",
        "-addext",
        "subjectAltName=DNS:example.test,IP:127.0.0.1",
        "-keyout",
        key,
        "-out",
        cert,
    ],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

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
                            {"id": str(USER), "email": "m9-local", "flow": ""}
                        ],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "alpn": ["h2", "http/1.1"],
                            "certificates": [
                                {"certificateFile": cert, "keyFile": key}
                            ],
                        },
                        "xhttpSettings": {
                            "path": "/xhttp/",
                            "host": "example.test",
                            "xPaddingBytes": "100",
                        },
                    },
                }
            ],
            "fallback": {
                "mode": "builtin",
                "site": {"seed": "m9", "title": "Harbor Journal"},
            },
        },
        f,
    )

wrong_key = os.path.join(tmp.name, "wrong-server.key")
subprocess.run(
    ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", wrong_key],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
with open(config_path, encoding="utf-8") as f:
    mismatched = json.load(f)
mismatched["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"] = wrong_key
mismatched_path = os.path.join(tmp.name, "mismatched.json")
with open(mismatched_path, "w", encoding="utf-8") as f:
    json.dump(mismatched, f)
checked = subprocess.run(
    [os.path.join(ROOT, "target", "debug", "rust-xhttp"), "check", mismatched_path],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if checked.returncode == 0 or "do not match" not in checked.stderr:
    raise RuntimeError(f"mismatched certificate/key was not rejected: {checked.stderr}")

server = subprocess.Popen(
    [os.path.join(ROOT, "target", "debug", "rust-xhttp"), config_path],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

try:
    wait_port(listen_port)
    base = f"https://example.test:{listen_port}"
    resolve = f"example.test:{listen_port}:127.0.0.1"

    index = subprocess.run(
        [
            "curl",
            "--noproxy",
            "*",
            "--http2",
            "-k",
            "-sS",
            "--resolve",
            resolve,
            "-D",
            "-",
            "-o",
            "-",
            "-w",
            "\nCURL_HTTP_VERSION=%{http_version}\n",
            f"{base}/",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    if "CURL_HTTP_VERSION=2" not in index:
        raise RuntimeError(f"did not negotiate HTTP/2:\n{index}")
    if "server: nginx" not in index.lower() or "Harbor Journal" not in index:
        raise RuntimeError(f"static fallback shape mismatch:\n{index}")
    if "x-padding:" in index.lower():
        raise RuntimeError(f"static fallback leaked XHTTP padding:\n{index}")

    options = subprocess.run(
        [
            "curl",
            "--noproxy",
            "*",
            "--http2",
            "-k",
            "-sS",
            "--resolve",
            resolve,
            "-X",
            "OPTIONS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            f"{base}/xhttp/session/0",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    if "HTTP/2 200" not in options:
        raise RuntimeError(f"XHTTP OPTIONS failed:\n{options}")
    if f"x-padding: {'x' * 100}" not in options.lower():
        raise RuntimeError(f"XHTTP OPTIONS missing response padding:\n{options}")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
    tmp.cleanup()

print("RESULT: SUCCESS - local TLS/H2 origin smoke passed")
PY
