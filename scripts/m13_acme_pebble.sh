#!/usr/bin/env bash
# Local ACME integration: Pebble CA -> rust-xhttp HTTP-01 -> atomic cache -> TLS.
# Usage: scripts/m13_acme_pebble.sh /path/to/pebble/source
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEBBLE_SOURCE="${1:-}"
if [ -z "$PEBBLE_SOURCE" ] || [ ! -f "$PEBBLE_SOURCE/go.mod" ]; then
  echo "usage: $0 /path/to/pebble/source" >&2
  exit 2
fi

cd "$ROOT"
cargo build --quiet --bin rust-xhttp

ROOT="$ROOT" PEBBLE_SOURCE="$PEBBLE_SOURCE" python3 - <<'PY'
import json
import os
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = os.environ["ROOT"]
PEBBLE_SOURCE = os.environ["PEBBLE_SOURCE"]
USER = str(uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811"))
DOMAIN = "localtest.me"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


tmp = tempfile.TemporaryDirectory()
pebble_port = free_port()
management_port = free_port()
challenge_port = free_port()
tls_port = free_port()
pebble_bin = os.path.join(tmp.name, "pebble")
subprocess.run(
    ["go", "build", "-o", pebble_bin, "./cmd/pebble"],
    cwd=PEBBLE_SOURCE,
    check=True,
)

ca = os.path.join(PEBBLE_SOURCE, "test/certs/pebble.minica.pem")
pebble_config = os.path.join(tmp.name, "pebble.json")
with open(pebble_config, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "pebble": {
                "listenAddress": f"127.0.0.1:{pebble_port}",
                "managementListenAddress": f"127.0.0.1:{management_port}",
                "certificate": os.path.join(
                    PEBBLE_SOURCE, "test/certs/localhost/cert.pem"
                ),
                "privateKey": os.path.join(
                    PEBBLE_SOURCE, "test/certs/localhost/key.pem"
                ),
                "httpPort": challenge_port,
                "tlsPort": free_port(),
                "ocspResponderURL": "",
                "externalAccountBindingRequired": False,
                "domainBlocklist": [],
                "retryAfter": {"authz": 1, "order": 1},
                "keyAlgorithm": "ecdsa",
                "profiles": {
                    "default": {
                        "description": "integration",
                        "validityPeriod": 7776000,
                    }
                },
            }
        },
        handle,
    )

cache = os.path.join(tmp.name, "acme")
server_config = os.path.join(tmp.name, "rust-xhttp.json")
with open(server_config, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "log": {"loglevel": "warn"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": tls_port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": USER, "flow": ""}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "alpn": ["h2", "http/1.1"],
                            "acme": {
                                "domains": [DOMAIN],
                                "email": "integration@example.com",
                                "directoryUrl": f"https://localhost:{pebble_port}/dir",
                                "caCertificateFile": ca,
                                "challengeListen": f"[::]:{challenge_port}",
                                "cacheDir": cache,
                                "renewBeforeDays": 30,
                                "renewCheckHours": 12,
                                "acceptTerms": True,
                            },
                        },
                        "xhttpSettings": {
                            "path": "/xhttp/",
                            "host": DOMAIN,
                            "xPaddingBytes": "100",
                        },
                    },
                }
            ],
            "fallback": {
                "mode": "builtin",
                "site": {"seed": "acme", "title": "Pebble Journal"},
            },
        },
        handle,
    )

pebble = subprocess.Popen(
    [pebble_bin, "-config", pebble_config],
    cwd=PEBBLE_SOURCE,
    env={**os.environ, "PEBBLE_VA_NOSLEEP": "1"},
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
server = None
try:
    wait_port(pebble_port)
    issued_root = os.path.join(tmp.name, "issued-root.pem")
    with open(issued_root, "wb") as handle:
        subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--cacert",
                ca,
                f"https://localhost:{management_port}/roots/0",
            ],
            check=True,
            stdout=handle,
        )
    server = subprocess.Popen(
        [os.path.join(ROOT, "target/debug/rust-xhttp"), server_config],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_port(tls_port, timeout=30.0)
    result = subprocess.run(
        [
            "curl",
            "--noproxy",
            "*",
            "--cacert",
            issued_root,
            "--resolve",
            f"{DOMAIN}:{tls_port}:127.0.0.1",
            "--silent",
            "--show-error",
            "--fail",
            f"https://{DOMAIN}:{tls_port}/",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if "Pebble Journal" not in result.stdout:
        raise RuntimeError("issued TLS endpoint did not serve the configured site")
    current = os.path.join(cache, "current")
    if not os.path.islink(current):
        raise RuntimeError("ACME current pointer is not an atomic symlink")
    for name in ("certificate.pem", "private-key.pem"):
        if not os.path.isfile(os.path.join(current, name)):
            raise RuntimeError(f"missing ACME cache file {name}")
finally:
    for process in (server, pebble):
        if process is None:
            continue
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if server is not None and server.returncode not in (0, -15):
        print(server.stderr.read(), file=os.sys.stderr)
    if pebble.returncode not in (0, -15):
        print(pebble.stderr.read(), file=os.sys.stderr)
    tmp.cleanup()

print("RESULT: SUCCESS - Pebble HTTP-01 issuance and TLS activation passed")
PY
