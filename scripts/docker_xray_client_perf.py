#!/usr/bin/env python3
"""Docker-hosted official-Xray-client benchmark for rust-xhttp vs Xray-core.

The workload is:

    Python SOCKS5 client -> Xray-core client -> VLESS/XHTTP server candidate
    -> direct TCP target -> HTTP echo response

This exercises the official Xray XHTTP dialer and VLESS outbound instead of a
hand-written XHTTP client.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable


USER = uuid.UUID("b831381d-6324-4d53-ad4f-8cda48b30811")
HZ = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, name: str, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"{name} did not open port {port}")


def proc_cpu_seconds(pid: int) -> float:
    try:
        stat = open(f"/proc/{pid}/stat", "r", encoding="utf-8").read()
    except OSError:
        return 0.0
    fields = stat.rsplit(") ", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / HZ


def proc_rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def terminate(process: subprocess.Popen[str]) -> dict[str, str]:
    if process.poll() is None:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=4)
    else:
        stdout, stderr = process.communicate(timeout=1)
    return {"stdout": stdout[-4000:], "stderr": stderr[-4000:]}


class HttpEchoServer:
    def __init__(self) -> None:
        self.port = free_port()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.accepted = 0

    def start(self) -> "HttpEchoServer":
        self._thread.start()
        if not self._ready.wait(3.0):
            raise RuntimeError("HTTP echo server did not start")
        return self

    def close(self) -> None:
        self._stop.set()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))
            listener.listen(4096)
            self._ready.set()
            while not self._stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    continue
                self.accepted += 1
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                headers, rest = read_until(conn, b"\r\n\r\n", 65536)
                if not headers:
                    return
                match = re.search(br"\r\ncontent-length:\s*(\d+)\r\n", headers.lower())
                content_len = int(match.group(1)) if match else 0
                body = rest + read_exact(conn, content_len - len(rest))
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n"
                    + b"Content-Type: application/octet-stream\r\n\r\n"
                    + body
                )
                conn.sendall(response)
            except OSError:
                return


def read_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed before expected bytes")
        data.extend(chunk)
    return bytes(data)


def read_until(sock: socket.socket, marker: bytes, limit: int) -> tuple[bytes, bytes]:
    data = bytearray()
    while marker not in data:
        if len(data) >= limit:
            raise ValueError("read limit exceeded")
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    marker_pos = data.find(marker)
    if marker_pos < 0:
        return bytes(data), b""
    body_start = marker_pos + len(marker)
    return bytes(data[:body_start]), bytes(data[body_start:])


def socks5_connect(proxy_port: int, target_port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if read_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-auth negotiation failed")
        request = bytearray(b"\x05\x01\x00\x01")
        request.extend(bytes([127, 0, 0, 1]))
        request.extend(target_port.to_bytes(2, "big"))
        sock.sendall(request)
        response = read_exact(sock, 4)
        if response[0] != 5 or response[1] != 0:
            raise RuntimeError(f"SOCKS5 connect failed: {response!r}")
        atyp = response[3]
        if atyp == 1:
            read_exact(sock, 4)
        elif atyp == 3:
            read_exact(sock, read_exact(sock, 1)[0])
        elif atyp == 4:
            read_exact(sock, 16)
        else:
            raise RuntimeError(f"SOCKS5 bad address type {atyp}")
        read_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def http_post_via_socks(proxy_port: int, target_port: int, payload: bytes, timeout: float) -> float:
    started = time.perf_counter()
    with socks5_connect(proxy_port, target_port, timeout) as sock:
        sock.settimeout(timeout)
        request = (
            b"POST /echo HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            + f"Content-Length: {len(payload)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + payload
        )
        sock.sendall(request)
        headers, rest = read_until(sock, b"\r\n\r\n", 65536)
        if b" 200 " not in headers.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"HTTP target returned bad status: {headers[:80]!r}")
        match = re.search(br"\r\ncontent-length:\s*(\d+)\r\n", headers.lower())
        if not match:
            raise RuntimeError("HTTP target response has no Content-Length")
        content_len = int(match.group(1))
        body = rest + read_exact(sock, content_len - len(rest))
        if body != payload:
            raise RuntimeError(f"HTTP echo mismatch: got {len(body)} bytes")
    return time.perf_counter() - started


def write_rust_config(path: str, port: int, max_post: int, decryption: str) -> None:
    with open(path, "w", encoding="utf-8") as config:
        config.write(
            f"""
[listen]
addr = "127.0.0.1:{port}"
workers = 0
tcp_nodelay = true
reuse_port = true
backlog = 4096
tcp_keepalive_secs = 300

[xhttp]
path = "/xhttp/"
host = ""
padding_from = 100
padding_to = 1000
max_each_post_bytes = {max_post}
max_buffered_posts = 30
session_grace_secs = 30
sse_header = true

[vless]
decryption = "{decryption}"

[[vless.users]]
id = "{USER}"
email = "docker-xray-client"
flow = ""

[limits]
max_sessions = 65536
max_pending_packets_per_session = 30
max_pending_bytes_per_session = 16777216
max_sessions_per_user = 4096
global_buffer_bytes = 1073741824
max_concurrent_target_conns = 100000
session_idle_secs = 300
handshake_timeout_secs = 10
target_connect_secs = 10
udp_association_idle_secs = 60

[observability]
log = "warn"
"""
        )


def xhttp_settings(max_post: int) -> dict[str, object]:
    return {
        "path": "/xhttp/",
        "mode": "packet-up",
        "xPaddingBytes": "100-1000",
        "scMaxEachPostBytes": max_post,
        "scMinPostsIntervalMs": 1,
        "scMaxBufferedPosts": 30,
        "serverMaxHeaderBytes": 8192,
        "uplinkDataPlacement": "body",
    }


def write_xray_server_config(path: str, port: int, max_post: int, decryption: str) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "server-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": str(USER), "email": "docker-xray-client"}],
                    "decryption": decryption,
                },
                "streamSettings": {"network": "xhttp", "xhttpSettings": xhttp_settings(max_post)},
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
    }
    with open(path, "w", encoding="utf-8") as output:
        json.dump(config, output, indent=2)


def write_xray_client_config(
    path: str,
    socks_port: int,
    server_port: int,
    max_post: int,
    encryption: str,
) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": server_port,
                            "users": [{"id": str(USER), "encryption": encryption}],
                        }
                    ]
                },
                "streamSettings": {"network": "xhttp", "xhttpSettings": xhttp_settings(max_post)},
            }
        ],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
        },
    }
    with open(path, "w", encoding="utf-8") as output:
        json.dump(config, output, indent=2)


@dataclass
class ProcessPair:
    name: str
    server_port: int
    socks_port: int
    server: subprocess.Popen[str]
    client: subprocess.Popen[str]


def start_process(command: list[str], name: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    if name == "rust-xhttp-server":
        env.setdefault("RUST_LOG", os.getenv("RUST_LOG", "warn"))
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def start_pair(
    tmp: str,
    name: str,
    server_starter: Callable[[str, int, int, str], tuple[int, subprocess.Popen[str]]],
    xray_bin: str,
    max_post: int,
    decryption: str,
    encryption: str,
) -> ProcessPair:
    server_port, server = server_starter(tmp, max_post, 0, decryption)
    socks_port = free_port()
    client_config = os.path.join(tmp, f"{name}-client.json")
    write_xray_client_config(client_config, socks_port, server_port, max_post, encryption)
    client = start_process([xray_bin, "run", "-config", client_config], f"{name}-client")
    try:
        wait_port(socks_port, f"{name} xray client")
    except Exception as error:
        client_logs = terminate(client)
        server_logs = terminate(server)
        raise RuntimeError(
            f"{name} pair failed to start: {error}\n"
            f"client stdout:\n{client_logs['stdout']}\nclient stderr:\n{client_logs['stderr']}\n"
            f"server stdout:\n{server_logs['stdout']}\nserver stderr:\n{server_logs['stderr']}"
        ) from error
    return ProcessPair(name, server_port, socks_port, server, client)


def start_rust_server(
    tmp: str, max_post: int, _unused: int, decryption: str
) -> tuple[int, subprocess.Popen[str]]:
    port = free_port()
    config_path = os.path.join(tmp, "rust-server.toml")
    write_rust_config(config_path, port, max_post, decryption)
    process = start_process([os.environ["RUST_XHTTP_BIN"], config_path], "rust-xhttp-server")
    try:
        wait_port(port, "rust-xhttp server")
    except Exception as error:
        logs = terminate(process)
        raise RuntimeError(
            f"rust-xhttp server failed to open port {port}: {error}\n"
            f"stdout:\n{logs['stdout']}\nstderr:\n{logs['stderr']}"
        ) from error
    return port, process


def start_xray_server(
    tmp: str, max_post: int, _unused: int, decryption: str
) -> tuple[int, subprocess.Popen[str]]:
    port = free_port()
    config_path = os.path.join(tmp, "xray-server.json")
    write_xray_server_config(config_path, port, max_post, decryption)
    process = start_process([os.environ["XRAY_BIN"], "run", "-config", config_path], "xray-server")
    try:
        wait_port(port, "xray server")
    except Exception as error:
        logs = terminate(process)
        raise RuntimeError(
            f"xray server failed to open port {port}: {error}\n"
            f"stdout:\n{logs['stdout']}\nstderr:\n{logs['stderr']}"
        ) from error
    return port, process


def run_load(
    socks_port: int,
    target_port: int,
    payload: bytes,
    operations: int,
    concurrency: int,
    timeout: float,
) -> list[float]:
    latencies: list[float] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(http_post_via_socks, socks_port, target_port, payload, timeout)
            for _ in range(operations)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                latencies.append(future.result())
            except Exception as error:  # noqa: BLE001
                errors.append(str(error))
    if errors:
        raise RuntimeError("; ".join(errors[:5]))
    return latencies


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def stop_pair(pair: ProcessPair) -> dict[str, dict[str, str]]:
    return {"client": terminate(pair.client), "server": terminate(pair.server)}


def bench_pair(
    pair: ProcessPair,
    target_port: int,
    payload: bytes,
    warmup: int,
    operations: int,
    concurrency: int,
    timeout: float,
) -> dict[str, object]:
    try:
        if warmup:
            run_load(pair.socks_port, target_port, payload, warmup, min(warmup, concurrency), timeout)
        server_cpu_before = proc_cpu_seconds(pair.server.pid)
        client_cpu_before = proc_cpu_seconds(pair.client.pid)
        server_rss_before = proc_rss_kib(pair.server.pid)
        client_rss_before = proc_rss_kib(pair.client.pid)
        started = time.perf_counter()
        latencies = run_load(pair.socks_port, target_port, payload, operations, concurrency, timeout)
        wall = time.perf_counter() - started
        server_cpu = max(0.0, proc_cpu_seconds(pair.server.pid) - server_cpu_before)
        client_cpu = max(0.0, proc_cpu_seconds(pair.client.pid) - client_cpu_before)
        completed = len(latencies)
        return {
            "name": pair.name,
            "server_port": pair.server_port,
            "socks_port": pair.socks_port,
            "operations": completed,
            "concurrency": concurrency,
            "payload_bytes": len(payload),
            "wall_seconds": wall,
            "ops_per_second": completed / wall if wall > 0 else 0.0,
            "echo_payload_mib_per_second": (completed * len(payload) * 2 / wall / 1048576.0)
            if wall > 0
            else 0.0,
            "server_cpu_seconds": server_cpu,
            "server_cpu_ms_per_op": server_cpu * 1000.0 / completed if completed else 0.0,
            "client_cpu_seconds": client_cpu,
            "client_cpu_ms_per_op": client_cpu * 1000.0 / completed if completed else 0.0,
            "latency_ms": {
                "mean": statistics.fmean(latencies) * 1000.0 if latencies else 0.0,
                "p50": percentile(latencies, 50) * 1000.0,
                "p90": percentile(latencies, 90) * 1000.0,
                "p99": percentile(latencies, 99) * 1000.0,
                "max": max(latencies) * 1000.0 if latencies else 0.0,
            },
            "rss_kib": {
                "server_before": server_rss_before,
                "server_after": proc_rss_kib(pair.server.pid),
                "client_before": client_rss_before,
                "client_after": proc_rss_kib(pair.client.pid),
            },
        }
    except Exception as error:
        logs = stop_pair(pair)
        raise RuntimeError(
            f"{pair.name} benchmark failed: {error}\n"
            f"client stdout:\n{logs['client']['stdout']}\n"
            f"client stderr:\n{logs['client']['stderr']}\n"
            f"server stdout:\n{logs['server']['stdout']}\n"
            f"server stderr:\n{logs['server']['stderr']}"
        ) from error
    finally:
        if pair.client.poll() is None or pair.server.poll() is None:
            stop_pair(pair)


def parse_vlessenc(output: str) -> tuple[str, str]:
    decryption = re.search(r'"decryption":\s*"([^"]+)"', output)
    encryption = re.search(r'"encryption":\s*"([^"]+)"', output)
    if not decryption or not encryption:
        raise RuntimeError(f"failed to parse xray vlessenc output:\n{output}")
    return decryption.group(1), encryption.group(1)


def generated_encryption_pair(xray_bin: str) -> tuple[str, str]:
    output = subprocess.check_output([xray_bin, "vlessenc"], text=True)
    return parse_vlessenc(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-bin", default="/work/target/release/rust-xhttp")
    parser.add_argument("--xray-bin", default="/usr/local/bin/xray")
    parser.add_argument("--operations", type=int, default=int(os.getenv("OPS", "100")))
    parser.add_argument("--warmup", type=int, default=int(os.getenv("WARMUP", "10")))
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("CONCURRENCY", "8")))
    parser.add_argument("--payload-bytes", type=int, default=int(os.getenv("PAYLOAD_BYTES", "4096")))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("TIMEOUT", "20")))
    parser.add_argument(
        "--vless-encryption",
        action="store_true",
        default=os.getenv("VLESS_ENCRYPTION", "0") == "1",
    )
    args = parser.parse_args()

    if args.operations <= 0 or args.concurrency <= 0 or args.payload_bytes <= 0:
        raise SystemExit("operations, concurrency, and payload-bytes must be positive")
    if not os.path.exists(args.rust_bin):
        raise SystemExit(f"missing rust-xhttp binary: {args.rust_bin}")
    if not os.path.exists(args.xray_bin):
        raise SystemExit(f"missing xray binary: {args.xray_bin}")
    os.environ["RUST_XHTTP_BIN"] = args.rust_bin
    os.environ["XRAY_BIN"] = args.xray_bin

    decryption = "none"
    encryption = "none"
    if args.vless_encryption:
        decryption, encryption = generated_encryption_pair(args.xray_bin)

    max_post = args.payload_bytes + 4096
    payload = bytes((i % 251 for i in range(args.payload_bytes)))
    target = HttpEchoServer().start()
    with tempfile.TemporaryDirectory(prefix="rxhttp-xray-client-perf-") as tmp:
        try:
            rust_pair = start_pair(
                tmp,
                "rust-xhttp-server",
                start_rust_server,
                args.xray_bin,
                max_post,
                decryption,
                encryption,
            )
            rust_result = bench_pair(
                rust_pair,
                target.port,
                payload,
                args.warmup,
                args.operations,
                args.concurrency,
                args.timeout,
            )
            xray_pair = start_pair(
                tmp,
                "xray-core-server",
                start_xray_server,
                args.xray_bin,
                max_post,
                decryption,
                encryption,
            )
            xray_result = bench_pair(
                xray_pair,
                target.port,
                payload,
                args.warmup,
                args.operations,
                args.concurrency,
                args.timeout,
            )
        finally:
            target.close()

    comparison = {
        "ops_per_second_ratio_rust_over_xray": rust_result["ops_per_second"]
        / xray_result["ops_per_second"],
        "server_cpu_ms_per_op_ratio_rust_over_xray": rust_result["server_cpu_ms_per_op"]
        / xray_result["server_cpu_ms_per_op"]
        if xray_result["server_cpu_ms_per_op"]
        else 0.0,
        "p99_latency_ratio_rust_over_xray": rust_result["latency_ms"]["p99"]
        / xray_result["latency_ms"]["p99"]
        if xray_result["latency_ms"]["p99"]
        else 0.0,
    }
    report = {
        "workload": {
            "protocol": "official Xray client SOCKS -> VLESS/XHTTP packet-up -> server -> TCP HTTP echo",
            "vless_encryption": args.vless_encryption,
            "operations_per_candidate": args.operations,
            "warmup_operations_per_candidate": args.warmup,
            "concurrency": args.concurrency,
            "payload_bytes": args.payload_bytes,
            "echo_payload_accounting": "payload bytes counted once uplink and once downlink",
        },
        "environment": {
            "container": True,
            "network": "host",
            "python": os.sys.version.split()[0],
        },
        "results": [rust_result, xray_result],
        "comparison": comparison,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
