#!/usr/bin/env python3
"""Docker-hosted rust-xhttp vs Xray-core XHTTP/VLESS benchmark harness.

This script is intended to be run inside a Docker container with host
networking. It starts both servers as child processes, drives the same raw
XHTTP packet-up / stream-down VLESS TCP echo workload against each, and prints a
JSON report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import os
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
PAD = "X" * 100
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
    utime = int(fields[11])
    stime = int(fields[12])
    return (utime + stime) / HZ


def proc_rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


class EchoServer:
    def __init__(self, expected_len: int) -> None:
        self.expected_len = expected_len
        self.port = free_port()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.accepted = 0

    def start(self) -> "EchoServer":
        self._thread.start()
        if not self._ready.wait(3.0):
            raise RuntimeError("echo server did not start")
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
            data = bytearray()
            while len(data) < self.expected_len:
                chunk = conn.recv(min(65536, self.expected_len - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if data:
                conn.sendall(data)


def vless_tcp_request(target_port: int, payload: bytes) -> bytes:
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


def write_rust_config(path: str, port: int, max_post: int) -> None:
    with open(path, "w", encoding="utf-8") as config:
        json.dump(
            {
                "log": {"loglevel": "warn"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": port,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": str(USER),
                                    "email": "docker-perf",
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
                                "scMaxEachPostBytes": max_post,
                                "scMaxBufferedPosts": 30,
                            },
                        },
                    }
                ],
                "server": {
                    "workers": 0,
                    "tcpNodelay": True,
                    "reusePort": True,
                    "backlog": 4096,
                    "tcpKeepaliveSeconds": 300,
                },
            },
            config,
        )


def write_xray_config(path: str, port: int, max_post: int) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "bench-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": str(USER), "email": "docker-perf"}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {
                        "path": "/xhttp/",
                        "mode": "packet-up",
                        "xPaddingBytes": "100-1000",
                        "scMaxEachPostBytes": max_post,
                        "scMaxBufferedPosts": 30,
                        "serverMaxHeaderBytes": 8192,
                        "uplinkDataPlacement": "body",
                    },
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["bench-in"],
                    "outboundTag": "direct",
                }
            ]
        },
    }
    with open(path, "w", encoding="utf-8") as output:
        json.dump(config, output, indent=2)


@dataclass
class Candidate:
    name: str
    port: int
    process: subprocess.Popen[str]


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


def start_rust(tmp: str, rust_bin: str, max_post: int) -> Candidate:
    port = free_port()
    config_path = os.path.join(tmp, "rust.json")
    write_rust_config(config_path, port, max_post)
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "warn")
    process = subprocess.Popen(
        [rust_bin, config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        wait_port(port, "rust-xhttp")
    except Exception as error:
        logs = terminate(process)
        raise RuntimeError(
            f"rust-xhttp failed to open port {port}: {error}\n"
            f"stdout:\n{logs['stdout']}\nstderr:\n{logs['stderr']}"
        ) from error
    return Candidate("rust-xhttp", port, process)


def start_xray(tmp: str, xray_bin: str, max_post: int) -> Candidate:
    port = free_port()
    config_path = os.path.join(tmp, "xray.json")
    write_xray_config(config_path, port, max_post)
    process = subprocess.Popen(
        [xray_bin, "run", "-config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_port(port, "xray-core")
    except Exception as error:
        logs = terminate(process)
        raise RuntimeError(
            f"xray-core failed to open port {port}: {error}\n"
            f"stdout:\n{logs['stdout']}\nstderr:\n{logs['stderr']}"
        ) from error
    return Candidate("xray-core", port, process)


def roundtrip(port: int, target_port: int, payload: bytes, op_id: int, timeout: float) -> float:
    session = f"bench-{op_id}-{time.time_ns()}"
    result: dict[str, object] = {}
    headers_ready = threading.Event()

    def download() -> None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request(
                "GET",
                f"/xhttp/{session}",
                headers={"Referer": f"https://example.test/?x_padding={PAD}"},
            )
            resp = conn.getresponse()
            result["download_status"] = resp.status
            headers_ready.set()
            result["vless_header"] = resp.read(2)
            result["payload"] = resp.read(len(payload))
        finally:
            conn.close()

    started = time.perf_counter()
    thread = threading.Thread(target=download)
    thread.start()
    if not headers_ready.wait(timeout):
        raise RuntimeError("download response headers were not received")

    body = vless_tcp_request(target_port, payload)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(
            "POST",
            f"/xhttp/{session}/0",
            body=body,
            headers={
                "Content-Length": str(len(body)),
                "Referer": f"https://example.test/?x_padding={PAD}",
            },
        )
        post = conn.getresponse()
        post_body = post.read()
        if post.status != 200:
            raise RuntimeError(f"packet-up status {post.status}, body={post_body!r}")
    finally:
        conn.close()

    thread.join(timeout)
    if thread.is_alive():
        raise RuntimeError("download did not complete")
    if result.get("download_status") != 200:
        raise RuntimeError(f"download status {result.get('download_status')}")
    if result.get("vless_header") != b"\x00\x00":
        raise RuntimeError(f"bad VLESS response header {result.get('vless_header')!r}")
    if result.get("payload") != payload:
        got = result.get("payload")
        raise RuntimeError(f"payload mismatch: got {len(got or b'')} bytes")
    return time.perf_counter() - started


def run_load(
    candidate: Candidate,
    echo_port: int,
    payload: bytes,
    operations: int,
    concurrency: int,
    timeout: float,
    first_op_id: int,
) -> list[float]:
    latencies: list[float] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(roundtrip, candidate.port, echo_port, payload, first_op_id + i, timeout)
            for i in range(operations)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                latencies.append(future.result())
            except Exception as error:  # noqa: BLE001 - report all benchmark failures
                errors.append(str(error))
    if errors:
        raise RuntimeError("; ".join(errors[:5]))
    return latencies


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def bench_candidate(
    starter: Callable[[str, int], Candidate],
    tmp: str,
    max_post: int,
    echo_port: int,
    payload: bytes,
    warmup: int,
    operations: int,
    concurrency: int,
    timeout: float,
    first_op_id: int,
) -> dict[str, object]:
    candidate = starter(tmp, max_post)
    logs: dict[str, str] = {}
    try:
        if warmup:
            run_load(candidate, echo_port, payload, warmup, min(concurrency, warmup), timeout, first_op_id)
        cpu_before = proc_cpu_seconds(candidate.process.pid)
        rss_before = proc_rss_kib(candidate.process.pid)
        wall_start = time.perf_counter()
        latencies = run_load(
            candidate,
            echo_port,
            payload,
            operations,
            concurrency,
            timeout,
            first_op_id + warmup,
        )
        wall = time.perf_counter() - wall_start
        cpu_after = proc_cpu_seconds(candidate.process.pid)
        rss_after = proc_rss_kib(candidate.process.pid)
        completed = len(latencies)
        cpu_seconds = max(0.0, cpu_after - cpu_before)
        return {
            "name": candidate.name,
            "port": candidate.port,
            "operations": completed,
            "concurrency": concurrency,
            "payload_bytes": len(payload),
            "wall_seconds": wall,
            "server_cpu_seconds": cpu_seconds,
            "server_cpu_ms_per_op": (cpu_seconds * 1000.0 / completed) if completed else 0.0,
            "ops_per_second": completed / wall if wall > 0 else 0.0,
            "echo_payload_mib_per_second": (completed * len(payload) * 2 / wall / 1048576.0)
            if wall > 0
            else 0.0,
            "latency_ms": {
                "mean": statistics.fmean(latencies) * 1000.0 if latencies else 0.0,
                "p50": percentile(latencies, 50) * 1000.0,
                "p90": percentile(latencies, 90) * 1000.0,
                "p99": percentile(latencies, 99) * 1000.0,
                "max": max(latencies) * 1000.0 if latencies else 0.0,
            },
            "rss_kib": {"before": rss_before, "after": rss_after},
            "process_exit": candidate.process.poll(),
        }
    finally:
        logs = terminate(candidate.process)
        if logs["stdout"].strip() or logs["stderr"].strip():
            log_path = os.path.join(tmp, f"{candidate.name}.log")
            with open(log_path, "w", encoding="utf-8") as log:
                log.write("STDOUT\n")
                log.write(logs["stdout"])
                log.write("\nSTDERR\n")
                log.write(logs["stderr"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-bin", default="/work/target/release/rust-xhttp")
    parser.add_argument("--xray-bin", default="/usr/local/bin/xray")
    parser.add_argument("--operations", type=int, default=int(os.getenv("OPS", "200")))
    parser.add_argument("--warmup", type=int, default=int(os.getenv("WARMUP", "20")))
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("CONCURRENCY", "8")))
    parser.add_argument("--payload-bytes", type=int, default=int(os.getenv("PAYLOAD_BYTES", "4096")))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("TIMEOUT", "15")))
    args = parser.parse_args()

    if args.operations <= 0 or args.concurrency <= 0 or args.payload_bytes <= 0:
        raise SystemExit("operations, concurrency, and payload-bytes must be positive")
    if not os.path.exists(args.rust_bin):
        raise SystemExit(f"missing rust-xhttp binary: {args.rust_bin}")
    if not os.path.exists(args.xray_bin):
        raise SystemExit(f"missing xray binary: {args.xray_bin}")

    max_post = args.payload_bytes + 128
    payload = bytes((i % 251 for i in range(args.payload_bytes)))
    echo = EchoServer(args.payload_bytes).start()
    with tempfile.TemporaryDirectory(prefix="rxhttp-docker-perf-") as tmp:
        try:
            rust_result = bench_candidate(
                lambda directory, post: start_rust(directory, args.rust_bin, post),
                tmp,
                max_post,
                echo.port,
                payload,
                args.warmup,
                args.operations,
                args.concurrency,
                args.timeout,
                0,
            )
            xray_result = bench_candidate(
                lambda directory, post: start_xray(directory, args.xray_bin, post),
                tmp,
                max_post,
                echo.port,
                payload,
                args.warmup,
                args.operations,
                args.concurrency,
                args.timeout,
                args.operations + args.warmup + 1000,
            )
        finally:
            echo.close()

    by_name = {"rust-xhttp": rust_result, "xray-core": xray_result}
    comparison = {
        "ops_per_second_ratio_rust_over_xray": by_name["rust-xhttp"]["ops_per_second"]
        / by_name["xray-core"]["ops_per_second"],
        "cpu_ms_per_op_ratio_rust_over_xray": by_name["rust-xhttp"]["server_cpu_ms_per_op"]
        / by_name["xray-core"]["server_cpu_ms_per_op"]
        if by_name["xray-core"]["server_cpu_ms_per_op"]
        else 0.0,
        "p99_latency_ratio_rust_over_xray": by_name["rust-xhttp"]["latency_ms"]["p99"]
        / by_name["xray-core"]["latency_ms"]["p99"]
        if by_name["xray-core"]["latency_ms"]["p99"]
        else 0.0,
    }
    report = {
        "workload": {
            "protocol": "VLESS over XHTTP packet-up/stream-down over plaintext HTTP/1.1",
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
