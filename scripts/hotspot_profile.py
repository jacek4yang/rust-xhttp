#!/usr/bin/env python3
"""Drive a sustained rust-xhttp raw XHTTP workload and optionally sample it with perf.

This intentionally reuses the protocol-correct workload from docker_xray_perf.py, but
starts only rust-xhttp.  perf is attached to that exact child PID; it never samples the
whole host.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import itertools
import json
import os
import subprocess
import tempfile
import threading
import time

import docker_xray_perf as workload


def run_for_duration(
    candidate: workload.Candidate,
    echo_port: int,
    payload: bytes,
    duration: float,
    concurrency: int,
    timeout: float,
) -> tuple[int, list[float]]:
    deadline = time.monotonic() + duration
    operation_ids = itertools.count()
    latencies: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        local_latencies: list[float] = []
        local_errors: list[str] = []
        while time.monotonic() < deadline:
            op_id = next(operation_ids)
            try:
                local_latencies.append(
                    workload.roundtrip(
                        candidate.port, echo_port, payload, op_id, timeout
                    )
                )
            except Exception as error:  # noqa: BLE001 - report workload failures
                local_errors.append(str(error))
                break
        with lock:
            latencies.extend(local_latencies)
            errors.extend(local_errors)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(concurrency)]
        for future in futures:
            future.result()

    if errors:
        raise RuntimeError("; ".join(errors[:5]))
    return len(latencies), latencies


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-bin", default="target/release/rust-xhttp")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--warmup", type=int, default=256)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--perf-data", help="record perf samples to this file")
    parser.add_argument("--perf-frequency", type=int, default=499)
    args = parser.parse_args()

    if args.duration <= 0 or args.concurrency <= 0 or args.payload_bytes <= 0:
        raise SystemExit("duration, concurrency, and payload-bytes must be positive")
    rust_bin = os.path.abspath(args.rust_bin)
    if not os.path.isfile(rust_bin):
        raise SystemExit(f"missing rust-xhttp binary: {rust_bin}")

    payload = bytes((index % 251 for index in range(args.payload_bytes)))
    echo = workload.EchoServer(args.payload_bytes).start()
    perf: subprocess.Popen[str] | None = None
    with tempfile.TemporaryDirectory(prefix="rxhttp-hotspot-") as tmp:
        candidate = workload.start_rust(tmp, rust_bin, args.payload_bytes + 128)
        try:
            if args.warmup:
                workload.run_load(
                    candidate,
                    echo.port,
                    payload,
                    args.warmup,
                    min(args.concurrency, args.warmup),
                    args.timeout,
                    1_000_000,
                )

            if args.perf_data:
                perf_data = os.path.abspath(args.perf_data)
                os.makedirs(os.path.dirname(perf_data), exist_ok=True)
                perf = subprocess.Popen(
                    [
                        "sudo",
                        "-n",
                        "perf",
                        "record",
                        "--quiet",
                        "--freq",
                        str(args.perf_frequency),
                        "--call-graph",
                        "dwarf,16384",
                        "--pid",
                        str(candidate.process.pid),
                        "--output",
                        perf_data,
                        "--",
                        "sleep",
                        str(args.duration),
                    ],
                    text=True,
                )
                # Give perf time to attach before the measured interval begins.
                time.sleep(0.25)

            cpu_before = workload.proc_cpu_seconds(candidate.process.pid)
            rss_before = workload.proc_rss_kib(candidate.process.pid)
            wall_start = time.perf_counter()
            completed, latencies = run_for_duration(
                candidate,
                echo.port,
                payload,
                args.duration,
                args.concurrency,
                args.timeout,
            )
            wall = time.perf_counter() - wall_start
            cpu_seconds = max(
                0.0, workload.proc_cpu_seconds(candidate.process.pid) - cpu_before
            )
            rss_after = workload.proc_rss_kib(candidate.process.pid)

            if perf is not None and perf.wait(timeout=args.duration + 10) != 0:
                raise RuntimeError("perf record failed")

            report = {
                "operations": completed,
                "concurrency": args.concurrency,
                "payload_bytes": args.payload_bytes,
                "wall_seconds": wall,
                "ops_per_second": completed / wall,
                "server_cpu_seconds": cpu_seconds,
                "server_cpu_ms_per_op": cpu_seconds * 1000 / completed,
                "latency_ms": {
                    "mean": sum(latencies) * 1000 / completed,
                    "p50": workload.percentile(latencies, 50) * 1000,
                    "p90": workload.percentile(latencies, 90) * 1000,
                    "p99": workload.percentile(latencies, 99) * 1000,
                    "max": max(latencies) * 1000,
                },
                "rss_kib": {"before": rss_before, "after": rss_after},
                "perf_data": os.path.abspath(args.perf_data)
                if args.perf_data
                else None,
            }
            print(json.dumps(report, indent=2, sort_keys=True))
        finally:
            if perf is not None and perf.poll() is None:
                perf.terminate()
                perf.wait(timeout=5)
            workload.terminate(candidate.process)
            echo.close()


if __name__ == "__main__":
    main()
