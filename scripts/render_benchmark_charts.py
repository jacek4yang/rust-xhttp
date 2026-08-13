#!/usr/bin/env python3
"""Render dependency-free SVG charts from the committed v0.1.0 benchmark evidence."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "benchmarks" / "v0.1.0"
OUTPUT = ROOT / "docs" / "assets"
CASES = (
    ("Raw server\nc64", EVIDENCE / "raw-server-c64.json"),
    ("Official client\nc32", EVIDENCE / "official-client-c32.json"),
    ("Client + encryption\nc32", EVIDENCE / "official-client-encryption-c32.json"),
)
COLORS = {"rust": "#f97316", "xray": "#2563eb"}


def load_cases() -> list[tuple[str, dict[str, dict[str, object]]]]:
    loaded = []
    for label, path in CASES:
        report = json.loads(path.read_text(encoding="utf-8"))
        results = {}
        for result in report["results"]:
            family = "rust" if str(result["name"]).startswith("rust-") else "xray"
            results[family] = result
        if set(results) != {"rust", "xray"}:
            raise ValueError(f"{path}: expected one Rust and one Xray result")
        loaded.append((label, results))
    return loaded


def render(
    filename: str,
    title: str,
    unit: str,
    direction: str,
    value: Callable[[dict[str, object]], float],
) -> None:
    cases = load_cases()
    width, height = 1040, 570
    left, right, top, bottom = 90, 35, 95, 105
    chart_w, chart_h = width - left - right, height - top - bottom
    values = [value(results[family]) for _, results in cases for family in ("rust", "xray")]
    y_max = max(values) * 1.18

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{html.escape(title)}</title>',
        f'<desc id="desc">rust-xhttp and Xray-core comparison; {html.escape(direction)}.</desc>',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#172033}.title{font-size:25px;font-weight:700}.sub{font-size:14px;fill:#526078}.axis{font-size:13px;fill:#526078}.value{font-size:13px;font-weight:650}.label{font-size:14px;font-weight:600}.grid{stroke:#dbe3ef;stroke-width:1}.base{stroke:#7b879c;stroke-width:1.5}</style>',
        f'<text class="title" x="{left}" y="38">{html.escape(title)}</text>',
        f'<text class="sub" x="{left}" y="64">v0.1.0 evidence snapshot · {html.escape(direction)} · controlled same-host loopback</text>',
    ]

    for tick in range(6):
        fraction = tick / 5
        y = top + chart_h * (1 - fraction)
        tick_value = y_max * fraction
        lines.append(f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{left + chart_w}" y2="{y:.1f}"/>')
        lines.append(
            f'<text class="axis" x="{left - 12}" y="{y + 4:.1f}" text-anchor="end">{tick_value:.{0 if y_max >= 100 else 2}f}</text>'
        )
    lines.append(f'<line class="base" x1="{left}" y1="{top + chart_h}" x2="{left + chart_w}" y2="{top + chart_h}"/>')
    lines.append(
        f'<text class="axis" transform="translate(22 {top + chart_h / 2}) rotate(-90)" text-anchor="middle">{html.escape(unit)}</text>'
    )

    group_w = chart_w / len(cases)
    bar_w, gap = 68, 18
    for index, (label, results) in enumerate(cases):
        center = left + group_w * (index + 0.5)
        for offset, family in enumerate(("rust", "xray")):
            current = value(results[family])
            bar_h = chart_h * current / y_max
            x = center - bar_w - gap / 2 + offset * (bar_w + gap)
            y = top + chart_h - bar_h
            lines.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" height="{bar_h:.1f}" rx="5" fill="{COLORS[family]}"/>'
            )
            precision = 0 if current >= 100 else 2
            lines.append(
                f'<text class="value" x="{x + bar_w / 2:.1f}" y="{max(top + 14, y - 8):.1f}" text-anchor="middle">{current:.{precision}f}</text>'
            )
        first, second = label.split("\n")
        lines.append(f'<text class="label" x="{center:.1f}" y="{top + chart_h + 30}" text-anchor="middle">{html.escape(first)}</text>')
        lines.append(f'<text class="axis" x="{center:.1f}" y="{top + chart_h + 51}" text-anchor="middle">{html.escape(second)}</text>')

    legend_y = height - 24
    for index, (family, label) in enumerate((("rust", "rust-xhttp"), ("xray", "Xray-core"))):
        x = width / 2 - 125 + index * 160
        lines.append(f'<rect x="{x}" y="{legend_y - 13}" width="18" height="18" rx="3" fill="{COLORS[family]}"/>')
        lines.append(f'<text class="axis" x="{x + 27}" y="{legend_y + 1}">{label}</text>')
    lines.append('</svg>\n')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / filename).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    render(
        "performance-ops-v0.1.0.svg",
        "Completed operations per second",
        "operations / second",
        "higher is better",
        lambda result: float(result["ops_per_second"]),
    )
    render(
        "performance-p99-v0.1.0.svg",
        "End-to-end p99 latency",
        "milliseconds",
        "lower is better",
        lambda result: float(result["latency_ms"]["p99"]),  # type: ignore[index]
    )
    render(
        "performance-cpu-v0.1.0.svg",
        "Server CPU cost per operation",
        "CPU milliseconds / operation",
        "lower is better",
        lambda result: float(result["server_cpu_ms_per_op"]),
    )
    print(f"wrote benchmark charts to {OUTPUT}")


if __name__ == "__main__":
    main()
