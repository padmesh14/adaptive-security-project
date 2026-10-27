"""Create a summary table and SVG latency plot from actual benchmark JSON."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
from pathlib import Path


COLORS = {
    "SingleAESBaseline": "#4e79a7",
    "Low": "#59a14f",
    "Medium": "#f28e2b",
    "High": "#e15759",
}


def _svg_plot(summary: list[dict], title: str) -> str:
    modes = list(COLORS)
    sizes = sorted({row["payload_bytes"] for row in summary if row["scenario"] == "isolated"})
    width, height = 1120, 760
    left, right = 95, 1080
    panels = [(95, "Encryption median (seconds, log scale)", "encrypt_seconds_median"),
              (425, "Decryption median (seconds, log scale)", "decrypt_seconds_median")]
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">']
    svg.append('<rect width="100%" height="100%" fill="white"/>')
    svg.append(f'<text x="{left}" y="38" font-family="sans-serif" font-size="22" font-weight="bold">{html.escape(title)}</text>')
    for top, panel_title, field in panels:
        bottom = top + 245
        values = [row[field] for row in summary if row["scenario"] == "isolated" and row[field] and row[field] > 0]
        if not values or not sizes:
            continue
        low, high = min(values) / 1.4, max(values) * 1.4
        low_log, high_log = math.log10(low), math.log10(high)
        svg.append(f'<text x="{left}" y="{top - 12}" font-family="sans-serif" font-size="16">{html.escape(panel_title)}</text>')
        svg.append(f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#555"/>')
        svg.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#555"/>')
        for tick in range(math.floor(low_log), math.ceil(high_log) + 1):
            yvalue = 10 ** tick
            if not low <= yvalue <= high:
                continue
            y = bottom - (math.log10(yvalue) - low_log) / (high_log - low_log) * (bottom - top)
            svg.append(f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#ddd"/>')
            svg.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="sans-serif" font-size="11">{yvalue:g}</text>')
        xcoords = [left + 80 + i * ((right - left - 160) / max(len(sizes) - 1, 1)) for i in range(len(sizes))]
        for x, size in zip(xcoords, sizes):
            svg.append(f'<text x="{x:.1f}" y="{bottom + 22}" text-anchor="middle" font-family="sans-serif" font-size="12">{size:,} B</text>')
        for mode_index, mode in enumerate(modes):
            points = []
            for x, size in zip(xcoords, sizes):
                row = next((r for r in summary if r["scenario"] == "isolated" and r["mode"] == mode and r["payload_bytes"] == size), None)
                value = row.get(field) if row else None
                if not value or value <= 0:
                    continue
                y = bottom - (math.log10(value) - low_log) / (high_log - low_log) * (bottom - top)
                points.append((x, y))
            if points:
                poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
                svg.append(f'<polyline points="{poly}" fill="none" stroke="{COLORS[mode]}" stroke-width="2"/>')
                for x, y in points:
                    svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{COLORS[mode]}"/>')
        legend_x = left
        for mode in modes:
            svg.append(f'<line x1="{legend_x}" y1="{bottom + 55}" x2="{legend_x + 18}" y2="{bottom + 55}" stroke="{COLORS[mode]}" stroke-width="3"/>')
            svg.append(f'<text x="{legend_x + 24}" y="{bottom + 59}" font-family="sans-serif" font-size="12">{mode}</text>')
            legend_x += 210
    svg.append('</svg>')
    return "\n".join(svg)


def analyze(path: Path) -> tuple[Path, Path, Path]:
    report = json.loads(path.read_text(encoding="utf-8"))
    summary = [row for row in report["summary"] if row["scenario"] == "isolated"]
    stem = path.with_suffix("")
    md_path, csv_path, svg_path = Path(f"{stem}-summary.md"), Path(f"{stem}-summary.csv"), Path(f"{stem}-latency.svg")
    fields = [
        "payload_bytes", "mode", "successful_trials", "failed_trials",
        "encrypt_seconds_mean", "encrypt_seconds_median", "encrypt_seconds_stdev", "encrypt_seconds_p95",
        "encrypt_median_95pct_bootstrap_ci", "encrypt_mib_per_second_median",
        "decrypt_seconds_mean", "decrypt_seconds_median", "decrypt_seconds_stdev", "decrypt_seconds_p95",
        "decrypt_median_95pct_bootstrap_ci", "decrypt_mib_per_second_median", "ciphertext_overhead_bytes_median",
    ]
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in summary:
            writer.writerow({field: row.get(field) for field in fields})

    lines = [
        f"# Benchmark summary: {path.name}", "",
        f"Environment: {report['environment'].get('platform')} / {report['environment'].get('processor')} / "
        f"{report['environment'].get('logical_cpu_count')} logical CPUs; Python {report['environment'].get('python_implementation')}; "
        f"cryptography {report['environment'].get('cryptography')}.", "",
        f"Measured failures (all scenarios): {report.get('failed_measured_trials', 'not recorded')}.", "",
        "| Payload | Mode | n | Fail | Encrypt mean µs | Encrypt median µs | Encrypt SD µs | Encrypt p95 µs | Encrypt median 95% CI µs | Encrypt MiB/s median | Decrypt median µs | Decrypt p95 µs | Decrypt median 95% CI µs | Decrypt MiB/s median | Expansion bytes |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        def us(name):
            value = row.get(name)
            return "—" if value is None else f"{value * 1e6:.3f}"
        ci = row.get("encrypt_median_95pct_bootstrap_ci")
        ci_text = "—" if ci is None else f"[{ci[0] * 1e6:.3f}, {ci[1] * 1e6:.3f}]"
        decrypt_ci = row.get("decrypt_median_95pct_bootstrap_ci")
        decrypt_ci_text = "—" if decrypt_ci is None else f"[{decrypt_ci[0] * 1e6:.3f}, {decrypt_ci[1] * 1e6:.3f}]"
        throughput = row.get("encrypt_mib_per_second_median")
        decrypt_throughput = row.get("decrypt_mib_per_second_median")
        expansion = row.get("ciphertext_overhead_bytes_median")
        lines.append(
            f"| {row['payload_bytes']:,} | {row['mode']} | {row['successful_trials']} | {row['failed_trials']} | "
            f"{us('encrypt_seconds_mean')} | {us('encrypt_seconds_median')} | {us('encrypt_seconds_stdev')} | "
            f"{us('encrypt_seconds_p95')} | {ci_text} | {throughput if throughput is not None else '—'} | "
            f"{us('decrypt_seconds_median')} | {us('decrypt_seconds_p95')} | {decrypt_ci_text} | "
            f"{decrypt_throughput if decrypt_throughput is not None else '—'} | {expansion if expansion is not None else '—'} |"
        )
    lines += ["", "Times, uncertainty values, and plot points are computed from the selected run's raw measurements. p95 is omitted when fewer than 30 successful observations exist.", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    svg_path.write_text(_svg_plot(report["summary"], "Encryption tier benchmark"), encoding="utf-8")
    return md_path, csv_path, svg_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_report", type=Path)
    args = parser.parse_args()
    try:
        outputs = analyze(args.json_report)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    for path in outputs:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
