#!/usr/bin/env python3
"""
Metrics Collector

Aggregates evaluation results from individual experiment outputs into
unified CSV and JSON files suitable for LaTeX table generation.

Usage:
    ./metrics_collector.py                    # Collect all available results
    ./metrics_collector.py --latex            # Generate LaTeX table snippets

For defensive security research only.
"""

import csv
import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


def collect_e1_metrics():
    """Collect E1 detection rate results."""
    e1_files = sorted(RESULTS_DIR.glob("e1_*_metrics.json"))
    if not e1_files:
        return None

    results = []
    for f in e1_files:
        with open(f) as fp:
            data = json.load(fp)
            results.append(data)

    return results


def collect_e3_metrics():
    """Collect E3 canonical reconstruction results."""
    e3_files = sorted(RESULTS_DIR.glob("e3_*_metrics.json"))
    if not e3_files:
        return None

    results = []
    for f in e3_files:
        with open(f) as fp:
            results.append(json.load(fp))

    return results


def collect_e4_metrics():
    """Collect E4 performance results."""
    categories = ["latency", "throughput", "fp"]
    results = {}

    for cat in categories:
        files = sorted(RESULTS_DIR.glob(f"e4_{cat}_*_metrics.json"))
        if files:
            results[cat] = []
            for f in files:
                with open(f) as fp:
                    results[cat].append(json.load(fp))

    return results if results else None


def generate_detection_table(e1_data):
    """Generate detection rate comparison table."""
    if not e1_data:
        return ""

    rows = []
    for m in e1_data:
        label = m.get("label", "unknown")
        rows.append({
            "Configuration": label,
            "Valid (FP%)": f"{m.get('false_positive_rate', 0)*100:.1f}%",
            "Malformed Det%": f"{m.get('malformed_detection_rate', 0)*100:.1f}%",
            "Attack Det%": f"{m.get('attacks_detection_rate', 0)*100:.1f}%",
            "Fuzz Det%": f"{m.get('fuzz_detection_rate', 0)*100:.1f}%",
            "Overall Det%": f"{m.get('overall_detection_rate', 0)*100:.1f}%",
        })

    return rows


def generate_latency_table(e4_latency):
    """Generate latency comparison table."""
    if not e4_latency:
        return ""

    rows = []
    for m in e4_latency:
        label = m.get("label", "unknown")
        rows.append({
            "Configuration": label,
            "Min (ms)": f"{m.get('min_ms', 0):.3f}",
            "P50 (ms)": f"{m.get('p50_ms', 0):.3f}",
            "Mean (ms)": f"{m.get('mean_ms', 0):.3f}",
            "P95 (ms)": f"{m.get('p95_ms', 0):.3f}",
            "P99 (ms)": f"{m.get('p99_ms', 0):.3f}",
            "Max (ms)": f"{m.get('max_ms', 0):.3f}",
            "StdDev (ms)": f"{m.get('stddev_ms', 0):.3f}",
        })

    return rows


def generate_latex_table(title, rows, label=""):
    """Generate a LaTeX table from row data."""
    if not rows:
        return ""

    headers = list(rows[0].keys())
    col_spec = "|".join(["l"] + ["r"] * (len(headers) - 1))

    lines = []
    lines.append(f"% {title}")
    lines.append(f"\\begin{{table}}[h]")
    lines.append(f"\\centering")
    lines.append(f"\\caption{{{title}}}")
    if label:
        lines.append(f"\\label{{{label}}}")
    lines.append(f"\\begin{{tabular}}{{{col_spec}}}")
    lines.append("\\toprule")
    lines.append(" & ".join(f"\\textbf{{{h}}}" for h in headers) + " \\\\")
    lines.append("\\midrule")

    for row in rows:
        line = " & ".join(str(row[h]) for h in headers) + " \\\\"
        lines.append(line)

    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")

    return "\n".join(lines)


def write_unified_csv(all_metrics):
    """Write a single unified CSV with all metrics."""
    csv_path = RESULTS_DIR / "unified_metrics.csv"

    rows = []

    # E1 Detection
    if all_metrics.get("e1"):
        for m in all_metrics["e1"]:
            rows.append({
                "experiment": "E1",
                "configuration": m.get("label", ""),
                "metric": "detection_rate",
                "malformed": f"{m.get('malformed_detection_rate', 0)*100:.2f}",
                "attacks": f"{m.get('attacks_detection_rate', 0)*100:.2f}",
                "fuzz": f"{m.get('fuzz_detection_rate', 0)*100:.2f}",
                "overall": f"{m.get('overall_detection_rate', 0)*100:.2f}",
                "false_positive": f"{m.get('false_positive_rate', 0)*100:.2f}",
            })

    # E3 Byte Control
    if all_metrics.get("e3"):
        for m in all_metrics["e3"]:
            if "byte_control_pct" in m:
                rows.append({
                    "experiment": "E3",
                    "configuration": m.get("label", ""),
                    "metric": "byte_control",
                    "byte_control_pct": f"{m.get('byte_control_pct', 0):.2f}",
                    "canonical": str(m.get("canonical_reconstruction", False)),
                })

    # E4 Latency
    if all_metrics.get("e4") and all_metrics["e4"].get("latency"):
        for m in all_metrics["e4"]["latency"]:
            rows.append({
                "experiment": "E4",
                "configuration": m.get("label", ""),
                "metric": "latency",
                "min_ms": f"{m.get('min_ms', 0):.3f}",
                "p50_ms": f"{m.get('p50_ms', 0):.3f}",
                "mean_ms": f"{m.get('mean_ms', 0):.3f}",
                "p95_ms": f"{m.get('p95_ms', 0):.3f}",
                "p99_ms": f"{m.get('p99_ms', 0):.3f}",
                "max_ms": f"{m.get('max_ms', 0):.3f}",
            })

    if rows:
        # Get all unique keys
        all_keys = set()
        for row in rows:
            all_keys.update(row.keys())
        all_keys = sorted(all_keys)

        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        print(f"Unified CSV: {csv_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Metrics Collector")
    parser.add_argument("--latex", action="store_true", help="Generate LaTeX tables")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Collecting evaluation metrics...")
    print("=" * 60)

    all_metrics = {}

    # E1
    e1 = collect_e1_metrics()
    if e1:
        all_metrics["e1"] = e1
        print(f"\nE1 Detection Rate: {len(e1)} configurations found")
        det_rows = generate_detection_table(e1)
        if det_rows:
            for row in det_rows:
                print(f"  {row['Configuration']:20s} | Det: {row['Overall Det%']:>6s} | FP: {row['Valid (FP%)']:>6s}")
    else:
        print("\nE1: No results found")

    # E3
    e3 = collect_e3_metrics()
    if e3:
        all_metrics["e3"] = e3
        print(f"\nE3 Byte Control: {len(e3)} configurations found")
        for m in e3:
            if "byte_control_pct" in m:
                print(f"  {m.get('label', 'unknown'):20s} | Byte control: {m['byte_control_pct']:.1f}% | Canonical: {m.get('canonical_reconstruction', 'N/A')}")
    else:
        print("\nE3: No results found")

    # E4
    e4 = collect_e4_metrics()
    if e4:
        all_metrics["e4"] = e4
        if "latency" in e4:
            print(f"\nE4A Latency: {len(e4['latency'])} configurations found")
            for m in e4["latency"]:
                print(f"  {m.get('label', 'unknown'):20s} | P50: {m.get('p50_ms', 0):.3f}ms | P99: {m.get('p99_ms', 0):.3f}ms | Mean: {m.get('mean_ms', 0):.3f}ms")
        if "throughput" in e4:
            print(f"\nE4B Throughput: {len(e4['throughput'])} configurations found")
            for m in e4["throughput"]:
                print(f"  {m.get('label', 'unknown'):20s} | Max: {m.get('max_sustainable_pps', 0)} pps")
        if "fp" in e4:
            print(f"\nE4C False Positives: {len(e4['fp'])} configurations found")
            for m in e4["fp"]:
                print(f"  {m.get('label', 'unknown'):20s} | FP rate: {m.get('false_positive_rate', 0):.2f}%")
    else:
        print("\nE4: No results found")

    # Write unified CSV
    if all_metrics:
        write_unified_csv(all_metrics)

    # Write unified JSON
    unified_json = RESULTS_DIR / "unified_metrics.json"
    with open(unified_json, "w") as f:
        json.dump(all_metrics, f, indent=2, default=str)
    print(f"Unified JSON: {unified_json}")

    # LaTeX output
    if args.latex and all_metrics:
        latex_path = RESULTS_DIR / "tables.tex"
        with open(latex_path, "w") as f:
            if e1:
                det_rows = generate_detection_table(e1)
                f.write(generate_latex_table(
                    "E1: Detection Rate Comparison", det_rows, "tab:detection") + "\n\n")

            if e4 and "latency" in e4:
                lat_rows = generate_latency_table(e4["latency"])
                f.write(generate_latex_table(
                    "E4A: Round-Trip Latency", lat_rows, "tab:latency") + "\n\n")

        print(f"LaTeX tables: {latex_path}")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
