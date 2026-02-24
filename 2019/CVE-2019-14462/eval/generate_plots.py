#!/usr/bin/env python3
"""
Generate Matplotlib Figures for Paper

Produces:
- CDF of latency distributions (E4A)
- Bar chart of detection rates (E1)
- Throughput comparison (E4B)
- Byte control comparison (E3)

Usage:
    ./generate_plots.py                  # Generate all available plots
    ./generate_plots.py --output-dir .   # Specify output directory

For defensive security research only.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available. Install with: pip install matplotlib numpy")

RESULTS_DIR = Path(__file__).parent / "results"

# Plot styling
COLORS = {
    "direct": "#2196F3",    # Blue
    "sel4": "#4CAF50",      # Green
    "snort": "#FF9800",     # Orange
    "snort_quickdraw": "#FF9800",
    "snort_talos": "#F44336",
    "snort_combined": "#9C27B0",
}

LABELS = {
    "direct": "Direct (no protection)",
    "sel4": "seL4 Gateway",
    "snort": "Snort IDS",
    "snort_quickdraw": "Snort (Quickdraw)",
    "snort_talos": "Snort (Talos)",
    "snort_combined": "Snort (Combined)",
}


def load_latency_samples(label):
    """Load raw latency samples from CSV."""
    csv_path = RESULTS_DIR / f"e4_latency_{label}.csv"
    if not csv_path.exists():
        return None

    latencies = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                latencies.append(float(row["latency_ms"]))
            except (ValueError, KeyError):
                continue

    return sorted(latencies) if latencies else None


def plot_latency_cdf(output_dir):
    """Generate CDF plot of latency distributions."""
    if not HAS_MATPLOTLIB:
        return

    fig, ax = plt.subplots(1, 1, figsize=(8, 5))

    labels_found = []
    for label in ["direct", "sel4", "snort", "snort_quickdraw", "snort_talos"]:
        samples = load_latency_samples(label)
        if samples:
            n = len(samples)
            cdf = np.arange(1, n + 1) / n
            ax.plot(samples, cdf,
                    color=COLORS.get(label, "#000000"),
                    label=LABELS.get(label, label),
                    linewidth=2)
            labels_found.append(label)

    if not labels_found:
        print("  No latency data found for CDF plot")
        plt.close()
        return

    ax.set_xlabel("Round-Trip Latency (ms)", fontsize=12)
    ax.set_ylabel("CDF", fontsize=12)
    ax.set_title("E4A: Latency Distribution Comparison", fontsize=14)
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 1.02)
    ax.yaxis.set_major_formatter(ticker.PercentFormatter(1.0))

    plt.tight_layout()
    path = output_dir / "e4a_latency_cdf.pdf"
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Generated: {path}")


def plot_detection_rates(output_dir):
    """Generate bar chart of detection rates."""
    if not HAS_MATPLOTLIB:
        return

    e1_files = sorted(RESULTS_DIR.glob("e1_*_metrics.json"))
    if not e1_files:
        print("  No E1 detection rate data found")
        return

    configs = []
    for f in e1_files:
        with open(f) as fp:
            data = json.load(fp)
            configs.append(data)

    if not configs:
        return

    fig, ax = plt.subplots(1, 1, figsize=(10, 6))

    categories = ["malformed", "attacks", "fuzz"]
    x = np.arange(len(configs))
    width = 0.25

    for i, cat in enumerate(categories):
        values = [c.get(f"{cat}_detection_rate", 0) * 100 for c in configs]
        bars = ax.bar(x + i * width - width, values, width,
                      label=cat.capitalize(), alpha=0.85)

    ax.set_xlabel("Configuration", fontsize=12)
    ax.set_ylabel("Detection Rate (%)", fontsize=12)
    ax.set_title("E1: Structural Violation Detection by Category", fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS.get(c.get("label", ""), c.get("label", ""))
                         for c in configs], fontsize=10)
    ax.legend(fontsize=10)
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    path = output_dir / "e1_detection_rates.pdf"
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Generated: {path}")


def plot_throughput(output_dir):
    """Generate throughput comparison plot."""
    if not HAS_MATPLOTLIB:
        return

    tp_files = sorted(RESULTS_DIR.glob("e4_throughput_*_metrics.json"))
    if not tp_files:
        print("  No E4B throughput data found")
        return

    fig, ax = plt.subplots(1, 1, figsize=(8, 5))

    for f in tp_files:
        with open(f) as fp:
            data = json.load(fp)
            label = data.get("label", "unknown")
            rate_results = data.get("rate_results", [])

            if rate_results:
                rates = [r["target_rate"] for r in rate_results]
                loss = [r["loss_pct"] for r in rate_results]
                ax.plot(rates, loss,
                        color=COLORS.get(label, "#000000"),
                        label=LABELS.get(label, label),
                        marker="o", linewidth=2, markersize=6)

    ax.set_xlabel("Request Rate (packets/sec)", fontsize=12)
    ax.set_ylabel("Packet Loss (%)", fontsize=12)
    ax.set_title("E4B: Throughput vs Packet Loss", fontsize=14)
    ax.axhline(y=1.0, color="red", linestyle="--", alpha=0.5, label="1% threshold")
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_xscale("log")

    plt.tight_layout()
    path = output_dir / "e4b_throughput.pdf"
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Generated: {path}")


def plot_byte_control(output_dir):
    """Generate byte control comparison plot."""
    if not HAS_MATPLOTLIB:
        return

    e3_files = sorted(RESULTS_DIR.glob("e3_byte_control_*_metrics.json"))
    if not e3_files:
        print("  No E3 byte control data found")
        return

    configs = []
    for f in e3_files:
        with open(f) as fp:
            data = json.load(fp)
            if "byte_control_pct" in data:
                configs.append(data)

    if not configs:
        return

    fig, ax = plt.subplots(1, 1, figsize=(6, 4))

    labels = [LABELS.get(c.get("label", ""), c.get("label", "")) for c in configs]
    values = [c.get("byte_control_pct", 0) for c in configs]
    colors = [COLORS.get(c.get("label", ""), "#888888") for c in configs]

    bars = ax.bar(labels, values, color=colors, alpha=0.85, edgecolor="black", linewidth=0.5)

    ax.set_ylabel("Attacker Byte Control (%)", fontsize=12)
    ax.set_title("E3: Non-Semantic Byte Forwarding", fontsize=14)
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3, axis="y")

    # Add value labels on bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 1,
                f"{val:.0f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    plt.tight_layout()
    path = output_dir / "e3_byte_control.pdf"
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Generated: {path}")


def plot_latency_boxplot(output_dir):
    """Generate box plot comparing latency distributions."""
    if not HAS_MATPLOTLIB:
        return

    all_data = []
    all_labels = []

    for label in ["direct", "sel4", "snort", "snort_quickdraw"]:
        samples = load_latency_samples(label)
        if samples:
            all_data.append(samples)
            all_labels.append(LABELS.get(label, label))

    if not all_data:
        print("  No latency data for box plot")
        return

    fig, ax = plt.subplots(1, 1, figsize=(8, 5))

    bp = ax.boxplot(all_data, labels=all_labels, patch_artist=True, showfliers=False)

    for i, (patch, label) in enumerate(zip(bp["boxes"], [l.split()[0].lower() for l in all_labels])):
        color = COLORS.get(label, "#888888")
        patch.set_facecolor(color)
        patch.set_alpha(0.6)

    ax.set_ylabel("Round-Trip Latency (ms)", fontsize=12)
    ax.set_title("E4A: Latency Distribution (outliers hidden)", fontsize=14)
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    path = output_dir / "e4a_latency_boxplot.pdf"
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Generated: {path}")


def main():
    parser = argparse.ArgumentParser(description="Generate evaluation plots")
    parser.add_argument("--output-dir", "-o", type=Path, default=RESULTS_DIR,
                        help="Output directory for plots")
    args = parser.parse_args()

    if not HAS_MATPLOTLIB:
        print("Error: matplotlib is required. Install with: pip install matplotlib numpy")
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating evaluation plots...")
    print("=" * 60)

    print("\n1. Latency CDF (E4A)")
    plot_latency_cdf(args.output_dir)

    print("\n2. Latency Box Plot (E4A)")
    plot_latency_boxplot(args.output_dir)

    print("\n3. Detection Rates (E1)")
    plot_detection_rates(args.output_dir)

    print("\n4. Throughput (E4B)")
    plot_throughput(args.output_dir)

    print("\n5. Byte Control (E3)")
    plot_byte_control(args.output_dir)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
