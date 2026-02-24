#!/usr/bin/env python3
"""
E1: Detection Rate Comparison

Measures structural violation detection rates across configurations:
- seL4 Gateway (port 502): Protocol-break with EverParse validation
- Snort Quickdraw (port 503): Packet-forwarding with Quickdraw rules
- Snort Talos (port 503): Packet-forwarding with Talos rules
- Snort Combined (port 503): Packet-forwarding with all rules
- Direct PLC (port 5020): No protection (baseline)

Metrics:
- Detection rate = (blocked malformed) / (total malformed)
- False positive rate = (blocked valid) / (total valid)

Usage:
    ./run_e1_detection.py --target <IP> --port <PORT> --label <LABEL>
    ./run_e1_detection.py --all --target <IP>

For defensive security research only.
"""

import argparse
import csv
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from datetime import datetime

CORPUS_DIR = Path(__file__).parent / "corpus"
RESULTS_DIR = Path(__file__).parent / "results"

# Response classification
RESULT_BLOCKED = "blocked"       # Connection reset or timeout
RESULT_PASSED = "passed"         # Got a Modbus response (valid or exception)
RESULT_ERROR = "error"           # Unexpected error

# Timeouts
CONNECT_TIMEOUT = 3.0
RECV_TIMEOUT = 3.0


def send_packet(ip, port, data, timeout=RECV_TIMEOUT):
    """Send a raw packet and classify the response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip, port))
        sock.settimeout(timeout)

        sock.sendall(data)

        try:
            response = sock.recv(1024)
            sock.close()

            if len(response) == 0:
                return RESULT_BLOCKED, None, "empty_response"

            # Parse Modbus response
            if len(response) >= 9:
                func_code = response[7]
                if func_code & 0x80:
                    # Exception response - packet reached PLC but was rejected
                    exception_code = response[8] if len(response) > 8 else 0
                    return RESULT_PASSED, response, f"exception_0x{exception_code:02x}"
                else:
                    return RESULT_PASSED, response, "success"

            return RESULT_PASSED, response, f"short_response_{len(response)}b"

        except socket.timeout:
            sock.close()
            return RESULT_BLOCKED, None, "timeout"

    except ConnectionRefusedError:
        return RESULT_BLOCKED, None, "connection_refused"
    except ConnectionResetError:
        return RESULT_BLOCKED, None, "connection_reset"
    except BrokenPipeError:
        return RESULT_BLOCKED, None, "broken_pipe"
    except socket.timeout:
        return RESULT_BLOCKED, None, "connect_timeout"
    except OSError as e:
        return RESULT_ERROR, None, str(e)


def load_corpus():
    """Load the test corpus manifest."""
    manifest_path = CORPUS_DIR / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Manifest not found at {manifest_path}")
        print("Run corpus_generator.py first.")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    return manifest


def run_detection_test(ip, port, label, manifest, delay=0.05):
    """Run the full detection test against one endpoint."""
    results = []
    total = manifest["total_packets"]

    print(f"\nTesting: {label} ({ip}:{port})")
    print(f"Corpus: {total} packets")
    print("-" * 60)

    categories = {"valid": [], "malformed": [], "attacks": [], "fuzz": []}
    blocked_count = 0
    passed_count = 0
    error_count = 0

    for i, packet_info in enumerate(manifest["packets"]):
        category = packet_info["category"]
        packet_id = packet_info["id"]
        filename = packet_info["filename"]
        expected = packet_info["expected_result"]

        # Read packet data
        packet_path = CORPUS_DIR / category / filename
        if not packet_path.exists():
            results.append({**packet_info, "result": "file_missing", "detail": str(packet_path)})
            continue

        with open(packet_path, "rb") as f:
            data = f.read()

        # Skip TCP segmentation packets (need special handling)
        if packet_info.get("cve") == "tcp_segmentation":
            results.append({**packet_info, "result": "skipped", "detail": "tcp_segmentation"})
            continue

        # Send packet
        result, response, detail = send_packet(ip, port, data)

        record = {
            "id": packet_id,
            "category": category,
            "name": packet_info["name"],
            "expected": expected,
            "result": result,
            "detail": detail,
            "correct": (result == RESULT_BLOCKED and expected == "block") or
                       (result == RESULT_PASSED and expected == "pass"),
        }

        if "violation" in packet_info:
            record["violation"] = packet_info["violation"]
        if "cve" in packet_info:
            record["cve"] = packet_info["cve"]

        results.append(record)
        categories[category].append(record)

        if result == RESULT_BLOCKED:
            blocked_count += 1
        elif result == RESULT_PASSED:
            passed_count += 1
        else:
            error_count += 1

        # Progress
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{total} ({blocked_count} blocked, {passed_count} passed, {error_count} errors)")

        time.sleep(delay)

    # Calculate metrics
    print(f"\n{'=' * 60}")
    print(f"Results for: {label}")
    print(f"{'=' * 60}")

    metrics = {"label": label, "ip": ip, "port": port, "timestamp": datetime.now().isoformat()}

    for cat_name, cat_results in categories.items():
        if not cat_results:
            continue

        total_cat = len(cat_results)
        blocked = sum(1 for r in cat_results if r["result"] == RESULT_BLOCKED)
        passed = sum(1 for r in cat_results if r["result"] == RESULT_PASSED)
        correct = sum(1 for r in cat_results if r.get("correct", False))
        skipped = sum(1 for r in cat_results if r.get("result") == "skipped")

        if cat_name == "valid":
            fp_rate = blocked / total_cat if total_cat > 0 else 0
            metrics["false_positive_rate"] = fp_rate
            metrics["valid_total"] = total_cat
            metrics["valid_blocked"] = blocked
            print(f"\n  {cat_name.upper()}: {total_cat} packets")
            print(f"    Passed (correct): {passed}")
            print(f"    Blocked (FP):     {blocked} ({fp_rate*100:.1f}% false positive rate)")
        else:
            det_rate = blocked / (total_cat - skipped) if (total_cat - skipped) > 0 else 0
            metrics[f"{cat_name}_detection_rate"] = det_rate
            metrics[f"{cat_name}_total"] = total_cat - skipped
            metrics[f"{cat_name}_blocked"] = blocked
            print(f"\n  {cat_name.upper()}: {total_cat} packets (excl {skipped} skipped)")
            print(f"    Blocked (detected): {blocked} ({det_rate*100:.1f}% detection rate)")
            print(f"    Passed (missed):    {passed}")

    # Overall detection rate (malformed + attacks + fuzz)
    all_malicious = [r for cat in ["malformed", "attacks", "fuzz"]
                     for r in categories[cat] if r.get("result") != "skipped"]
    if all_malicious:
        overall_det = sum(1 for r in all_malicious if r["result"] == RESULT_BLOCKED) / len(all_malicious)
        metrics["overall_detection_rate"] = overall_det
        print(f"\n  OVERALL DETECTION RATE: {overall_det*100:.1f}%")

    # Breakdown by violation type
    violation_stats = {}
    for r in results:
        vtype = r.get("violation", r.get("cve", "other"))
        if vtype and r.get("result") in [RESULT_BLOCKED, RESULT_PASSED]:
            if vtype not in violation_stats:
                violation_stats[vtype] = {"blocked": 0, "passed": 0}
            if r["result"] == RESULT_BLOCKED:
                violation_stats[vtype]["blocked"] += 1
            else:
                violation_stats[vtype]["passed"] += 1

    metrics["violation_breakdown"] = violation_stats

    return results, metrics


def write_results(label, results, metrics):
    """Write results to CSV and JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # CSV with per-packet results
    csv_path = RESULTS_DIR / f"e1_{label}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "category", "name", "expected",
                                                "result", "detail", "correct",
                                                "violation", "cve"])
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in writer.fieldnames})

    # JSON with summary metrics
    json_path = RESULTS_DIR / f"e1_{label}_metrics.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n  Results written to: {csv_path}")
    print(f"  Metrics written to: {json_path}")


def main():
    parser = argparse.ArgumentParser(description="E1: Detection Rate Comparison")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP")
    parser.add_argument("--port", "-p", type=int, help="Target port")
    parser.add_argument("--label", "-l", help="Test label (e.g., sel4, snort_quickdraw)")
    parser.add_argument("--all", action="store_true", help="Run all configurations")
    parser.add_argument("--delay", "-d", type=float, default=0.05,
                        help="Delay between packets in seconds")
    args = parser.parse_args()

    manifest = load_corpus()

    if args.all:
        configs = [
            (5020, "direct"),
            (502, "sel4"),
            (503, "snort_quickdraw"),
        ]
        all_metrics = []
        for port, label in configs:
            print(f"\n{'#' * 60}")
            print(f"# Configuration: {label} (port {port})")
            print(f"{'#' * 60}")
            results, metrics = run_detection_test(args.target, port, label, manifest, args.delay)
            write_results(label, results, metrics)
            all_metrics.append(metrics)

        # Write comparison summary
        summary_path = RESULTS_DIR / "e1_comparison.json"
        with open(summary_path, "w") as f:
            json.dump(all_metrics, f, indent=2)
        print(f"\nComparison summary: {summary_path}")

    elif args.port and args.label:
        results, metrics = run_detection_test(args.target, args.port, args.label, manifest, args.delay)
        write_results(args.label, results, metrics)

    else:
        parser.error("Specify --all or both --port and --label")

    return 0


if __name__ == "__main__":
    sys.exit(main())
