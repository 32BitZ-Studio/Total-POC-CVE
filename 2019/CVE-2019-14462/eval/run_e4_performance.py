#!/usr/bin/env python3
"""
E4: Performance Measurement (Latency, Throughput, False Positives)

Experiments:
- E4A: Latency measurement (P50/P95/P99/mean/stddev)
- E4B: Throughput measurement (max sustainable pps)
- E4C: False positive analysis (edge-case valid traffic)

Usage:
    ./run_e4_performance.py --latency --target <IP>
    ./run_e4_performance.py --throughput --target <IP>
    ./run_e4_performance.py --fp --target <IP>
    ./run_e4_performance.py --all --target <IP>

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

RESULTS_DIR = Path(__file__).parent / "results"
CORPUS_DIR = Path(__file__).parent / "corpus"

# Standard Modbus FC03 request
MODBUS_READ = struct.pack(">HHHBBHH", 0x0001, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 0x0001)


def get_time_us():
    """Get monotonic time in microseconds."""
    return time.monotonic() * 1_000_000


def do_modbus_request(ip, port, data=MODBUS_READ, timeout=5.0):
    """Send Modbus request, return (success, latency_ms, response)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start = time.monotonic()
        sock.connect((ip, port))
        sock.sendall(data)
        response = sock.recv(1024)
        end = time.monotonic()

        sock.close()
        latency_ms = (end - start) * 1000
        return True, latency_ms, response

    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
        try:
            sock.close()
        except:
            pass
        return False, None, None


def percentile(sorted_data, p):
    """Calculate percentile from sorted data."""
    if not sorted_data:
        return 0
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_data[lo] * (1 - frac) + sorted_data[hi] * frac


def run_latency_test(ip, port, label, iterations=1000, warmup=10, rate=10):
    """E4A: Latency measurement with percentiles."""
    print(f"\nE4A Latency Test: {label} ({ip}:{port})")
    print(f"  Iterations: {iterations} (+ {warmup} warmup)")
    print(f"  Rate: {rate} req/s")
    print("-" * 60)

    delay = 1.0 / rate if rate > 0 else 0.1

    # Warmup
    if warmup > 0:
        print(f"  Warming up ({warmup} iterations)...", end="", flush=True)
        for _ in range(warmup):
            do_modbus_request(ip, port)
            time.sleep(delay)
        print(" done")

    # Measurement
    latencies = []
    errors = 0

    print(f"  Measuring", end="", flush=True)
    for i in range(iterations):
        success, latency_ms, _ = do_modbus_request(ip, port)
        if success:
            latencies.append(latency_ms)
        else:
            errors += 1

        if (i + 1) % (iterations // 20 or 1) == 0:
            print(".", end="", flush=True)

        time.sleep(delay)

    print(" done")

    if not latencies:
        print("  ERROR: No successful measurements!")
        return {"label": label, "error": "no_successful_measurements"}

    latencies.sort()
    n = len(latencies)

    metrics = {
        "label": label,
        "ip": ip,
        "port": port,
        "iterations": iterations,
        "warmup": warmup,
        "rate": rate,
        "successful": n,
        "errors": errors,
        "min_ms": latencies[0],
        "p50_ms": percentile(latencies, 50),
        "mean_ms": sum(latencies) / n,
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "max_ms": latencies[-1],
        "stddev_ms": (sum((x - sum(latencies)/n)**2 for x in latencies) / n) ** 0.5,
        "timestamp": datetime.now().isoformat(),
    }

    print(f"\n  Results:")
    print(f"    Samples: {n} successful, {errors} errors")
    print(f"    Min:     {metrics['min_ms']:.3f} ms")
    print(f"    P50:     {metrics['p50_ms']:.3f} ms")
    print(f"    Mean:    {metrics['mean_ms']:.3f} ms")
    print(f"    P95:     {metrics['p95_ms']:.3f} ms")
    print(f"    P99:     {metrics['p99_ms']:.3f} ms")
    print(f"    Max:     {metrics['max_ms']:.3f} ms")
    print(f"    StdDev:  {metrics['stddev_ms']:.3f} ms")

    # Write raw samples for CDF generation
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / f"e4_latency_{label}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["sample_index", "latency_ms"])
        for i, lat in enumerate(latencies):
            writer.writerow([i, f"{lat:.6f}"])

    json_path = RESULTS_DIR / f"e4_latency_{label}_metrics.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"  CSV: {csv_path}")
    print(f"  Metrics: {json_path}")

    return metrics


def run_throughput_test(ip, port, label, rates=None, packets_per_rate=100):
    """E4B: Throughput measurement - find max sustainable rate."""
    if rates is None:
        rates = [10, 50, 100, 200, 500, 1000]

    print(f"\nE4B Throughput Test: {label} ({ip}:{port})")
    print(f"  Test rates: {rates} pps")
    print(f"  Packets per rate: {packets_per_rate}")
    print("-" * 60)

    results = []

    for target_rate in rates:
        delay = 1.0 / target_rate if target_rate > 0 else 0
        successes = 0
        failures = 0
        latencies = []

        print(f"  Rate {target_rate:5d} pps: ", end="", flush=True)

        start_time = time.monotonic()
        for i in range(packets_per_rate):
            send_start = time.monotonic()
            success, latency_ms, _ = do_modbus_request(ip, port, timeout=2.0)

            if success:
                successes += 1
                latencies.append(latency_ms)
            else:
                failures += 1

            # Rate limiting
            elapsed = time.monotonic() - send_start
            remaining = delay - elapsed
            if remaining > 0:
                time.sleep(remaining)

        total_time = time.monotonic() - start_time
        actual_rate = packets_per_rate / total_time if total_time > 0 else 0
        loss_rate = failures / packets_per_rate * 100

        p99 = percentile(sorted(latencies), 99) if latencies else 0
        median = percentile(sorted(latencies), 50) if latencies else 0

        result = {
            "target_rate": target_rate,
            "actual_rate": round(actual_rate, 1),
            "sent": packets_per_rate,
            "received": successes,
            "lost": failures,
            "loss_pct": round(loss_rate, 2),
            "median_ms": round(median, 3),
            "p99_ms": round(p99, 3),
            "sustainable": loss_rate < 1.0 and (p99 < 10 * median if median > 0 else True),
        }
        results.append(result)

        status = "OK" if result["sustainable"] else "OVERLOADED"
        print(f"{successes}/{packets_per_rate} recv, {loss_rate:.1f}% loss, "
              f"P50={median:.1f}ms P99={p99:.1f}ms [{status}]")

    # Find max sustainable rate
    max_sustainable = 0
    for r in results:
        if r["sustainable"]:
            max_sustainable = r["target_rate"]

    metrics = {
        "label": label,
        "ip": ip,
        "port": port,
        "max_sustainable_pps": max_sustainable,
        "rate_results": results,
        "timestamp": datetime.now().isoformat(),
    }

    print(f"\n  Max sustainable throughput: {max_sustainable} pps")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"e4_throughput_{label}_metrics.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics: {json_path}")

    return metrics


def run_false_positive_test(ip, port, label, delay=0.1):
    """E4C: False positive analysis with edge-case valid traffic."""
    print(f"\nE4C False Positive Test: {label} ({ip}:{port})")
    print("-" * 60)

    # Generate edge-case valid packets
    edge_cases = []

    # Max quantities (boundary)
    edge_cases.append(("fc01_max_qty", struct.pack(">HHHBBHH",
        0x0001, 0x0000, 0x0006, 0x01, 0x01, 0x0000, 2000)))
    edge_cases.append(("fc03_max_qty", struct.pack(">HHHBBHH",
        0x0002, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 125)))
    edge_cases.append(("fc04_max_qty", struct.pack(">HHHBBHH",
        0x0003, 0x0000, 0x0006, 0x01, 0x04, 0x0000, 125)))

    # Boundary addresses
    edge_cases.append(("fc03_addr_0000", struct.pack(">HHHBBHH",
        0x0004, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 1)))
    edge_cases.append(("fc03_addr_ffff", struct.pack(">HHHBBHH",
        0x0005, 0x0000, 0x0006, 0x01, 0x03, 0xFFFF, 1)))
    edge_cases.append(("fc06_addr_ffff", struct.pack(">HHHBBHH",
        0x0006, 0x0000, 0x0006, 0x01, 0x06, 0xFFFF, 0x1234)))

    # All valid function codes
    for fc in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]:
        edge_cases.append((f"fc{fc:02x}_basic", struct.pack(">HHHBBHH",
            0x0010 + fc, 0x0000, 0x0006, 0x01, fc, 0x0000,
            0xFF00 if fc == 0x05 else 1)))

    # Unit IDs
    for uid in [0x00, 0x01, 0x7F, 0xFE, 0xFF]:
        edge_cases.append((f"uid_{uid:02x}", struct.pack(">HHHBBHH",
            0x0020 + uid, 0x0000, 0x0006, uid, 0x03, 0x0000, 1)))

    # Various transaction IDs
    for tid in [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]:
        edge_cases.append((f"tid_{tid:04x}", struct.pack(">HHHBBHH",
            tid, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 1)))

    # FC05 valid values only
    edge_cases.append(("fc05_on", struct.pack(">HHHBBHH",
        0x0030, 0x0000, 0x0006, 0x01, 0x05, 0x0000, 0xFF00)))
    edge_cases.append(("fc05_off", struct.pack(">HHHBBHH",
        0x0031, 0x0000, 0x0006, 0x01, 0x05, 0x0000, 0x0000)))

    # FC0F Write Multiple Coils (correct format)
    qty = 8
    byte_count = 1
    fc0f_data = struct.pack(">HHHB", 0x0032, 0x0000, qty + byte_count + 6, 0x01)
    fc0f_data += struct.pack(">BHHB", 0x0F, 0x0000, qty, byte_count)
    fc0f_data += bytes([0xFF])
    edge_cases.append(("fc0f_8coils", fc0f_data))

    # FC10 Write Multiple Registers (correct format)
    qty = 2
    byte_count = 4
    fc10_pdu = struct.pack(">BHHB", 0x10, 0x0000, qty, byte_count) + struct.pack(">HH", 100, 200)
    fc10_mbap = struct.pack(">HHHB", 0x0033, 0x0000, len(fc10_pdu) + 1, 0x01)
    edge_cases.append(("fc10_2regs", fc10_mbap + fc10_pdu))

    # Address + Quantity exactly at boundary (not overflow)
    edge_cases.append(("fc03_boundary", struct.pack(">HHHBBHH",
        0x0040, 0x0000, 0x0006, 0x01, 0x03, 0xFFFF - 125, 125)))

    # Also test with N=100 repeated identical requests (consistency)
    for i in range(100):
        edge_cases.append((f"repeated_{i:03d}", struct.pack(">HHHBBHH",
            0x0100 + i, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 1)))

    print(f"  Total edge-case packets: {len(edge_cases)}")

    # Send all packets
    blocked = 0
    passed = 0
    errors = 0
    blocked_names = []

    for name, data in edge_cases:
        success, latency_ms, response = do_modbus_request(ip, port, data)

        if success and response:
            passed += 1
        elif not success:
            blocked += 1
            blocked_names.append(name)
        else:
            errors += 1

        time.sleep(delay)

    total = len(edge_cases)
    fp_rate = blocked / total * 100

    print(f"\n  Results:")
    print(f"    Total:   {total}")
    print(f"    Passed:  {passed}")
    print(f"    Blocked: {blocked} ({fp_rate:.2f}% false positive rate)")
    print(f"    Errors:  {errors}")

    if blocked_names:
        print(f"\n  Blocked packets (false positives):")
        for name in blocked_names[:20]:
            print(f"    - {name}")
        if len(blocked_names) > 20:
            print(f"    ... and {len(blocked_names) - 20} more")

    metrics = {
        "label": label,
        "ip": ip,
        "port": port,
        "total_packets": total,
        "passed": passed,
        "blocked": blocked,
        "errors": errors,
        "false_positive_rate": fp_rate,
        "blocked_names": blocked_names,
        "timestamp": datetime.now().isoformat(),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"e4_fp_{label}_metrics.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics: {json_path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(description="E4: Performance Measurement")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP")
    parser.add_argument("--all", action="store_true", help="Run all tests on all endpoints")
    parser.add_argument("--latency", action="store_true", help="Run latency test (E4A)")
    parser.add_argument("--throughput", action="store_true", help="Run throughput test (E4B)")
    parser.add_argument("--fp", action="store_true", help="Run false positive test (E4C)")
    parser.add_argument("-n", type=int, default=1000, help="Iterations for latency test")
    parser.add_argument("--rate", type=int, default=10, help="Request rate for latency test")
    parser.add_argument("--warmup", type=int, default=10, help="Warmup iterations")
    parser.add_argument("--port", "-p", type=int, help="Single port to test")
    parser.add_argument("--label", "-l", help="Label for single port test")
    args = parser.parse_args()

    configs = [
        (5020, "direct"),
        (502, "sel4"),
        (503, "snort"),
    ]

    if args.port and args.label:
        configs = [(args.port, args.label)]

    all_metrics = []

    if args.all or args.latency:
        for port, label in configs:
            metrics = run_latency_test(args.target, port, label, args.n, args.warmup, args.rate)
            all_metrics.append(("latency", metrics))

    if args.all or args.throughput:
        for port, label in configs:
            metrics = run_throughput_test(args.target, port, label)
            all_metrics.append(("throughput", metrics))

    if args.all or args.fp:
        for port, label in configs:
            metrics = run_false_positive_test(args.target, port, label)
            all_metrics.append(("fp", metrics))

    if not (args.all or args.latency or args.throughput or args.fp):
        parser.error("Specify --all, --latency, --throughput, or --fp")

    # Write comparison
    if len(all_metrics) > 1:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        summary_path = RESULTS_DIR / "e4_comparison.json"
        with open(summary_path, "w") as f:
            json.dump([{"test": t, **m} for t, m in all_metrics], f, indent=2)
        print(f"\nComparison: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
