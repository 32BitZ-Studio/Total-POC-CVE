#!/usr/bin/env python3
"""
E3: Canonical Reconstruction Verification (Byte Control Analysis)

Verifies that the seL4 gateway performs canonical reconstruction, eliminating
attacker-controlled non-semantic bytes from reaching the PLC.

Experiment 2A: Attacker Byte Control
- Send N packets with varying Transaction IDs (non-semantic field)
- Same semantic operation: FC03 Read Holding Registers, addr=0, qty=1
- Capture packets at PLC side (via tcpdump on br1)
- Compare: Snort passes all attacker bytes, seL4 assigns new Transaction IDs

Experiment 2B: Zero-Day Trigger Pattern
- PLC compiled with -DTRIGGER_PATTERN_VULN crashes on Transaction ID = 0xDEAD
- Direct/Snort: PLC crashes (byte passed through)
- seL4: PLC survives (new Transaction ID assigned)

Usage:
    ./run_e3_canonical.py --target <IP> --port <PORT> --label <LABEL> -n 100
    ./run_e3_canonical.py --all --target <IP> -n 100
    ./run_e3_canonical.py --trigger-test --target <IP>

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


def build_modbus_read(transaction_id, unit_id=0x01, address=0x0000, quantity=0x0001):
    """Build a Modbus FC03 Read Holding Registers request with specific Transaction ID."""
    pdu = struct.pack(">BHH", 0x03, address, quantity)
    length = len(pdu) + 1  # +1 for unit_id
    mbap = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)
    return mbap + pdu


def send_and_receive(ip, port, data, timeout=3.0):
    """Send a Modbus packet and return (success, response_bytes, transaction_id_echoed)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(data)

        response = sock.recv(1024)
        sock.close()

        if len(response) >= 2:
            echoed_tid = struct.unpack(">H", response[0:2])[0]
            return True, response, echoed_tid
        return True, response, None

    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
        return False, None, None
    except OSError:
        return False, None, None


def run_byte_control_test(ip, port, label, n_packets=100, delay=0.1):
    """
    E2A: Send N packets with varying Transaction IDs.
    Record which Transaction IDs are echoed back.
    """
    print(f"\nE3 Byte Control Test: {label} ({ip}:{port})")
    print(f"Sending {n_packets} packets with unique Transaction IDs")
    print("-" * 60)

    results = []
    unique_sent_tids = set()
    unique_received_tids = set()
    successes = 0
    failures = 0

    for i in range(n_packets):
        # Use distinct Transaction IDs (non-sequential to avoid coincidence)
        tid = (i * 37 + 0x1000) & 0xFFFF  # Spread across ID space
        unique_sent_tids.add(tid)

        packet = build_modbus_read(tid)
        success, response, echoed_tid = send_and_receive(ip, port, packet)

        record = {
            "index": i,
            "sent_tid": tid,
            "success": success,
            "echoed_tid": echoed_tid,
            "tid_preserved": echoed_tid == tid if echoed_tid is not None else None,
        }

        if success:
            successes += 1
            if echoed_tid is not None:
                unique_received_tids.add(echoed_tid)
        else:
            failures += 1

        results.append(record)

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{n_packets} ({successes} ok, {failures} failed)")

        time.sleep(delay)

    # Analysis
    preserved = sum(1 for r in results if r["tid_preserved"] is True)
    replaced = sum(1 for r in results if r["tid_preserved"] is False)

    print(f"\n{'=' * 60}")
    print(f"Results for: {label}")
    print(f"{'=' * 60}")
    print(f"  Packets sent:     {n_packets}")
    print(f"  Successful:       {successes}")
    print(f"  Failed:           {failures}")
    print(f"  TID preserved:    {preserved} ({preserved/max(successes,1)*100:.1f}%)")
    print(f"  TID replaced:     {replaced} ({replaced/max(successes,1)*100:.1f}%)")
    print(f"  Unique sent TIDs: {len(unique_sent_tids)}")
    print(f"  Unique recv TIDs: {len(unique_received_tids)}")

    if replaced > 0:
        print(f"\n  >>> CANONICAL RECONSTRUCTION DETECTED <<<")
        print(f"  Gateway replaced {replaced}/{successes} Transaction IDs")
        print(f"  Attacker byte control: 0% (non-semantic bytes replaced)")
    else:
        print(f"\n  >>> PASS-THROUGH DETECTED <<<")
        print(f"  All Transaction IDs preserved verbatim")
        print(f"  Attacker byte control: 100% (non-semantic bytes forwarded)")

    metrics = {
        "label": label,
        "ip": ip,
        "port": port,
        "n_packets": n_packets,
        "successes": successes,
        "failures": failures,
        "tid_preserved": preserved,
        "tid_replaced": replaced,
        "unique_sent": len(unique_sent_tids),
        "unique_received": len(unique_received_tids),
        "byte_control_pct": preserved / max(successes, 1) * 100,
        "canonical_reconstruction": replaced > 0,
        "timestamp": datetime.now().isoformat(),
    }

    return results, metrics


def run_trigger_test(ip, port, label, timeout=5.0):
    """
    E2B: Zero-Day Trigger Pattern Test
    Send Transaction ID = 0xDEAD, check if PLC survives.
    """
    print(f"\nE3 Trigger Pattern Test: {label} ({ip}:{port})")
    print("-" * 60)

    # First verify PLC is alive
    print("  Verifying PLC is alive...")
    success, _, _ = send_and_receive(ip, port, build_modbus_read(0x0001))
    if not success:
        print("  ERROR: PLC not responding (test cannot proceed)")
        return {"label": label, "result": "plc_not_responding"}

    print("  PLC responding normally.")

    # Send trigger packet
    print(f"  Sending trigger packet (TID=0xDEAD)...")
    trigger_packet = build_modbus_read(0xDEAD)
    success, response, echoed_tid = send_and_receive(ip, port, trigger_packet, timeout=timeout)

    if success:
        print(f"  Response received (TID echoed: {echoed_tid:#06x})")
        if echoed_tid == 0xDEAD:
            print(f"  Trigger TID passed through to PLC!")
        else:
            print(f"  Trigger TID replaced by gateway (0xDEAD -> {echoed_tid:#06x})")
    else:
        print(f"  No response (PLC may have crashed or gateway blocked)")

    # Check if PLC is still alive after trigger
    time.sleep(1.0)
    print("  Checking if PLC survived...")
    alive_after, _, _ = send_and_receive(ip, port, build_modbus_read(0x0002))

    if alive_after:
        print("  PLC SURVIVED the trigger packet!")
        result = "survived"
    else:
        print("  PLC CRASHED after trigger packet!")
        result = "crashed"

    metrics = {
        "label": label,
        "ip": ip,
        "port": port,
        "trigger_tid": 0xDEAD,
        "trigger_success": success,
        "echoed_tid": echoed_tid,
        "tid_preserved": echoed_tid == 0xDEAD if echoed_tid is not None else None,
        "plc_survived": alive_after,
        "result": result,
        "timestamp": datetime.now().isoformat(),
    }

    return metrics


def write_results(label, results, metrics, test_type="byte_control"):
    """Write results to CSV and JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if results:
        csv_path = RESULTS_DIR / f"e3_{test_type}_{label}.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)
        print(f"  Results: {csv_path}")

    json_path = RESULTS_DIR / f"e3_{test_type}_{label}_metrics.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics: {json_path}")


def main():
    parser = argparse.ArgumentParser(description="E3: Canonical Reconstruction Verification")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP")
    parser.add_argument("--port", "-p", type=int, help="Target port")
    parser.add_argument("--label", "-l", help="Test label")
    parser.add_argument("--all", action="store_true", help="Run all configurations")
    parser.add_argument("-n", type=int, default=100, help="Number of packets for byte control test")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between packets")
    parser.add_argument("--trigger-test", action="store_true", help="Run trigger pattern test (E2B)")
    args = parser.parse_args()

    if args.all:
        configs = [
            (5020, "direct"),
            (502, "sel4"),
            (503, "snort"),
        ]
        all_metrics = []

        for port, label in configs:
            print(f"\n{'#' * 60}")
            print(f"# Configuration: {label} (port {port})")
            print(f"{'#' * 60}")

            results, metrics = run_byte_control_test(args.target, port, label, args.n, args.delay)
            write_results(label, results, metrics)
            all_metrics.append(metrics)

            if args.trigger_test:
                trigger_metrics = run_trigger_test(args.target, port, label)
                write_results(label, None, trigger_metrics, "trigger")
                all_metrics.append(trigger_metrics)

        # Comparison summary
        summary_path = RESULTS_DIR / "e3_comparison.json"
        with open(summary_path, "w") as f:
            json.dump(all_metrics, f, indent=2)
        print(f"\nComparison: {summary_path}")

    elif args.trigger_test:
        configs = [(5020, "direct"), (502, "sel4"), (503, "snort")]
        for port, label in configs:
            metrics = run_trigger_test(args.target, port, label)
            write_results(label, None, metrics, "trigger")

    elif args.port and args.label:
        results, metrics = run_byte_control_test(args.target, args.port, args.label, args.n, args.delay)
        write_results(args.label, results, metrics)

    else:
        parser.error("Specify --all or both --port and --label")

    return 0


if __name__ == "__main__":
    sys.exit(main())
