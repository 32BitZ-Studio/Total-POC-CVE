"""
tui.py — Terminal UI for Fracture
"""

import sys, time

# ── colours ───────────────────────────────────────────────────────────────────
R   = "\033[0m";   B   = "\033[1m";   DIM = "\033[2m"
RED = "\033[91m";  GRN = "\033[92m";  YLW = "\033[93m"
BLU = "\033[94m";  MAG = "\033[95m";  CYN = "\033[96m"
WH  = "\033[97m"

W = 68

BANNER = f"""
{RED}{B}
  ███████╗██████╗  █████╗  ██████╗████████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
  █████╗  ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝█████╗
  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗██╔══╝
  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
{R}{DIM}  FragAttacks WiFi Penetration Framework  ·  CVE-2020-24586/87/88{R}
{DIM}  For authorized testing only{R}
"""

def clear():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def print_banner():
    print(BANNER)

def info(msg):
    print(f"  {BLU}{B}[*]{R} {msg}")

def success(msg):
    print(f"  {GRN}{B}[+]{R} {msg}")

def warn(msg):
    print(f"  {YLW}{B}[!]{R} {msg}")

def error(msg):
    print(f"  {RED}{B}[-]{R} {msg}")

def phase(title):
    pad = W - len(title) - 4
    print(f"\n  {RED}{B}┌{'─' * (W)}┐{R}")
    print(f"  {RED}{B}│  {WH}{B}{title}{R}{RED}{B}{'─' * pad}  │{R}")
    print(f"  {RED}{B}└{'─' * (W)}┘{R}\n")

def divider():
    print(f"  {DIM}{'─' * W}{R}")

def scan_table(networks):
    """Render a numbered table of discovered networks."""
    print(f"\n  {WH}{B}  #   BSSID              SSID                      CH  ENC       SIG  WPS  CLIENTS{R}")
    divider()
    for i, n in enumerate(networks, 1):
        enc_col = YLW if n.enc == 'WPA2' else (RED if n.enc == 'OPEN' else WH)
        wps_col = YLW if n.wps else DIM
        sig_col = GRN if n.signal > -60 else (YLW if n.signal > -75 else RED)
        clients = len(n.clients)
        print(
            f"  {DIM}{i:>2}{R}   "
            f"{WH}{n.bssid:<18}{R}  "
            f"{WH}{n.ssid[:24]:<24}{R}  "
            f"{WH}{n.channel:>2}{R}  "
            f"{enc_col}{n.enc:<9}{R}  "
            f"{sig_col}{n.signal:>4}{R}  "
            f"{wps_col}{'YES' if n.wps else ' no'}{R}  "
            f"{WH}{clients:>4}{R}"
        )
    divider()

def pick_target(networks):
    """Interactive target selection. Networks sorted strongest first."""
    while True:
        try:
            raw = input(f"\n  {WH}Select target [1-{len(networks)}] or Enter for strongest: {R}").strip()
            if raw == "":
                return networks[0]
            idx = int(raw) - 1
            if 0 <= idx < len(networks):
                return networks[idx]
        except (ValueError, KeyboardInterrupt):
            pass

def attack_result(path_num, success_flag, detail=""):
    icon = f"{GRN}{B}[+]{R}" if success_flag else f"{RED}{B}[-]{R}"
    label = f"Path {path_num}"
    print(f"  {icon}  {WH}{B}{label}{R}  {DIM}{detail}{R}")
