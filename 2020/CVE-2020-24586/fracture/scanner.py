"""
scanner.py — Network discovery and fingerprinting
Channel-hops 1-13, collects APs and associated clients,
detects WPS, encryption type, and captive portal presence.
"""

import time, subprocess, threading
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import sniff, RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
except ImportError:
    raise SystemExit("Install scapy: sudo apt install python3-scapy")

from . import tui

# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class Network:
    bssid:   str
    ssid:    str        = "—"
    channel: int        = 0
    enc:     str        = "OPEN"   # OPEN / WEP / WPA / WPA2 / WPA3 / ENT
    wps:     bool       = False
    signal:  int        = -100
    portal:  bool       = False    # captive portal heuristic
    clients: list       = field(default_factory=list)
    vendor:  str        = ""       # OUI vendor string

@dataclass
class Client:
    mac:     str
    ap_bssid: str
    signal:  int = -100

# ── helpers ───────────────────────────────────────────────────────────────────

_OUI_DB = {}  # populated lazily

def _oui_lookup(mac: str) -> str:
    prefix = mac.upper().replace(':', '')[:6]
    return _OUI_DB.get(prefix, "")

def _rssi(pkt) -> Optional[int]:
    try:
        v = pkt[RadioTap].dBm_AntSignal
        return int(v) if v is not None else None
    except Exception:
        return None

def _parse_enc(pkt) -> str:
    """Detect encryption from capability flags and RSN/WPA IEs."""
    cap = pkt[Dot11Beacon].cap
    privacy = cap & 0x0010

    rsn  = pkt.getlayer(Dot11Elt, ID=48)  # RSN IE → WPA2/WPA3
    wpa1 = None

    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 0xDD and hasattr(elt, 'info') and len(elt.info) >= 4:
            if elt.info[:3] == b'\x00\x50\xf2' and elt.info[3] == 0x01:
                wpa1 = elt
                break
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break

    if rsn:
        # Check for SAE (WPA3) in AKM suite
        try:
            if b'\x00\x0f\xac\x08' in rsn.info:
                return "WPA3"
        except Exception:
            pass
        # Check for 802.1X (Enterprise)
        try:
            if b'\x00\x0f\xac\x01' in rsn.info:
                return "ENT"
        except Exception:
            pass
        return "WPA2"
    if wpa1:
        return "WPA"
    if privacy:
        return "WEP"
    return "OPEN"

def _parse_wps(pkt) -> bool:
    """Detect WPS IE (OUI 00:50:f2:04)."""
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 0xDD and hasattr(elt, 'info') and len(elt.info) >= 4:
            if elt.info[:4] == b'\x00\x50\xf2\x04':
                return True
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break
    return False

def _portal_heuristic(ssid: str, enc: str) -> bool:
    """
    Rough heuristic: open networks commonly have captive portals.
    Also flag SSIDs that look like public/commercial hotspots.
    """
    if enc == "OPEN":
        return True
    keywords = ['hotel', 'guest', 'wifi', 'hotspot', 'airport',
                'starbucks', 'hilton', 'marriott', 'lounge', 'attwifi']
    return any(k in ssid.lower() for k in keywords)

def _set_channel(iface: str, ch: int):
    subprocess.run(
        ["iwconfig", iface, "channel", str(ch)],
        capture_output=True, timeout=2
    )

# ── main scanner ──────────────────────────────────────────────────────────────

def scan(iface: str, dwell: float = 0.4, rounds: int = 2) -> list[Network]:
    """
    Hop channels 1-13 for `rounds` passes, collecting all APs and clients.
    Returns list of Network objects sorted by signal strength.
    """
    networks: dict[str, Network] = {}
    clients:  dict[str, Client]  = {}
    lock = threading.Lock()

    def handler(pkt):
        rssi = _rssi(pkt)

        # ── beacon / probe response → AP ──────────────────────────────────
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
            if not bssid:
                return
            bssid = bssid.lower()

            try:
                ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip() or "—"
            except Exception:
                ssid = "—"

            ch = 0
            try:
                elt = pkt[Dot11Elt]
                while elt and hasattr(elt, 'ID'):
                    if elt.ID == 3:
                        ch = elt.info[0]; break
                    elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                pass

            enc = _parse_enc(pkt) if pkt.haslayer(Dot11Beacon) else "?"
            wps = _parse_wps(pkt) if pkt.haslayer(Dot11Beacon) else False

            with lock:
                if bssid not in networks:
                    networks[bssid] = Network(bssid=bssid)
                n = networks[bssid]
                n.ssid    = ssid
                n.channel = ch or n.channel
                if enc != "?":
                    n.enc = enc
                n.wps    = wps or n.wps
                if rssi and rssi > n.signal:
                    n.signal = rssi
                n.portal = _portal_heuristic(n.ssid, n.enc)
                n.vendor  = _oui_lookup(bssid)
            return

        # ── data / mgmt frames → client association ────────────────────────
        if not pkt.haslayer(Dot11):
            return
        fc = pkt[Dot11].FCfield
        to_ds   = fc & 0x01
        from_ds = fc & 0x02
        addr1, addr2, addr3 = pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3
        if not addr1 or not addr2:
            return

        client_mac = ap_bssid = None
        if to_ds and not from_ds:      # client → AP
            client_mac = addr2.lower()
            ap_bssid   = addr1.lower()
        elif not to_ds and from_ds:    # AP → client
            client_mac = addr1.lower()
            ap_bssid   = addr2.lower()
        else:
            return

        if client_mac.startswith('ff:') or ap_bssid.startswith('ff:'):
            return

        with lock:
            if ap_bssid in networks:
                c = clients.get(client_mac)
                if c is None:
                    clients[client_mac] = Client(mac=client_mac, ap_bssid=ap_bssid,
                                                  signal=rssi or -100)
                    if client_mac not in networks[ap_bssid].clients:
                        networks[ap_bssid].clients.append(client_mac)
                elif rssi and rssi > c.signal:
                    c.signal = rssi

    channels = list(range(1, 14))
    total_steps = rounds * len(channels)
    step = 0

    tui.info(f"Scanning {len(channels)} channels × {rounds} passes…")
    print()

    for _ in range(rounds):
        for ch in channels:
            _set_channel(iface, ch)
            sniff(iface=iface, prn=handler, timeout=dwell, store=False)
            step += 1
            pct = int(step / total_steps * 100)
            bar_w = 40
            filled = int(step / total_steps * bar_w)
            bar = f"\033[91m{'█' * filled}\033[2m{'░' * (bar_w - filled)}\033[0m"
            found = len(networks)
            print(f"  {bar}  {pct:>3}%  {found} APs", end='\r')

    print()

    result = sorted(networks.values(), key=lambda n: n.signal, reverse=True)
    return result
