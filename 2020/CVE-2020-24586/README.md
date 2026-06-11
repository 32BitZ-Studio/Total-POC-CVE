# Fracture

**FragAttacks WiFi Penetration Framework**  
CVE-2020-24586 / CVE-2020-24587 / CVE-2020-24588

Fracture automates three novel attack chains via 802.11 frame injection. It exploits the A-MSDU aggregation vulnerability in WPA2/WPA3 to inject arbitrary plaintext frames into encrypted networks — **without knowing the password**.

> **For authorized penetration testing only. Only use against networks you own or have explicit written permission to test.**

---

## How It Works

The A-MSDU present flag in 802.11 QoS Control is not covered by CCMP/GCMP authentication. By setting this flag in a crafted frame, an attacker causes the receiver to interpret the payload as an inner ethernet frame, bypassing encryption entirely.

Fracture uses this primitive to power three attack paths:

### Path 1 — Router Admin Injection
Injects HTTP requests directly to the router's management interface (192.168.x.1 and common variants) from outside the network. Tries default credentials and known unauthenticated CVE endpoints across TP-Link, D-Link, Netgear, and ASUS firmware. Silent — no deauth, no detectable signature.

### Path 2 — DNS Injection → Cloned Portal → Credential Harvest
Detects captive portal networks, clones the portal page, then injects spoofed DNS responses to redirect connected clients. When a client submits credentials to the clone, Fracture captures them and uses them to authenticate legitimately. Targets hotel WiFi, corporate guest networks, cafe hotspots.

### Path 3 — UPnP AddPortMapping
Injects UPnP SSDP discovery and SOAP AddPortMapping commands. Most home routers accept these without authentication. If successful, opens an external port on the router's WAN interface forwarded to an internal client's SSH — providing inbound access from anywhere without ever touching the WiFi password.

---

## Requirements

- Linux (Kali recommended)
- Python 3.10+
- WiFi adapter with monitor mode + injection support (e.g. Alfa AWUS036H)
- Root privileges

```bash
sudo apt install python3-scapy python3-requests python3-bs4 python3-flask
```

---

## Install

```bash
git clone https://github.com/fracture-wifi/fracture
cd fracture
sudo pip3 install -e . --break-system-packages
```

After install, `fracture` is available as a system command.

---

## Usage

```bash
# Put adapter in monitor mode first
sudo iwconfig wlan1 mode monitor

# Full auto — scan, select target, run all applicable paths
sudo fracture -i wlan1

# Scan only — no attacks
sudo fracture -i wlan1 --scan-only

# Lock to a specific target
sudo fracture -i wlan1 -t AA:BB:CC:DD:EE:FF

# Force a specific path
sudo fracture -i wlan1 --path 1    # router admin
sudo fracture -i wlan1 --path 2    # portal harvest
sudo fracture -i wlan1 --path 3    # UPnP

# Verbose injection log
sudo fracture -i wlan1 -v

# Detailed help
sudo fracture --about
```

---

## Most Vulnerable Targets

| Target | Why |
|--------|-----|
| Home routers (TP-Link, D-Link, Netgear, ASUS) | Stock firmware, default creds, UPnP enabled |
| IoT devices | Almost never patched post-2021 |
| Captive portal networks | Hotel/cafe WiFi designed around credential submission |
| Linux kernel < 5.12.4 | Pre-patch kernel |
| Windows pre-June 2021 | Pre-patch OS |

Enterprise gear (Cisco, Aruba, Ruckus, Ubiquiti) is generally patched.

---

## What Fracture Does Not Do

- No deauth floods (won't trigger WIDS deauth signatures)
- No WPA handshake capture or cracking
- No WiFi password brute force

---

## Project Structure

```
fracture/
├── fracture/
│   ├── __init__.py     version, metadata
│   ├── __main__.py     entry point, orchestration
│   ├── tui.py          terminal UI, colors, tables
│   ├── scanner.py      channel-hopping AP/client discovery
│   ├── injector.py     FragAttacks frame engine (CVE-2020-24588)
│   ├── portal.py       portal detection, cloning, credential server
│   └── paths.py        the three attack chains
├── setup.py
└── README.md
```

---

## References

- [FragAttacks — Mathy Vanhoef (2021)](https://fragattacks.com)
- CVE-2020-24586, CVE-2020-24587, CVE-2020-24588
- [Original FragAttacks paper (IEEE S&P 2021)](https://papers.mathyvanhoef.com/usenix2021.pdf)

---

## License

MIT
