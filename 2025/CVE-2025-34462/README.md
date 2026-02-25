
# BLE Smart Lock Denial-of-Service (DoS) Vulnerability

> An unauthenticated Bluetooth Low Energy (BLE) connection flood can reliably prevent legitimate users from unlocking the device by interrupting keypad input and forcing repeated lockout states.

---

## 📌 Summary

This repository documents a **Denial-of-Service (DoS)** vulnerability affecting a commercial BLE smart padlock  
([Amazon Product](https://www.amazon.com/dp/B0F9L1M4XG)).

The device exposes a **static BLE MAC address (no RPA)** and accepts unauthenticated connection attempts.  
By repeatedly initiating BLE connections in a loop, an attacker can interfere with the lock’s keypad authentication flow, preventing users from completing PIN entry.

This behavior is **not caused by incorrect password attempts** — the user is denied sufficient time to enter the PIN before the device forcibly enters a lockout state.

---

## 🔥 Impact

- ❌ Prevents legitimate users from unlocking the device  
- ⛔ Keypad becomes unresponsive mid‑input  
- 🔁 Forced lockout occurs every **10–15 seconds**  
- 🧠 Lockout is triggered **by BLE interference**, not invalid PIN attempts  
- 🔓 Works on both default and custom configurations  
- 📡 Target uses a **static MAC address**, allowing persistent tracking  
- 🚫 No pairing or authentication required  

As long as the attack is sustained, the device remains effectively unusable.

---

## 🧪 Attack Prerequisites

- BLE-capable Linux  
- Python 3.x  
- `bleak` Python library  
- Target MAC address (device must broadcast it after physical button press)

---

## 🚀 Proof of Concept (PoC)

### Step 1: Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install bleak
```

### Step 2: Run the Attack
```bash
python3 poc.py -m <target_mac>
```

This initiates unauthenticated BLE connection attempts in a loop.  
The lock becomes unusable, consistently interrupting user input and forcing lockout behavior.

---

## 📷 Demo

Below is a still image from a live attack session where the device's keypad was rendered non-functional:

![Attack in action](attack_live.jpg)

---

## 🛑 Legal Disclaimer

This proof-of-concept is provided **strictly for educational and responsible disclosure purposes**.

- Do **not** test this on devices you don’t own or lack permission to assess  
- This tool must **not** be used for malicious activity  
- The author takes **no responsibility for misuse**

This vulnerability is being reported responsibly to the vendor and relevant CVE authorities.

---

## 🕒 Disclosure Timeline

- Vulnerability discovered: 2025  
- Reported to: MITRE + VulnCheck  
- CVE status: **Assigned**  
- Researcher: **nsm_barii**  
  GitHub: https://github.com/nsm-barii

---

## 🔗 References

- Amazon Product: https://www.amazon.com/dp/B0F9L1M4XG  
- GitHub Repo: https://github.com/nsm-barii/CVE-2025-34462
