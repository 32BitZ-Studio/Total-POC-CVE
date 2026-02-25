# CVE-2023-34837 — eScan Management Console: Reflected Cross-Site Scripting (XSS)

![CVE](https://img.shields.io/badge/CVE-2023--34837-red) ![Severity](https://img.shields.io/badge/Severity-Medium-orange) ![Type](https://img.shields.io/badge/Type-Reflected%20XSS-blue) ![Vendor](https://img.shields.io/badge/Vendor-Microworld%20Technologies-lightgrey)

---

## Overview

**CVE-2023-34837** is a **Reflected Cross-Site Scripting (XSS)** vulnerability discovered in the **Microworld Technologies eScan Management Console** version `14.0.1400.2281`. The vulnerability exists in the `GrpPath` POST parameter within the *Unmanaged Computers → Network Computers* feature. Because user-supplied input is reflected in the server response without adequate sanitisation or output encoding, an attacker can craft a malicious request that causes arbitrary JavaScript to execute in the victim's browser session.

Reflected XSS vulnerabilities are particularly dangerous in management consoles because:

- Authenticated sessions carry elevated privileges.
- Successful exploitation can lead to **session hijacking**, **credential theft**, **malware delivery**, or full **account takeover**.
- The attack can be triggered by tricking an authenticated administrator into clicking a crafted link or intercepting and modifying an in-flight request.

---

## Vulnerability Details

| Field | Value |
|---|---|
| **CVE ID** | CVE-2023-34837 |
| **Affected Product** | Microworld Technologies eScan Management Console |
| **Affected Version** | 14.0.1400.2281 |
| **Vulnerability Type** | Reflected Cross-Site Scripting (XSS) |
| **Vulnerable Parameter** | `GrpPath` (HTTP POST body) |
| **Attack Vector** | Network (requires authenticated session) |
| **Severity** | Medium |
| **Reported Date** | 23 June 2023 |
| **Researcher** | Sahil Ojha |
| **Vendor Homepage** | https://www.escanav.com |
| **Software Download** | https://cl.escanav.com/ewconsole.dll |
| **Tested On** | Windows |

---

## Technical Background

### What is Reflected XSS?

Reflected XSS occurs when an application takes user-supplied data (usually from an HTTP request parameter) and immediately includes it in the HTTP response without proper validation or encoding. Unlike Stored XSS, the malicious payload is not persisted in the database — it is *reflected* back to the user in the same request/response cycle.

### Root Cause

The eScan Management Console fails to sanitise or HTML-encode the value of the `GrpPath` parameter before including it in the page response. This means that special characters such as `<`, `>`, and `"` are passed through verbatim, allowing an attacker to break out of the intended HTML context and inject executable JavaScript.

### Impact

A successful exploit allows the attacker to:

- **Steal session cookies** — gaining full access to the administrator's session.
- **Perform actions on behalf of the victim** — add users, change configurations, deploy policies, etc.
- **Redirect the victim** to a phishing or malware-hosting page.
- **Log keystrokes** or capture form data entered by the administrator.

---

## Proof of Concept

### Vulnerable Endpoint

```
POST /[endpoint] HTTP/1.1
Host: <escan-console-host>
Content-Type: application/x-www-form-urlencoded
Cookie: <session-cookie>

GrpPath=<XSS_PAYLOAD>&...
```

### Example Payload

The following payload injects a `<script>` tag that displays the current document cookie — demonstrating that script execution is possible in the context of the authenticated session:

```html
<script>alert(document.cookie)</script>
```

> **Note:** In a real attack scenario, the `alert()` call would be replaced with code that silently exfiltrates the cookie to an attacker-controlled server.

---

## Steps to Reproduce

> **Prerequisites:** Access to the eScan Management Console with a valid user/admin credential and an HTTP interception proxy (e.g., Burp Suite).

**Step 1 — Log in to the eScan Management Console.**

Access the console on the internal network with valid credentials and navigate to:
**Unmanaged Computers → Network Computers**

![Step 1 – Navigate to Network Computers](https://github.com/sahiloj/CVE-2023-34837/blob/main/1.png)

---

**Step 2 — Intercept the POST request in Burp Suite.**

Enable your proxy, trigger the **Network Computer scan / group path lookup action** in the console (e.g., browsing or expanding the group tree), and capture the outgoing POST request. Locate the `GrpPath` parameter in the request body and replace its value with the XSS payload:

```
GrpPath=<script>alert(document.cookie)</script>
```

![Step 2 – Inject payload into GrpPath](https://github.com/sahiloj/CVE-2023-34837/blob/main/2.png)

---

**Step 3 — Forward the request and observe script execution.**

After forwarding the modified request, the injected script executes in the browser. An alert box appears displaying the current user's session cookie, confirming successful XSS exploitation.

![Step 3 – XSS alert with session cookie](https://github.com/sahiloj/CVE-2023-34837/blob/main/3.png)

---

## Remediation / Mitigation

The following measures are recommended to mitigate this vulnerability:

1. **Input Validation** — Reject or strip any characters that are not expected in the `GrpPath` field (e.g., allow only alphanumeric characters, dots, and slashes for path values).
2. **Output Encoding** — HTML-encode all user-supplied data before rendering it in an HTTP response. At a minimum, encode `<`, `>`, `"`, `'`, and `&`.
3. **Content Security Policy (CSP)** — Deploy a strict CSP header to restrict the sources from which scripts can be loaded and block inline script execution.
4. **Web Application Firewall (WAF)** — Use a WAF with XSS detection rules as a defence-in-depth measure.
5. **Vendor Patch** — Check the [eScan website](https://www.escanav.com) for security advisories and apply the latest available update.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 23 June 2023 | Vulnerability discovered and reported |
| — | CVE-2023-34837 assigned |

---

## References

- [CVE-2023-34837 – NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-34837)
- [Microworld Technologies – eScan](https://www.escanav.com)
- [OWASP – Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## Disclaimer

This repository is published for **educational and research purposes only**. The information provided is intended to help security professionals understand the vulnerability so that affected systems can be secured. **Do not use this information to attack systems you do not own or have explicit written permission to test.** The author assumes no liability for any misuse of the information contained herein.
