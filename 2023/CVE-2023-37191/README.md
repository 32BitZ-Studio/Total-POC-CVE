# CVE-2023-37191 — Issabel PBX 4.0.0-6: Stored Cross-Site Scripting (XSS)

## Overview

| Field | Details |
|---|---|
| **CVE ID** | [CVE-2023-37191](https://nvd.nist.gov/vuln/detail/CVE-2023-37191) |
| **Product** | Issabel PBX (`issabel-pbx`) |
| **Affected Version** | 4.0.0-6 |
| **Vulnerability Type** | Stored Cross-Site Scripting (XSS) |
| **Severity** | Medium |
| **Discovery Date** | 7 July 2023 |
| **Discovered By** | Sahil Ojha |
| **Vendor Homepage** | https://www.issabel.org/ |
| **Source Code** | https://github.com/IssabelFoundation/issabelPBX |
| **Tested On** | Windows |

---

## Description

A **Stored Cross-Site Scripting (XSS)** vulnerability exists in **Issabel PBX version 4.0.0-6**. The application fails to properly sanitize or encode user-supplied input before storing it in the database and later rendering it in the browser. This allows an authenticated attacker to inject arbitrary JavaScript or HTML code via the **Group** and **Description** input fields found under **System → Users → Groups**.

Once the malicious payload is saved, it is persistently stored on the server. Every time any user (including administrators) visits the affected page, the injected script is automatically executed within their browser session — without any further action required from the attacker. This is what distinguishes a **Stored (Persistent) XSS** from a Reflected XSS; the impact is broader and more dangerous because the payload affects all visitors of the page.

---

## Vulnerability Details

- **Component:** `System → Users → Groups` module of the Issabel PBX web interface
- **Vulnerable Parameters:** `Group` (name field) and `Description` (text field)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** Low (authenticated user)
- **User Interaction:** Required (victim must visit the injected page)
- **Scope:** Changed (script executes in victim's browser context)

---

## Impact

A successful exploitation of this vulnerability can allow an attacker to:

- **Session Hijacking:** Steal authenticated session cookies, enabling account takeover without knowing the user's password.
- **Credential Harvesting:** Inject fake login forms or redirect users to phishing pages to capture credentials.
- **Persistent Defacement:** Permanently alter the visual appearance of the application for all users.
- **Malicious Redirection:** Silently redirect victims to attacker-controlled domains hosting malware or phishing content.
- **Keylogging:** Capture keystrokes entered by victims on the affected page.
- **Unauthorized Actions:** Perform actions on behalf of the victim (e.g., creating backdoor admin accounts, modifying system configuration) using their session privileges.

Because the payload is **stored on the server**, every user who visits the compromised page is affected — amplifying the damage compared to a reflected XSS attack.

---

## Proof of Concept (PoC)

### Prerequisites

- Access to an Issabel PBX 4.0.0-6 instance
- An account with permission to manage Users/Groups (e.g., administrator credentials)

### Steps to Reproduce

**Step 1:** Log in to the Issabel PBX web interface using administrator credentials.

**Step 2:** Navigate to **System → Users → Groups**. In the **Group** and/or **Description** input fields, enter the following XSS payload:

```html
"><script>alert(1)</script>
```

The fields should look similar to the screenshot below:

![Payload injected into Group and Description fields](https://github.com/sahiloj/CVE-2023-37191/blob/main/1.png)

**Step 3:** Click **Save**. The payload is now persistently stored in the application's database.

**Step 4:** Navigate back to the **System → Users → Groups** page (or have any other user visit it). The injected script executes automatically in the browser, as shown below:

![XSS payload executing in the browser](https://github.com/sahiloj/CVE-2023-37191/blob/main/2.png)

---

## Remediation

To mitigate this vulnerability, the Issabel PBX development team should apply the following fixes:

1. **Input Validation:** Strictly validate all user-supplied input server-side. Reject or sanitize values that contain HTML special characters (`<`, `>`, `"`, `'`, `&`) in fields that do not require HTML formatting.

2. **Output Encoding:** When rendering stored data back to the browser, apply context-aware output encoding (e.g., HTML entity encoding) to neutralize any injected markup. Since Issabel PBX is PHP-based, use PHP's built-in `htmlspecialchars()` or `htmlentities()` functions rather than custom filtering.

3. **Content Security Policy (CSP):** Implement a strict Content Security Policy HTTP header to limit the sources from which scripts can be executed. A properly configured CSP can prevent injected scripts from running even if input sanitization is bypassed.

4. **Regular Security Audits:** Conduct periodic code reviews and penetration tests to identify and remediate injection vulnerabilities across the entire application.

---

## References

- [NVD — CVE-2023-37191](https://nvd.nist.gov/vuln/detail/CVE-2023-37191)
- [OWASP — Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Issabel Foundation — issabelPBX on GitHub](https://github.com/IssabelFoundation/issabelPBX)

---

## Disclaimer

This information is provided for **educational and research purposes only**. The author is not responsible for any misuse of this information. Always obtain proper written authorization before testing vulnerabilities on any system you do not own.
