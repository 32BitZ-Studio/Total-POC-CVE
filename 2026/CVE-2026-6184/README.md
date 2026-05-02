# Stored XSS in News Title - Simple Content Management System PHP

## Description
A Stored Cross-Site Scripting (XSS) vulnerability exists in Simple 
Content Management System PHP. The News Title field in the admin 
panel does not sanitize user input before storing it in the database 
and reflecting it on the public index page. Any visitor who browses 
the main page will trigger the stored XSS payload, allowing an 
attacker to steal session cookies and hijack accounts.

---

## Vulnerability Details
- **Type:** Stored Cross-Site Scripting (CWE-79)
- **Impact:** Session Hijacking / Cookie Theft
- **Affected File:** `/web/admin/welcome.php`
- **Affected Parameter:** News Title field
- **Attack Vector:** Remote, Authenticated (Admin)
- **Triggered On:** `/web/index.php` (public, unauthenticated)

---

## Vendor
code-projects.org

## Product
Simple Content Management System PHP

## Version
1.0

---

## Proof of Concept (PoC)

### Step 1 - Login to admin panel and go to Add News:
http://[target]/web/admin/welcome.php?addnews

### Step 2 - Enter XSS payload in News Title field:
<script>alert(document.cookie)</script>

### Step 3 - Submit the form:
<img width="1920" height="1080" alt="Screenshot 2026-04-05 051828" src="https://github.com/user-attachments/assets/94575afc-584a-4e71-9f07-f247f97179f1" />


### Step 4 - Visit the public index page:
http://[target]/web/index.php

### Step 5 - XSS executes and leaks session cookies:
<img width="1920" height="1080" alt="Screenshot 2026-04-05 051844" src="https://github.com/user-attachments/assets/58a38de2-41e5-43a6-a976-f7af0e417877" />


---

## Impact
Any user visiting the public index page will have their session 
cookies exposed to the attacker. This allows full session hijacking 
and account takeover of any logged in user including administrators.

---

## Author
Imad Alvi

---

## Refernce
https://code-projects.org/simple-content-management-system-in-php-with-source-code/
