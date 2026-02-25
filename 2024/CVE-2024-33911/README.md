
# The School Management 10.3.4 - Post-Authenticated SQL Injection

**Exploit Title:** The School Management 10.3.4 - Post-Authenticated SQL Injection  
**Date:** 29 April, 2024  
**Exploit Author:** Ivan Spiridonov (xbz0n)  
**Vendor Homepage:** https://theschool-management.com  
**Version:** 10.3.4  
**Tested on:** Ubuntu 22.04  
**CVE:** CVE-2024-33911

## Vulnerability

The School Management plugin, version 10.3.4, developed by Weblizar for WordPress, is vulnerable to Post-Authenticated SQL Injection via the 'order%5B0%5D%5Bdir%5D' parameter in the /wp-admin/admin-ajax.php endpoint. This vulnerability results from insufficient escaping of the user-supplied parameter and a lack of proper preparation of the SQL query. Such a vulnerability allows authenticated attackers to inject and execute arbitrary SQL commands, which could lead to unauthorized access to or manipulation of database information.


## Affected Components

- **Plugin:** The School Management
- **Version:** 10.3.4
- **Affected Parameter:** 'order%5B0%5D%5Bdir%5D'
- **Affected Endpoint:** /wp-admin/admin-ajax.php

## Description

The vulnerability is found in the 'order%5B0%5D%5Bdir%5D' parameter within the admin AJAX endpoint. By manipulating this parameter, authenticated attackers can inject SQL commands, leading to a time-based SQL Injection vulnerability.

## Proof of Concept

### Manual Exploitation

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
[Additional Headers]
draw=3&[Other Parameters]&order%5B0%5D%5Bdir%5D=asc%2c(select*from(select(sleep(20)))a)
```

If the server response is delayed by approximately 20 seconds, it indicates a successful exploitation of the time-based SQL Injection, confirming the vulnerability.

## Recommendations

Users of The School Management v10.3.4 are strongly advised to restrict access to the affected endpoint and update the plugin to the latest version. Additionally, it is crucial to implement proper input validation and sanitization checks. Using prepared statements or parameterized queries to handle SQL commands can help mitigate such vulnerabilities.
