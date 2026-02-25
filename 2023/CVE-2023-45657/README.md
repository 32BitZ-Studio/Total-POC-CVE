# CVE-2023-45657
Nexter &lt;= 2.0.3 - Authenticated (Subscriber+) SQL Injection via 'to' and 'from'

Description:

The Nexter theme for WordPress is vulnerable to  SQL Injection via the 'to' and 'from' parameters in versions up to, and including, 2.0.3 due to insufficient escaping on the user supplied parameter and lack of valid preparation on the existing SQL query.  This makes it possible for authenticated attackers, with subscriber-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

```
Severity: high
CVE ID: CVE-2023-45657
CVSS Score: 8.8
CVSS Metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Plugin Slug: nexter
WPScan URL: https://www.wpscan.com/plugin/nexter
Reference URL: https://www.wordfence.com/threat-intel/vulnerabilities/id/a0164123-11b0-4b3b-bc76-c6aee8ca9d34?source=api-prod
```


How to run
---
```
python3 CVE-2023-45657.py --url http://wordpress.lan -u user -p useruser1
```
