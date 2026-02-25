# CVE-2023-47179
WooODT Lite &lt;= 2.4.6 - Missing Authorization to Arbitrary Options Update (Subscriber+)


### Description:
The WooODT Lite plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the byconsolewooodt_admin_fields_setting_files() function hooked via AJAX in versions up to, and including, 2.4.6. This makes it possible for authenticated attackers, with subscriber-level access and above, to modify arbitrary site options which can easily be leveraged for privilege escalation.

```
Severity: high
CVE ID: CVE-2023-47179
CVSS Score: 8.8
CVSS Metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Plugin Slug: byconsole-woo-order-delivery-time
WPScan URL: https://www.wpscan.com/plugin/byconsole-woo-order-delivery-time
Reference URL: https://www.wordfence.com/threat-intel/vulnerabilities/id/9939f297-e3ca-4d7d-9acd-c416ee2014c9?source=api-prod
```


Usage
---

```
usage: exploit.py [-h] -u URL [-un USERNAME] [-p PASSWORD] [-f FIX]

WooODT Lite <= 2.4.6 - Missing Authorization to Arbitrary Options Update Description: The WooODT Lite plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the byconsolewooodt_admin_fields_setting_files() function hooked via AJAX in
versions up to, and including, 2.4.6. This makes it possible for authenticated attackers, with subscriber-level access and above, to modify arbitrary site options which can easily be leveraged for privilege escalation. CVE-2023-47179

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Website URL
  -un USERNAME, --username USERNAME
                        WordPress username
  -p PASSWORD, --password PASSWORD
                        WordPress password
  -f FIX, --fix FIX     Reset after Exploit
```
