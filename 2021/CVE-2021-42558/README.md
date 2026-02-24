# CVE-2021-42558: Multiple Cross-Site Scripting in MITRE Caldera

Caldera (versions <=2.8.1) contains multiple reflected, stored and self XSS vulnerabilities that may be exploited by authenticated and unauthenticated attackers.

### Vendor Disclosure:

The vendor's disclosure for this vulnerability can be found [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42558).

### Requirements:

This vulnerability requires:
<br/>
- Some XSSs require valid user credentials

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2021-42558/blob/main/Caldera%20-%20CVE-2021-42558.pdf).

### Additional Information:

The XSS vector "1.1. Unauthenticated Stored XSS in Agent" was also found in paralel and fixed by [Daniel "uruwhy" Matthews](https://github.com/uruwhy) in this [Caldera commit](https://github.com/mitre/caldera/commit/7d3dedb8a03cb2fcddbcb292b7ca8b8c31af62e5).
