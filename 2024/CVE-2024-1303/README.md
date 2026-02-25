# CVE-2024-1303 --- Badgermeter moni tool - Path-Traversal
https://www.incibe.es/en/incibe-cert/notices/aviso-sci/multiple-vulnerabilities-badger-meters-monitool

CVE-2024-1303: 6.5 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | CWE-22.

**Software link**: https://www.s-can.at/en/product/monitool/

**Version**: 4.6.3

**@author**: Guillermo García Molina

**Description**: In s:can moni:tools up to and including version 4.6.3, an authenticated attacker could get any file from the device by path traversal in the download-file functionality.

## POC

The Download files functionality, found in (Service>Output>Export Data>Files), is used to download different documents from the application. When these documents are selected and the button “Download files” is pressed, a compressed file with the requested documents is downloaded:
 
![image](https://github.com/guillermogm4/CVE-2024-1303---Badgermeter-moni-tool-Path-Traversal/assets/26895345/aa1bfaea-e7c6-487d-98c1-72d7c85e51c0)

The parameter names, which is found in the request performed to the server, is affected by a path traversal vulnerability. As it is shown in the following pictures, injecting the payload ../../../../../etc/passwd in the vulnerable parameter of the request performed to the export-autofiles-download.x endpoint, downloads a compressed file with /etc/passwd.
 
![image](https://github.com/guillermogm4/CVE-2024-1303---Badgermeter-moni-tool-Path-Traversal/assets/26895345/1948fb0b-8a2f-4020-8c2c-400bd80bac5e)
 
![image](https://github.com/guillermogm4/CVE-2024-1303---Badgermeter-moni-tool-Path-Traversal/assets/26895345/af7bbafa-7293-46c1-85b1-f103a0333e3f)

![image](https://github.com/guillermogm4/CVE-2024-1303---Badgermeter-moni-tool-Path-Traversal/assets/26895345/6a415a19-5f0e-47aa-93f9-8172fd954b63)
 
![image](https://github.com/guillermogm4/CVE-2024-1303---Badgermeter-moni-tool-Path-Traversal/assets/26895345/3d3b0978-a6f6-4456-9ad6-29c8e7dfa830)

