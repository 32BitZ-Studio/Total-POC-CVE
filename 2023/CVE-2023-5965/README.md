# PoC for Espo CRM 7.2.4 CVE-2023-5965 & CVE-2023-5965

## CVE-2023-5965

[Advisory](https://vulmon.com/vulnerabilitydetails?qid=CVE-2023-5965&scoretype=cvssv3)

``An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the update form, which could lead to arbitrary PHP code execution.``

- To upload the file go to Administration => Upgrades
  ![image](https://github.com/josemlwdf/CVE-2023-5965/assets/60181010/ebe1293b-d749-4a12-b1f4-41de2b222b5e)

## CVE-2023-5966

[Advisory](https://vulmon.com/vulnerabilitydetails?qid=CVE-2023-5966&scoretype=cvssv3)

``An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the extension deployment form, which could lead to arbitrary PHP code execution.``
- To upload the file go to Administration => Extensions
  ![image](https://github.com/josemlwdf/CVE-2023-5965/assets/60181010/56087c0c-3c47-46c7-bda5-9004c85a2c3b)
  ![image](https://github.com/josemlwdf/CVE-2023-5965/assets/60181010/a3c6668d-a812-4ba3-83a1-acf8737bc3d6)

## PoC

- The zip files on this repo upload a web shell to /webshell.php

``Ex:``
 
     https://localhost/espocrm/webshell.php?cmd=id
