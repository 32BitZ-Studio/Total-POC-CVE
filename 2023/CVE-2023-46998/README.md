# Cross Site Scripting in Bootbox.js v.3.2 thru 6.0 allows a remote attacker to to inject HTML code and execute arbitrary JavaScript.

## Summary
Vendor: BootBox

Product: bootbox.js

Affected version(s): 3.2 to 6.0

CodeName: Venga-Que-Si-Es-Pa-Eso

## Vulnerability
Type: Improper Neutralization of Input During Web Page Generation 'Cross-site Scripting' (CWE-79)

CVSSv3.1 Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N

CVSSv3.1 Base Score: 5.4 (Medium)

Exploit Available: Yes

CVE ID: CVE-2023-46998

## Description
Functions like alert(), confirm(), prompt() does not sanitize user input in the provided dialog boxes, allowing attackers to inject HTML code and execute arbitrary JavaScript via use Jquery

## Poc
### Steps to reproduce
Insert `<script>alert('Hola BB :*')</script>` into a vulnerable function like prompt. Vulnerable code available here: https://jsfiddle.net/93sk1zeh/2/

## Exploit
`<script>alert('Hola BB :*')</script>`

## Mitigation
Sanitize input before adding it to a DOM element using jquery

## References
https://github.com/bootboxjs/bootbox/issues/661

## Timeline
2018-05-28: Vulnerability reported to vendor.

2023-10-01: CVE ID assigned
