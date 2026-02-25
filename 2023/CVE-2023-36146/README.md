# CVE-2023-36146

PoC of CVE-2023-36146 - Multilaser RE 170 Firmware 2.2.6733

## Authenticated stored Cross Site Scripting


## Steps to Reproduce:

1. Log in the equipment via your web browser
2. Go to Security > IP Filtering
3. In the "Description" field inject the payload "<image/src/onerror=prompt(8)>"
4. Click Add
5. Exploit!
