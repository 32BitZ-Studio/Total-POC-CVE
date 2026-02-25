# CVE-2023-23752
simple bash script for CVE-2023-23752 (joomla CMS)
You can use the `-u` option to specify a single URL or the `-l` option to provide a file containing a list of URLs to test the vulnerable endpoint.
This script saves all HTTP response data and displays sensitive information. 
dependancy: httpx (before using this script install [httpx](https://github.com/projectdiscovery/httpx) tool)<br>
examples:
```
./cve-2023-23752-PoC.sh -u https://vuln-site-example.com
./cve-2023-23752-PoC.sh -l list.txt
```

cve reference:https://cve.report/CVE-2023-23752<br>
author: whiteOwl<br>
enjoy!
