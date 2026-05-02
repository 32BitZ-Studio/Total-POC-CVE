# CVE-2000-0649 for Apache
CVE-2000-0649 is a low risk vulnerability that can potentially disclose the internal IP addresses of the server from the Location parameter in the respose header. Official details are here:

* Rapid7:
https://www.rapid7.com/db/modules/auxiliary/scanner/http/iis_internal_ip/
* CVE:
https://www.cvedetails.com/cve/CVE-2000-0649/
* NIST:
https://nvd.nist.gov/vuln/detail/CVE-2000-0649

The vulnerability has been seen to be exploited on Microsoft IIS Servers, from 2.0 to 5.0 versions, but it hasn't been reported for Apache.

This script is made as PoC to extract local IP address of Apache 2.4.29 server, but it hasn't been tested on newer versions.

The following is a screenshot taken for this vulnerability.

![Poc Tested](poc-tested.png)

Reference:

Security Tracker Archives:
https://securitytracker.com/id/1002188

