# CVE-2024-1301 --- Badgermeter moni tool - SQL Injection
https://www.incibe.es/en/incibe-cert/notices/aviso-sci/multiple-vulnerabilities-badger-meters-monitool

CVE-2024-1301: 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | CWE-89.

**Software link**: https://www.s-can.at/en/product/monitool/

**Version**: 4.6.3

**@author**: Guillermo García Molina

**Description**: In s:can moni:tools up to and including version 4.6.3, an unauthenticated attacker could get full access to the database through SQL injection. This may result in loss of confidentiality, loss of integrity and DoS.

## POC

The parameter j_username which is included in the login request, is affected by a sql injection vulnerability. In the following picture is shown the request where the payload test'+AND+1=(SELECT+1+FROM+PG_SLEEP(10))+AND+'GKZy'='GKZy&j_password=test is included, forcing the database to wait 10 second before sending the response:

![image](https://github.com/guillermogm4/CVE-2024-1301---Badgermeter-moni-tool-SQL-Injection/assets/26895345/ad91b996-49ee-44d7-a2eb-e62de653421a)

![image](https://github.com/guillermogm4/CVE-2024-1301---Badgermeter-moni-tool-SQL-Injection/assets/26895345/93c6cbf9-5687-45f2-a3ad-c1b4f3a7bd8c)

Using blind sqli injection technique (https://owasp.org/www-community/attacks/Blind_SQL_Injection), it has been possible to dump all the data of the database, for example dumping the User table of the ipc database:

![image](https://github.com/guillermogm4/CVE-2024-1301---Badgermeter-moni-tool-SQL-Injection/assets/26895345/879dfb0c-2bf0-4269-bb02-c628f017fb08) 
