# CVE-2024-35469
#### Submitter: Kha Do

## Human Resource Management System 1.0

## Vulnerability
SQL injection

## Description
SQL injection vulnerability in /hrm/user/ in SourceCodester Human Resource Management System 1.0 allow attackers to execute arbitrary SQL commands via the password parameters.

## Affected component
/hrm/user/

## Impact
The attacker can use payload `'or'1'='1` login with administrator account without credentials.

## POC
Login with anonymous
![SQL_bypass_login](https://github.com/dovankha/SQLi_Login_User/assets/63991630/789f57b7-ca51-4e1c-b9ca-f0c880f003a3)


Source code contain vulnerability
![Source_code_SQLi](https://github.com/dovankha/SQLi_Login/assets/63991630/6ff51ab9-c33f-413b-bf18-52bf06388067)


### Video

https://github.com/dovankha/SQLi_Login_User/assets/63991630/63129397-26e9-47fa-a2bc-0748fcc03c6b




