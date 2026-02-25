# ABO.CMS-Login-SQLi-CVE-2024-25227

<h2>Unauthenticated SQLi and Login Bypass</h2>
<h2>CVE-2024-25227</h2>

**Date: 23/02/2024**

**Tested on ABO.CMS 5.8**

**Vendor: ABO.CMS**

**Vendor URL: https://abocms.ru**

*ABO.CMS 5.8 is vulnerable to SQL Injection via the tb_login parameter, admin login page.*



*The affected component is "tb_login" parameter, admin login page*

*It is likely vulnerabable on other editions*

*The attack type is remote with the attack vector being a post request in admin login page(s) with the parameter "tb_login"*

Description:

ABO.CMS 5.8 SQLi,

SQL injection vulnerabiolity in ABO.CMS, it passes unsafe SQL queries into the backend resulting in Injection.

In an admin page(s) using a POST request in the "tb_login" perameter.

During my testing the CMS seemed to allow these types of SQL injection:

boolean-based blind, error-based, stacked queries, time-based blind and union queries.

With this it is possible to takeover the database server in its entirety (under specific conditions, xp_cmdshell etc) 

The test enviroment was IIS 7.5/8.5 with MSSQL Server 2008 RP2 SP3 running ASPx, PHP etc.

SQLi is likely exploitable in past edditions of the CMS software, but I have only tested this vulnerability on edition 5.8.

(Exploit is **here**: https://github.com/thetrueartist/ABO.CMS-EXPLOIT-Unauthenticated-Login-Bypass-CVE-2024-25227/tree/main)
