# Human Resource Management System Project in PHP and MySQL Free Source Code
#### Submitter: Kha Do

## Vulnerability
Insecure Permission

## Description
Insecure permission vulnerability in /hrm/leaverequest.php in SourceCodester Human Resource Management System 1.0 allow attackers to approve or reject leave ticket.

## Affected component
Path URL: /hrm/leaverequest.php

Parameter: **?msg=**, **?id=**

## Impact
The normal user can self-approve or reject leave ticket, which is not permitted.

**id:** accept ticket.

**msg:** reject ticket.

## PoC

https://github.com/dovankha/CVE-2024-34223/assets/63991630/05efa194-bcc4-4ecf-bf47-8316fae2452a


