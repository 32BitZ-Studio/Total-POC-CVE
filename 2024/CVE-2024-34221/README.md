# Human Resource Management System Project in PHP and MySQL Free Source Code
#### Submitter: Kha Do

## Vulnerability
Insecure permission

## Description
There is an insecure permission vulnerability in `/hrm/controller/ccity.php?positionedit=` in the SourceCodester Human Resource Management System 1.0, allowing attackers to access functions that are not permitted for a normal user.

## Affected component
Path URL: /hrm/controller/ccity.php?positionedit=

Parameter: position.php

## Impact
The attacker can use normal account to add new position, which is not permitted for a normal user.

## POC

https://github.com/dovankha/CVE-2024-34221/assets/63991630/667ddbd4-af03-4959-9f20-765e9e8a8bae

