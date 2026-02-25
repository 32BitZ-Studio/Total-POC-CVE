# Computer Laboratory Management System using PHP and MySQL 1.0
#### Submitter: Kha Do

## Vulnerability
Cross Site Scripting

## Description
Cross Site Scripting vulnerability in /php-lms/classes/Users.php?f=save in Computer Laboratory Management System using PHP and MySQL 1.0 allow remote attackers to inject arbitrary web script or HTML via the firstname, middlename, lastname parameters.

## Affected component
Path URL: /php-lms/classes/Users.php?f=save

Parameters: **firstname, middlename, lastname**

## POC

Input payload `<script>alert(123)</script>` into firstname **parameter** and save it.
![Firstname](https://github.com/dovankha/CVE-2024-34224/assets/63991630/17934b7c-bb6a-4ced-b9b2-d10ff4a39e74)

After saving, the pop-up windows like will appear:
![Firstname_Popup](https://github.com/dovankha/CVE-2024-34224/assets/63991630/d6bb4232-aa8a-4bf8-a7cd-158507de4dbf)
