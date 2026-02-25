# Computer Laboratory Management System using PHP and MySQL 1.0
#### Submitter: Kha Do

## Vulnerability
Cross Site Scripting

## Description
Cross Site Scripting vulnerability in php-lms/admin/?page=system_info in Computer Laboratory Management System using PHP and MySQL 1.0 allow remote attackers to inject arbitrary web script or HTML via the name, shortname parameters.

## Affected component
Path URL: php-lms/admin/?page=system_info

Parameters: System name (**name**), System short name (**shortname**)

## POC

Input payload `<script>alert(1337)</script>` into System name **name** and save it.
![system_name](https://github.com/dovankha/CVE-2024-34225/assets/63991630/6daf37fa-0e03-4c1f-880b-d43649e4ba78)


After saving, the pop-up windows like will appear:
![system_name_popup](https://github.com/dovankha/CVE-2024-34225/assets/63991630/e805bbc6-4ebb-4e86-a2cf-c7df485a2878)

