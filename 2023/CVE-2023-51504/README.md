# CVE-2023-51504
This is a dockerized reproduction of the MotoCMS SQL injection (cf exploit db) 

# Description
MotoCMS Version 3.4.3 SQL Injection via the keyword parameter on the link https://template189526.motopreview.com/store/category/search/?keyword=1

Reproducing the vulnerability involved defining (in a Dockerfile) the commands or instructions needed to reproduce a kali linux machine and run sqlmap in order to detect and display the results of the vulnerability.

To get the results, run the command 

```docker run -d sybelle20/cve-2023-51504:motocms-sqli```
