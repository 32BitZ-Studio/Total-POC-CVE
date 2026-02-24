# [Offensive technologies course](https://securitylab.disi.unitn.it/doku.php?id=course_on_offensive_technologies)

This repository contains descriptions of several vulnerabilities and the code that exploits them.

Exploitable environments can be found in `/dockerfiles/victim` folder. Attacker environments can be found in `/dockerfiles/attacker` folder. Everything comes as Docker images.

Exploited CVEs:
* CVE-2008-2938 (Tomcat path traversal)
* CVE-2014-1904 (Spring path traversal)
* CVE-2014-2064 (Jenkins information disclosure)
* CVE-2016-1240 (Tomcat privilege escalation)

For each vulnerability a shell is uploaded on the victim server, infecting each webpage in order to include an [exploit kit](https://www.f-secure.com/en/web/labs_global/exploit-kits)