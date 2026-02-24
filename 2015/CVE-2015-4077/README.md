# forti_shield
A combined POC for CVE-2021-31955,  CVE-2015-4077, and CVE-2015-5736

This one of the possible solutions for an extra mile in the 2022 version of the EXP-401 course. This extra mile was removed in the 2025 version of the course. This solution will not work for the current extra mile without changing offsets. All offsets in this poc are hardcoded and it is not version independent. It works on Windows 10 20H2.

CVE-2021-31955 POC from freeide was modified to leak the EPROCESS of the exploits process. https://github.com/freeide/CVE-2021-31955-POC

Morten and Sickness's POC for CVE-2015-4077 and CVE-2015-5736 was then modifeid to work with 20H2 https://www.exploit-db.com/exploits/45149

<img width="2108" height="838" alt="image" src="https://github.com/user-attachments/assets/f3f4eb77-f597-4517-8a9e-fa1a65809ec4" />

