<b> #CVE-2024-41453 </b>

<b> #CVE-2024-41454 </b>

ProcessMaker Vulnerabilites (just for education):
@ryancooley @velkymx @nolanpro @caleeli

- install ProcessMaker 4 Core Docker Instance frome this repository:
https://github.com/ProcessMaker/pm4core-docker

- this is latest pm docker version (PM_VERSION=4.1.21), below image is the .env file.
   ![image](https://github.com/php-lover-boy/processmaker/assets/111951701/6399239e-8f0b-467e-8f44-dedb21130389)
  
# Stored Xss
1. create a json file with xss payload.
   ![image](https://github.com/php-lover-boy/processmaker/assets/111951701/fc68a457-7ae6-4b5d-bcc0-8ed79b4a9871)
(I uploaded sample file named: sample.json)

2.Send this file to process admin user and request to import thie file as a process.
![image](https://github.com/php-lover-boy/processmaker/assets/111951701/42c2568d-8176-4b48-a738-b71a6e7e3d53)
![image](https://github.com/php-lover-boy/processmaker/assets/111951701/97d5524c-4227-47f9-805a-d2bc402b2465)
![image](https://github.com/php-lover-boy/processmaker/assets/111951701/ff1da235-b5f3-4af4-8f06-4ac3147997dc)

3. when admin user import this file and try to archive this process, the malicious javascript code will be executed. 

(chrome latest version: Version 126.0.6478.127 (Official Build) (64-bit))

![image](https://github.com/php-lover-boy/processmaker/assets/111951701/c62fdb6a-2303-46c9-8df8-6e07f617a9d5)

It is obvius that in import function there is lack of user input sanitization. 

# Maliciuos file upload 
1. admin user can upload html file and bypass image restrication in Customize UI, custom login logo upload section.
  ![image](https://github.com/php-lover-boy/processmaker/assets/111951701/802a0386-9977-4c9a-a508-09a761e49e6e)


2. this is uploaded file:
![image](https://github.com/php-lover-boy/processmaker/assets/111951701/078df8da-12dd-4105-a85f-ba0d00e3aa80)

3. also it is possible to uplaod php file but its not executed.
   ![image](https://github.com/php-lover-boy/processmaker/assets/111951701/9a441470-5baa-46f2-a023-14093957487d)
![image](https://github.com/php-lover-boy/processmaker/assets/111951701/a6cc1129-3d0f-477c-b22e-756f452249c0)

there is lack of proper input validation in uploaders.



