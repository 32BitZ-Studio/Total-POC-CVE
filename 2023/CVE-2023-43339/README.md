# Cmsmadesimple CMS Reflected XSS v2.2.18

## Author: (Sergio)

**Description:** Multiple Cross-Site Scripting (XSS) vulnerabilities in installation of  cmsmadesimple v.2.2.18 allows a local attacker to execute arbitrary web scripts via a crafted payload injected into the Database Name, DataBase User or Database Port.

**Attack Vectors:** A vulnerability in the installation sanitation in the Database name, user name and port allows JavaScript code to be injected.

---

### POC:


During the installation process we enter the XSS payload in any of the 3 fields and when we click on next, we will obtain the XSS pop-up

### XSS Payload:

```js
"' on focus="alert(1)" autofocus="
```


In the following image you can see the embedded code that executes the payload in the instalaltion process.
![imagen](https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS/assets/87250597/5858abd6-73ad-4e76-881f-7b4efe090c6e)


![imagen](https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS/assets/87250597/426542dc-cebc-4c5f-98a7-695837889d34)


![imagen](https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS/assets/87250597/fef08e57-214e-4357-b8f0-eec40b12fce5)


![imagen](https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS/assets/87250597/7825fac8-bd75-40d7-aee4-530ebd9e3b5f)

![image](https://github.com/sromanhu/Cmsmadesimple-CMS-Reflected-XSS/assets/87250597/7806fca2-d08c-4a0b-9b30-e1e7b092a195)

![imagen](https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS/assets/87250597/8d580af3-2e89-4f17-a3a6-9096fec22b4c)



</br>

### Additional Information:

http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/

