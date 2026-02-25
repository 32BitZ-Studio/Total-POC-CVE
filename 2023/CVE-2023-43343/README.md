# Quick CMS Stored XSS v6.7

## Author: (Sergio)

**Description:** Multiple Cross-Site Scripting (XSS) vulnerabilities in Quick CMS v6.7 allows a local attacker to execute arbitrary code via a crafted script to the to the Files - Description in the Pages Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Description of "Pages- Files Menu" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Pages - Files ." section off General Menu. 

![XSS Payload Files description](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Pages-Files/assets/87250597/7d436b43-6e7d-4249-9a95-461d3df1ae3e)





We edit that Description Settings and see that we can inject arbitrary Javascript code in the Desription field.


### XSS Payload:

```js
'"><svg/onload=alert('Description')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS resultado Payload Files description](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Pages-Files/assets/87250597/97129f36-7dc4-487d-934d-070a63da6b12)





</br>

### Additional Information:
https://opensolution.org/cms-system-quick-cms.html

https://owasp.org/Top10/es/A03_2021-Injection/
