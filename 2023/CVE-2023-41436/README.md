# CSZ CMS Stored XSS v1.3.0

## Author: (Sergio)

**CVE:** 2023-41436

**Description:** Cross Site Scripting vulnerability in CSZCMS v.1.3.0 allows a local attacker to execute arbitrary code via a crafted script to the Additional Meta Tag parameter in the Pages Content Menu component. 

**Attack Vectors:** AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L

**CVSS3 Score:** 5.4 - MEDIUM

---

### POC:


When logging into the panel, we will go to the "Pages Content" section off General Menu [(http://localhost/cszcms/admin/pages)]

![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/06e7b1a7-8a72-40c6-bc12-d5e766e98e80)






We edit the Content of /home and see that we can inject arbitrary Javascript code into the Additional Meta tag field.


### XSS Payload:

```js
<img src=1 onerror=alert("1")
```



In the following image you can see the embedded code that executes the payload in the main web /home with the admin user:

![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/5b957c84-17c9-4a1c-8c42-b5b7e4841c04)


![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/8b7d56e0-056a-4afb-8d5c-9b8f1fb2a088)




If we log in with another user, the payload also skips:
![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/90de0270-0c92-4853-8da6-cc55c81ef3bc)



![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/341f4853-8b72-492d-8d12-5c86a9ae095f)


It can also be verified using other payloads as in the following evidence:
![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/54f0aacb-fa4a-4999-a8e8-270209d95f6f)

![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/65dd9069-ba4b-491a-a8a1-3d2c0cc0a74f)

Or this other:

![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/e2c34cd7-2420-4fd1-a1ba-153e52d4e3d3)

![image](https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content/assets/87250597/3595f1db-e553-4a57-8290-ad4950303517)

</br>

### Additional Information:
http://cszcms.com
https://owasp.org/Top10/es/A03_2021-Injection/
https://owasp.org/www-community/attacks/xss/
