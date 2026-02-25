# Quick CMS Stored XSS v6.7

## Author: (Sergio)

**Description:** A Cross-Site Scripting (XSS) vulnerability in Quick CMS v6.7 allows a local attacker to execute arbitrary code via a crafted script to the to the Backend - Dashboard in the Languages Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Backend of "Languages- Backend" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Languages - Backend ." section off General Menu. 

![XSS payload Backend Languages - Dashboard](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Languages-Backend/assets/87250597/987abaf6-0e18-4e4b-9780-07e8bfb23ab1)







We edit that Backend Settings and see that we can inject arbitrary Javascript code in the Dashboard field.


### XSS Payload:

```js
'"><svg/onload=alert('Dashboard')>
```


In the following image you can see the embedded code that executes the payload in the main web.

![XSS resultado Backend Languages - Dashboard](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Languages-Backend/assets/87250597/0b7142c7-d899-4f76-b41c-2fb44576c8a1)






</br>

### Additional Information:
https://opensolution.org/cms-system-quick-cms.html

https://owasp.org/Top10/es/A03_2021-Injection/
