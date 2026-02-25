# Quick CMS Stored XSS v6.7

## Author: (Sergio)

**Description:** A Cross-Site Scripting (XSS) vulnerability in Quick CMS v6.7 allows a local attacker to execute arbitrary code via a crafted script to the to the Front and back end - Pages in the Languages Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Pages of "Languages- Front and back end" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Languages - Front and back end ." section off General Menu. 

![XSS payload Languages - Pages](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Languages-Frontend/assets/87250597/47d8fd8f-06b6-4f9c-ae44-bb8d933b20d2)







We edit that Front and back end Settings and see that we can inject arbitrary Javascript code in the Pages field.


### XSS Payload:

```js
'"><svg/onload=alert('Pages')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS Languages - Pages Resultado](https://github.com/sromanhu/Quick-CMS-Stored-XSS---Languages-Frontend/assets/87250597/b164f76f-9ec1-4cfe-b180-56b44184cc3d)






</br>

### Additional Information:
https://opensolution.org/cms-system-quick-cms.html

https://owasp.org/Top10/es/A03_2021-Injection/
