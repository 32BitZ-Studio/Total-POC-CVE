# ConcreteCMS Stored XSS v.9.2.1

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to the SITE parameter from installation or in the Settings.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Site of Installation or Settings allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


In the installation process we add the payload in the SITE parameter:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Site_Installation/assets/87250597/a5dbbb11-9c2e-45e8-bfee-ff43dc07ec3c)





### XSS Payload:

```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Site'>
```


In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Site_Installation/assets/87250597/f9557aa6-886f-49f9-bbe6-946c17569303)



</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
