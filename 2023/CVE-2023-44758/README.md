# GDidees Stored XSS v3.0

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in GDidees v.3.0 allows a local attacker to execute arbitrary code via a crafted script to the Page Title.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Page Title allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:

We edit the "Outils d'édition" and see that we can inject arbitrary Javascript code in the "Titre de la page".


![image](https://github.com/sromanhu/GDidees-CMS-Stored-XSS---Titulo/assets/87250597/943ec358-f36b-4e3e-9f8f-e26447154da8)



### XSS Payload:

```js
'"><svg/onload=prompt('text')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/GDidees-CMS-Stored-XSS---Titulo/assets/87250597/cac9aa1a-29e2-4403-abbd-918f3fa23d43)





</br>

### Additional Information:
https://www.gdidees.eu/cms-1-0.html

https://owasp.org/Top10/es/A03_2021-Injection/
