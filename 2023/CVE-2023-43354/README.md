# CMSmadesimple Stored XSS v2.2.18

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to execute arbitrary code via a crafted script to the Profiles in the Extensions - MicroTiny WYSIWYG editor.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Profiles of "MicroTiny WYSIWYG editor" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Extensions- MicroTiny WYSIWYG editor." section off General Menu.

![XSS Microtiny](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---MicroTIny-extension/assets/87250597/aadc3194-1f5b-420f-acdb-01161623bf94)





We edit that MicroTiny WYSIWYG edito Menu with the payload that we have created and see that we can inject arbitrary Javascript code in the Profile field.


### XSS Payload:

```js
""><svg/onload=alert('Profile')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS resultado](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---MicroTIny-extension/assets/87250597/584720d6-dc91-44f4-beb3-b5b805ede4a3)






</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/
