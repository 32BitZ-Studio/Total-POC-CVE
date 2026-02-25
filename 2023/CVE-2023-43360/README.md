# CMSmadesimple Stored XSS v2.2.18

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to execute arbitrary code via a crafted script to the Top Directory in the File Picker Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Top Directory of "File Picker Menu" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "File Picker extensions- Top Directory." section off General Menu.

![XSS FilePicker](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---File-Picker-extension/assets/87250597/4d1698ef-6760-481a-9997-fc23a05f7c19)






We edit that Top Directory Menu that we have created and see that we can inject arbitrary Javascript code in the Global Meatadata field.


### XSS Payload:

```js
""><svg/onload=alert('FilePicker')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS FilePicker resultado](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---File-Picker-extension/assets/87250597/e32ead82-e655-4f4c-b605-90eb8ec08d4c)





</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/
