# CMSmadesimple Stored XSS v2.2.18

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to execute arbitrary code via a crafted script to the Title in the My Preferences - Manage Shortcuts

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Title of "My Preferences - Manage Shortcuts" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "My Preferences - Manage Shortcuts" section off General Menu.

![XSS Shortcut](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---Shortcut/assets/87250597/1f75dd25-968c-4d06-9894-674a279c7247)





We edit that Content - News Menu with the payload that we have created and see that we can inject arbitrary Javascript code in the Title field.


### XSS Payload:

```js
'"><svg/onload=alert('Title')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS Shortcut resultado](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---Shortcut/assets/87250597/c4002952-ecf1-4bee-a02f-008eb6b05efe)









</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/
