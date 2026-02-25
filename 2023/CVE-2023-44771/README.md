# ZenarioCMS Stored XSS v.9.4.59197

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ZenarioCMS v.9.4.59197 allows a local attacker to execute arbitrary code via a crafted script to the Page Layout.

**Attack Vectors:** Scripting a vulnerability in the sanitization of the entry in the Page Layout allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Layout - Page Layout off the Administration Menu.

![image](https://github.com/sromanhu/ZenarioCMS--Stored-XSS---Page-Layout/assets/87250597/234b6102-58ff-454a-988b-f5c775de4c2e)


We click on Edit Layout and add the following payload:


### XSS Payload:

```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Page Layout'>
```


![image](https://github.com/sromanhu/ZenarioCMS--Stored-XSS---Page-Layout/assets/87250597/a254aeb8-cdcd-43ce-9de7-3a3380a22634)




In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ZenarioCMS--Stored-XSS---Page-Layout/assets/87250597/b63d1ac5-1ed9-457c-83e5-7c859d07b43f)





</br>

### Additional Information:
https://zenar.io/

https://owasp.org/Top10/es/A03_2021-Injection/
