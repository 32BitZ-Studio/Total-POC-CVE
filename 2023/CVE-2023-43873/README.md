# e107 CMS Stored XSS v2.3.2

## Author: (Sergio)

**Description:** Cross Site Scripting (XSS) vulnerability in e017 CMS v.2.3.2 allows a local attacker to execute arbitrary code via a crafted script to the Name filed in the Manage Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Name of "Manage" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Manage" section off General Menu.

![XSS Name Home payload](https://github.com/sromanhu/e107-CMS-Stored-XSS---Manage/assets/87250597/0d43df62-7041-4a5b-b6b5-84fbccc1149e)




We edit that Site Settings that we have created and see that we can inject arbitrary Javascript code in the Name field.


### XSS Payload:

```js
<img src=1 onerror=alert("1")
```


In the following image you can see the embedded code that executes the payload in the main web.

![XSS Name result](https://github.com/sromanhu/e107-CMS-Stored-XSS---Manage/assets/87250597/6e18932b-b476-452d-9397-bf622cf2dc0e)



</br>

### Additional Information:
https://e107.org/

https://owasp.org/Top10/es/A03_2021-Injection/

https://owasp.org/www-community/attacks/xss/
