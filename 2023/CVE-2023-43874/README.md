# e107 CMS Stored XSS v2.3.2

## Author: (Sergio)

**Description:** Multiple Cross Site Scripting (XSS) vulnerability in e017 CMS v.2.3.2 allows a local attacker to execute arbitrary code via a crafted script to the Copyright and Author fields in the Meta & Custom Tags Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Copyright and Author fields of "Meta & Custom Tags Menu" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Meta & Custom Tags Menu." section off General Menu.

![XSS Payload](https://github.com/sromanhu/e107-CMS-Stored-XSS---MetaCustomTags/assets/87250597/c7a32405-a34a-4166-aa92-c8b554265a5a)



We edit that Settings that we have created and see that we can inject arbitrary Javascript code in the Copyright and Author fields.


### XSS Payload:

```js
'"><svg/onload=alert('Copyright')>
```

### XSS Payload:

```js
'"><svg/onload=alert('Author')>
```


In the following image you can see the embedded code that executes the payload in the main web.

![XSS Result Copyright](https://github.com/sromanhu/e107-CMS-Stored-XSS---MetaCustomTags/assets/87250597/80122e6a-599f-4b9e-a621-1383bc936101)



![XSS Result Author](https://github.com/sromanhu/e107-CMS-Stored-XSS---MetaCustomTags/assets/87250597/2a7db06d-ec46-40ff-ae2a-fe8fd3425741)




</br>

### Additional Information:
https://e107.org/

https://owasp.org/Top10/es/A03_2021-Injection/

https://owasp.org/www-community/attacks/xss/
