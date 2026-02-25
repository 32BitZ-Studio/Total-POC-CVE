# Rite CMS v3.0 Multiple Stored XSS 

## Author: (Sergio)

**Description:** Rite CMS 3.0 is affected by a Multiple Cross-Site scripting (XSS) stored vulnerability that allows attackers to execute arbitrary code via a crafted payload i to the Main Menu - Items in the Administration Menu.

**Attack Vectors:** AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L

---

### POC:


When logging into the panel, we will go to the "Administration - Menus - Main Menu" section.


We click on Add item button and we add the XSS payloads to the Name, Title, Link and Accesskey fields.

![XSS Menú endpoint payload](https://github.com/sromanhu/RiteCMS-Stored-XSS---MainMenu/assets/87250597/05b49367-dcfb-49f7-b50a-ddbdde0e6e00)




### XSS Payload:

```js
'"><svg/onload=propmt('Name')>
```


In the following images you can see the embedded code that executes the payload in the main web.

![XSS Nmae result](https://github.com/sromanhu/RiteCMS-Stored-XSS---MainMenu/assets/87250597/6da294f4-ff18-40db-8bdf-f9cb157ffb02)

![XSS title result](https://github.com/sromanhu/RiteCMS-Stored-XSS---MainMenu/assets/87250597/ecaedee3-6b11-45a6-b1fd-8857ec7c9376)

![XSS link result](https://github.com/sromanhu/RiteCMS-Stored-XSS---MainMenu/assets/87250597/c2c287ac-53fe-4111-a39b-de9bfd106466)

![XSS Accesskey result](https://github.com/sromanhu/RiteCMS-Stored-XSS---MainMenu/assets/87250597/ddeafb76-5411-4b2e-83aa-7bb8e73caa9f)




</br>
