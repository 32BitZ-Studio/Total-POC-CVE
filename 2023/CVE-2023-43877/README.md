# Rite CMS v3.0 Multiple Stored XSS 

## Author: (Sergio)

**Description:** Rite CMS 3.0 is affected by a Multiple Cross-Site scripting (XSS) stored vulnerability that allows attackers to execute arbitrary code via a payload crafted in the Home Page fields in the Administration menu. The payload will be executed on the main page independent of the user's session, so accessing the home web with another user will also execute the payload.

**Attack Vectors:** AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L

---

### POC:


When logging into the panel, we will go to the "Administration - Home" section or we create a new page and add the payloads.

We edit the body configuration where we add the XSS payloads. As there are several fields and only the output of the alert changes, I indicate the payload one of them:

![XSS payload Properties](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/38d92abd-034a-4317-bb6a-705ac5bd735e)



### XSS Payload:

```js
'"><svg/onload=alert('Description')>
```


In the following images you can see the embedded code that executes the payload in the main web. As there are several sections, I show them separately:


### CONTENT:

![XSS Payloadpng](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/dfe799d5-7548-474d-a275-df63c33ed7c6)


We click on Edit:

![XSS Path](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/c1834c33-d6f9-43ac-be41-19c4bdbc686f)

Result:

![XSS Resultado](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/f035199d-ccd1-49ca-a0ba-084f5fa96758)


### PROPERTIES:

![XSS payload Properties](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/840ecd22-0b16-4dd7-84ba-1698325d9f29)


Result:

![XSS result Properties](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/6f8da1e9-fa53-45df-b54b-83ea2fe5d199)

![XSS result Properties 2](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/44d7df14-28cc-4e02-8397-d651160045a6)

![XSS result Properties 3](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/a4e60f0c-aa36-4f03-aeea-bd0731f413f1)


### SIDEBAR:

![XSS payload Sidebar](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/55efffce-5fe0-4453-9716-c642035eef44)

Result:

![XSS result sidebar](https://github.com/sromanhu/-RiteCMS-Stored-XSS---Home/assets/87250597/4473839b-2374-4e71-9d04-fca7c77fec82)



</br>
