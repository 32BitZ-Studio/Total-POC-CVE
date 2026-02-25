# CMSmadesimple Stored XSS v2.2.18

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to execute arbitrary code via a crafted script to the Extra in the Content - News Menu.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Extra of "Content - News Menu" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Content- News" section off General Menu.

![XSS Extra](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---News---Extra/assets/87250597/6f2c0ed1-0ed3-4bd8-b911-1f81ed28cea6)







We edit that Content - News Menu with the payload that we have created and see that we can inject arbitrary Javascript code in the Extra field.


### XSS Payload:

```js
'"><svg/onload=prompt('Extra')>
```


In the following image you can see the embedded code that executes the payload in the main web.
![XSS Extra resultado](https://github.com/sromanhu/CMSmadesimple-Stored-XSS---News---Extra/assets/87250597/06be394a-f054-40bc-bb02-ebf7ba579662)








</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/
