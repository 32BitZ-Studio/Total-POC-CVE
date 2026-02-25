# ConcreteCMS Stored XSS v.9.2.1

## Author: (Sergio)

**Description:** Multiple Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to the Header and Footer Tracking Codes of the SEO & Statistics.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Header and Footer Tracking Codes of "SEO & Statistics" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "SEO & Statistics- Header and Footer Tracking Codes." section off Dashboard Menu.

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/6b7c8a46-9654-41a2-9bae-3f6fbc0d88bf)



### XSS Payload:

```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Header'>
```


```js
<img src=x:alert(alt) onerror=eval(src) alt='XSS Footer'>
```



In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/863d688b-070d-45fd-af4a-5d6c2d8eeb61)


![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/b62dbf4b-0bed-4457-b0de-d10eb215451a)



We can use a payload to steal cookies and obtain them when a user logs on to the website in the two vulnerable fields.

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/c48195a2-8eb8-4c38-b1bb-1097ac8f1fd3)


![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/9faf9541-1dd9-4490-abba-808e702a643f)


Original session cookie.

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/12dce455-d11a-47b9-8cdf-6c18d507c40f)



Request captured with the external server:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---TrackingCodes/assets/87250597/e70817ae-140b-4943-abd8-e585f5593556)




</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
