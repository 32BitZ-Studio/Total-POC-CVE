# ZenarioCMS Reflected XSS v.9.4.59197

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ZenarioCMS v.9.4.59197 allows a local attacker to execute arbitrary code via a crafted script to the Organizer - Spare alias.

**Attack Vectors:** Scripting a vulnerability in the sanitization of the entry in the Spare alias. allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Organizer - Spare alias off the Organizer Menu.


We click on Create a spare alias and add the following payload to the Spare alias field:



### XSS Payload:

```js
"' onfocus="alert(1)" autofocus="
```



In the following image you can see the XSS pop-up when the payload is executed:


![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Organizer-Alias/assets/87250597/f20c7a1e-27c2-440e-bade-7da83968f7ca)




</br>

### Additional Information:
https://zenar.io/

https://owasp.org/Top10/es/A03_2021-Injection/
