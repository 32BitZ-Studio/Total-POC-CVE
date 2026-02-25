# Evolution CMS Reflected XSS v3.2.3

## Author: (Sergio)

**Description:** A cross-site scripting (XSS) reflected vulnerability in the evolution v.3.2.3 installation process connection allows a local attacker to execute arbitrary web scripts via a crafted payload injected into the uid parameter.

**Attack Vectors:** A vulnerability in the sanitization of the uid parameter of the Database installation process allows JavaScript code to be injected.

---

### POC:


During the installation process we enter the XSS payload in the uid parameter and when we click on next, we will obtain the XSS pop-up.

### XSS Payload:

```js
'"><svg/onload=alert('XSS')>
```


In the following image you can see the embedded code that executes the payload in the instalaltion process.
![XSS Payloadpng](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Connection-/assets/87250597/0d9df46e-2179-4447-b36d-59db765a0d21)



And the result will be reflected with the pop-up of the following evidence:

![XSS Resultado](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Connection-/assets/87250597/56110716-8b0d-4682-b1d8-7100cde05c8a)




</br>

### Additional Information:

https://evo.im/

