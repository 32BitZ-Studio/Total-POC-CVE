# RiteCMS 3.0 File Upload - XSS

## Author: (Sergio)

**Description:** File upload vulnerability in RiteCMS 3.0 allows a local attacker to upload a svg file with XSS content.

**Attack Vectors:** AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L

---

### POC:

We create an svg file with the following content:

```js
<svg
onload="alert('xss attach')"
 xmlns="http://www.w3.org/2000/svg">
</svg>
```


When logging into the panel, we will go to the "Filemanager" section off Administration Menu and click on Upload file.

![File Upload XSS fichero subido](https://github.com/sromanhu/RiteCMS-File-Upload--XSS---Filemanager/assets/87250597/5f6da339-3efb-4e2b-b05e-ad7ed9131c9c)



Here we see the svg file uploaded correctly:

![File Upload XSS fichero subido 2](https://github.com/sromanhu/RiteCMS-File-Upload--XSS---Filemanager/assets/87250597/efaf16c0-42f2-4251-8c3c-5409914235b2)



Then we open the file and the XSS pop-up appears

![File Upload XSS result](https://github.com/sromanhu/RiteCMS-File-Upload--XSS---Filemanager/assets/87250597/01fbe601-b9d9-40c1-a0ab-0c9e24d8efb9)



</br>

### Additional Information:
https://github.com/handylulu/RiteCMS/
