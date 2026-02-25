# ConcreteCMS Stored XSS v.9.2.1

## Author: (Sergio)

**Description:** ConcreteCMS v9.2.1 is affected by Arbitrary File Upload vulnerability which allows Cross-Site Scriting (XSS) stored.

**Attack Vectors:** A vulnerability in "Thumbnail" file upload sanitation allows you to upload a PDF / SVG /HTML file with hidden alert Cross-Site scripting (XSS).

---

### POC:


When logging into the panel, we will go to the "Settings - Tags - Thumbnail off Dashboard Menu.

![image](https://github.com/sromanhu/ConcreteCMS-Arbitrary-file-upload-Thumbnail/assets/87250597/d84b46ee-afdf-4525-93a7-1a8b18640ca8)


There is the payloads:

### XSS PDF Payload:

It is an XSS payload generated with the JS2PDFInjector tool and a js payload that contains the following content:

```js
app.alert("XSS");
```

Once uploaded, if we click on the link we can see the path where they are stored:

![image](https://github.com/sromanhu/ConcreteCMS-Arbitrary-file-upload-Thumbnail/assets/87250597/12f185c7-5cab-4d61-a038-d0914dc8d7b7)



In the following image you can see the embedded code that executes the payload in the main web.

![image](https://github.com/sromanhu/ConcreteCMS-Arbitrary-file-upload-Thumbnail/assets/87250597/dc0ad943-22ea-4976-95fa-e71210d878f9)


</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
