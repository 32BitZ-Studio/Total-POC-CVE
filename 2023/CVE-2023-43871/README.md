# WBCE File Upload XSS - WBCE v1.6.1

## Author: (Sergio)

**Description:** File upload vulnerability in WBCE v.1.6.1 allows a local attacker to upload a pdf file with hidden XSS.

**Attack Vectors:** A vulnerability in Media file upload sanitation allows you to upload a PDF file with hidden XSS.

---

### POC:


When logging into the panel, we will go to the "Media" section off General Menu.

![XSS Pdf](https://github.com/sromanhu/WBCE-File-Upload--XSS---Media/assets/87250597/0f499101-c248-4e6c-923a-3a532320dd1a)


We upload the PDF file with the hidden XSS and we see that we can execute it and the Reflected XSS appears.


![XSS Pdf resultado](https://github.com/sromanhu/WBCE-File-Upload--XSS---Media/assets/87250597/a0b6405e-7431-4793-9168-7a0d9aea6b21)






</br>

### Additional Information:
[http://www.cmsmadesimple.org/](https://wbce-cms.org/)

https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
