# CMSmadesimple File Upload - XSS v2.2.18

## Author: (Sergio)

**Description:** File upload vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to upload a pdf file with hidden XSS.

**Attack Vectors:** A vulnerability in File Manager file upload sanitation allows you to upload a PDF file with hidden XSS.

---

### POC:


When logging into the panel, we will go to the "Content- File Manager." section off General Menu.

![XSS pdf file upload](https://github.com/sromanhu/CMSmadesimple-File-Upload--XSS---File-Manager/assets/87250597/8274bb28-3e8c-4118-9241-33970ca1e9f3)


We upload the PDF file with the hidden XSS and we see that we can execute it and the Reflected XSS appears.


![XSS pdf file upload resultado](https://github.com/sromanhu/CMSmadesimple-File-Upload--XSS---File-Manager/assets/87250597/d1bbaad5-96a4-4377-a514-3e271b2fc7de)





</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
