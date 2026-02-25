# Evolution CMS Reflected XSS v3.2.3

## Author: (Sergio)

**Description:** Multiple Cross-site scripting (XSS) reflected vulnerabilities in the evolution v.3.2.3 installation process Admin options allows a local attacker to execute arbitrary web scripts via a crafted payload injected into the cmsadmin, cmsadminemail, cmspassword and cmspasswordconfim parameters.

**Attack Vectors:** A vulnerability in the sanitization of the cmsadmin, cmsadminemail, cmspassword and cmspasswordconfim parameters of the Database installation Admin options process allows JavaScript code to be injected.

---

### POC:


During the installation process we enter the XSS payload in the cmsadmin, cmsadminemail, cmspassword and cmspasswordconfim parameters and when we click on next, we will obtain the XSS pop-up.

### XSS Payload:

```js
'"><svg/onload=alert('admin_name')>
```


In the following image you can see the embedded code that executes the payload in the installation process.

![XSS Payload Name](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/33343245-d79a-4a21-903a-a3f8a3d720eb)



![XSS Payload email](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/36fef73d-2192-4778-b28f-ac790801768c)



![XSS Payload password y password confirm](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/db8b8593-92c0-4836-a400-f7f693bc724d)



And the result will be reflected with the pop-up of the following evidence:

![XSS result Name](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/b8feecd9-4fcf-436d-a4ed-8fef58fa0cc3)



![XSS result emailpng](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/e6c0d2fb-9f0c-49c9-882d-e308ad286e57)



![XSS result password](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/88084157-9b67-46b9-9cca-d8e5887124b8)



![XSS result password confirm](https://github.com/sromanhu/Evolution-Reflected-XSS---Installation-Admin-Options/assets/87250597/9f375374-a148-4f4b-9f31-3c7ac11bbeb4)



</br>

### Additional Information:

https://evo.im/

