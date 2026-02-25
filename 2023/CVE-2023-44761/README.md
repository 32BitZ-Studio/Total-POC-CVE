# ConcreteCMS Stored XSS v.9.2.1

## Author: (Sergio)

**Description:** Multiple Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to the Forms of the Data objects.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Forms of "Data Objects" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "System & Settings - Express - Data Objects from section off Dashboard Menu and we select one.

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/be263718-ebe4-44a2-b223-023dd980f1bd)


Within the chosen Data object, we go to the Forms option:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/2ac75c58-d0d6-4ba1-b3c0-61893fcb9949)


We click on the "Add Form" option:
![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/731f4aad-c0c7-469d-8a1e-fda548caa635)



In the details of the form we choose "Add Field Set":

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/65e06a09-9b04-4dfd-8070-5bae77113faa)


Next, we choose the + option to add data to the form field:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/55d5dc6f-15ae-4223-8489-e272183694d0)


The vulnerability works with various fields, for example with "Core Properties - Text":

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/e2b67c68-13be-42dc-bc05-9cd953d6fe13)



Finally we edit the content to add the payload:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/abde0d37-b313-4218-a132-aa7097e0cb30)


### XSS Payload:

```js
<><img src=1 onerror=alert('Custom')>
```


We add the indicated payload in the "Custom Label" field:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/279bff73-950c-4f82-92cb-26dfc1254e6b)


In the following image you can see the embedded code that executes the payload in the main web.
![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/14e04a92-f56a-450c-915c-d1eb775afd90)



As I have indicated, it works in different fields, such as the following:


![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/b4ef2600-24d6-4c43-b9f5-34d560e246ab)



![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Form/assets/87250597/16cf4b0d-b9c4-49d3-9792-24ced1d97cee)



</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
