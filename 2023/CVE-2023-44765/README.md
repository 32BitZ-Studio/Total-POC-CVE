# ConcreteCMS XSS v2.2.18

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ConcreteCMS v.9.2.1 allows a local attacker to execute arbitrary code via a crafted script to Plural Handle of the Data Objects from System & Settings.

**Attack Vectors:** Scripting A vulnerability in the sanitization of the entry in the Plural Handle of "Data Objects from System & Settings" allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "System & Settings - Data Objects." section off General Menu.

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Associations/assets/87250597/bc9b9dba-8851-4253-9dd4-08528178471f)



We edit the Entity field with the payload that we have created and see that we can inject arbitrary Javascript code in the Plural Handle field.


### XSS Payload:

```js
""><svg/onload=alert('PluralHandle')>
```


Then we add an association:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Associations/assets/87250597/2569bb41-9235-4026-8605-d3587307c90a)


And we add the Type to Many to Many to add the payload to "Target Property Name and Inversed Property Name":

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Associations/assets/87250597/cc724fdf-6a4d-49f9-9364-20e2c58f7b25)



We execute the association created:

![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Associations/assets/87250597/e3db63a2-1340-4316-98e9-28af92e1701a)



In the following image you can see the embedded code that executes the payload in the main web.


![image](https://github.com/sromanhu/ConcreteCMS-Stored-XSS---Associations/assets/87250597/47ea2a5b-01c6-453d-840f-f267d1095a98)





</br>

### Additional Information:
https://www.concretecms.com/

https://owasp.org/Top10/es/A03_2021-Injection/
