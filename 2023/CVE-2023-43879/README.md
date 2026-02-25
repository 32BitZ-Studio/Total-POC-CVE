# Rite CMS v3.0 Multiple Stored XSS 

## Author: (Sergio)

**Description:** Rite CMS 3.0 is affected by a Cross-Site scripting (XSS) stored vulnerability that allows attackers to execute arbitrary code via a crafted payload in to the Global Content Blocks in the Administration Menu.

**Attack Vectors:** AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L

---

### POC:


When logging into the panel, we will go to the "Administration - Global Content Blocks - Home" .


We edit the body configuration where we add the XSS payloads. 

![XSS Payload](https://github.com/sromanhu/RiteCMS-Stored-XSS---GlobalContent/assets/87250597/2f6ab0d8-d70c-45dc-a4c5-ea87ef6e05c6)




### XSS Payload:

```js
'"><svg/onload=alert('document.domain')>
```


And when we save it, we will see that the XSS pop-up appears

![XSS Payload  Result](https://github.com/sromanhu/RiteCMS-Stored-XSS---GlobalContent/assets/87250597/0fb066be-8082-44c8-b174-479677cdbcba)



</br>
