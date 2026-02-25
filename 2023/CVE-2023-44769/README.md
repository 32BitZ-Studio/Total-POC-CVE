# ZenarioCMS Reflected XSS v.9.4.59197

## Author: (Sergio)

**Description:** Cross Site Scripting vulnerability in ZenarioCMS v.9.4.59197 allows a local attacker to execute arbitrary code via a crafted script to the Spare aliases from Alias.

**Attack Vectors:** Scripting a vulnerability in the sanitization of the entry in the Spare Aliases allows injecting JavaScript code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Menu node properties - Select content item" off the Administration Menu.

![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/7bdf147a-62b1-4ee8-861c-76b8575c2aab)



We select an alias and click on Edit content item:

![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/f1f25adf-418b-4d43-9b9b-21fd6fb79233)



And now in Edit alias:

![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/2e0b64c9-860f-4353-9091-d252cbfe0de2)



We add the payload in the Spare aliases field and we will have the XSS reflected pop-up.


### XSS Payload:

```js
<><img src=1 onerror=alert('Spare')>
```

![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/432362fc-8669-462c-9e7a-087063a40673)


We can also access the alias panel from the Edit Layout of the administration panel.


![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/7f7515d9-b2ea-4fcc-a5ed-be5e7ad812ed)


And add the payload:

![image](https://github.com/sromanhu/ZenarioCMS--Reflected-XSS---Alias/assets/87250597/19512158-0f27-4c9f-b18e-79499d79abc0)






</br>

### Additional Information:
https://zenar.io/

https://owasp.org/Top10/es/A03_2021-Injection/
