# CMSmadesimple SSTI v2.2.18

## Author: (Sergio)

**Description:** Server Side Template Injection (SSTI) vulnerability in CMSmadesimple v.2.2.18 allows a local attacker to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

**Attack Vectors:** A SSTI vulnerability in the sanitization of the entry in the Content of "Content - Content Manager Menu" allows injecting  a malicious payload into a template code that will be executed when the user accesses the web page.

---

### POC:


When logging into the panel, we will go to the "Content Manager- Title" section off Content Menu.

![SSTI Payload](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/f1b5d449-6483-4719-86c1-d2602668b4b8)





<br>
We edit that Content field with a template malicious payload.


### SSTI Payload:

```js
{{4*4}}
```

<br>
In the following image you can see the embedded code that executes the payload in the main web.

![SSTI Resultado](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/b4e2af09-190c-486a-81c4-a3f0eb477762)





<br>
We identify the technology used with the following payload.


### SSTI Payload:

```js
a{*comment*}b
```

![Smarty Test payload](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/463e36fc-830d-4fb7-ac21-49e78ad86e68)



<br>
And the result is the following:


![Smarty Test resultado](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/343f36c5-be62-4dc3-99a8-32df3c0d0241)



<br>
Since the payload has worked we know that it uses Smarty, then we obtain the Smarty version with the following payload:

### SSTI Payload:

```js
{$smarty.version}
```

![Smarty version payload](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/51c3ff82-1251-45ab-9acc-5469ead3a8d5)




And in the result we can see the version of Smarty using the SSTI:

![Smarty version resultado](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/8984b6dd-22ed-4b26-ac63-1287708d7ed5)


<br>
We can also use the following payload to see the server name variable:

### SSTI Payload:

```js
{$smarty.server.SERVER_NAME}
```

</br>

![Smarty Server Name payload](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/d0b845e1-b9d2-4051-b557-ce43568e7f19)


<br>
Below is the result of the SSTI payload with the server name:
<br>
</br>

![Smarty Server Name resultado](https://github.com/sromanhu/CMSmadesimple-SSTI--Content/assets/87250597/be3ef7c9-027a-4965-bcda-5c49703c94d1)






</br>

### Additional Information:
http://www.cmsmadesimple.org/

https://owasp.org/Top10/es/A03_2021-Injection/
