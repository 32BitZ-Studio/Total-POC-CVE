# CVE-2019-9787 CSRF PoC

## Overview
PoC of CVE-2019-9787 CSRF    
WordPress Version 5.0    
[refference](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/)

Do not use this except for test purpose.

## Installation

```
$ docker-compose up -d
```

1. access http://localhost:8080/ and install WordPress. you only have to create WP admin account.   
2. access http://localhost:8080/?p=1#comments as a visitor, and post comment like "csrf site: http://localhost/".   
![comment ex](https://github.com/rkatogit/cve-2019-9787_csrf_poc/blob/images/1.png)


## Test
click the link posted at 2.    
![comment ex](https://github.com/rkatogit/cve-2019-9787_csrf_poc/blob/images/2.png)

you'll see the comment "csrf success" is posted by user you currently logged in.


