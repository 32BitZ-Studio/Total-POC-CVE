# Drupalgeddon Python3 Edition  

An rewritten POC on the CVE-2014-3704, done as part of my CPTS training on HackTheBox.
https://nvd.nist.gov/vuln/detail/CVE-2014-3704

CVE-2014-3704 known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user.

Only minor changes has been done here, making the script compatible with Python3 and changing some of the formatting of print statements.

######################################################################################

Drupal 7.x SQL Injection SA-CORE-2014-005 https://www.drupal.org/SA-CORE-2014-005
Inspired by yukyuk's P.o.C (https://www.reddit.com/user/fyukyuk)

Tested on Drupal 7.31 with BackBox 3.x

This material is intended for educational 
purposes only and the author can not be held liable for 
any kind of damages done whatsoever to your machine, 
or damages caused by some other,creative application of this material.
In any case you disagree with the above statement,stop here.
######################################################################################
