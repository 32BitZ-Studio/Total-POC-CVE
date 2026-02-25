# CVE-2023-26852-Textpattern-v4.8.8-and version below
Textpattern v4.8.8 and Below are vulnerable to Unrestricted File Upload – Dangerous File Content Leading to Remote Code Execution

This is my first repo. Don't beat me if i didn't explain well...

Textpattern is a free and open-source content management system for PHP and MySQL. While it is typically listed among weblogging tools, its aim is to be a general-purpose content management system.

We found that this web application allowed privilege user such as admin to upload a .php file via upload and install plugins.(although the developer claims that this is 1 of the intended features and there is not issue with a webadmin upload their customize plugins into the web application). Hmmm....sounds make sense but in real world, A web admin is not always a server admin or IT admin, and i am sure a webadmin dont have privilege to run OS command if you are not running a 1 man company. Below are the steps to reproduce and again, dont beat me if i din'nt explain well. :-)



Step 1 : Login as admin

Step 2 : Navigate to "Admin" tab > click "Plugins" . refer to Step1.png

Step 3 : Click "Browse" and choose your php file (in my case, i choose plugin.php) and clcik "upload" . refer to Step2.png

Step 4 : naviate to http://127.0.0.1/textpattern/plugins/plugin/plugin.php?cmd=YOURCOMMANDPLS

Step 5 : enjoy your day!!!

plugin.php = "1 liner webshell or any php shell"
