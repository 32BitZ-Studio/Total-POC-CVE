<b>Upgrade</b>
<p>
<center>
Select the version of Simplog you are upgrading from:
<p>
<form method=POST action=install.php>
<input type=hidden name=dbtype value="<?=$_REQUEST['dbtype']?>">
<input type=hidden name=dbname value="<?=$_REQUEST['dbname']?>">
<input type=hidden name=dbhost value="<?=$_REQUEST['dbhost']?>">
<input type=hidden name=dbuser value="<?=$_REQUEST['dbuser']?>">
<input type=hidden name=dbpass value="<?=$_REQUEST['dbpass']?>">
<input type=hidden name=from value="upgrade1">
<input class=search type=submit name=version value="0.5.x">&nbsp;&nbsp;
<input class=search type=submit name=version value="0.6">&nbsp;&nbsp;
<input class=search type=submit name=version value="0.7">&nbsp;&nbsp;
<input class=search type=submit name=version value="0.8">&nbsp;&nbsp;
<input class=search type=submit name=version value="0.9/0.9.1">
</form>
</center>
