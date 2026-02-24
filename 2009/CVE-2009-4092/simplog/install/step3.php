Please edit the following lines in your config.php file to match the following lines:
<p>
<center>
<table><tr><td>
$host = "<?=$_REQUEST['dbhost']?>";<br>
$dbase = "<?=$_REQUEST['dbname']?>";<br>
$user = "<?=$_REQUEST['dbuser']?>";<br>
$passwd = "<?=$_REQUEST['dbpass']?>";<br>
$dbtype = "<?=$_REQUEST['dbtype']?>";
<p>
<form method=POST action="install.php">
<input type=hidden name=act value="Accept">
<input type=hidden name=from value="step1">
<input class=search type=submit value="Change Info">
</form>
</td></tr></table>
<p>
If performing a new install and database <?=$_REQUEST['dbname']?> does not exist, please create a new database named <?=$_REQUEST['dbname']?>. 
</code>
<p>
Please select <b>New Install</b> or <b>Upgrade</b> to continue
<br>
<form method=POST action="install.php">
<input type=hidden name=dbtype value="<?=$_REQUEST['dbtype']?>">
<input type=hidden name=dbname value="<?=$_REQUEST['dbname']?>">
<input type=hidden name=dbhost value="<?=$_REQUEST['dbhost']?>">
<input type=hidden name=dbuser value="<?=$_REQUEST['dbuser']?>">
<input type=hidden name=dbpass value="<?=$_REQUEST['dbpass']?>">
<input type=hidden name=from value="step3">
<input class=search type=submit name=act value="New Install">&nbsp;&nbsp;&nbsp;&nbsp;
<input class=search type=submit name=act value="Upgrade">
</form>
</center>
