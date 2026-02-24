<?php 

include("./adodb/adodb-errorhandler.inc.php");
include("./adodb/adodb.inc.php");
$db = NewADOConnection($_REQUEST['dbtype']);
$db->Connect($_REQUEST['dbhost'],$_REQUEST['dbuser'],$_REQUEST['dbpass'],$_REQUEST['dbname']);

	$sql = "UPDATE blog_users set admin=1 where id=".$_REQUEST['id'];
	$res = $db->Execute($sql);
?>
<b>Admin user set!</b><p>
<p>
Be sure to edit your config.php file to reflect your current blog information.<p>
Please remove the install.php file and install/ directory before continuing, as leaving these files poses a security risk!<p>
<a href="login.php">Login to Simplog</a>
<p>
