<?php 

/*From what I can tell, some DB engines create the database automatically, while others don't.  
In particular, SOLite will create the database if it doesn't already exist, while mySQL will
throw an error.  Add code to handle this.
*/

switch ($_REQUEST['dbtype']){
	case 'mysql':
		$link = mysql_connect($_REQUEST['dbhost'], $_REQUEST['dbuser'],$_REQUEST['dbpass']);
		if (!$link) {
			die('Could not connect: ' . mysql_error());
		}
		$dbname = $_REQUEST['dbname'];
	
		if(!mysql_select_db($dbname)) {
	
			$result = mysql_query("CREATE DATABASE $dbname");
			if ($result) {
				echo "Database created successfully<br>\n";
			}else{
				echo 'Error creating database: ' . mysql_error() . "<br>\n";
			}
		}

		
		mysql_close($link);
			
		break;
	default:
		break;
}



if(!$_REQUEST['act']) {
    #open connection to DB
    include("./adodb/adodb-errorhandler.inc.php");
    include("./adodb/adodb.inc.php");
    $db = NewADOConnection($_REQUEST['dbtype']);


    $db->Connect($_REQUEST['dbhost'],$_REQUEST['dbuser'],$_REQUEST['dbpass'],$_REQUEST['dbname']);

    $db->StartTrans();

    // here is where the schema creation will occur.
    include("create-schema.php");

    $db->CompleteTrans();

	if(!get_magic_quotes_gpc()) {
		$_REQUEST['alogin'] = addslashes($_REQUEST['alogin']);
		$_REQUEST['aname'] = addslashes($_REQUEST['aname']);
		$_REQUEST['aurl'] = addslashes($_REQUEST['aurl']);
		$_REQUEST['aemail'] = addslashes($_REQUEST['aemail']);
	}

	$enc = md5($_REQUEST['apass1']);
	$sql = "INSERT INTO blog_users VALUES( '1', '".$_REQUEST['alogin']."', '$enc', '".$_REQUEST['aname']."', '".$_REQUEST['aurl']."', '".$_REQUEST['aemail']."',1)";
	$res = $db->Execute($sql);

}

?>
<b>Database Install Complete!</b> -- if you see any error messages, please submit a bug report in the <a href="http://www.simplog.org/bugs/">Simplog Bug Tracker</a>.
<p>
<b>Be sure to copy the config-dist.php file to config.php and edit it with the correct values before continuing.</b>  <p>
Please remove the install.php file and install/ directory before continuing, as leaving these files poses a security
 risk!<p>
You are now ready to start using Simplog.  Login with<br>
login: <?=$_REQUEST['alogin']?><br>
pass: <?=$_REQUEST['apass1']?><br>
<p>
<a href="login.php">Start using Simplog</a>
