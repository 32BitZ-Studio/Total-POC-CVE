<?php 

#open connection to DB
include("./adodb/adodb-errorhandler.inc.php");
include("./adodb/adodb.inc.php");
$db = NewADOConnection($_REQUEST['dbtype']);
$db->Connect($_REQUEST['dbhost'],$_REQUEST['dbuser'],$_REQUEST['dbpass'],$_REQUEST['dbname']);

$dict = NewDataDictionary($db);

$db->StartTrans();

if($_REQUEST['version'] == "0.5.x") {
	mknewpass();
	include("install/06to07.php");
	include("install/07to08.php");
	include("install/08to09.php");
	include("install/09to092.php");
} elseif($_REQUEST['version'] == "0.6") {
	include("install/06to07.php");
	include("install/07to08.php");
	include("install/08to09.php");
	include("install/09to092.php");
} elseif($_REQUEST['version'] == "0.7") {
    	include("install/07to08.php");
    	include("install/08to09.php");
	include("install/09to092.php");
} elseif($_REQUEST['version'] == "0.8") {
    	include("install/08to09.php");
	include("install/09to092.php");
} elseif($_REQUEST['version'] == "0.9/0.9.1") {
	include("install/09to092.php");
}

$db->CompleteTrans();

?>
<b>Database Upgrade Complete!</b> -- if you see any error messages or have any problems, support can be found in the  <a href="http://www.simplog.org/forums/">Simplog Support Forums</a>.
<p>
<?php 
	echo "<b>Please copy the config-dist.php file into the config.php file and edit config.php accordingly</b>\n";


function mknewpass() {
	global $_SERVER, $db,$dict;

	$uri = ereg_replace("install.php","",$_SERVER['SCRIPT_NAME']);
 
	$url = "http://".$_SERVER['HTTP_HOST'].$uri;
  
	$fields = "password C(32) notnull";

	$sql = $dict->ChangeTableSQL('blog_users',$fields,$opts);
	$res = $db->Execute($sql[0]);
	 
	$sql = "select id, login, name, email from blog_users";	  
	$res = $db->Execute($sql);
	   
	while(!$res->EOF) {
    
    	$pass = random_password();
    	$enc = md5($pass);
						  
    	$sql2 = "update blog_users set password='$enc' where id='".$res->fields['id']."'";
    	$res2 = $db->Execute($sql2);
		   
    	$mesg = $res->fields['name'].",\n\nDue to an upgrade and security enhancement in Simplog,";
    	$mesg .= "it was required to issue new passwords to all users.\n\n";
	    $mesg .= "New password for account ".$res->fields['login']." is: $pass.\n\n";
	    $mesg .= "Please login at $url and change your password as soon as possible.\n\nThanks!";
												    
	    mail($res->fields['email'],"New Simplog Password",$mesg,"From: admin@".$_SERVER['HTTP_HOST']);
    	$res->MoveNext();

	}

	echo "<b>NOTE!</b> - Due to a security enhancement in Simplog, it was required to issue ";
	echo "new passwords to all users.  Please check your email to get your new password<P>\n";

}

?>
