<?PHP
session_start();
require("lib.php");
require("rand_pass.php");

if(isLoggedIn()) {
	header("Location: edit.php\n\n");
	exit(0);
}

if($_REQUEST['blogid']){
	$blogid=$_REQUEST['blogid'];
}

if(($_REQUEST['act'] == "login") && ($_REQUEST['ulogin'] != "")) {

	$enc = md5($_REQUEST['password']);

    $mysql = "SELECT * from blog_users where login='" . escape($_REQUEST['ulogin']);
	$mysql = $mysql."' AND password='$enc'";

    require('token_gen_and_validate.php');

	$res = $db->Execute($mysql);

    $ts = time();
    $token  = generate_token($ts);
    $mysql = "";

	if($res->fields['login'] == $_REQUEST['ulogin']) {
		//session_register("login");
		$_SESSION['login'] = $_REQUEST['ulogin'];
		//session_register("ip");
		$_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['token'] = $token;
        $_SESSION['timestamp'] = $ts;
		header("Location: edit.php\n\n");
		exit(0);
	} else {
		header("Location: login.php?act=bad\n\n");
		exit(0);
	}

} elseif($_REQUEST['act'] == "newpass") {
	$new = random_password();

	include("header.php");

    $mysql = "SELECT count(email) as count FROM blog_users WHERE login='" . escape($_REQUEST['ulogin']) . "' and email='" . escape($_REQUEST['email']) . "'";

	$res = $db->Execute($mysql);

	if($res->fields['count'] > 0) {

		mailpass($_REQUEST['email'], $new);

		$enc = md5($new);

    	$mysql = "UPDATE blog_users SET password='$enc' where login='" . $_REQUEST['ulogin'] . "'";

		$res = $db->Execute($mysql);

		echo "<h3>You new password has been sent to ".$_REQUEST['email']."</h3>\n";
		echo "<a href=\"$baseurl\">Back to Login</a>\n";
	} else {
		echo "<h3>User and/or email address not found</h3>\nPlease <a href=\"mailto: ".adminemail()."\">contact the blog administrator.</a>";
	}
	include("footer.php");

} elseif($_REQUEST['act'] == "change") {
    include("header.php");
	echo "Please provide your username and email address.  A new password will be emailed to you at that address.<p>\n";
	echo "<form action=\"login.php\" method=POST>\n";
	echo "User: <input type=text size=8 maxsize=8 name=ulogin value=\"\"><br>\n";
	echo "Email: <input type=text size=32 name=email><p>\n";
	echo "<input type=hidden name=act value=\"newpass\">\n";
	echo "<input class=search type=submit value=\"Send New Password\"><p>\n";
	echo "</form>\n";
	include("footer.php");
} else {
	include("header.php");

	if($_REQUEST['act'] == "bad") {
		print "<b>Authentication Error</b><p>\n";
	}

	print_login();

	include("footer.php");

}


function mailpass($mail,$pass)
{
	global $baseurl;

	$mesg = "Your new password is: $pass.\n\n"
          ."Please go login in at $baseurl and change your password. ";

	mail($mail,"New Simplog password", $mesg, "From: ".adminemail()." (Simplog Admin)\n");

}

?>
