<?PHP

session_start();

require("lib.php");
require('token_gen_and_validate.php');
auth();

$uid = getUID($_SESSION['login']);

#if no blog id passed, set to arbitrary blog in user's acl
if(!$_REQUEST['blogid']) {
    $sql = "SELECT blog_id from blog_acl where user_id=$uid";
    $res = $db->Execute($sql);

    $blogid = $res->fields[blog_id];
} else {
    $blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);

include("header.php");
echo "<h3>Modify User Info</h3>\n";

if($_REQUEST['act'] == "edit") {

	$sql = "update blog_users set login='".escape($_REQUEST[luser])."', name='".escape($_REQUEST[name])."', url='".escape($_REQUEST[url])."', email='".escape($_REQUEST[email])."' where login='$_SESSION[login]'";
	$res = $db->Execute($sql);

	echo "<b>Account $_REQUEST[luser] succesfully updated</b><p><hr>\n";

	$_SESSION['login'] = $_REQUEST['luser'];

} elseif($_REQUEST['act'] == "del") {

	$sql = "SELECT id from blog_users where login='".escape($_REQUEST[luser])."'";
	$res = $db->Execute($sql);

	$sql = "DELETE from blog_users where id=".$res->fields['id'];
	$res = $db->Execute($sql);

	$sql = "DELETE from blog_acl where user_id=".$res->fields['id'];
	$res = $db->Execute($sql);

	echo "<b>Account $_REQUEST[luser] deleted</b><br><hr>\n";
} elseif($_REQUEST['act'] == "change") {
    if (!validate_token($_SESSION['timestamp'], $_REQUEST['token'])) {
        echo "<b>BAD TOKEN.</b><br>\n";
    } else {
        if(($_REQUEST['pass1'] == "") or ($_REQUEST['pass2'] == "") or ($_REQUEST['pass1'] != $_REQUEST['pass2'])) {
    		$err = "<font color=red><b>Passwords must match!</b></font><P>";
    	} else {
    		$enc = md5($_REQUEST['pass1']);
    		$sql = "UPDATE blog_users set password='$enc' where login='$_SESSION[login]'";
    		$res = $db->Execute($sql);
    		echo "<b>Password updated</b><br><hr><p>\n";
    	}
    }

} elseif($_REQUEST['act'] == "flickr") {

	if(!preg_match("/\w/",$_REQUEST['key'])) {
		echo "<b>You must enter an API key</b><br>\n";
	} else if(!preg_match("/\w/",$_REQUEST['femail'])) {
	        echo "<b>You must enter an email address</b><br>\n";
	} else if(!preg_match("/\w/",$_REQUEST['fpass'])) {
	        echo "<b>You must enter a password</b><br>\n";
	} else {

		$sql = "select * from blog_flickr where user_id=".getUID($_SESSION['login']);
		$res = $db->Execute($sql);

		if($res->RecordCount() > 0) {
			$sql = "update blog_flickr set api_key='".$_REQUEST['key']."', email='".$_REQUEST['femail']."', password='".$_REQUEST['fpass']."' where user_id=".$res->fields['user_id'];
			$res = $db->Execute($sql);
			echo "<b>Flickr info updated!</b><br>\n";
		} else {
			$sql = "insert into blog_flickr (user_id,api_key,email,password) values (".getUID($_SESSION['login']).",'".$_REQUEST['key']."','".$_REQUEST['femail']."','".$_REQUEST['fpass']."')";
			$res = $db->Execute($sql);
			echo "<b>Flickr info saved!</b><br>\n";
		}
	}
}

$sql = "SELECT * from blog_users where login='$_SESSION[login]'";
$res = $db->Execute($sql);

$sql = "select * from blog_flickr where user_id=".$res->fields['id'];
$flick = $db->Execute($sql);

?>

<script language="JavaScript">
function Del() {
	if(confirm("Are you sure you want to delete your account?  You will not be granted access until a new account has been created.")){
		document.deluser.submit();
	}
}
</script>

<table width=100%>
<tr>
<td width=50% valign=top>
	<table width=100%>
	<tr>
	<td class="header">
	<b>Modify User</b>
	</td>
	</tr>
	</table>
<form action="user.php" method=POST>
	<table>
	<tr>
	<td align=right>Login:</td><td><?= $_SESSION[login] ?>
<input type=hidden name=luser value="<?= $_SESSION[login] ?>">
	</td>
	</tr>
	<tr>
<td align=right>Name:</td>
<td><input type=text size=32 maxlength=32 name=name value="<?= $res->fields['name']; ?>"></td></tr>
<tr><td align=right>URL:</td>
<td><input type=text size=32 maxlength=64 name=url value="<?= $res->fields['url']; ?>"></td></tr>
<tr><td align=right>Email:</td>
<td><input type=text size=30 maxlength=40 name=email value="<?= $res->fields['email']; ?>"></td></tr>
</table>
<input type=hidden name=blogid value="<?=$blogid?>">
<input type=hidden name=act value="edit">
<input class=search type=submit value="Edit Info">
</form>
<?php if($enable_flickr): ?>

        <table width=100%>
        <tr>
        <td class="header">
        <b>Flickr Account Info</b>
        </td>
        </tr>
        </table>
	<form action="user.php" method=POST>
        <table>
        <tr>
        <td align=right>API Key:</td>
	<td><input type=text name=key size=32 maxlength=32 value="<?= $flick->fields['api_key']; ?>"></td>
        </tr>
        <tr>
	<td align=right>Flickr Email:</td>
	<td><input type=text size=32 maxlength=255 name=femail value="<?= $flick->fields['email']; ?>"></td></tr>
	<tr><td align=right>Flickr Password:</td>
	<td><input type=text size=32 maxlength=32 name=fpass value="<?= $flick->fields['password']; ?>"></td></tr>
	</table>
	<input type=hidden name=blogid value="<?=$blogid?>">
	<input type=hidden name=act value="flickr">
	<input class=search type=submit value="Edit Flickr Info">
	</form>

<?php endif; ?>
</td>
<td width=50% valign=top>
<table width=100%>
<tr>
<td class="header">
<b>Change Passsword</b>
</td>
</tr>
</table>
<?php if($err) { echo "$err\n"; } ?>
<form action="user.php" method=POST>
<table><tr>
<td align=right>New Password:</td>
<td><input type=password size=8 maxlength=16 name=pass1></td></tr>
<tr><td align=right>Re-type Password:</td>
<td><input type=password size=8 maxlength=16 name=pass2></td></tr>
</table>
<input type=hidden name=blogid value="<?=$blogid?>">
<input type=hidden name=act value="change">
<input type=hidden name=token value="<?=$_SESSION['token']?>">
<input class=search type=submit value="Change">
</form>
</td>
</tr>
</table>
<p>
<?php
	include("footer.php");
?>

