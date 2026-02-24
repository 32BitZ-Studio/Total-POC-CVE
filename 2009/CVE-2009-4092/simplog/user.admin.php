<?php 

if($_REQUEST['act'] == "add") {
    require("rand_pass.php");
 
    $passwd = random_password();
 
    $sql = "SELECT max(id) as id from blog_users";
    $res = $db->Execute($sql);
    $id = $res->fields['id'] + 1;
 
    $enc = md5($passwd);
 
    $sql = "INSERT into blog_users VALUES($id,'".escape($_REQUEST[luser])."','$enc','".escape($_REQUEST[name])."','".escape($_REQUEST[url])."','".escape($_REQUEST[email])."',0)";
    $res = $db->Execute($sql);

    if($_REQUEST['newblog'] == 'new') {
	$userarr = array(1);
	require_once("class.BlogServer.php");
        $blogServer = new BlogServer();

        $blogInfo = $blogServer->createBlog($_REQUEST['newblogtitle'], '', 3, $userarr, $id);
	$sql = "insert into blog_acl (user_id,blog_id) values ($id,".$blogInfo->blogId.")";
        $res = $db->Execute($sql);
    } else {
	$sql = "insert into blog_acl (user_id,blog_id) values ($id,".$_REQUEST['blog'].")";
	$res = $db->Execute($sql);
    }
 
    $mesg = "$_REQUEST[name] -\n\nAn account has been created for you for Simplog.\n";
    $mesg .= "Your account information:\n\nLogin: $_REQUEST[luser]\n\nPassword: $passwd\n\n";
    $mesg .= "DO NOT give your account\n";
    $mesg .= "info to ANYONE, or your account will be taken away.  Log in and \n";
    $mesg .= "enjoy.\n";
 
    mail($_REQUEST[email],"Simplog account information",$mesg,"From: $adminemail\nReply-To: $adminemail"); 
    echo "<tr><td colspan=2><b>Account $_REQUEST[luser] succesfully added</b></td></tr>\n";
 
} elseif($_REQUEST['act'] == "delete") {
    $sql = "DELETE from blog_users where id=".$_REQUEST['uid'];
    $res = $db->Execute($sql);
 
    $sql = "DELETE from blog_acl where user_id=".$_REQUEST['uid'];
    $res = $db->Execute($sql);

    $sql = "DELETE from blog_entries where userid=".$_REQUEST['uid'];
    $res = $db->Execute($sql);
 
    echo "<tr><td colspan=2><b>Account deleted</b></td></tr>\n";
 
} elseif($_REQUEST['act'] == 'edit') {
	if(is_numeric($_REQUEST['uid'])) {
		$sql = "select * from blog_users where id=".$_REQUEST['uid'];
		$res = $db->Execute($sql);
	} else {
		echo "<b>Invalid Operation</b><br/>\n";
	}
} elseif($_REQUEST['act'] == 'update') {

	if(is_numeric($_REQUEST['uid'])) {

		$sql = "update blog_users set name='".$_REQUEST['name']."', email='".$_REQUEST['email']."', url='".$_REQUEST['url']."'";
		if(preg_match("/\w/",$_REQUEST['passwd'])) {
			$sql .= ", password='".md5($_REQUEST['passwd'])."'";
		}

		$sql .= " where id=".$_REQUEST['uid'];
		$res = $db->Execute($sql);
	
		echo "<tr><td colspan=2><b>Account updated</b></td></tr>\n";
	} else {
                echo "<b>Invalid Operation</b><br/>\n";
        }
}

?>
<tr>
<td width=50% valign=top>
	<table width=100%>
	<tr><td class=header>
<b><?php if($_REQUEST['act'] == 'edit') { echo "Edit "; } else { echo  "Add "; }  ?> User</b>
	</td></tr>
	</table>
<form action="admin.php" method=POST>
<table>
<tr><td align=right>Login:</td>
<td>
<?php if($_REQUEST['act'] == 'edit'):
	echo $res->fields['login'];
 else: ?>
<input type=text size=15 maxlength=20 name=luser>
<?php endif; ?>
</td>
</tr>
<tr><td align=right>Name:</td>
<td><input type=text size=32 maxlength=32 name=name value="<?=$res->fields['name']?>"></td></tr>
<tr><td align=right>URL:</td>
<td><input type=text size=32 maxlength=64 name=url value="<?=$res->fields['url']?>"></td></tr>
<tr><td align=right>Email:</td>
<td><input type=text size=30 maxlength=40 name=email value="<?=$res->fields['email']?>"></td></tr>
<?php if($_REQUEST['act'] == 'edit'): ?>
<tr><td align=right>New Password:</td>
<td><input type=text size=8 maxlength=16 name=passwd><input type=hidden name=uid value="<?=$_REQUEST['uid']?>"></td></tr>
<?php else: ?>
<tr><td colspan=2><hr></td></tr>
<tr><td align=right><input type=radio name=newblog value='set' checked> Set Default Blog:</td>
<td>
<select name=blog>
<?php blog_list(); ?>
</select>
</td></tr>
<tr><td colspan=2 align=center>~or~</td></tr>
<tr><td align=right><input type=radio name=newblog value='new'> Create New Blog:</td>
<td>
<input type=text name=newblogtitle size=16 maxlength=32>
</td></tr>
<?php endif; ?>
</table>
<input type=hidden name=blogid value="<?=$blogid?>">
<input type=hidden name=act value="<?php if($_REQUEST['act'] == 'edit') { echo "update"; } else { echo  "add"; }  ?>">
<input type=hidden name=adm value="user">
<input class=search type=submit value="<?php if($_REQUEST['act'] == 'edit') { echo "Edit"; } else { echo  "Add"; }  ?> User">
</form>
</td>
<td valign=top>
	<table width=100%>
	    <tr><td class=header><b>User List</b></td></tr>
	    <tr><td align=center>
		<table>
	    	<tr class=darkrow><td><b>Login</b></td><td><b>Name</b></td><td><b>Email</b></td><td><b>Edit</b></td><td><b>Delete</b></td></tr>
<?php 
	$sql = "SELECT * from blog_users where login != '$_SESSION[login]'";
	$res = $db->Execute($sql);
	
	$count = 0;
	while(!$res->EOF) {
		if($count % 2 == 0) {
			$class = 'lightrow';
		} else {
			$class = 'darkrow';
		}
		echo "<tr class=$class><td>".$res->fields['login']."</td><td>".$res->fields['name']."</td><td>".$res->fields['email']."</td><td align=center><a href=\"admin.php?adm=user&act=edit&uid=".$res->fields['id']."&blogid=$blogid\"><img src=\"images/edit.gif\" border=0></a></td><td align=center><a href=\"admin.php?adm=user&act=delete&uid=".$res->fields['id']."&blogid=$blogid\" onClick=\"return confirm('Are you sure you want to delete this user?');\"><img src=\"images/delete.gif\" border=0></a></td></tr>\n";
		$res->MoveNext();
		++$count;
	}
?>
		</table>
	</td></tr>
	</table>
</td>
</tr>

