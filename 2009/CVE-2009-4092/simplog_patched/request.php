<?PHP
 
session_start();
  
include('lib.php');

if(!$_REQUEST['blogid']) {
    $sql = "SELECT blog_id from blog_acl where user_id=$uid";
    $res = $db->Execute($sql);

    $blogid = $res->fields[blog_id];
} else {
    $blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);

auth();

$uid = getUID($_SESSION['login']);

include("header.php");

if($act == "req") {

	$sql = "select max(id) as id from blog_request";
	$res = $db->Execute($sql);
	$id = $res->fields['id'] + 1;

	$sql = "insert into blog_request values ($id,'".escape($_REQUEST[blogtitle])."','$users','".escape($_REQUEST[reason])."',now(),'$HTTP_SESSION_VARS[login]',$_REQUEST[type])";
	$res = $db->Execute($sql);

	echo "<b>Blog Request Sent!</b><p>\n";
}

?>
	<p>
    <table>
    <tr>
    <td class=header>
    <b>Request New Blog</b>
    </td>
    </tr>
    <tr>
    <td>
    <form action="request.php" method=POST>
    Title: <input type=text size=8 maxlength=8 name=blogtitle>
    Blog Type:
    <select name=type>
<?php 
    $sql = "SELECT type_id,description from blog_types";
	$res = $db->Execute($sql);

	while(!$res->EOF) {
        echo "<option value=\"".$res->fields['type_id']."\"";
        if($res->fields['description'] == "protected") {
            echo "SELECTED";
        }
        echo ">".$res->fields['description']."\n";
		$res->MoveNext();
    }
?>
    </select>
    <p>
	Reason: <textarea name=reason cols=40 rows=5 wrap=physical></textarea><p>
    Users:
    <select name="luser[]" size=5 multiple>
<?php 
    $sql = "SELECT login,name from blog_users";
	$res = $db->Execute($sql);
    
	while(!$res->EOF) {
		if($res->fields['login'] != $_SESSION['login']) {
        	echo "<option value=\"".$res->fields['login']."\">".$res->fields['name']."\n";
		}
		$res->MoveNext();
    }
?>
    </select>
    <p>
    <p>
    <input type=hidden name=act value="req">
	<input type=hidden name=blogid value="<?=$blogid?>">
    <input class=search type=submit value="Request Blog">
    </form>
 
    </td>
    </tr>
    </table>

<?PHP
	include("footer.php");
?>
