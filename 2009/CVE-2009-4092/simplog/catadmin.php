<?php 

session_start();

require("lib.php");

auth();

$uid = getUID($HTTP_SESSION_VARS['login']);

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

		if($_REQUEST['act'] == "edit") {
			$sql = "SELECT * from blog_categories where cat_id=".$_REQUEST['cid']." and blog_id=$blogid";
			$res = $db->Execute($sql);
			$cname = stripslashes($res->fields['cat_name']);
			
		} elseif($_REQUEST['act'] == "updcat") {
			$sql = "UPDATE blog_categories set cat_name='".escape($_REQUEST['cname'])."' where cat_id=".$_REQUEST['cid']." and blog_id=$blogid";

			$res = $db->Execute($sql);
			echo "<tr><td colspan=2><b>Category Updated</b></td></tr>\n";
		} elseif($_REQUEST['act'] == "addcat") {
	         $sql = "INSERT into blog_categories (cat_name,blog_id) values ('".escape($_REQUEST['cname'])."',$blogid)";
		   
	         $res = $db->Execute($sql);
	         echo "<b>Category Added</b><p>\n";
		} elseif($_REQUEST['act'] == "delcat") {
			$sql = "DELETE from blog_categories where cat_id=".$_REQUEST['cid']." and blog_id=$blogid";
			$res= $db->Execute($sql);
			echo "<tr><td colspan=2><b>Category Deleted</b></td></tr>\n";
		}

?>
<table width=100%>
	<tr>
	<td width=50% valign=top>
		<table width=100%>
		    <tr>
			    <td bgColor="#dddddd" style="border:1px solid #999999;">
				    <b><?php if($_REQUEST['act'] == "edit"){ echo "Edit"; } else { echo "Add New"; }?> Category</b>
				</td>
			</tr>
		</table>
		<form action="catadmin.php" method=POST name=entry>
        Name: <input type=text size=32 name=cname value="<?php if($_REQUEST['act'] == "edit") { echo $cname; } ?>"><p>
		<input type=hidden name=act value="<?php if($_REQUEST['act'] == "edit") { echo "updcat"; } else { echo "addcat"; } ?>">
		<input type=hidden name=adm value="cat">
		<?php if($_REQUEST['act'] == "edit") { echo "<input type=hidden name=cid value=\"".$_REQUEST['cid']."\">\n"; } ?>
		<input type=hidden name=blogid value="<?=$blogid?>">
		<input type=hidden name=remuser value="<?=$_SESSION['login']?>">
        <input class=search type=submit value="<?php if($_REQUEST['act'] == "edit") { echo "Update"; } else { echo "Add"; } ?>">&nbsp;
        </form>
	</td>
	<td valign=top align=center>
	
		<table width=100%>
		<tr>
		<td bgColor="#dddddd" style="border:1px solid #999999;" colspan=4>
		<b>Available Categories</b>
		</td>
		</tr>
		</table>

		<table>
		<tr>
		<td class=header>Category</td>
		<td class=header>Edit</td>
		<td class=header>Delete</td>
		</tr>
<?php 

	$sql = "SELECT * FROM blog_categories where blog_id=$blogid";
	$res = $db->Execute($sql);

	while(!$res->EOF) {
		echo "<tr bgcolor=#eeeeee><td><b>".$res->fields['cat_name']."</b></td>\n";
		echo "<td align=center><A href=\"catadmin.php?act=edit&cid=".$res->fields['cat_id']."&blogid=$blogid\"><IMG alt=\"Edit\" title=\"Edit\" src=\"images/edit.gif\" border=0></A></td>\n";
		echo "<td align=center><A href=\"catadmin.php?act=delcat&cid=".$res->fields['cat_id']."&blogid=$blogid\" onClick=\"return confirm('Are you sure you want to delete this category?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td></tr>\n";
		$res->MoveNext();
	}

?>	
		</table>
	
	</td>
	</tr>
	</table>


</td></tr>
</table>

<?php include("footer.php"); ?>
