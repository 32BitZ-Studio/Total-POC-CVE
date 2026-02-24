<?PHP

session_start();
 
require("lib.php");

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

if(!isBlogAdmin($blogid)) {
	header("Location: logout.php\n\n");
	exit(0);
}

include("header.php");

if($_REQUEST['op'] == 'move') {
	
	if($_REQUEST['go'] == 'up') {
		$order = $_REQUEST['ord'] - 1;
	} elseif($_REQUEST['go'] == 'down') {
		$order = $_REQUEST['ord'] + 1;
	}

	$sql = "UPDATE blog_blocks set blk_order=0 where blog_id=$blogid and blk_order=$order";
	$res2 = $db->Execute($sql);
	$sql = "UPDATE blog_blocks set blk_order=$order where blk_id=".$_REQUEST['bid'];
	$res2 = $db->Execute($sql);
	$sql = "UPDATE blog_blocks set blk_order=".$_REQUEST['ord']." where blog_id=$blogid and blk_order=0";
	$res2 = $db->Execute($sql);
} elseif($_REQUEST['op'] == 'del') {

	$sql = "DELETE from blog_blocks where blk_id=".$_REQUEST['bid'];
	$res = $db->Execute($sql);
	$sql = "UPDATE blog_blocks set blk_order=blk_order-1 where blog_id=$blogid and blk_order > ".$_REQUEST['ord'];
	$res = $db->Execute($sql);

	echo "<br><b>Block Deleted!</b><p>\n";

} elseif($_REQUEST['op'] == 'add') {

	add_block();

} elseif($_REQUEST['op'] == 'save') {

	save_block();

} elseif($_REQUEST['op'] == 'edit') {

	edit_block($_REQUEST['bid']);
	
} elseif($_REQUEST['op'] == 'update') {

	if($_REQUEST['rss_id']) {
		$res = $db->Execute("select * from blog_rss where rss_id=".$_REQUEST['rss_id']);
		$_REQUEST['blk_title'] = $res->fields['title'];
	}

	$res = $db->Execute("UPDATE blog_blocks set title='".escape($_REQUEST['blk_title'])."', content='".escape($_REQUEST['content'])."',rss_id='".$_REQUEST['rss_id']."' where blk_id=".$_REQUEST['blk_id']);
	echo "<b>Block Updated</b><br>\n";
}

?>
<p>
<table width=100%>
<tr><td class=header><b>Blocks Administration</b></td></tr>
<tr>
	<td align=center>
		<table>
			<tr>
				<th class=header>Title</th>
				<th class=header>Type</th>
				<th class=header>Order</th>
				<th class=header>Edit</th>
				<th class=header>Delete</th>
			</tr>
<?php 
    	$sql = "SELECT * from blog_blocks where blog_id=$blogid order by blk_order";
        $res = $db->Execute($sql);
      
		$sql = "SELECT count(*) as count from blog_blocks where blog_id=$blogid";
        $r = $db->Execute($sql);
        $c = $r->fields['count'];
	  
	    $count = 0;
        while(!$res->EOF) {
				$sql2 = "select * from blog_block_types where blk_type_id=".$res->fields['blk_type_id'];
				$res2 = $db->Execute($sql2);
                echo "<tr bgcolor=#eeeeee>\n";
				echo "<td>".$res->fields['title']."</td>\n";
				echo "<td>".$res2->fields['blk_type']."</td>\n";
				echo "<td>";
				if($res->fields['blk_order'] == 1) {
					echo "<img src=\"images/spacer.gif\" width=24><a href=\"blocksadmin.php?blogid=$blogid&op=move&go=down&bid=".$res->fields['blk_id']."&ord=".$res->fields['blk_order']."\"><img src=images/down.gif border=0></a>";
				} elseif($res->fields['blk_order'] == $c) {
					echo "<a href=\"blocksadmin.php?blogid=$blogid&op=move&go=up&bid=".$res->fields['blk_id']."&ord=".$res->fields['blk_order']."\"><img src=images/up.gif border=0></a>";
				} else {
					echo "<a href=\"blocksadmin.php?blogid=$blogid&op=move&go=up&bid=".$res->fields['blk_id']."&ord=".$res->fields['blk_order']."\"><img src=images/up.gif border=0></a><a href=\"blocksadmin.php?blogid=$blogid&op=move&go=down&bid=".$res->fields['blk_id']."&ord=".$res->fields['blk_order']."\"><img src=images/down.gif border=0></a>";
				}
				echo "</td>\n";
				echo "<td align=center>";
				#type that can be edited
				$edits = array(2,5,6);
				if(in_array($res->fields['blk_type_id'],$edits)) {
					echo "<a href=\"blocksadmin.php?blogid=$blogid&op=edit&bid=".$res->fields['blk_id']."\"><img src=images/edit.gif border=0></a>";
				} else {
					echo "<br>";
				}
				echo "</td>\n";
				echo "<td align=center><a href=\"blocksadmin.php?blogid=$blogid&op=del&bid=".$res->fields['blk_id']."&ord=".$res->fields['blk_order']."\" onClick=\"return confirm('Are you sure?');\"><img src=images/delete.gif border=0></a></td>\n";
				echo "</tr>\n";
                $count++;
                $res->MoveNext();
        }

        if($count == 0) {
                echo "<tr><td colspan=5><b>No Blocks Found!</b></td></tr>\n";
        }
?>
		<tr>
		<td colspan=5><br></td>
		</tr>
		<tr>
		<td class=header colspan=5>
		Add New Block 
		</td>
		</tr>
		<tr>
		<td colspan=5>
		<form method=POST action=blocksadmin.php?blogid=<?=$blogid?>>
		Type: <select name=type>
<?php 

$sql = "select * from blog_block_types";
$res = $db->Execute($sql);

while(!$res->EOF) {

	echo "<option value=\"".$res->fields['blk_type_id']."\">".$res->fields['blk_type']."</option>\n";
	$res->MoveNext();
}

?>
		</select>
		<input type=hidden name=op value="add">
		<input type=submit class=search value="Add">
		</form>
		</td>
		</tr>
		</table>
	</td>
	</tr>
</table>
</form>
<?php 
	include("footer.php");
?>
