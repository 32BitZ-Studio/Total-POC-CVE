<?PHP
session_start();

include("lib.php");

if(!is_numeric($_REQUEST['blogid'])) {
    	$sql = "SELECT * from blog_list";
	$res = $db->Execute($sql);
	$blogid = $res->fields['blog_id'];
} else {
	$sql = "SELECT * from blog_list where blog_id=".$_REQUEST['blogid'];
	$res = $db->Execute($sql);
	$blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);

$btitle = $blogInfo->getBlogTitle();
$tid = $blogInfo->getBlogTemplateId();

include("header.php"); 

if(isLoggedIn()) {

	$uid = getUID($_SESSION['login']);
}

if($_REQUEST['op'] == "add") {
	$host = $_SERVER['HTTP_HOST'];
    if(!preg_match("/^http(s*):\/\/$host(.*?)comments\.php/",$_SERVER['HTTP_REFERER'])) {
	echo "<b>Comments can not be posted from outside the application</b><br>\n";
    } else {	    
	if(!$_REQUEST['cname']) {
		$_REQUEST['cname'] = $anon;
	}
	$cname = $_REQUEST['cname'];
	
	if($_REQUEST['comment']) {

		$ok = filter_comment();
		
		if($ok) {
		
			if ($safe_comments) {
	        		$comment = safeHTML($_REQUEST['comment']);
        		}
		
			$sql = "INSERT into blog_comments (bid,eid,name,email,comment,date,ip) values ";
			$sql .= "(".$_REQUEST['blogid'].",".$_REQUEST['pid'].",'".escape($_REQUEST['cname'])."','".escape($_REQUEST['email'])."','".escape($comment)."',now(),'".$_SERVER['REMOTE_ADDR']."')";
			$res = $db->Execute($sql);
		}
	} else {
		echo "<b><font color=red>Sorry chief, no blank comments</font></b><p>\n";
	}
    }
    
} elseif($_REQUEST['op'] == "prev") {
	
	if(!$_REQUEST['cname']) {
        	$_REQUEST['cname'] = $anon;
    	}
	
	$cname = $_REQUEST['cname'];
        $comment = $_REQUEST['comment'];
	
} elseif($_REQUEST['op'] == "del") {

	if(is_numeric($_REQUEST['cid'])) {

		$res = $db->Execute("delete from blog_comments where id=".$_REQUEST['cid']);
		echo "<b>Comment Deleted</b><br>\n";
	} else {
		echo "<b>Invalid operation</b>\n";
	}
} elseif($_REQUEST['op'] == "edit") {

	if(is_numeric($_REQUEST['cid'])) {
		$res = $db->Execute("select * from blog_comments where id=".$_REQUEST['cid']);
		$cname = $res->fields['name'];
		$email = $res->fields['email'];
		$comment = $res->fields['comment'];
	} else {
                echo "<b>Invalid operation</b><br/>\n";
        }

} elseif($_REQUEST['op'] == "save") {

	if(is_numeric($_REQUEST['cid'])) {

		if(!$_REQUEST['cname']) {
        		$_REQUEST['cname'] = $anon;
    		}

    		if($_REQUEST['comment']) {
        		if ($safe_comments) {
            			$comment = safeHTML($_REQUEST['comment']);
        		} else {
				$comment = $_REQUEST['comment'];
			}
	
        		$sql = "UPDATE blog_comments set name='".escape($_REQUEST['cname'])."',email='".escape($_REQUEST['email'])."',comment='".escape($comment)."' where id=".$_REQUEST['cid'];
        		$res = $db->Execute($sql);

			echo "<b>Comment updated</b><br>\n";
    		} else {
        		echo "<b><font color=red>Sorry, no blank comments</font></b><p>\n";
    		}	
	} else {
		echo "<b>Invalid Operation</b><br/>\n";
	}
}

echo "<center><table width=100% cellspacing=5 cellpadding=2><tr><td valign=top colspan=2>\n";
echo "<font face=\"arial,helvetica,sans-serif\">\n";
if(!is_numeric($_REQUEST['pid'])) {
    $blogEntries = $blogInfo->getLastNEntries(1);
    $blogEntry = $blogEntries[0];
} else {
    $blogEntry = $blogInfo->getBlogEntryById($_REQUEST['pid']);
}

	if(!is_numeric($_REQUEST['pid'])) { $_REQUEST['pid'] = $blogEntry->entryId; }

	$res->fields['body'] = ereg_replace("<tick>","'",$res->fields['body']);
	$res->fields['title'] = ereg_replace("<tick>","'",$res->fields['title']);

	$format = $res->fields['format'];

	$sql3 = "SELECT template from blog_template where temp_id=$tid";
    	$res3 = $db->Execute($sql3);

	$line = marker_sub(stripslashes($res3->fields['template']),&$blogEntry,&$blogInfo);
    echo stripslashes($line);


echo "<small>[ ";

if($comment_win) {
	echo "<a href=\"javascript: window.close();\">Close Window</a>";
} else {
	echo "<a href=\"$blogurl?blogid=$blogid\">Blog Main</a>";
}

echo "| <a href=\"#form\">Post a comment</a> ]</small></font></td></tr>\n";

echo "<tr><td bgColor=\"#dddddd\" style=\"border:1px solid #999999;\" colspan=2><a name=\"comment\"></a><b>Comments.....</b></td></tr>\n";

if($_REQUEST['op'] == 'prev') {
	echo "<tr><td colspan=2><b>Preview</b></td></tr>\n";
	echo "<tr><td bgColor=\"#dddddd\" style=\"border:1px solid #999999;\" align=right valign=top width=150><small>\n";
    if($_REQUEST['email'] != "") {
        echo "<a href=\"mailto: ".$_REQUEST['email']."\">".$_REQUEST['cname']."</a>\n";
    } else {
        echo $_REQUEST['cname']."\n";
    }

    echo "<p>".date("m/d/Y h:iA")."</small></td>\n<td bgcolor=#eeeeee>\n";
    echo $_REQUEST['comment'];
	echo "</td></tr>\n";
} else {

  $sql = "SELECT * from blog_comments where bid=$blogid and eid=".intval($_REQUEST['pid'])." order by id";
  $res = $db->Execute($sql);

  while(!$res->EOF) {
	echo "<tr><td bgColor=\"#dddddd\" style=\"border:1px solid #999999;\" align=right valign=top width=150><small>\n";
	if($res->fields['email'] != "") {
		echo "<a href=\"mailto: ".$res->fields['email']."\">".$res->fields['name']."</a>\n";
	} else {
		echo $res->fields['name']."\n";
	}

	echo "<p>".format_date($res->fields['date'])."</small></td>\n<td bgcolor=#eeeeee>\n";
	echo $res->fields['comment'];

	if(isAdmin() or isBlogAdmin($blogid)) {
		echo "<p>[<a href=\"comments.php?blogid=$blogid&pid=".$_REQUEST['pid']."&op=edit&cid=".$res->fields['id']."\">Edit</a>][<a href=\"comments.php?blogid=$blogid&pid=".$_REQUEST['pid']."&op=del&cid=".$res->fields['id']."\" onClick=\"return confirm('Are you sure?');\">Delete</a>] IP Address: ".$res->fields['ip']." <small>[<a href=\"admin.php?blogid=$blogid&adm=ban&ip=".$res->fields['ip']."\" onClick=\"return confirm('Are you sure you want to ban this IP?');\">ban</a>]</small>\n";
	}
	
	echo "</td></tr>\n";
	$res->MoveNext();
  }

}

echo "</table>\n";
echo "</center>\n";

?>

<p>
<a name="form"></a>
<form method=POST action="comments.php#form" name="comment">
<input type=hidden name=blogid value="<?=$blogid?>">
<input type=hidden name=pid value="<?=$_REQUEST['pid']?>">
<input type=hidden name=op value="<?php if($_REQUEST['op'] == 'edit'){ echo "save"; } else { echo "add"; } ?>">
<?php if($_REQUEST['op'] == 'edit') { echo "<input type=hidden name=cid value=\"".$_REQUEST['cid']."\">\n"; } ?>
<table>
<tr><td bgColor="#dddddd" style="border:1px solid #999999;" colspan=2><b>Want to share?</b> (Use HTML for formatting)</td></tr>
<tr>
<td bgColor="#dddddd" style="border:1px solid #999999;" valign=top align=right><b>Name:</b></td>
<td><input type=text name=cname maxlength=64 value="<?php if (($_REQUEST['op'] == 'edit') or ($_REQUEST['op'] == 'prev')){ echo $cname; }else{echo $user_name;} ?>"></td>
</tr>
<tr>
<td bgColor="#dddddd" style="border:1px solid #999999;" valign=top align=right><b>Email:</b></td>
<td><input type=text name=email maxlength=128 value="<?php if (($_REQUEST['op'] == 'edit') or ($_REQUEST['op'] == 'prev')){ echo $_REQUEST['email']; }  ?>"></td>
</tr>
<tr>
<td bgColor="#dddddd" style="border:1px solid #999999;" valign=top align=right><b>Comment:</b></td>
<td><textarea name=comment rows=10 cols=40 wrap=physical><?php if (($_REQUEST['op'] == 'edit') or ($_REQUEST['op'] == 'prev')){ echo $comment; } ?></textarea></td>
</tr>
</table>
<input class=search type=submit value="<?php if($_REQUEST['op'] == 'edit'){ echo "Update"; } else { echo "Post"; } ?> Comment">
<?php if($_REQUEST['op'] != "edit"): ?>
<input class=search type=submit value="Preview" onClick="document.comment.op.value='prev';">
<?php endif; ?>
</form>

<?php 

include("footer.php");

?>
