<?php 

if($_REQUEST['act'] == "add") {

    // no need to calculate a table name, as we will not be
    // creating new tables for each blog any longer.

    $err = "";

    if(($_REQUEST['type'] == 2) and (count($_REQUEST['luser']) == 0)) {
        $err = "Must pick atleast one user for this blog!";
    }

    if(($_REQUEST['type'] == 3) and (count($_REQUEST['luser']) != 1)) {
        $err = "Private Blog must have one user!";
    }

    if($err == "") {
	require_once("class.BlogServer.php");
        $blogServer = new BlogServer();

        $blogInfo = $blogServer->createBlog($_REQUEST['blogtitle'], $_REQUEST['tagline'], $_REQUEST['type'], $_REQUEST['luser'], $_REQUEST['badmin']);
        $blogUsers = $blogInfo->getBlogUsers();



        $to = "To:";
        foreach ($blogUsers as $blogUser) {
            $to .= $blogUser->userEmail.",";
        }

        $mesg = "The Blog admin has created a new blog, ".$_REQUEST['blogtitle'].", and has allowed you to contribute.  The next time you log in, you will be able to contribute to ".$_REQUEST['blogtitle'].".  Enjoy!\n";

        mail($to,"New Blog Creation",$mesg,"From: $adminemail\nReply-to: $adminemail");

        echo "<tr><td colspan=2>Blog ".$_REQUEST['blogtitle']." created!!!!</td></tr>\n";

    } else {
        echo "<tr><td colspan=2><b>$err</b></td></tr>\n";
    }

    $head = 'Add';
    $action = 'add';
    $blogtitle = '';
    $type_id = '';
    $blogadmin = '';
    $tagline = '';
} elseif($_REQUEST['act'] == "delete") { 
    $blogInfo =& new BlogInfo($_REQUEST['blog']);
    $title = $blogInfo->getBlogTitle();

    require("class.BlogServer.php");

    $blogServer = new BlogServer();
    $blogServer->deleteBlogById($_REQUEST['blog']);
    $blogInfo = NULL;
    echo "<tr><td colspan=2><b>Blog ".$title." deleted!</b></td></tr>\n";
    $head = 'Add';
    $action = 'add';
    $blogtitle = '';
    $type_id = '';
    $blogadmin = '';
    $tagline = '';

} elseif($_REQUEST['act'] == "update") {

    $err = "";

    if(($_REQUEST['type'] == 2) and (count($_REQUEST['acl']) == 0)) {
        $err = "Must pick atleast one user for this blog!";
    }

    if(($_REQUEST['type'] == 3) and (count($_REQUEST['acl']) != 1)) {
        $err = "Private Blog must have one user!";
    }

    if($err == "") {
	
    	if($_REQUEST['blogtitle'] != $_REQUEST['oldtitle']) {
        	$sql = "select count(*) as count from blog_list where title='".escape($_REQUEST['blogtitle'])."'";
        	$res = $db->Execute($sql);
        	$found = $res->fields['count'];
    	}
 
    	if(!$found) {
	
        	$sql = "update blog_list set title='".escape($_REQUEST['blogtitle'])."',type_id=".$_REQUEST['type'].", admin=".$_REQUEST['badmin'].", tagline='".escape($_REQUEST['tagline'])."'  where blog_id=".$_REQUEST['bid'];
        	$res = $db->Execute($sql);
 
        	$sql = "delete from blog_acl where blog_id=".$_REQUEST['bid'];
        	$res = $db->Execute($sql);
 
        	for($i=0; $i<count($_REQUEST['acl']); $i++) {
            		$sql = "SELECT id from blog_users where id='".$_REQUEST['acl'][$i]."'";
            		$res = $db->Execute($sql);
 
            		$sql = "insert into blog_acl (user_id,blog_id) values (".$res->fields['id'].",".$_REQUEST['bid'].")";
            		$res = $db->Execute($sql);
        	}

        	echo "<tr><td colspan=2><b>Blog $blogtitle Updated!</b></td></tr>\n";
    	} else {
        	echo "<tr><td colspan=2><b>Blog titled $blogtitle already exists!</b></td></tr>\n";
    	}

    } else {
      echo "<tr><td colspan=2><b>$err</b></td></tr>\n";
    }

    $head = 'Add';
    $action = 'add';
    $blogtitle = '';
    $type_id = '';
    $blogadmin = '';
    $tagline = '';
} elseif($_REQUEST['act'] == 'edit') {
	$sql = "select * from blog_list where blog_id=".$_REQUEST['blog'];
        $res = $db->Execute($sql);
        $blogtitle = $res->fields['title'];
        $type_id = $res->fields['type_id'];
        $blogadmin = $res->fields['admin'];
        $tagline = $res->fields['tagline'];
	$head = "Edit";
	$action = "update";
} else {
	$head = 'Add';
	$action = 'add';
	$type_id = 1;
}

?>

<tr>
<td valign=top>

<table>
        <tr>
        <td class=header>
        <b><?=$head?> Blog</b>
        </td>
        </tr>
        <tr>
        <td>
        <form action="admin.php" name=modblog method=POST>
                <table>
                <tr>
                <td valign=top>
                Title: <input type=text size=16 maxlength=32 name=blogtitle value="<?= $blogtitle; ?>"><p>
                </td>
                <td valign=top>
                Blog Type:
                <select name=type>
<?php 
    $sql = "SELECT type_id,description from blog_types";
        $res = $db->Execute($sql);
        while(!$res->EOF) {
            echo "<option value=\"".$res->fields['type_id']."\"";
            if($res->fields['type_id'] == $type_id) {
                echo " SELECTED";
	    }
		
            echo ">".$res->fields['description']."</option>\n";
            $res->MoveNext();
        }
?>
                </select>
                </td>
                </tr>
                <tr>
                <td colspan=2>
                Tagline: <input type=text size=16 maxlength=128 name=tagline value="<?=$tagline?>">
                </td>
                </tr>
                <tr>
                <td colspan=2>
                Blog Admin:
                <select name="badmin">
<?php 
                $sql = "SELECT blog_users.id,blog_users.name from blog_users";

		if($_REQUEST['act'] == 'edit') {
			$sql .= ", blog_acl where blog_acl.blog_id=".$_REQUEST['blog']." and blog_acl.user_id=blog_users.id";
		}

                $res = $db->Execute($sql);

                while(!$res->EOF) {
                        echo "<option value=\"".$res->fields['id']."\"";

                        if($blogadmin == $res->fields['id']) {
                                echo " SELECTED";
                        }

                        echo ">".$res->fields['name']."\n";
                $res->MoveNext();
             }

?>
                </select>
                </td>
                </tr>
                <tr>
                <td valign=top colspan=2>
                        <table>
                        <tr>
                        <tr>
                        <td>All Users<br>
                        <select name="luser[]" size=5 multiple>
<?php 
    $sql = "SELECT * from blog_users";
        $res = $db->Execute($sql);
        while(!$res->EOF) {
        echo "<option value=\"".$res->fields['id']."\">".$res->fields['name']."\n";
                $res->MoveNext();
        }
?>
			</select>
                        </td>
<?php if($_REQUEST['act'] == 'edit'):  ?>
                        <td valign=middle>
                        <input class=search type=button value=">>" onClick="javascript:addNames()"><p>
                        <input class=search type=button value="<<" onClick="javascript:removeNames()">
                        </td>
                        <td><?=$blogtitle?> ACL<br>
                        <select name="acl[]" size=5 multiple>

<?php 

	$count = 0;
       	$sql = "SELECT user_id from blog_acl where blog_id=".$_REQUEST['blog'];
        $res = $db->Execute($sql);
        while(!$res->EOF) {
                if(($res->fields['user_id'] == "") and ($count == 0)) {
                        break;
                }
                $sql2 = "select * from blog_users where id=".$res->fields['user_id'];
                $res2 = $db->Execute($sql2);
                echo "<option value=\"".$res2->fields['id']."\">".$res2->fields['name']."</option>\n";
                $count++;
                $res->MoveNext();
        }
	

        if($count == 0) {
                echo "<option value=\"null\">No Users Selected</option>\n";
        }
?>

                        </select>
                        </td>
<?php endif; ?>
                        </tr>
                        </table>
</td>
                </tr>
                </table>

        <input type=hidden name=blogid value="<?=$blogid?>">
        <input type=hidden name=oldtitle value="<?=$blogtitle?>">
        <input type=hidden name=bid value="<?=$_REQUEST['blog']?>">
        <input type=hidden name=act value="<?=$action?>">
        <input type=hidden name=adm value="blog">
        <input class=search type=submit onClick="return selectAll('<?=$action?>');" value="Submit">
        </form>

        </td>
        </tr>
        </table>

</td>
<td valign=top>

	<table>
	<tr><td class=header colspan=4><b>Active Blogs</b></td></tr>
	<tr class=darkrow><td><b>Blog Title</b></td><td><b>Blog Admin</b></td><td><b>Edit</b></td><td><b>Delete</b></td></tr>
<?php 

	$sql = "select * from blog_list order by blog_id";
	$res = $db->Execute($sql);
	$count = 0;
        while(!$res->EOF) {
		if($count % 2 == 0) {
			$class = 'lightrow';
		} else {
			$class = 'darkrow';
		}
                echo "<tr class=\"$class\">\n";
		echo "<td>".$res->fields['title']."</td>";
		$user = getUserInfo($res->fields['admin']);
		echo "<td>".$user['login']."</td>";
		echo "<td align=center><a href=\"admin.php?adm=blog&act=edit&blog=".$res->fields['blog_id']."&blogid=$blogid\"><img src=\"images/edit.gif\" border=0></a></td>";
		echo "<td align=center><a href=\"admin.php?adm=blog&act=delete&blog=".$res->fields['blog_id']."&blogid=$blogid\" onClick=\"return confirm('Are you sure you want to delete this blog?  This will delete all posts, comments, and everything for this blog from the system.');\"><img src=\"images/delete.gif\" border=0></a></td>";
                $res->MoveNext();
		++$count;
        }

?>
	</table>

</td>
</tr>
