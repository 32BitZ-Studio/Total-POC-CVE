<?PHP

session_start();

require("lib.php");
require_once("class.BlogInfo.php");
auth();

# get userid
$uid = getUID($_SESSION['login']);

#if no blog id passed, set to arbitrary blog in user's acl
if(!$_REQUEST['blogid']) {
    $sql = "SELECT blog_id from blog_acl where user_id=$uid order by blog_id";
    $res = $db->Execute($sql);
    $blogid = $res->fields[blog_id];
} else {
	$blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);

if(!isset($_REQUEST['trans'])) {
    $_REQUEST['trans'] = 0;
}

if(!isset($_REQUEST['format'])) {
    $_REQUEST['format']=0;
}
if(!isset($_REQUEST['act'])) {
    $_REQUEST['act']='';
}

if($blogid != "") {

#check if user in in blog's acl
    $sql = "select blog_id from blog_acl where user_id=$uid";
    $res = $db->Execute($sql);

    $ids = array();
    while(!$res->EOF) {
        array_push($ids,$res->fields['blog_id']);
        $res->MoveNext();
    }

#if not kick them out of the application
    if(!in_array($blogid,$ids)) {
        header("Location: logout.php\n\n");
    }

#get blog title and table name in DB
    $blogInfo =& new BlogInfo($blogid);

    $btitle = $blogInfo->getBlogTitle();
    $blogname = $blogInfo->getBlogTitle();
    $btemp = $blogInfo->getBlogTemplateId();
    $badmin = $blogInfo->getBlogAdminName();

}

    include("header.php");

echo "<b><a href=\"news.php\">News Feeds</a></b>\n";
echo "<table>\n";

		if($_REQUEST['act'] == "edit") {
			$sql = "SELECT * from blog_rss where rss_id=".$_REQUEST['fid'];
			$res = $db->Execute($sql);
			$fname = stripslashes($res->fields['title']);
			$url = stripslashes($res->fields['url']);
		} elseif($_REQUEST['act'] == "updfeed") {
			$rss = get_feed($_REQUEST['fid'],$_REQUEST['url']);
			$sql = "UPDATE blog_rss set title='".addslashes($rss->channel['title'])."', description='".addslashes($rss->channel['description'])."', url='".escape($_REQUEST['url'])."' where rss_id=".$_REQUEST['fid'];

			$res = $db->Execute($sql);
			echo "<tr><td colspan=2><b>News Feed Updated</b></td></tr>\n";
		} elseif($_REQUEST['act'] == "addfeed") {
	         $sql = "INSERT into blog_rss (url,user_id,title,description) values ('".escape($_REQUEST['url'])."',$uid,'','')";
	         $res = $db->Execute($sql);
			 $sql = "SELECT max(rss_id) as id from blog_rss";
			 $res = $db->Execute($sql);
			 $rid = $res->fields['id'];
			 $rss = get_feed($rid,$_REQUEST['url']);
			 $sql = "UPDATE blog_rss set title='".addslashes($rss->channel['title'])."', description='".addslashes($rss->channel['description'])."' where rss_id=$rid";
			 $res = $db->Execute($sql);
			
	         echo "<b>News Feed Added</b><p>\n";
		} elseif($_REQUEST['act'] == "delfeed") {
			$sql = "DELETE from blog_rss where rss_id=".$_REQUEST['fid'];
			$res= $db->Execute($sql);
			echo "<tr><td colspan=2><b>News Feed Deleted</b></td></tr>\n";
		} elseif($_REQUEST['act'] == "save") {

		    if($_REQUEST['body'] == "") {
        		echo "<b><font color=red>Sorry, gotta type something chief!</font></b><P>\n";
		    } else {

				$_REQUEST['body'] .= "<p><em>".$_REQUEST['comm']."</em>";

		        if($_REQUEST['trans']) {
        		    $_REQUEST['body'] = str_to_link($_REQUEST['body']);
				}
				# Insert the new blog entry.
				    $blogInfo->insertBlogEntry($_REQUEST['etitle'], $_REQUEST['body'], $uid, $_REQUEST['format'], $_REQUEST['cid']);
					
				do_pings(getLastInsertID($blogid));
        			echo "<p><b>Item Saved as Entry</b><br>\n";
    		}

		}

	?>
<?php if($_REQUEST['act'] == "view"): ?>
<?php 

$sql = "SELECT * from blog_rss where rss_id=".$_REQUEST['fid'];
$res = $db->Execute($sql);

 	$rss = get_feed($_REQUEST['fid'],$res->fields['url']);

      	echo "<p><table align=center width=50% cellspacing=1>\n";
	echo "<tr><td class=header colspan=2><b>";
	if($rss->channel['link']) {
		echo "<a href=\"".$rss->channel['link']."\" target=\"_new\">".$rss->channel['title']."</a>";
	} else {
		echo $rss->channel['title'];
	}
	echo "</b></td></tr>\n";
      for($y=0;$y<count($rss->items);$y++) {
			$rss->items[$y]['title'] = unhtmlentities($rss->items[$y]['title']);
			if($rss->items[$y]['link'] == '') {
				$rss->items[$y]['link'] = $rss->items[$y]['guid'];
			}

			if($rss->items[$y]['title'] == '') {
				$rss->items[$y]['title'] = "&gt;&gt;";
			}
			
			print "<tr class=darkrow><td valign=middle><a href=\"".$rss->items[$y]['link'] ."\" target=_new><b>". $rss->items[$y]['title'] . "</b></a></td><td align=center valign=middle width=100><form name=\"post$y\" action=news.php?blogid=$blogid&act=use method=POST><input type=hidden name=blogid value=\"$blogid\"><input type=hidden name=fid value=\"".$_REQUEST['fid']."\"><input type=hidden name=item value=\"$y\"><a href=\"javascript: document.post$y.submit();\"><img src=\"images/blog.gif\" alt=\"Blog This!\" title=\"Blog This!\" border=0 align=middle><b>Blog This!</b></a></form></td></tr>";
			$rss->items[$y]['description'] = unhtmlentities($rss->items[$y]['description']);
			print "<tr class=lightrow><td colspan=2><small>" . $rss->items[$y]['description'] ."</small></td></tr>\n";
		
      }
?>
</table>
</td></tr>
<?php elseif($_REQUEST['act'] == "use"): ?>
<?php 

$item = $_REQUEST['item'];
	
$sql = "SELECT * from blog_rss where rss_id=".$_REQUEST['fid'];
$res = $db->Execute($sql);

$rss = get_feed($_REQUEST['fid'],$res->fields['url']);

echo "<pre>";
print_r($rss);
echo "</pre><br>\n";

	$rss->items[$item]['title'] = unhtmlentities($rss->items[$item]['title']);
            if($rss->items[$item]['link'] == '') {
                $rss->items[$item]['link'] = $rss->items[$item]['guid'];
            }

            if($rss->items[$item]['title'] == '') {
                $rss->items[$item]['title'] = "&gt;&gt;";
            } 

 $entry = "<a href=\"".$rss->items[$item]['link']."\" target=_new>".$rss->items[$item]['title']."</a>: ".$rss->items[$item]['description']." \n\n{from <a href=\"".$rss->channel['link']."\" target=\"_new\">".$rss->channel['title']."</a>}";

	echo "<form action=\"preview.php\" method=POST target=\"preview\" name=prev>
          <input type=hidden name=etitle>
          <input type=hidden name=body>
          <input type=hidden name=blogid value=\"$blogid\">
          <input type=hidden name=uid value=\"$uid\">
          <input type=hidden name=cid>
          <input type=hidden name=trans>
          <input type=hidden name=format>
          </form>
          <form action=\"news.php\" method=POST name=entry>
          <p>
          <table width=100%>
            <tr>
            <td colspan=2 bgColor=\"#dddddd\" style=\"border:1px solid #999999;\">
          <b>Blog This!</b>
            </td>
            </tr>
            <tr>
            <td align=right bgcolor=\"#eeeeee\">
          Category:
            </td>
            <td>".category_list()."</td>
            </tr>
            <tr>
            <td align=right bgcolor=\"#eeeeee\">Title:</td>
            <td><input type=text size=24 maxlength=32 name=etitle>";
	    
	    if($enable_flickr) {
	            if(hasFlickrAccount($_SESSION['login'])) {
	                    echo " [<a href=\"javascript: openImg();\">Add an image</a>]";
	            }
	    }
	    
	    print "</td>
            </tr>
            <tr>
            <td align=right valign=top bgcolor=\"#eeeeee\">Entry:</td>
            <td>
          <textarea name=\"body\" rows=8 cols=60>$entry</textarea>
            </td></tr>
			<tr>
            <td align=right valign=top bgcolor=\"#eeeeee\">Comments:</td>
            <td>
          <textarea name=\"comm\" rows=4 cols=60></textarea>
            </td></tr>
            </table>
          <input type=hidden name=blogid value=\"$blogid\">
          <input type=hidden name=act value=\"save\">
          <input type=checkbox name=format value=\"1\" CHECKED>preserve formatting<br>
          <input type=checkbox name=trans value=\"1\" CHECKED>translate links(http, mailto)<br>";

		  if($use_weblog_rpc) {
            echo "<input type=checkbox name=ping value=\"1\">send update notice to weblogs.com<br>(may cause longer load time)<br>";
          }

          if($enable_trackback) {
                  echo "<input type=checkbox name=tb value=\"1\">send trackback ping<br>";
          }

          if($enable_pingback) {
                  echo "<input type=checkbox name=pb value=\"1\">send pingback<br>";
          }

         echo "<p>
          <input class=search type=submit value=\"Save\">&nbsp;
          <input type=button class=search value=\"Preview\" onClick=\"javascript: openPrev();\">
          </form><p>\n";

?>
<?php else: ?>
	<tr>
	<td class=header>Title</td>
	<td class=header>Description</td>
	<td class=header>URL</td>
	<td class=header>Edit</td>
	<td class=header>Delete</td>
	<td class=header>XML</td>
	</tr>
<?php 

    $sql = "SELECT * FROM blog_rss where user_id=$uid";
    $res = $db->Execute($sql);

    while(!$res->EOF) {
        echo "<tr bgcolor=#eeeeee><td><b><A href=\"news.php?act=view&fid=".$res->fields['rss_id']."&blogid=$blogid\">".$res->fields['title']."</a></b></td>\n";
		echo "<td>".$res->fields['description']."</td>\n";
		echo "<td>".$res->fields['url']."</td>\n";
        echo "<td align=center><A href=\"news.php?act=edit&fid=".$res->fields['rss_id']."&blogid=$blogid\"><IMG alt=\"Edit\" title=\"Edit\" src=\"images/edit.gif\" border=0></A></td>\n";
        echo "<td align=center><A href=\"news.php?act=delfeed&fid=".$res->fields['rss_id']."&blogid=$blogid\" onClick=\"return confirm('Are you sure you want to delete this feed?');\"><IMG title=\"Delete
\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>\n";
        echo "<td align=center valign=middle><a href=\"".$res->fields['url']."\" target=_new><img src=\"images/xml.gif\" border=0></a></td></tr>\n";
        $res->MoveNext();
    }

?>
			<tr><td colspan=6></td></tr>
		    <tr>
				<td><br></td>
			    <td valign=top>
				    <b><?php if($_REQUEST['act'] == "edit"){ echo "Edit"; } else { echo "Add New"; }?> News Feed</b>
				</td>
				<td colspan=4>
		<form action="news.php" method=POST name=entry>
		URL: <input type=text size=32 maxlength=128 name=url value="<?php if($_REQUEST['act'] == "edit") { echo $url; } ?>">
		<input type=hidden name=act value="<?php if($_REQUEST['act'] == "edit") { echo "updfeed"; } else { echo "addfeed"; } ?>">
		<?php if($_REQUEST['act'] == "edit") { echo "<input type=hidden name=fid value=\"".$_REQUEST['fid']."\">\n"; } ?>
		<input type=hidden name=blogid value="<?=$blogid?>">
		<input type=hidden name=user value="<?=$uid?>">
        <input class=search type=submit value="<?php if($_REQUEST['act'] == "edit") { echo "Update"; } else { echo "Add"; } ?>">&nbsp;
        </form>
		Find sydicated news feeds at <a href="http://www.syndic8.com" target=_new>syndic8</a> and <a href="http://www.newsisfree.com" target=_new>NewsIsFree</a>
				</td>
	</tr>
	</table>


</td></tr>
<?php endif; ?>
</table>
<?php 
    include("footer.php");
?>
