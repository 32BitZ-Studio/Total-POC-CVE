<?php 

session_start();

include_once('lib.php');
include_once('class.BlogInfo.php');
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

if(!isset($_REQUEST['trans'])) {
	$_REQUEST['trans'] = 0;
}

if(!isset($_REQUEST['format'])) {
	$_REQUEST['format']=0;
}

# by this point in time, we really should have a valid
# blogid, so we can use that to resurrect our bloginfo object.
$blogInfo =& new BlogInfo($blogid);

if($blogid != "") {

#check if user in in blog's acl
	$ids = $blogInfo->getBlogUsers();

#if not kick them out of the application
	if(!userHasRights($uid,$ids)) {
	#if((!in_array($uid,$ids)) and (!isBlogAdmin($blogid)) and (!isAdmin())) {
		header("Location: logout.php?blogid=$blogid\n\n");
	}

#get blog title and table name in DB
	$btitle = $blogInfo->getBlogTitle();
	$btemp = $blogInfo->getBlogTemplateId();

}

include("header.php");

?>

<script>

function add_smiley(smile) {

	document.entry.body.value += smile;

}
function add_glyph(glyph) {

	document.entry.body.value += glyph;

}

</script>

<table cellpadding=0 cellspacing=0 border=0 width="100%">
		<tr valign = "top">
						<td style="border-right:1px solid black;padding-right:24px;">
<?php 
#upper left feedback
switch ($_REQUEST['act']){
	case "save": 
	if($_REQUEST['body'] == "") {
		echo "<b><font color=red>Sorry, gotta type something chief!</font></b><P>\n";
	} else {
		if($_REQUEST['trans']) {
			$_REQUEST['body'] = str_to_link($_REQUEST['body']);
		}

        # Insert the new blog entry.
			$blogInfo->insertBlogEntry($_REQUEST['etitle'], do_tags($_REQUEST['body']), $uid, $_REQUEST['format'], $_REQUEST['cid']);

			do_pings(getLastInsertID($blogid));

		echo "<b>Entry Saved</b><br>\n";
		}
		print_form();
		break;

	case "del":
    // make sure this user is authorized to delete this entry.
	if($blogInfo->deleteBlogEntryById($_REQUEST['pid'])){
        echo "<b>Blog Entry Deleted</b><p>\n";
    } else {
        echo "<b><font color=red>Wait a minute, you don't own that entry....</font></b><p>\n";
    }
		print_form();
		break;

	case "update":
		if( $blogInfo->updateBlogEntryById($_REQUEST['pid'], $_REQUEST['etitle'], do_tags($_REQUEST['body']), $_REQUEST['format'], $_REQUEST['cid']) ){
			do_pings($_REQUEST['pid']);
		echo "<b>Entry Updated</b><p>\n";
	} else {
		echo "<b><font color=red>Wait a minute, you don't own that entry....</font></b><p>\n";
	}
		print_form();
		break;

	case "templ":
    if ( $blogInfo->updateBlogTemplate($_REQUEST['templ']) ) {
        $btemp = $_REQUEST['templ'];
        echo "<b>Template Changed</b><p>\n";
    } else {
        echo "<b><font color=red>Blog Template could not be updated.</font></b><p>\n";
    }
		break;

	case "edit":
    $blogEntry = $blogInfo->getBlogEntryById($_REQUEST['pid']);
    $body = ereg_replace("<tick>","'",$blogEntry->entryBody);
    $title = ereg_replace("<tick>","'",$blogEntry->entryTitle);
    print_edit($title,$body,$_REQUEST['pid'],$blogEntry->entryCategoryId);
		break;

	default:
		#print edit box, palettes, buttons
		print_form();

}
echo "</td>\n";

#right side content

echo "<td valign=top align=\"center\" style=\"padding-left:24px;\">\n";

if($blogid) {

	$max = $blogInfo->getEntryCount();
    if(!$_REQUEST['start']) {
        $start = 0;
    } else {
		$start = $_REQUEST['start'];
	}

	$end = $start + $limit;



tem_select();
echo "<br><table width=100%><tr><td bgColor=\"#dddddd\" align=center style=\"border:1px solid #999999;\">\n";
echo "<b>Blog entries ".($start+1)."-".$end." for ".$_SESSION['login'].":</b></td></tr></table>\n";

	echo "<table width=100%><tr>";

	if($start != 0) {
		echo "<td align=left valign=middle><a href=\"edit.php?start=".($start-$limit)."&blogid=$blogid\"><img src=images/prev.gif border=0 title=\"Previous $limit\" alt=\"Previous $limit\"></a></td>\n";
	}

	if($end <$max) {
		echo "<td align=right valign=middle><a href=\"edit.php?start=".($start+$limit)."&blogid=$blogid\"><img src=images/next.gif border=0 title=\"Next $limit\" alt=\"Next $limit\"></a></td>\n";
	}

	echo "</tr></table>\n";

	$blogEntries = $blogInfo->getBlogEntriesByRange($limit, $start, 1);

    echo "<table>\n";

    echo "<tr><th class=\"smallheader\">Posted By</th>
    	<th class=\"smallheader\">Title</th>
		<th class=\"smallheader\">Category</th>
		<th class=\"smallheader\">Date</th>
		<th class=\"smallheader\">Edit</th>
		<th class=\"smallheader\">Delete</th>
		<th class=\"smallheader\">Comments</th>
		\n";

	$count = 0;
	foreach ($blogEntries as $blogEntry) {

    	$body = ereg_replace("<tick>","'",$blogEntry->entryBody);
		$title = ereg_replace("<tick>","'",$blogEntry->entryTitle);

		if($blogEntry->entryFormat) {
			$body  = nl2br($body);
		}

		if(($count % 2) == 0) {
			$bg = "lightRow";
		} else {
			$bg = "darkRow";
		}

		echo "<tr class=\"$bg\">
			<td class=\"small\" align=center>".$blogEntry->entryAuthorName."</td>
			<td class=\"small\"><A href=\"edit.php?act=edit&pid=".$blogEntry->entryId."&blogid=$blogid&cid=".$blogEntry->entryCategoryId."\">".$title."</a></td>
			<td class=\"small\" align=center>".$blogEntry->entryCategoryName."</td>
			<td class=\"small\" align=center><small>".$blogEntry->formattedEntryDate."</small></td>
			<td align=center><A href=\"edit.php?act=edit&pid=".$blogEntry->entryId."&blogid=$blogid&cid=".$blogEntry->entryId."\"><IMG alt=\"Edit\" title=\"Edit\" src=\"images/edit.gif\" border=0></A></td>
			<td align=center><A href=\"javascript:del(".$blogEntry->entryId.",$blogid);\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>
			<td class=\"small\" align=center>
			\n";

		#get number of comments for entry
		$commentCount = $blogEntry->getCommentCount();
		
		if($commentCount == 0) {
			echo "0\n";
		} else {
			echo "<a href=\"comments.php?blogid=$blogid&pid=".$blogEntry->entryId."\">".$commentCount."</a>\n";
		}
		
		echo "</td></tr>\n";
		$count++;
	}

	echo "</table>\n<center>\n";
 
	if(!$count) {
		echo "No blog entries found<P>\n";
	}

	echo "<table width=100%><tr>";

	if($start != 0) {
    	echo "<td align=left valign=middle><a href=\"edit.php?start=".($start-$limit)."&blogid=$blogid\"><img src=images/prev.gif border=0 title=\"Previous $limit\" alt=\"Previous $limit\"></a></td>\n";
	}

	if($end <$max) {
    	echo "<td align=right valign=middle><a href=\"edit.php?start=".($start+$limit)."&blogid=$blogid\"><img src=images/next.gif border=0 title=\"Next $limit\" alt=\"Next $limit\"></a></td>\n";
	} 

} else {
	echo "</td>\n";
}

	echo "</tr></table></center></td></tr></table>\n";

	include("footer.php");

?>
