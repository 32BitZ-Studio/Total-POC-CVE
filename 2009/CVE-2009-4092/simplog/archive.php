<?PHP

include("lib.php");
include_once ("class.BlogInfo.php");
include_once ("class.BlogEntry.php");
session_start();

if(!is_numeric($_REQUEST['blogid'])) {
	$sql = "select * from blog_list";
	$r = $db->Execute($sql);
	$blogid = $r->fields['blog_id'];
} else {
    $blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);

$btitle = $blogInfo->getBlogTitle();

include("header.php");

echo "[<small><a href=\"$blogurl?blogid=$blogid\">Back to $btitle</a></small>]<center><table width=100% cellspacing=5><tr><td valign=top>\n";
echo "<font face=\"arial,helvetica,sans-serif\">\n";

if(@$_REQUEST['act'] == "search") {
	echo "Results for <font color=red>".$_REQUEST['keyw']."</font>:<p>\n";
	$keyw = escape($_REQUEST['keyw']);
	$keyw = urldecode($keyw);
}

if(!is_numeric($_REQUEST['y'])) {
	$_REQUEST['y'] = '';
}

if(!is_numeric($_REQUEST['m'])) {
        $_REQUEST['m'] = '';
}

if(!is_numeric($_REQUEST['d'])) {
        $_REQUEST['d'] = '';
}

if ( isset($_REQUEST['y']) && isset($_REQUEST['m']) && isset($_REQUEST['d'])) {
    $date = $_REQUEST['y']."-".$_REQUEST['m']."-".$_REQUEST['d'];
} elseif ( isset($_REQUEST['y']) && isset($_REQUEST['m']) ) {
    $date = $_REQUEST['y']."-".$_REQUEST['m'];
} else {
    $date = "";
}

$count = 0;
if ( $blogInfo->isUserAuthorized() ) {
$blogEntries = $blogInfo->getBlogEntriesByCriteria(escape(@$_REQUEST['keyw']), escape(@$_REQUEST['pid']), escape(@$_REQUEST['cid']), escape($date), escape(@$_REQUEST['eid']));
    

    
    foreach ($blogEntries as $blogEntry) {
		
	$line = marker_sub(stripslashes($blogInfo->getBlogTemplate()),$blogEntry, $blogInfo);
	$line = stripslashes($line);
			
        echo $line;
        $count++;
    }
}
if($count == 0) {
	echo "<b>No matching results found</b><p>\n";
}

if(isset($_REQUEST['pid'])) {
	tb_list(escape($_REQUEST['pid']));
	echo "<p>\n";
	pb_list(escape($_REQUEST['pid']));
}

echo "</font></td><td valign=top align=right>\n";

$m = (!@$_REQUEST['m']) ? date("n",mktime()) : escape($_REQUEST['m']);
$y = (!@$_REQUEST['y']) ? date("Y",mktime()) : escape($_REQUEST['y']);

mk_drawCalendar($m,$y);

echo "</tr></table>\n";
echo "</center>\n";

include("footer.php");

?>
