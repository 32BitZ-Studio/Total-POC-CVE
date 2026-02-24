<?php 
/* rss.php -- generate an RSS feed from  simplog
 *
 * Coded by Dougal Campbell <http://dougal.gunters.org/>
 * 
 * TODO: create a static version automagicaly when stories
 *       are added/updated.
 */

session_start();

include "lib.php";
include_once("class.BlogInfo.php");

header("Content-type: text/xml");

$tem = "rss";

/* Get blog entries, using the rss template (mostly copied from blog.php) */

if(!isset($_REQUEST['blogid'])) {
	$sql = "SELECT blog_id FROM blog_list";
	$res = $db->Execute($sql);
	$blogid = $res->fields['blog_id'];
} else {
	$blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);
$blogEntries = $blogInfo->getLastNEntries(20);
$blogEntry = $blogEntries[0];

$maxdate = $blogEntry->entryDate;
$unixtime = strtotime($maxdate);

// How long do we want to allow descriptions to be?
$desc_len = 500;

/* print the rss header and channel start */
print '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
#print '<!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" "http://my.netscape.com/publish/formats/rss-0.91.dtd">' . "\n";
print '<rss version="0.91">' . "\n\n";

print "<channel>\n";
print "<title>".htmlentities($blogInfo->getBlogTitle())."</title>\n";
print "<link>".htmlentities($blogInfo->getBlogURL())."</link>\n";
print "<description>".$blogInfo->getBlogTagLine()."</description>\n";
print "<language>en-us</language>\n\n";

$pubDate = date("r",$unixtime);
print "<pubDate>$pubDate</pubDate>\n\n";

foreach ($blogEntries as $blogEntry) {
	$eid = $blogEntry->entryId;

	$isrss=1;

	/* Here we hardcode the "rss" template */
	echo "<item>\n";
	echo "<title>".htmlentities($blogEntry->entryTitle)."</title>\n";
	echo "<link>".htmlentities($blogEntry->entryURL)."</link>\n";
	echo "<description>".htmlentities($blogEntry->entryBody)."</description>\n";
	echo "</item>\n\n";
}


/* Close out the rss channel */
print "</channel>\n";
print "</rss>\n";

/* eof */
?>
