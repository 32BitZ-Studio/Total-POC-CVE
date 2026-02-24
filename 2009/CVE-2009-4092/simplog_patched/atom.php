<?php 
/* atom.php -- generate an Atom 0.3 feed from Simplog
 *
 * Coded by Jeremy Ashcraft <http://www.simplog.org/>
 * 
 */

session_start();

include "lib.php";
include_once("class.BlogInfo.php");

header("Content-type: text/xml");

/* Get blog entries, using the rss template (mostly copied from blog.php) */

if(!isset($_REQUEST['blogid'])) {
	$sql = "SELECT blog_id FROM blog_list";
	$res = $db->Execute($sql);
	$blogid = $res->fields['blog_id'];
} else {
	$blogid = $_REQUEST['blogid'];
}

$blogInfo =& new BlogInfo($blogid);
$blogEntries = $blogInfo->getLastNEntries(10);
$blogEntry = $blogEntries[0];

$maxdate = $blogEntry->entryDate;
$unixtime = strtotime($maxdate);

// How long do we want to allow descriptions to be?
$desc_len = 500;

/* print the xml header and channel start */
print '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
print '<feed version="0.3" xmlns="http://purl.org/atom/ns#">' . "\n\n";

print "<title>".htmlentities($blogInfo->getBlogTitle())."</title>\n";
print "<link rel=\"alternate\" type=\"text/html\" href=\"".htmlentities($blogInfo->getBlogURL())."\" />\n";

$tz = date("O",(date("U",$unixtime) - date("Z",$unixtime)));
$tz = substr($tz,0,3).':'.substr($tz,3);
$modified = date("Y-m-d\TH:i:s",$unixtime).$tz;

print "<modified>$modified</modified>\n";
print "<tagline>".$blogInfo->getBlogTagline()."</tagline>\n";
$data = parse_url($baseurl);
print "<id>$blogInfo->blogURL</id>\n";
print "<generator name=\"Simplog 0.9\">http://www.simplog.org</generator>\n";
print "<copyright>Copyright (c) ".date("y")."</copyright>\n\n";

foreach ($blogEntries as $blogEntry) {
	$eid = $blogEntry->entryId;

	$tz = date("O",(date("U",strtotime($blogEntry->entryDate)) - date("Z",strtotime($blogEntry->entryDate))));
	$tz = substr($tz,0,3).':'.substr($tz,3);
	$modified = date("Y-m-d\TH:i:s",strtotime($blogEntry->entryDate));
	$issued = $modified.$tz;

	/* Here we hardcode the "atom" template */
	echo "<entry>\n";
	echo "<title>".htmlentities($blogEntry->entryTitle)."</title>\n";
	echo "<link rel=\"alternate\" type=\"text/html\" href=\"".htmlentities($blogEntry->entryURL)."\" />\n";
	echo "<id>".htmlentities($blogEntry->entryURL)."</id>\n";
	echo "<issued>$issued</issued>\n";
	echo "<modified>$issued</modified>\n";
	//user section
	$sql = "select * from blog_users where id=".$blogEntry->entryUserId;
	$res = $db->Execute($sql);
	echo "<author>\n";
	echo "	<name>".$res->fields['name']."</name>\n";
	echo "	<url>".$res->fields['url']."</url>\n";
	echo "	<email>".$res->fields['email']."</email>\n";
	echo "</author>\n";
	echo "<content type=\"text/html\" mode=\"escaped\">\n";
	echo "	".htmlentities($blogEntry->entryBody)."\n";
	echo "</content>\n";
	echo "</entry>\n\n";
}


/* Close out the atom feed */
print "</feed>\n";

/* eof */
?>
