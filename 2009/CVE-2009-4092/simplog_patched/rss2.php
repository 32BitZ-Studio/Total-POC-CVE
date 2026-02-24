<?php 
    /**
     * rss2.php by Jason Buberel jason@buberel.org
     * Generates an rss-2.0 compliant feed of the blog
     * referenced by $blogid.
     */
	session_start();

	require_once("class.BlogInfo.php"); 

if(!isset($_REQUEST['blogid'])) {
	$sql = "SELECT blog_id FROM blog_list";
	$res = $db->Execute($sql);
	$blogid = $res->fields['blog_id'];
} else {
	$blogid = $_REQUEST['blogid'];
	}

    // get an instancce of the BlogInfo object.
    $blogInfo = new BlogInfo($blogid);

    // now grab the last 20 entries from that blog.
    $blogEntries = $blogInfo->getLastNEntries(20);

    // need to set the output content type to text/xml
    header("Content-type: text/xml");

    print '<?xml version="1.0" encoding="UTF-8"?>';
    print "\n";
?>
<rss version="2.0">
    <channel>
        <title><?= htmlentities($blogInfo->getBlogTitle()) ?></title>
        <link><?= htmlentities($blogInfo->getBlogURL()) ?></link>
        <description><?= $blogInfo->getBlogTagLine() ?></description>
        <language>en-us</language>
        <managingEditor><?= $blogInfo->getBlogAdminEmail() ?></managingEditor>
        <webMaster><?= $blogInfo->getBlogAdminEmail() ?></webMaster>
        <lastBuildDate><?= $blogInfo->getLastUpdate() ?></lastBuildDate>
<?php 
    // here we need to iterate over the list of blogentries and 
    // generate the output.
    foreach ($blogEntries as $blogEntry) {
?>
        <item>
            <title><?= $blogEntry->entryTitle ?></title>
            <description><?= htmlentities($blogEntry->entryBody) ?></description>
            <link><?= htmlentities($blogEntry->entryURL) ?></link>
	    <guid isPermaLink="true"><?= htmlentities($blogEntry->entryURL) ?></guid>
            <author><?= $blogEntry->entryAuthorEmail ?></author>
            <category><?= $blogEntry->entryCategoryName ?></category>
            <comments><?= htmlentities($blogEntry->entryCommentsURL) ?></comments>
            <pubDate><?= date("r",strtotime($blogEntry->entryDate)); ?></pubDate>
            <source url="<?= htmlentities($blogEntry->entryRSSURL) ?>">
                <?= $blogEntry->entryTitle ?>
            </source>
        </item>
<?php 
    }
?>
        
    </channel>
</rss>

