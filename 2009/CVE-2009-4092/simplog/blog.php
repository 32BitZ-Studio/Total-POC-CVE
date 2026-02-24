<?PHP

session_start();
require_once("lib.php");
require_once("class.BlogInfo.php");
require_once("class.BlogEntry.php");


echo "<script language=javascript src='".$baseurl."/simplog.js'></script>\n";

if ( !isset($blogid)) {
    $blogid = $_REQUEST['blogid'];
}

if(!$blogid) {
        $blogid = 1;
}


$blogInfo = new BlogInfo($blogid);

if ( $blogInfo->isUserAuthorized()) {
    
	$entryID = @$_REQUEST['entryID'];
	$keyword = @$_REQUEST['keyword'];
	$cid = @$_REQUEST['cid'];
	$date = @$_REQUEST['date'];
	
	if($entryID||$keyword|| $cid||$date){
			#	echo "line 30 <br>";

		
		$blogEntries = $blogInfo->getBlogEntriesByCriteria($keyword, $entryID, $cid, $date, $eid);
	
	}else{
    $blogEntries = $blogInfo->getLastNEntries($limit);
	}	
    foreach ($blogEntries as $blogEntry) {
		$line = marker_sub(stripslashes($blogInfo->getBlogTemplate()),$blogEntry,$blogInfo);
		
		#process <!--readmore--> as Continue reading and truncate.
		#echo $blogEntry->entryId;
		
		$subitem = explode('<!--readmore-->',$line);
		if (strlen(@$subitem[1]) == 0 || @$_REQUEST['cont'] == $blogEntry->entryId){
			$line = str_replace("<!--readmore-->","<a id='$blogEntry->entryId'>",$line); 					}else{
			$line = str_replace("<!--readmore-->","<br><a id='$blogEntry->entryId'></a><a href='?blogid=$blogid&cont=$blogEntry->entryId#$blogEntry->entryId'>Read More...</a><!--",$line);
			$line = str_replace("<!--endpost-->","-->",$line);
		}
		echo stripslashes($line);

    }
}
echo "<p><br></p>\n";

#echo "<div id=css-buttons2><p><a class=\"css-button2 simp\" href=\"http://www.simplog.org\" title=\"Powered by Simplog\"><span>Powered by</span> Simplog</a></div><br>\n";

#echo "<span class=small style=\"border: 2px dotted #000000; padding: 5px;\"><em>Powered by <a href=\"http://www.simplog.org\" target=_new>Simplog</a></em></span>\n";


?>
