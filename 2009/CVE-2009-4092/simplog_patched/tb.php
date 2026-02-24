<?php 
// Trackback server module for MyPHPBlog
// Written by Dougal Campbell

include_once("lib.php");

if(!$enable_trackback) {
	tb_failure('Trackback is disabled');
	exit(0);
}

$method = $_SERVER["METHOD"];

$track_id = $_SERVER["PATH_INFO"];
#$track_id = $_REQUEST['eid'];
// Get rid of the leading slash
$track_id = ereg_replace('^/','',$track_id);


$title = @$_REQUEST["title"];
$excerpt = @$_REQUEST["excerpt"];
$url = @$_REQUEST["url"];
$blog_name = @$_REQUEST["blog_name"];
$tb_url = @$_REQUEST["tb_url"];

// Decide what to do:
if (isset($_REQUEST["__mode"])){
	switch ($_REQUEST["__mode"]){
		case "send_ping":
		    	$tb_result = send_tb_ping($tb_url);
   			print $tb_result;
			break;
		case "rss":
    			tb_rss($track_id);
			break;
		case "list":
		    	tb_list($track_id);
			break;
		default:
	
	}
}else{
	if(isset($track_id)) {
		echo $track_id;
    	do_trackback($track_id);
    }	
}

// END OF MAIN CODE

// Save a trackback from elsewhere to us
function do_trackback($id) {
    global $title,$excerpt,$url,$blog_name,$db,$conn;
    
    $datetime = time();
    
    if ($url) {
        if (!$title)
            $title = $url;
    } else {
        return tb_failure("URL required.");
    }

    //check that referrer is same domain as passed url
    #$urlparam = parse_url($url);
    #$refer = parse_url($_SERVER['HTTP_REFERER']);

    #if($urlparam['host'] != $refer['host']) {
	    #	return tb_failure("URL and referrer domain must match.");
	    #}
    
#	echo "<br>Referring URL:$url<br>";
	include "tb_validate.php";
 
 	if ($blacklist == 1){
 		tb_failure("URL blacklisted.");
 		#$excerpt ="***This entry has been censored***";
 		#$title = "***title removed***";
		exit;
 	}
 
 	$title = addslashes($title);
  	$excerpt = addslashes($excerpt);
 	$blog_name = addslashes($blog_name);
 
    $sql = "INSERT INTO blog_trackback
        (entry_id,url,title,excerpt,blog_name,added,ip)
        VALUES
        ($id,'$url','$title','$excerpt','$blog_name',NOW(),'".$_SERVER['REMOTE_ADDR']."')";
#	echo "<br>SQL:$sql<br>";
    $res = $db->Execute($sql);

    if ($res) {
        tb_success();
    } else {
        tb_failure('Could not insert Trackback data!');
    }
}

function tb_success() {
    header ("Content-type: text/xml");
    
    print '<?php xml version="1.0" encoding="iso-8859-1"?>' . "\n";
    print '<response>' . "\n";
    print '<error>0</error>' . "\n";
    print '</response>' . "\n";

}

function tb_failure($msg = 'TrackBack Failed') {
    header ("Content-type: text/xml");
    
    print '<?php xml version="1.0" encoding="iso-8859-1"?>' . "\n";
    print "<response>\n";
    print "<error>1</error>\n";
    print "<message>$msg</message>\n";
    print "</response>\n";

}

?>
