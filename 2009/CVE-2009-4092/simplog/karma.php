<?php 

require("lib.php");

if(!isset($_SERVER['HTTP_REFERER'])) {
	echo "<b>No karma whores!</b>\n";
	exit();
}
$blogid=$_REQUEST['blogid'];
# number of seconds in one hour 
$oneday = 60 * 60;

#get current timestamp
$now = time();

#calculate timestamp of one day ago
$delete = $now - $oneday;

#delete all entries older than one day
$sql = "DELETE FROM blog_karma where timestamp <= $delete";
$res = $db->Execute($sql);

if(is_numeric($_REQUEST['blogid']) and is_numeric($_REQUEST['pid'])) {

	#look if already had karma vote for this entry
	$sql = "SELECT count(*) as count from blog_karma where ip='".$_SERVER['REMOTE_ADDR']."' and bid=".$_REQUEST['blogid']." and eid=".$_REQUEST['pid'];
	$res = $db->Execute($sql);

	#if not 
	if($res->fields['count'] == 0) {

		#get karma value for entry
		$sql = "SELECT karma from blog_entries where blog_entry_id=".$_REQUEST['pid'];
		$res = $db->Execute($sql);

		$karma = $res->fields['karma'];

		#perform op
		if($_REQUEST['op'] == "add") {
			$karma = $karma + 1;
		} elseif($_REQUEST['op'] == "sub") {
			$karma = $karma - 1;
		}

		#update karma for entry
		$sql = "UPDATE blog_entries set karma=$karma where blog_entry_id=".$_REQUEST['pid'];
		#echo "$sql<br>\n";
		$res = $db->Execute($sql);
	
		#enter IP into karma table
		$sql = "INSERT into blog_karma values ('".$_SERVER['REMOTE_ADDR']."',".$_REQUEST['blogid'].",".$_REQUEST['pid'].",'$now')";
		$res = $db->Execute($sql);
	} else {
		$blogInfo =& new BlogInfo($_REQUEST['blogid']);
		include("header.php");

?>
Sorry, only one karma vote per IP, per entry, per hour<p>
<a href="javascript: history.go(-1);">Go back</a>
<?php 
		include("footer.php");
		exit();
	}

	if(eregi("comments.php",$_SERVER['HTTP_REFERER'])) {
		header("Location: comments.php?blogid=".$_REQUEST['blogid']."&pid=".$_REQUEST['pid']."\n\n");
	} else {
		if(eregi("blogid",$_SERVER['HTTP_REFERER'])) {
		header("Location: ".$_SERVER['HTTP_REFERER']."\n\n");

		}else{
			header("Location: ".$_SERVER['HTTP_REFERER']."?blogid=".$_REQUEST['blogid']."\n\n");
		}
	}
} else {
	echo "<b>Invalid Operation</b><br/>\n";
}

?>
