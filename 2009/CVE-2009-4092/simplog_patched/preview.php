<?php session_start() ?>
<html>
<head>
<title>Preview</title>
<script>
window.focus();
</script>
<link rel="stylesheet" href="simplog.css">
</head>
<body bgcolor=#ffffff>
<div align=center>
<small><a href="javascript: window.close();">Close Window</a></small><p>
<table>
<tr>
<td>
<?php 
    include("lib.php");
    include_once("class.BlogInfo.php");
    include_once("class.BlogEntry.php");
    $blogid = $_REQUEST['blogid'];
    if (!$blogid) { $blogid = 1;}
    $blogInfo =& new BlogInfo($blogid);
    $blogEntries = $blogInfo->getLastNEntries(1);
    $blogEntry = $blogEntries[0];

	if(!$blogEntry) {
		//initiate ugly hack to get around getcmntlink bug
		$resultSet->fields['blog_entry_id'] = 0;
	        $resultSet->fields['body'] = '';
	        $resultSet->fields['post_date'] = date("Y-m-d H:i:s");
	        $resultSet->fields['date'] = date("Y-m-d H:i:s");
	        $resultSet->fields['userid'] = getUID($_SESSION['login']);
	        $resultSet->fields['title'] = '';
	        $resultSet->fields['karma'] = 0;
	        $resultSet->fields['format'] = 1;
	        $resultSet->fields['cat_id'] = 1;
		$resultSet->fields['blog_id'] = $blogid;

		$blogEntry = new BlogEntry($resultSet);
	}
	
    
	$templ = stripslashes($_REQUEST['templ']);

	if($_REQUEST['adm'] == "tem") {

		if(is_numeric($_REQUEST['tid'])) {
			$sql = "select template from blog_template where temp_id=".$_REQUEST['tid'];
			$res = $db->Execute($sql);
			$templ = $res->fields['template'];
			$templ = stripslashes($templ);
		}

		$sql2 = "select name,url,email from blog_users where login = '".escape($_REQUEST['remuser'])."'";
		$res2 = $db->Execute($sql2);

		$pid = 1;
        	$cid = 1;
        	$etitle = "This is a preview";
        	$body = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit, sed diam nonummy nibh euismod tincidunt ut laoreet dolore magna aliquam erat volutpat. Ut wisi enim ad minim veniam, quis nostrud exerci tation ullamcorper suscipit lobortis nisl ut aliquip ex ea commodo consequat. Duis autem vel eum iriure d";
		$eid = 1;
        	$blogEntry->entryCategoryId = $cid;
        	$blogEntry->entryTitle = $etitle;
        	$blogEntry->entryBody = $body;
        	$blogEntry->entryId = $eid;
        	$blogEntry->entryDate = "2004-01-01 12:12:12";


	} else {
	
		$sql = "SELECT temp_id from blog_list where blog_id=".$_REQUEST['blogid'];
		$res = $db->Execute($sql);

		if(isset($res->fields['temp_id'])) {
			$sql = "select template from blog_template where temp_id=".$res->fields['temp_id'];
			$res = $db->Execute($sql);
			$templ = $res->fields['template'];
			$templ = stripslashes($templ);
		}

		if($_REQUEST['comm']) {
			$_REQUEST['body'] .= "<p><em>".$_REQUEST['comm']."</em>";
		}

        	$blogEntry->entryCategoryId = $_REQUEST['cid'];
	        $blogEntry->entryTitle = stripslashes($_REQUEST['etitle']);
	        $blogEntry->entryBody = stripslashes($_REQUEST['body']);
	        $blogEntry->entryDate = date("Y-m-d h:i:s");
		$blogEntry->entryFormat = $_REQUEST['format'];

	}

	$line = marker_sub($templ,$blogEntry,$blogInfo);
	echo $line;

?>
</div>
</td>
</tr>
</table>
</body>
</html>
