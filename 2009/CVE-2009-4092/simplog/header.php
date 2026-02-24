<?php
    
	header("X-Pingback: $baseurl/api.php\n");
	if(!isset($blogInfo)) {
		$btitle = "Simplog";
		$btag = "Powerful, yet simple....";
	} else {
		$btitle = $blogInfo->getBlogTitle();
		$btag = $blogInfo->getBlogTagline();
	}


	if(isLoggedIn()) {
		$uid = getUID($_SESSION['login']);
	}
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<title><?=$btitle?>: <?=$btag?></title>

<script language="javascript" type="text/javascript" src="<?=$baseurl?>/simplog.js"></script>

<link rel="alternate" type="text/xml" title="RSS" href="<?=$baseurl?>/rss2.php" />
<link rel="pingback" href="<?=$baseurl?>/api.php" />
<link rel="stylesheet" href="<?=$baseurl?>/simplog.css" type="text/css" />
</head> 
<body bgcolor=#ffffff marginwidth=0 marginheight=0 leftmargin=0 topmargin=0>
<table width=100% border=0 cellspacing=0 cellpadding=5 class=header>
<tr>
<td align=left><span class=blogname><?=$btitle?></span><br><span class=blogtag><?=$btag?></span></td>
</tr>
</table>
<?php 
	if(isLoggedIn()) {
		show_menu(); 
	}

?>
<br>
