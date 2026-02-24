<?php 
	if(!file_exists("config.php")) {
		header("Location: install.php");
		exit(0);
	}

	session_start();

    require_once("lib.php");
    require_once("class.BlogInfo.php");
    require_once("class.BlogEntry.php");

    $blogid = $_REQUEST['blogid'];
    if(!isset($blogid)) {
            $blogid = 1;
    }

    $blogInfo = new BlogInfo($blogid);

    include("header.php");

?>

<table cellpadding=0 cellspacing=0 border=0 width="100%" style="height:90%;">
	<tr valign="top">
		<td style="border-right:1px solid #999999;padding-right:24px;">
<div style="padding:10px;">

<?php include("blog.php"); ?>

</div>
		</td>
		<td align="center" width=150 style="padding-left: 24px;">

<?php include("blocks.php"); ?>

		</td>
	</tr>
</table>

<?php include("footer.php"); ?>
