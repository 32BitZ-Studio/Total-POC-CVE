<?php 
	include("../lib.php");
        include("../header.php");	
?>
<h3>Online Documentation</h3>
<li><b><a href="index.php?s=admin">Administration/Installation Guide</a></b>
<li><b><a href="index.php?s=user">User's Guide</a></b>
<p>

<?php

	if(isset($_REQUEST['s'])) {
		switch ($_REQUEST['s']){
			case 'admin':
				include("admin.html");
				break;
			default:
				include("user.html");
				break;
		}
	}

?>

</p>
<?php include("../footer.php"); ?>
	
