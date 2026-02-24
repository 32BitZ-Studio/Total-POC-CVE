<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<title>Simplog Installation</title>

<link rel="stylesheet" href="simplog.css" type="text/css" />
</head>
<body bgcolor=#ffffff marginwidth=0 marginheight=0 leftmargin=0 topmargin=0>
<table width=100% border=0 cellspacing=0 cellpadding=5 class=header>
<tr>
<td align=left><span class=blogname>Simplog Installation</span></td>
</tr>
</table>
<?php 
	include('rand_pass.php');
	
	$errors = array();

	switch($_REQUEST['from']) {

		case "step1":
			if($_REQUEST['act'] == "Accept") {
				include("install/step2.php");
			} else {
				include("install/gpl.inc");
			}
			break;
		case "step2":
			if(!step2check()) {
			    include("install/step3.php");
			} else {
			    $error = 1;
			    include("install/step2.php");
			}
			break;
		case "step3":
			if($_REQUEST['act'] == "New Install") {
				include("install/install1.php");
			} else {
				include("install/upgrade1.php");
			}
			break;
		case "install1":
			if(!admincheck()) {
				include("install/install2.php");
			} else {
				include("install/install1.php");
			}
			break;
		case "install2":
			include("install/install3.php");
			break;
		case "upgrade1":
			include("install/upgrade2.php");
			break;
		case "upgrade2":
            include("install/upgrade3.php");
            break;
		default:
			include("install/step1.php");
			break;

	}

	include("footer.php");

function step2check() {

	global $_REQUEST;

	$err = 0;

	if($_REQUEST['dbhost'] == "") {
		$err = 1;
	}

	if($_REQUEST['dbname'] == "") {
	        $err = 1;
    }

	return $err;
}

function admincheck() {

	global $_REQUEST, $errors;

	$err = 0;

	if($_REQUEST['alogin'] == "") {
	        $err = 1;
			array_push($errors,"alogin");
    }

	if($_REQUEST['apass1'] == "") {
            $err = 1;
            array_push($errors,"apass");
    }

    if($_REQUEST['apass1'] != $_REQUEST['apass2']) {
            $err = 1;
            array_push($errors,"apasseq");
    }

	if($_REQUEST['aemail'] == "") {
            $err = 1;
            array_push($errors,"aemail");
    }

	return $err;
}

?>
