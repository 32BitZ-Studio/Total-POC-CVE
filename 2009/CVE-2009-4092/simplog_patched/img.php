<?php
	session_start();
	require_once("lib.php");

//	auth();
	
	$uid = getUID($_SESSION['login']);
	
	$sql = "select * from blog_flickr where user_id=$uid";
	
	$res = $db->Execute($sql);

?>
<html>
<head>

<link rel="stylesheet" type="text/css" href="simplog.css">

<style>

body {
	margin: 5px;
}

</style>

<script>

function addImg(thumb,img) {
	
	var align = 'left';
	
	ialign = document.img.ialign;
	for (var i=0; i < ialign.length; i++) {
		if(ialign[i].checked) {
			align = ialign[i].value;
		}
	}
	
	var link = '<a href="'+img+'" target="_new"><img src="'+thumb+'" style="border: 2px solid black; margin: 3px;" align="'+align+'"></a>';
	
	
	opener.document.entry.body.value = link + opener.document.entry.body.value;
	return false;
}

</script>
</head>
<body>
<form method=post target="_new" action="http://www.flickr.com/signin/flickr/">
<input type=hidden name="email" value="<?=$res->fields['email']?>">
<input type=hidden name="password" value="<?=$res->fields['password']?>">
<input type=hidden name="cf" value="">
<input type=hidden name="done" value="1">
<input type=submit name="Submit" value="Manage Your Images on flickr" class="search">

<div style="float: right"><a href="javascript: window.close();">Close Window</a></div>

</form>
<h3>Select an image....</h3>
<center>
<form name="img">
Align: 
<input type="radio" name="ialign" value="left" checked>Left &nbsp;
<input type="radio" name="ialign" value="right">Right &nbsp;
</form>
<?php

	
/*if(isset($_POST['submit'])) {
	
	print "uploading ".$_FILES['photo']['name']."<br>";
	
	$url = 'http://www.flickr.com/tools/uploader_go.gne';

	$postData = array();

	//simulates <input type="file" name="file_name">
	$postData[ 'photo' ] = "@".$_FILES['photo']['tmp_name'];
	$postData[ 'email' ] = "ashcraft@13monkeys.com";
	$postData[ 'password' ] = "foobar";
	$postData[ 'title' ] = "Test";
	$postData[ 'is_public' ] = "1";

	$ch = curl_init();

	curl_setopt($ch, CURLOPT_URL, $url );
	curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
	curl_setopt($ch, CURLOPT_POST, 1 );

	//seems no need to tell it enctype='multipart/data' it already knows
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postData );

	$response = curl_exec( $ch );

	if(preg_match("/<status>ok<\/status>/",$response)) {
		echo "Photo uploaded succesfully!<br>\n";
	} else {
		preg_match("/<verbose>(.*?)<\/verbose>/",$response,$m);

		echo "Upload Failed: $m[1]<br>\n";
	}

}*/

require_once("phpFlickr/phpFlickr.php");
// Create new phpFlickr object
$f = new phpFlickr($res->fields['api_key']);

$i = 0;
    // Find the NSID of the username inputted via the form
    $nsid = $f->people_findByEmail($res->fields['email']);
    
    // Get the friendly URL of the user's photos
    $photos_url = $f->urls_getUserPhotos($nsid);
    
    // Get the user's first 36 public photos
    $photos = $f->people_getPublicPhotos($nsid, NULL, 36);
    
    // Loop through the photos and output the html
    foreach ($photos['photo'] as $photo) {
	    #echo "<a href=$photos_url$photo[id]>";
	    echo "<a href=\"#\" onClick=\"addImg('".$f->buildPhotoURL($photo,"square")."','".$f->buildPhotoURL($photo)."');\">";
        echo "<img style='border: 2px solid black'  alt='$photo[title]' ".
            "src=" . $f->buildPhotoURL($photo, "square") . ">";
        echo "</a> &nbsp; ";
        $i++;
        // If it reaches the third photo, insert a line break
        if ($i % 4 == 0) {
            echo "<br>\n";
        }
    }
?>

<!--h3>Upload a photo to your Flickr acct</h3>
<form method='post' enctype="multipart/form-data">
    <input type="file" name='photo'><br>
    <input type='submit' name="submit" value='Upload Photo'>
</form-->
</center>
</body>
</html>
