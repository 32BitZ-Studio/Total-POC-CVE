<?php
echo "echo start 05to06<br>\n";

$uri = ereg_replace("install.php","",$uri);

$url = "http://".$host.$uri;

#echo "$url<p>\n";

$opts = array('mysql' => 'ENGINE=MyISAM');

$fields = "
password C(32) notnull
";

$sql = $dict->ChangeTableSQL('blog_users', $fields, $opts));

$res = $db->Execute($sql);

$sql = "select id, login, name, email from blog_users";

$res = $db->Execute($sql);

while(!$res->EOF) {

	$pass = random_password();
    $enc = md5($pass);

    echo $res->fields['login'].": pass = $pass<br>\n";

    $sql2 = "update blog_users set password='$enc' where id='".$res->fields['id']."'";
    $res2 = $db->Execute($sql2);

    $mesg = $res->fields['name'].",\n\nDue to an upgrade and security enhancement in Simplog,";
    $mesg .= "it was required to issue new passwords to all users.\n\n";
    $mesg .= "New password for account ".$res->fields['login']." is: $pass.\n\n";
    $mesg .= "Please login at $url and change you password as soon as possible.\n\nThanks!";

    mail($res->fields['email'],"New Simplog Password",$mesg,"From: admin@".$HTTP_ENV_VARS['HTTP_HOST']);
    $res->MoveNext();
}
echo "end 05to06<br>\n";
?>
