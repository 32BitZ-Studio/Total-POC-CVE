<?php 

$fields = "
admin I notnull default 0
";

$sql = $dict->ChangeTableSQL('blog_users',$fields,$opts);

$res = $db->Execute($sql[0]);

$fields = "
temp_id I notnull default '1',
admin I notnull default '1'
";

$sql = $dict->ChangeTableSQL('blog_list',$fields,$opts);

foreach($sql as $s) {
	echo "$s<br>\n";
	$res = $db->Execute($s);
}

$sql = "SELECT * from blog_list";
$res = $db->Execute($sql);

while(!$res->EOF) {
   	
	$fields = "format I notnull default'0'";
	$sql2 = $dict->ChangeTableSQL("blog_".$res->fields['table_name'],$fields,$opts);
	foreach($sql2 as $s) {
		$res2 = $db->Execute($s);
	}
	$res->MoveNext();
}

$fields = "
temp_id I KEY AUTO,
name C(16) NOTNULL default '',
template X NOTNULL default ''
";

$sql = $dict->CreateTableSQL('blog_template',$fields,$opts);

foreach($sql as $s) {
	echo $s."<br>\n";
	$res = $db->Execute($s);
}
		   
    if ($dir = @opendir("./templates")) {
        while (($file = readdir($dir)) !== false) {
            if(preg_match("/(.*?)\.tem$/",$file,$match)) {
                if($file != 'rss.tem') {
                    echo "importing $file.......<br>\n";
                    $cont = implode('',file("./templates/$file"));
                    $sql = "insert into blog_template (name,template) values ('$match[1]','$cont')";
                    $res = $db->Execute($sql);
				}
           }
        }
        closedir($dir);
    } else {
		echo "<b>Error!! : Couldn't load templates into DB</b><p>\n";
	}

?>

<b>Please select which user is the admin superuser:</b><p>
<form method=POST action=install.php>
<select name=id>
<?php 
    $sql = "select id,login from blog_users";
    $res = $db->Execute($sql);

    while(!$res->EOF) {
        echo "<option value=\"".$res->fields['id']."\">".$res->fields['login']."</option>\n";
 		$res->MoveNext(); 
    }

?>
</select>
<input type=hidden name=dbtype value="<?=$_REQUEST['dbtype']?>">
<input type=hidden name=dbname value="<?=$_REQUEST['dbname']?>">
<input type=hidden name=dbhost value="<?=$_REQUEST['dbhost']?>">
<input type=hidden name=dbuser value="<?=$_REQUEST['dbuser']?>">
<input type=hidden name=dbpass value="<?=$_REQUEST['dbpass']?>">
<input type=hidden name=from value="upgrade2">
<input class=search type=submit value="Set SuperUser">
</form>
<p>
