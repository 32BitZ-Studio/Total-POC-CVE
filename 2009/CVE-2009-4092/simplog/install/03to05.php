<?php 

$sql = "CREATE TABLE blog_comments (id INT not null AUTO_INCREMENT, bid INT not null , eid INT not null , name VARCHAR (64) , email VARCHAR (128) , comment TEXT not null , date DATETIME not null , PRIMARY KEY (id))"; 

$res = $db->Execute($sql);

$sql = "SELECT table_name from blog_list";
$res = $db->Execute($sql);
while(!$res->EOF) {
	$sql2 = "ALTER TABLE blog_".$res->fields['table_name']." ADD karma INT DEFAULT '0' not null";
	$res2 = $db->Execute($sql2);
	$res->MoveNext();
}

$sql = "CREATE TABLE blog_karma (ip VARCHAR (16) not null , bid INT not null , eid INT not null , timestamp VARCHAR (16) not null )";
$res = $db->Execute($sql);

?>
