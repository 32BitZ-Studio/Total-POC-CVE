<?php 

$sql = "alter table blog rename blog_default";
$res = $db->Execute($sql);

$sql = "alter table users rename blog_users";
$res = $db->Execute($sql);

$fields = "
type_id I notnull default '0',
description C(10) notnull default 'protected'
";

$sql = "CREATE TABLE blog_types (type_id INT DEFAULT '0' not null , description VARCHAR (10) DEFAULT 'protected' not null)";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_types (type_id, description) VALUES ('1', 'public')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_types (type_id, description) VALUES ('2', 'protected')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_types (type_id, description) VALUES ('3', 'private')";
$res = $db->Execute($sql);

$sql = "CREATE TABLE blog_list (blog_id INT DEFAULT '0' not null , title VARCHAR (32) not null , table_name VARCHAR (32) not null , type_id INT DEFAULT '2' not null)";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_list (blog_id, title, type_id, table_name) VALUES ('1', 'Simplog','2','default')";
$res = $db->Execute($sql);

$sql = "CREATE TABLE blog_acl (user_id INT not null , blog_id INT not null, admin VARCHAR (1) DEFAULT 'N' not null)";
$res = $db->Execute($sql);

$sql = "CREATE TABLE blog_request (id int(11) NOT NULL,title varchar(32) NOT NULL,users varchar(255) NOT NULL,reason varchar(255) NOT NULL,datetime datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,uid varchar(16) NOT NULL,type_id int(11) NOT NULL)";
$res = $db->Execute($sql);

$sql = "ALTER TABLE blog_default ADD title VARCHAR(64)";
$res = $db->Execute($sql);

$sql = "SELECT id from blog_users";
$res = $db->Execute($sql);
while(!$res->EOF) {
	$sql2 = "INSERT into blog_acl (blog_id,user_id,admin) values (1,".$res->fields['id'].",'N')";
	$res2 = $db->Execute($sql2);
	$res->MoveNext();
}

?>
