<?php 

$fields = "
cat_id I KEY AUTO,
blog_id I notnull default '1',
cat_name C(32) notnull default ''
";

$sql = $dict->CreateTableSQL('blog_categories',$fields,$opts);

$r = $db->Execute($sql[0]);

//iterate through blog tables

$r = $db->Execute("select * from blog_list");
$count = 1;

while(!$r->EOF) {

	$r2 = $db->Execute("INSERT INTO blog_categories (blog_id,cat_name) values (".$r->fields['blog_id'].",'General')");
	
	$fields = "cat_id I NOTNULL default '$count'";
	$sql2 = $dict->ChangeTableSQL('blog_'.$r->fields['table_name'],$fields,$opts);
	$r2 = $db->Execute($sql2[0]);

	$r2 = $db->Execute("UPDATE blog_".$r->fields['table_name']." set cat_id=$count");
	$count++;
	$r->MoveNext();
}

//Add rss table

$fields = "
rss_id I KEY AUTO,
user_id I notnull default '0',
title C(64) notnull default '',
description C(128),
url C(128) notnull default ''
";

$sql = $dict->CreateTableSQL('blog_rss',$fields,$opts);
$r = $db->Execute($sql[0]);

//add block_type table

$fields = "
blk_type_id I KEY AUTO,
blk_type C(32) NOTNULL default ''
";

$sql = $dict->CreateTableSQL('blog_block_types',$fields,$opts);
$r = $db->Execute($sql[0]);

#
# Dumping data for table `blog_block_types`
#

$sql = "INSERT INTO blog_block_types VALUES (1, 'Categories')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (2, 'RSS')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (3, 'Previous Entries')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (4, 'Archives')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (5, 'PHP')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (6, 'HTML')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (7, 'Search')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (8, 'Login')";
$r = $db->Execute($sql);
$sql = "INSERT INTO blog_block_types VALUES (9, 'Calendar')";
$r = $db->Execute($sql);

//add block table

$fields = "
blk_id I KEY AUTO,
blk_type_id I notnull default '0',
blog_id I notnull default '1',
title C(64) notnull default '',
content X,
rss_id I notnull default '0',
blk_order I notnull default '0'
";

$sql = $dict->CreateTableSQL('blog_blocks',$fields,$opts);
$r = $db->Execute($sql[0]);

$sql = "INSERT into blog_blocks VALUES (1,9,1,'Calendar','','',1)";

$r = $db->Execute($sql);

$sql = "INSERT into blog_blocks VALUES (2,4,1,'Archives','','',2)";

$r = $db->Execute($sql);

$sql = "INSERT into blog_blocks VALUES (3,8,1,'Login','','',3)";

$r = $db->Execute($sql);

?>
