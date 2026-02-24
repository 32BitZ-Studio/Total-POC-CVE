<?php

// here, we will take the system from v0.8 to 0.9.

// first, we need to create the blog entry table...
include("create-blog-entry-table.php");
// then populate that table with blog entries from legacy
// blog tables.
include("populate-blog-entry-table.php");

$fields = "
pb_id I KEY AUTO,
entry_id I DEFAULT 0 NOTNULL,
url C(255) DEFAULT '' NOTNULL,
title C(128) DEFAULT '' NOTNULL,
excerpt X NOTNULL,
blog_name C(64) DEFAULT '' NOTNULL,
added T DEFTIMESTAMP
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_pingback',$fields,$opts);

$res = $db->Execute($sql[0]);

$fields = "
tb_id I KEY AUTO,
entry_id I DEFAULT 0 NOTNULL,
url C(255) DEFAULT '' NOTNULL,
title C(128) DEFAULT '' NOTNULL,
excerpt X NOTNULL,
blog_name C(64) DEFAULT '' NOTNULL,
added T DEFTIMESTAMP
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_trackback',$fields,$opts);

$res = $db->Execute($sql[0]);

$fields = "
tagline C(128)
";

$sql = $dict->ChangeTableSQL('blog_list',$fields,$opts);

$res = $db->Execute($sql[0]);

$sql = "UPDATE blog_block_types set blk_type='Headlines' where blk_type_id=2";

$res = $db->Execute($sql);

$sql = "INSERT into blog_block_types VALUES ('10','XML Feeds')";

$res = $db->Execute($sql);

?>
