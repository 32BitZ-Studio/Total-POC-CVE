<?php

// here, we will take the system from v0.9 to 0.9.2
// blog_ip_blacklist
$fields = "
ip C(16) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_ip_blacklist',$fields,$opts);

$res = $db->Execute($sql[0]);

//blog_spam
$fields = "
id I KEY AUTO,
field_id I DEFAULT 0 NOTNULL,
term C(255) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_spam',$fields,$opts);

$res = $db->Execute($sql[0]);

//blog_spam_field
$fields = "
id I KEY AUTO,
field C (32) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_spam_field',$fields,$opts);

$res = $db->Execute($sql[0]);

//blog_tb_whitelist
$fields = "
id I KEY AUTO,
host C (255) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$sql = $dict->CreateTableSQL('blog_tb_whitelist',$fields,$opts);

$res = $db->Execute($sql[0]);

//blog_flickr
$fields = "
id I KEY AUTO,
user_id I NOTNULL,
api_key C (32) DEFAULT '' NOTNULL,
email C (255) DEFAULT '' NOTNULL,
password C (32) DEFAULT '' NOTNULL
";

$sql = $dict->CreateTableSQL('blog_flickr',$fields,$opts);

$res = $db->Execute($sql[0]);

// add post_date to blog_entries
$fields = "
post_date T NOTNULL
";

$sql = $dict->ChangeTableSQL('blog_entries',$fields,$opts);

$res = $db->Execute($sql[0]);

//add ip to blog_trackback
$fields = "
ip C(16)
";

$sql = $dict->ChangeTableSQL('blog_trackback',$fields,$opts);

$res = $db->Execute($sql[0]);

//add ip to blog_comment
$fields = "
ip C(16)
";

$sql = $dict->ChangeTableSQL('blog_comments',$fields,$opts);

$res = $db->Execute($sql[0]);

$sql = "INSERT into blog_block_types VALUES ('11','Recent Trackbacks')";
$res = $db->Execute($sql);

$sql = "INSERT into blog_block_types VALUES ('12','Recent Comments')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_spam_field VALUES (1,'Trackback URL')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_spam_field VALUES (2,'Trackback Blog Name')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_spam_field VALUES (3,'Trackback Excerpt')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_spam_field VALUES (4,'Comment Name')";
$res = $db->Execute($sql);

$sql = "INSERT INTO blog_spam_field VALUES (5,'Comment Body')";
$res = $db->Execute($sql);


?>
