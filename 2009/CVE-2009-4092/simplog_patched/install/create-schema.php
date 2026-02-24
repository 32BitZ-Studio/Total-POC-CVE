<?php


// grab the dictionary processor for this db connection.
$dict = NewDataDictionary($db);

function formatSQL($sqlArray) {
	#print "<pre>";
	//print_r($dict->MetaTables());
	foreach($sqlArray as $s) {
		$s .= ";";
		if ($dbtype == 'oci8') {
            		$s .= "/\n";
        	}
        #print htmlspecialchars($s)."\n";
        $result .= $s;
	}
	#print "</pre><hr>";
    return $result;
}

$opts = array('mysql' => 'ENGINE=MyISAM');
/*
CREATE TABLE blog_acl (
  user_id INT4 NOT NULL DEFAULT '0',
  blog_id INT4 NOT NULL DEFAULT '0',
  admin char(1) NOT NULL DEFAULT 'N'
);
INSERT INTO blog_acl VALUES (1,1,'N');
*/
$tableName = "blog_acl";

$fields = "
user_id I NOTNULL default 0,
blog_id I NOTNULL default 0,
admin C(1) NOTNULL default 'N'
";

$tableSQL = ($dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL = array_merge($tableSQL,($dict->CreateIndexSQL("blog_acl_user_blog_index", $tableName, "user_id,blog_id", array())));
$tableSQL[] = "INSERT into blog_acl VALUES (1,1,'N')";

/*
CREATE SEQUENCE blog_block_types_blk_type_id;

CREATE TABLE blog_block_types (
  blk_type_id INT4 DEFAULT nextval('blog_block_types_blk_type_id'),
  blk_type varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (blk_type_id)

);
*/
$tableName = "blog_block_types";

$fields = "
blk_type_id I KEY AUTO,
blk_type C(32) NOTNULL default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Categories')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('RSS')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Previous Entries')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Archives')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('PHP')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('HTML')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Search')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Login')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Calendar')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('XML Feeds')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Recent Trackbacks')";
$tableSQL[] = "INSERT INTO blog_block_types (blk_type) VALUES ('Recent Comments')";

/*
CREATE SEQUENCE blog_blocks_blk_id_seq;

CREATE TABLE blog_blocks (
  blk_id INT4 DEFAULT nextval('blog_blocks_blk_id_seq'),
  blk_type_id INT4 NOT NULL DEFAULT '0',
  blog_id INT4 NOT NULL DEFAULT '1',
  title varchar(64) NOT NULL DEFAULT '',
  content text,
  rss_id INT4 DEFAULT NULL,
  blk_order INT4 NOT NULL DEFAULT '0',
  PRIMARY KEY (blk_id)

);
*/
$tableName = "blog_blocks";

$fields = "
blk_id I KEY AUTO,
blk_type_id I NOTNULL default 0,
blog_id I NOTNULL default 1,
title C(64) NOTNULL default '',
content X,
rss_id I NOTNULL default 0,
blk_order I NOTNULL default 0
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL[] = "INSERT into blog_blocks (blk_type_id,blog_id,title,content, rss_id,blk_order) VALUES (9,1,'Calendar','',0,1)";
$tableSQL[] = "INSERT into blog_blocks (blk_type_id,blog_id,title,content, rss_id,blk_order) VALUES (4,1,'Archives','',0,2)";
$tableSQL[] = "INSERT into blog_blocks (blk_type_id,blog_id,title,content, rss_id,blk_order) VALUES (8,1,'Login','',0,3)";

/*

CREATE TABLE blog_categories (
  cat_id INT4 DEFAULT nextval('blog_categories_cat_id_seq'),
  blog_id INT4 NOT NULL DEFAULT '1',
  cat_name varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (cat_id)

);
*/
$tableName = "blog_categories";

$fields = "
cat_id I KEY AUTO,
blog_id I NOTNULL default 1,
cat_name C(32) NOTNULL default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL[] = "INSERT INTO blog_categories (blog_id, cat_name) VALUES (1,'General')";

/*

CREATE TABLE blog_comments (
  id INT4 DEFAULT nextval('blog_comments_id_seq'),
  bid INT4 NOT NULL DEFAULT '0',
  eid INT4 NOT NULL DEFAULT '0',
  name varchar(64) DEFAULT NULL,
  email varchar(128) DEFAULT NULL,
  comment TEXT DEFAULT '' NOT NULL,
  DATE TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',
  PRIMARY KEY (id)

);
*/
$tableName = "blog_comments";

$fields = "
id I KEY AUTO,
bid I NOTNULL default 0,
eid I NOTNULL default 0,
name C(64) NOTNULL default '',
email C(128) default '',
comment X notnull,
date T NOTNULL,
ip C(16) default '' NOTNULL
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));

/*
CREATE TABLE blog_karma (
  ip varchar(16) NOT NULL DEFAULT '',
  bid INT4 NOT NULL DEFAULT '0',
  eid INT4 NOT NULL DEFAULT '0',
  timestamp varchar(16) NOT NULL DEFAULT ''
);
*/
$tableName = "blog_karma";

$fields = "
ip C(16) NOTNULL default '',
bid I NOTNULL default 0,
eid I NOTNULL default 0,
timestamp C(16) NOTNULL default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));

/*
CREATE TABLE blog_list (
  blog_id INT4 NOT NULL DEFAULT '0',
  title varchar(32) NOT NULL DEFAULT '',
  type_id INT4 NOT NULL DEFAULT '2',
  table_name varchar(32) NOT NULL DEFAULT '',
  admin INT4 NOT NULL DEFAULT '0',
  temp_id INT4 NOT NULL DEFAULT '1'
);
*/
$tableName = "blog_list";

$fields = "
blog_id I key auto,
title C(64) NOTNULL default '',
type_id I NOTNULL default 2,
admin I NOTNULL default 0,
temp_id I NOTNULL default 1,
tagline C(128) notnull default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL[] = "INSERT INTO blog_list (title,type_id,admin,temp_id,tagline) VALUES ('Simplog',2,1,2,'Powerful, yet simple....')";

// now would be a good time to create the blog entry table.
// it will be looking for a variable named $db with which to
// perform the table creation.
include ("./install/create-blog-entry-table.php");

/*
CREATE TABLE blog_request (
  id INT4 NOT NULL DEFAULT '0',
  title varchar(32) NOT NULL DEFAULT '',
  users varchar(255) NOT NULL DEFAULT '',
  reason varchar(255) NOT NULL DEFAULT '',
  datetime TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',
  uid varchar(16) NOT NULL DEFAULT '',
  type_id INT4 NOT NULL DEFAULT '0'
);
*/
$tableName = "blog_request";

$fields = "
id I KEY AUTO,
title C(64) NOTNULL default '',
users C(255) NOTNULL default '',
reason C(255) NOTNULL default '',
datetime T NOTNULL,
uid C(16) NOTNULL default '',
type_id I NOTNULL default 0
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));

/*
CREATE TABLE blog_rss (
  rss_id INT4 DEFAULT nextval('blog_rss_rss_id_seq'),
  user_id INT4 NOT NULL DEFAULT '0',
  title varchar(64) NOT NULL DEFAULT '',
  description varchar(128) DEFAULT NULL,
  url varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (rss_id)

);
*/
$tableName = "blog_rss";

$fields = "
rss_id I KEY AUTO,
user_id I NOTNULL default 0,
title C(64) NOTNULL default '',
description C(128) NOTNULL default '',
url C(255) NOTNULL default '',
type C(1) NOTNULL default 'R'
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));

/*
CREATE SEQUENCE blog_template_temp_id_seq;

CREATE TABLE blog_template (
  temp_id INT4 DEFAULT nextval('blog_template_temp_id_seq'),
  name varchar(16) NOT NULL DEFAULT '',
  template TEXT DEFAULT '' NOT NULL,
  PRIMARY KEY (temp_id)

);
*/
$tableName = "blog_template";

$fields = "
temp_id I KEY AUTO,
name C(16) NOTNULL default '',
template X NOTNULL default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));

$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('blog','<table width=100%><tr><td>--date-- by <a href=\"--url--\">--name--</a><br><hr><b>--title--</b><p>--body--</td></tr><tr><td>[ --comments-- | --karma-- | --link-- ]</td></tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('new','<table width=100% cellspacing=0 class=\\\"header\\\">\r\n<tr><td><b>--title--</b> posted --date-- by <a href=\\\"--url--\\\">--name--</a></td><td align=right valign=top>[--category--]</td></tr></table>--body--<br clear=\"both\"><br><small>--link-- : --comments-- : --trackbacks-- : --pingbacks-- : --karma--</small><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('slash','<table width=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" bgcolor=\"#DDDDDD\"><tr valign=\"top\" bgcolor=\"#660000\"><td><img src=\"templates/images/cl.gif\" width=\"7\" height=\"10\" alt=\"\"><img src=\"templates/images/pix.gif\" width=\"4\" height=\"4\" alt=\"\"></td><td width=\"100%\">	<table width=\"100%\" border=\"0\" cellpadding=\"2\" cellspacing=\"0\">	<tr>	<td align=left>		<font size=\"3\" color=\"#FFFFFF\"><B>--title--</b></font>	</td>	<td align=right>		<font size=\"1\" color=#ffffff>--date-- by <a href=\"--url--\">--name--</a></font>	</td>	</tr>	</table></td><td align=\"right\" valign=\"top\"><img src=\"templates/images/cr.gif\" width=\"7\" height=\"10\" alt=\"\"></td></tr></table><table border=\"0\" cellpadding=\"0\" cellspacing=\"0\"><tr bgcolor=\"#e6e6e6\"><td background=\"templates/images/gl.gif\"><img src=\"templates/images/pix.gif\" width=\"11\" height=\"11\" alt=\"\"></td><td width=\"100%\">--body--</td><td background=\"templates/images/gr.gif\"><img src=\"templates/images/pix.gif\" width=\"11\" height=\"11\" alt=\"\"></td></tr><tr bgcolor=\"#006666\"><td colspan=\"3\"><img src=\"templates/images/pix.gif\" width=\"1\" height=\"1\"></td></tr></table><table border=\"0\" cellpadding=\"0\" cellspacing=\"0\"><tr bgcolor=\"#e6e6e6\"><td background=\"templates/images/gl.gif\"><img src=\"templates/images/pix.gif\" width=\"11\" height=\"11\" alt=\"\"></td><td width=\"100%\" align=right>[--comments--][--karma--][--link--]<br></td><td background=\"templates/images/gr.gif\"><img src=\"templates/images/pix.gif\" width=\"11\" height=\"11\" alt=\"\"></td></tr><tr bgcolor=\"#006666\"><td colspan=\"3\"><img src=\"templates/images/pix.gif\" width=\"1\" height=\"1\"></td></tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('post','<table width=\"100%\">	<tr> 	<td>  	      <table width=\"100%\" cellpadding=0 cellspacing=0>        	<tr><td width=\"100%\"><IMG SRC=\"templates/images/black_dot.gif\" WIDTH=\"100%\" HEIGHT=\"1\" BORDER=0 ALT=\"\"></td></tr>        	<tr bgcolor=\"#E1E4CE\">            	<td><font color=\"black\" size=2 face=\"arial, Verdana, sans-serif\"><b>--title--</b></font><br>            		<font color=\"black\" size=1 face=\"arial, Verdana, sans-serif\">Posted By: <a href=\"--url--\">--name--</a></font>             	</td>        	</tr>        	<tr><td width=\"100%\"><IMG SRC=\"templates/images/black_dot.gif\" WIDTH=\"100%\" HEIGHT=\"1\" BORDER=0 ALT=\"\"></td></tr>        	<tr>            	<td>					<font color=\"black\" size=1 face=\"arial, Verdana, sans-serif\">--date--</font><br>            		<font color=\"black\" size=2 face=\"arial, Verdana, sans-serif\">--body--</font>            	</td>        	</tr>			<tr><td width=\"100%\"><IMG SRC=\"templates/images/black_dot.gif\" WIDTH=\"100%\" HEIGHT=\"1\" BORDER=0 ALT=\"\"></td></tr>			<tr bgcolor=\"#E1E4CE\">			    <td align=right><font color=\"black\" size=2 face=\"arial, Verdana, sans-serif\"><small>[--karma--][--comments--][--link--]</small></font>			    </td>		    </tr>		    <tr><td width=\"100%\"><IMG SRC=\"templates/images/black_dot.gif\" WIDTH=\"100%\" HEIGHT=\"1\" BORDER=0 ALT=\"\"></td></tr>        	</table>        </td>        </tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('webhack','<table width=100%><tr><td align=left><font face=\"helvetica,arial,sans-serif\"><b>--title--</b></font></td><td align=right><font size=1 face=\"helvetica,arial,sans-serif\">--date-- by <a href=\"--url--\">--name--</a></font></td></tr><tr><td colspan=2><img src=\"templates/images/line.gif\" width=100% height=5></td></tr><tr><td colspan=2><font size=2 face=\"helvetica,arial,sans-serif\">--body--</font></td></tr><tr><td colspan=2><font size=2 face=\"helvetica,arial,sans-serif\">[--comments--][--karma--][--link--]</font></td></tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('basic','<table width=100%><tr bgcolor=#000000><td><font color=white>--date-- by <a href=\"--url--\">--name--</a></td></tr><tr><td><b>--title--</b><p>--body--</td></tr><tr><td>[--comments--][--karma--][--link--]</td></tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('slashdot','<table width=\"99%\" cellpadding=0 cellspacing=0 border=0><tr><td valign=top bgcolor=\"#006666\"><img src=\"templates/images/slc.gif\" width=13 height=16 alt=\"\" align=top><font size=4 color=\"#FFFFFF\"><b>--title--</b></td></tr></table><b>Posted by <a href=\"--url--\">--name--</a> on  --date--</b><br>--body--<br clear=\"both\"><br>[--link--][--comments--][--karma--]<p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('kuro5hin','<table width=\"100%\" cellpadding=1 cellspacing=0 border=0 bgcolor=006699>		<tbody>		<tr>		<td valign=top>		 <table width=\"100%\" cellpadding=1 cellspacing=0 border=0 bgcolor=006699>		  <tbody>		  <tr>		   <td bgcolor=eeeeee><font size=4 color=\"#000000\"><b>		    --title--</b><br>		    Posted by <a href=\"--url--\">--name--</a> on 		    --date--<br>		   </td>		  </tr>		  </tbody>		 </table>		</td>		</tr>		</tbody>		</table>--body--<br clear=\"both\"><br>[--link--][--comments--][--karma--]<p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('kde','<TABLE WIDTH=100% CELLPADDING=0 CELLSPACING=0 BORDER=0>    <TR>    <TD ALIGN=right VALIGN=BOTTOM WIDTH=11 HEIGHT=11><IMG SRC=templates/images/menutopleft.gif width=11 height=11></TD>    <TD ALIGN=MIDDLE HEIGHT=11 VALIGN=BOTTOM><IMG SRC=templates/images/menutop.gif width=100% height=1></TD>    <TD ALIGN=left VALIGN=BOTTOM WIDTH=11 HEIGHT=11><IMG SRC=templates/images/menutopright.gif width=11 height=11></TD></TR>    <TR>    <TD ALIGN=right VALIGN=BOTTOM WIDTH=11 HEIGHT=11 BACKGROUND=templates/images/menuleft.gif><IMG SRC=templates/images/menutopleft.gif width=11 height=11></TD>    <TD ALIGN=CENTER bgcolor=#6C6C6C BACKGROUND=templates/images/menutitle.gif>    <FONT size=3 color=white></center>    <b>--title--</b><br><font size=1>Posted on --date-- by <a href=\"--url--\">--name--</a>    </FONT></TD>    <TD ALIGN=left VALIGN=BOTTOM WIDTH=11 HEIGHT=11 BACKGROUND=templates/images/menuright.gif><IMG SRC=templates/images/menutopright.gif width=11 height=11></TD></TR>    <TR>    <TD ALIGN=RIGHT BACKGROUND=templates/images/menuleft.gif WIDTH=11>&nbsp;</TD>    <TD ALIGN=left VALIGN=TOP BGCOLOR=#CFCFCF BACKGROUND=templates/images/sketch.gif>    <FONT size=2>    --body--<p>[--comments--][--karma--][--link--]</TD>    <TD ALIGN=LEFT BACKGROUND=templates/images/menuright.gif WIDTH=11>&nbsp;</TD></TR>    <TR>    <TD ALIGN=right VALIGN=TOP WIDTH=11 HEIGHT=11><IMG SRC=templates/images/menubottomleft.gif width=11 height=11></TD>    <TD ALIGN=MIDDLE HEIGHT=11 VALIGN=TOP><IMG SRC=templates/images/menubottom.gif width=100% height=1></TD>    <TD ALIGN=left VALIGN=TOP WIDTH=11 HEIGHT=11><IMG SRC=templates/images/menubottomright.gif width=11 height=11></TD></TR></TABLE><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('nuke','<table border=0 cellpadding=0 cellspacing=0 bgcolor=ffffff width=100%><tr><td><table border=0 cellpadding=1 cellspacing=1 bgcolor=000000 width=100%><tr><td><table border=0 cellpadding=3 cellspacing=0 bgcolor=cfcfbb width=100%><tr><td align=left><font size=3 color=\"#363636\"><b>--title--</b></font><br><font size=2>Posted on --date-- by<a href=\"--url--\">--name--</a></td></tr></table></td></tr></table><br>--body--<br clear=\"both\"><br>[--link--][--karma--][--comments--]</td></tr></table><p>')";
$tableSQL[] = "INSERT INTO blog_template (name,template) VALUES ('test','<table width=90%><tr><td bgcolor=#ffaa99><fieldset><p><strong><legend>--title--</legend></strong></p><p><small>Posted --date-- by <a href=\"--url--\" target=_new>--name--</a></small></p><p>--body--</p><br clear=\"both\"><br>[ --comments-- | --karma-- | --link-- ]</p></fieldset></td></tr></table>')";

/*
CREATE TABLE blog_types (
  type_id INT4 NOT NULL DEFAULT '0',
  description varchar(10) NOT NULL DEFAULT 'protected'
);
*/
$tableName = "blog_types";

$fields = "
type_id I NOTNULL default 0,
description C(10) NOTNULL default ''
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$fields = array();
$tableSQL[] = "INSERT INTO blog_types VALUES (1,'public')";
$tableSQL[] = "INSERT INTO blog_types VALUES (2,'protected')";
$tableSQL[] = "INSERT INTO blog_types VALUES (3,'private')";

/*
CREATE TABLE blog_users (
  id INT4 NOT NULL DEFAULT '0',
  login varchar(8) NOT NULL DEFAULT '',
  password varchar(32) NOT NULL DEFAULT '',
  name varchar(64) NOT NULL DEFAULT '',
  url varchar(128) DEFAULT NULL,
  email varchar(64) DEFAULT NULL,
  admin INT4 NOT NULL DEFAULT '0',
  PRIMARY KEY (id)
);
*/
$tableName = "blog_users";

$fields = "
id I KEY NOTNULL,
login C(8) notnull default '',
password C(32) notnull defalt '',
name C(64) notnull default '',
url C(128) ,
email C(64),
admin I notnull default 0
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL($tableName, $fields, $opts));
$tableSQL = array_merge($tableSQL,$dict->CreateIndexSQL("blog_users_id_idx", $tableName, "id", $indexOpts));


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

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_pingback',$fields,$opts));

$fields = "
tb_id I KEY AUTO,
entry_id I DEFAULT 0 NOTNULL,
url C(255) DEFAULT '' NOTNULL,
title C(128) DEFAULT '' NOTNULL,
excerpt X NOTNULL,
blog_name C(64) DEFAULT '' NOTNULL,
added T NOTNULL,
ip c(16) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_trackback',$fields,$opts));

// blog_ip_blacklist
$fields = "
ip C(16) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_ip_blacklist',$fields,$opts));


//blog_spam
$fields = "
id I KEY AUTO,
field_id I DEFAULT 0 NOTNULL,
term C(255) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_spam',$fields,$opts));


//blog_spam_field
$fields = "
id I KEY AUTO,
field C (32) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_spam_field',$fields,$opts));


//insert field types
$tableSQL[] = "INSERT INTO blog_spam_field VALUES (1,'Trackback URL')";
$tableSQL[] = "INSERT INTO blog_spam_field VALUES (2,'Trackback Blog Name')";
$tableSQL[] = "INSERT INTO blog_spam_field VALUES (3,'Trackback Excerpt')";
$tableSQL[] = "INSERT INTO blog_spam_field VALUES (4,'Comment Name')";
$tableSQL[] = "INSERT INTO blog_spam_field VALUES (5,'Comment Body')";

//blog_tb_whitelist
$fields = "
id I KEY AUTO,
host C (255) DEFAULT '' NOTNULL
";

$opts = array('mysql' => 'ENGINE=MyISAM');

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_tb_whitelist',$fields,$opts));

//blog_flickr
$fields = "
id I KEY AUTO,
user_id I NOTNULL,
api_key C (32) DEFAULT '' NOTNULL,
email C (255) DEFAULT '' NOTNULL,
password C (32) DEFAULT '' NOTNULL
";

$tableSQL = array_merge($tableSQL,$dict->CreateTableSQL('blog_flickr',$fields,$opts));

$sql = formatSQL($tableSQL);

$db->StartTrans();
#if ( $db->Execute($sql) === false) {
#    print "Error creating tables <br/>".$dbconn->ErrorMsg()."<br/>\n";
#    print "Make sure you have already created the database named '$databaseName'<br/>\n";
#} else {

foreach($tableSQL as $sql){
	$db->Execute($sql);
}

$db->CompleteTrans();
#}
?>
