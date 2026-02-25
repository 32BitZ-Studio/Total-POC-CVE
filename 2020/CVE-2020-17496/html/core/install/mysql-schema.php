<?php
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

define('SCHEMA', 'mysql');

if (!is_object($db))
{
	die('<strong>MySQL Schema</strong>: $db is not an instance of the vB Database class. This script requires the escape_string() method from the vB Database class.');
}

require_once(DIR . '/install/functions_installupgrade.php');

$myisam = 'MyISAM';
$innodb = get_innodb_engine($db);
$memory = get_memory_engine($db);

$phrasegroups = array();
$specialtemplates = array();

// Check userfield table is still used and how long the default length should be

$schema['CREATE']['query']['ad'] = "
CREATE TABLE " . TABLE_PREFIX . "ad (
	adid INT UNSIGNED NOT NULL auto_increment,
	title VARCHAR(250) NOT NULL DEFAULT '',
	adlocation VARCHAR(250) NOT NULL DEFAULT '',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	active SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	snippet MEDIUMTEXT,
	PRIMARY KEY (adid),
	KEY active (active)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['ad'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "ad");



$schema['CREATE']['query']['adcriteria'] = "
CREATE TABLE " . TABLE_PREFIX . "adcriteria (
	adid INT UNSIGNED NOT NULL DEFAULT '0',
	criteriaid VARCHAR(191) NOT NULL DEFAULT '',
	condition1 VARCHAR(250) NOT NULL DEFAULT '',
	condition2 VARCHAR(250) NOT NULL DEFAULT '',
	condition3 VARCHAR(250) NOT NULL DEFAULT '',
	conditionjson TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (adid,criteriaid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['adcriteria'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "adcriteria");



$schema['CREATE']['query']['adminhelp'] = "
CREATE TABLE " . TABLE_PREFIX . "adminhelp (
	adminhelpid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	script VARCHAR(50) NOT NULL DEFAULT '',
	action VARCHAR(25) NOT NULL DEFAULT '',
	optionname VARCHAR(100) NOT NULL DEFAULT '',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	volatile SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product VARCHAR(25) NOT NULL DEFAULT '',
	PRIMARY KEY (adminhelpid),
	UNIQUE KEY phraseunique (script, action, optionname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['adminhelp'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "adminhelp");



$schema['CREATE']['query']['administrator'] = "
CREATE TABLE " . TABLE_PREFIX . "administrator (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	adminpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	navprefs MEDIUMTEXT,
	cssprefs VARCHAR(250) NOT NULL DEFAULT '',
	notes MEDIUMTEXT,
	dismissednews TEXT,
	languageid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['administrator'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "administrator");



$schema['CREATE']['query']['adminlog'] = "
CREATE TABLE " . TABLE_PREFIX . "adminlog (
	adminlogid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	script VARCHAR(50) NOT NULL DEFAULT '',
	action VARCHAR(20) NOT NULL DEFAULT '',
	extrainfo VARCHAR(200) NOT NULL DEFAULT '',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	PRIMARY KEY (adminlogid),
	KEY script_action (script, action)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['adminlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "adminlog");



$schema['CREATE']['query']['adminmessage'] = "
CREATE TABLE " . TABLE_PREFIX . "adminmessage (
	adminmessageid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	varname varchar(250) NOT NULL DEFAULT '',
	dismissable SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	script varchar(50) NOT NULL DEFAULT '',
	action varchar(20) NOT NULL DEFAULT '',
	execurl MEDIUMTEXT,
	method enum('get','post') NOT NULL DEFAULT 'post',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	status enum('undone','done','dismissed') NOT NULL default 'undone',
	statususerid INT UNSIGNED NOT NULL DEFAULT '0',
	args MEDIUMTEXT,
	PRIMARY KEY (adminmessageid),
	KEY script_action (script, action),
	KEY varname (varname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['adminmessage'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "adminmessage");



$schema['CREATE']['query']['adminutil'] = "
CREATE TABLE " . TABLE_PREFIX . "adminutil (
	title VARCHAR(50) NOT NULL DEFAULT '',
	text MEDIUMTEXT,
	PRIMARY KEY (title)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['adminutil'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "adminutil");

$schema['CREATE']['query']['announcement'] = "
CREATE TABLE " . TABLE_PREFIX . "announcement (
	announcementid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(250) NOT NULL DEFAULT '',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	startdate INT UNSIGNED NOT NULL DEFAULT '0',
	enddate INT UNSIGNED NOT NULL DEFAULT '0',
	pagetext MEDIUMTEXT,
	nodeid INT NOT NULL DEFAULT '0',
	views INT UNSIGNED NOT NULL DEFAULT '0',
	announcementoptions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (announcementid),
	KEY nodeid (nodeid),
	KEY startdate (enddate, nodeid, startdate)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['announcement'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "announcement");



$schema['CREATE']['query']['announcementread'] = "
CREATE TABLE " . TABLE_PREFIX . "announcementread (
	announcementid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY  (announcementid,userid),
	KEY userid (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['announcementread'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "announcementread");

$schema['CREATE']['query']['attach'] = "
CREATE TABLE " . TABLE_PREFIX . "attach (
	nodeid INT UNSIGNED NOT NULL,
	filedataid INT UNSIGNED NOT NULL,
	visible SMALLINT NOT NULL DEFAULT 1,
	counter INT UNSIGNED NOT NULL DEFAULT '0',
	posthash VARCHAR(32) NOT NULL DEFAULT '',
	filename VARCHAR(255) NOT NULL DEFAULT '',
	caption TEXT,
	reportthreadid INT UNSIGNED NOT NULL DEFAULT '0',
	settings MEDIUMTEXT,
	PRIMARY KEY (nodeid),
	KEY attach_filedataid(filedataid)
 ) ENGINE = $innodb
";
$schema['CREATE']['explain']['attach'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attach");

$schema['CREATE']['query']['apiclient'] = "
CREATE TABLE " . TABLE_PREFIX . "apiclient (
	apiclientid INT UNSIGNED NOT NULL auto_increment,
	secret VARCHAR(32) NOT NULL DEFAULT '',
	apiaccesstoken VARCHAR(32) NOT NULL DEFAULT '',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	clienthash VARCHAR(32) NOT NULL DEFAULT '',
	clientname VARCHAR(250) NOT NULL DEFAULT '',
	clientversion VARCHAR(50) NOT NULL DEFAULT '',
	platformname VARCHAR(250) NOT NULL DEFAULT '',
	platformversion VARCHAR(50) NOT NULL DEFAULT '',
	uniqueid VARCHAR(250) NOT NULL DEFAULT '',
	initialipaddress VARCHAR(45) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL,
	lastactivity INT UNSIGNED NOT NULL,
	PRIMARY KEY  (apiclientid),
	KEY clienthash (clienthash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['apiclient'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "apiclient");


/*
	Separate table instead of a column on apiclient because for the most part the processing we do for this
	is independent from apiclient.
	There doesn't seem to be a documented limt for how long a device token/registration id can actually be,
	so I'm going with 191 (VBV-15905, not that device tokens *can* use multibyte characters AFAIK...).
	library will check if token is larger & throw an error.
	Userid is here in case single user has multiple devices (clients) that have notifications enabled.
	We are explicitly allowing multiple simultaneous device tokens per user here!!
 */
$schema['CREATE']['query']['apiclient_devicetoken'] = "
CREATE TABLE " . TABLE_PREFIX . "apiclient_devicetoken (
	apiclientid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	devicetoken VARCHAR(191) NOT NULL DEFAULT '',
	PRIMARY KEY  (apiclientid),
	INDEX (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['apiclient_devicetoken'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "apiclient_devicetoken");


$schema['CREATE']['query']['apilog'] = "
CREATE TABLE " . TABLE_PREFIX . "apilog (
	apilogid INT UNSIGNED NOT NULL auto_increment,
	apiclientid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	method VARCHAR(32) NOT NULL DEFAULT '',
	paramget MEDIUMTEXT,
	parampost MEDIUMTEXT,
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	PRIMARY KEY  (apilogid),
	KEY apiclientid (apiclientid, method, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['apilog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "apilog");


$schema['CREATE']['query']['attachmentcategory'] = "
CREATE TABLE " . TABLE_PREFIX . "attachmentcategory (
	categoryid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	title VARCHAR(255) NOT NULL DEFAULT '',
	parentid INT UNSIGNED NOT NULL DEFAULT '0',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (categoryid),
	KEY userid (userid, parentid, displayorder)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['attachmentcategory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attachmentcategory");



$schema['CREATE']['query']['attachmentcategoryuser'] = "
CREATE TABLE " . TABLE_PREFIX . "attachmentcategoryuser (
	filedataid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	categoryid INT UNSIGNED NOT NULL DEFAULT '0',
	filename VARCHAR(255) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (filedataid, userid),
	KEY categoryid (categoryid, userid, filedataid),
	KEY userid (userid, categoryid, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['attachmentcategoryuser'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attachmentcategoryuser");



$schema['CREATE']['query']['attachmentpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "attachmentpermission (
	attachmentpermissionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	extension VARCHAR(20) BINARY NOT NULL DEFAULT '',
	usergroupid INT UNSIGNED NOT NULL DEFAULT '0',
	size INT UNSIGNED NOT NULL DEFAULT '0',
	width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	attachmentpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY  (attachmentpermissionid),
	UNIQUE KEY extension (extension, usergroupid),
	KEY usergroupid (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['attachmentpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attachmentpermission");



$schema['CREATE']['query']['attachmenttype'] = "
CREATE TABLE " . TABLE_PREFIX . "attachmenttype (
	extension CHAR(20) BINARY NOT NULL DEFAULT '',
	mimetype VARCHAR(255) NOT NULL DEFAULT '',
	size INT UNSIGNED NOT NULL DEFAULT '0',
	width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	display SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	contenttypes MEDIUMTEXT,
	PRIMARY KEY (extension)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['attachmenttype'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attachmenttype");


$schema['CREATE']['query']['attachmentviews'] = "
CREATE TABLE " . TABLE_PREFIX . "attachmentviews (
	attachmentid INT UNSIGNED NOT NULL DEFAULT '0',
	KEY postid (attachmentid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['attachmentviews'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "attachmentviews");



$schema['CREATE']['query']['avatar'] = "
CREATE TABLE " . TABLE_PREFIX . "avatar (
	avatarid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(100) NOT NULL DEFAULT '',
	minimumposts INT UNSIGNED NOT NULL DEFAULT '0',
	avatarpath VARCHAR(100) NOT NULL DEFAULT '',
	imagecategoryid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (avatarid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['avatar'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "avatar");


$schema['CREATE']['query']['autosavetext'] = "
CREATE TABLE " . TABLE_PREFIX . "autosavetext (
	parentid INT UNSIGNED NOT NULL DEFAULT '0',
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	pagetext MEDIUMTEXT,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid, parentid, userid),
	KEY userid (userid),
	KEY parentid (parentid, userid),
	KEY dateline (dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['autosavetext'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "autosavetext");


$schema['CREATE']['query']['bbcode'] = "
CREATE TABLE " . TABLE_PREFIX . "bbcode (
	bbcodeid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	bbcodetag VARCHAR(191) NOT NULL DEFAULT '',
	bbcodereplacement MEDIUMTEXT,
	bbcodeexample VARCHAR(200) NOT NULL DEFAULT '',
	bbcodeexplanation MEDIUMTEXT,
	twoparams SMALLINT NOT NULL DEFAULT '0',
	title VARCHAR(100) NOT NULL DEFAULT '',
	buttonimage VARCHAR(250) NOT NULL DEFAULT '',
	options INT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (bbcodeid),
	UNIQUE KEY uniquetag (bbcodetag, twoparams)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['bbcode'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "bbcode");



$schema['CREATE']['query']['bbcode_video'] = "
CREATE TABLE " . TABLE_PREFIX . "bbcode_video (
  providerid INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tagoption VARCHAR(50) NOT NULL DEFAULT '',
  provider VARCHAR(50) NOT NULL DEFAULT '',
  url VARCHAR(100) NOT NULL DEFAULT '',
  regex_url VARCHAR(254) NOT NULL DEFAULT '',
  regex_scrape VARCHAR(254) NOT NULL DEFAULT '',
  embed MEDIUMTEXT,
  priority INT UNSIGNED NOT NULL DEFAULT '0',
  PRIMARY KEY  (providerid),
  UNIQUE KEY tagoption (tagoption),
  KEY priority (priority),
  KEY provider (provider)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['bbcode_video'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "bbcode_video");

$schema['CREATE']['query']['cache'] = "
CREATE TABLE " . TABLE_PREFIX . "cache (
	cacheid VARBINARY(64) NOT NULL,
	expires INT UNSIGNED NOT NULL,
	created INT UNSIGNED NOT NULL,
	locktime INT UNSIGNED NOT NULL,
	serialized ENUM('0','1') NOT NULL DEFAULT '0',
	data MEDIUMTEXT,
	PRIMARY KEY (cacheid),
	KEY expires (expires)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['cache'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "cache");



$schema['CREATE']['query']['cacheevent'] = "
CREATE TABLE " . TABLE_PREFIX . "cacheevent (
	cacheid VARBINARY(64) NOT NULL,
	event VARBINARY(50) NOT NULL,
	PRIMARY KEY (cacheid, event),
	KEY event (event)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['cacheevent'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "cacheevent");

// TODO: remove when legacyevent is removed.
$schema['CREATE']['query']['calendar'] = "
CREATE TABLE " . TABLE_PREFIX . "calendar (
	calendarid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(255) NOT NULL DEFAULT '',
	description VARCHAR(100) NOT NULL DEFAULT '',
	displayorder SMALLINT NOT NULL DEFAULT '0',
	neweventemail TEXT,
	moderatenew SMALLINT NOT NULL DEFAULT '0',
	startofweek SMALLINT NOT NULL DEFAULT '0',
	options INT UNSIGNED NOT NULL DEFAULT '0',
	cutoff SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	eventcount SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	birthdaycount SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	startyear SMALLINT UNSIGNED NOT NULL DEFAULT '2000',
	endyear SMALLINT UNSIGNED NOT NULL DEFAULT '2006',
	holidays INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (calendarid),
	KEY displayorder (displayorder)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['calendar'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "calendar");



$schema['CREATE']['query']['calendarcustomfield'] = "
CREATE TABLE " . TABLE_PREFIX . "calendarcustomfield (
	calendarcustomfieldid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	calendarid INT UNSIGNED NOT NULL DEFAULT '0',
	title VARCHAR(255) NOT NULL DEFAULT '',
	description MEDIUMTEXT,
	options MEDIUMTEXT,
	allowentry SMALLINT NOT NULL DEFAULT '1',
	required SMALLINT NOT NULL DEFAULT '0',
	length SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (calendarcustomfieldid),
	KEY calendarid (calendarid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['calendarcustomfield'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "calendarcustomfield");



$schema['CREATE']['query']['calendarmoderator'] = "
CREATE TABLE " . TABLE_PREFIX . "calendarmoderator (
	calendarmoderatorid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	calendarid INT UNSIGNED NOT NULL DEFAULT '0',
	neweventemail SMALLINT NOT NULL DEFAULT '0',
	permissions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (calendarmoderatorid),
	KEY userid (userid, calendarid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['calendarmoderator'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "calendarmoderator");



$schema['CREATE']['query']['calendarpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "calendarpermission (
	calendarpermissionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	calendarid INT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	calendarpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (calendarpermissionid),
	KEY calendarid (calendarid),
	KEY usergroupid (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['calendarpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "calendarpermission");


$schema['CREATE']['query']['channel'] = "
CREATE TABLE " . TABLE_PREFIX . "channel (
	nodeid INT UNSIGNED NOT NULL PRIMARY KEY,
	styleid SMALLINT NOT NULL DEFAULT '0',
	options INT(10) UNSIGNED NOT NULL DEFAULT 1984,
	daysprune SMALLINT NOT NULL DEFAULT '0',
	newcontentemail TEXT,
	defaultsortfield VARCHAR(50) NOT NULL DEFAULT 'lastcontent',
	defaultsortorder ENUM('asc', 'desc') NOT NULL DEFAULT 'desc',
	imageprefix VARCHAR(100) NOT NULL DEFAULT '',
	guid char(150) DEFAULT NULL,
	filedataid INT,
	category SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product varchar(25) NOT NULL DEFAULT 'vbulletin',
	UNIQUE KEY guid (guid)
	) ENGINE = $innodb";
$schema['CREATE']['explain']['channel'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "channel");


$schema['CREATE']['query']['channelprefixset'] = "
CREATE TABLE " . TABLE_PREFIX . "channelprefixset (
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	prefixsetid VARCHAR(25) NOT NULL DEFAULT '',
	PRIMARY KEY (nodeid, prefixsetid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['channelprefixset'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "channelprefixset");


$schema['CREATE']['query']['closure'] = "
CREATE TABLE " . TABLE_PREFIX . "closure (
	parent INT UNSIGNED NOT NULL,
	child INT UNSIGNED NOT NULL,
	depth SMALLINT NULL,
	displayorder SMALLINT NOT NULL DEFAULT 0,
	publishdate INT,
	KEY parent_2 (parent, depth, publishdate, child),
	KEY publishdate (publishdate, child),
	KEY child (child, depth),
	KEY displayorder (displayorder),
	UNIQUE KEY closure_uniq (parent, child)
	) ENGINE = $innodb";
$schema['CREATE']['explain']['closure'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "closure");

$schema['CREATE']['query']['contenttype'] = "
CREATE TABLE " . TABLE_PREFIX . "contenttype (
	contenttypeid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	class VARBINARY(50) NOT NULL,
	packageid INT UNSIGNED NOT NULL,
	canplace ENUM('0','1') NOT NULL DEFAULT '0',
	cansearch ENUM('0','1') NOT NULL DEFAULT '0',
	cantag ENUM('0','1') DEFAULT '0',
	canattach ENUM('0','1') DEFAULT '0',
	isaggregator ENUM('0', '1') NOT NULL DEFAULT '0',
	PRIMARY KEY (contenttypeid),
	UNIQUE KEY packageclass (packageid, class)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['contenttype'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "contenttype");



$schema['CREATE']['query']['cpsession'] = "
CREATE TABLE " . TABLE_PREFIX . "cpsession (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	hash VARCHAR(32) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (userid, hash)
) ENGINE = $memory
";
$schema['CREATE']['explain']['cpsession'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "cpsession");



$schema['CREATE']['query']['cron'] = "
CREATE TABLE " . TABLE_PREFIX . "cron (
	cronid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nextrun INT UNSIGNED NOT NULL DEFAULT '0',
	weekday SMALLINT NOT NULL DEFAULT '0',
	day SMALLINT NOT NULL DEFAULT '0',
	hour SMALLINT NOT NULL DEFAULT '0',
	minute VARCHAR(100) NOT NULL DEFAULT '',
	filename CHAR(50) NOT NULL DEFAULT '',
	loglevel SMALLINT NOT NULL DEFAULT '0',
	active SMALLINT NOT NULL DEFAULT '1',
	varname VARCHAR(100) NOT NULL DEFAULT '',
	volatile SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product VARCHAR(25) NOT NULL DEFAULT '',
	PRIMARY KEY (cronid),
	KEY nextrun (nextrun),
	UNIQUE KEY (varname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['cron'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "cron");



$schema['CREATE']['query']['cronlog'] = "
CREATE TABLE " . TABLE_PREFIX . "cronlog (
	cronlogid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	varname VARCHAR(100) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	description MEDIUMTEXT,
	type SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (cronlogid),
	KEY (varname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['cronlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "cronlog");



$schema['CREATE']['query']['customavatar'] = "
CREATE TABLE " . TABLE_PREFIX . "customavatar (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	filedata MEDIUMBLOB,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	filename VARCHAR(100) NOT NULL DEFAULT '',
	visible SMALLINT NOT NULL DEFAULT '1',
	filesize INT UNSIGNED NOT NULL DEFAULT '0',
	width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	filedata_thumb MEDIUMBLOB,
	width_thumb INT UNSIGNED NOT NULL DEFAULT '0',
	height_thumb INT UNSIGNED NOT NULl DEFAULT '0',
	extension VARCHAR(10) NOT NULL,
	PRIMARY KEY (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['customavatar'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "customavatar");

$schema['CREATE']['query']['customprofile'] = "
CREATE TABLE " . TABLE_PREFIX . "customprofile (
	customprofileid integer AUTO_INCREMENT,
	title VARCHAR(100),
	thumbnail VARCHAR(255),
	userid INT NOT NULL,
	themeid INT,
	font_family VARCHAR(255),
	fontsize VARCHAR(20),
	title_text_color VARCHAR(20),
	page_background_color VARCHAR(20),
	page_background_image VARCHAR(255),
	page_background_repeat  VARCHAR(20),
	module_text_color VARCHAR(20),
	module_link_color VARCHAR(20),
	module_background_color VARCHAR(20),
	module_background_image VARCHAR(255),
	module_background_repeat VARCHAR(20),
	module_border VARCHAR(20),
	content_text_color VARCHAR(20),
	content_link_color VARCHAR(20),
	content_background_color VARCHAR(20),
	content_background_image VARCHAR(255),
	content_background_repeat VARCHAR(20),
	content_border VARCHAR(20),
	button_text_color VARCHAR(20),
	button_background_color VARCHAR(20),
	button_background_image VARCHAR(255),
	button_background_repeat VARCHAR(20),
	button_border VARCHAR(20),
	moduleinactive_text_color varchar(20),
	moduleinactive_link_color varchar(20),
	moduleinactive_background_color varchar(20),
	moduleinactive_background_image varchar(255),
	moduleinactive_background_repeat varchar(20),
	moduleinactive_border varchar(20),
	headers_text_color varchar(20),
	headers_link_color varchar(20),
	headers_background_color varchar(20),
	headers_background_image varchar(255),
	headers_background_repeat varchar(20),
	headers_border varchar(20),
	page_link_color varchar(20),
	PRIMARY KEY  (customprofileid),
	KEY(userid)
	) ENGINE = $innodb
";
$schema['CREATE']['explain']['customprofile'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "customprofile");


$schema['CREATE']['query']['datastore'] = "
CREATE TABLE " . TABLE_PREFIX . "datastore (
	title CHAR(50) NOT NULL DEFAULT '',
	data MEDIUMTEXT,
	unserialize SMALLINT NOT NULL DEFAULT '0',
	PRIMARY KEY (title)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['datastore'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "datastore");

$schema['CREATE']['query']['deletionlog'] = "
CREATE TABLE " . TABLE_PREFIX . "deletionlog (
	primaryid INT UNSIGNED NOT NULL DEFAULT '0',
	type ENUM('post', 'thread', 'visitormessage', 'groupmessage', 'picturecomment') NOT NULL DEFAULT 'post',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	reason VARCHAR(125) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (primaryid, type),
	KEY type (type, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['deletionlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "deletionlog");



$schema['CREATE']['query']['discussion'] = "
CREATE TABLE " . TABLE_PREFIX . "discussion (
	discussionid INT unsigned NOT NULL auto_increment,
	groupid INT unsigned NOT NULL,
	firstpostid INT unsigned NOT NULL,
	lastpostid INT unsigned NOT NULL,
	lastpost INT unsigned NOT NULL,
	lastposter VARCHAR(255) NOT NULL,
	lastposterid INT unsigned NOT NULL,
	visible INT unsigned NOT NULL default '0',
	deleted INT unsigned NOT NULL default '0',
	moderation INT unsigned NOT NULL default '0',
	subscribers ENUM('0', '1') default '0',
	PRIMARY KEY  (discussionid),
	KEY groupid (groupid, lastpost)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['discussion'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "discussion");


$schema['CREATE']['query']['editlog'] = "
CREATE TABLE " . TABLE_PREFIX . "editlog (
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	postid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	reason VARCHAR(200) NOT NULL DEFAULT '',
	hashistory SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid),
	KEY postid (postid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['editlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "editlog");



$schema['CREATE']['query']['event'] = "
CREATE TABLE " . TABLE_PREFIX . "event (
	nodeid          INT UNSIGNED NOT NULL PRIMARY KEY,
	eventstartdate  INT UNSIGNED NOT NULL DEFAULT '0',
	eventenddate    INT UNSIGNED NOT NULL DEFAULT '0',
	location        VARCHAR (191) NOT NULL DEFAULT '',
	maplocation     VARCHAR (191) NOT NULL DEFAULT '',
	allday          TINYINT(1) NOT NULL DEFAULT '0',
	ignoredst       TINYINT(1) NOT NULL DEFAULT '1',
	eventhighlightid INT UNSIGNED NOT NULL DEFAULT '0',
	KEY eventstartdate (eventstartdate),
	KEY eventenddate   (eventenddate)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['event'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "event");


$schema['CREATE']['query']['eventhighlight'] = "
CREATE TABLE " . TABLE_PREFIX . "eventhighlight (
	eventhighlightid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	backgroundcolor VARCHAR(50) NOT NULL DEFAULT '',
	textcolor VARCHAR(50) NOT NULL DEFAULT '',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	denybydefault TINYINT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (eventhighlightid),
	INDEX displayorder (displayorder)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['eventhighlight'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "eventhighlight");


$schema['CREATE']['query']['eventhighlightpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "eventhighlightpermission (
	eventhighlightid INT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid INT UNSIGNED NOT NULL DEFAULT '0',
	UNIQUE INDEX eventhighlightid (eventhighlightid, usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['eventhighlightpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "eventhighlightpermission");



$schema['CREATE']['query']['externalcache'] = "
CREATE TABLE " . TABLE_PREFIX . "externalcache (
	cachehash CHAR(32) NOT NULL DEFAULT '',
	text MEDIUMTEXT,
	headers MEDIUMTEXT,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	forumid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (cachehash),
	KEY dateline (dateline, cachehash),
	KEY forumid (forumid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['externalcache'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "externalcache");



$schema['CREATE']['query']['faq'] = "
CREATE TABLE " . TABLE_PREFIX . "faq (
	faqname VARCHAR(191) BINARY NOT NULL DEFAULT '',
	faqparent VARCHAR(50) NOT NULL DEFAULT '',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	volatile SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product VARCHAR(25) NOT NULL DEFAULT '',
	PRIMARY KEY (faqname),
	KEY faqparent (faqparent)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['faq'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "faq");


/*
	Currently, there's no recipient-specific data in these payloads.
	That provides an opportunity to bundle multiple messages as one
	multicast message.
	The basic idea is that the fcmessage saves the CONTENT of the
	message body, and fcmessage_queue saves the intended recipients,
	and the "send after" times for each recipient (as each may get
	different responses requiring different wait times), and the cron
	will pick up *all* messages & recipients that are ready, bundle up
	whichever ones can be grouped & send as many in bulk as possible.

	Note that this design may not be very useful if we start adding a lot of
	"static" (i.e. doesn't have to be calculated @ send time)
	recipient-specific data to the message body.
 */
$schema['CREATE']['query']['fcmessage'] = "
CREATE TABLE " . TABLE_PREFIX . "fcmessage (
	messageid                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
	message_data                VARCHAR(2048) NOT NULL DEFAULT '',
	message_hash                CHAR(32) NULL DEFAULT NULL,
	PRIMARY KEY (messageid),
	UNIQUE KEY message_hash (message_hash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['fcmessage'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "fcmessage");


$schema['CREATE']['query']['fcmessage_queue'] = "
CREATE TABLE " . TABLE_PREFIX . "fcmessage_queue (
	recipient_apiclientid       INT UNSIGNED NOT NULL DEFAULT '0',
	messageid                   INT UNSIGNED NOT NULL DEFAULT '0',
	retryafter                  INT UNSIGNED NOT NULL DEFAULT '0',
	retryafterheader            INT UNSIGNED NOT NULL DEFAULT '0',
	retries						INT UNSIGNED NOT NULL DEFAULT '0',
	status                      ENUM('ready', 'processing') NOT NULL DEFAULT 'ready',
	UNIQUE KEY guid  (recipient_apiclientid, messageid),
	KEY id_status (messageid, status)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['fcmessage_queue'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "fcmessage_queue");


$schema['CREATE']['query']['fcmessage_offload'] = "
CREATE TABLE " . TABLE_PREFIX . "fcmessage_offload (
	recipientids                VARCHAR(2048) NOT NULL DEFAULT '',
	message_data                VARCHAR(2048) NOT NULL DEFAULT '',
	hash                        CHAR(32) NOT NULL DEFAULT '',
	removeafter                 INT UNSIGNED NOT NULL DEFAULT '0',
	UNIQUE KEY guid  (hash),
	KEY removeafter_hash (removeafter, hash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['fcmessage_offload'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "fcmessage_offload");



$schema['CREATE']['query']['filedata'] = "
CREATE TABLE " . TABLE_PREFIX . "filedata (
	filedataid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	filedata LONGBLOB,
	filesize INT UNSIGNED NOT NULL DEFAULT '0',
	filehash CHAR(32) NOT NULL DEFAULT '',
	extension VARCHAR(20) BINARY NOT NULL DEFAULT '',
	refcount INT UNSIGNED NOT NULL DEFAULT '0',
	width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	publicview SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (filedataid),
	KEY filesize (filesize),
	KEY filehash (filehash),
	KEY userid (userid),
	KEY refcount (refcount, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['filedata'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "filedata");



$schema['CREATE']['query']['filedataresize'] = "
CREATE TABLE " . TABLE_PREFIX . "filedataresize (
	filedataid INT UNSIGNED NOT NULL,
	resize_type ENUM('icon', 'thumb', 'small', 'medium', 'large') NOT NULL DEFAULT 'thumb',
	resize_filedata MEDIUMBLOB,
	resize_filesize INT UNSIGNED NOT NULL DEFAULT '0',
	resize_dateline INT UNSIGNED NOT NULL DEFAULT '0',
	resize_width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	resize_height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	reload TINYINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (filedataid, resize_type),
	KEY type (resize_type)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['filedataresize'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "filedataresize");

$schema['CREATE']['query']['forumpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "forumpermission (
	forumpermissionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	forumid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	forumpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (forumpermissionid),
	UNIQUE KEY ugid_fid (usergroupid, forumid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['forumpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "forumpermission");


$schema['CREATE']['query']['gallery'] = "
CREATE TABLE " . TABLE_PREFIX . "gallery (
	nodeid INT UNSIGNED NOT NULL,
	caption VARCHAR(512),
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['gallery'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "gallery");


$schema['CREATE']['query']['privacyconsent'] = "
CREATE TABLE " . TABLE_PREFIX . "privacyconsent (
	privacyconsentid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	created INT UNSIGNED NOT NULL DEFAULT '0',
	consent TINYINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (privacyconsentid),
	KEY (ipaddress),
	KEY (created)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['privacyconsent'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "privacyconsent");


$schema['CREATE']['query']['hook'] = "
CREATE TABLE " . TABLE_PREFIX . "hook (
	hookid INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	product VARCHAR(25) NOT NULL DEFAULT 'vbulletin',
	hookname VARCHAR(100) NOT NULL DEFAULT '',
	title VARCHAR(50) NOT NULL DEFAULT '',
	active TINYINT(3) UNSIGNED NOT NULL DEFAULT 0,
	hookorder TINYINT(3) UNSIGNED NOT NULL DEFAULT 10,
	template VARCHAR(100) NOT NULL DEFAULT '',
	arguments TEXT NOT NULL,
	PRIMARY KEY (hookid),
	KEY product (product, active, hookorder),
	KEY hookorder (hookorder)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['hook'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "hook");



$schema['CREATE']['query']['holiday'] = "
CREATE TABLE " . TABLE_PREFIX . "holiday (
	holidayid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	varname VARCHAR(100) NOT NULL DEFAULT '',
	recurring SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	recuroption CHAR(6) NOT NULL DEFAULT '',
	allowsmilies SMALLINT NOT NULL DEFAULT '1',
	PRIMARY KEY (holidayid),
	KEY varname (varname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['holiday'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "holiday");



$schema['CREATE']['query']['humanverify'] = "
CREATE TABLE " . TABLE_PREFIX . "humanverify (
	hash CHAR(32) NOT NULL DEFAULT '',
	answer MEDIUMTEXT,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	viewed SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	KEY hash (hash),
	KEY dateline (dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['humanverify'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "humanverify");



$schema['CREATE']['query']['hvanswer'] = "
CREATE TABLE " . TABLE_PREFIX . "hvanswer (
	answerid INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	questionid INT NOT NULL DEFAULT '0',
	answer VARCHAR(255) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	INDEX (questionid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['hvanswer'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "hvanswer");



$schema['CREATE']['query']['hvquestion'] = "
CREATE TABLE " . TABLE_PREFIX . "hvquestion (
	questionid INT  UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	regex VARCHAR(255) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0'
) ENGINE = $innodb
";
$schema['CREATE']['explain']['hvquestion'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "hvquestion");



$schema['CREATE']['query']['icon'] = "
CREATE TABLE " . TABLE_PREFIX . "icon (
	iconid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(100) NOT NULL DEFAULT '',
	iconpath VARCHAR(100) NOT NULL DEFAULT '',
	imagecategoryid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (iconid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['icon'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "icon");



$schema['CREATE']['query']['imagecategory'] = "
CREATE TABLE " . TABLE_PREFIX . "imagecategory (
	imagecategoryid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(255) NOT NULL DEFAULT '',
	imagetype SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (imagecategoryid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['imagecategory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "imagecategory");


$schema['CREATE']['query']['imagecategorypermission'] = "
CREATE TABLE " . TABLE_PREFIX . "imagecategorypermission (
	imagecategoryid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	KEY imagecategoryid (imagecategoryid, usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['imagecategorypermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "imagecategorypermission");


$schema['CREATE']['query']['infraction'] = "
CREATE TABLE " . TABLE_PREFIX . "infraction (
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	infractionlevelid INT UNSIGNED NOT NULL DEFAULT '0',
	infractednodeid INT UNSIGNED NOT NULL DEFAULT '0',
	infracteduserid INT UNSIGNED NOT NULL DEFAULT '0',
	points INT UNSIGNED NOT NULL DEFAULT '0',
	reputation_penalty INT UNSIGNED NOT NULL DEFAULT '0',
	note varchar(255) NOT NULL DEFAULT '',
	action SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	actiondateline INT UNSIGNED NOT NULL DEFAULT '0',
	actionuserid INT UNSIGNED NOT NULL DEFAULT '0',
	actionreason VARCHAR(255) NOT NULL DEFAULT '0',
	expires INT UNSIGNED NOT NULL DEFAULT '0',
	customreason VARCHAR(255) NOT NULL DEFAULT '',
	PRIMARY KEY (nodeid),
	KEY expires (expires, action),
	KEY infracteduserid (infracteduserid, action),
	KEY infractonlevelid (infractionlevelid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['infraction'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "infraction");



$schema['CREATE']['query']['infractionban'] = "
CREATE TABLE " . TABLE_PREFIX . "infractionban (
	infractionbanid int unsigned NOT NULL auto_increment,
	usergroupid int NOT NULL DEFAULT '0',
	banusergroupid int unsigned NOT NULL DEFAULT '0',
	amount int unsigned NOT NULL DEFAULT '0',
	period char(5) NOT NULL DEFAULT '',
	method enum('points','infractions') NOT NULL default 'infractions',
	PRIMARY KEY (infractionbanid),
	KEY usergroupid (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['infractionban'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "infractionban");


$schema['CREATE']['query']['infractiongroup'] = "
CREATE TABLE " . TABLE_PREFIX . "infractiongroup (
	infractiongroupid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	usergroupid INT NOT NULL DEFAULT '0',
	orusergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	pointlevel INT UNSIGNED NOT NULL DEFAULT '0',
	override SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (infractiongroupid),
	KEY usergroupid (usergroupid, pointlevel)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['infractiongroup'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "infractiongroup");


$schema['CREATE']['query']['infractionlevel'] = "
CREATE TABLE " . TABLE_PREFIX . "infractionlevel (
	infractionlevelid INT UNSIGNED NOT NULL AUTO_INCREMENT ,
	points INT UNSIGNED NOT NULL DEFAULT '0',
	reputation_penalty INT UNSIGNED NOT NULL DEFAULT '0',
	expires INT UNSIGNED NOT NULL DEFAULT '0',
	period ENUM('H','D','M','N') DEFAULT 'H' NOT NULL,
	warning SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	extend SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (infractionlevelid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['infractionlevel'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "infractionlevel");


$schema['CREATE']['query']['ipaddressinfo'] = "
CREATE TABLE " . TABLE_PREFIX . "ipaddressinfo (
	`ipaddressinfoid` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
	`ipaddress` VARCHAR(45) NOT NULL DEFAULT '',
	`eustatus` TINYINT NOT NULL DEFAULT 0,
	`created` INT UNSIGNED NOT NULL,
	PRIMARY KEY (`ipaddressinfoid`),
	UNIQUE KEY (`ipaddress`),
	KEY (`created`)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['ipaddressinfo'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "ipaddressinfo");


$schema['CREATE']['query']['groupintopic'] = "
CREATE TABLE " . TABLE_PREFIX . "groupintopic (
	userid INT UNSIGNED NOT NULL,
	groupid INT UNSIGNED NOT NULL,
	nodeid INT UNSIGNED NOT NULL,
	UNIQUE KEY (userid, groupid, nodeid),
	KEY (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['groupintopic'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "groupintopic");


$schema['CREATE']['query']['language'] = "
CREATE TABLE " . TABLE_PREFIX . "language (
	languageid smallint(5) UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(50) NOT NULL default '',
	userselect smallint(5) UNSIGNED NOT NULL default '1',
	options smallint(5) UNSIGNED NOT NULL default '1',
	languagecode VARCHAR(12) NOT NULL default '',
	charset VARCHAR(15) NOT NULL default '',
	dateoverride VARCHAR(50) NOT NULL default '',
	timeoverride VARCHAR(50) NOT NULL default '',
	registereddateoverride VARCHAR(50) NOT NULL default '',
	calformat1override VARCHAR(50) NOT NULL default '',
	calformat2override VARCHAR(50) NOT NULL default '',
	eventdateformatoverride VARCHAR(50) NOT NULL default '',
	pickerdateformatoverride VARCHAR(50) NOT NULL default '',
	logdateoverride VARCHAR(50) NOT NULL default '',
	locale VARCHAR(20) NOT NULL default '',
	decimalsep CHAR(1) NOT NULL default '.',
	thousandsep CHAR(1) NOT NULL default ',',
	phrasegroup_global MEDIUMTEXT,
	phrasegroup_cpglobal MEDIUMTEXT,
	phrasegroup_cppermission MEDIUMTEXT,
	phrasegroup_forum MEDIUMTEXT,
	phrasegroup_calendar MEDIUMTEXT,
	phrasegroup_attachment_image MEDIUMTEXT,
	phrasegroup_style MEDIUMTEXT,
	phrasegroup_logging MEDIUMTEXT,
	phrasegroup_cphome MEDIUMTEXT,
	phrasegroup_promotion MEDIUMTEXT,
	phrasegroup_user MEDIUMTEXT,
	phrasegroup_help_faq MEDIUMTEXT,
	phrasegroup_sql MEDIUMTEXT,
	phrasegroup_subscription MEDIUMTEXT,
	phrasegroup_language MEDIUMTEXT,
	phrasegroup_bbcode MEDIUMTEXT,
	phrasegroup_stats MEDIUMTEXT,
	phrasegroup_diagnostic MEDIUMTEXT,
	phrasegroup_maintenance MEDIUMTEXT,
	phrasegroup_profilefield MEDIUMTEXT,
	phrasegroup_thread MEDIUMTEXT,
	phrasegroup_timezone MEDIUMTEXT,
	phrasegroup_banning MEDIUMTEXT,
	phrasegroup_reputation MEDIUMTEXT,
	phrasegroup_wol MEDIUMTEXT,
	phrasegroup_threadmanage MEDIUMTEXT,
	phrasegroup_pm MEDIUMTEXT,
	phrasegroup_cpuser MEDIUMTEXT,
	phrasegroup_cron MEDIUMTEXT,
	phrasegroup_moderator MEDIUMTEXT,
	phrasegroup_cpoption MEDIUMTEXT,
	phrasegroup_cprank MEDIUMTEXT,
	phrasegroup_cpusergroup MEDIUMTEXT,
	phrasegroup_holiday MEDIUMTEXT,
	phrasegroup_posting MEDIUMTEXT,
	phrasegroup_poll MEDIUMTEXT,
	phrasegroup_fronthelp MEDIUMTEXT,
	phrasegroup_register MEDIUMTEXT,
	phrasegroup_search MEDIUMTEXT,
	phrasegroup_showthread MEDIUMTEXT,
	phrasegroup_postbit MEDIUMTEXT,
	phrasegroup_forumdisplay MEDIUMTEXT,
	phrasegroup_messaging MEDIUMTEXT,
	phrasegroup_inlinemod MEDIUMTEXT,
	phrasegroup_hooks MEDIUMTEXT,
	phrasegroup_cprofilefield MEDIUMTEXT,
	phrasegroup_reputationlevel MEDIUMTEXT,
	phrasegroup_infraction MEDIUMTEXT,
	phrasegroup_infractionlevel MEDIUMTEXT,
	phrasegroup_notice MEDIUMTEXT,
	phrasegroup_prefix MEDIUMTEXT,
	phrasegroup_prefixadmin MEDIUMTEXT,
	phrasegroup_album MEDIUMTEXT,
	phrasegroup_socialgroups MEDIUMTEXT,
	phrasegroup_advertising MEDIUMTEXT,
	phrasegroup_tagscategories MEDIUMTEXT,
	phrasegroup_contenttypes MEDIUMTEXT,
	phrasegroup_vbblock MEDIUMTEXT,
	phrasegroup_vbblocksettings MEDIUMTEXT,
	phrasegroup_vb5blog MEDIUMTEXT,
	vblangcode VARCHAR(12)  NOT NULL default '',
	revision SMALLINT(5) UNSIGNED NOT NULL default '0',
	PRIMARY KEY  (languageid)
) ENGINE = $myisam
";
$schema['CREATE']['explain']['language'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "language");



$schema['CREATE']['query']['link'] = "
CREATE TABLE " . TABLE_PREFIX . "link (
	nodeid INT UNSIGNED NOT NULL,
	filedataid INT UNSIGNED NOT NULL DEFAULT '0',
	url VARCHAR(255),
	url_title VARCHAR(255),
	meta MEDIUMTEXT,
	PRIMARY KEY (nodeid),
	KEY (filedataid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['link'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "link");



$schema['CREATE']['query']['mailqueue'] = "
CREATE TABLE " . TABLE_PREFIX . "mailqueue (
	mailqueueid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	toemail MEDIUMTEXT,
	fromemail MEDIUMTEXT,
	subject MEDIUMTEXT,
	message MEDIUMTEXT,
	header MEDIUMTEXT,
	PRIMARY KEY (mailqueueid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['mailqueue'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "mailqueue");


$schema['CREATE']['query']['messagefolder'] = "
CREATE TABLE " . TABLE_PREFIX . "messagefolder (
	folderid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL,
	title varchar(512),
	titlephrase varchar(250),
	oldfolderid TINYINT NULL DEFAULT NULL,
	PRIMARY KEY (folderid),
	KEY (userid),
	UNIQUE KEY userid_oldfolderid (userid, oldfolderid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['messagefolder'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "messagefolder");


$schema['CREATE']['query']['moderation'] = "
CREATE TABLE " . TABLE_PREFIX . "moderation (
	primaryid INT UNSIGNED NOT NULL DEFAULT '0',
	type ENUM('thread', 'reply', 'visitormessage', 'groupmessage', 'picturecomment') NOT NULL DEFAULT 'thread',
	dateline INT UNSIGNED NOT NULl DEFAULT '0',
	PRIMARY KEY (primaryid, type),
	KEY type (type, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['moderation'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "moderation");



$schema['CREATE']['query']['moderator'] = "
CREATE TABLE " . TABLE_PREFIX . "moderator (
	moderatorid INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	nodeid INT NOT NULL DEFAULT '0',
	permissions INT UNSIGNED NOT NULL DEFAULT '0',
	permissions2 INT UNSIGNED NOT NULl DEFAULT '0',
	PRIMARY KEY (moderatorid),
	UNIQUE KEY userid_nodeid (userid, nodeid),
	KEY nodeid (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['moderator'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "moderator");



$schema['CREATE']['query']['moderatorlog'] = "
CREATE TABLE " . TABLE_PREFIX . "moderatorlog (
	moderatorlogid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	action VARCHAR(250) NOT NULL DEFAULT '',
	type SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	nodetitle VARCHAR(250) NOT NULL DEFAULT '',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	product VARCHAR(25) NOT NULL DEFAULT '',
	id1 INT UNSIGNED NOT NULL DEFAULT '0',
	id2 INT UNSIGNED NOT NULL DEFAULT '0',
	id3 INT UNSIGNED NOT NULL DEFAULT '0',
	id4 INT UNSIGNED NOT NULL DEFAULT '0',
	id5 INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (moderatorlogid),
	KEY nodeid (nodeid),
	KEY product (product),
	KEY id1 (id1),
	KEY id2 (id2)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['moderatorlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "moderatorlog");

/*
	Index notes

		INDEX node_parent(parentid),
	is not strictly needed because mysql should be able to use the following composite index
		INDEX node_parent_lastcontent(parentid, showpublished, showapproved, lastcontent, lastcontentid),
	for the same purpose, as parentid is the left-most column there.
	For very large channels (> 30k topics), fetching topics with filters on parentid, inlist,  showpublished,
	showapproved, and sorted by lastcontent with a limit was driving the optimizer to do a index_merge of
	node_parent & node_inlist (or worse) instead of utilizing a more optimal (in practice) index of
	(parentid, inlist, lastcontent) that was added specifically to support the topic queries.
	E.g. with a limit 1000 the index merge query was taking ~15s, while the same query after dropping the
	node_parent index (causing the optimizer to use one of the composite indices) took less than 0.5s.
	Since the index was causing more harm than good, and queries using that index should be able to use the
	composite indices (other than possibly other queries using index merges, which really suggests we need
	to add a composite index), I've removed it.

		INDEX node_parent_userid(parentid, userid),
	is useful for counting blocked/ignored users' topics in a channel. The existing node_user(userid) is not
	very useful for this query (~3s to find 2-300 records in a 30k topics channel with the old index vs
	<0.1s with new index)

		INDEX created(created, nodeid),
	The nodeid is there in order to allow mysql optimizer to sort via the index & perform LIMIT optimizations
	for frequent ORDER BY node.created ASC, node.nodeid ASC conditions.
 */
$schema['CREATE']['query']['node'] = "
CREATE TABLE " . TABLE_PREFIX . "node (
	nodeid INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	routeid INT UNSIGNED NOT NULL,
	contenttypeid SMALLINT NOT NULL,
	publishdate INTEGER,
	unpublishdate INTEGER,
	userid INT UNSIGNED ,
	groupid INT UNSIGNED,
	authorname VARCHAR(100),
	description VARCHAR(1024),
	title VARCHAR(512),
	htmltitle VARCHAR(512),
	parentid INTEGER NOT NULL,
	urlident VARCHAR(512),
	displayorder SMALLINT,
	starter INT NOT NULL DEFAULT '0',
	created INT,
	lastcontent INT NOT NULL DEFAULT '0',
	lastcontentid INT NOT NULL DEFAULT '0',
	lastcontentauthor VARCHAR(100) NOT NULL DEFAULT '',
	lastauthorid INT UNSIGNED NOT NULL DEFAULT '0',
	lastprefixid VARCHAR(25) NOT NULL DEFAULT '',
	textcount mediumint UNSIGNED NOT NULL DEFAULT '0',
	textunpubcount mediumint UNSIGNED NOT NULL DEFAULT '0',
	totalcount mediumint UNSIGNED NOT NULL DEFAULT '0',
	totalunpubcount mediumint UNSIGNED NOT NULL DEFAULT '0',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	showpublished SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	oldid INT UNSIGNED,
	oldcontenttypeid INT UNSIGNED,
	nextupdate INTEGER,
	lastupdate INTEGER,
	featured SMALLINT NOT NULL DEFAULT 0,
	CRC32 VARCHAR(10) NOT NULL DEFAULT '',
	taglist MEDIUMTEXT,
	inlist SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	protected SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	setfor INTEGER NOT NULL DEFAULT 0,
	votes SMALLINT(5) UNSIGNED NOT NULL DEFAULT '0',
	hasphoto SMALLINT NOT NULL DEFAULT '0',
	hasvideo SMALLINT NOT NULL DEFAULT '0',
	deleteuserid  INT UNSIGNED,
	deletereason VARCHAR(125),
	open SMALLINT NOT NULL DEFAULT '1',
	showopen SMALLINT NOT NULL DEFAULT '1',
	sticky TINYINT(1) NOT NULL DEFAULT '0',
	approved TINYINT(1) NOT NULL DEFAULT '1',
	showapproved TINYINT(1) NOT NULL DEFAULT '1',
	viewperms TINYINT NOT NULL DEFAULT 2,
	commentperms TINYINT NOT NULL DEFAULT 1,
	nodeoptions INT UNSIGNED NOT NULL DEFAULT 138,
	prefixid VARCHAR(25) NOT NULL DEFAULT '',
	iconid SMALLINT NOT NULL DEFAULT '0',
	public_preview SMALLINT NOT NULL DEFAULT '0',
	INDEX node_lastauthorid(lastauthorid),
	INDEX node_lastcontent(lastcontent),
	INDEX node_textcount(textcount),
	INDEX node_ip(ipaddress),
	INDEX node_pubdate(publishdate, nodeid),
	INDEX node_unpubdate(unpublishdate),
	INDEX node_parent_lastcontent(parentid, showpublished, showapproved, lastcontent, lastcontentid),
	INDEX node_parent_inlist_lastcontent(parentid, inlist, lastcontent),
	INDEX node_parent_userid(parentid, userid),
	INDEX node_nextupdate(nextupdate),
	INDEX node_lastupdate(lastupdate),
	INDEX node_user(userid),
	INDEX node_oldinfo(oldcontenttypeid, oldid),
	INDEX node_urlident(urlident),
	INDEX node_sticky(sticky),
	INDEX node_starter(starter),
	INDEX node_approved(approved),
	INDEX node_ppreview(public_preview),
	INDEX node_showapproved(showapproved),
	INDEX node_ctypid_userid_dispo_idx(contenttypeid, userid, displayorder),
	INDEX node_setfor_pubdt_idx(setfor, publishdate),
	INDEX prefixid (prefixid, nodeid),
	INDEX nodeid (nodeid, contenttypeid),
	INDEX contenttypeid_parentid (contenttypeid, parentid),
	INDEX node_featured(featured),
	INDEX node_inlist(inlist),
	INDEX created(created, nodeid),
	INDEX totalcount(totalcount),
	INDEX showpublished(showpublished),
	INDEX routeid(routeid)
	) ENGINE = $innodb
";
$schema['CREATE']['explain']['node'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "node");



$schema['CREATE']['query']['noderead'] = "
CREATE TABLE " . TABLE_PREFIX . "noderead (
	userid int(10) unsigned NOT NULL default '0',
	nodeid int(10) unsigned NOT NULL default '0',
	readtime int(10) unsigned NOT NULL default '0',
	PRIMARY KEY  (userid, nodeid),
	KEY readtime (readtime)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['noderead'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "noderead");


$schema['CREATE']['query']['nodeview'] = "
CREATE TABLE " . TABLE_PREFIX . "nodeview (
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	count INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['nodeview'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "nodeview");

$schema['CREATE']['query']['notice'] = "
CREATE TABLE " . TABLE_PREFIX . "notice (
	noticeid INT UNSIGNED NOT NULL auto_increment,
	title VARCHAR(250) NOT NULL DEFAULT '',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	persistent SMALLINT UNSIGNED NOT NULL default '0',
	active SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	dismissible SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	noticeoptions INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (noticeid),
	KEY active (active)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['notice'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "notice");



$schema['CREATE']['query']['noticecriteria'] = "
CREATE TABLE " . TABLE_PREFIX . "noticecriteria (
	noticeid INT UNSIGNED NOT NULL DEFAULT '0',
	criteriaid VARCHAR(191) NOT NULL DEFAULT '',
	condition1 VARCHAR(250) NOT NULL DEFAULT '',
	condition2 VARCHAR(250) NOT NULL DEFAULT '',
	condition3 VARCHAR(250) NOT NULL DEFAULT '',
	PRIMARY KEY (noticeid,criteriaid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['noticecriteria'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "noticecriteria");



$schema['CREATE']['query']['noticedismissed'] = "
CREATE TABLE " . TABLE_PREFIX . "noticedismissed (
	noticeid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (noticeid,userid),
	KEY userid (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['noticedismissed'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "noticedismissed");



/*
 * notification tables, added in 5.1.6 Alpha 1~2
 * Probably best to create the tables in order of dependence, parent to child:
 *  notificationtype > notificationtrigger > notification
 * Default data is added in upgrade final.
 */

$schema['CREATE']['query']['notificationtype'] = "
CREATE TABLE " . TABLE_PREFIX . "notificationtype (
	typeid 			SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	typename 		VARCHAR(191) NOT NULL UNIQUE,
	class			VARCHAR(191) NOT NULL UNIQUE,
	PRIMARY KEY  	(typeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['notificationtype'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "notificationtype");


$schema['CREATE']['query']['notificationevent'] = "
CREATE TABLE " . TABLE_PREFIX . "notificationevent (
	eventname		VARCHAR(191) NOT NULL UNIQUE,
	classes 		MEDIUMTEXT NULL DEFAULT NULL,
	PRIMARY KEY  	(eventname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['notificationevent'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "notificationevent");

$schema['CREATE']['query']['notification'] = "
CREATE TABLE " . TABLE_PREFIX . "notification (
	notificationid		INT UNSIGNED NOT NULL AUTO_INCREMENT,
	recipient	 		INT UNSIGNED NOT NULL,
	sender	 			INT UNSIGNED DEFAULT NULL,
	lookupid			VARCHAR(150) NULL DEFAULT NULL,
	lookupid_hashed		CHAR(32) NULL DEFAULT NULL,
	sentbynodeid		INT UNSIGNED DEFAULT NULL,
	customdata			MEDIUMTEXT,
	typeid				SMALLINT UNSIGNED NOT NULL,
	lastsenttime 		INT(10) UNSIGNED NOT NULL DEFAULT '0',
	lastreadtime 		INT(10) UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY 	(notificationid),
	UNIQUE KEY guid	(recipient, lookupid_hashed),
	KEY 			(recipient),
	KEY 			(lookupid_hashed),
	KEY 			(lastsenttime),
	KEY 			(lastreadtime)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['notification'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "notification");
/* END CREATE NOTIFICATION TABLES (Added 5.1.6) */


$schema['CREATE']['query']['mapiposthash'] = "
	CREATE TABLE " . TABLE_PREFIX . "mapiposthash (
		posthashid INT UNSIGNED NOT NULL AUTO_INCREMENT,
		posthash VARCHAR(32) NOT NULL DEFAULT '',
		filedataid INT UNSIGNED NOT NULL DEFAULT '0',
		dateline INT UNSIGNED NOT NULL DEFAULT '0',
		PRIMARY KEY (posthashid),
		KEY posthash (posthash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['mapiposthash'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "mapiposthash");

$schema['CREATE']['query']['package'] = "
CREATE TABLE " . TABLE_PREFIX . "package (
	packageid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	productid VARCHAR(25) NOT NULL,
	class VARBINARY(50) NOT NULL,
	PRIMARY KEY  (packageid),
	UNIQUE KEY class (class)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['package'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "package");



$schema['CREATE']['query']['passwordhistory'] = "
CREATE TABLE " . TABLE_PREFIX . "passwordhistory (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	token VARCHAR(255) NOT NULL DEFAULT '',
	scheme VARCHAR(100) NOT NULL DEFAULT '',
	passworddate int NOT NULL DEFAULT '0',
	KEY userid (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['passwordhistory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "passwordhistory");



$schema['CREATE']['query']['paymentapi'] = "
CREATE TABLE " . TABLE_PREFIX . "paymentapi (
	paymentapiid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(250) NOT NULL DEFAULT '',
	currency VARCHAR(250) NOT NULL DEFAULT '',
	recurring SMALLINT NOT NULL DEFAULT '0',
	classname VARCHAR(250) NOT NULL DEFAULT '',
	active SMALLINT NOT NULL DEFAULT '0',
	settings MEDIUMTEXT,
	subsettings MEDIUMTEXT,
	PRIMARY KEY (paymentapiid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['paymentapi'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "paymentapi");



$schema['CREATE']['query']['paymentinfo'] = "
CREATE TABLE " . TABLE_PREFIX . "paymentinfo (
	paymentinfoid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	hash VARCHAR(32) NOT NULL DEFAULT '',
	subscriptionid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	subscriptionsubid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	completed SMALLINT NOT NULL DEFAULT '0',
	PRIMARY KEY (paymentinfoid),
	KEY hash (hash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['paymentinfo'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "paymentinfo");

$schema['CREATE']['query']['paymenttransaction'] = "
CREATE TABLE " . TABLE_PREFIX . "paymenttransaction (
	paymenttransactionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	paymentinfoid INT UNSIGNED NOT NULL DEFAULT '0',
	transactionid VARCHAR(250) NOT NULL DEFAULT '',
	state SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	amount DOUBLE UNSIGNED NOT NULL DEFAULT '0',
	currency VARCHAR(5) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	paymentapiid INT UNSIGNED NOT NULL DEFAULT '0',
	request MEDIUMTEXT,
	reversed INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (paymenttransactionid),
	KEY dateline (dateline),
	KEY transactionid (transactionid),
	KEY paymentapiid (paymentapiid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['paymenttransaction'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "paymenttransaction");

$schema['CREATE']['query']['permission'] = "
CREATE TABLE " . TABLE_PREFIX . "permission (
	permissionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nodeid INT UNSIGNED NOT NULL,
	groupid INT UNSIGNED NOT NULL,
	forumpermissions INT UNSIGNED NOT NULL DEFAULT 0,
	moderatorpermissions INT UNSIGNED NOT NULL DEFAULT 0,
	createpermissions INT UNSIGNED NOT NULL DEFAULT 0,
	forumpermissions2 INT UNSIGNED NOT NULL DEFAULT 0,
	edit_time FLOAT NOT NULL DEFAULT 0,
	maxtags SMALLINT UNSIGNED NOT NULL DEFAULT 0,
	maxstartertags SMALLINT UNSIGNED NOT NULL DEFAULT 0,
	maxothertags SMALLINT UNSIGNED NOT NULL DEFAULT 0,
	maxattachments SMALLINT UNSIGNED NOT NULL DEFAULT 0,
	maxchannels SMALLINT UNSIGNED NOT NULL DEFAULT 0,
	channeliconmaxsize INT UNSIGNED NOT NULL DEFAULT 0,
	PRIMARY KEY (permissionid),
	KEY perm_nodeid (nodeid),
	KEY perm_groupid (groupid),
	UNIQUE KEY perm_group_node (groupid, nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['permission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "permission");

$schema['CREATE']['query']['contentpriority'] = "
CREATE TABLE " . TABLE_PREFIX . "contentpriority (
	contenttypeid VARCHAR(20) NOT NULL,
	sourceid INT(10) UNSIGNED NOT NULL,
	prioritylevel DOUBLE(2,1) NOT NULL,
	PRIMARY KEY (contenttypeid, sourceid)
) ENGINE = $innodb
";

$schema['CREATE']['explain']['contentpriority'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "contentpriority");

$schema['CREATE']['query']['photo'] = "
CREATE TABLE " . TABLE_PREFIX . "photo (
	nodeid INT UNSIGNED NOT NULL,
	filedataid INT UNSIGNED NOT NULL,
	caption VARCHAR(512),
	height SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	width SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	style varchar(512),
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['photo'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "photo");

$schema['CREATE']['query']['phrase'] = "
CREATE TABLE " . TABLE_PREFIX . "phrase (
	phraseid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	languageid SMALLINT NOT NULL DEFAULT '0',
	varname VARCHAR(191) BINARY NOT NULL DEFAULT '',
	fieldname VARCHAR(20) NOT NULL DEFAULT '',
	text MEDIUMTEXT,
	product VARCHAR(25) NOT NULL DEFAULT '',
	username VARCHAR(100) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	version VARCHAR(30) NOT NULL DEFAULT '',
	PRIMARY KEY  (phraseid),
	UNIQUE KEY name_lang_type (varname, languageid),
	FULLTEXT INDEX (text),
	KEY languageid (languageid, fieldname)
) ENGINE = $myisam
";
$schema['CREATE']['explain']['phrase'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "phrase");



$schema['CREATE']['query']['phrasetype'] = "
CREATE TABLE " . TABLE_PREFIX . "phrasetype (
	fieldname CHAR(20) NOT NULL default '',
	title CHAR(50) NOT NULL DEFAULT '',
	editrows SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product VARCHAR(25) NOT NULL DEFAULT '',
	special SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (fieldname)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['phrasetype'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "phrasetype");

$schema['CREATE']['query']['poll'] = "
CREATE TABLE " . TABLE_PREFIX . "poll (
	nodeid INT UNSIGNED NOT NULL,
	options TEXT,
	active SMALLINT NOT NULL DEFAULT '1',
	numberoptions SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	timeout INT UNSIGNED NOT NULL DEFAULT '0',
	multiple SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	votes SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	public SMALLINT NOT NULL DEFAULT '0',
	lastvote INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['poll'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "poll");


$schema['CREATE']['query']['polloption'] = "
CREATE TABLE " . TABLE_PREFIX . "polloption (
	polloptionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	title TEXT,
	votes INT UNSIGNED NOT NULL DEFAULT '0',
	voters TEXT,
	PRIMARY KEY (polloptionid),
	KEY nodeid (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['polloption'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "polloption");


$schema['CREATE']['query']['pollvote'] = "
CREATE TABLE " . TABLE_PREFIX . "pollvote (
	pollvoteid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	pollid INT UNSIGNED NOT NULL DEFAULT '0',
	polloptionid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NULL DEFAULT NULL,
	votedate INT UNSIGNED NOT NULL DEFAULT '0',
	voteoption INT UNSIGNED DEFAULT '0',
	PRIMARY KEY (pollvoteid),
	UNIQUE KEY nodeid (nodeid, userid, polloptionid),
	KEY polloptionid (polloptionid),
	KEY pollid (pollid, voteoption),
	KEY userid (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['pollvote'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "pollvote");

// This table is required for relating vB4 threadid with postid, since we don't have this info in node table.
// In a fresh install this table will be empty. After upgraded, it will contain a record for each thread starter
$schema['CREATE']['query']['thread_post'] = "
CREATE TABLE " . TABLE_PREFIX . "thread_post (
	nodeid INT UNSIGNED NOT NULL,
	threadid INT UNSIGNED NOT NULL,
	postid INT UNSIGNED NOT NULL,
	PRIMARY KEY (nodeid),
	UNIQUE KEY thread_post (threadid, postid),
	KEY threadid (threadid),
	KEY postid (postid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['thread_post'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "thread_post");


$schema['CREATE']['query']['nodehash'] = "
CREATE TABLE " . TABLE_PREFIX . "nodehash (
	userid INT UNSIGNED NOT NULL,
	nodeid INT UNSIGNED NOT NULL,
	dupehash char(32) NOT NULL,
	dateline INT UNSIGNED NOT NULL,
	KEY (userid, dupehash),
	KEY (dateline)
) ENGINE = " . $innodb . "
";
$schema['CREATE']['explain']['nodehash'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "nodehash");


$schema['CREATE']['query']['postedithistory'] = "
CREATE TABLE " . TABLE_PREFIX . "postedithistory (
	postedithistoryid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	postid INT UNSIGNED NOT NULL DEFAULT '0',
	nodeid INT UNSIGNED NOT NULl DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	title VARCHAR(250) NOT NULL DEFAULT '',
	iconid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	reason VARCHAR(200) NOT NULL DEFAULT '',
	original SMALLINT NOT NULL DEFAULT '0',
	pagetext MEDIUMTEXT,
	PRIMARY KEY  (postedithistoryid),
	KEY postid (postid,userid),
	KEY nodeid (nodeid,userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['postedithistory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "postedithistory");

$schema['CREATE']['query']['prefix'] = "
CREATE TABLE " . TABLE_PREFIX . "prefix (
	prefixid VARCHAR(25) NOT NULL DEFAULT '',
	prefixsetid VARCHAR(25) NOT NULL DEFAULT '',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	options INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (prefixid),
	KEY prefixsetid (prefixsetid, displayorder)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['prefix'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "prefix");




$schema['CREATE']['query']['prefixpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "prefixpermission (
	prefixid VARCHAR(25) NOT NULL DEFAULT '',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	KEY prefixsetid (prefixid, usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['prefixpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "prefixpermission");



$schema['CREATE']['query']['prefixset'] = "
CREATE TABLE " . TABLE_PREFIX . "prefixset (
	prefixsetid VARCHAR(25) NOT NULL DEFAULT '',
	displayorder INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (prefixsetid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['prefixset'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "prefixset");


$schema['CREATE']['query']['privatemessage'] = "
CREATE TABLE " . TABLE_PREFIX . "privatemessage (
	nodeid INT UNSIGNED NOT NULL,
	msgtype ENUM('message','notification','request') NOT NULL default 'message',
	about ENUM(
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTE . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTEREPLY . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_RATE . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_REPLY . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOW . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOWING . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VM . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_COMMENT . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_THREADCOMMENT . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_SUBSCRIPTION . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MODERATE . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_USERMENTION . "',
		'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MONITOREDWORD . "',
		'" . vB_Api_Node::REQUEST_TAKE_OWNER . "',
		'" . vB_Api_Node::REQUEST_TAKE_MODERATOR . "',
		'" . vB_Api_Node::REQUEST_GRANT_OWNER . "',
		'" . vB_Api_Node::REQUEST_GRANT_MODERATOR . "',
		'" . vB_Api_Node::REQUEST_GRANT_MEMBER . "',
		'" . vB_Api_Node::REQUEST_TAKE_MEMBER . "',
		'" . vB_Api_Node::REQUEST_TAKE_SUBSCRIBER . "',
		'" . vB_Api_Node::REQUEST_GRANT_SUBSCRIBER . "',
		'" . vB_Api_Node::REQUEST_SG_TAKE_OWNER . "',
		'" . vB_Api_Node::REQUEST_SG_TAKE_MODERATOR . "',
		'" . vB_Api_Node::REQUEST_SG_GRANT_OWNER . "',
		'" . vB_Api_Node::REQUEST_SG_GRANT_MODERATOR . "',
		'" . vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER . "',
		'" . vB_Api_Node::REQUEST_SG_TAKE_SUBSCRIBER . "',
		'" . vB_Api_Node::REQUEST_SG_GRANT_MEMBER . "',
		'" . vB_Api_Node::REQUEST_SG_TAKE_MEMBER . "'),
	aboutid INT,
	deleted INT NOT NULL DEFAULT 0,
	PRIMARY KEY (nodeid),
	KEY (deleted)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['privatemessage'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "privatemessage");

$schema['CREATE']['query']['product'] = "
CREATE TABLE " . TABLE_PREFIX . "product (
	productid VARCHAR(25) NOT NULL DEFAULT '',
	title VARCHAR(250) NOT NULL DEFAULT '',
	description VARCHAR(250) NOT NULL DEFAULT '',
	version VARCHAR(25) NOT NULL DEFAULT '',
	active SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	url VARCHAR(250) NOT NULL DEFAULT '',
	versioncheckurl VARCHAR(250) NOT NULL DEFAULT '',
	PRIMARY KEY (productid),
	INDEX (active)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['product'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "product");



$schema['CREATE']['query']['productcode'] = "
CREATE TABLE " . TABLE_PREFIX . "productcode (
	productcodeid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	productid VARCHAR(25) NOT NULL DEFAULT '',
	version VARCHAR(25) NOT NULL DEFAULT '',
	installcode MEDIUMTEXT,
	uninstallcode MEDIUMTEXT,
	PRIMARY KEY (productcodeid),
	KEY (productid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['productcode'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "productcode");



$schema['CREATE']['query']['productdependency'] = "
CREATE TABLE " . TABLE_PREFIX . "productdependency (
	productdependencyid INT NOT NULL AUTO_INCREMENT,
	productid varchar(25) NOT NULL DEFAULT '',
	dependencytype varchar(25) NOT NULL DEFAULT '',
	parentproductid varchar(25) NOT NULL DEFAULT '',
	minversion varchar(50) NOT NULL DEFAULT '',
	maxversion varchar(50) NOT NULL DEFAULT '',
	PRIMARY KEY (productdependencyid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['productdependency'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "productdependency");

$schema['CREATE']['query']['profilefield'] = "
CREATE TABLE " . TABLE_PREFIX . "profilefield (
	profilefieldid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	profilefieldcategoryid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	required SMALLINT NOT NULL DEFAULT '0',
	hidden SMALLINT NOT NULL DEFAULT '0',
	maxlength SMALLINT NOT NULL DEFAULT '250',
	size SMALLINT NOT NULL DEFAULT '25',
	displayorder SMALLINT NOT NULL DEFAULT '0',
	editable SMALLINT NOT NULL DEFAULT '1',
	type ENUM('input','select','radio','textarea','checkbox','select_multiple') NOT NULL DEFAULT 'input',
	data MEDIUMTEXT,
	height SMALLINT NOT NULL DEFAULT '0',
	def SMALLINT NOT NULL DEFAULT '0',
	optional SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	searchable SMALLINT NOT NULL DEFAULT '0',
	memberlist SMALLINT NOT NULL DEFAULT '0',
	showonpost SMALLINT NOT NULL DEFAULT '0',
	regex VARCHAR(255) NOT NULL DEFAULT '',
	form SMALLINT NOT NULL DEFAULT '0',
	html SMALLINT NOT NULL DEFAULT '0',
	perline SMALLINT NOT NULL DEFAULT '0',
	PRIMARY KEY (profilefieldid),
	KEY editable (editable),
	KEY profilefieldcategoryid (profilefieldcategoryid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['profilefield'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "profilefield");



$schema['CREATE']['query']['profilefieldcategory'] = "
CREATE TABLE " . TABLE_PREFIX . "profilefieldcategory (
	profilefieldcategoryid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	displayorder SMALLINT NOT NULL DEFAULT '0',
	location VARCHAR(25) NOT NULL DEFAULT '',
	allowprivacy SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (profilefieldcategoryid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['profilefieldcategory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "profilefieldcategory");



$schema['CREATE']['query']['profilevisitor'] = "
CREATE TABLE " . TABLE_PREFIX . "profilevisitor (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	visitorid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	visible SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (visitorid, userid),
	KEY userid (userid, visible, dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['profilevisitor'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "profilevisitor");



$schema['CREATE']['query']['ranks'] = "
CREATE TABLE " . TABLE_PREFIX . "ranks (
	rankid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	minposts INT UNSIGNED NOT NULL DEFAULT '0',
	ranklevel SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	rankimg MEDIUMTEXT,
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	type SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	stack SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	display SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (rankid),
	KEY grouprank (usergroupid, minposts)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['ranks'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "ranks");


// We need this table because we may add more fields to video content type. For example, description.
$schema['CREATE']['query']['video'] = "
CREATE TABLE " . TABLE_PREFIX . "video (
	nodeid INT UNSIGNED NOT NULL,
	url VARCHAR(255),
	url_title VARCHAR(255),
	meta MEDIUMTEXT,
	thumbnail VARCHAR(255) NOT NULL DEFAULT '',
	thumbnail_date INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['video'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "video");


$schema['CREATE']['query']['videoitem'] = "
CREATE TABLE " . TABLE_PREFIX . "videoitem (
	videoitemid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nodeid INT UNSIGNED NOT NULL,
	provider VARCHAR(255),
	code VARCHAR(255),
	url VARCHAR(255),
	PRIMARY KEY (videoitemid),
	KEY nodeid (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['videoitem'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "videoitem");

$schema['CREATE']['query']['redirect'] = "
CREATE TABLE " . TABLE_PREFIX . "redirect (
	nodeid INT UNSIGNED NOT NULL,
	tonodeid INT UNSIGNED NOT NULL,
	PRIMARY KEY (nodeid),
	KEY tonodeid (tonodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['redirect'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "redirect");


$schema['CREATE']['query']['report'] = "
CREATE TABLE " . TABLE_PREFIX . "report (
	nodeid INT UNSIGNED NOT NULL,
	reportnodeid INT UNSIGNED NOT NULL DEFAULT '0',
	closed SMALLINT(5) UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid),
	KEY (reportnodeid, closed)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['report'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "report");



$schema['CREATE']['query']['reputation'] = "
CREATE TABLE " . TABLE_PREFIX . "reputation (
	reputationid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	nodeid INT UNSIGNED NOT NULL DEFAULT '1',
	userid INT UNSIGNED NOT NULL DEFAULT '1',
	reputation INT NOT NULL DEFAULT '0',
	whoadded INT UNSIGNED NOT NULL DEFAULT '0',
	reason VARCHAR(250) DEFAULT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (reputationid),
	KEY userid (userid),
	UNIQUE KEY whoadded_nodeid (whoadded, nodeid),
	KEY multi (nodeid, userid),
	KEY dateline (dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['reputation'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "reputation");



$schema['CREATE']['query']['reputationlevel'] = "
CREATE TABLE " . TABLE_PREFIX . "reputationlevel (
	reputationlevelid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	minimumreputation INT NOT NULL DEFAULT '0',
	PRIMARY KEY (reputationlevelid),
	KEY reputationlevel (minimumreputation)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['reputationlevel'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "reputationlevel");


$schema['CREATE']['query']['rssfeed'] = "
CREATE TABLE " . TABLE_PREFIX . "rssfeed (
	rssfeedid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(250) NOT NULL DEFAULT '',
	url TEXT,
	port SMALLINT UNSIGNED NOT NULL DEFAULT '80',
	ttl SMALLINT UNSIGNED NOT NULL DEFAULT '1500',
	maxresults SMALLINT NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	prefixid VARCHAR(25) NOT NULL DEFAULT '',
	iconid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	titletemplate MEDIUMTEXT,
	bodytemplate MEDIUMTEXT,
	searchwords MEDIUMTEXT,
	itemtype ENUM('topic','announcement') NOT NULL DEFAULT 'topic',
	topicactiondelay SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	endannouncement INT UNSIGNED NOT NULL DEFAULT '0',
	options INT UNSIGNED NOT NULL DEFAULT '0',
	lastrun INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (rssfeedid),
	KEY lastrun (lastrun)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['rssfeed'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "rssfeed");

$schema['CREATE']['query']['rsslog'] = "
CREATE TABLE " . TABLE_PREFIX . "rsslog (
	rssfeedid INT UNSIGNED NOT NULL DEFAULT '0',
	itemid INT UNSIGNED NOT NULL DEFAULT '0',
	itemtype ENUM('topic','announcement') NOT NULL DEFAULT 'topic',
	uniquehash CHAR(32) NOT NULL DEFAULT '',
	contenthash CHAR(32) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	topicactiontime INT UNSIGNED NOT NULL DEFAULT '0',
	topicactioncomplete TINYINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (rssfeedid, itemid, itemtype),
	UNIQUE KEY uniquehash (uniquehash)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['rsslog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "rsslog");


$schema['CREATE']['query']['searchlog'] = "
CREATE TABLE " . TABLE_PREFIX . "searchlog (
	searchlogid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	type SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	searchhash VARCHAR(32) NOT NULL,
	sortby VARCHAR(15) NOT NULL DEFAULT '',
	sortorder ENUM('asc','desc') NOT NULL DEFAULT 'asc',
	searchtime FLOAT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	completed SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	json TEXT NOT NULL,
	results MEDIUMBLOB,
	results_count INT NOT NULL,
	PRIMARY KEY (searchlogid),
	KEY search (userid, searchhash, sortby, sortorder),
	KEY userfloodcheck (userid, dateline),
	KEY ipfloodcheck (ipaddress, dateline),
	KEY dateline (dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['searchlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "searchlog");


for ($i=ord('a'); $i<=ord('z'); $i++)
{
	$schema['CREATE']['query']['searchtowords_'.chr($i)] = "
	CREATE TABLE IF NOT EXISTS " . TABLE_PREFIX . "searchtowords_".chr($i)." (
		wordid int(11) NOT NULL,
		nodeid int(11) NOT NULL,
		is_title TINYINT(1) NOT NULL DEFAULT '0',
		score INT NOT NULL DEFAULT '0',
		position INT NOT NULL DEFAULT '0',
		UNIQUE (wordid, nodeid),
		UNIQUE (nodeid, wordid)
		) ENGINE = $innodb
	";
	$schema['CREATE']['explain']['searchtowords_'.chr($i)] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "searchtowords_".chr($i));
}


$schema['CREATE']['query']['searchtowords_other'] = "
CREATE TABLE IF NOT EXISTS " . TABLE_PREFIX . "searchtowords_other (
	wordid int(11) NOT NULL,
	nodeid int(11) NOT NULL,
	is_title TINYINT(1) NOT NULL DEFAULT '0',
	score INT NOT NULL DEFAULT '0',
	position INT NOT NULL DEFAULT '0',
	UNIQUE (wordid, nodeid),
	UNIQUE (nodeid, wordid)
	) ENGINE = $innodb
";
$schema['CREATE']['explain']['searchtowords_other'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "searchtowords_other");


$schema['CREATE']['query']['sentto'] = "
CREATE TABLE " . TABLE_PREFIX . "sentto (
	nodeid INT NOT NULL,
	userid INT NOT NULL,
	folderid INT NOT NULL,
	deleted SMALLINT NOT NULL DEFAULT 0,
	msgread SMALLINT NOT NULL DEFAULT 0,
	PRIMARY KEY(nodeid, userid, folderid),
	KEY (nodeid),
	KEY user_read_deleted (userid, msgread, deleted),
	KEY (folderid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['sentto'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "sentto");

$schema['CREATE']['query']['session'] = "
CREATE TABLE " . TABLE_PREFIX . "session (
	sessionhash CHAR(32) NOT NULL DEFAULT '',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	host VARCHAR(45) NOT NULL DEFAULT '',
	idhash CHAR(32) NOT NULL DEFAULT '',
	lastactivity INT UNSIGNED NOT NULL DEFAULT '0',
	location CHAR(255) NOT NULL DEFAULT '',
	useragent CHAR(255) NOT NULL DEFAULT '',
	styleid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	languageid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	loggedin SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	inforum SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	inthread INT UNSIGNED NOT NULL DEFAULT '0',
	incalendar SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	badlocation SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	bypass TINYINT NOT NULL DEFAULT '0',
	profileupdate SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	apiclientid INT UNSIGNED NOT NULL DEFAULT '0',
	apiaccesstoken VARCHAR(32) NOT NULL DEFAULT '',
	wol CHAR(255) NOT NULL DEFAULT '',
	pagekey VARCHAR(255) NOT NULL DEFAULT '',
	emailstamp INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (sessionhash),
	KEY last_activity USING BTREE (lastactivity),
	KEY user_activity USING BTREE (userid, lastactivity),
	KEY guest_lookup (idhash, host, userid),
	KEY apiaccesstoken (apiaccesstoken),
	KEY pagekey (pagekey)
) ENGINE = $memory
";
$schema['CREATE']['explain']['session'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "session");



$schema['CREATE']['query']['setting'] = "
CREATE TABLE " . TABLE_PREFIX . "setting (
	varname VARCHAR(100) NOT NULL DEFAULT '',
	grouptitle VARCHAR(50) NOT NULL DEFAULT '',
	value MEDIUMTEXT,
	defaultvalue MEDIUMTEXT,
	optioncode MEDIUMTEXT,
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	advanced SMALLINT NOT NULL DEFAULT '0',
	volatile SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	datatype ENUM('free', 'number', 'boolean', 'bitfield', 'username', 'integer', 'posint') NOT NULL DEFAULT 'free',
	product VARCHAR(25) NOT NULL DEFAULT '',
	validationcode TEXT,
	blacklist SMALLINT NOT NULL DEFAULT '0',
	ispublic SMALLINT NOT NULL DEFAULT '0',
	adminperm varchar(32) NOT NULL DEFAULT '0',
	PRIMARY KEY (varname),
	KEY ispublic (ispublic)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['setting'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "setting");



$schema['CREATE']['query']['settinggroup'] = "
CREATE TABLE " . TABLE_PREFIX . "settinggroup (
	grouptitle CHAR(50) NOT NULL DEFAULT '',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	volatile SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	product VARCHAR(25) NOT NULL DEFAULT '',
	adminperm varchar(32) NOT NULL DEFAULT '0',
	PRIMARY KEY (grouptitle)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['settinggroup'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "settinggroup");



$schema['CREATE']['query']['sigparsed'] = "
CREATE TABLE " . TABLE_PREFIX . "sigparsed (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	styleid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	languageid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	signatureparsed MEDIUMTEXT,
	hasimages SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (userid, styleid, languageid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['sigparsed'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "sigparsed");



$schema['CREATE']['query']['smilie'] = "
CREATE TABLE " . TABLE_PREFIX . "smilie (
	smilieid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title CHAR(100) NOT NULL DEFAULT '',
	smilietext VARCHAR(100) NOT NULL DEFAULT '',
	smiliepath CHAR(100) NOT NULL DEFAULT '',
	imagecategoryid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (smilieid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['smilie'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "smilie");



$schema['CREATE']['query']['spamlog'] = "
CREATE TABLE " . TABLE_PREFIX . "spamlog (
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['spamlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "spamlog");


$schema['CREATE']['query']['stats'] = "
CREATE TABLE " . TABLE_PREFIX . "stats (
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	nuser mediumint UNSIGNED NOT NULL DEFAULT '0',
	nthread mediumint UNSIGNED NOT NULL DEFAULT '0',
	npost mediumint UNSIGNED NOT NULL DEFAULT '0',
	ausers mediumint UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (dateline)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['stats'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "stats");



$schema['CREATE']['query']['strikes'] = "
CREATE TABLE " . TABLE_PREFIX . "strikes (
	striketime INT UNSIGNED NOT NULL DEFAULT '0',
	strikeip VARCHAR(45) NOT NULL DEFAULT '',
	ip_4 INT UNSIGNED NOT NULL DEFAULT 0,
	ip_3 INT UNSIGNED NOT NULL DEFAULT 0,
	ip_2 INT UNSIGNED NOT NULL DEFAULT 0,
	ip_1 INT UNSIGNED NOT NULL DEFAULT 0,
	username VARCHAR(100) NOT NULL DEFAULT '',
	KEY striketime (striketime),
	KEY strikeip (strikeip),
	INDEX ip (ip_4, ip_3, ip_2, ip_1)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['strikes'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "strikes");



$schema['CREATE']['query']['style'] = "
CREATE TABLE " . TABLE_PREFIX . "style (
	styleid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title VARCHAR(250) NOT NULL DEFAULT '',
	parentid SMALLINT NOT NULL DEFAULT '0',
	parentlist VARCHAR(250) NOT NULL DEFAULT '',
	templatelist MEDIUMTEXT,
	newstylevars MEDIUMTEXT,
	replacements MEDIUMTEXT,
	editorstyles MEDIUMTEXT,
	userselect SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	guid char(150) NULL DEFAULT NULL UNIQUE,
	filedataid INT UNSIGNED NOT NULL DEFAULT '0',
	previewfiledataid INT UNSIGNED NOT NULL DEFAULT '0',
	styleattributes TINYINT NOT NULL DEFAULT '" . vB_Library_Style::ATTR_DEFAULT . "',
	PRIMARY KEY (styleid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['style'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "style");


$schema['CREATE']['query']['stylevar'] = "
CREATE TABLE " . TABLE_PREFIX . "stylevar (
	stylevarid varchar(191) NOT NULL,
	styleid SMALLINT NOT NULL DEFAULT '-1',
	value MEDIUMBLOB NOT NULL,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	UNIQUE KEY stylevarinstance (stylevarid, styleid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['stylevar'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "stylevar");


$schema['CREATE']['query']['userstylevar'] = "
CREATE TABLE " . TABLE_PREFIX . "userstylevar (
	stylevarid varchar(191) NOT NULL,
	userid INT(10) NOT NULL DEFAULT '-1',
	value MEDIUMBLOB NOT NULL,
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	UNIQUE KEY stylevarinstance (stylevarid, userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userstylevar'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userstylevar");


$schema['CREATE']['query']['stylevardfn'] = "
CREATE TABLE " . TABLE_PREFIX . "stylevardfn (
	stylevarid varchar(191) NOT NULL,
	styleid SMALLINT NOT NULL DEFAULT '-1',
	parentid SMALLINT NOT NULL,
	parentlist varchar(250) NOT NULL DEFAULT '0',
	stylevargroup varchar(250) NOT NULL,
	product varchar(25) NOT NULL default 'vbulletin',
	datatype varchar(25) NOT NULL default 'string',
	validation varchar(250) NOT NULL,
	failsafe MEDIUMBLOB NOT NULL,
	units enum('','%','px','pt','em','rem','ch','ex','pc','in','cm','mm','vw','vh','vmin','vmax') NOT NULL default '',
	uneditable tinyint(3) unsigned NOT NULL default '0',
	PRIMARY KEY (stylevarid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['stylevardfn'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "stylevardfn");




$schema['CREATE']['query']['subscribediscussion'] = "
CREATE TABLE " . TABLE_PREFIX . "subscribediscussion (
	subscribediscussionid INT unsigned NOT NULL auto_increment,
	userid INT unsigned NOT NULL,
	discussionid INT unsigned NOT NULL,
	emailupdate SMALLINT unsigned NOT NULL default '0',
	oldid INT(10) UNSIGNED,
	oldtypeid INT(10) UNSIGNED,
	PRIMARY KEY (subscribediscussionid),
	UNIQUE KEY userdiscussion (userid, discussionid, oldtypeid),
	KEY discussionid (discussionid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['subscribediscussion'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "subscribediscussion");



$schema['CREATE']['query']['subscribeevent'] = "
CREATE TABLE " . TABLE_PREFIX . "subscribeevent (
	subscribeeventid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	eventid INT UNSIGNED NOT NULL DEFAULT '0',
	lastreminder INT UNSIGNED NOT NULL DEFAULT '0',
	reminder INT UNSIGNED NOT NULL DEFAULT '3600',
	PRIMARY KEY (subscribeeventid),
	UNIQUE KEY subindex (userid, eventid),
	KEY eventid (eventid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['subscribeevent'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "subscribeevent");

$schema['CREATE']['query']['subscription'] = "
CREATE TABLE " . TABLE_PREFIX . "subscription (
	subscriptionid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	varname VARCHAR(100) NOT NULL DEFAULT '',
	cost MEDIUMTEXT,
	forums MEDIUMTEXT,
	nusergroupid SMALLINT NOT NULL DEFAULT '0',
	membergroupids VARCHAR(255) NOT NULL DEFAULT '',
	active SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	options INT UNSIGNED NOT NULL DEFAULT '0',
	displayorder SMALLINT UNSIGNED NOT NULL DEFAULT '1',
	adminoptions INT UNSIGNED NOT NULL DEFAULT '0',
	newoptions MEDIUMTEXT,
	PRIMARY KEY (subscriptionid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['subscription'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "subscription");



$schema['CREATE']['query']['subscriptionlog'] = "
CREATE TABLE " . TABLE_PREFIX . "subscriptionlog (
	subscriptionlogid MEDIUMINT UNSIGNED NOT NULL AUTO_INCREMENT,
	subscriptionid SMALLINT NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	pusergroupid SMALLINT NOT NULL DEFAULT '0',
	status SMALLINT NOT NULL DEFAULT '0',
	regdate INT UNSIGNED NOT NULL DEFAULT '0',
	expirydate INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (subscriptionlogid),
	KEY userid (userid, subscriptionid),
	KEY subscriptionid (subscriptionid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['subscriptionlog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "subscriptionlog");



$schema['CREATE']['query']['subscriptionpermission'] = "
CREATE TABLE " . TABLE_PREFIX . "subscriptionpermission (
	subscriptionpermissionid INT UNSIGNED NOT NULL auto_increment,
	subscriptionid INT UNSIGNED NOT NULL default '0',
	usergroupid INT UNSIGNED NOT NULL default '0',
	PRIMARY KEY  (subscriptionpermissionid),
	UNIQUE KEY subscriptionid (subscriptionid,usergroupid),
	KEY usergroupid (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['subscriptionpermission'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "subscriptionpermission");

$schema['CREATE']['query']['tag'] = "
CREATE TABLE " . TABLE_PREFIX . "tag (
	tagid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	tagtext VARCHAR(100) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	canonicaltagid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (tagid),
	UNIQUE KEY tagtext (tagtext),
	KEY canonicaltagid (canonicaltagid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['tag'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "tag");

$schema['CREATE']['query']['tagsearch'] = "
CREATE TABLE " . TABLE_PREFIX . "tagsearch (
	tagid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	KEY (tagid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['tagsearch'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "tagsearch");


$schema['CREATE']['query']['tagnode'] = "
CREATE TABLE " . TABLE_PREFIX . "tagnode (
	tagid INT UNSIGNED NOT NULL DEFAULT 0,
	nodeid INT UNSIGNED NOT NULL DEFAULT '0',
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY tag_type_cid (tagid, nodeid),
	KEY id_type_user (nodeid, userid),
	KEY id_type_node (nodeid),
	KEY id_type_tag (tagid),
	KEY user (userid),
	KEY dateline (dateline)
)
ENGINE = $innodb
";
$schema['CREATE']['explain']['tagnode'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "tagnode");


$schema['CREATE']['query']['template'] = "
CREATE TABLE " . TABLE_PREFIX . "template (
	templateid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	styleid SMALLINT NOT NULL DEFAULT '0',
	title VARCHAR(100) NOT NULL DEFAULT '',
	template MEDIUMTEXT,
	template_un MEDIUMTEXT,
	templatetype ENUM('template','stylevar','css','replacement') NOT NULL DEFAULT 'template',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	version VARCHAR(30) NOT NULL DEFAULT '',
	product VARCHAR(25) NOT NULL DEFAULT '',
	mergestatus ENUM('none', 'merged', 'conflicted') NOT NULL DEFAULT 'none',
	textonly SMALLINT NOT NULL default 0,
	PRIMARY KEY (templateid),
	UNIQUE KEY title (title, styleid, templatetype),
	KEY styleid (styleid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['template'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "template");



$schema['CREATE']['query']['templatehistory'] = "
CREATE TABLE " . TABLE_PREFIX . "templatehistory (
	templatehistoryid int(10) unsigned NOT NULL auto_increment,
	styleid smallint NOT NULL default '0',
	title varchar(100) NOT NULL default '',
	template MEDIUMTEXT,
	dateline int(10) unsigned NOT NULL default '0',
	username varchar(100) NOT NULL default '',
	version varchar(30) NOT NULL default '',
	comment varchar(255) NOT NULL default '',
	PRIMARY KEY (templatehistoryid),
	KEY title (title, styleid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['templatehistory'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "templatehistory");



$schema['CREATE']['query']['templatemerge'] = "
CREATE TABLE " . TABLE_PREFIX . "templatemerge (
	templateid INT UNSIGNED NOT NULL DEFAULT '0',
	template MEDIUMTEXT NOT NULL,
	version VARCHAR(30) NOT NULL DEFAULT '',
	savedtemplateid INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (templateid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['templatemerge'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "templatemerge");



$schema['CREATE']['query']['text'] = "
CREATE TABLE " . TABLE_PREFIX . "text (
	nodeid INT UNSIGNED NOT NULL PRIMARY KEY,
	previewtext VARCHAR(2048),
	previewimage VARCHAR(256),
	previewvideo TEXT,
	imageheight SMALLINT,
	imagewidth SMALLINT,
	rawtext MEDIUMTEXT,
	pagetextimages TEXT,
	moderated smallint,
	pagetext MEDIUMTEXT,
	htmlstate ENUM('off', 'on', 'on_nl2br') NOT NULL DEFAULT 'off',
	allowsmilie SMALLINT NOT NULL DEFAULT '0',
	showsignature SMALLINT NOT NULL DEFAULT '0',
	attach SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	infraction SMALLINT UNSIGNED NOT NULL DEFAULT '0'
 ) ENGINE = $innodb
";
$schema['CREATE']['explain']['text'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "text");


$schema['CREATE']['query']['trending'] = "
CREATE TABLE " . TABLE_PREFIX . "trending (
	nodeid INT UNSIGNED NOT NULL PRIMARY KEY,
	weight INT UNSIGNED NOT NULL,
	KEY weight (weight)
 ) ENGINE = $innodb
";
$schema['CREATE']['explain']['trending'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "trending");


$schema['CREATE']['query']['upgradelog'] = "
CREATE TABLE " . TABLE_PREFIX . "upgradelog (
	upgradelogid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	script VARCHAR(50) NOT NULL DEFAULT '',
	steptitle VARCHAR(250) NOT NULL DEFAULT '',
	step smallint(5) UNSIGNED NOT NULL DEFAULT '0',
	startat INT UNSIGNED NOT NULL DEFAULT '0',
	perpage SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	only TINYINT NOT NULL DEFAULT '0',
	PRIMARY KEY (upgradelogid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['upgradelog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "upgradelog");



$schema['CREATE']['query']['user'] = "
CREATE TABLE " . TABLE_PREFIX . "user (
	userid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	membergroupids CHAR(250) NOT NULL DEFAULT '',
	displaygroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	token VARCHAR(255) NOT NULL DEFAULT '',
	scheme VARCHAR(100) NOT NULL DEFAULT '',
	secret VARCHAR(100) NOT NULL DEFAULT '',
	passworddate date NOT NULL DEFAULT '0000-00-00',
	email CHAR(100) NOT NULL DEFAULT '',
	styleid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	parentemail CHAR(50) NOT NULL DEFAULT '',
	homepage CHAR(100) NOT NULL DEFAULT '',
	icq CHAR(20) NOT NULL DEFAULT '',
	aim CHAR(20) NOT NULL DEFAULT '',
	yahoo CHAR(32) NOT NULL DEFAULT '',
	msn CHAR(100) NOT NULL DEFAULT '',
	skype CHAR(32) NOT NULL DEFAULT '',
	google CHAR(32) NOT NULL DEFAULT '',
	status VARCHAR(1000) NOT NULL DEFAULT '',
	showvbcode SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	showbirthday SMALLINT UNSIGNED NOT NULL DEFAULT '2',
	usertitle CHAR(250) NOT NULL DEFAULT '',
	customtitle SMALLINT NOT NULL DEFAULT '0',
	joindate INT UNSIGNED NOT NULL DEFAULT '0',
	daysprune SMALLINT NOT NULL DEFAULT '0',
	lastvisit INT UNSIGNED NOT NULL DEFAULT '0',
	lastactivity INT UNSIGNED NOT NULL DEFAULT '0',
	lastpost INT UNSIGNED NOT NULL DEFAULT '0',
	lastpostid INT UNSIGNED NOT NULL DEFAULT '0',
	posts INT UNSIGNED NOT NULL DEFAULT '0',
	reputation INT NOT NULL DEFAULT '10',
	reputationlevelid INT UNSIGNED NOT NULL DEFAULT '1',
	timezoneoffset CHAR(4) NOT NULL DEFAULT '',
	pmpopup SMALLINT NOT NULL DEFAULT '0',
	avatarid SMALLINT NOT NULL DEFAULT '0',
	avatarrevision INT UNSIGNED NOT NULL DEFAULT '0',
	sigpicrevision INT UNSIGNED NOT NULL DEFAULT '0',
	options INT UNSIGNED NOT NULL DEFAULT '167788559',
	privacy_options MEDIUMTEXT NULL,
	notification_options INT UNSIGNED NOT NULL DEFAULT '1073741818',
	birthday CHAR(10) NOT NULL DEFAULT '',
	birthday_search DATE NOT NULL DEFAULT '0000-00-00',
	maxposts SMALLINT NOT NULL DEFAULT '-1',
	startofweek SMALLINT NOT NULL DEFAULT '1',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	referrerid INT UNSIGNED NOT NULL DEFAULT '0',
	languageid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	emailstamp INT UNSIGNED NOT NULL DEFAULT '0',
	threadedmode SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	autosubscribe SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	emailnotification SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	pmtotal SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	pmunread SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	ipoints INT UNSIGNED NOT NULL DEFAULT '0',
	infractions INT UNSIGNED NOT NULL DEFAULT '0',
	warnings INT UNSIGNED NOT NULL DEFAULT '0',
	infractiongroupids VARCHAR (255) NOT NULL DEFAULT '',
	infractiongroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	adminoptions INT UNSIGNED NOT NULL DEFAULT '0',
	profilevisits INT UNSIGNED NOT NULL DEFAULT '0',
	friendcount INT UNSIGNED NOT NULL DEFAULT '0',
	friendreqcount INT UNSIGNED NOT NULL DEFAULT '0',
	vmunreadcount INT UNSIGNED NOT NULL DEFAULT '0',
	vmmoderatedcount INT UNSIGNED NOT NULL DEFAULT '0',
	socgroupinvitecount INT UNSIGNED NOT NULL DEFAULT '0',
	socgroupreqcount INT UNSIGNED NOT NULL DEFAULT '0',
	pcunreadcount INT UNSIGNED NOT NULL DEFAULT '0',
	pcmoderatedcount INT UNSIGNED NOT NULL DEFAULT '0',
	gmmoderatedcount INT UNSIGNED NOT NULL DEFAULT '0',
	assetposthash VARCHAR(32) NOT NULL DEFAULT '',
	fbuserid VARCHAR(255) NOT NULL DEFAULT '',
	fbjoindate INT UNSIGNED NOT NULL DEFAULT '0',
	fbname VARCHAR(255) NOT NULL DEFAULT '',
	`privacyconsent` TINYINT SIGNED NOT NULL DEFAULT '0',
	`privacyconsentupdated` INT UNSIGNED NOT NULL DEFAULT '0',
	`eustatus` TINYINT NOT NULL DEFAULT 0,
	editorstate INT UNSIGNED NOT NULL DEFAULT '1',
	PRIMARY KEY (userid),
	KEY usergroupid (usergroupid),
	KEY username (username),
	KEY email (email),
	KEY birthday (birthday, showbirthday),
	KEY birthday_search (birthday_search),
	KEY referrerid (referrerid),
	KEY (fbuserid),
	KEY joindate (joindate),
	KEY `privacy_updated` (`privacyconsent`, `privacyconsentupdated`)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['user'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "user");



$schema['CREATE']['query']['useractivation'] = "
CREATE TABLE " . TABLE_PREFIX . "useractivation (
	useractivationid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	activationid VARCHAR(40) NOT NULL DEFAULT '',
	type SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	emailchange SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	reset_attempts INT UNSIGNED NOT NULL DEFAULT '0',
	reset_locked_since INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (useractivationid),
	UNIQUE KEY userid (userid, type)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['useractivation'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "useractivation");


$schema['CREATE']['query']['userban'] = "
CREATE TABLE " . TABLE_PREFIX . "userban (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	displaygroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	usertitle VARCHAR(250) NOT NULL DEFAULT '',
	customtitle SMALLINT NOT NULL DEFAULT '0',
	adminid INT UNSIGNED NOT NULL DEFAULT '0',
	bandate INT UNSIGNED NOT NULL DEFAULT '0',
	liftdate INT UNSIGNED NOT NULL DEFAULT '0',
	reason VARCHAR(250) NOT NULL DEFAULT '',
	PRIMARY KEY (userid),
	KEY liftdate (liftdate)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userban'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userban");

$schema['CREATE']['query']['userchangelog'] = "
CREATE TABLE " . TABLE_PREFIX . "userchangelog (
	changeid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	fieldname VARCHAR(250) NOT NULL DEFAULT '',
	newvalue VARCHAR(250) NOT NULL DEFAULT '',
	oldvalue VARCHAR(250) NOT NULL DEFAULT '',
	adminid INT UNSIGNED NOT NULL DEFAULT '0',
	change_time INT UNSIGNED NOT NULL DEFAULT '0',
	change_uniq VARCHAR(32) NOT NULL DEFAULT '',
	ipaddress VARCHAR(45) NOT NULL DEFAULT '',
	PRIMARY KEY  (changeid),
	KEY userid (userid,change_time),
	KEY change_time (change_time),
	KEY change_uniq (change_uniq),
	KEY fieldname (fieldname,change_time),
	KEY adminid (adminid,change_time)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userchangelog'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userchangelog");



$schema['CREATE']['query']['userfield'] = "
CREATE TABLE " . TABLE_PREFIX . "userfield (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	temp MEDIUMTEXT,
	field1 MEDIUMTEXT,
	field2 MEDIUMTEXT,
	field3 MEDIUMTEXT,
	field4 MEDIUMTEXT,
	PRIMARY KEY (userid)
) ENGINE = $myisam
";
$schema['CREATE']['explain']['userfield'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userfield");



$schema['CREATE']['query']['usergroup'] = "
CREATE TABLE " . TABLE_PREFIX . "usergroup (
	usergroupid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	title CHAR(100) NOT NULL DEFAULT '',
	description VARCHAR(250) NOT NULL DEFAULT '',
	usertitle CHAR(100) NOT NULL DEFAULT '',
	passwordexpires SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	passwordhistory SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	pmquota SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	pmsendmax SMALLINT UNSIGNED NOT NULL DEFAULT '5',
	opentag CHAR(100) NOT NULL DEFAULT '',
	closetag CHAR(100) NOT NULL DEFAULT '',
	canoverride SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	ispublicgroup SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	forumpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	forumpermissions2 INT UNSIGNED NOT NULL DEFAULT 0,
	pmpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	calendarpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	wolpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	adminpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	genericpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	genericpermissions2 INT UNSIGNED NOT NULL DEFAULT '0',
	genericoptions INT UNSIGNED NOT NULL DEFAULT '0',
	signaturepermissions INT UNSIGNED NOT NULL DEFAULT '0',
	visitormessagepermissions INT UNSIGNED NOT NULL DEFAULT '0',
	attachlimit INT UNSIGNED NOT NULL DEFAULT '0',
	avatarmaxwidth SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	avatarmaxheight SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	avatarmaxsize INT UNSIGNED NOT NULL DEFAULT '0',
	sigpicmaxwidth SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigpicmaxheight SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigpicmaxsize INT UNSIGNED NOT NULL DEFAULT '0',
	sigmaximages SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigmaxsizebbcode SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigmaxchars SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigmaxrawchars SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	sigmaxlines SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	usercsspermissions INT UNSIGNED NOT NULL DEFAULT '0',
	albumpermissions INT UNSIGNED NOT NULL DEFAULT '0',
	albumpicmaxwidth SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	albumpicmaxheight SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	albummaxpics INT UNSIGNED NOT NULL DEFAULT '0',
	albummaxsize INT UNSIGNED NOT NULL DEFAULT '0',
	socialgrouppermissions INT UNSIGNED NOT NULL DEFAULT '0',
	pmthrottlequantity INT UNSIGNED NOT NULL DEFAULT '0',
	groupiconmaxsize INT UNSIGNED NOT NULL DEFAULT '0',
	maximumsocialgroups INT UNSIGNED NOT NULL DEFAULT '0',
	systemgroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usergroup'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usergroup");



$schema['CREATE']['query']['usergroupleader'] = "
CREATE TABLE " . TABLE_PREFIX . "usergroupleader (
	usergroupleaderid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (usergroupleaderid),
	KEY ugl (userid, usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usergroupleader'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usergroupleader");



$schema['CREATE']['query']['usergrouprequest'] = "
CREATE TABLE " . TABLE_PREFIX . "usergrouprequest (
	usergrouprequestid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	usergroupid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
	reason VARCHAR(250) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	PRIMARY KEY (usergrouprequestid),
	KEY usergroupid (usergroupid),
	UNIQUE KEY (userid, usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usergrouprequest'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usergrouprequest");



$schema['CREATE']['query']['userlist'] = "
CREATE TABLE " . TABLE_PREFIX . "userlist (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	relationid INT UNSIGNED NOT NULL DEFAULT '0',
	type ENUM('buddy', 'ignore', 'follow') NOT NULL DEFAULT 'buddy',
	friend ENUM('yes', 'no', 'pending', 'denied') NOT NULL DEFAULT 'no',
	PRIMARY KEY (userid, relationid, type),
	KEY relationid (relationid, type, friend),
	KEY userid (userid, type, friend)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userlist'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userlist");

$schema['CREATE']['query']['userloginmfa'] = "
CREATE TABLE " . TABLE_PREFIX . "userloginmfa (
	userid INT UNSIGNED NOT NULL,
	enabled TINYINT NOT NULL,
	secret VARCHAR(255) NOT NULL,
	dateline INT NOT NULL,
	PRIMARY KEY (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userloginmfa'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userloginmfa");




$schema['CREATE']['query']['usernote'] = "
CREATE TABLE " . TABLE_PREFIX . "usernote (
	usernoteid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	posterid INT UNSIGNED NOT NULL DEFAULT '0',
	username VARCHAR(100) NOT NULL DEFAULT '',
	dateline INT UNSIGNED NOT NULL DEFAULT '0',
	message MEDIUMTEXT,
	title VARCHAR(255) NOT NULL DEFAULT '',
	allowsmilies SMALLINT NOT NULL DEFAULT '0',
	PRIMARY KEY (usernoteid),
	KEY userid (userid),
	KEY posterid (posterid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usernote'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usernote");



$schema['CREATE']['query']['userpromotion'] = "
CREATE TABLE " . TABLE_PREFIX . "userpromotion (
	userpromotionid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	usergroupid INT UNSIGNED NOT NULL DEFAULT '0',
	joinusergroupid INT UNSIGNED NOT NULL DEFAULT '0',
	reputation INT NOT NULL DEFAULT '0',
	date INT UNSIGNED NOT NULL DEFAULT '0',
	posts INT UNSIGNED NOT NULL DEFAULT '0',
	strategy SMALLINT NOT NULL DEFAULT '0',
	type SMALLINT NOT NULL DEFAULT '2',
	PRIMARY KEY (userpromotionid),
	KEY usergroupid (usergroupid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userpromotion'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userpromotion");



$schema['CREATE']['query']['usertextfield'] = "
CREATE TABLE " . TABLE_PREFIX . "usertextfield (
	userid INT UNSIGNED NOT NULL DEFAULT '0',
	subfolders MEDIUMTEXT,
	pmfolders MEDIUMTEXT,
	buddylist MEDIUMTEXT,
	ignorelist MEDIUMTEXT,
	signature MEDIUMTEXT,
	searchprefs MEDIUMTEXT,
	`rank` MEDIUMTEXT,
	PRIMARY KEY (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usertextfield'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usertextfield");



$schema['CREATE']['query']['usertitle'] = "
CREATE TABLE " . TABLE_PREFIX . "usertitle (
	usertitleid SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
	minposts INT UNSIGNED NOT NULL DEFAULT '0',
	title CHAR(250) NOT NULL DEFAULT '',
	PRIMARY KEY (usertitleid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['usertitle'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "usertitle");


$schema['CREATE']['query']['sigpic'] = "
CREATE TABLE " . TABLE_PREFIX . "sigpic (
	userid int(10) unsigned NOT NULL default '0',
	filedata mediumblob,
	dateline int(10) unsigned NOT NULL default '0',
	filename varchar(100) NOT NULL default '',
	visible smallint(6) NOT NULL default '1',
	filesize int(10) unsigned NOT NULL default '0',
	width smallint(5) unsigned NOT NULL default '0',
	height smallint(5) unsigned NOT NULL default '0',
	PRIMARY KEY  (userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['sigpic'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "sigpic");


$schema['CREATE']['query']['sigpicnew'] = "
CREATE TABLE " . TABLE_PREFIX . "sigpicnew (
	userid int(10) unsigned NOT NULL default '0',
	filedataid int(10) unsigned NOT NULL default '0',
	PRIMARY KEY  (userid),
	KEY filedataid (filedataid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['sigpicnew'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "sigpicnew");

// BEGIN: vB5 tables *******************************************************************************



$schema['CREATE']['query']['page'] = "
CREATE TABLE " . TABLE_PREFIX . "page (
  pageid int(10) unsigned NOT NULL AUTO_INCREMENT,
  parentid int(10) unsigned NOT NULL,
  pagetemplateid int(10) unsigned NOT NULL,
  title varchar(200) NOT NULL,
  metadescription varchar(200) NOT NULL,
  routeid int(10) unsigned NOT NULL,
  moderatorid int(10) unsigned NOT NULL,
  displayorder int(11) NOT NULL,
  pagetype enum('default','custom') NOT NULL DEFAULT 'custom',
  product varchar(25) NOT NULL DEFAULT 'vbulletin',
  guid char(150) DEFAULT NULL,
  PRIMARY KEY (pageid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['page'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "page");


$schema['CREATE']['query']['pagetemplate'] = "
CREATE TABLE " . TABLE_PREFIX . "pagetemplate (
  pagetemplateid int(10) unsigned NOT NULL AUTO_INCREMENT,
  title varchar(200) NOT NULL,
  screenlayoutid int(10) unsigned NOT NULL,
  screenlayoutsectiondata TEXT NOT NULL DEFAULT '',
  content text NOT NULL,
  product varchar(25) NOT NULL DEFAULT 'vbulletin',
  guid char(150) DEFAULT NULL,
  PRIMARY KEY (pagetemplateid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['pagetemplate'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "pagetemplate");


$schema['CREATE']['query']['routenew'] = "
CREATE TABLE " . TABLE_PREFIX . "routenew (
	routeid int(10) unsigned NOT NULL AUTO_INCREMENT,
	name varchar(100) DEFAULT NULL,
	redirect301 int(10) unsigned DEFAULT NULL,
	prefix varchar(" . vB5_Route::PREFIX_MAXSIZE . ") NOT NULL,
	regex varchar(" . vB5_Route::REGEX_MAXSIZE . ") NOT NULL,
	class varchar(100) DEFAULT NULL,
	controller varchar(100) NOT NULL,
	action varchar(100) NOT NULL,
	template varchar(100) NOT NULL,
	arguments mediumtext NOT NULL,
	contentid int(10) unsigned NOT NULL,
	product varchar(25) NOT NULL DEFAULT 'vbulletin',
	guid char(150) DEFAULT NULL,
	ishomeroute tinyint,
	PRIMARY KEY (routeid),
	KEY regex (regex),
	KEY prefix (prefix),
	KEY route_name (name),
	KEY route_class_cid (class, contentid),
	KEY ishomeroute(ishomeroute)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['routenew'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "routenew");


$schema['CREATE']['query']['screenlayout'] = "
CREATE TABLE " . TABLE_PREFIX . "screenlayout (
	screenlayoutid INT UNSIGNED NOT NULL AUTO_INCREMENT,
	varname VARCHAR(20) NOT NULL,
	title VARCHAR(200) NOT NULL,
	displayorder SMALLINT UNSIGNED NOT NULL,
	columncount TINYINT UNSIGNED NOT NULL,
	sectiondata TEXT NOT NULL DEFAULT '',
	template VARCHAR(200) NOT NULL,
	admintemplate VARCHAR(200) NOT NULL,
	guid CHAR(150) NULL DEFAULT NULL,
	PRIMARY KEY (screenlayoutid),
	UNIQUE KEY (varname),
	UNIQUE KEY (guid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['screenlayout'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "screenlayout");

$schema['CREATE']['query']['site'] = "
CREATE TABLE " . TABLE_PREFIX . "site (
	siteid INT NOT NULL AUTO_INCREMENT,
	title VARCHAR(100) NOT NULL,
	headernavbar MEDIUMTEXT NULL,
	footernavbar MEDIUMTEXT NULL,
	PRIMARY KEY (siteid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['site'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "site");

/*
	Note, the "parentid" column for UPGRADES can be added at 517a4 step_15() for certain vB5 -> vB5 upgrades,
	or by vB_Xml_Import_Widget::checkWidgetParentidAndAlterTable() for other vB5 -> vB5 upgrades and (more commonly)
	vB3/vB4 -> vB5 upgrades during any of the widget XML import steps. See VBV-16969
	IMPORTANT: If you change the parentid column, update 517a4 step_15() & vBInstall:addWidgetParentid query (used by
	checkWidgetParentidAndAlterTable()) as well.
 */
$schema['CREATE']['query']['widget'] = "
CREATE TABLE " . TABLE_PREFIX . "widget (
  widgetid int(10) unsigned NOT NULL AUTO_INCREMENT,
  parentid INT UNSIGNED NOT NULL DEFAULT '0',
  template varchar(200) NOT NULL,
  admintemplate varchar(200) NOT NULL,
  titlephrase VARCHAR(255) NOT NULL DEFAULT '',
  icon varchar(200) NOT NULL,
  isthirdparty tinyint(3) unsigned NOT NULL,
  category varchar(100) NOT NULL DEFAULT 'uncategorized',
  cloneable tinyint(3) unsigned NOT NULL DEFAULT '1',
  canbemultiple tinyint(3) unsigned NOT NULL DEFAULT '1',
  product VARCHAR(25) NOT NULL DEFAULT 'vbulletin',
  guid char(150) NULL DEFAULT NULL UNIQUE,
  PRIMARY KEY (widgetid),
  KEY product (product)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['widget'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "widget");


$schema['CREATE']['query']['widgetdefinition'] = "
CREATE TABLE " . TABLE_PREFIX . "widgetdefinition (
  widgetid int(10) unsigned NOT NULL,
  name varchar(50) NOT NULL,
  field varchar(50) NOT NULL,
  labelphrase VARCHAR(250) NOT NULL DEFAULT '',
  descriptionphrase VARCHAR(250) NOT NULL DEFAULT '',
  defaultvalue blob NOT NULL,
  isusereditable tinyint(4) NOT NULL DEFAULT '1',
  ishiddeninput tinyint(4) NOT NULL DEFAULT '0',
  isrequired tinyint(4) NOT NULL DEFAULT '0',
  displayorder smallint(6) NOT NULL,
  validationtype enum('force_datatype','regex','method') NOT NULL,
  validationmethod varchar(200) NOT NULL,
  product VARCHAR(25) NOT NULL DEFAULT 'vbulletin',
  data text NOT NULL,
  KEY (widgetid),
  KEY product (product)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['widgetdefinition'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "widgetdefinition");


$schema['CREATE']['query']['widgetinstance'] = "
CREATE TABLE " . TABLE_PREFIX . "widgetinstance (
  widgetinstanceid int(10) unsigned NOT NULL AUTO_INCREMENT,
  containerinstanceid int(10) unsigned NOT NULL DEFAULT '0',
  pagetemplateid int(10) unsigned NOT NULL,
  widgetid int(10) unsigned NOT NULL,
  displaysection tinyint(3) unsigned NOT NULL,
  displayorder smallint(5) unsigned NOT NULL,
  adminconfig mediumtext CHARACTER SET utf8mb4 NOT NULL,
  PRIMARY KEY (widgetinstanceid),
  KEY pagetemplateid (pagetemplateid,widgetid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['widgetinstance'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "widgetinstance");

$schema['CREATE']['query']['widgetchannelconfig'] = "
CREATE TABLE " . TABLE_PREFIX . "widgetchannelconfig (
  widgetinstanceid int(10) unsigned NOT NULL,
  nodeid int(10) unsigned NOT NULL,
  channelconfig blob NOT NULL,
  UNIQUE KEY widgetinstanceid (widgetinstanceid,nodeid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['widgetchannelconfig'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "widgetchannelconfig");

$schema['CREATE']['query']['widgetuserconfig'] = "
CREATE TABLE " . TABLE_PREFIX . "widgetuserconfig (
  widgetinstanceid int(10) unsigned NOT NULL,
  userid int(10) unsigned NOT NULL,
  userconfig blob NOT NULL,
  UNIQUE KEY widgetinstanceid (widgetinstanceid,userid)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['widgetuserconfig'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "widgetuserconfig");


$schema['CREATE']['query']['words'] = "
CREATE TABLE IF NOT EXISTS " . TABLE_PREFIX . "words (
	wordid int(11) NOT NULL AUTO_INCREMENT,
	word varchar(50) NOT NULL,
	PRIMARY KEY (wordid),
	UNIQUE KEY word (word)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['words'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "words");


// BEGIN: externallogin tables

/*
* user_platform_constraint unique key / constraint means that
a given user is NOT allowed to have multiple 3rd party accounts
associated with it PER LIBRARY (no control if they have 2 twitter
libraries to allow for 2 accounts, for e.g.)
*- If we want to allow for multiple 3rd party accounts, we could
add `external_userid` to the index.
* token should be an access token (unique to user).
* For storing data in the state when user does not have an access
* token-pair & external_userid yet (e.g. have not made a connection
* yet, or creating one during registration of a new user), use
* `sessionauth` table instead.
 */
$schema['CREATE']['query']['userauth'] = "
CREATE TABLE `" . TABLE_PREFIX . "userauth` (
	`userid`               INT UNSIGNED NOT NULL DEFAULT '0',
	`loginlibraryid`       INT UNSIGNED NOT NULL DEFAULT '0',
	`external_userid`      VARCHAR(191) NOT NULL DEFAULT '',
	`token`                VARCHAR(191) NOT NULL DEFAULT '',
	`token_secret`         VARCHAR(191) NOT NULL DEFAULT '',
	`additional_params`    VARCHAR(2048) NOT NULL DEFAULT '',

	PRIMARY KEY `user_platform_constraint`  (`userid`, `loginlibraryid`),
	UNIQUE KEY `platform_extuser_constraint`  (`loginlibraryid`, `external_userid`),
	KEY         `token_lookup`              (`userid`, `loginlibraryid`, `token`)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['userauth'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "userauth");


$schema['CREATE']['query']['loginlibrary'] = "
CREATE TABLE `" . TABLE_PREFIX . "loginlibrary` (
	`loginlibraryid`       INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	`productid`            VARCHAR(25) NOT NULL,
	`class`                VARCHAR(64) NOT NULL,

	UNIQUE KEY (`productid`)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['loginlibrary'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "loginlibrary");


/*
* Very similar to `userauth` table, but strictly to allow storing information prior to
* making a connection/authentication that provides the external_userid & access token+secret
* Also used for storing request toke+secret when a guest is trying to log-in or register.
 */
$schema['CREATE']['query']['sessionauth'] = "
CREATE TABLE `" . TABLE_PREFIX . "sessionauth` (
	`sessionhash`          CHAR(32) NOT NULL DEFAULT '',
	`loginlibraryid`       INT UNSIGNED NOT NULL DEFAULT '0',
	`token`                VARCHAR(191) NOT NULL DEFAULT '',
	`token_secret`         VARCHAR(191) NOT NULL DEFAULT '',
	`additional_params`    VARCHAR(2048) NOT NULL DEFAULT '',
	`expires`              INT UNSIGNED NOT NULL,

	PRIMARY KEY `session_platform_constraint`  (`sessionhash`, `loginlibraryid`),
	INDEX (`expires`)
) ENGINE = $innodb
";
$schema['CREATE']['explain']['sessionauth'] = sprintf($vbphrase['create_table'], TABLE_PREFIX . "sessionauth");

// END: externallogin tables




// END: vB5 tables *******************************************************************************
// BEGIN: vB5 default data *******************************************************************************



$navbars = get_default_navbars();
$headernavbar = serialize($navbars['header']);
$footernavbar = serialize($navbars['footer']);

$schema['INSERT']['query']['site'] = "
INSERT INTO " . TABLE_PREFIX . "site
(title, headernavbar, footernavbar)
VALUES
('Default Site','$headernavbar','$footernavbar');
";
$schema['INSERT']['explain']['site'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "site");



$schema['INSERT']['query']['adminutil'] = "
REPLACE INTO " . TABLE_PREFIX . "adminutil
	(title, text)
VALUES
	('datastorelock', '0')";
$schema['INSERT']['explain']['adminutil'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "adminutil");


$schema['INSERT']['query']['attachmenttype'] = getAttachmenttypeInsertQuery($db);
$schema['INSERT']['explain']['attachmenttype'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "attachmenttype");

$schema['INSERT']['query']['attachmentcache'] = "
INSERT INTO " . TABLE_PREFIX . "datastore
	(title, data, unserialize)
VALUES
	('attachmentcache', '" . $db->escape_string(serialize(array())) . "', 1)
";
$schema['INSERT']['explain']['attachmentcache'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "datastore");

$schema['INSERT']['query']['calendar'] = "
INSERT INTO " . TABLE_PREFIX . "calendar
	(title, description, displayorder, neweventemail, moderatenew, startofweek, options, cutoff, eventcount, birthdaycount, startyear, endyear)
VALUES
	('" . $db->escape_string($install_phrases['default_calendar']) . "', '', 1, '" . serialize(array()) . "', 0, 1, 631, 40, 4, 4, " . (date('Y') - 3) . ", " . (date('Y') + 3) . ")
";
$schema['INSERT']['explain']['calendar'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "calendar");

// TODO: remove vb4 contenttypes? (LegacyEvent, Calendar)
$schema['INSERT']['query']['contenttype'] = "
	INSERT INTO " . TABLE_PREFIX . "contenttype
		(contenttypeid, class, packageid, canplace, cansearch, cantag, canattach)
	VALUES
		(1, 'Post', 1, '0', '0', '0', '1'),
		(2, 'Thread', 1, '0', '0', '1', '0'),
		(3, 'Forum', 1, '0', '0', '0', '0'),
		(4, 'Announcement', 1, '0', '0', '0', '0'),
		(5, 'SocialGroupMessage', 1, '0', '0', '0', '0'),
		(6, 'SocialGroupDiscussion', 1, '0', '0', '0', '0'),
		(7, 'SocialGroup', 1, '0', '0', '0', '1'),
		(8, 'Album', 1, '0', '0', '0', '1'),
		(9, 'Picture', 1, '0', '0', '0', '0'),
		(10, 'PictureComment', 1, '0', '0', '0', '0'),
		(11, 'VisitorMessage', 1, '0', '0', '0', '0'),
		(12, 'User', 1, '0', '0', '0', '0'),
		(13, 'LegacyEvent', 1, '0', '0', '0', '0'),
		(14, 'Calendar', 1, '0', '0', '0', '0'),
		(15, 'Attach',  1, '0', '0', '1', '1'),
		(16, 'Photo', 1, '0', '1', '1', '1'),
		(19, 'BlogEntry', 2, '0', '0', '0', '1'),
		(20, 'BlogComment', 2, '0', '0', '0', '1'),
		(21, 'Article', 3, '0', '0', '1', '1'),
		(22, 'Text',     1, '1', '1', '1', '1'),
		(23, 'Channel', 1, '1','0', '0', '0'),
		(24, 'Poll', 1, '1','1', '0', '0'),
		(25, 'Gallery', 1, '1', '1', '1', '1'),
		(26, 'Video', 1, '1', '1', '1', '1'),
		(27, 'PrivateMessage', 1, '0', '1', '0', '0'),
		(28, 'Link', 1, '1', '1', '1', '1'),
		(29, 'Report', 1, '0', '0', '0', '0'),
		(30, 'Redirect', 1, '0', '0', '0', '0'),
		(31, 'Infraction', 1, '0', '0', '0', '0'),
		(32, 'Event', 1, '1','1', '1', '1')
";
$schema['INSERT']['explain']['contenttype'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "contenttype");



$schema['INSERT']['query']['cron'] = "
INSERT INTO " . TABLE_PREFIX . "cron
	(nextrun, weekday, day, hour, minute, filename, loglevel, varname, volatile, product)
VALUES
	(1053271660, -1, -1,  0, 'a:1:{i:0;i:1;}',           './includes/cron/birthday.php',        1, 'birthday',        1, 'vbulletin'),
	(1053531900, -1, -1, -1, 'a:1:{i:0;i:25;}',          './includes/cron/promotion.php',       1, 'promotion',       1, 'vbulletin'),
	(1053271720, -1, -1,  0, 'a:1:{i:0;i:2;}',           './includes/cron/digestdaily.php',     1, 'digestdaily',     1, 'vbulletin'),
	(1053991800,  1, -1,  0, 'a:1:{i:0;i:30;}',          './includes/cron/digestweekly.php',    1, 'digestweekly',    1, 'vbulletin'),
	(1053271820, -1, -1,  0, 'a:1:{i:0;i:2;}',           './includes/cron/subscriptions.php',   1, 'subscriptions',   1, 'vbulletin'),
	(1053533100, -1, -1, -1, 'a:1:{i:0;i:5;}',           './includes/cron/cleanup.php',         0, 'cleanup',         1, 'vbulletin'),
	(1053990180, -1, -1,  0, 'a:1:{i:0;i:3;}',           './includes/cron/activate.php',        1, 'activate',        1, 'vbulletin'),
	(1053271600, -1, -1, -1, 'a:1:{i:0;i:15;}',          './includes/cron/removebans.php',      1, 'removebans',      1, 'vbulletin'),
	(1053531600, -1, -1, -1, 'a:1:{i:0;i:20;}',          './includes/cron/cleanup2.php',        0, 'cleanup2',        1, 'vbulletin'),
	(1053271600, -1, -1,  0, 'a:1:{i:0;i:0;}',           './includes/cron/stats.php',           0, 'stats',           1, 'vbulletin'),
	(1053533100, -1, -1,  0, 'a:1:{i:0;i:10;}',          './includes/cron/dailycleanup.php',    0, 'dailycleanup',    1, 'vbulletin'),
	(1053271600, -1, -1, -1, 'a:2:{i:0;i:20;i:1;i:50;}', './includes/cron/infractions.php',     1, 'infractions',     1, 'vbulletin'),
	(1053271600, -1, -1, -1, 'a:1:{i:0;i:10;}',          './includes/cron/ccbill.php',          1, 'ccbill',          1, 'vbulletin'),
	(1053271600, -1, -1, -1, 'a:6:{i:0;i:0;i:1;i:10;i:2;i:20;i:3;i:30;i:4;i:40;i:5;i:50;}', './includes/cron/rssposter.php', 1, 'rssposter',1, 'vbulletin'),
	(1232082000, -1, -1,  5, 'a:1:{i:0;i:0;}',           './includes/cron/sitemap.php',         1, 'sitemap',         1, 'vbulletin'),
	(1232082000, -1, -1,  5, 'a:6:{i:0;i:0;i:1;i:10;i:2;i:20;i:3;i:30;i:4;i:40;i:5;i:50;}',           './includes/cron/privatemessage_cleanup.php',         1, 'privatemessages',         1, 'vbulletin'),
	(1232082000, -1, -1, -1, 'a:6:{i:0;i:0;i:1;i:10;i:2;i:20;i:3;i:30;i:4;i:40;i:5;i:50;}',	'./includes/cron/unpublished.php', 1, 'scheduled_publish', 1, 'vbulletin'),
	(1320000000, -1, -1, -1, 'a:6:{i:0;i:0;i:1;i:10;i:2;i:20;i:3;i:30;i:4;i:40;i:5;i:50;}', './includes/cron/mailqueue.php', 1, 'cronmail', 1, 'vbulletin'),
	(0,			 -1, -1,  0, 'a:1:{i:0;i:20;}', 		 './includes/cron/notification_cleanup.php', 1, 'notificationcleanup', 1, 'vbulletin'),
	(0,			 -1, -1, -1, 'a:2:{i:0;i:0;i:1;i:30;}',  './includes/cron/fcmqueue.php', 1, 'fcmqueue', 1, 'vbulletin'),
	(0,			 -1, -1, -1, '" . serialize(array(50)). "',  './includes/cron/trending.php', 1, 'trending', 1, 'vbulletin'),
	(0,			 -1, -1, -1, '" . serialize(array(15)). "',  './includes/cron/privacyconsentremoveuser.php', 1, 'privacyconsentremoveuser', 1, 'vbulletin')
";
$schema['INSERT']['explain']['cron'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "cron");



$schema['INSERT']['query']['datastore'] = "
INSERT INTO " . TABLE_PREFIX . "datastore
	(title, data, unserialize)
VALUES
	('products', '" . $db->escape_string(serialize(array('vbulletin' => '1'))) . "', 1)
";
$schema['INSERT']['explain']['datastore'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "datastore");

// this query is used by the 370b6 upgrade script, so the REPLACE avoids errors
$schema['INSERT']['query']['faq'] = "
REPLACE INTO " . TABLE_PREFIX . "faq
	(faqname, faqparent, displayorder, volatile, product)
VALUES
	('account_avatar', 'account_overview', 2, 1, 'vbulletin'),
	('account_customizeprofile', 'account_overview', 3, 1, 'vbulletin'),
	('account_ignore', 'account_overview', 10, 1, 'vbulletin'),
	('account_notifications', 'account_overview', 8, 1, 'vbulletin'),
	('account_overview', 'faqroot', 20, 1, 'vbulletin'),
	('account_privacy', 'account_overview', 7, 1, 'vbulletin'),
	('account_privatemessages', 'account_overview', 11, 1, 'vbulletin'),
	('account_reputation', 'account_overview', 13, 1, 'vbulletin'),
	('account_resetprofile', 'account_overview', 4, 1, 'vbulletin'),
	('account_settings', 'account_overview', 1, 1, 'vbulletin'),
	('account_signature_new', 'account_overview', 5, 1, 'vbulletin'),
	('account_signatureimage', 'account_overview', 6, 1, 'vbulletin'),
	('account_subscribers', 'account_overview', 9, 1, 'vbulletin'),
	('account_visitormessages', 'account_overview', 12, 1, 'vbulletin'),
	('albums_add_photos', 'albums_overview', 2, 1, 'vbulletin'),
	('albums_create_new', 'albums_overview', 1, 1, 'vbulletin'),
	('albums_create_video', 'albums_overview', 3, 1, 'vbulletin'),
	('albums_delete_album', 'albums_overview', 5, 1, 'vbulletin'),
	('albums_overview', 'faqroot', 60, 1, 'vbulletin'),
	('albums_posted_photos', 'albums_overview', 4, 1, 'vbulletin'),
	('albums_reuse_photo', 'albums_overview', 5, 1, 'vbulletin'),
	('bbcode_basic', 'bbcode_reference', 2, 1, 'vbulletin'),
	('bbcode_code', 'bbcode_reference', 9, 1, 'vbulletin'),
	('bbcode_links', 'bbcode_reference', 3, 1, 'vbulletin'),
	('bbcode_lists', 'bbcode_reference', 7, 1, 'vbulletin'),
	('bbcode_media', 'bbcode_reference', 5, 1, 'vbulletin'),
	('bbcode_quotes', 'bbcode_reference', 4, 1, 'vbulletin'),
	('bbcode_reference', 'faqroot', 80, 1, 'vbulletin'),
	('bbcode_smilies', 'bbcode_reference', 6, 1, 'vbulletin'),
	('bbcode_tables', 'bbcode_reference', 8, 1, 'vbulletin'),
	('bbcode_why', 'bbcode_reference', 1, 1, 'vbulletin'),
	('blog_create', 'blog_overview', 1, 1, 'vbulletin'),
	('blog_manage_privacy', 'blog_overview', 4, 1, 'vbulletin'),
	('blog_members', 'blog_overview', 3, 1, 'vbulletin'),
	('blog_overview', 'faqroot', 40, 1, 'vbulletin'),
	('blog_owners', 'blog_overview', 2, 1, 'vbulletin'),
	('community_overview', 'faqroot', 10, 1, 'vbulletin'),
	('content_advanced', 'content_overview', 5, 1, 'vbulletin'),
	('content_attachments', 'content_overview', 7, 1, 'vbulletin'),
	('content_flag', 'content_overview', 8, 1, 'vbulletin'),
	('content_links', 'content_overview', 3, 1, 'vbulletin'),
	('content_messages', 'content_overview', 6, 1, 'vbulletin'),
	('content_overview', 'faqroot', 30, 1, 'vbulletin'),
	('content_photos', 'content_overview', 2, 1, 'vbulletin'),
	('content_polls', 'content_overview', 4, 1, 'vbulletin'),
	('content_subscriptions', 'content_overview', 9, 1, 'vbulletin'),
	('content_topics', 'content_overview', 1, 1, 'vbulletin'),
	('general_cookies_clear', 'community_overview', 11, 1, 'vbulletin'),
	('general_cookies_usage', 'community_overview', 10, 1, 'vbulletin'),
	('general_facebook_connect', 'community_overview', 6, 1, 'vbulletin'),
	('general_forums_topics_posts', 'community_overview', 1, 1, 'vbulletin'),
	('general_loginlogoff', 'community_overview', 3, 1, 'vbulletin'),
	('general_lostpassword', 'community_overview', 5, 1, 'vbulletin'),
	('general_new_content', 'community_overview', 9, 1, 'vbulletin'),
	('general_registration', 'community_overview', 2, 1, 'vbulletin'),
	('general_search', 'community_overview', 8, 1, 'vbulletin'),
	('general_tos', 'community_overview', 12, 1, 'vbulletin'),
	('group_add_owner', 'group_overview', 2, 1, 'vbulletin'),
	('group_create_new', 'group_overview', 1, 1, 'vbulletin'),
	('group_manage_members', 'group_overview', 4, 1, 'vbulletin'),
	('group_overview', 'faqroot', 50, 1, 'vbulletin'),
	('group_share', 'group_overview', 5, 1, 'vbulletin')
";
$schema['INSERT']['explain']['faq'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "faq");


$schema['INSERT']['query']['icon'] = "
INSERT INTO " . TABLE_PREFIX . "icon
	(title, iconpath, imagecategoryid, displayorder)
VALUES
	('{$install_phrases['posticon_1']}', 'images/icons/icon1.png', '2', '1'),
	('{$install_phrases['posticon_2']}', 'images/icons/icon2.png', '2', '1'),
	('{$install_phrases['posticon_3']}', 'images/icons/icon3.png', '2', '1'),
	('{$install_phrases['posticon_4']}', 'images/icons/icon4.png', '2', '1'),
	('{$install_phrases['posticon_5']}', 'images/icons/icon5.png', '2', '1'),
	('{$install_phrases['posticon_6']}', 'images/icons/icon6.png', '2', '1'),
	('{$install_phrases['posticon_7']}', 'images/icons/icon7.png', '2', '1'),
	('{$install_phrases['posticon_8']}', 'images/icons/icon8.png', '2', '1'),
	('{$install_phrases['posticon_9']}', 'images/icons/icon9.png', '2', '1'),
	('{$install_phrases['posticon_10']}', 'images/icons/icon10.png', '2', '1'),
	('{$install_phrases['posticon_11']}', 'images/icons/icon11.png', '2', '1'),
	('{$install_phrases['posticon_12']}', 'images/icons/icon12.png', '2', '1'),
	('{$install_phrases['posticon_13']}', 'images/icons/icon13.png', '2', '1'),
	('{$install_phrases['posticon_14']}', 'images/icons/icon14.png', '2', '1')
";
$schema['INSERT']['explain']['icon'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "icon");



$schema['INSERT']['query']['imagecategory'] = "
INSERT INTO " . TABLE_PREFIX . "imagecategory
	(title, imagetype, displayorder)
VALUES
	('{$install_phrases['generic_smilies']}', 3, 1),
	('{$install_phrases['generic_icons']}', 2, 1),
	('{$install_phrases['generic_avatars']}', 1, 1)
";
$schema['INSERT']['explain']['imagecategory'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "imagecategory");



$schema['INSERT']['query']['language'] = "
INSERT INTO " . TABLE_PREFIX . "language
	(title, languagecode, charset, decimalsep, thousandsep)
VALUES
	('{$install_phrases['master_language_title']}', '{$install_phrases['master_language_langcode']}', '{$install_phrases['master_language_charset']}', '{$install_phrases['master_language_decimalsep']}', '{$install_phrases['master_language_thousandsep']}')";
$schema['INSERT']['explain']['language'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "language");



$schema['INSERT']['query']['package'] = "
INSERT INTO " . TABLE_PREFIX . "package
	(packageid, productid, class)
VALUES
	(1, 'vbulletin', 'vBForum'),
	(2, 'vbulletin', 'vBBlog'),
	(3, 'vbulletin', 'vBCms')
";
$schema['INSERT']['explain']['package'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "package");



$schema['INSERT']['query']['paymentapi'] = "
INSERT INTO " . TABLE_PREFIX . "paymentapi
	(title, currency, recurring, classname, active, settings, subsettings)
VALUES
	('Paypal', 'usd,gbp,eur,aud,cad', 1, 'paypal', 0, '" . $db->escape_string(serialize(array(
		'ppemail' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'primaryemail' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
		'tax' => array(
			'type' => 'yesno',
			'value' => 0,
			'validate' => 'boolean'
		),
		'shipping_address' => array(
			'type' => 'select',
			'options' => array(
				'none',
				'optional',
				'required',
			),
			'value' => 'none',
			'validate' => 'boolean'
		),
	))) . "'),
	('Google', 'usd,gbp', 1, 'google', 0, '" . $db->escape_string(serialize(array(
		'google_merchant_id' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'google_merchant_key' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'sandbox' => array(
			'type' => 'yesno',
			'value' => 0,
			'validate' => 'boolean'
		)
	)))  . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
		'tax' => array(
			'type' => 'yesno',
			'value' => 0,
			'validate' => 'boolean'
		),
		'message' => array(
			'type'     => 'text',
			'value'    => '',
			'validate' => 'string'
		)
	))) . "'),
	('NOCHEX', 'gbp', 0, 'nochex', 0, '" . $db->escape_string(serialize(array(
		'ncxemail' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "'),
	('Worldpay', 'usd,gbp,eur', 0, 'worldpay', 0, '" . $db->escape_string(serialize(array(
		'worldpay_instid' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'worldpay_password' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "'),
	('Authorize.Net', 'usd,gbp,eur', 0, 'authorizenet', 0, '" . $db->escape_string(serialize(array(
		'authorize_loginid' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'txnkey' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'signaturekey' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "'),
	('2Checkout', 'usd', 0, '2checkout', 0, '" . $db->escape_string(serialize(array(
		'twocheckout_id' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'number'
		),
		'secret_word' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "'),
	('Moneybookers', 'usd,gbp,eur,aud,cad', 0, 'moneybookers', 0, '" . $db->escape_string(serialize(array(
		'mbemail' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'mbsecret' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "'),
	('CCBill', 'usd', 0, 'ccbill', 0, '" . $db->escape_string(serialize(array(
		'clientAccnum' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'clientSubacc' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'formName' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'secretword' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'username' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		),
		'password' => array(
			'type' => 'text',
			'value' => '',
			'validate' => 'string'
		)
	))) . "', '" . $db->escape_string(serialize(array(
		'show' => array(
			'type' => 'yesno',
			'value' => 1,
			'validate' => 'boolean'
		),
	))) . "')
";
$schema['INSERT']['explain']['paymentapi'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "paymentapi");



$schema['INSERT']['query']['profilefield'] = "
INSERT INTO " . TABLE_PREFIX . "profilefield
	(profilefieldid, required, hidden, maxlength, size, displayorder, editable, type, data, height, def, optional, searchable, memberlist, regex, form)
VALUES
	('1', '0', '0', '16384', '50', '1', '1', 'textarea', '', '0', '0', '0', '1', '1', '', '0'),
	('2', '0', '0', '100', '25', '2', '1', 'input', '', '0', '0', '0', '1', '1', '', '0'),
	('3', '0', '0', '100', '25', '3', '1', 'input', '', '0', '0', '0', '1', '1', '', '0'),
	('4', '0', '0', '100', '25', '4', '1', 'input', '', '0', '0', '0', '1', '1', '', '0')
";
$schema['INSERT']['explain']['profilefield'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "profilefield");



// Phrases
if (!empty($customphrases) AND is_array($customphrases))
{
	foreach ($customphrases AS $fieldname => $phrase)
	{
		foreach ($phrase AS $varname => $text)
		{
			$schema['INSERT']['query']["$varname"] = "
			INSERT INTO " . TABLE_PREFIX . "phrase (languageid, fieldname, varname, text, product) VALUES
			(0, '$fieldname', '$varname', '" . $db->escape_string($text) . "', 'vbulletin')
			";
			$schema['INSERT']['explain']["$varname"] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "phrase");
		}
	}
}



// Phrasetypes TODO: MAKE THIS NICER
$schema['INSERT']['query']['phrasetype'] = "
INSERT INTO " . TABLE_PREFIX . "phrasetype
	(fieldname, title, editrows, special)
VALUES
	('global',           '" . $db->escape_string($phrasetype['global']) . "', 3, 0),
	('cpglobal',         '" . $db->escape_string($phrasetype['cpglobal']) . "', 3, 0),
	('cppermission',     '" . $db->escape_string($phrasetype['cppermission']) . "', 3, 0),
	('forum',            '" . $db->escape_string($phrasetype['forum']) . "', 3, 0),
	('calendar',         '" . $db->escape_string($phrasetype['calendar']) . "', 3, 0),
	('attachment_image', '" . $db->escape_string($phrasetype['attachment_image']) . "', 3, 0),
	('style',            '" . $db->escape_string($phrasetype['style']) . "', 3, 0),
	('logging',          '" . $db->escape_string($phrasetype['logging']) . "', 3, 0),
	('cphome',           '" . $db->escape_string($phrasetype['cphome']) . "', 3, 0),
	('promotion',        '" . $db->escape_string($phrasetype['promotion']) . "', 3, 0),
	('user',             '" . $db->escape_string($phrasetype['user']) . "', 3, 0),
	('help_faq',         '" . $db->escape_string($phrasetype['help_faq']) . "', 3, 0),
	('sql',              '" . $db->escape_string($phrasetype['sql']) . "', 3, 0),
	('subscription',     '" . $db->escape_string($phrasetype['subscription']) . "', 3, 0),
	('language',         '" . $db->escape_string($phrasetype['language']) . "', 3, 0),
	('bbcode',           '" . $db->escape_string($phrasetype['bbcode']) . "', 3, 0),
	('stats',            '" . $db->escape_string($phrasetype['stats']) . "', 3, 0),
	('diagnostic',       '" . $db->escape_string($phrasetype['diagnostics']) . "', 3, 0),
	('maintenance',      '" . $db->escape_string($phrasetype['maintenance']) . "', 3, 0),
	('cprofilefield',    '" . $db->escape_string($phrasetype['cprofilefield']) . "', 3, 0),
	('profilefield',     '" . $db->escape_string($phrasetype['profile']) . "', 3, 0),
	('thread',           '" . $db->escape_string($phrasetype['thread']) . "', 3, 0),
	('timezone',         '" . $db->escape_string($phrasetype['timezone']) . "', 3, 0),
	('banning',          '" . $db->escape_string($phrasetype['banning']) . "', 3, 0),
	('reputation',       '" . $db->escape_string($phrasetype['reputation']) . "', 3, 0),
	('wol',              '" . $db->escape_string($phrasetype['wol']) . "', 3, 0),
	('threadmanage',     '" . $db->escape_string($phrasetype['threadmanage']) . "', 3, 0),
	('pm',               '" . $db->escape_string($phrasetype['pm']) . "', 3, 0),
	('cpuser',           '" . $db->escape_string($phrasetype['cpuser']) . "', 3, 0),
	('cron',             '" . $db->escape_string($phrasetype['cron']) . "', 3, 0),
	('moderator',        '" . $db->escape_string($phrasetype['moderator']) . "', 3, 0),
	('cpoption',         '" . $db->escape_string($phrasetype['cpoption']) . "', 3, 0),
	('cprank',           '" . $db->escape_string($phrasetype['cprank']) . "', 3, 0),
	('cpusergroup',      '" . $db->escape_string($phrasetype['cpusergroup']) . "', 3, 0),
	('posting',          '" . $db->escape_string($phrasetype['posting']) . "', 3, 0),
	('poll',             '" . $db->escape_string($phrasetype['poll']) . "', 3, 0),
	('fronthelp',        '" . $db->escape_string($phrasetype['fronthelp']) . "', 3, 0),
	('register',         '" . $db->escape_string($phrasetype['register']) . "', 3, 0),
	('search',           '" . $db->escape_string($phrasetype['search']) . "', 3, 0),
	('showthread',       '" . $db->escape_string($phrasetype['showthread']) . "', 3, 0),
	('postbit',          '" . $db->escape_string($phrasetype['postbit']) . "', 3, 0),
	('forumdisplay',     '" . $db->escape_string($phrasetype['forumdisplay']) . "', 3, 0),
	('messaging',        '" . $db->escape_string($phrasetype['messaging']) . "', 3, 0),
	('hooks',            '" . $db->escape_string($phrasetype['hooks']) . "', 3, 0),
	('inlinemod',        '" . $db->escape_string($phrasetype['inlinemod']) . "', 3, 0),
	('reputationlevel',  '" . $db->escape_string($phrasetype['reputationlevel']) . "', 3, 0),
	('infraction',       '" . $db->escape_string($phrasetype['infraction']) . "', 3, 0),
	('infractionlevel',  '" . $db->escape_string($phrasetype['infractionlevel']) . "', 3, 0),
	('notice',           '" . $db->escape_string($phrasetype['notice']) . "', 3, 0),
	('prefix',           '" . $db->escape_string($phrasetype['prefix']) . "', 3, 0),
	('prefixadmin',      '" . $db->escape_string($phrasetype['prefixadmin']) . "', 3, 0),
	('album',            '" . $db->escape_string($phrasetype['album']) . "', 3, 0),
	('error',            '" . $db->escape_string($phrasetype['front_end_error']) . "', 8, 1),
	('frontredirect',    '" . $db->escape_string($phrasetype['front_end_redirect']) . "', 8, 1),
	('emailbody',        '" . $db->escape_string($phrasetype['email_body']) . "', 10, 1),
	('emailsubject',     '" . $db->escape_string($phrasetype['email_subj']) . "', 3, 1),
	('vbsettings',       '" . $db->escape_string($phrasetype['vbulletin_settings']) . "', 4, 1),
	('cphelptext',       '" . $db->escape_string($phrasetype['cp_help']) . "', 8, 1),
	('faqtitle',         '" . $db->escape_string($phrasetype['faq_title']) . "', 3, 1),
	('faqtext',          '" . $db->escape_string($phrasetype['faq_text']) . "', 10, 1),
	('hvquestion',       '" . $db->escape_string($phrasetype['hvquestion']) . "', 3, 1),
	('socialgroups',     '" . $db->escape_string($phrasetype['socialgroups']) . "', 3, 0),
	('tagscategories',   '" . $db->escape_string($phrasetype['tagscategories']) . "', 3, 0),
	('advertising',      '" . $db->escape_string($phrasetype['advertising']) . "', 3, 0),
	('vbblock',	         '" . $db->escape_string($phrasetype['vbblock']) . "', 3, 0),
	('vb5blog',          '" . $db->escape_string($phrasetype['vb5blog']) . "', 3, 0)
";
$schema['INSERT']['explain']['phrasetype'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "phrasetype");


$schema['INSERT']['query']['style'] = "
INSERT INTO " . TABLE_PREFIX . "style
	(styleid, title, parentid, parentlist, templatelist, replacements, userselect, displayorder)
VALUES
	(1, '{$install_phrases['default_style']}', -1, '1,-1', '1,-1', '', 1, 1)
";
$schema['INSERT']['explain']['style'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "style");



$schema['INSERT']['query']['infractionlevel'] = "
INSERT INTO " . TABLE_PREFIX . "infractionlevel
	(infractionlevelid, points, expires, period, warning)
VALUES
	(1, 1, 10, 'D', 1),
	(2, 1, 10, 'D', 1),
	(3, 1, 10, 'D', 1),
	(4, 1, 10, 'D', 1)
";
$schema['INSERT']['explain']['infractionlevel'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "infractionlevel");



$schema['INSERT']['query']['reputationlevel'] = "
INSERT INTO " . TABLE_PREFIX . "reputationlevel
	(reputationlevelid, minimumreputation)
VALUES
	(1, -999999),
	(2, -50),
	(3, -10),
	(4, 0),
	(5, 10),
	(6, 50),
	(7, 150),
	(8, 250),
	(9, 350),
	(10, 450),
	(11, 550),
	(12, 650),
	(13, 1000),
	(14, 1500),
	(15, 2000)
";
$schema['INSERT']['explain']['reputationlevel'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "reputationlevel");



$schema['INSERT']['query']['smilie'] = "
INSERT INTO " . TABLE_PREFIX . "smilie
	(title, smilietext, smiliepath, imagecategoryid, displayorder)
VALUES
	('{$install_phrases['smilie_smile']}', ':)', 'images/smilies/smile.png', '1', '1'),
	('{$install_phrases['smilie_embarrass']}', ':o', 'images/smilies/redface.png', '1', '1'),
	('{$install_phrases['smilie_grin']}', ':D', 'images/smilies/biggrin.png', '1', '1'),
	('{$install_phrases['smilie_wink']}', ';)', 'images/smilies/wink.png', '1', '1'),
	('{$install_phrases['smilie_tongue']}', ':p', 'images/smilies/tongue.png', '1', '1'),
	('{$install_phrases['smilie_cool']}', ':cool:', 'images/smilies/cool.png', '1', '5'),
	('{$install_phrases['smilie_roll']}', ':rolleyes:', 'images/smilies/rolleyes.png', '1', '3'),
	('{$install_phrases['smilie_mad']}', ':mad:', 'images/smilies/mad.png', '1', '1'),
	('{$install_phrases['smilie_eek']}', ':eek:', 'images/smilies/eek.png', '1', '7'),
	('{$install_phrases['smilie_confused']}', ':confused:', 'images/smilies/confused.png', '1', '1'),
	('{$install_phrases['smilie_frown']}', ':(', 'images/smilies/frown.png', '1', '1')
";
$schema['INSERT']['explain']['smilie'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "smilie");


// Load usergroup permissions to see what is given on new installs
require_once(DIR . '/includes/class_bitfield_builder.php');
if (vB_Bitfield_Builder::build(false) !== false)
{
	$myobj =& vB_Bitfield_Builder::init();
}
else
{
	echo "<strong>error</strong>\n";
	print_r(vB_Bitfield_Builder::fetch_errors());
}

$groupinfo = array();
foreach ($myobj->data['ugp'] AS $grouptitle => $perms)
{
	for ($x = 1; $x <= 10; $x++)
	{
		$groupinfo["$x"]["$grouptitle"] = 0;
	}

	foreach ($perms AS $permtitle => $permvalue)
	{
		if (empty($permvalue['group']))
		{
			continue;
		}

		if (!empty($permvalue['install']))
		{
			foreach ($permvalue['install'] AS $gid)
			{
				$groupinfo["$gid"]["$grouptitle"] += $permvalue['value'];
			}
		}
	}
}


// KEEP THIS IN SYNC with vB_Upgrade's createSystemGroups() until we refactor this & get rid of dupe code.
if(!function_exists('mysqlschema_create_usergroup_array'))
{
	function mysqlschema_create_usergroup_array($groupdetails, $groupoverrides, $groupperms)
	{
		//we need to make sure that the order of fields is consistent between different groups
		//even if the source arrays are not.  So do not simply loop through the arrays and
		//add fields even if that's a little cleaner.
		$group = array(
			'usergroupid' => $groupdetails['usergroupid'],
			'title' => $groupdetails['title'],
			'description' => '',
			'usertitle' => $groupdetails['usertitle'],
			'passwordexpires' => 0,
			'passwordhistory' => 0,
			'pmquota' => 500,
			'pmsendmax' => 5,
			'opentag' => '',
			'closetag' => '',
			'canoverride' => 0,
			'ispublicgroup' => 0,
			'attachlimit' => 0,
			'avatarmaxwidth' => 200,
			'avatarmaxheight' => 200,
			'avatarmaxsize' => 100000,
			'sigmaxrawchars' => 1000,
			'sigmaxchars' => 500,
			'sigmaxlines' => 0,
			'sigmaxsizebbcode' => 7,
			'sigmaximages' => 4,
			'sigpicmaxwidth' => 500,
			'sigpicmaxheight' => 100,
			'sigpicmaxsize' => 10000,
			'albumpicmaxwidth' => 600,
			'albumpicmaxheight' => 600,
			'albummaxpics' => 100,
			'albummaxsize' => 0,
			'pmthrottlequantity' => 0,
			'groupiconmaxsize' => 65535,
			'maximumsocialgroups' => 5,
			'systemgroupid' => $groupdetails['systemgroupid'],

			//the group permissions contain a field that doesn't belong here.
			//let's only copy what we know we need to avoid errors.
			'forumpermissions' => $groupperms['forumpermissions'],
			'forumpermissions2' => $groupperms['forumpermissions2'],
			'pmpermissions' => $groupperms['pmpermissions'],
			'calendarpermissions' => $groupperms['calendarpermissions'],
			'wolpermissions' => $groupperms['wolpermissions'],
			'adminpermissions' => $groupperms['adminpermissions'],
			'genericpermissions' => $groupperms['genericpermissions'],
			'genericpermissions2' => $groupperms['genericpermissions2'],
			'signaturepermissions' => $groupperms['signaturepermissions'],
			'genericoptions' => $groupperms['genericoptions'],
			'usercsspermissions' => $groupperms['usercsspermissions'],
			'visitormessagepermissions' => $groupperms['visitormessagepermissions'],
			'socialgrouppermissions' => $groupperms['socialgrouppermissions'],
			'albumpermissions' => $groupperms['albumpermissions'],
		);

		//this doesn't change the order to number of fields so it's safe
		foreach($groupoverrides AS $key => $value)
		{
			//don't add the key if it's not already present.  This should never happen.
			if(isset($group[$key]))
			{
				$group[$key] = $value;
			}
		}

		return $group;
	}
}

//these are the details that every group needs to set -- they either always will be
//different or are too variable for defaulting to make sense
$groupdetails = array(
	1 => array(
		'usergroupid' => 1,
		'systemgroupid' => 1,
		'title' => $install_phrases['usergroup_guest_title'],
		'usertitle' => $install_phrases['usergroup_guest_usertitle'],
	),
	2 => array(
		'usergroupid' => 2,
		'systemgroupid' => 2,
		'title' => $install_phrases['usergroup_registered_title'],
		'usertitle' => '',
	),
	3 => array(
		'usergroupid' => 3,
		'systemgroupid' => 3,
		'title' => $install_phrases['usergroup_activation_title'],
		'usertitle' => '',
	),
	4 => array(
		'usergroupid' => 4,
		'systemgroupid' => 4,
		'title' => $install_phrases['usergroup_coppa_title'],
		'usertitle' => '',
	),
	5 => array(
		'usergroupid' => 5,
		'systemgroupid' => 5,
		'title' => $install_phrases['usergroup_super_title'],
		'usertitle' => $install_phrases['usergroup_super_usertitle'],
	),
	6 => array(
		'usergroupid' => 6,
		'systemgroupid' => 6,
		'title' => $install_phrases['usergroup_admin_title'],
		'usertitle' => $install_phrases['usergroup_admin_usertitle'],
	),
	7 => array(
		'usergroupid' => 7,
		'systemgroupid' => 7,
		'title' => $install_phrases['usergroup_mod_title'],
		'usertitle' => $install_phrases['usergroup_mod_usertitle'],
	),
	8 => array(
		'usergroupid' => 8,
		'systemgroupid' => 8,
		'title' => $install_phrases['usergroup_banned_title'],
		'usertitle' => $install_phrases['usergroup_banned_usertitle'],
	),
	9 => array(
		'usergroupid' => 9,
		'systemgroupid' => vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID,
		'title' => $install_phrases['channelowner_title'],
		'usertitle' => '',
	),
	10 => array(
		'usergroupid' => 10,
		'systemgroupid' => vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
		'title' => $install_phrases['channelmod_title'],
		'usertitle' => '',
	),
	11 => array(
		'usergroupid' => 11,
		'systemgroupid' => vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
		'title' => $install_phrases['channelmember_title'],
		'usertitle' => '',
	),
	12 => array(
		'usergroupid' => 12,
		'systemgroupid' => vB_Api_UserGroup::CMS_AUTHOR_SYSGROUPID,
		'title' => $install_phrases['cms_author_title'],
		'usertitle' => '',
	),
	13 => array(
		'usergroupid' => 13,
		'systemgroupid' => vB_Api_UserGroup::CMS_EDITOR_SYSGROUPID,
		'title' => $install_phrases['cms_editor_title'],
		'usertitle' => '',
	),
);

//these are fields that have a default value but are different for one or
//two groups.  This allows us to tweak the groups without specifying the
//value for *every* *single* group.
$groupoverrides = array(
	1 => array (
		'pmsendmax' => 0,
		'maximumsocialgroups' => 0,
	),
	3 => array (
		'pmsendmax' => 1,
	),
	4 => array (
		'pmsendmax' => 1,
	),
	5 => array (
		//pmsendax of 0 here seems really odd -- the other groups that are zero are
		//low priv groups and this one emphatically isn't -- but not changing it.
		'pmsendmax' => 0,
	),
	6 => array(
		'passwordhistory' => 360,
		'sigmaxrawchars' => 0,
		'sigmaxchars' => 0,
		'sigmaxlines' => 0,
		'sigmaximages' => 0,
	),
	8 => array (
		'pmsendmax' => 0,
		'pmquota' => 0,
	),
);

$groups = array(
	1 => mysqlschema_create_usergroup_array($groupdetails[1], $groupoverrides[1], $groupinfo[1]),
	2 => mysqlschema_create_usergroup_array($groupdetails[2], array(), $groupinfo[2]),
	3 => mysqlschema_create_usergroup_array($groupdetails[3], $groupoverrides[3], $groupinfo[3]),
	4 => mysqlschema_create_usergroup_array($groupdetails[4], $groupoverrides[4], $groupinfo[4]),
	5 => mysqlschema_create_usergroup_array($groupdetails[5], $groupoverrides[5], $groupinfo[5]),
	6 => mysqlschema_create_usergroup_array($groupdetails[6], $groupoverrides[6], $groupinfo[6]),
	7 => mysqlschema_create_usergroup_array($groupdetails[7], array(), $groupinfo[7]),
	8 => mysqlschema_create_usergroup_array($groupdetails[8], $groupoverrides[8], $groupinfo[8]),
	9 => mysqlschema_create_usergroup_array($groupdetails[9], array(), $groupinfo[9]),
	10 => mysqlschema_create_usergroup_array($groupdetails[10], array(), $groupinfo[10]),
	//these groups should have there own groupinfo entry instead of using the values for registered users
	//but that's beyond the scope of the current refactor.
	11 => mysqlschema_create_usergroup_array($groupdetails[11], array(), $groupinfo[2]),
	12 => mysqlschema_create_usergroup_array($groupdetails[12], array(), $groupinfo[2]),
	13 => mysqlschema_create_usergroup_array($groupdetails[13], array(), $groupinfo[2]),
);

//we assume that the fields are in the same order for each of the groups.
//we should really move this to the assertor/merge with function in the upgrade
//class for adding the new groups.  But that's going to require some changes to
//install class that need to be considered.

$fields = implode(', ', array_keys($groups[1]));
$values = array();
foreach($groups AS $group)
{
	//quote and escape any strings
	foreach($group AS $key => $value)
	{
		if(is_string($value))
		{
			$group[$key] = "'" . $db->escape_string($value) . "'";
		}
	}

	$values[] = '(' . implode (', ', $group) . ')';
}

$values = implode(",\n", $values);

$schema['INSERT']['query']['usergroup'] = "
INSERT INTO " . TABLE_PREFIX . "usergroup
(	$fields )
VALUES
$values
";
$schema['INSERT']['explain']['usergroup'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "usergroup");

$schema['INSERT']['query']['usertitle'] = "
INSERT INTO " . TABLE_PREFIX . "usertitle
	(minposts, title)
VALUES
	('0', '{$install_phrases['usertitle_jnr']}'),
	('30', '{$install_phrases['usertitle_mbr']}'),
	('100', '{$install_phrases['usertitle_snr']}')
";
$schema['INSERT']['explain']['usertitle'] = sprintf($vbphrase['default_data_type'], TABLE_PREFIX . "usertitle");

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
