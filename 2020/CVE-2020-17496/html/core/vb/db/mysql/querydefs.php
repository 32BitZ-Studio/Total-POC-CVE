<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

/**
 * @package vBDatabase
 */

/**
 * @package vBDatabase
 */
class vB_dB_MYSQL_QueryDefs extends vB_dB_QueryDefs
{

	/*
	* This class is called by the new vB_dB_Assertor database class
	* It does the actual execution. See the vB_dB_Assertor class for more information

	* $queryid can be either the id of a query from the dbqueries table, or the
	* name of a table.
	*
	* if it is the name of a table , $params MUST include 'type' of either update, insert, select, or delete.
	*
	* $params includes a list of parameters. Here's how it gets interpreted.
	*
	* If the queryid was the name of a table and type was "update", one of the params
	* must be the primary key of the table. All the other parameters will be matched against
	* the table field names, and appropriate fields will be updated. The return value will
	* be false if an error is generated and true otherwise
	*
	* If the queryid was the name of a table and type was "delete", one of the params
	* must be the primary key of the table. All the other parameters will be ignored
	* The return value will be false if an error is generated and true otherwise
	*
	* If the queryid was the name of a table and type was "insert", all the parameters will be
	* matched against the table field names, and appropriate fields will be set in the insert.
	* The return value is the primary key of the inserted record.
	*
	* If the queryid was the name of a table and type was "select", all the parameters will be
	* matched against the table field names, and appropriate fields will be part of the
	* "where" clause of the select. The return value will be a vB_dB_Result object
	* The return value is the primary key of the inserted record.
	*
	* If the queryid is the key of a record in the dbqueries table then each params
	* value will be matched to the query. If there are missing parameters we will return false.
	* If the query generates an error we return false, and otherwise we return either true,
	* or an inserted id, or a recordset.
	*/
	/* Properties==================================================================== */

	protected $db_type = 'MYSQL';

	/**
	 * Flag to determine if we are in a state of database error. Used by saveDbCache method.
	 *
	 * @var	bool
	 */
	protected $saveDbCacheErrorState = false;

	/**
	 * This is the definition for tables we will process through. It saves a
	 * database query to put them here.
	 */
	protected $table_data = array(
		//these should be in alpha order for readability.
		'adminutil' => array(
			'key' => 'title',
			'structure' => array('title', 'text')
		),
		'album' => array('key' => 'albumid', 'structure' => array('albumid', 'userid',
				'createdate', 'lastpicturedate', 'visible', 'moderation', 'title', 'description', 'state',
				'coverattachmentid')
		),
		'customavatar' => array('key' => 'customavatarid', 'structure' => array('customavatarid',
			'userid', 'filedata', 'dateline', 'filename', 'visible', 'filesize', 'width', 'height',
			'filedata_thumb', 'width_thumb', 'height_thumb')
		),
		'privacyconsent' => array(
			'key' => 'privacyconsent',
			'structure' => array(
				'privacyconsentid',
				'ipaddress',
				'created',
				'consent',
			),
		),
		'widget' => array(
			'key' => 'widgetid',
			'structure' => array(
				'widgetid',
				'parentid',
				'template',
				'admintemplate',
				'titlephrase',
				'icon',
				'isthirdparty',
				'category',
				'cloneable',
				'guid',
				'canbemultiple',
				'product',
			),
		),
		'widgetdefinition' => array(
			'key' => '',
			'structure' => array(
				'widgetid',
				'name',
				'field',
				'labelphrase',
				'descriptionphrase',
				'defaultvalue',
				'isusereditable',
				'ishiddeninput',
				'isrequired',
				'displayorder',
				'validationtype',
				'validationmethod',
				'data',
				'product',
			),
		),
		'widgetinstance' => array(
			'key' => 'widgetinstanceid',
			'structure' => array('widgetinstanceid', 'containerinstanceid', 'pagetemplateid', 'widgetid', 'displaysection', 'displayorder', 'adminconfig', 'guid'),
		),
		'widgetuserconfig' => array(
			'key' => 'widgetinstanceid',
			'structure' => array('widgetinstanceid', 'userid', 'userconfig'),
		),
		'widgetchannelconfig' => array(
			'key' => array('widgetinstanceid','nodeid'),
			'structure' => array('widgetinstanceid', 'nodeid', 'channelconfig'),
		),
		'cache' => array(
			'key' => 'cacheid',
			'structure' => array('cacheid', 'expires', 'created', 'locktime', 'serialized', 'data'),
			'forcetext' => array('serialized')
		),

		'cacheevent' => array(
			'key' => array('cacheid', 'event'),
			'structure' => array('cacheid', 'event')
		),

		'datastore' => array('key' => 'title', 'structure' => array('title', 'data', 'unserialize')
		),

		'externalcache' => array(
			'key' => 'cachehash',
			'structure' => array('cachehash', 'text', 'headers', 'dateline', 'forumid')
		),

		'ipaddressinfo' => array(
			'key' => 'ipaddressinfoid',
			'structure' => array('ipaddressinfoid', 'ipaddress', 'eustatus', 'created'),
		),

		'filedata' => array('key' => 'filedataid', 'structure' => array('filedataid', 'userid', 'dateline',
			'filedata', 'filesize', 'filehash', 'extension', 'refcount', 'width', 'height', 'publicview')
		),

		'filedataresize' => array('key' => array('filedataid', 'type'), 'structure' => array('filedataid', 'resize_type', 'resize_filedata',
			'resize_dateline', 'resize_dateline', 'resize_width', 'resize_height', 'reload')),

		'setting' => array('key' => 'varname', 'structure' => array('varname', 'grouptitle', 'value', 'defaultvalue',
			'optioncode', 'displayorder', 'advanced', 'volatile', 'datatype', 'product', 'validationcode', 'blacklist', 'adminperm')
		),

		'settinggroup' => array('key' => 'grouptitle', 'structure' => array('grouptitle',
			'displayorder', 'volatile', 'product', 'adminperm')
		),

		'smilie' => array(
			'key' => 'smilieid',
			'structure' => array('smilieid', 'title', 'smilietext', 'smiliepath', 'imagecategoryid', 'displayorder')
		),

		'session' => array(
			'key' => 'sessionhash',
			'structure' => array('sessionhash', 'userid', 'host', 'idhash',
				'lastactivity', 'location', 'useragent', 'styleid', 'languageid', 'loggedin', 'inforum', 'inthread',
				'incalendar', 'badlocation', 'bypass', 'profileupdate', 'apiclientid', 'apiaccesstoken'),
			'forcetext' => array('sessionhash', 'idhash', 'apiaccesstoken')
		),

		// @TODO Not sure why we have the style table defined in both
		// the vbforum package and the base mysql querydefs
		'style' => array(
			'key'=> 'styleid',
			'structure' => array(
				'styleid',
				'parentid',
				'title',
				'parentlist',
				'templatelist',
				'newstylevars',
				'replacements',
				'editorstyles',
				'userselect',
				'displayorder',
				'dateline',
				'guid',
				'filedataid',
				'previewfiledataid',
				'styleattributes',
			)
		),

		'template' => array('key' => 'templateid', 'forcetext' => array('templatetype',
			'mergestatus'), 'structure' => array('templateid', 'styleid', 'title', 'template',
			'template_un', 'templatetype', 'dateline', 'username', 'version', 'product',
			'mergestatus', 'textonly')
		),

		'templatehistory' => array('key' => 'templatehistoryid', 'structure' =>
			array('templatehistoryid', 'styleid', 'title', 'template', 'dateline', 'username',
			'version', 'comment')
		),

		'templatemerge' => array('key' => 'templateid', 'structure' => array('templateid',
			'template', 'version', 'savedtemplateid')
		),

		'user' => array(
			'key' => 'userid',
			'structure' => array('userid', 'usergroupid',
				'membergroupids', 'displaygroupid', 'username', 'token', 'passworddate', 'email',
				'styleid', 'parentemail', 'homepage', 'icq', 'aim', 'yahoo', 'msn', 'skype', 'google', 'status',
				'showvbcode', 'showbirthday', 'usertitle', 'customtitle', 'joindate', 'daysprune',
				'lastvisit', 'lastactivity', 'lastpost', 'lastpostid', 'posts', 'reputation',
				'reputationlevelid', 'timezoneoffset', 'pmpopup', 'avatarid', 'avatarrevision',
				'sigpicrevision', 'options', 'privacy_options', 'notification_options',
				'birthday', 'birthday_search', 'maxposts', 'startofweek', 'ipaddress', 'referrerid', 'languageid',
				'emailstamp', 'threadedmode', 'autosubscribe', 'emailnotification', 'pmtotal', 'pmunread', 'scheme',
				'secret', 'ipoints', 'infractions', 'warnings', 'infractiongroupids', 'infractiongroupid',
				'adminoptions', 'profilevisits', 'friendcount', 'friendreqcount', 'vmunreadcount', 'vmmoderatedcount',
				'socgroupinvitecount', 'socgroupreqcount', 'pcunreadcount', 'pcmoderatedcount', 'gmmoderatedcount',
				'assetposthash', 'fbuserid', 'fbjoindate', 'fbname', 'privacyconsent',
				'privacyconsentupdated', 'editorstate',
			),
			'forcetext' => array('username', 'status'),
		),

		'usergroup' => array('key' => 'usergroupid', 'structure' => array( 'usergroupid',
			'title','description','usertitle','passwordexpires','passwordhistory','pmquota',
			'pmsendmax','opentag','closetag','canoverride','ispublicgroup','forumpermissions',
			'pmpermissions','calendarpermissions','wolpermissions','adminpermissions','genericpermissions',
			'genericpermissions2','genericoptions','signaturepermissions','visitormessagepermissions',
			'attachlimit','avatarmaxwidth','avatarmaxheight', 'avatarmaxsize',
			'sigpicmaxwidth','sigpicmaxheight','sigpicmaxsize',
			'sigmaximages','sigmaxsizebbcode','sigmaxchars','sigmaxrawchars','sigmaxlines',
			'usercsspermissions','albumpermissions','albumpicmaxwidth','albumpicmaxheight',
			'albummaxpics','albummaxsize','socialgrouppermissions','pmthrottlequantity',
			'groupiconmaxsize','maximumsocialgroups', 'systemgroupid')
		),

		'userlist' => array(
			'key' => array('userid', 'relationid','type'),
			'structure' => array('type', 'userid', 'relationid', 'friend'),
		),

		'userloginmfa' => array(
			'key' => array('userid'),
			'structure' => array('userid', 'enabled', 'secret', 'dateline'),
		),

		'userpromotion' => array('key' => 'userpromotionid', 'structure' =>array('userpromotionid',
			'usergroupid', 'joinusergroupid', 'reputation', 'date', 'posts', 'strategy', 'type')
		),

		'routenew' => array(
			'key' => 'routeid',
			'structure' => array(
				'routeid', 'name', 'redirect301',
				'prefix', 'regex', 'class', 'controller', 'action', 'template', 'arguments', 'contentid',
				'guid', 'product', 'ishomeroute'
			)
		),

		'page' => array('key' => 'pageid', 'structure' => array('pageid', 'parentid', 'pagetemplateid',
			'title', 'metadescription', 'routeid', 'moderatorid', 'displayorder',
			'pagetype', 'guid', 'product')
		),

		'pagetemplate' => array(
			'key' => 'pagetemplateid',
			'structure' => array(
				'pagetemplateid',
				'title',
				'screenlayoutid',
				'content',
				'guid',
				'product',
				'screenlayoutsectiondata',
			)
		),

		'passwordhistory' => array(
			'key' => array(),
			'structure' => array('userid', 'token', 'scheme', 'passworddate'),
			'forcetext' => array('password')
		),

		'humanverify' => array(
			'key' => 'hash',
			'structure' => array('hash', 'answer', 'dateline', 'viewed'),
			'forcetext' => array('hash', 'answer'),
		),

		'hvanswer' => array(
			'key' => 'answerid',
			'structure' => array('answerid', 'questionid', 'answer', 'dateline'),
		),

		'hvquestion' => array('key' => 'questionid', 'structure' => array('questionid', 'regex', 'dateline')),

		'useractivation' => array('key' => 'useractivationid', 'structure' => array('useractivationid', 'userid',
			'dateline', 'activationid', 'type', 'usergroupid', 'emailchange', 'reset_attempts', 'reset_locked_since')
		),

		'cron' => array( 'key' => 'cronid', 'structure' => array('cronid', 'nextrun', 'weekday',
			'day', 'hour', 'minute', 'filename', 'loglevel', 'active', 'varname', 'volatile', 'product')
		),

		'userban' => array('key' => 'userid', 'structure' => array(
			'userid', 'usergroupid', 'displaygroupid', 'usertitle', 'customtitle',
			'adminid', 'bandate', 'liftdate', 'reason')
		),

		'apiclient' => array(
			'key' => 'apiclientid',
			'structure' => array(
				'apiclientid',
				'secret',
				'apiaccesstoken',
				'userid',
				'clienthash',
				'clientname',
				'clientversion',
				'platformname',
				'platformversion',
				'uniqueid',
				'initialipaddress',
				'dateline',
				'lastactivity',
			),
			'forcetext' => array('apiaccesstoken'),
		),

		'apilog' => array('key' => 'apilogid', 'structure' => array(
			'apilogid', 'apiclientid', 'dateline', 'method', 'paramget',
			'parampost', 'ipaddress')
		),

		'phrase' => array(
			'key' => 'phraseid',
			'structure' => array(
				'phraseid',
				'languageid',
				'varname',
				'fieldname',
				'text',
				'product',
				'username',
				'dateline',
				'version',
			),
			'forcetext' => array('varname'),
		),

		'phrasetype' => array('key' => 'fieldname', 'structure' => array('fieldname', 'title',
				'editrows', 'prodiuct', 'special')
		),
		'noderead' => array('key' => array('userid', 'nodeid'), 'structure' => array(
			'userid', 'nodeid', 'readtime'
		)),
		'mailqueue' => array('key' => 'mailqueueid', 'structure' => array(
			'mailqueueid', 'dateline', 'toemail', 'fromemail', 'subject', 'message', 'header'
		)),
		'ad' => array('key' => 'adid', 'structure' => array(
			'adid', 'title', 'adlocation', 'displayorder', 'active', 'snippet'
		)),
		'adcriteria' => array('key' => 'adid', 'structure' => array(
			'adid', 'criteriaid', 'condition1', 'condition2', 'condition3'
		)),
		'infraction' => array('key' => 'infractionid', 'structure' => array(
			'infractionid', 'infractionlevelid', 'nodeid', 'postid', 'userid', 'whoadded', 'points', 'reputation_penalty',
			'dateline', 'note', 'action', 'actiondateline', 'actionuserid', 'actionreason', 'expires',
			'channelid', 'threadid', 'customreason'
		)),
		'cpsession' => array(
			'key' => array('userid', 'hash'),
			'structure' => array('userid', 'hash', 'dateline'),
			'forcetext' => array('hash'),
		),
		'product' => array('key' => 'productid', 'structure' => array(
			'productid', 'title', 'description', 'version', 'active', 'url', 'versioncheckurl'
		)),
		'productcode' => array('key' => 'productcodeid', 'structure' => array(
			'productcodeid', 'productid', 'version', 'installcode', 'uninstallcode'
		)),
		'productdependency' => array('key' => 'productdependencyid', 'structure' => array(
			'productdependency', 'productid', 'dependencytype', 'parentproductid', 'minversion', 'maxversion'
		)),
		'hook' => array(
			'key' => 'hookid',
			'structure' => array('hookid', 'product', 'hookname', 'title', 'active', 'hookorder', 'template', 'arguments')
		),
		'cron' => array('key' => 'cronid', 'structure' => array(
			'cronid', 'nextrun', 'weekday', 'day', 'hour', 'minute', 'filename', 'loglevel', 'active', 'varname', 'volatile', 'product'
		)),
		'adminmessage' => array('key' => 'adminmessageid', 'structure' => array(
			'adminmessageid', 'varname', 'dismissable', 'script', 'action', 'execurl', 'method',
			'dateline', 'status', 'statususerid', 'args'
		)),
		'adminlog' => array('key' => 'adminlogid', 'structure' => array(
			'adminlogid', 'userid', 'dateline', 'script', 'action', 'extrainfo', 'ipaddress'
		)),
		'usertitle' => array('key' => 'usertitleid', 'structure' => array('usertitleid',
			'minposts', 'title'
		)),
		'moderatorlog' => array('key' => 'moderatorlogid', 'structure' => array('moderatorlogid',
			'dateline', 'userid', 'nodeid', 'action', 'type', 'nodetitle', 'ipaddress', 'product', 'id1', 'id2', 'id3', 'id4', 'id5'
		)),
		'screenlayout' => array(
			'key' => 'screenlayoutid',
			'structure' => array(
				'screenlayoutid',
				'varname',
				'title',
				'displayorder',
				'columncount',
				'template',
				'admintemplate',
				'guid',
				'sectiondata',
			),
		),
		'language' => array(
			'key' => 'languageid',
			'structure' => array(
				'languageid',
				'title',
				'userselect',
				'options',
				'languagecode',
				'charset',
				'dateoverride',
				'timeoverride',
				'registereddateoverride',
				'calformat1override',
				'calformat2override',
				'eventdateformatoverride',
				'pickerdateformatoverride',
				'logdateoverride',
				'locale',
				'decimalsep',
				'thousandsep',
				'phrasegroup_global',
				'phrasegroup_cpglobal',
				'phrasegroup_cppermission',
				'phrasegroup_forum',
				'phrasegroup_calendar',
				'phrasegroup_attachment_image',
				'phrasegroup_style',
				'phrasegroup_logging',
				'phrasegroup_cphome',
				'phrasegroup_promotion',
				'phrasegroup_user',
				'phrasegroup_help_faq',
				'phrasegroup_sql',
				'phrasegroup_subscription',
				'phrasegroup_language',
				'phrasegroup_bbcode',
				'phrasegroup_stats',
				'phrasegroup_diagnostic',
				'phrasegroup_maintenance',
				'phrasegroup_profilefield',
				'phrasegroup_thread',
				'phrasegroup_timezone',
				'phrasegroup_banning',
				'phrasegroup_reputation',
				'phrasegroup_wol',
				'phrasegroup_threadmanage',
				'phrasegroup_pm',
				'phrasegroup_cpuser',
				'phrasegroup_cron',
				'phrasegroup_moderator',
				'phrasegroup_cpoption',
				'phrasegroup_cprank',
				'phrasegroup_cpusergroup',
				'phrasegroup_holiday',
				'phrasegroup_posting',
				'phrasegroup_poll',
				'phrasegroup_fronthelp',
				'phrasegroup_register',
				'phrasegroup_search',
				'phrasegroup_showthread',
				'phrasegroup_postbit',
				'phrasegroup_forumdisplay',
				'phrasegroup_messaging',
				'phrasegroup_inlinemod',
				'phrasegroup_hooks',
				'phrasegroup_cprofilefield',
				'phrasegroup_reputationlevel',
				'phrasegroup_infraction',
				'phrasegroup_infractionlevel',
				'phrasegroup_notice',
				'phrasegroup_prefix',
				'phrasegroup_prefixadmin',
				'phrasegroup_album',
				'phrasegroup_socialgroups',
				'phrasegroup_advertising',
				'phrasegroup_tagscategories',
				'phrasegroup_contenttypes',
				'phrasegroup_vbblock',
				'phrasegroup_vbblocksettings',
				'phrasegroup_vb5blog',
				'phrasegroup_navbarlinks',
				'vblangcode',
			)
		),
		'bbcode' => array(
			'key' => 'bbcodeid',
			'structure' => array(
				'bbcodeid',
				'bbcodetag',
				'bbcodereplacement',
				'bbcodeexample',
				'bbcodeexplanation',
				'twoparams',
				'title',
				'buttonimage',
				'options',
			)
		),
		'icon' => array('key' => 'iconid', 'structure' => array('iconid',
			'title', 'iconpath', 'imagecategoryid', 'displayorder')),
			'userstylevar' => array('key' => array('stylevarid', 'userid'), 'structure' => array(
			'stylevarid', 'userid', 'value', 'dateline')
		),
		'bbcode_video' => array('key' => 'providerid', 'structure' => array('providerid',
			'tagoption', 'provider', 'url', 'regex_url', 'regex_scrape', 'embed', 'priority' )),
			'package' => array('key' => 'packageid', 'structure' => array('packageid', 'productid', 'class')),
		'userchangelog' => array('key' => 'changeid', 'structure' => array('changeid',
			'userid', 'fieldname', 'newvalue', 'oldvalue', 'adminid', 'change_time', 'change_uniq', 'ipaddress'
		)),
		'stylevar' => array('key' => 'stylevarid', 'structure' => array('stylevarid',
			'styleid', 'value', 'dateline', 'username'
		)),
		'videoitem' => array('key' => 'videoitemid', 'structure' => array('videoitemid',
			'nodeid', 'provider', 'code', 'url'
		)),
		'usernote' => array('key' =>  array('usernoteid', 'userid', 'posterid'), 'structure' => array('usernoteid',
			'userid', 'posterid', 'username', 'dateline', 'message', 'title', 'allowsmilies'
		)),
		/*
		// vB5's event table data is stored in vbforum package.
		'event' => array('key' =>  array('eventid', 'userid', 'calendarid', 'visible', 'dateline_to'), 'structure' => array('eventid', 'userid',
				'event', 'title', 'allowsmilies', 'recurring', 'recuroption', 'calendarid', 'customfields', 'visible', 'dateline', 'utc',
				'dst', 'dateline_from', 'dateline_to'
		)),
		*/
		// 'eventhighlight' and 'eventhighlightpermission' are also in the vbforum package
		'subscribeevent' => array('key' =>  array('subscribeeventid', 'userid', 'eventid'), 'structure' => array('subscribeeventid',
			'userid', 'eventid', 'lastreminder', 'reminder'
		)),
		'deletionlog' => array('key' => array('primaryid', 'type'), 'structure' => array('primaryid','type','userid','username','reason','dateline')),
		'infractionlevel' => array(
			'key' => 'infractionlevelid',
			'structure' => array('infractionlevelid', 'points', 'expires', 'period', 'warning', 'extend', 'reputation_penalty')
		),
		'infractiongroup' => array(
			'key' => 'infractiongroupid',
			'structure' => array('infractiongroupid', 'usergroupid', 'orusergroupid', 'pointlevel', 'override')
		),
		'infractionban' => array(
			'key' => 'infractionbanid',
			'structure' => array('infractionbanid', 'usergroupid', 'banusergroupid', 'amount', 'period', 'method')
		),
		'stats' => array(
			'key' => 'dateline',
			'structure' => array('dateline', 'nuser', 'nthread', 'npost', 'ausers')
		),
		'profilevisitor' => array(
			'key' => array('userid', 'visitorid'),
			'structure' => array('userid', 'visitorid', 'dateline', 'visible')
		),
		'spamlog' => array(
			'key' => 'nodeid',
			'structure' => array('nodeid')
		),
		'editlog' => array(
			'key' => 'postid',
			'structure' => array('postid', 'userid', 'username', 'dateline', 'reason', 'hashistory')
		),
		'contentpriority' => array(
			'key' => array('contenttypeid', 'sourceid'),
			'structure' => array('contenttypeid', 'sourceid', 'prioritylevel')
		),
	);

	/**
	 * This is the definition for queries we will process through. We could also
	 * put them in the database, but this eliminates a query.
	 */
	protected $query_data = array(
		'mysqlVersion' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT version() AS version"
		),
		'getFoundRows' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT FOUND_ROWS()"
		),
		'fetch_options' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT * FROM {TABLE_PREFIX}datastore WHERE title in ({option_names})'
		),
		'datastore_lock' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}adminutil SET text = UNIX_TIMESTAMP() WHERE title = 'datastorelock' AND text < UNIX_TIMESTAMP() - 15"
		),
		'verifyUsername' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT userid, username FROM {TABLE_PREFIX}user
			WHERE userid != {userid}
			AND
			(
				username = {username}
				OR
				username = {username_raw}
			)",
			'forcetext' => array('username', 'username_raw')
		),
		'replaceTachyforumcounterForum' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "REPLACE INTO {TABLE_PREFIX}tachyforumcounter
						(userid, forumid, threadcount, replycount)
					VALUES
						({userid}), {forumid}, {threadcount}, {replycount})"
		),
		'replaceTachyforumpostForum' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "REPLACE INTO {TABLE_PREFIX}tachyforumpost
						(userid, forumid, lastpost, lastposter, lastposterid, lastpostid, lastthread, lastthreadid, lasticonid, lastprefixid)
					VALUES
						({userid}, {forumid}, {lastpost}, {lastposter}, {lastposterid}, {lastpostid}, {lastthread}, {lastthreadid}, {lasticonid}, {lastprefixid})"
		),
		'getRecipientsPM' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT usertextfield.*, user.*
						FROM {TABLE_PREFIX}user AS user
						LEFT JOIN {TABLE_PREFIX}usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
						WHERE username IN({username})
						ORDER BY user.username"
		),

		'getUsersWithRank' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.*, usertextfield.`rank`
				FROM {TABLE_PREFIX}user AS user
					LEFT JOIN {TABLE_PREFIX}usertextfield AS usertextfield ON (user.userid = usertextfield.userid)
				WHERE user.userid >= {startid}
				ORDER BY user.userid
				LIMIT {limit}
		"),

		/* Template API SQL Start */
		'template_get_existing' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT templateid, styleid, product FROM {TABLE_PREFIX}template
								WHERE title = {title}
								AND templatetype = 'template'",
		),
		'template_savehistory' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}templatehistory
										(styleid, title, template, dateline, username, version, comment)
								VALUES
										({dostyleid}, {title}, {template_un}, {dateline}, {username}, {version}, {comment})",
		),
		'template_fetchbystyleandtitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT templateid
								FROM {TABLE_PREFIX}template
								WHERE styleid = {styleid} AND title = {title}",
		),
		'template_fetchbystyleandtitle2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT templateid, title, styleid, dateline, username, version
								FROM {TABLE_PREFIX}template
								WHERE title = {title}
										AND styleid IN (-1, {styleid})",
		),
		'template_update' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}template SET
										title = {title},
										template = {template},
										template_un = {template_un},
										dateline = {dateline},
										username = {username},
										version = {version},
										product = {product},
										textonly = {textonly},
										mergestatus = 'none'
								WHERE templateid = {templateid} AND
										(
												MD5(template_un) = {hash} OR
												template_un = {template_un}
										)"
		),

		'template_deletefrom_templatemerge' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}templatemerge
				WHERE templateid IN (
					SELECT templateid
					FROM {TABLE_PREFIX}template
					WHERE styleid = {styleid}
				)
			",
		),
		'template_updatecustom_product' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}template
								SET product = {product}
								WHERE title = {title}
										AND styleid <> -1"
		),
		'template_fetchoriginal' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT templateid, styleid, title, template_un
								FROM {TABLE_PREFIX}template
								WHERE styleid IN (-1,0) AND title = {title}",
		),
		'template_update_mergestatus' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}template
						SET mergestatus = 'none'
						WHERE templateid IN ({templateids})",
		),
		'template_getrevertingtemplates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT DISTINCT t1.templateid, t1.title
						FROM {TABLE_PREFIX}template AS t1
						INNER JOIN {TABLE_PREFIX}template AS t2 ON
								(t2.styleid IN ({styleparentlist}) AND t2.styleid <> {styleid} AND t2.title = t1.title)
						WHERE t1.templatetype = 'template'
								AND t1.styleid = {styleid}",
		),
		'template_getmasters' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT templateid, title
								FROM {TABLE_PREFIX}template
								WHERE templatetype = 'template'
										AND styleid IN (-1,0)
								ORDER BY title",
		),
		'template_getmasters2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT title, templateid FROM {TABLE_PREFIX}template WHERE styleid IN (-1,0)",
		),
		'template_fetch_css_svg_templates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT title
				FROM {TABLE_PREFIX}template
				WHERE styleid IN ({styleidlist}) AND
				 	templatetype = 'template' AND
					(title LIKE '%.css' OR title LIKE '%.svg')
			"
		),
		/* Template API SQL End */

		/* Style API SQL Start */
		'style_updateparent' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}style
				SET parentid = {parentid},
				parentlist = {parentlist}
				WHERE parentid = {styleid}
			",
		),
		/* Style API SQL End */

		/* User API SQL Start */
		'user_fetchforupdating' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.*, avatar.avatarpath, customavatar.dateline AS avatardateline, customavatar.width AS avatarwidth, customavatar.height AS avatarheight,
					NOT ISNULL(customavatar.userid) AS hascustomavatar, usertextfield.signature, usergroup.adminpermissions,
					NOT ISNULL(sigpic.userid) AS hassigpic,
					sigpic.width AS sigpicwidth, sigpic.height AS sigpicheight, sigpic.dateline AS sigpicdateline
				FROM {TABLE_PREFIX}user AS user
					LEFT JOIN {TABLE_PREFIX}avatar AS avatar ON(avatar.avatarid = user.avatarid)
					LEFT JOIN {TABLE_PREFIX}customavatar AS customavatar ON(customavatar.userid = user.userid)
					LEFT JOIN {TABLE_PREFIX}sigpic AS sigpic ON(sigpic.userid = user.userid)
					LEFT JOIN {TABLE_PREFIX}usertextfield AS usertextfield ON(usertextfield.userid = user.userid)
					LEFT JOIN {TABLE_PREFIX}usergroup AS usergroup ON(usergroup.usergroupid = user.usergroupid)
				WHERE user.userid = {userid}
			",
		),
		'user_fetchmoderate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT userid, username, email, ipaddress
				FROM {TABLE_PREFIX}user
				WHERE usergroupid = 4
				ORDER BY username
			",
		),
		'user_fetchusergroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT title
				FROM {TABLE_PREFIX}usergroup
				WHERE usergroupid = {usergroupid}
			",
		),
		'user_updateusergroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET displaygroupid = IF(displaygroupid = usergroupid, 0, displaygroupid),
					usergroupid = {usergroupid}
				WHERE userid IN({userids})
			",
		),
		'user_fetch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT userid, username
				FROM {TABLE_PREFIX}user
				WHERE userid IN ({userids})
				LIMIT {startat}, 50
			",
		),
		'user_deleteusertextfield' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}usertextfield WHERE userid IN({userids})
			",
		),
		'user_deleteuserfield' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}userfield WHERE userid IN({userids})
			",
		),
		'user_deleteuser' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}user WHERE userid IN({userids})
			",
		),
		'user_fetchwithtextfield' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}user AS user
				LEFT JOIN {TABLE_PREFIX}usertextfield AS usertextfield USING(userid)
				WHERE user.userid = {userid}
			",
		),
		'user_insertuserlist' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				INSERT IGNORE INTO {TABLE_PREFIX}userlist
					(userid, relationid, type, friend)
				SELECT {destuserid}, relationid, type, friend
				FROM {TABLE_PREFIX}userlist
				WHERE userid = {sourceuserid}
			",
		),
		'user_updateuserlist' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE IGNORE {TABLE_PREFIX}userlist
				SET relationid = {destuserid}
				WHERE relationid = {sourceuserid}
					AND relationid <> {destuserid}
			",
		),
		'user_fetchuserlistcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) FROM {TABLE_PREFIX}userlist
				WHERE userid = {userid}
					AND type = 'buddy'
					AND friend = 'yes'
			",
		),
		'user_fetchinfractiongroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroupid, orusergroupid, pointlevel, override
				FROM {TABLE_PREFIX}infractiongroup
				ORDER BY pointlevel
			",
		),
		'user_updateannouncement' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}announcement
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updateattachment' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}attachment
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatedeletionlog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}deletionlog SET
					userid = {destuserid},
					username = {destusername}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatepostedithistory' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}postedithistory SET
					userid = {destuserid},
					username = {destusername}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updateeditlog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}editlog SET
					userid = {destuserid},
					username = {destusername}
				WHERE userid = {sourceuserid}
			",
		),

		'usermerge_conflictedpolls' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT sourcevote.nodeid
				FROM {TABLE_PREFIX}pollvote AS sourcevote
					INNER JOIN {TABLE_PREFIX}pollvote AS destvote ON (destvote.nodeid = sourcevote.nodeid AND destvote.userid = {destuserid})
				WHERE sourcevote.userid = {sourceuserid}
			",
		),

		'usermerge_updatelastpollvote' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}poll AS poll
				SET lastvote = (SELECT max(pollvote.votedate) FROM {TABLE_PREFIX}pollvote AS pollvote WHERE poll.nodeid = pollvote.nodeid)
				WHERE poll.nodeid IN ({nodeid});
			",
		),



		'user_updateusernote' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}usernote
				SET posterid = {destuserid}
				WHERE posterid = {sourceuserid}
			",
		),
		'user_updateusernote2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}usernote
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatereputation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}reputation
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatereputation2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}reputation
				SET whoadded = {destuserid}
				WHERE whoadded = {sourceuserid}
			",
		),
		'user_updateinfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}infraction
				SET infracteduserid = {destuserid}
				WHERE infracteduserid = {sourceuserid}
			",
		),
		'user_updateinfraction2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS n
				INNER JOIN {TABLE_PREFIX}infraction AS i ON(i.nodeid = n.nodeid)
				SET n.userid = {destuserid}
				WHERE n.userid = {sourceuserid}
			",
		),
		'user_updateusergrouprequest' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}usergrouprequest
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatesocgroupreqcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user SET
				socgroupreqcount = {socgroupreqcount}
				WHERE userid = {userid}
			",
		),
		'user_updatepaymentinfo' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}paymentinfo
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_updatesubscriptionlog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}subscriptionlog
				SET userid = {destuserid}
				WHERE userid = {sourceuserid}
			",
		),
		'user_fetchsubscriptionlog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT
					subscriptionlogid, subscriptionid, expirydate
				FROM {TABLE_PREFIX}subscriptionlog
				WHERE
					userid = {userid}
						AND
					status = 1
			",
		),
		'user_deletesubscriptionlog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}subscriptionlog
				WHERE subscriptionlogid IN ({ids})
			",
		),
		'user_updatesubscriptionlog2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}subscriptionlog
				SET expirydate = {expirydate}
				WHERE subscriptionlogid = {subscriptionlogid}
			",
		),
		'user_searchpostip' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT ipaddress
				FROM {TABLE_PREFIX}node
				WHERE userid = {userid} AND
				ipaddress <> {ipaddress} AND
				ipaddress <> ''
				ORDER BY ipaddress
			",
		),
		'user_fetchcontacts' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT type, friend
				FROM {TABLE_PREFIX}userlist AS userlist
				WHERE userlist.userid = {user1}
					AND userlist.relationid = {user2}
			",
		),
		'user_useractivation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT useractivationid, activationid, dateline, reset_attempts, reset_locked_since
				FROM {TABLE_PREFIX}useractivation
				WHERE type = 1
					AND userid = {userid}
			",
		),
		'user_deleteactivationid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}useractivation
				WHERE userid = {userid} AND type = 1
			",
		),
		'user_replaceuseractivation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}useractivation
					(userid, dateline, activationid, type, usergroupid, emailchange)
				VALUES
					({userid}, {timenow}, {activateid} , {type}, {usergroupid}, {emailchange})
			",
		),
		'user_replaceuseractivation2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}useractivation
					(userid, dateline, activationid, type, usergroupid)
				VALUES
					({userid}, {timenow}, {activateid} , {type}, {usergroupid})
			",
		),
		'user_fetchstrikes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS strikes, MAX(striketime) AS lasttime
				FROM {TABLE_PREFIX}strikes
				WHERE ip_4 = {ip_4} AND ip_3 = {ip_3} AND ip_2 = {ip_2} AND ip_1 = {ip_1}"
		),
		'user_fetchprofilefieldsforregistration' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}profilefield
				WHERE editable > 0 AND required <> 0
				ORDER BY displayorder"
			),
		'user_fetchcurrentbans' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.userid, userban.liftdate, userban.bandate
				FROM {TABLE_PREFIX}user AS user
				LEFT JOIN {TABLE_PREFIX}userban AS userban ON(userban.userid = user.userid)
				WHERE user.userid IN ({userids})"
		),
		/* User API SQL End */

		/* Userrank API SQL Start */
		'userrank_fetchranks' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT rankid, ranklevel, minposts, rankimg, ranks.usergroupid, title, type, display, stack
				FROM {TABLE_PREFIX}ranks AS ranks
				LEFT JOIN {TABLE_PREFIX}usergroup AS usergroup USING(usergroupid)
				ORDER BY ranks.usergroupid, minposts
			",
		),
		/* Userrank API SQL End */


		/* User Datamanager Start */
		'userdm_reputationlevel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT reputationlevelid
				FROM {TABLE_PREFIX}reputationlevel
				WHERE {reputation} >= minimumreputation
				ORDER BY minimumreputation DESC
				LIMIT 1",
		),
		'userdm_verifyusername' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT userid, username FROM {TABLE_PREFIX}user
				WHERE userid != {userid}
				AND
				(
					username = {username}
					OR
					username = {username_raw}
					)",
			'forcetext' => array('username', 'username_raw')
		),
		'userdm_unregisteredphrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT text
				FROM {TABLE_PREFIX}phrase
				WHERE varname = 'unregistered'
					AND fieldname = 'global'",
		),
		'userdm_showusercol' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SHOW COLUMNS FROM {TABLE_PREFIX}user LIKE 'username'",
		),

		'userdm_usertitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT title
				FROM {TABLE_PREFIX}usertitle
				WHERE minposts <= {minposts}
				ORDER BY minposts DESC
				LIMIT 1
			",
		),
		'userdm_profilefields' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT profilefieldid
				FROM {TABLE_PREFIX}profilefield
				WHERE editable > 0 AND required <> 0
			",
		),
		'userdm_updateuseractivation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
					UPDATE {TABLE_PREFIX}useractivation
					SET usergroupid = {usergroupid}
					WHERE userid = {userid}
						AND type = 0"
		),
		'userdm_friendlist' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT relationid, friend
				FROM {TABLE_PREFIX}userlist
				WHERE userid = {userid}
					AND type = 'buddy'
					AND friend IN('pending','yes')
			"
		),
		'userdm_updatefriendcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET friendcount = IF(friendcount > 0, friendcount - 1, 0)
				WHERE userid IN ({userids})
			"
		),
		'userdm_picture' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT a.attachmentid, a.filedataid, a.userid
				FROM {TABLE_PREFIX}attachment AS a
				WHERE
					a.userid = {userid}
						AND
					a.contenttypeid IN ({contenttypeids})
			"
		),
		'userdm_updatefriendcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}pmtext SET
					touserarray = REPLACE(touserarray,
						'i:{userid};s:{usernamelength}:\"{username}\";',
						'i:{userid};s:{username2length}:\"{username2}\";'
					)
				WHERE touserarray LIKE '%i:{userid};s:{usernamelength}:\"{username}\";%'
			"
		),
		'userdm_infractiongroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT orusergroupid, override
				FROM {TABLE_PREFIX}infractiongroup AS infractiongroup
				WHERE infractiongroup.usergroupid IN (-1, {usergroupid})
					AND infractiongroup.pointlevel <= {ipoints}
				ORDER BY pointlevel
			"
		),
			/* User Datamanager End */

		/* Usergroup API SQL Start */
		'usergroup_fetchperms' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroup.usergroupid, title,
					(COUNT(forumpermission.forumpermissionid) + COUNT(calendarpermission.calendarpermissionid)) AS permcount
				FROM {TABLE_PREFIX}usergroup AS usergroup
				LEFT JOIN {TABLE_PREFIX}forumpermission AS forumpermission ON (usergroup.usergroupid = forumpermission.usergroupid)
				LEFT JOIN {TABLE_PREFIX}calendarpermission AS calendarpermission ON (usergroup.usergroupid = calendarpermission.usergroupid)
				GROUP BY usergroup.usergroupid
				HAVING permcount > 0
				ORDER BY title
			"
		),
		'usergroup_checkadmin' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
					SELECT COUNT(*) AS usergroups
					FROM {TABLE_PREFIX}usergroup
					WHERE (adminpermissions & {cancontrolpanel}) AND
						usergroupid <> {usergroupid}
			"
		),
		'usergroup_makeuservisible' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET options = (options & ~{invisible})
				WHERE usergroupid = {usergroupid}
			"
		),
		'usergroup_fetchausers' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.userid
				FROM {TABLE_PREFIX}user AS user
				LEFT JOIN {TABLE_PREFIX}administrator as administrator ON (user.userid = administrator.userid)
				WHERE administrator.userid IS NULL AND
					user.usergroupid = {usergroupid}
			"
		),
		'usergroup_insertprefixpermission' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}prefixpermission (usergroupid, prefixid)
				SELECT {newugid}, prefixid FROM {TABLE_PREFIX}prefix
				WHERE options & {deny_by_default}
			"
		),
		'usergroup_inserteventhighlightpermission' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}eventhighlightpermission (eventhighlightid, usergroupid)
				SELECT eventhighlightid, {newugid} FROM {TABLE_PREFIX}eventhighlight
				WHERE denybydefault = 1
			"
		),
		'usergroup_fetchmarkups' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroupid, opentag, closetag
				FROM {TABLE_PREFIX}usergroup
				WHERE opentag <> '' OR
				closetag <> ''
			"
		),
		'getUserGroupIdCountByPromotion' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT COUNT(*) AS count, usergroupid
			FROM {TABLE_PREFIX}userpromotion GROUP BY usergroupid"
		),
		'getUserPromotionsAndUserGroups' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT userpromotion.*, usergroup.title
			FROM {TABLE_PREFIX}userpromotion AS userpromotion, {TABLE_PREFIX}usergroup AS usergroup
			WHERE userpromotionid = {userpromotionid} AND userpromotion.usergroupid = usergroup.usergroupid"
		),
		'getUserPromotionBasicFields' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT userpromotionid, usergroup.title
				FROM {TABLE_PREFIX}userpromotion AS userpromotion
				INNER JOIN {TABLE_PREFIX}usergroup AS usergroup ON (userpromotion.usergroupid = usergroup.usergroupid)
				WHERE userpromotionid = {userpromotionid}"
		),
		'deleteUserPromotion' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}userpromotion
				WHERE usergroupid = {usergroupid} OR joinusergroupid = {usergroupid}
			"
		),
		'usergroup_fetchmemberstoremove' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT userid, username, membergroupids, infractiongroupids
				FROM {TABLE_PREFIX}user
				WHERE FIND_IN_SET({usergroupid}, membergroupids)
				OR FIND_IN_SET({usergroupid}, infractiongroupids)
			"
		),
		'usergroup_fetchwithjoinrequests' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT req.usergroupid, COUNT(req.usergrouprequestid) AS requests,
				IF(usergroup.usergroupid IS NULL, 0, 1) AS validgroup
				FROM {TABLE_PREFIX}usergrouprequest AS req
				LEFT JOIN {TABLE_PREFIX}usergroup AS usergroup ON (usergroup.usergroupid = req.usergroupid)
				LEFT JOIN {TABLE_PREFIX}user AS user ON (user.userid = req.userid)
				WHERE user.userid IS NOT NULL
				GROUP BY req.usergroupid
			"
		),
		'usergroup_fetchleaders' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroupleader.userid, user.username
				FROM {TABLE_PREFIX}usergroupleader AS usergroupleader
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				WHERE usergroupleader.usergroupid = {usergroupid}
			"
		),
		'usergroup_fetchallleaders' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT ugl.*, user.username
				FROM {TABLE_PREFIX}usergroupleader AS ugl
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
			"
		),
		'usergroup_fetchjoinrequests' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT req.*, user.username
				FROM {TABLE_PREFIX}usergrouprequest AS req
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				WHERE req.usergroupid = {usergroupid}
				ORDER BY user.username
			"
		),
		'usergroup_fetchjoinrequests2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT req.userid, user.username, user.usergroupid, user.membergroupids, req.usergrouprequestid
				FROM {TABLE_PREFIX}usergrouprequest AS req
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				WHERE usergrouprequestid IN ({auth})
				ORDER BY user.username
			"
		),
		'usergroup_fetchjoinrequests3' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroup.title, usergroup.opentag, usergroup.closetag, usergroup.usergroupid, COUNT(usergrouprequestid) AS requests
				FROM {TABLE_PREFIX}usergroup AS usergroup
				LEFT JOIN {TABLE_PREFIX}usergrouprequest AS req USING(usergroupid)
				WHERE usergroup.usergroupid IN({usergroupids})
				GROUP BY usergroup.usergroupid
				ORDER BY usergroup.title
			"
		),
		'usergroup_updatemembergroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user SET
				membergroupids = IF(membergroupids = '', {usergroupid}, CONCAT(membergroupids, ',{usergroupid}'))
				WHERE userid IN ({auth})
			"
		),
		'usergroup_fetchusertitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}usertitle
				WHERE minposts < {posts}
				ORDER BY minposts DESC
				LIMIT 1
			"
		),
		/* Usergroup API SQL End */

		/* Phrase API SQL Start */
		'phrase_fetchorphans' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT orphan.varname, orphan.languageid, orphan.fieldname
				FROM {TABLE_PREFIX}phrase AS orphan
				LEFT JOIN {TABLE_PREFIX}phrase AS phrase ON (phrase.languageid IN(-1, 0) AND phrase.varname = orphan.varname AND phrase.fieldname = orphan.fieldname)
				WHERE orphan.languageid NOT IN (-1, 0)
					AND phrase.phraseid IS NULL
				ORDER BY orphan.varname
			"
		),
		'phrase_fetchupdates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT pGlobal.phraseid, pCustom.varname, pCustom.languageid,
					pCustom.username AS customuser, pCustom.dateline AS customdate, pCustom.version AS customversion,
					pGlobal.username AS globaluser, pGlobal.dateline AS globaldate, pGlobal.version AS globalversion,
					pGlobal.product, phrasetype.title AS phrasetype_title
				FROM {TABLE_PREFIX}phrase AS pCustom
				INNER JOIN {TABLE_PREFIX}phrase AS pGlobal ON (pGlobal.languageid = -1 AND pGlobal.varname = pCustom.varname AND pGlobal.fieldname = pCustom.fieldname)
				LEFT JOIN {TABLE_PREFIX}phrasetype AS phrasetype ON (phrasetype.fieldname = pGlobal.fieldname)
				WHERE pCustom.languageid <> -1
				ORDER BY pCustom.varname
			"
		),
		'phrase_replace' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}phrase
					(languageid, varname, text, fieldname, product, username, dateline, version)
				VALUES
					({languageid}, {varname}, {text}, {fieldname}, {product}, {username}, {dateline}, {version})
			"
		),
		/* Phrase API SQL End */

		/* Language API SQL Start */
		'language_count' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS total FROM {TABLE_PREFIX}language
			"
		),

		/* Language API SQL End */

		/* Cron API SQL Start */
		'cron_fetchphrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT varname, text
				FROM {TABLE_PREFIX}phrase
				WHERE languageid = {languageid} AND
					fieldname = 'cron' AND
					varname IN ({title}, {desc}, {logphrase})
			"
		),
		'cron_fetchall' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT cron.*, IF(product.productid IS NULL OR product.active = 1, cron.active, 0) AS effective_active
				FROM {TABLE_PREFIX}cron AS cron
				LEFT JOIN {TABLE_PREFIX}product AS product ON (cron.product = product.productid)
				ORDER BY effective_active DESC, nextrun
			"
		),
		'cron_insertphrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}phrase
					(languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES
					(
						{new_languageid},
						'cron',
						CONCAT('task_', {varname}, '_title'),
						{title},
						{product},
						{username},
						{timenow},
						{product_version}
					),
					(
						{new_languageid},
						'cron',
						CONCAT('task_', {varname}, '_desc'),
						{description},
						{product},
						{username},
						{timenow},
						{product_version}
					),
					(
						{new_languageid},
						'cron',
						CONCAT('task_', {varname}, '_log'),
						{logphrase},
						{product},
						{username},
						{timenow},
						{product_version}
					)
			"
		),
		'cron_fetchswitch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT cron.*,
					IF(product.productid IS NULL OR product.active = 1, 1, 0) AS product_active,
					product.title AS product_title
				FROM {TABLE_PREFIX}cron AS cron
				LEFT JOIN {TABLE_PREFIX}product AS product ON (cron.product = product.productid)
				WHERE cronid = {cronid}
			"
		),
		'cron_switchactive' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}cron SET
					active = IF(active = 1, 0, 1)
				WHERE cronid = {cronid}
			"
		),
		'cron_fetchnext' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT MIN(nextrun) AS nextrun
				FROM {TABLE_PREFIX}cron AS cron
					LEFT JOIN {TABLE_PREFIX}product AS product ON (cron.product = product.productid)
					WHERE cron.active = 1
					AND (product.productid IS NULL OR product.active = 1)
			"
		),
		/* Cron API SQL End */

		'fetch_page_pagetemplate_screenlayout' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT page.*, pagetemplate.screenlayoutid, screenlayout.template AS screenlayouttemplate, pagetemplate.title as templatetitle
				FROM {TABLE_PREFIX}page AS page
				LEFT JOIN {TABLE_PREFIX}pagetemplate AS pagetemplate ON(page.pagetemplateid = pagetemplate.pagetemplateid)
				LEFT JOIN {TABLE_PREFIX}screenlayout AS screenlayout ON(pagetemplate.screenlayoutid = screenlayout.screenlayoutid)
				WHERE page.pageid = {pageid}
			'
		),

		/*
		 *	While this is an *or* query, the specific circumstances will
		 *	allow mysql to use indexes (it does a seperate lookup for each of the
		 *	items in the in clause and one for the "ishomeroute" selection.  This isn't
		 *	ideal but is better than two seperate queries or a union.
		 */
		'get_best_routes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT routenew.*
				FROM {TABLE_PREFIX}routenew AS routenew
				WHERE routenew.prefix IN ({prefix}) OR ishomeroute = 1
			'
		),

		'get_update_route_301'	=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT routeid
				FROM {TABLE_PREFIX}routenew
				WHERE redirect301 = {oldrouteid} OR routeid = {oldrouteid}
			'
		),

		'getPageInfoExport' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT p.*, t.guid as pageTemplateGuid, r.guid as routeGuid, p2.guid as parentGuid
				FROM {TABLE_PREFIX}page p
				LEFT JOIN {TABLE_PREFIX}page p2 ON p.parentid = p2.pageid
				INNER JOIN {TABLE_PREFIX}pagetemplate t ON p.pagetemplateid = t.pagetemplateid
				INNER JOIN {TABLE_PREFIX}routenew r ON p.routeid = r.routeid
				WHERE p.product = {productid}
			'
		),

		'fetchPageList' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT page.*
				FROM {TABLE_PREFIX}page as page,
					{TABLE_PREFIX}routenew as routenew
				WHERE routenew.routeid = page.routeid
					AND routenew.prefix = routenew.regex
			'
		),

		'getUsernameAndId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT userid, username
				FROM {TABLE_PREFIX}user
				WHERE userid != {userid}
					AND (username = {username} OR username = {username_raw})
			',
			'forcetext' => array('username', 'username_raw')
		),

		'getColumnUsername' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SHOW COLUMNS FROM {TABLE_PREFIX}user LIKE {field}"
		),
		'getInfractiongroups' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT orusergroupid, override
					FROM {TABLE_PREFIX}infractiongroup AS infractiongroup
					WHERE infractiongroup.usergroupid IN (-1, {usergroupid})
						AND infractiongroup.pointlevel <= {pointlevel}
					ORDER BY pointlevel"
		),
		'updFriendReqCount' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => "UPDATE {TABLE_PREFIX}user
					SET friendreqcount = IF(friendreqcount > 0, friendreqcount - 1, 0)
					WHERE userid IN ({userid})"
		),
		'updFriendCount' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => "UPDATE {TABLE_PREFIX}user
					SET friendcount = IF(friendcount > 0, friendcount - 1, 0)
					WHERE userid IN ({userid})"
		),
		'delUserList' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'query_string' => "DELETE FROM {TABLE_PREFIX}userlist
					WHERE userid = {userid} OR relationid = {relationid}"
		),
		'updPmText' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => "UPDATE {TABLE_PREFIX}pmtext SET
						touserarray = REPLACE(touserarray,
							'i:{userid};s:{exusrstrlen}:\"{exusername}\";',
							'i:{userid};s:{usrstrlen}:\"{username}\";'
						)
					WHERE touserarray LIKE '%i:{userid};s:{usrstrlen}:\"{username}\";%'"
		),
		'countOtherAdmins' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT COUNT(*) AS users
					FROM {TABLE_PREFIX}user
					WHERE userid <> {userid}
					AND usergroupid IN({usergroupid})"
		),
		'countOtherAdminsGroups' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT COUNT(*) AS users
					FROM {TABLE_PREFIX}user
					WHERE userid <> {userid}
					AND
					(
						usergroupid IN({usergroupid}) OR
						FIND_IN_SET({groupids}, membergroupids)
					)"
		),
		'getUserPictures' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT album.userid
					FROM {TABLE_PREFIX}attachment AS a
					INNER JOIN {TABLE_PREFIX}album AS album ON (a.contentid = album.albumid)
					WHERE a.attachmentid = {attachmentid AND
					a.contenttypeid = {contenttypeid} AND
					album.state IN ({state}) AND
					album.userid = {userid} AND
					album.albumid = {albumid}"
		),
		'fetch_page_template_list' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT pagetemplate.*, screenlayout.varname AS screenlayoutvarname
				FROM {TABLE_PREFIX}pagetemplate AS pagetemplate
				LEFT JOIN {TABLE_PREFIX}screenlayout AS screenlayout ON(screenlayout.screenlayoutid = pagetemplate.screenlayoutid)
				WHERE pagetemplate.title <> \'\' OR
					pagetemplate.pagetemplateid = {pagetemplateid}
			',
		),
		'updateFiledataRefCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}filedata
				SET refcount = IF((refcount <= 0 AND {countChange} < 0), 0, (refcount + {countChange}))
				WHERE filedataid = {filedataid}',
		),
		'getSuperGroups' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT user.*, usergroup.usergroupid
					FROM {TABLE_PREFIX}usergroup AS usergroup
					INNER JOIN {TABLE_PREFIX}user AS user ON(user.usergroupid = usergroup.usergroupid OR FIND_IN_SET(usergroup.usergroupid, user.membergroupids))
					WHERE (usergroup.adminpermissions & {ismoderator})
					GROUP BY user.userid
					ORDER BY user.username",
		),

		//appears unused
		'getCategoryTitle' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT text AS title
					FROM {TABLE_PREFIX}phrase
					WHERE varname = CONCAT(CONCAT('category', {category}), '_title') AND fieldname = 'vbblogcat' AND languageid = 0"
		),

		//appears unused
		'getProfileAlbums' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT
					album.title, album.albumid,
					a.dateline, a.attachmentid, a.caption,
					fd.filesize, fdr.resize_filesize, fdr.resize_dateline, fdr.resize_width, fdr.resize_height, IF(fdr.resize_filesize > 0, 1, 0) AS hasthumbnail
					FROM {TABLE_PREFIX}album AS album
					INNER JOIN {TABLE_PREFIX}attachment AS a ON (a.contentid = album.albumid)
					INNER JOIN {TABLE_PREFIX}filedata AS fd ON (fd.filedataid = a.filedataid)
					LEFT JOIN {TABLE_PREFIX}filedataresize AS fdr ON (fd.filedataid = fdr.filedataid AND fdr.type = 'thumb')
					WHERE
					album.state = 'profile'
					AND
					album.userid = {userid}
					AND
					a.state = 'visible'
					AND
					a.contenttypeid = {contenttypeid}
					ORDER BY
					album.albumid, a.attachmentid",
		),
		'getForumAds' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT ad.*
					FROM {TABLE_PREFIX}ad AS ad
					LEFT JOIN {TABLE_PREFIX}adcriteria AS adcriteria ON(adcriteria.adid = ad.adid)
					WHERE (adcriteria.criteriaid = 'browsing_forum_x' OR adcriteria.criteriaid = 'browsing_forum_x_and_children')",
		),
		'fetchUncachablePhrase' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT text, languageid
				FROM {TABLE_PREFIX}phrase AS phrase
				INNER JOIN {TABLE_PREFIX}phrasetype USING(fieldname)
				WHERE phrase.fieldname = {phrasegroup}
				AND varname = {phrasekey} AND languageid IN (-1, 0, {languageid})"
		),
		'perminfoquery' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.nodeid, node.htmltitle AS nodetitle,usergroup.title AS grouptitle
					FROM {TABLE_PREFIX}permission AS permission
					INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = permission.nodeid)
					INNER JOIN {TABLE_PREFIX}usergroup AS usergroup ON (usergroup.usergroupid = permission.groupid)
					WHERE permissionid = {permissionid}
			"
		),
		'fetchpermgroups' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usergroup.usergroupid, title, COUNT(permission.permissionid) AS permcount
					FROM {TABLE_PREFIX}usergroup AS usergroup
					LEFT JOIN {TABLE_PREFIX}permission AS permission ON (usergroup.usergroupid = permission.groupid)
					GROUP BY usergroup.usergroupid
					HAVING permcount > 0
					ORDER BY title
			"
		),
		'fetchinherit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT groupid, closure.parent as nodeid, IF(permission.nodeid = closure.parent, 0, 1) AS inherited
					FROM {TABLE_PREFIX}permission AS permission
					INNER JOIN {TABLE_PREFIX}closure AS closure ON (closure.child = permission.nodeid)
			"
		),
		'replacePermissions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}permission(
					nodeid, groupid, forumpermissions, moderatorpermissions, createpermissions, forumpermissions2, edit_time,
					maxtags, maxstartertags, maxothertags, maxattachments, maxchannels, channeliconmaxsize
				)
				VALUES (
					{nodeid}, {usergroupid}, '{forumpermissions}', '{moderatorpermissions}', '{createpermissions}', '{forumpermissions2}', '{edit_time}',
					'{maxtags}', '{maxstartertags}', '{maxothertags}', '{maxattachments}', '{maxchannels}', '{channeliconmaxsize}'
				)
			"
		),
		'fetchperms' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT permissionid, usergroup.title AS ug_title, node.htmltitle AS node_title, IF({order_first} = 'usergroup', CONCAT(usergroup.title, node.htmltitle), CONCAT(node.htmltitle, usergroup.title)) as sortfield
					FROM {TABLE_PREFIX}permission AS permission
					INNER JOIN {TABLE_PREFIX}usergroup AS usergroup ON (usergroup.usergroupid = permission.groupid)
					INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = permission.nodeid)
					GROUP BY usergroup.usergroupid
					ORDER BY sortfield
			"
		),
		'fetchExistingPermsForGroup' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT permission.nodeid
				FROM {TABLE_PREFIX}permission AS permission
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = permission.nodeid)
				WHERE permission.groupid = {groupid}
			"
		),
		'fetchExistingPermsForGroupLimit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT permission.nodeid
				FROM {TABLE_PREFIX}permission AS permission
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = permission.nodeid)
				INNER JOIN {TABLE_PREFIX}closure AS closure ON (closure.child = permission.nodeid)
				WHERE permission.groupid = {groupid}
					AND closure.parent = {parentid}
			"
		),
		'fetchTemplateWithStyle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT template.*, style.title AS style, IF(template.styleid = 0, -1, template.styleid) AS styleid, MD5(template.template_un) AS hash
				FROM {TABLE_PREFIX}template AS template
				LEFT JOIN {TABLE_PREFIX}style AS style USING(styleid)
				WHERE templateid = {templateid}
			"
		),
		'replaceIntoPhrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}phrase (languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES ({languageid}, {fieldname}, {varname}, {text}, {product}, {enteredBy}, {dateline}, {version})
			"
		),
		'fetchInfractionsByUser' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT infraction.*, node.userid, user.username AS whoadded_username, user2.username
				FROM {TABLE_PREFIX}infraction AS infraction
				LEFT JOIN {TABLE_PREFIX}node AS node ON (infraction.nodeid = node.nodeid)
				LEFT JOIN {TABLE_PREFIX}user AS user ON (node.userid = user.userid)
				LEFT JOIN {TABLE_PREFIX}user AS user2 ON (infraction.infracteduserid = user2.userid)
				WHERE infraction.nodeid = {nodeid}
			"
		),
		'fetchInfractionsByUser2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT infraction.*, node.userid, user.username AS whoadded_username, user2.username, user3.username AS action_username, node.publishdate
				FROM {TABLE_PREFIX}infraction AS infraction
				LEFT JOIN {TABLE_PREFIX}node AS node ON (infraction.nodeid = node.nodeid)
				LEFT JOIN {TABLE_PREFIX}user AS user ON (node.userid = user.userid)
				LEFT JOIN {TABLE_PREFIX}user AS user2 ON (infraction.infracteduserid = user2.userid)
				LEFT JOIN {TABLE_PREFIX}user AS user3 ON (infraction.actionuserid = user3.userid)
				WHERE infraction.nodeid = {nodeid}
			"
		),
		'fetchCountInfractionsByInfractionLvl' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count, infractionlevelid
				FROM {TABLE_PREFIX}infraction
				GROUP BY infractionlevelid
				ORDER BY count DESC
			"
		),
		/* Class BBCode */
		'fetchSmilies' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *, LENGTH(smilietext) AS smilielen
				FROM {TABLE_PREFIX}smilie
				ORDER BY smilielen DESC
			"
		),

		/* Human Verify Question */
		'hv_question_fetch_answer' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT hvquestion.questionid, COUNT(*) AS answers
				FROM {TABLE_PREFIX}hvquestion AS hvquestion
				LEFT JOIN {TABLE_PREFIX}hvanswer AS hvanswer
					ON (hvquestion.questionid = hvanswer.questionid)
				WHERE hvanswer.answerid IS NOT NULL
					OR hvquestion.regex <> ''
				GROUP BY hvquestion.questionid
				ORDER BY RAND()
				LIMIT 1
			"
		),

		'hv_question_fetch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT question.questionid, question.regex
				FROM {TABLE_PREFIX}humanverify AS hv
				LEFT JOIN {TABLE_PREFIX}hvquestion AS question ON (hv.answer = question.questionid)
				WHERE hash = {hash}
					AND viewed = 1
			"
		),

		//PM Recipients
		'fetchPmRecipients' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT usertextfield.*, user.*, userlist.type
				FROM {TABLE_PREFIX}user AS user
				LEFT JOIN {TABLE_PREFIX}usertextfield AS usertextfield ON(usertextfield.userid=user.userid)
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist ON(user.userid = userlist.userid AND userlist.relationid = {userid} AND userlist.type = 'buddy')
				WHERE user.username IN({usernames})
			"
		),
		'chooseModLog' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT moderatorlog.userid, user.username
				FROM {TABLE_PREFIX}moderatorlog AS moderatorlog
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				ORDER BY username
			"
		),

		/* Admincp API Log */
		'api_fetchclientnames' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT clientname
				FROM {TABLE_PREFIX}apiclient AS apiclient
				ORDER BY clientname
			"
		),
		'api_fetchclientusers' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT apiclient.userid, user.username
				FROM {TABLE_PREFIX}apiclient AS apiclient
				LEFT JOIN {TABLE_PREFIX}user AS user USING(userid)
				ORDER BY username
			"
		),
		'api_fetchclientbyid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT apiclient.*, user.username FROM {TABLE_PREFIX}apiclient AS apiclient
				LEFT JOIN {TABLE_PREFIX}user AS user using(userid)
				WHERE apiclientid = {apiclientid}
			"
		),

		/* Admincp API Stats */
		'api_fetchmaxclient' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT apilog.apiclientid, apiclient.clientname, COUNT(*) as c
				FROM {TABLE_PREFIX}apilog AS apilog
				LEFT JOIN {TABLE_PREFIX}apiclient AS apiclient using(apiclientid)
				GROUP BY apilog.apiclientid
				ORDER BY c DESC
			"
		),
		'api_fetchmaxmethod' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT apilog.method, COUNT(*) as c
				FROM {TABLE_PREFIX}apilog AS apilog
				GROUP BY apilog.method
				ORDER BY c DESC
			"
		),
		'api_methodcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS total FROM (
					SELECT method, COUNT(*) FROM {TABLE_PREFIX}apilog AS apilog
					GROUP BY method
				) AS t
			"
		),
		'api_methodlogs' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT method, COUNT(*) AS c
				FROM {TABLE_PREFIX}apilog AS apilog
				GROUP BY method
				ORDER BY c DESC
				LIMIT {startat}, {limit}
			"
		),
		'api_clientcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS total FROM (
					SELECT apiclientid, COUNT(*)
					FROM {TABLE_PREFIX}apilog AS apilog
					GROUP BY apiclientid
				) AS t
			"
		),
		'api_clientlogs' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT apilog.apiclientid, apiclient.userid, apiclient.clientname, user.username, COUNT(*) as c
				FROM {TABLE_PREFIX}apilog AS apilog
				LEFT JOIN {TABLE_PREFIX}apiclient AS apiclient ON (apiclient.apiclientid = apilog.apiclientid)
				LEFT JOIN {TABLE_PREFIX}user AS user ON (apiclient.userid = user.userid)
				GROUP BY apilog.apiclientid
				ORDER BY c DESC
				LIMIT {startat}, {limit}
			"
		),
		'updt_style_parentlist' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => "
					UPDATE {TABLE_PREFIX}style SET
						parentid = -1,
						parentlist = CONCAT(styleid,',-1')
					WHERE parentid = 0
			"
		),
		'fetchPhrassesByLanguage' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "SELECT * FROM {TABLE_PREFIX}phrase
				WHERE varname = {varname} AND
				fieldname = {fieldname}
				ORDER BY languageid
				LIMIT 1"
		),
		'fetchProfileFields' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "
				SELECT * FROM {TABLE_PREFIX}profilefield AS profilefield
				LEFT JOIN {TABLE_PREFIX}profilefieldcategory AS profilefieldcategory ON
				(profilefield.profilefieldcategoryid = profilefieldcategory.profilefieldcategoryid)
				ORDER BY profilefield.form, profilefieldcategory.displayorder, profilefield.displayorder"
		),
		'fetchActiveSubscriptions' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "
				SELECT status, regdate, expirydate, subscriptionlogid, subscription.subscriptionid
				FROM {TABLE_PREFIX}subscriptionlog AS subscriptionlog
				INNER JOIN {TABLE_PREFIX}subscription AS subscription USING (subscriptionid)
				WHERE userid = {userid}
				ORDER BY status DESC, regdate"
		),

		'node_checktopicread' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN {TABLE_PREFIX}noderead AS noderead ON (noderead.nodeid = node.nodeid AND noderead.userid = {userid})
				WHERE node.parentid = {parentid}
					AND node.inlist = 1
					AND node.protected = 0
					AND IF(node.lastcontent >0, node.lastcontent, node.created) > {noderead}
					AND (noderead.nodeid IS NULL OR noderead.readtime < IF(node.lastcontent >0, node.lastcontent, node.created))
			"
		),
		'node_checktopicreadinchannels' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN {TABLE_PREFIX}noderead AS topicread ON (topicread.nodeid = node.nodeid AND topicread.userid = {userid})
				LEFT JOIN {TABLE_PREFIX}noderead AS channelread ON (channelread.nodeid = node.parentid AND channelread.userid = {userid})
				WHERE node.parentid IN ({children})
					AND node.nodeid = node.starter
					AND node.inlist = 1
					AND node.protected = 0
					AND IF(node.lastcontent >0, node.lastcontent, node.created) > IF(topicread.readtime IS NULL, {cutoff}, topicread.readtime)
					AND IF(node.lastcontent >0, node.lastcontent, node.created) > IF(channelread.readtime IS NULL, {cutoff}, channelread.readtime)
					AND IF(node.lastcontent >0, node.lastcontent, node.created) > {cutoff}
			"
		),
		'mailqueue_updatecount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}datastore SET data = data + {counter} WHERE title = 'mailqueue'
			"
		),
		'mailqueue_updatecount2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}datastore SET
					data = {newmail},
					data = IF(data < 0, 0, data)
				WHERE title = 'mailqueue'
			"
		),
		'mailqueue_locktable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				LOCK TABLES {TABLE_PREFIX}mailqueue WRITE
			"
		),
		'fcmqueue_locktable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				LOCK TABLES {TABLE_PREFIX}fcmessage_queue WRITE
			"
		),
		'mailqueue_fetch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}mailqueue
				ORDER BY mailqueueid
				LIMIT {limit}
			"
		),
		'unlock_tables' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UNLOCK TABLES
			"
		),

		/* AD API */
		'ad_replaceadtemplate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}template SET
					styleid = {styleid},
					title = {title},
					template = {template},
					template_un = {template_un},
					templatetype = 'template',
					dateline = {timenow},
					username = {username},
					version = {templateversion},
					product = {product}
			"
		),
		/* needed for assert_cp_sessionhash() */
		'cpSessionUpdate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE LOW_PRIORITY {TABLE_PREFIX}cpsession
				SET dateline = {timenow}
				WHERE userid = {userid}
					AND hash = {hash}
			"
		),
		// assertor in admincp/language.php [START]
		'getLanguagePhrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT phrase.varname, phrase.text, phrase.fieldname
				FROM {TABLE_PREFIX}phrase AS phrase
				LEFT JOIN {TABLE_PREFIX}phrasetype AS phrasetype USING (fieldname)
				WHERE languageid = -1 AND phrasetype.special = 0
				ORDER BY varname
			"
		),
		// assertor in admincp/language.php [END]

		'getNewThreads' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT
					user.userid, user.username, user.email, user.languageid, user.usergroupid, user.membergroupids,
					user.timezoneoffset, IF(user.options & {dstonoff}, 1, 0) AS dstonoff,
					user.emailnotification,
					node.nodeid, node.routeid, node.htmltitle, node.publishdate, node.parentid, node.lastcontentid,
					node.lastcontent, node.userid AS authorid, node.authorname,
					node.open, node.totalcount, node.lastcontentauthor, node.lastauthorid, node.prefixid,
					subscribediscussion.subscribediscussionid
				FROM {TABLE_PREFIX}subscribediscussion AS subscribediscussion
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = subscribediscussion.discussionid)
				INNER JOIN {TABLE_PREFIX}user AS user ON (user.userid = subscribediscussion.userid)
				LEFT JOIN {TABLE_PREFIX}usergroup AS usergroup ON (usergroup.usergroupid = user.usergroupid)
				WHERE
					node.lastcontent > {lastdate} AND
					node.showpublished = 1 AND
					node.nodeid = node.starter AND
					user.usergroupid <> 3 AND
					(usergroup.genericoptions & {isnotbannedgroup})
			"
		),

		'getNewPosts' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT
					IFNULL(user.username, node.authorname) AS postusername,
					node.nodeid, node.routeid, node.userid, node.htmltitle, node.publishdate, node.contenttypeid
					FROM {TABLE_PREFIX}node AS node
					LEFT JOIN {TABLE_PREFIX}user AS user ON (user.userid = node.userid)
					INNER JOIN {TABLE_PREFIX}closure AS closure ON ( closure.child = node.nodeid )
					WHERE closure.parent = {threadid} AND closure.depth = 1 AND
						node.showpublished = 1 AND
						user.usergroupid <> 3 AND
						node.publishdate > {lastdate}
					ORDER BY node.publishdate
			"
		),
		'getNewForums' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.userid, user.username, user.email, user.languageid, user.usergroupid, user.membergroupids,
					user.timezoneoffset, IF(user.options & {dstonoff}, 1, 0) AS dstonoff,
					node.nodeid AS forumid, node.routeid, node.htmltitle AS title_clean, node.title
				FROM {TABLE_PREFIX}subscribediscussion AS subscribediscussion
				INNER JOIN {TABLE_PREFIX}node AS node
					ON (node.nodeid = subscribediscussion.discussionid AND
						node.contenttypeid = {channelcontenttype})
				INNER JOIN {TABLE_PREFIX}user AS user
					ON (user.userid = subscribediscussion.userid)
				LEFT JOIN {TABLE_PREFIX}usergroup AS usergroup
					ON (usergroup.usergroupid = user.usergroupid)
				WHERE user.emailnotification = {type} AND
					node.lastcontent > {lastdate} AND
					user.usergroupid <> 3 AND
					(usergroup.genericoptions & {isnotbannedgroup})
				"
		),
		'fetchForumThreads' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT forum.htmltitle AS forumhtmltitle, thread.nodeid, thread.routeid, thread.htmltitle,
					thread.publishdate, thread.parentid AS forumid, thread.lastcontent, thread.open, thread.textcount AS replycount,
					thread.authorname, thread.userid, thread.lastcontentauthor, thread.publishdate AS dateline, thread.prefixid
				FROM {TABLE_PREFIX}node AS thread
				INNER JOIN {TABLE_PREFIX}closure AS closure ON ( closure.child = thread.nodeid )
				INNER JOIN {TABLE_PREFIX}node AS forum ON ( forum.nodeid = thread.parentid)
				WHERE closure.parent = {forumid} AND closure.depth >= 1 AND
					thread.nodeid = thread.starter AND
					thread.lastcontent > {lastdate} AND
					thread.showpublished = 1
				"
		),
		'getSubscriptionsReminders' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT subscriptionlog.subscriptionid, subscriptionlog.userid, subscriptionlog.expirydate, user.username, user.email, user.languageid
				FROM {TABLE_PREFIX}subscriptionlog AS subscriptionlog
				LEFT JOIN {TABLE_PREFIX}user AS user ON (user.userid = subscriptionlog.userid)
				WHERE subscriptionlog.expirydate >= {time1}
					AND subscriptionlog.expirydate <= {time2}
					AND subscriptionlog.status = 1
			"
		),
		'getBannedUsers' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.*,
					userban.usergroupid AS banusergroupid, userban.displaygroupid AS bandisplaygroupid, userban.customtitle AS bancustomtitle, userban.usertitle AS banusertitle
				FROM {TABLE_PREFIX}userban AS userban
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				WHERE liftdate <> 0 AND liftdate < {liftdate}
			"
		),
		'cleanupUA' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}useractivation
				WHERE dateline < {time} AND
					(type = 1 OR (type = 0 and usergroupid = 2))
			"
		),
		'fetchEvents' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT event.eventid, event.title, recurring, recuroption, dateline_from, dateline_to, IF (dateline_to = 0, 1, 0) AS singleday,
					dateline_from AS dateline_from_user, dateline_to AS dateline_to_user, utc, dst, event.calendarid,
					subscribeevent.userid, subscribeevent.lastreminder, subscribeevent.subscribeeventid, subscribeevent.reminder,
					user.email, user.languageid, user.usergroupid, user.username, user.timezoneoffset, IF(user.options & 128, 1, 0) AS dstonoff,
					calendar.title AS calendar_title
				FROM {TABLE_PREFIX}event AS event
				INNER JOIN {TABLE_PREFIX}subscribeevent AS subscribeevent ON (subscribeevent.eventid = event.eventid)
				INNER JOIN {TABLE_PREFIX}user AS user ON (user.userid = subscribeevent.userid)
				LEFT JOIN {TABLE_PREFIX}calendar AS calendar ON (event.calendarid = calendar.calendarid)
				WHERE ((dateline_to >= {beginday} AND dateline_from < {endday}) OR (dateline_to = 0 AND dateline_from >= {beginday} AND dateline_from <= {endday} ))
					AND event.visible = 1
			"
		),
		'fetchFeeds' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT rssfeed.*, rssfeed.options AS rssoptions, user.*, channel.nodeid as channelid
					FROM {TABLE_PREFIX}rssfeed AS rssfeed
					INNER JOIN {TABLE_PREFIX}user AS user ON (user.userid = rssfeed.userid)
					INNER JOIN {TABLE_PREFIX}node AS channel ON(channel.nodeid = rssfeed.nodeid)
					WHERE rssfeed.options & {bf_misc_feedoptions_enabled}
			"
		),
		'fetchRSSFeeds' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *, node.title AS threadtitle
				FROM {TABLE_PREFIX}rsslog AS rsslog
				INNER JOIN {TABLE_PREFIX}rssfeed AS rssfeed ON(rssfeed.rssfeedid = rsslog.rssfeedid)
				INNER JOIN {TABLE_PREFIX}node AS node ON(node.nodeid = rsslog.itemid AND node.starter = node.nodeid)
				WHERE rsslog.topicactioncomplete = 0
					AND rsslog.itemtype = 'topic'
					AND rsslog.topicactiontime <> 0
					AND rsslog.topicactiontime < {TIMENOW}
				"
		),
		'fetchUsersToActivate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT user.userid, user.usergroupid, username, email, activationid, user.languageid
				FROM {TABLE_PREFIX}user AS user
				LEFT JOIN {TABLE_PREFIX}useractivation AS useractivation ON (user.userid=useractivation.userid AND type = 0)
				WHERE user.usergroupid = 3
					AND ((joindate >= {time1} AND joindate <= {time2}) OR (joindate >= {time3} AND joindate <= {time4}))
					AND NOT (user.options & {noactivationmails})
				"
		),
		'removeProfileVisits' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT userid
				FROM {TABLE_PREFIX}profilevisitor
				WHERE visible = 1
				GROUP BY userid
				HAVING COUNT(*) > {profilemaxvisitors}
				"
		),
		'getUserExpiredInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT i.nodeid, i.infracteduserid, i.infractednodeid, i.points, u.username
				FROM {TABLE_PREFIX}infraction AS i
				LEFT JOIN {TABLE_PREFIX}user AS u ON(u.userid = i.infracteduserid)
				WHERE i.expires <= {timenow}
					AND i.expires <> 0
					AND i.action = 0
				"
		),
		'updateSettingsDefault' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => "
				UPDATE {TABLE_PREFIX}setting
				SET value = defaultvalue
				WHERE varname = 'templateversion'
				"
		),

		// admincp - index [START]
		'getCustomAvatarFilesizeSum' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT SUM(filesize) AS size FROM {TABLE_PREFIX}customavatar
			"
		),
		'showVariablesLike' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SHOW VARIABLES LIKE {var}
			"
		),
		'getIncompleteAdminMessages' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT adminmessage.adminmessageid
			FROM {TABLE_PREFIX}adminmessage AS adminmessage
			INNER JOIN {TABLE_PREFIX}adminlog AS adminlog ON (adminlog.script = adminmessage.script AND adminlog.action = adminmessage.action)
			WHERE adminmessage.status = 'undone'
				AND adminmessage.script <> ''
				AND adminlog.dateline > adminmessage.dateline
			GROUP BY adminmessage.adminmessageid
			"
		),
		'getUserSessionsCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT DISTINCT userid FROM {TABLE_PREFIX}session WHERE userid <> 0 AND lastactivity > {datecut}"
		),
		// admincp - index [END]

		'admincpSearch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT varname, fieldname, MATCH (text) AGAINST ({terms} IN BOOLEAN MODE) AS relevance
				FROM {TABLE_PREFIX}phrase
				WHERE fieldname IN ('cphelptext', 'cphome', 'cpglobal', 'global')
					AND MATCH (text) AGAINST ({terms} IN BOOLEAN MODE)
				ORDER BY relevance DESC"
		),

		// admincp - email [START]
		'emailReplaceUserActivation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}useractivation
					(userid, dateline, activationid, type, usergroupid)
				VALUES
					({userid}, {dateline}, {activateid} , {type}, {usergroupid})
			",
		),
		// admincp - email [END]

		// admincp - deployads [START]
		'updateTemplateAdDeploy' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}template
				SET
					template = {template},
					template_un = {template_un},
					dateline = {dateline},
					username = {username}
				WHERE
					title = {title} AND
					styleid = -1 AND
					product IN ('', 'vbulletin')
			",
		),
		// admincp - deployads [END]

		// admincp - plugin [START]
		'getHookInfo' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT hook.*,
					IF(product.productid IS NULL, 0, 1) AS foundproduct,
					IF(hook.product = 'vbulletin', 1, product.active) AS productactive
				FROM {TABLE_PREFIX}hook AS hook
				LEFT JOIN {TABLE_PREFIX}product AS product ON(product.productid = hook.product)
				WHERE hookid = {hookid}
			",
		),
		'getHooktypePhrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT varname
				FROM {TABLE_PREFIX}phrase
				WHERE varname LIKE 'hooktype_%'
			",
		),
		'getHookProductInfo' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT hook.*, IF(hook.product = '', 'vbulletin', product.title) AS producttitle,
				description, version, url, versioncheckurl, product.active AS productactive
				FROM {TABLE_PREFIX}hook AS hook
				LEFT JOIN {TABLE_PREFIX}product AS product ON (hook.product = product.productid)
				ORDER BY producttitle, hook.title
			",
		),
		'getHookProductList' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT hook.hookname, hook.template, hook.arguments, hook.hookid, hook.product
				FROM {TABLE_PREFIX}hook AS hook
				LEFT JOIN {TABLE_PREFIX}product AS product ON (hook.product = product.productid)
				WHERE hook.active = 1 AND (IFNULL(product.active, 0) = 1 OR hook.product = 'vbulletin')
				ORDER BY hook.hookname, hook.hookorder
			",
		),
		// @TODO define how to remove package related info
		'removePackage' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE package, route, contenttype
				FROM {TABLE_PREFIX}package AS package
				LEFT JOIN {TABLE_PREFIX}routenew AS route
					ON route.packageid = package.packageid
				LEFT JOIN {TABLE_PREFIX}contenttype AS contenttype
					ON contenttype.packageid = package.packageid
				WHERE productid = {productid}
			",
		),
		'removePackageTemplate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE t1
				FROM {TABLE_PREFIX}template AS t1
				INNER JOIN {TABLE_PREFIX}template AS t2 ON (t1.title = t2.title AND t2.product = {productid} AND t2.styleid = -1)
				WHERE t1.styleid = -10
			",
		),
		'removePackageTypesFetch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT contenttypeid
				FROM {TABLE_PREFIX}contenttype AS c
				INNER JOIN {TABLE_PREFIX}package AS p ON (c.packageid = p.packageid)
				WHERE
					p.productid = {productid}
						AND
					c.canattach = 1
			",
		),
		'installProductPhraseTypeInsert' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				INSERT IGNORE INTO {TABLE_PREFIX}phrasetype
					(fieldname, title, editrows, product)
				VALUES
					({fieldname}, {title}, {editrows}, {product})
			",
		),
		// admincp - plugin [END]

		// we assume that there's only one instance of this type of container
		'getBlogSidebarModules' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT m.*, w2.guid
				FROM {TABLE_PREFIX}widgetinstance container
				INNER JOIN {TABLE_PREFIX}widget w ON w.widgetid = container.widgetid AND w.guid = 'vbulletin-widget_container-4eb423cfd6dea7.34930867'
				INNER JOIN {TABLE_PREFIX}widgetinstance m ON m.containerinstanceid = container.widgetinstanceid
				INNER JOIN {TABLE_PREFIX}widget w2 ON w2.widgetid = m.widgetid
				WHERE container.pagetemplateid = {blogPageTemplate}
			",
		),

		'getWidgetTemplates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT m.widgetinstanceid, w.widgetid, w.template
				FROM {TABLE_PREFIX}widgetinstance m
				INNER JOIN {TABLE_PREFIX}widget w ON w.widgetid = m.widgetid
				WHERE m.widgetinstanceid IN ({modules})
			",
		),

		'fetchUserFields' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SHOW COLUMNS FROM {TABLE_PREFIX}userfield
			",
		),

		// mostly needed for unit test.
		'addUserField' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				ALTER TABLE {TABLE_PREFIX}userfield ADD field{profilefieldid} MEDIUMTEXT NOT NULL
			",
		),

		'cacheExpireDelete' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE cache, cacheevent
				FROM {TABLE_PREFIX}cache AS cache
				LEFT JOIN {TABLE_PREFIX}cacheevent AS cacheevent USING (cacheid)
				WHERE cache.expires BETWEEN {timefrom} AND {timeto}
			",
		),

		'cacheAndEventDelete' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE cache, cacheevent
				FROM {TABLE_PREFIX}cache AS cache
				LEFT JOIN {TABLE_PREFIX}cacheevent AS cacheevent USING (cacheid)
				WHERE cache.cacheid IN ({cacheid})
			",
		),

		'getStylesForMaster' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT styleid
				FROM {TABLE_PREFIX}style
				WHERE INSTR(CONCAT(',', parentlist, ','), {masterid})
			",
		),

		'getStylevarData' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT stylevar.*
				FROM {TABLE_PREFIX}stylevar AS stylevar
				INNER JOIN {TABLE_PREFIX}stylevardfn AS stylevardfn
				ON (stylevar.stylevarid = stylevardfn.stylevarid)
				WHERE stylevar.styleid IN ({styles})
				AND stylevardfn.styleid = {masterid}
			",
		),

		'deleteStylevarData' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				DELETE stylevar, stylevardfn
				FROM {TABLE_PREFIX}stylevar AS stylevar
				INNER JOIN {TABLE_PREFIX}stylevardfn AS stylevardfn
				ON (stylevar.stylevarid = stylevardfn.stylevarid)
				WHERE stylevardfn.stylevarid = {stylevar}
				AND stylevardfn.product IN ({products})
				AND stylevar.styleid IN ({styles})
			",
		),

		'deleteStylevarPhrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}phrase
				WHERE fieldname = 'style'
				AND product IN ({products})
				AND varname IN ({phrases})
			",
		),
		'updateLastVisit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET lastvisit = lastactivity,
				lastactivity = {timenow}
				WHERE userid = {userid}
			",
		),
		'decrementFiledataRefcount' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}filedata
			SET refcount = (refcount - 1)
			WHERE filedataid IN ({filedataid}) AND refcount > 0"
		),
		'incrementFiledataRefcountAndMakePublic' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}filedata
			SET refcount = (refcount + 1),
			publicview = 1
			WHERE filedataid IN ({filedataid})"
		),
		'checkFiledataConsistency' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			// LENGTH counts bytes, not chars. Also, we shouldn't need to check if filedata is
			// null/empty, which is the case when attachments are stored in the filesystem, since
			// this query is only called when attachments are stored in the database.
			'query_string' => "
				SELECT
					IF(filehash = MD5(filedata), 1, 0) AS filehash_matches,
					IF(filesize = LENGTH(filedata), 1, 0) AS filesize_matches
				FROM {TABLE_PREFIX}filedata AS fd
				WHERE filedataid = {filedataid}
			",
		),
		'attachmentsByContentType' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT a.attachmentid, a.contenttypeid
				FROM {TABLE_PREFIX}filedata AS fd
				LEFT JOIN {TABLE_PREFIX}attachment AS a ON (a.filedataid = fd.filedataid)
				WHERE contenttypeid = {ctypeid}
			",
		),
		'getModLogs' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT type, username, dateline
				FROM {TABLE_PREFIX}moderatorlog AS modlog
				INNER JOIN {TABLE_PREFIX}user AS user USING(userid)
				WHERE nodeid = {nodeid}
				ORDER BY modlog.dateline DESC
			"
		),
		'editlog_replacerecord' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}editlog
					(nodeid, userid, username, dateline, reason, hashistory)
				VALUES
					({nodeid}, {userid}, {username}, {timenow}, {reason}, {hashistory})
			",
		),
		'getModeratedTopics' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node
				INNER JOIN {TABLE_PREFIX}closure
				WHERE showapproved = 0
 				AND child = nodeid
				AND starter = nodeid
 				AND parent IN ({rootids})
				AND contenttypeid NOT IN ({typeids})
			",
		),
		'getModeratedReplies' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node
				INNER JOIN {TABLE_PREFIX}closure
				WHERE showapproved = 0
 				AND child = nodeid
				AND starter != nodeid
 				AND parent IN ({rootids})
				AND contenttypeid NOT IN ({typeids})
			",
		),
		'getModeratedVisitorMessages' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(nodeid) AS count
				FROM {TABLE_PREFIX}node
				WHERE showapproved = 0
				AND parentid = {typeid}
			",
		),
		'getSiteForums' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT n.nodeid, n.title, n.htmltitle AS title_clean, n.lastcontent AS lastpost, n.routeid
				FROM {TABLE_PREFIX}node n
				WHERE n.nodeid IN ({viewable_forums}) AND n.nodeid >= {startat} AND n.showapproved > 0 AND n.showpublished > 0 AND n.open = 1 AND n.inlist = 1
				ORDER BY n.nodeid
				LIMIT {perpage}
			",
		),
		'writeAdminUtilSession' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				REPLACE INTO {TABLE_PREFIX}adminutil
					(title, text)
				VALUES
					('sitemapsession', {session})
			",
		),
		'getUserInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT infraction.*, node.publishdate
				FROM {TABLE_PREFIX}infraction AS infraction
				LEFT JOIN {TABLE_PREFIX}node AS node ON(node.nodeid = infraction.nodeid)
				WHERE infraction.infracteduserid = {infracteduserid}
				ORDER BY node.publishdate DESC
			",
		),
		'getReplacementTemplates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT templateid, title, styleid, template
				FROM {TABLE_PREFIX}template
				WHERE templatetype = 'replacement'
				AND templateid IN({templateids})
				ORDER BY title
			",
		),
		'userstylevarCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*)
				FROM {TABLE_PREFIX}userstylevar
				WHERE userid = {userid}
			",
		),
		'getWidgetdefinition' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT widgetdefinition.*, widget.template
				FROM {TABLE_PREFIX}widgetdefinition AS widgetdefinition
				JOIN {TABLE_PREFIX}widget AS widget ON (widgetdefinition.widgetid = widget.widgetid)
				WHERE widgetdefinition.widgetid IN({widgetid})
			",
		),
		'fetchPhraseList' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT p.languageid, p.varname, p.text
					FROM {TABLE_PREFIX}phrase AS p
					WHERE p.varname IN ({varname}) AND p.languageid IN ({languageid}) ORDER BY p.languageid DESC
			",
		),
		'getChannelsToMark' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT ch.nodeid FROM {TABLE_PREFIX}closure AS cl
				INNER JOIN {TABLE_PREFIX}channel AS ch ON ch.nodeid = cl.child
				INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = ch.nodeid
				WHERE cl.parent = {nodeid} AND ch.nodeid IN ({canview}) AND n.lastcontent > {cutoff}
			",
		),
		'channelsMarkRead' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}noderead (nodeid, userid, readtime)
				SELECT ch.nodeid, {userid}, {readtime}
				FROM {TABLE_PREFIX}closure AS cl
				INNER JOIN {TABLE_PREFIX}channel AS ch ON ch.nodeid = cl.child
				INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = ch.nodeid
				WHERE cl.parent = {nodeid} AND ch.nodeid IN ({canview}) AND n.lastcontent > {cutoff}
				ON DUPLICATE KEY UPDATE readtime = {readtime};
			",
		),
		'startersMarkRead' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}noderead (nodeid, userid, readtime)
				SELECT n.nodeid, {userid}, {readtime}
				FROM {TABLE_PREFIX}closure AS cl
				INNER JOIN {TABLE_PREFIX}channel AS ch ON ch.nodeid = cl.child
				INNER JOIN {TABLE_PREFIX}node AS n ON n.parentid = ch.nodeid AND n.starter = n.nodeid
				WHERE cl.parent = {nodeid} AND ch.nodeid IN ({canview})  AND n.lastcontent > {cutoff}
				ON DUPLICATE KEY UPDATE readtime = {readtime};
			",
		),
		'decUserReputation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}user SET reputation = reputation - {penalty}
				WHERE userid = {userid}
			",
		),
		'incUserReputation' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}user SET reputation = reputation + {bonus}
				WHERE userid = {userid}
			",
		),
		'usersCountStartsWithNumber' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT COUNT(*) FROM {TABLE_PREFIX}user
				WHERE username REGEXP '^[^a-z].?' AND
					usergroupid IN ({usergroupid})
			",
		),
		'replaceSigpic' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "REPLACE INTO {TABLE_PREFIX}sigpicnew (userid, filedataid)
				VALUES
				({userid}, {filedataid})
			",
		),
		'getPagesWithoutGUID' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT * FROM {TABLE_PREFIX}page
				WHERE guid = '' OR guid IS NULL
			",
		),
		'showWidgetTableColumns' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SHOW COLUMNS FROM {TABLE_PREFIX}widget"
		),
		'showWidgetDefintionTableColumns' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SHOW COLUMNS FROM {TABLE_PREFIX}widgetdefinition"
		),
		'fetchMasterStylevars' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT stylevar.stylevarid
				FROM {TABLE_PREFIX}stylevar AS stylevar
				LEFT JOIN {TABLE_PREFIX}stylevardfn AS stylevardfn
				USING (stylevarid)
				WHERE stylevar.styleid = -1
				AND stylevardfn.product IS NULL"
		),

		// vB4 api
		'fetchDataForBuddyList' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT user.userid,
					user.username,
					user.options & {bit_useroptions_invisible} AS invisible,
					session.lastactivity
				FROM {TABLE_PREFIX}userlist AS userlist
				INNER JOIN {TABLE_PREFIX}user AS user
					ON user.userid = userlist.relationid
				LEFT JOIN {TABLE_PREFIX}session AS session
					ON session.userid = user.userid
					AND session.lastactivity > {cutoff}
				WHERE userlist.userid = {userid}
					AND userlist.type = 'follow'
					AND userlist.friend = 'yes'
				ORDER BY user.username ASC,
					session.lastactivity DESC
				"
		),
		//this is a bit awkward because it's very inside baseball for MySQL and ideally would
		//be part of the query that needs it, but I can't figure a good way to do that.  We
		//need to make sure that the group_concat is has a big enough limit to handle the
		//values procesed.  The default 1024 isn't that generous and hitting it quietly truncates
		//instead of causing an error.
		'setGroupConcatSize' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "SET SESSION group_concat_max_len = {maxlen}",
		),
	);

	public function getModeratorInfo($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['condition']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'condition' => vB_Cleaner::TYPE_NOCLEAN, // cleaned in conditionsToFilter
			));

			$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
			$queryBuilder = new $className($db, false);
			$where = $queryBuilder->conditionsToFilter($params['condition']);

			$sql = "SELECT user.userid, usergroupid, username, displaygroupid, moderatorid ";
			$sql.= "FROM " . TABLE_PREFIX . "moderator AS moderator ";
			$sql.= "INNER JOIN " . TABLE_PREFIX . "user AS user USING(userid) ";
			$sql.= "WHERE " . $where;

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function getChangelogData($params, $db, $check_only = false) {
		if ($check_only)
		{
			return isset($params[vB_dB_Query::PARAM_LIMITPAGE]);
		}
		else
		{
			// since params can change, we have to unset unused params
			// so that the sql is correct.
			// see vB_UserChangeLog->sql_select_core()
			$cleanList = array(
				'userchangelog.userid' => vB_Cleaner::TYPE_UINT,
				'userchangelog.fieldname' => vB_Cleaner::TYPE_STR,
				'userchangelog.oldvalue' => vB_Cleaner::TYPE_STR,
				'userchangelog.newvalue' => vB_Cleaner::TYPE_STR,
				'time_start' => vB_Cleaner::TYPE_UINT,
				'time_end' => vB_Cleaner::TYPE_UINT,
				'just_count' => vB_Cleaner::TYPE_INT,
				vB_dB_Query::PARAM_LIMITSTART => vB_Cleaner::TYPE_UINT,
				vB_dB_Query::PARAM_LIMITPAGE => vB_Cleaner::TYPE_UINT,
				vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT,
				vB_dB_Query::TYPE_KEY => vB_Cleaner::TYPE_NOCLEAN,
			);
			// also need to escape strings
			$strList = array(
				'userchangelog.oldvalue' => vB_Cleaner::TYPE_STR,
				'userchangelog.newvalue' => vB_Cleaner::TYPE_STR,
				'userchangelog.fieldname' => vB_Cleaner::TYPE_STR,
			);
			// unset any unused params from the cleaning list.
			foreach ($cleanList AS $key => $cleantype)
			{
				if (!array_key_exists($key, $params))
				{
					unset($cleanList[$key]);
					// we don't want to accidentally set an unused string parameter
					if ($cleantype === vB_Cleaner::TYPE_STR)
					{
						unset($strList[$key]);
					}
				}
			}

			// clean params. Any parameter NOT in the cleaning list will be dropped
			$params = vB::getCleaner()->cleanArray($params, $cleanList);
			// escape any strings included in the params
			foreach ($strList AS $key => $cleantype)
			{
				$params[$key] = $db->escape_string($params[$key]);
			}

			$count = count($params);
			$query = "SELECT ".($params['just_count'] ? "COUNT(userchangelog.changeid) AS change_count" : "user.*, userchangelog.*, adminuser.username AS admin_username ") . "
				FROM " . TABLE_PREFIX . "userchangelog AS userchangelog
				LEFT JOIN " . TABLE_PREFIX . "user AS user ON(user.userid = userchangelog.userid)
				LEFT JOIN " . TABLE_PREFIX . "user AS adminuser ON(adminuser.userid = userchangelog.adminid)
				WHERE ";
			$i = 0;
			foreach ($params as $key => $value) {
				switch ($key) {
					case 'userchangelog.oldvalue':
						$query.= " ($key = '$value' OR userchangelog.newvalue = '$value') ";
						break;
					case 'time_start':
						$query.= " change_time >= $value ";
						break;
					case 'time_end':
						$query.= " change_time <= $value ";
						break;
					case 'userchangelog.newvalue':
					case 'just_count':
					case vB_dB_Query::PARAM_LIMITSTART:
					case vB_dB_Query::PARAM_LIMITPAGE:
					case vB_dB_Query::PARAM_LIMIT:
					case vB_dB_Query::TYPE_KEY:
						break;
					default:
						$query.= " $key = '$value' ";
						break;
				}

				if ($i < $count && ($key != 'userchangelog.newvalue' && $key != 'just_count' && $key != 'page' && $key != vB_dB_Query::PARAM_LIMIT && $key != vB_dB_Query::TYPE_KEY))
				{
					$query.= "AND";
					$i++;
				}
			}
			$query.= ($params['just_count'] ? "" : " ORDER BY userchangelog.change_time DESC, userchangelog.change_uniq ASC, userchangelog.fieldname DESC ");
			$query.= ($params['just_count'] ? "" : " LIMIT " . ($params[vB_dB_Query::PARAM_LIMIT]*$params[vB_dB_Query::PARAM_LIMITPAGE]) . ", " . $params[vB_dB_Query::PARAM_LIMIT]);

			while(strpos($query, 'ANDAND') !== false)
			{
				$query = str_replace("ANDAND", "AND", $query);

			}
			$query = str_replace("AND ORDER", " ORDER", $query);

			if (substr($query, -4) == ' AND')
			{
				$query = substr($query, 0, -4);
			}

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $query);
			return $result;
		}
	}

	public function getStyle($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			//I can't work without a styleid
			return !empty($params['styleid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'styleid' => vB_Cleaner::TYPE_UINT,
				'userselect' => vB_Cleaner::TYPE_NOCLEAN,		// not used in sql statement
				'defaultstyleid' => vB_Cleaner::TYPE_UINT,
				'direction' => vB_Cleaner::TYPE_NOCLEAN,		// not used in sql statement
			));
			//Note the opening paren is here, and the closing paren is several lines down.
			$sql = "SELECT * FROM " . TABLE_PREFIX . "style AS style WHERE (styleid = " . $params['styleid'];
			if ($params['userselect'])
			{
				$sql .= " AND userselect = 1 ";
			}
			if ($params['defaultstyleid'])
			{
				$sql .= " OR styleid = " . $params['defaultstyleid'];
			}
			$sql .= ") ORDER BY styleid ";

			if (empty($params['direction']) OR ($params['direction'] == 'asc'))
			{
				$sql .= 'ASC';
			}
			else
			{
				$sql .= 'DESC';
			}

			$sql .= " LIMIT 1";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function searchTemplates($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['templateids']);
		}
		else
		{
			$params['templateids'] = explode(',', $params['templateids']);
			$params = vB::getCleaner()->cleanArray($params, array(
				'searchstring' => vB_Cleaner::TYPE_STR,
				'templateids' => vB_Cleaner::TYPE_ARRAY_UINT,
				'titlesonly' => vB_Cleaner::TYPE_NOCLEAN,
			));
			$params['templateids'] = implode(',', $params['templateids']);
			if (empty($params['searchstring']))
			{
				$searchconds = '';
			}
			elseif ($params['titlesonly'])
			{
				$searchconds = "AND t1.title LIKE('%" . $db->escape_string_like($params['searchstring']) . "%')";
			}
			else
			{
				$searchconds = "AND ( t1.title LIKE('%" . $db->escape_string_like($params['searchstring']) . "%') OR template_un LIKE('%" . $db->escape_string_like($params['searchstring']) . "%') ) ";
			}

			$sql = "
				SELECT
					templateid, IF(((t1.title LIKE '%.css') AND (t1.title NOT like 'css_%')),
					CONCAT('csslegacy_', t1.title), title) AS title, styleid, templatetype, dateline, username
				FROM " . TABLE_PREFIX . "template AS t1
				WHERE
					templatetype IN('template', 'replacement') $searchconds
						AND
					templateid IN($params[templateids])
				ORDER BY title
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function getStyleByConds($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['conds']) AND isset($params['limit_style']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'conds' => vB_Cleaner::TYPE_NOCLEAN,		// cleaned by querybuilder
				'limit_style' => vB_Cleaner::TYPE_UINT,
			));
			$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
			$queryBuilder = new $className($db, false);
			$where = $queryBuilder->conditionsToFilter($params['conds']);

			$sql = "SELECT styleid, title, templatelist FROM " . TABLE_PREFIX .
				"style WHERE $where LIMIT $params[limit_style], 1";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchUserinfo($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['userid']);
		}
		else
		{
			if (!isset($params['currentuserid']) OR !$params['currentuserid'])
			{
				if ($session = vB::getCurrentSession())
				{
					$params['currentuserid'] = $session->get('userid');
				}
				else
				{
					$params['currentuserid'] = 0;
				}
			}

			if (!is_array($params['userid']))
			{
				$params['userid'] = array($params['userid']);
			}

			$params = vB::getCleaner()->cleanArray($params, array(
				'option' => vB_Cleaner::TYPE_ARRAY_STR,
				'userid' => vB_Cleaner::TYPE_ARRAY_UINT,
				'currentuserid' => vB_Cleaner::TYPE_UINT,
			));

			$select = array();
			$join = array();

			//sort out the option data blocks.
			if (in_array(vB_Api_User::USERINFO_ADMIN, $params['option']))
			{
				$select[] = 'administrator.*';
				$join[] = 'LEFT JOIN ' . TABLE_PREFIX . 'administrator AS administrator ON (administrator.userid = user.userid)';
			}

			if (in_array(vB_Api_User::USERINFO_AVATAR, $params['option']))
			{
				$select[] = 'avatar.avatarpath';
				$select[] = 'NOT ISNULL(customavatar.userid) AS hascustomavatar';
				$select[] = 'customavatar.dateline AS avatardateline';
				$select[] = 'customavatar.width AS avwidth';
				$select[] = 'customavatar.height AS avheight';
				$select[] = 'customavatar.height_thumb AS avheight_thumb';
				$select[] = 'customavatar.width_thumb AS avwidth_thumb';
				$select[] = 'customavatar.filedata_thumb';
				$select[] = 'customavatar.extension AS avatarextension';

				$join[] = 'LEFT JOIN ' . TABLE_PREFIX . 'avatar AS avatar ON (avatar.avatarid = user.avatarid)';
				$join[] =	'LEFT JOIN ' . TABLE_PREFIX . 'customavatar AS customavatar ON (customavatar.userid = user.userid)';
			}

			if (in_array(vB_Api_User::USERINFO_SIGNPIC, $params['option']))
			{
				$select[] = 'sigpicnew.userid AS sigpic';
				$select[] = 'sigpicnew.filedataid AS sigpicfiledataid';
				$select[] = 'sigpicfiledata.dateline AS sigpicdateline';
				$select[] = 'sigpicfiledata.width AS sigpicwidth';
				$select[] = 'sigpicfiledata.height AS sigpicheight';

				$join[] =  'LEFT JOIN ' . TABLE_PREFIX . 'sigpicnew AS sigpicnew ON (user.userid = sigpicnew.userid)';
			 	$join[] =  'LEFT JOIN ' . TABLE_PREFIX . 'filedata AS sigpicfiledata ON (sigpicnew.filedataid = sigpicfiledata.filedataid)';
			}

			if ($params['currentuserid'] AND in_array(vB_Api_User::USERINFO_ISFRIEND, $params['option']))
			{
				$select[] = "IF(userlist1.friend = 'yes', 1, 0) AS isfriend";
				$select[] = "IF (userlist1.friend = 'pending' OR userlist1.friend = 'denied', 1, 0) AS ispendingfriend";
				$select[] = "IF(userlist1.userid IS NOT NULL, 1, 0) AS u_iscontact_of_bbuser";
				$select[] = "IF (userlist2.friend = 'pending', 1, 0) AS requestedfriend";
				$select[] = "IF(userlist2.userid IS NOT NULL, 1, 0) AS bbuser_iscontact_of_user";

				$join[] = "LEFT JOIN " . TABLE_PREFIX . "userlist AS userlist1 ON " .
					"(userlist1.relationid = user.userid AND userlist1.type = 'buddy' AND userlist1.userid = " . $params['currentuserid'] . ")";
				$join[] =	"LEFT JOIN " . TABLE_PREFIX . "userlist AS userlist2 ON " .
					"(userlist2.userid = user.userid AND userlist2.type = 'buddy' AND userlist2.relationid = " . $params['currentuserid'] . ")";
			}

			if ($select)
			{
				$select = implode(', ', $select) . ',';
			}
			else
			{
				$select = "";
			}

			$sql = "
				SELECT $select
					userfield.*, usertextfield.*, user.*, UNIX_TIMESTAMP(passworddate) AS passworddate, user.languageid AS saved_languageid,
					IF(displaygroupid=0, user.usergroupid, displaygroupid) AS displaygroupid
				FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "userfield AS userfield ON (user.userid = userfield.userid)
				LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid) " .
				implode("\n", $join) . "
					WHERE user.userid IN (" . implode(',', $params['userid']) . ")
					/** fetchUserinfo **/
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchLanguage($params, $dbobject, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'phrasegroups' => vB_Cleaner::TYPE_NOCLEAN,		// cleaned soon below
			'languageid' => vB_Cleaner::TYPE_UINT,
		));

		if (empty($params['phrasegroups']))
		{
			$phrasegroups = array();
		}
		else if (is_array($params['phrasegroups']))
		{
			$phrasegroups = $params['phrasegroups'];
		}
		else
		{
			$phrasegroups = array($params['phrasegroups']);
		}

		if (!in_array('global', $phrasegroups))
		{
			$phrasegroups[]= 'global';
		}
		$sql = 'SELECT ';
		$fields = array();
		foreach ($phrasegroups AS $group)
		{
			$fields[] = 'phrasegroup_' . preg_replace('#[^a-z0-9_]#i', '', $group); // just to be safe...
		}
		$sql .= implode(",\n ", $fields);
		$sql .= ",
		options AS lang_options,
		languagecode AS lang_code,
		charset AS lang_charset,
		locale AS lang_locale,
		dateoverride AS lang_dateoverride,
		timeoverride AS lang_timeoverride,
		registereddateoverride AS lang_registereddateoverride,
		calformat1override AS lang_calformat1override,
		calformat2override AS lang_calformat2override,
		eventdateformatoverride AS lang_eventdateformatoverride,
		pickerdateformatoverride AS lang_pickerdateformatoverride,
		logdateoverride AS lang_logdateoverride,
		decimalsep AS lang_decimalsep,
		thousandsep AS lang_thousandsep";

		if (!empty($params['languageid']))
		{
			$sql .= "\n FROM " . TABLE_PREFIX . "language WHERE languageid = " . $params['languageid'];
		}
		else
		{
			$options = vB::getDatastore()->getValue('options');
			$sql .= "\n FROM " . TABLE_PREFIX . "language WHERE languageid = " . intval($options['languageid']);
		}

		$sql .= "/* fetchLanguage */";
		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($dbobject, $sql);
		return $result;
	}

	public function userFind($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['filters']) OR !empty($params['unions']) OR !empty($params['exceptions']));
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'limitstart'	=> vB_Cleaner::TYPE_UINT,
				vB_dB_Query::PARAM_LIMIT	=> vB_Cleaner::TYPE_UINT,
				'orderby'	=> vB_Cleaner::TYPE_STR,
				'direction'	=> vB_Cleaner::TYPE_STR,
				'exceptions'	=> vB_Cleaner::TYPE_NOCLEAN,

				//filters is passed to the querybuilder object below and is not used directly in the query.
				'filters'	=> vB_Cleaner::TYPE_NOCLEAN,
				'unions'	=> vB_Cleaner::TYPE_NOCLEAN,
			));

			if ($params['exceptions'])
			{
				$params['exceptions'] = vB::getCleaner()->cleanArray($params['exceptions'], array(
					'membergroup'	=> vB_Cleaner::TYPE_ARRAY_UINT,
					'aim'	=> vB_Cleaner::TYPE_STR,
				));
			}

			switch ($params['orderby'])
			{
				//user id is mostly used for tests, but its a valid option so it can
				//be included here.
				case 'userid':
				case 'username':
				case 'email':
				case 'joindate':
				case 'lastactivity':
				case 'lastpost':
				case 'posts':
				case 'birthday_search':
				case 'reputation':
				case 'warnings':
				case 'infractions':
				case 'ipoints':
					//qualify the field so that we don't get DB errors
					//this is safe because the param *must* match one of the above options.
					$params['orderby'] = '`user`.`' . $params['orderby'] . '`';
					break;
				default:
					$params['orderby'] = 'username';
			}

			if ($params['direction'] != 'DESC')
			{
				$params['direction'] = 'ASC';
			}

			if (empty($params['limitstart']))
			{
				$params['limitstart'] = 0;
			}

			if (empty($params[vB_dB_Query::PARAM_LIMIT]))
			{
				$params[vB_dB_Query::PARAM_LIMIT] = 25;
			}

			$queryBuilder = $this->getQueryBuilder($db);
			if (empty($params['unions']))
			{
				$where = $queryBuilder->conditionsToFilter($params['filters']);
			}
			else
			{
				$where = '';
				$params['filters'] = array(); // filters & unions are not compatible with each other.
				$union_where = array();
				foreach($params['unions'] AS $filter)
				{
					$union_where[] = $queryBuilder->conditionsToFilter(array($filter));
				}
			}


			// if 'filters' are not set but 'exceptions' are, then $where begins with " AND".
			// Since $where is appended to "WHERE " later, this causes an SQL error ("..WHERE AND..")
			// To fix this, prepend $where with ' true ' ("..WHERE true AND..")
			if (	(!isset($params['filters']) OR empty($params['filters'])) AND
					(!isset($params['unions']) OR empty($params['unions'])) AND
					(isset($params['exceptions']) AND !empty($params['exceptions']))
			)
			{
				$where .= ' true ';
			}
			$exceptions = $params['exceptions'];
			if (isset($exceptions['membergroup']) AND is_array($exceptions['membergroup']))
			{
				foreach ($exceptions['membergroup'] AS $id)
				{
					$where .= " AND FIND_IN_SET(" . intval($id) . ", user.membergroupids)";
				}
			}

			if ($exceptions['aim'])
			{
				$where .= " AND REPLACE(" . TABLE_PREFIX . "aim, ' ', '') LIKE '%" .
					$db->escape_string_like(str_replace(' ', '', $exceptions['aim'])) . "%'";
			}

			if (!empty($union_where))
			{
				foreach ($union_where AS $_key => $_where)
				{
					$union_where[$_key] = "WHERE $_where $where";
				}
			}
			else if (!empty($where))
			{
				$where = "WHERE $where";
			}


			$bf_misc_useroptions = vB::getDatastore()->getValue('bf_misc_useroptions');
			$sql_select = "
				SELECT
					user.userid, reputation, username, usergroupid, birthday_search, ";

			if (vB::getUserContext()->hasAdminPermission('canadminusers'))
			{
				$sql_select .= "email, parentemail, ";
			}
			$sql_select .= " (options & " . $bf_misc_useroptions['coppauser'] . ") AS coppauser,
					homepage, icq, aim, yahoo, msn, skype, signature,
					usertitle, joindate, lastpost, posts, ipaddress, lastactivity, userfield.*, infractions, ipoints, warnings,
					user.eustatus, user.privacyconsent, user.privacyconsentupdated
				";
			$sql_from = "
				FROM " . TABLE_PREFIX . "user AS user LEFT JOIN " .
					TABLE_PREFIX . "userfield AS userfield ON(userfield.userid = user.userid) LEFT JOIN " .
					TABLE_PREFIX . "usertextfield AS usertextfield ON(usertextfield.userid = user.userid)
				";
			$sql_orderlimit = "
				ORDER BY " . $db->escape_string($params['orderby']) . " " . $db->escape_string($params['direction']) . "
				LIMIT " . $params['limitstart'] . ", " . $params[vB_dB_Query::PARAM_LIMIT]
			;
			if (!empty($union_where))
			{
				$sql_union = array();
				foreach ($union_where AS $_where)
				{
					$sql_union[] = "(" . $sql_select . $sql_from . $_where . $sql_orderlimit . ")";
				}
				$sql = implode("\nUNION\n", $sql_union);
			}
			else
			{
				$sql = $sql_select . $sql_from . $where  . $sql_orderlimit;
			}

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function userFindCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['filters']) OR !empty($params['unions']) OR !empty($params['exceptions']));
		}
		else
		{
			$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
			$queryBuilder = new $className($db, false);
			if (empty($params['unions']))
			{
				$where = $queryBuilder->conditionsToFilter($params['filters']);
			}
			else
			{
				$where = '';
				$union_where = array();
				foreach($params['unions'] AS $filter)
				{
					$union_where[] = $queryBuilder->conditionsToFilter(array($filter));
				}
			}

			// if 'filters' are not set but 'exceptions' are, then $where begins with " AND".
			// Since $where is appended to "WHERE " later, this causes an SQL error ("..WHERE AND..")
			// To fix this, prepend $where with ' true ' ("..WHERE true AND..")
			if (	(!isset($params['filters']) OR empty($params['filters'])) AND
					(!isset($params['unions']) OR empty($params['unions'])) AND
					(isset($params['exceptions']) AND !empty($params['exceptions']))
			)
			{
				$where .= ' true ';
			}

			$exceptions = $params['exceptions'];
			if (isset($exceptions['membergroup']) AND is_array($exceptions['membergroup']))
			{
				foreach ($exceptions['membergroup'] AS $id)
				{
					$where .= " AND FIND_IN_SET(" . intval($id) . ", user.membergroupids)";
				}
			}

			if ($exceptions['aim'])
			{
				$where .= " AND REPLACE(" . TABLE_PREFIX . "aim, ' ', '') LIKE '%" .
					$db->escape_string_like(str_replace(' ', '', $exceptions['aim'])) . "%'";
			}

			$sql = "
				SELECT COUNT(*) AS users
				FROM " . TABLE_PREFIX . "user AS user LEFT JOIN " .
					TABLE_PREFIX . "userfield AS userfield ON(userfield.userid = user.userid) LEFT JOIN " .
					TABLE_PREFIX . "usertextfield AS usertextfield ON(usertextfield.userid = user.userid)
			";

			if (!empty($union_where))
			{
				$sql_union = array();
				$sql_pre = "
				SELECT user.userid
				FROM " . TABLE_PREFIX . "user AS user LEFT JOIN " .
					TABLE_PREFIX . "userfield AS userfield ON(userfield.userid = user.userid) LEFT JOIN " .
					TABLE_PREFIX . "usertextfield AS usertextfield ON(usertextfield.userid = user.userid)
				";
				foreach ($union_where AS $_where)
				{
					$sql_union[] = "(" . $sql_pre . "\n\t\t\t\tWHERE $_where)";
				}
				$sql = "SELECT COUNT(*) FROM (" . implode("\nUNION\n", $sql_union) . ") AS some_alias";
			}
			else if (!empty($where))
			{
				$sql .= "\n\t\t\t\tWHERE $where";
			}
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function userInsertSubscribeevent($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['sourceuserid']) AND !empty($params['destuserid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'sourceuserid'	=> vB_Cleaner::TYPE_UINT,
				'destuserid' => vB_Cleaner::TYPE_UINT,
			));
			$insertsql = '';
			$events = $db->query_read("
								SELECT eventid, reminder
								FROM " . TABLE_PREFIX . "subscribeevent
								WHERE userid = $params[sourceuserid]
						");
			while ($event = $db->fetch_array($events))
			{
				if (!empty($insertsql))
				{
					$insertsql .= ',';
				}
				$insertsql .= "($params[destuserid], $event[eventid], $event[reminder])";
			}

			if ($insertsql)
			{
				/* insert sql */
				$sql = "
										INSERT IGNORE INTO " . TABLE_PREFIX . "subscribeevent
												(userid, eventid, reminder)
										VALUES
												$insertsql
								";

				$resultclass = 'vB_dB_' . $this->db_type . '_result';
				$result = new $resultclass($db, $sql);
				return $result;
			}
			return null;
		}
	}

	public function userInsertAnnouncementread($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['sourceuserid']) AND !empty($params['destuserid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'destuserid' => vB_Cleaner::TYPE_UINT,
				'sourceuserid' => vB_Cleaner::TYPE_UINT,
			));
			$insertsql = array();
			$announcements = $db->query_read("
								SELECT announcementid
								FROM " . TABLE_PREFIX . "announcementread
								WHERE userid = $params[sourceuserid]
						");
			while ($announcement = $db->fetch_array($announcements))
			{
				$insertsql[] = "($params[destuserid], $announcement[announcementid])";
			}

			if ($insertsql)
			{
				/* insert sql */
				$sql = "
										INSERT IGNORE INTO " . TABLE_PREFIX . "announcementread
												(userid, announcementid)
										VALUES
												" . implode(', ', $insertsql) . "
								";

				$resultclass = 'vB_dB_' . $this->db_type . '_result';
				$result = new $resultclass($db, $sql);
				return $result;
			}
			return null;
		}
	}



	public function userDeleteUsergrouprequest($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['sourceuserid']) AND !empty($params['destusergroupid']);
		}
		else
		{
			$params['destmembergroupids'] = explode(',', $params['destmembergroupids']);
			$params = vB::getCleaner()->cleanArray($params, array(
				'sourceuserid' => vB_Cleaner::TYPE_UINT,
				'destusergroupid' => vB_Cleaner::TYPE_UINT,
				'destmembergroupids' => vB_Cleaner::TYPE_ARRAY_UINT,
			));
			$params['destmembergroupids'] = implode(',', $params['destmembergroupids']);
			/* insert sql */
			$sql = "
								DELETE FROM " . TABLE_PREFIX . "usergrouprequest
								WHERE userid = $params[sourceuserid] AND
										(usergroupid = $params[destusergroupid] " . ($params['destmembergroupids'] != '' ? "OR usergroupid IN (0,$params[destmembergroupids])" : '') . ")
						";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function userSearchRegisterIP($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['ipaddress']) AND isset($params['prevuserid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'ipaddress' => vB_Cleaner::TYPE_NOCLEAN, //cleaned right after this
				'prevuserid' => vB_Cleaner::TYPE_UINT,
			));

			if (substr($params['ipaddress'], -1) == '.' OR substr_count($params['ipaddress'], '.') < 3)
			{
				// ends in a dot OR less than 3 dots in IP -> partial search
				$ipaddress_match = "ipaddress LIKE '" . $db->escape_string_like($params['ipaddress']) . "%'";
			}
			else
			{
				// exact match
				$ipaddress_match = "ipaddress = '" . $db->escape_string($params['ipaddress']) . "'";
			}

			$sql = "
				SELECT userid, username, ipaddress
				FROM " . TABLE_PREFIX . "user AS user
				WHERE $ipaddress_match AND
					ipaddress <> '' AND
					userid <> $params[prevuserid]
				ORDER BY username
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function userSearchIPUsage($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['ipaddress']) AND isset($params['prevuserid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'ipaddress' => vB_Cleaner::TYPE_NOCLEAN,  //cleaned right after this
				'prevuserid' => vB_Cleaner::TYPE_UINT,
			));
			if (substr($params['ipaddress'], -1) == '.' OR substr_count($params['ipaddress'], '.') < 3)
			{
				// ends in a dot OR less than 3 dots in IP -> partial search
				$ipaddress_match = "node.ipaddress LIKE '" . $db->escape_string_like($params['ipaddress']) . "%'";
			}
			else
			{
				// exact match
				$ipaddress_match = "node.ipaddress = '" . $db->escape_string($params['ipaddress']) . "'";
			}

			/* insert sql */
			$sql = "
				SELECT DISTINCT user.userid, user.username, node.ipaddress
				FROM " . TABLE_PREFIX . "node AS node,
					" . TABLE_PREFIX . "user AS user
				WHERE user.userid = node.userid AND
					$ipaddress_match AND
				node.ipaddress <> '' AND
					user.userid <> " . $params['prevuserid'] . "
				ORDER BY user.username
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function userReferrers($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			//we always want to allow this.  Without params we'll show the
			//entire range.  That's not necesarily a good idea but we allowed
			//it before (the params where arrays that would pretty much always
			//be set even if the dates weren't
			return true;
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'startdate' => vB_Cleaner::TYPE_UINT,
				'enddate' => vB_Cleaner::TYPE_UINT,
			));

			$datefilter = '';
			if ($params['startdate'])
			{
				$datefilter .= " AND users.joindate >= " . $params['startdate'];
			}

			if ($params['enddate'])
			{
				$datefilter .= " AND users.joindate <= " . $params['enddate'];
			}

			$sql = "
				SELECT COUNT(*) AS count, user.username, user.userid
				FROM " . TABLE_PREFIX . "user AS users
					INNER JOIN " . TABLE_PREFIX . "user AS user ON(users.referrerid = user.userid)
				WHERE users.referrerid <> 0 AND
					users.usergroupid NOT IN (3,4)
					$datefilter
				GROUP BY users.referrerid
				ORDER BY count DESC, username ASC
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchPhraseInfo($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['languageId']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'languageId' => vB_Cleaner::TYPE_UINT,
				'languageFields' => vB_Cleaner::TYPE_NOCLEAN,
			));
			$params['languageFields'] = $db->clean_identifier($params['languageFields']);
			$sql = "
					SELECT languageid" . $params['languageFields'] . "
					FROM " . TABLE_PREFIX . "language
					WHERE languageid = " . intval($params['languageId']);

			$resultClass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultClass($db, $sql);
		}
		return $result;
	}

	// find all groups allowed to be invisible - don't change people with those as secondary groups
	public function updateInvisible($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['caninvisible']) AND !empty($params['invisible']) AND !empty($params['usergroupid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'caninvisible' => vB_Cleaner::TYPE_UINT,
				'invisible' => vB_Cleaner::TYPE_UINT,
				'usergroupid' => vB_Cleaner::TYPE_UINT,
			));
			$invisible_groups = '';
			$invisible_sql = $db->query_read("
				SELECT usergroupid
				FROM " . TABLE_PREFIX . "usergroup
				WHERE genericpermissions & " . $params['caninvisible']
			);
			while ($invisible_group = $db->fetch_array($invisible_sql))
			{
				$invisible_groups .= "\nAND NOT FIND_IN_SET($invisible_group[usergroupid], membergroupids)";
			}

			$sql ="
				UPDATE " . TABLE_PREFIX . "user
				SET options = (options & ~" . $params['invisible'] . ")
				WHERE usergroupid = " . $params['usergroupid'] . "
					$invisible_groups
			";


			return $db->query_write($sql);
		}
	}

	public function disableProducts($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['products']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'reason' => vB_Cleaner::TYPE_STR,
				'products' => vB_Cleaner::TYPE_STR,
			));
			$reason = $params['reason'];
			$products = $params['products'];

			if ($reason)
			{
				$reason = $db->escape_string($reason) . ' ';
			}

			$products = array_map(array($db, 'escape_string'), $products);
			$list = "'" . implode("','", $products) . "'";

			$sql ="
				UPDATE " . TABLE_PREFIX . "product
				SET active = 0,
				description = CONCAT($reason, description)
				WHERE productid IN ($list) AND active = 1
			";

			return $db->query_write($sql);
		}
	}

	public function updateMemberForDeletedUsergroup($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['users']) AND !empty($params['usergroupid']);
		}
		else
		{
			$casesql = $casesqli = '';
			$updateusers = $updateusersi = array();

			foreach ($params['users'] as $user)
			{
				if (!empty($user['membergroupids']))
				{
					$membergroups = fetch_membergroupids_array($user, false);
					foreach($membergroups AS $key => $val)
					{
						if ($val == $params['usergroupid'])
						{
							unset($membergroups["$key"]);
						}
					}
					$user['membergroupids'] = implode(',', $membergroups);
					$casesql .= "WHEN $user[userid] THEN '$user[membergroupids]' ";
					$updateusers[] = $user['userid'];
				}
				if (!empty($user['infractiongroupids']))
				{
					$infractiongroups = explode(',', str_replace(' ', '', $user['infractiongroupids']));
					foreach($infractiongroups AS $key => $val)
					{
						if ($val == $params['usergroupid'])
						{
							unset($infractiongroups["$key"]);
						}
					}
					$user['infractiongroupids'] = implode(',', $infractiongroups);
					$casesqli .= "WHEN $user[userid] THEN '$user[infractiongroupids]' ";
					$updateusersi[] = $user['userid'];
				}
			}

			// do a big update to get rid of this usergroup from matched members' membergroupids
			if (!empty($casesql))
			{
				$sql = "
					UPDATE " . TABLE_PREFIX . "user SET
					membergroupids = CASE userid
					$casesql
					ELSE '' END
					WHERE userid IN(" . implode(',', $updateusers) . ")
				";

				$resultclass = 'vB_dB_' . $this->db_type . '_result';
				$result = new $resultclass($db, $sql);
				$result->valid();
				unset($result);
			}

			// do a big update to get rid of this usergroup from matched members' infractiongroupids
			if (!empty($casesqli))
			{
				$sql2 = "
					UPDATE " . TABLE_PREFIX . "user SET
					infractiongroupids = CASE userid
					$casesqli
					ELSE '' END
					WHERE userid IN(" . implode(',', $updateusersi) . ")
				";

				$resultclass2 = 'vB_dB_' . $this->db_type . '_result';
				$result2 = new $resultclass2($db, $sql2);
				$result2->valid();
				unset($result2);
			}

			return true;
		}
	}

	public function fetchPromotions($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['usergroupid']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'usergroupid' => vB_Cleaner::TYPE_UINT,
			));
			$sql = "
				SELECT userpromotion.*, joinusergroup.title
				FROM " . TABLE_PREFIX . "userpromotion AS userpromotion
				LEFT JOIN " . TABLE_PREFIX . "usergroup AS joinusergroup ON (userpromotion.joinusergroupid = joinusergroup.usergroupid)
				" . ($params['usergroupid']?"WHERE userpromotion.usergroupid = " . $params['usergroupid']:'');

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function deleteOrphans($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['del']);
		}
		else
		{
			$delcondition = array();

			foreach ($params['del'] AS $key)
			{
				fetch_varname_fieldname($key, $varname, $fieldname);
				$delcondition[] = "(varname = '" . $db->escape_string($varname) . "' AND fieldname = '" . $db->escape_string($fieldname) . "')";
			}

			$sql = "
				DELETE FROM " . TABLE_PREFIX . "phrase
				WHERE " . implode("\nOR ", $delcondition);

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function keepOrphans($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['keep']);
		}
		else
		{
			$insertsql = array();
			$params = vB::getCleaner()->cleanArray($params, array(
				'keep' => vB_Cleaner::TYPE_ARRAY_UINT,
			));
			$phrases = $db->query_read("
				SELECT *
				FROM " . TABLE_PREFIX . "phrase
				WHERE phraseid IN(" . implode(', ', $params['keep']) . ")
			");
			while ($phrase = $db->fetch_array($phrases))
			{
				$insertsql[] = "
					(0,
					'" . $db->escape_string($phrase['fieldname']) . "',
					'" . $db->escape_string($phrase['varname']) . "',
					'" . $db->escape_string($phrase['text']) . "',
					'" . $db->escape_string($phrase['product']) . "',
					'" . $db->escape_string($phrase['username']) . "',
					$phrase[dateline],
					'" . $db->escape_string($phrase['version']) . "')
				";
			}

			$sql = "
				REPLACE INTO " . TABLE_PREFIX . "phrase
					(languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES
					" . implode(', ', $insertsql);

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function searchPhrases($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['criteria']['searchstring']);
		}
		else
		{
			$criteria = $params['criteria'];
			$vb5_config =& vB::getConfig();

			if ($criteria['exactmatch'])
			{
				$sql = ($criteria['casesensitive'] ? 'BINARY ' : '');

				switch($criteria['searchwhere'])
				{
					case 0: $sql .= "text = '" . $db->escape_string($criteria['searchstring']) . "'"; break;
					case 1: $sql .= "varname = '" . $db->escape_string($criteria['searchstring']) . "'"; break;
					case 10: $sql .= "(text = '" . $db->escape_string($criteria['searchstring']) . "' OR $sql varname = '" . $db->escape_string($criteria['searchstring']) . "')"; break;
					default: $sql .= '';
				}
			}
			else
			{
// 				$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
// 				$queryBuilder = new $className($db, false);
// 				switch($criteria['searchwhere'])
// 				{
// 					case 0:
// 						$sql = $queryBuilder->conditionsToFilter(array(
// 							array('field' => 'text', 'value' => $criteria['searchstring'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES)
// 						));
// 						break;
// 					case 1:
// 						$sql = $queryBuilder->conditionsToFilter(array(
// 							array('field' => 'varname', 'value' => $criteria['searchstring'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES)
// 						));
// 						break;
// 					case 10:
// 						$sql = '(' . $queryBuilder->conditionsToFilter(array(
// 								array('field' => 'text', 'value' => $criteria['searchstring'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES)
// 								)) .
// 							') OR (' .
// 							$queryBuilder->conditionsToFilter(array(
// 								array('field' => 'varname', 'value' => $criteria['searchstring'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES)
// 							));
// 						break;
// 					default: $sql = '';
// 				}

				$this->db = $db;
				switch($criteria['searchwhere'])
				{
					case 0: $sql = $this->fetch_field_like_sql($criteria['searchstring'], 'text', false, $criteria['casesensitive']); break;
					case 1: $sql = $this->fetch_field_like_sql($criteria['searchstring'], 'varname', true, $criteria['casesensitive']); break;
					case 10: $sql = '(' . $this->fetch_field_like_sql($criteria['searchstring'], 'text', false, $criteria['casesensitive']) . ' OR ' . $this->fetch_field_like_sql($criteria['searchstring'], 'varname', true, $criteria['casesensitive']) . ')'; break;
					default: $sql = '';
				}
			}

			if (!empty($criteria['phrasetype']) AND trim(implode('', $criteria['phrasetype'])) != '')
			{
				$phrasetype_sql = "'" . implode("', '", array_map(array(&$db, 'escape_string'), $criteria['phrasetype'])) . "'";
			}
			else
			{
				$phrasetype_sql = '';
			}

			if ($criteria['languageid'] == -10)
			{
				// query ALL languages
				if ($vb5_config['Misc']['debug'])
				{
					// searches all phrases
					$sql = "
						SELECT phrase.*, language.title
						FROM " . TABLE_PREFIX . "phrase AS phrase
						LEFT JOIN " . TABLE_PREFIX . "language AS language USING(languageid)
						WHERE $sql
						" . ($phrasetype_sql ? "AND phrase.fieldname IN($phrasetype_sql)" : "") . "
						" . ($criteria['product'] ? "AND phrase.product = '" . $db->escape_string($criteria['product']) . "'" : "") . "
						ORDER BY languageid DESC, fieldname DESC
					";
				}
				else
				{
					// searches all phrases that are in use. Translated master phrases will not be searched
					$sql = "
						SELECT IF (pcustom.fieldname IS NOT NULL, pcustom.fieldname, pmaster.fieldname) AS fieldname,
							IF (pcustom.varname IS NOT NULL, pcustom.varname, pmaster.varname) AS varname,
							IF (pcustom.languageid IS NOT NULL, pcustom.languageid, pmaster.languageid) AS languageid,
							IF (pcustom.text IS NOT NULL, pcustom.text, pmaster.text) AS text,
							language.title
						FROM " . TABLE_PREFIX . "language AS language
						INNER JOIN " . TABLE_PREFIX . "phrase AS pmaster ON
							(pmaster.languageid IN (-1, 0))
						LEFT JOIN " . TABLE_PREFIX . "phrase AS pcustom ON
							(pcustom.languageid = language.languageid AND pcustom.varname = pmaster.varname AND pcustom.fieldname = pmaster.fieldname)
						WHERE 1=1
							" . ($phrasetype_sql ? "AND pmaster.fieldname IN($phrasetype_sql)" : '') . "
							" . ($criteria['product'] ? "AND pmaster.product = '" . $db->escape_string($criteria['product']) . "'" : "") . "
						" . ($sql ? "HAVING $sql" : '') . "
						ORDER BY languageid DESC, fieldname DESC
					";
				}

			}
			else if ($criteria['languageid'] > 0 AND !$criteria['transonly'])
			{
				// query specific translation AND master/custom master languages
				$sql = "
					SELECT IF (pcustom.fieldname IS NOT NULL, pcustom.fieldname, pmaster.fieldname) AS fieldname,
						IF (pcustom.varname IS NOT NULL, pcustom.varname, pmaster.varname) AS varname,
						IF (pcustom.languageid IS NOT NULL, pcustom.languageid, pmaster.languageid) AS languageid,
						IF (pcustom.text IS NOT NULL, pcustom.text, pmaster.text) AS text,
						language.title
					FROM " . TABLE_PREFIX . "phrase AS pmaster
					LEFT JOIN " . TABLE_PREFIX . "phrase AS pcustom ON (pcustom.languageid = " . $criteria['languageid'] . " AND pcustom.varname = pmaster.varname)
					LEFT JOIN " . TABLE_PREFIX . "language AS language ON (pcustom.languageid = language.languageid)
					WHERE pmaster.languageid IN (-1, 0)
					" . ($phrasetype_sql ? "AND pmaster.fieldname IN($phrasetype_sql)" : '') . "
					" . ($criteria['product'] ? "AND pmaster.product = '" . $db->escape_string($criteria['product']) . "'" : "") . "
					" . ($sql ? "HAVING $sql" : '') . "
					ORDER BY languageid DESC, fieldname DESC
				";
			}
			else
			{
				// query ONLY specific language
				$sql = "
					SELECT phrase.*, language.title
					FROM " . TABLE_PREFIX . "phrase AS phrase
					LEFT JOIN " . TABLE_PREFIX . "language AS language USING(languageid)
					WHERE $sql
					" . ($phrasetype_sql ? "AND phrase.fieldname IN($phrasetype_sql)" : '') . "
					" . ($criteria['product'] ? "AND phrase.product = '" . $db->escape_string($criteria['product']) . "'" : "") . "
					AND phrase.languageid = " . $criteria['languageid'] . "
					ORDER BY fieldname DESC
				";
			}
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function deleteOldPhrases($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['varname']) AND !empty($params['fieldname']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'varname' => vB_Cleaner::TYPE_STR,
				'fieldname' => vB_Cleaner::TYPE_ARRAY_STR,
				't' => vB_Cleaner::TYPE_BOOL,
				'debug' => vB_Cleaner::TYPE_BOOL,
			));
			$fieldnames = array_map(array($db, 'escape_string'), $params['fieldname']);
			$sql = "
				DELETE FROM " . TABLE_PREFIX . "phrase
				WHERE varname = '" . $db->escape_string($params['varname']) . "' AND
						fieldname IN ('" . implode("','", $fieldnames) . "')
				" . ($params['t'] ? " AND languageid NOT IN(-1,0)" : "") . "
				" . (!$params['debug'] ? ' AND languageid <> -1' : '') . "
			";
			$result = $db->query_write($sql);
		}
	}

	public function fetchLanguages($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['baseonly']) AND !empty($params['direction']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'baseonly' => vB_Cleaner::TYPE_BOOL,
				'direction' => vB_Cleaner::TYPE_UINT,
				'languageid' => vB_Cleaner::TYPE_UINT,
			));
			$sql = "
				SELECT languageid, title, vblangcode, revision
				" . iif($params['baseonly'] == false, ', userselect, options, languagecode, charset, dateoverride, timeoverride, registereddateoverride,
					calformat1override, calformat2override, eventdateformatoverride, pickerdateformatoverride, logdateoverride, decimalsep, thousandsep, locale,
					IF(options & ' . $params['direction'] . ', \'ltr\', \'rtl\') AS direction'
				) . "
				FROM " . TABLE_PREFIX . "language
				" . ((!empty($params['languageid'])) ? 'WHERE languageid = ' . $params['languageid'] : 'ORDER BY title')
			;

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchPhrasesForExport($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['languageid']) AND !empty($params['product']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'languageid' => vB_Cleaner::TYPE_INT,
				'product' => vB_Cleaner::TYPE_STR,
				'custom' => vB_Cleaner::TYPE_NOCLEAN,
				'default_skipped_groups' => vB_Cleaner::TYPE_ARRAY_STR,
			));
			$params['default_skipped_groups'] = array_map(array(&$db, 'escape_string'), $params['default_skipped_groups']);
			$sql = "
				SELECT phrase.varname, phrase.text, phrase.fieldname, phrase.languageid,
					phrase.username, phrase.dateline, phrase.version
					" . (($params['languageid'] != -1) ? ", IF(ISNULL(phrase2.phraseid), 1, 0) AS iscustom" : "") . "
				FROM " . TABLE_PREFIX . "phrase AS phrase
				" . (($params['languageid'] != -1) ? "LEFT JOIN " . TABLE_PREFIX . "phrase AS phrase2 ON (phrase.varname = phrase2.varname AND phrase2.languageid = -1 AND phrase.fieldname = phrase2.fieldname)" : "") . "
				WHERE phrase.languageid IN (" . $params['languageid'] . ($params['custom'] ? ", 0" : "") . ")
					AND (phrase.product = '" . $db->escape_string($params['product']) . "'" .
					iif($params['product'] == 'vbulletin', " OR phrase.product = ''") . ")
					" . (($params['languageid'] == -1 AND !empty($params['default_skipped_groups'])) ? "AND fieldname NOT IN ('" . implode("', '", $params['default_skipped_groups']) . "')" : '') . "
				ORDER BY phrase.languageid, phrase.fieldname, phrase.varname
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function updateLanguagePhrases($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['languageid']) AND !empty($params['def']) AND !empty($params['fieldname']);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'def' => vB_Cleaner::TYPE_ARRAY_STR,
				'phr' => vB_Cleaner::TYPE_ARRAY_STR,
				'prod' => vB_Cleaner::TYPE_ARRAY_STR,
				'fieldname' => vB_Cleaner::TYPE_STR,
				'languageid' => vB_Cleaner::TYPE_INT,
			));
			$sql = array();

			require_once(DIR . '/includes/adminfunctions.php');
			$full_product_info = fetch_product_list(true);
			$userinfo = vB::getCurrentSession()->fetch_userinfo();

			foreach (array_keys($params['def']) AS $varname)
			{
				$defphrase =& $params['def']["$varname"];
				$newphrase =& $params['phr']["$varname"];
				$product	=& $params['prod']["$varname"];
				$product_version = $full_product_info["$product"]['version'];

				if ($newphrase != $defphrase)
				{
					$sql[] = "
						(" . $params['languageid'] . ",
						'" . $db->escape_string($params['fieldname']) . "',
						'" . $db->escape_string($varname) . "',
						'" . $db->escape_string($newphrase) . "',
						'" . $db->escape_string($product) . "',
						'" . $db->escape_string($userinfo['username']) . "',
						" . TIMENOW . ",
						'" . $db->escape_string($product_version) . "')
					";
				}
			}


			if (!empty($sql))
			{
				$query = "
					### UPDATE CHANGED PHRASES FROM LANGUAGE:" . $vbulletin->GPC['dolanguageid'] . ", PHRASETYPE:" . $vbulletin->GPC['fieldname'] . " ###
					REPLACE INTO " . TABLE_PREFIX . "phrase
						(languageid, fieldname, varname, text, product, username, dateline, version)
					VALUES
						" . implode(",\n\t\t\t\t", $sql) . "
				";

				$resultclass = 'vB_dB_' . $this->db_type . '_result';
				$result = new $resultclass($db, $query);
				return $result;
			}
		}
	}

	public function updateCronEnabled($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['updates']);
		}
		else
		{
			// clean inputs
			$params = vB::getCleaner()->cleanArray($params, array(
				'updates' => vB_Cleaner::TYPE_NOCLEAN,					// array(string => int)   cleaning next
			));
			$cleanedArray = array();
			foreach ($params['updates'] AS $key => $val)
			{
				$key = vB::getCleaner()->clean($key, vB_Cleaner::TYPE_STR);		// string, escaped below
				$val = vB::getCleaner()->clean($val, vB_Cleaner::TYPE_INT);		// int, 0 or 1
				$cleanedArray["$key"] = $val;
			}
			$params['updates'] = $cleanedArray; // replace with cleaned input
			unset($cleanedArray);

			$cases = '';
			foreach ($params['updates'] AS $varname => $status)
			{
				$cases .= "WHEN '" . $db->escape_string($varname) . "' THEN $status ";
			}

			$sql = "
				UPDATE " . TABLE_PREFIX . "cron SET active = CASE varname $cases ELSE active END
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchCronLogCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['varname']);
		}
		else
		{
			// clean params
			$params = vB::getCleaner()->cleanArray($params, array(
				'varname' => vB_Cleaner::TYPE_STR,						// string, also escaped below
			));

			$sqlconds = '';
			if (!empty($params['varname']))
			{
				$sqlconds = "WHERE cronlog.varname = '" . $db->escape_string($params['varname']) . "'";
			}

			$sql = "
				SELECT COUNT(*) AS total
				FROM " . TABLE_PREFIX . "cronlog AS cronlog
				$sqlconds
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchCronLog($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['varname']) AND !empty($params[vB_dB_Query::PARAM_LIMIT]);
		}
		else
		{
			// clean params
			$params = vB::getCleaner()->cleanArray($params, array(
				'varname' => vB_Cleaner::TYPE_STR,						// string, also escaped below
				'orderby' => vB_Cleaner::TYPE_NOCLEAN,					// string, used for switch control only
				vB_dB_Query::PARAM_LIMITPAGE => vB_Cleaner::TYPE_UINT, 	// int
				vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT, 		// int
				));

			$sqlconds = '';
			if (!empty($params['varname']))
			{
				$sqlconds = "WHERE cronlog.varname = '" . $db->escape_string($params['varname']) . "'";
			}

			if (empty($params[vB_dB_Query::PARAM_LIMITPAGE]))
			{
				$params[vB_dB_Query::PARAM_LIMITPAGE] = 1;
			}

			$startat = ($params[vB_dB_Query::PARAM_LIMITPAGE] - 1) * $params[vB_dB_Query::PARAM_LIMIT];

			switch ($params['orderby'])
			{
				case 'date':
					$order = 'cronlog.dateline DESC, cronlog.cronlogid DESC';
					break;

				case 'action':
					$order = 'cronlog.varname ASC, cronlog.cronlogid DESC';
					break;

				case 'cronid':
				default:
					$order = 'cronlog.cronlogid DESC';
					break;
			}

			$sql = "
				SELECT cronlog.*
				FROM " . TABLE_PREFIX . "cronlog AS cronlog
				LEFT JOIN " . TABLE_PREFIX . "cron AS cron ON (cronlog.varname = cron.varname)
				$sqlconds
				ORDER BY $order
				LIMIT $startat, " . $params[vB_dB_Query::PARAM_LIMIT]
			;

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function pruneCronLog($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['varname']) AND !empty($params['datecut']);
		}
		else
		{
			// clean params
			$params = vB::getCleaner()->cleanArray($params, array(
				'varname' => vB_Cleaner::TYPE_STR,				// string, also escaped below
				'datecut' => vB_Cleaner::TYPE_INT
			));

			$sqlconds = '';
			if (!empty($params['varname']))
			{
				$sqlconds = "AND varname = '" . $db->escape_string($params['varname']) . "'";
			}

			$sql = "
				DELETE FROM " . TABLE_PREFIX . "cronlog
				WHERE dateline < " . $params['datecut'] . "
					$sqlconds
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchWolAllUsers($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		else
		{
			$timeout = vB::getDatastore()->getOption('cookietimeout');
			$sortorder = (isset($params['sortorder']) AND $params['sortorder'] == 'asc') ? 'asc' : 'desc';

			if (isset($params['sortfield']))
			{
				switch ($params['sortfield'])
				{
					case 'location':
						$sqlsort = 'session.location';
						break;
					case 'time':
						$sqlsort = 'session.lastactivity';
						break;
					case 'host':
						$sqlsort = 'session.host';
						break;
					case 'posts':
						$sqlsort = 'user.posts';
						break;
					case 'username':
						$sqlsort = 'user.username';
						break;
					default:
						$sqlsort = 'session.lastactivity';
				}
			}
			else
			{
				$sqlsort = 'session.lastactivity';
			}

			$sqlsort = ' CASE WHEN user.userid > 0 THEN 1 ELSE 0 END DESC, ' . $sqlsort . ' ' . $sortorder;

			if (isset($params['sortfield']) AND !empty($params['sortfield']) AND $params['sortfield'] != 'time')
			{
				$sqlsort .= ', session.lastactivity DESC';
			}

			$cutoff = vB::getRequest()->getTimeNow() - $timeout;
			$wheresql = "WHERE session.lastactivity > $cutoff";

			$wheresql .= (isset($params['who']) AND $params['who'] == 'members') ? ' AND session.userid > 0' : '';

			if (isset($params['pagekey']) AND !empty($params['pagekey']))
			{
				$wheresql .= " AND session.pagekey = '" . $db->escape_string($params['pagekey']) . "'";
			}

			$perpage = (isset($params[vB_dB_Query::PARAM_LIMIT])) ? intval($params[vB_dB_Query::PARAM_LIMIT]) : 0;

			if ($perpage == 0)
			{
				$perpage = 200;
			}
			else if ($perpage < 1)
			{
				$perpage = 1;
			}

			if (empty($params['pagenumber']))
			{
				$params['pagenumber'] = 1;
			}

			$limitlower = ($params['pagenumber'] - 1) * $perpage;
			$limitupper = $perpage;

			//it doesn't appear that the avatar information is actually used anywhere.  Leaving the
			//flag in place (it used to be hookedup to an admin option) so that we can more easily
			//remove the avatar part of the query if/when we determine that we don't need it.
			$avatarenabled = true;
			$sql = "
				SELECT user.username, user.usergroupid AS usergroupid, session.useragent, session.wol, session.lastactivity, session.location,
					session.userid, user.options, user.posts, user.joindate, user.reputationlevelid, user.reputation,
					session.host, session.badlocation, session.incalendar, session.inthread,
					user.aim, user.icq, user.msn, user.yahoo, user.skype,
				IF(displaygroupid=0, user.usergroupid, displaygroupid) AS displaygroupid, infractiongroupid, user.usergroupid
				" . ($avatarenabled ? ', avatar.avatarpath, NOT ISNULL(customavatar.userid) AS hascustomavatar, customavatar.dateline AS avatardateline, customavatar.width AS avwidth, customavatar.height AS avheight, customavatar.height_thumb AS avheight_thumb, customavatar.width_thumb AS avwidth_thumb' : ''). "
				FROM " . TABLE_PREFIX . "session AS session
				" . (($params['who'] == 'guest' OR !$params['who']) ? "LEFT JOIN" : "INNER JOIN") . " " . TABLE_PREFIX . "user AS user ON session.userid = user.userid" ."
				" . ($avatarenabled ? "LEFT JOIN " . TABLE_PREFIX . "avatar AS avatar ON (avatar.avatarid = user.avatarid) LEFT JOIN " . TABLE_PREFIX . "customavatar AS customavatar ON (customavatar.userid = user.userid) " : '') . "
				$wheresql
				ORDER BY $sqlsort
				LIMIT $limitlower, $limitupper
			";

			return $this->getResultSet($db, $sql, __FUNCTION__);
		}
	}


	public function fetchWol($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['userid']);
		}
		else
		{
			$vboptions = vB::getDatastore()->getValue('options');
			$datecut = vB::getRequest()->getTimeNow() - $vboptions['cookietimeout'];
			$params['userid'] = intval($params['userid']);

			$sql = "
				SELECT user.username, session.useragent, session.location, session.lastactivity,
					user.userid, user.options, user.posts,
					session.host, session.badlocation, session.incalendar, session.inthread,
					user.aim, user.icq, user.msn, user.yahoo, user.skype,
				IF(displaygroupid=0, user.usergroupid, displaygroupid) AS displaygroupid, infractiongroupid, user.usergroupid
				FROM " . TABLE_PREFIX . "session AS session
				INNER JOIN " . TABLE_PREFIX . "user AS user" ." ON user.userid = session.userid
				WHERE session.lastactivity > $datecut
					AND session.userid = $params[userid]
				ORDER BY lastactivity DESC
				LIMIT 1
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchWolCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		else
		{
			$vboptions = vB::getDatastore()->getValue('options');
			$datecut = vB::getRequest()->getTimeNow() - $vboptions['cookietimeout'];

			$idsql = '';
			if (!empty($params['pagekey']))
			{
				$idsql = " AND session.pagekey = '" . $db->escape_string($params['pagekey']) . "'";
			}

			switch ($params['who'])
			{
				case 'members':
					$selectsql = 'DISTINCT session.userid';
					$whosql = ' AND session.userid > 0';
					break;
				case 'guests':
					$selectsql = 'session.sessionhash';
					$whosql = ' AND session.userid = 0';
					break;
				default:
					$whosql = '';
			}

			$sql = "
				SELECT COUNT($selectsql)
				FROM " . TABLE_PREFIX . "session AS session
				WHERE session.lastactivity > $datecut
					$idsql
					$whosql
			";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchTagsForCloud($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params[vB_dB_Query::PARAM_LIMIT]);
		}
		else
		{
			$sql = "
				SELECT tagnode.tagid, tag.tagtext, COUNT(*) AS searchcount
				FROM " . TABLE_PREFIX . "tagnode AS tagnode
				INNER JOIN " . TABLE_PREFIX . "tag AS tag ON (tagnode.tagid = tag.tagid)
				GROUP BY tagnode.tagid, tag.tagtext
				ORDER BY searchcount DESC
				LIMIT " . intval($params[vB_dB_Query::PARAM_LIMIT])
			;

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchSearchTagsForCloud($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params[vB_dB_Query::PARAM_LIMIT]);
		}
		else
		{
			$options = vB::getDatastore()->get_value('options');
			$timenow = vB::getRequest()->getTimeNow();
			$sql = "
				SELECT tagsearch.tagid, tag.tagtext, COUNT(*) AS searchcount
				FROM " . TABLE_PREFIX . "tagsearch AS tagsearch
				INNER JOIN " . TABLE_PREFIX . "tag AS tag ON (tagsearch.tagid = tag.tagid)
				" . ($options['tagcloud_searchhistory'] ?
					"WHERE tagsearch.dateline > " . ($timenow - (60 * 60 * 24 * $options['tagcloud_searchhistory'])) :
					'') . "
				GROUP BY tagsearch.tagid, tag.tagtext
				ORDER BY searchcount DESC
				LIMIT " . intval($params[vB_dB_Query::PARAM_LIMIT])
			;
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	public function fetchTagsForTagNavigation($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (intval($params['root_channel']) > 0 AND intval($params[vB_dB_Query::PARAM_LIMIT]) > 0);
		}
		else
		{
			$params = vB::getCleaner()->cleanArray($params, array(
				'root_channel' => vB_Cleaner::TYPE_INT,
				vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_INT,
			));

			// If root_channel is set to 0 or 1, we don't need the closure join,
			// because we should return tags from any channel

			/*select query*/
			$sql = "
				SELECT tag.tagid, tag.tagtext, COUNT(tag.tagid) AS count
				FROM " . TABLE_PREFIX . "tag AS tag
				INNER JOIN " . TABLE_PREFIX . "tagnode AS tagnode ON (tagnode.tagid = tag.tagid)
				" . ($params['root_channel'] > 1 ? ("
				INNER JOIN " . TABLE_PREFIX . "closure AS closure ON (closure.child = tagnode.nodeid)
				WHERE closure.parent = " . intval($params['root_channel']) . "
				") : '') . "
				GROUP BY tag.tagid
				ORDER BY count DESC
				LIMIT " . intval($params[vB_dB_Query::PARAM_LIMIT]) . "
			";
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);

			return $result;
		}
	}

	public function fetchCountInfractionsByCond($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['status']);
		}
		else
		{
			$cleaner = vB::getCleaner();
			$params = $cleaner->cleanArray($params, array(
 				'whoadded'=> vB_Cleaner::TYPE_UINT,
 				'userid' => vB_Cleaner::TYPE_UINT,
 				'start' => vB_Cleaner::TYPE_UNIXTIME,
 				'end' => vB_Cleaner::TYPE_UNIXTIME,
 				'infractionlevelid' => vB_Cleaner::TYPE_INT,
 				'status' => vB_Cleaner::TYPE_STR,
 			));

			$sql = $this->getInfractionsSearchSql('COUNT(*) AS total', $params, $db, false);
			return $this->getResultSet($db, $sql);
		}
	}

	public function fetchInfractionsByCondLimit($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['status']);
		}
		else
		{
			$cleaner = vB::getCleaner();
			$params = $cleaner->cleanArray($params, array(
 				'whoadded'=> vB_Cleaner::TYPE_UINT,
 				'userid' => vB_Cleaner::TYPE_UINT,
 				'start' => vB_Cleaner::TYPE_UNIXTIME,
 				'end' => vB_Cleaner::TYPE_UNIXTIME,
 				'infractionlevelid' => vB_Cleaner::TYPE_INT,
				'status' => vB_Cleaner::TYPE_STR,
				'orderby' => vB_Cleaner::TYPE_STR,
				vB_dB_Query::PARAM_LIMITSTART => vB_Cleaner::TYPE_UINT,
				vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT,
 			));

			$select = "
				infraction.*,
				user2.username,
				user.username AS leftby_username,
				node.userid AS whoadded,
				node.publishdate,
				IF(ISNULL(node.nodeid) AND infraction.nodeid != 0, 1, 0) AS postdeleted,
				node.parentid AS postthreadid";

			$sql = $this->getInfractionsSearchSql($select, $params, $db, true);
			return $this->getResultSet($db, $sql);
		}
	}

	private function getInfractionsSearchSql($select, $params, $db, $joinUsers)
	{
		$where = array();
		if ($params['whoadded'])
		{
			$where[] = "node.userid = " . intval($params['whoadded']);
		}

		if ($params['userid'])
		{
			$where[] = "infraction.infracteduserid = " . intval($params['userid']);
		}

		if ($params['start'])
		{
			$where[] = "node.publishdate >= " . intval($params['start']);
		}

		if ($params['end'])
		{
			$where[] = "node.publishdate <= " . intval($params['end']);
		}

		if ($params['infractionlevelid'] != -1)
		{
			$where[] = "infraction.infractionlevelid = " . intval($params['infractionlevelid']);
		}

		switch ($params['status'])
		{
			case 'active':
				$where[] = "action = 0";
				break;
			case 'expired':
				$where[] = "action = 1";
				break;
			case 'reversed':
				$where[] = "action = 2";
				break;
		}

		$orderby = '';
		if(isset($params['orderby']))
		{
			switch($params['orderby'])
			{
				case 'points':
					$orderby = 'points DESC';
					break;
				case 'expires':
					$orderby = 'action, expires';
					break;
				case 'username':
					$orderby = 'node.authorname';
					break;
				case 'leftby_username':
					$orderby = 'user.username';
					break;
				default:
					$orderby = 'node.publishdate DESC';
					break;
			}
		}

		$limit = '';
		if(isset($params[vB_dB_Query::PARAM_LIMITSTART]))
		{
			$limit = intval($params[vB_dB_Query::PARAM_LIMITSTART]) . ", " . intval($params[vB_dB_Query::PARAM_LIMIT]);
		}

		$sql = "
			SELECT $select
			FROM " . TABLE_PREFIX . "infraction AS infraction
				LEFT JOIN " . TABLE_PREFIX . "node AS node ON (infraction.nodeid = node.nodeid)";

		if($joinUsers)
		{
			$sql .= " LEFT JOIN " . TABLE_PREFIX . "user AS user ON (node.userid = user.userid)
				LEFT JOIN " . TABLE_PREFIX . "user AS user2 ON (infraction.infracteduserid = user2.userid)";
		}

		if($where)
		{
			$sql .= " WHERE " . implode(' AND ', $where);
		}

		if($orderby)
		{
			$sql .= " ORDER BY $orderby";
		}

		if ($limit)
		{
			$sql .= " LIMIT $limit";
		}

		return $sql;
	}


	/**
	 * "Magic" Function that builds all the information regarding infractions
	 * (only used in Cron)
	 *
	 * @param	array	Infraction Points Array
	 * @param	array	Infractions Array
	 * @param	array	Warnings Array
	 *
	 * @return	boolean	Whether infractions info was updated.
	 */
	public function buildUserInfractions($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['points']) OR !isset($params['infractions']) OR !isset($params['warnings']))
			{
				return false;
			}
			return true;
		}

		$warningsql = array();
		$infractionsql = array();
		$ipointssql = array();
		$querysql = array();
		$userids = array();

		// ############################ WARNINGS #################################
		$wa = array();
		foreach($params['warnings'] AS $userid => $warning)
		{
			$warning = (int) $warning;
			$userid = (int) $userid;
			$wa["$warning"][] = $userid;
			$userids["$userid"] = $userid;
		}
		unset($params['warnings']);

		foreach($wa AS $warning => $users)
		{
			$warningsql[] = "WHEN userid IN(" . implode(', ', $users) . ") THEN $warning";
		}
		unset($wa);
		if (!empty($warningsql))
		{
			$querysql[] = "
			warnings = CAST(warnings AS SIGNED) -
			CASE
				" . implode(" \r\n", $warningsql) . "
			ELSE 0
			END";
		}
		unset($warningsql);

		// ############################ INFRACTIONS ##############################
		$if = array();
		foreach($params['infractions'] AS $userid => $infraction)
		{
			$infraction = (int) $infraction;
			$userid = (int) $userid;
			$if["$infraction"][] = $userid;
			$userids["$userid"] = $userid;
		}
		unset($params['infractions']);
		foreach($if AS $infraction => $users)
		{
			$infractionsql[] = "WHEN userid IN(" . implode(', ', $users) . ") THEN $infraction";
		}
		unset($if);
		if (!empty($infractionsql))
		{
			$querysql[] = "
			infractions = CAST(infractions AS SIGNED) -
			CASE
				" . implode(" \r\n", $infractionsql) . "
			ELSE 0
			END";
		}
		unset($infractionsql);

		// ############################ POINTS ###################################
		$ip = array();
		foreach($params['points'] AS $userid => $point)
		{
			$point = (int) $point;
			$userid = (int) $userid;
			$ip["$point"][] = $userid;
		}
		unset($params['points']);
		foreach($ip AS $point => $users)
		{
			$ipointssql[] = "WHEN userid IN(" . implode(', ', $users) . ") THEN $point";
		}
		unset($ip);
		if (!empty($ipointssql))
		{
			$querysql[] = "
			ipoints = CAST(ipoints AS SIGNED) -
			CASE
				" . implode(" \r\n", $ipointssql) . "
			ELSE 0
			END";
		}
		unset($ipointssql);

		if (!empty($querysql))
		{
			$db->query_write("
				UPDATE " . TABLE_PREFIX . "user
				SET " . implode(', ', $querysql) . "
				WHERE userid IN (" . implode(', ', $userids) . ")
			");

			return true;
		}
		else
		{
			return false;
		}
	}

	public function fetchUsersInfractionGroups($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['override_groupid']);
		}
		$sql = "SELECT userid
			FROM " . TABLE_PREFIX . "user
			WHERE FIND_IN_SET('" . intval($params['override_groupid']) . "', infractiongroupids)";
		if (isset($params['point_level']))
		{
			$sql .= "\n OR (ipoints >= " . intval($params['point_level']);
			if (isset($params['point_level']))
			{
				$sql .= " AND usergroupid = " . intval($params['applies_groupid']);
			}
			$sql .= ')';
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;

	}

	public function fetchModlogCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}

		if ($params['userid'] OR $params['modaction'])
		{
			if ($params['userid'])
			{
				$sqlconds[] = "moderatorlog.userid = " . intval($params['userid']);
			}
			if ($params['modaction'])
			{
				$sqlconds[] = "moderatorlog.action LIKE '%" . $vbulletin->db->escape_string_like($params['modaction']) . "%'";
			}
		}

		if ($params['startdate'])
		{
			$sqlconds[] = "moderatorlog.dateline >= " . intval($params['startdate']);
		}

		if ($params['enddate'])
		{
			$sqlconds[] = "moderatorlog.dateline <= " . intval($params['enddate']);
		}

		if ($params['product'])
		{
			if ($params['product'] == 'vbulletin')
			{
				$sqlconds[] = "moderatorlog.product IN ('', 'vbulletin')";
			}
			else
			{
				$sqlconds[] = "moderatorlog.product = '" . $vbulletin->db->escape_string($params['product']) . "'";
			}
		}
	/** @todo call hook */
	// Legacy Hook 'admin_modlogviewer_query' Removed //

		$sql = "
			SELECT COUNT(*) AS total
			FROM " . TABLE_PREFIX . "moderatorlog AS moderatorlog
			" . (!empty($sqlconds) ? "WHERE " . implode("\r\n\tAND ", $sqlconds) : "") . "
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchModlogs($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}

		if(empty($params[vB_dB_Query::PARAM_LIMIT]))
		{
			$params[vB_dB_Query::PARAM_LIMIT] = intval($params['perpage']);
		}

		if ($params['userid'] OR $params['modaction'])
		{
			if ($params['userid'])
			{
				$sqlconds[] = "moderatorlog.userid = " . intval($params['userid']);
			}
			if ($params['modaction'])
			{
				$sqlconds[] = "moderatorlog.action LIKE '%" . $db->escape_string_like($params['modaction']) . "%'";
			}
		}

		if ($params['startdate'])
		{
			$sqlconds[] = "moderatorlog.dateline >= " . intval($params['startdate']);
		}

		if ($params['enddate'])
		{
			$sqlconds[] = "moderatorlog.dateline <= " . intval($params['enddate']);
		}

		if ($params['product'])
		{
			if ($params['product'] == 'vbulletin')
			{
				$sqlconds[] = "moderatorlog.product IN ('', 'vbulletin')";
			}
			else
			{
				$sqlconds[] = "moderatorlog.product = '" . $db->escape_string($params['product']) . "'";
			}
		}

	// Legacy Hook 'admin_modlogviewer_query' Removed //

		$startat = ($params['pagenumber'] - 1) * intval($params[vB_dB_Query::PARAM_LIMIT]);

		switch($params['orderby'])
		{
			case 'user':
				$order = 'username ASC, dateline DESC';
				break;
			case 'modaction':
				$order = 'action ASC, dateline DESC';
				break;
			case 'date':
			default:
				$order = 'dateline DESC';
		}
		$sql = "
				SELECT moderatorlog.*, user.username,
				node.title AS node_title, node.routeid
				FROM " . TABLE_PREFIX . "moderatorlog AS moderatorlog
				LEFT JOIN " . TABLE_PREFIX . "user AS user ON (user.userid = moderatorlog.userid)
				LEFT JOIN " . TABLE_PREFIX . "node AS node ON (node.nodeid = moderatorlog.nodeid)
				" . (!empty($sqlconds) ? "WHERE " . implode("\r\n\tAND ", $sqlconds) : "") . "
				ORDER BY $order
				LIMIT $startat, " . intval($params[vB_dB_Query::PARAM_LIMIT]) . "
				";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function getModLogsByConds($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['conds']);
		}
		$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
		$queryBuilder = new $className($db, false);
		$where = $queryBuilder->conditionsToFilter($params['conds']);

		$sql = "
			SELECT COUNT(*) AS total
			FROM " . TABLE_PREFIX ."moderatorlog
			WHERE $where
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchApiLogs($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}

		$sqlconds = $this->fetchApiLogsSqlconds($params, $db);

		switch ($params['orderby'])
		{
			case 'user':
				$order = 'user.username ASC, apilog.apilogid DESC';
				break;
			case 'clientname':
				$order = 'apiclient.clientname ASC, apilog.apiclientid ASC, apilog.apilogid DESC';
				break;
			default:	// Date
				$order = 'apilogid DESC';
		}

		$sql = "
			SELECT apilog.*, user.username, apiclient.clientname, apiclient.userid
			FROM " . TABLE_PREFIX . "apilog AS apilog
			LEFT JOIN " . TABLE_PREFIX . "apiclient AS apiclient ON (apiclient.apiclientid = apilog.apiclientid)
			LEFT JOIN " . TABLE_PREFIX . "user AS user ON (apiclient.userid = user.userid)
			$sqlconds
			ORDER BY $order
			LIMIT " . intval($params[vB_dB_Query::PARAM_LIMITSTART]) . ", " . intval($params[vB_dB_Query::PARAM_LIMIT]);

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;

	}

	public function fetchApiLogsCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}

		$sqlconds = $this->fetchApiLogsSqlconds($params, $db);

		$sql = "SELECT COUNT(*) AS total FROM " . TABLE_PREFIX . "apilog AS apilog
			LEFT JOIN " . TABLE_PREFIX . "apiclient AS apiclient ON (apiclient.apiclientid = apilog.apiclientid)
			LEFT JOIN " . TABLE_PREFIX . "user AS user ON (apiclient.userid = user.userid)
		$sqlconds";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;

	}

	protected function fetchApiLogsSqlconds($params, $db)
	{
		if ($params['userid'] >= 0 OR $params['apiclientid'] OR $params['apiclientuniqueid'] OR $params['apiclientname'] OR $params['startdate'] OR $params['enddate'])
		{
			$sqlconds = 'WHERE 1=1 ';
			if ($params['apiclientid'])
			{
				$sqlconds .= " AND apilog.apiclientid = " . intval($params['apiclientid']);
			}
			elseif ($params['apiclientuniqueid'])
			{
				$sqlconds .= " AND apiclient.uniqueid = '" . $db->escape_string($params['apiclientuniqueid']) . "'";
			}
			else
			{
				if ($params['userid'] >= 0)
				{
					$sqlconds .= " AND apiclient.userid = " . intval($params['userid']);
				}
				if ($params['apiclientname'])
				{
					$sqlconds .= " AND apiclient.clientname = '" . $db->escape_string($params['apiclientname']) . "'";
				}
			}
			if ($params['startdate'])
			{
				$sqlconds .= " AND apilog.dateline >= " . intval($params['startdate']);
			}
			if ($params['enddate'])
			{
				$sqlconds .= " AND apilog.dateline <= " . intval($params['enddate']);
			}
		}
		else
		{
			$sqlconds = '';
		}

		return $sqlconds;
	}


	public function fetchApiLogsCountDatecut($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['datecut']);
		}

		$sql = "SELECT COUNT(*) AS total FROM " . TABLE_PREFIX . "apilog AS apilog WHERE dateline < " . intval($params['datecut']);

		if ($params['apiclientid'])
		{
			$sql .= "\nAND apiclientid = " . intval($params['apiclientid']);
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;

	}


	public function fetchApiActivity($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['start_time']) AND !empty($params['end_time']);
		}

		switch ($params['sort'])
		{
			case 'date_asc':
				$orderby = 'dateline ASC';
				break;
			case 'date_desc':
				$orderby = 'dateline DESC';
				break;
			case 'total_asc':
				$orderby = 'total ASC';
				break;
			case 'total_desc':
				$orderby = 'total DESC';
				break;
			default:
				$orderby = 'dateline DESC';
		}

		switch ($params['scope'])
		{
			case 'weekly':
				$sqlformat = '%U %Y';
				break;
			case 'monthly':
				$sqlformat = '%m %Y';
				break;
			default:
				$sqlformat = '%w %U %m %Y';
				break;
		}

		$sql = "
			SELECT COUNT(*) AS total,
			DATE_FORMAT(from_unixtime(dateline), '$sqlformat') AS formatted_date,
			AVG(dateline) AS dateline
			FROM " . TABLE_PREFIX . "apilog
			WHERE dateline >= " . intval($params['start_time']) . "
				AND dateline <= " . intval($params['end_time']) . "
			GROUP BY formatted_date
			" . (empty($params['nullvalue']) ? " HAVING total > 0 " : "") . "
			ORDER BY $orderby
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;

	}
	public function fetchStylevarsArray($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['parentlist']);
		}

		$cleaner = vB::getCleaner();
		$cleaned = $cleaner->cleanArray($params, array(
			'stylevars' => vB_Cleaner::TYPE_ARRAY_STR,
			'parentlist' => vB_Cleaner::TYPE_ARRAY_INT,
			'sortdir' => vB_Cleaner::TYPE_STR
		));
		$sortdir = empty($params['sortdir']) ? 'ASC' : $db->clean_identifier($cleaned['sortdir']);
		$clause = '';
		if (!empty($cleaned['stylevars']))
		{
			$cleaned['stylevars'] = array_map(array($db, 'escape_string'), $cleaned['stylevars']);
			$clause = ' AND stylevar.stylevarid IN ("' . implode('", "', $cleaned['stylevars']) . '")';
		}
		$sql = "
		SELECT stylevardfn.*, stylevar.styleid AS stylevarstyleid, stylevar.value, stylevar.stylevarid
			FROM " . TABLE_PREFIX . "stylevar AS stylevar
			INNER JOIN " . TABLE_PREFIX . "stylevardfn AS stylevardfn ON(stylevar.stylevarid = stylevardfn.stylevarid)
			WHERE stylevar.styleid IN (" . implode(',', $cleaned['parentlist']) . ") $clause
			ORDER by stylevar.stylevarid, stylevar.styleid $sortdir
		";

		$config = vB::getConfig();
		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function isFreeLock($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['table']);
		}

		$params['table'] = vB::getCleaner()->clean($params['table'], vB_Cleaner::TYPE_STR);
		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, "SELECT IS_FREE_LOCK('" . TABLE_PREFIX . $db->clean_identifier($params['table']) . "')");
		return $result;
	}

	public function getLock($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['table']);
		}

		$params['table'] = vB::getCleaner()->clean($params['table'], vB_Cleaner::TYPE_STR);
		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, "SELECT GET_LOCK('" . TABLE_PREFIX . $db->clean_identifier($params['table']) . "', 2)");
		return $result;
	}
	public function releaseLock($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['table']);
		}

		$params['table'] = vB::getCleaner()->clean($params['table'], vB_Cleaner::TYPE_STR);
		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, "SELECT RELEASE_LOCK('" . TABLE_PREFIX . $db->clean_identifier($params['table']) . "')");
		return $result;
	}

	/**
	* Lock tables
	*/
	public function lockTables($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['tablelist']) AND is_array($params['tablelist']);
		}

		$sql = '';
		$cleaner = vB::getCleaner();
		foreach($params['tablelist'] AS $name => $type)
		{
			$name = $cleaner->clean($name, vB_Cleaner::TYPE_STR);
			$type = $cleaner->clean($type, vB_Cleaner::TYPE_STR);
			$sql .= (!empty($sql) ? ', ' : '') . TABLE_PREFIX . $db->clean_identifier($name) . " " . $db->clean_identifier($type);
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, "LOCK TABLES $sql");
		return $result;

	}

	/**
	* Unlock tables
	*
	*/
	public function unlockTables($params, $db, $check_only = false)
	{
		# must be called from exec_shutdown as tables can get stuck locked if pconnects are enabled
		if ($check_only)
		{
			return true;
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, "UNLOCK TABLES");
		return $result;
	}

	public function updateCron($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['updates']);
		}

		$cases = '';
		foreach ($params['updates'] AS $varname => $status)
		{
			$cases .= "WHEN '" . $db->escape_string($varname) . "' THEN $status ";
		}

		$sql = "
			UPDATE " . TABLE_PREFIX . "cron SET active = CASE varname $cases ELSE active END
		";
		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}
	/**
	* Fetch SQL clause for haystack LIKE needle
	*
	* @param	string	Needle
	* @param	string	Field to search (varname or text)
	* @param	boolean	Search field is binary?
	* @param	boolean	Do case-sensitive search?
	*
	* @return	string	'haystack LIKE needle' variant
	*/
	private function fetch_field_like_sql($searchstring, $field, $isbinary = false, $casesensitive = false)
	{
		if ($casesensitive)
		{
			return "BINARY $field LIKE '%" . $this->db->escape_string_like($searchstring) . "%'";
		}
		else if ($isbinary)
		{
			return "UPPER($field) LIKE UPPER('%" . $this->db->escape_string_like($searchstring) . "%')";
		}
		else
		{
			return "$field LIKE '%" . $this->db->escape_string_like($searchstring) . "%'";
		}
	}

	public function fetchPhrasesForDisplay($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['searchstring']) AND isset($params['languageid']);
		}
		$this->db = &$db;

		$params = vB::getCleaner()->cleanArray($params, array(
			'languageid' => vB_Cleaner::TYPE_INT,
			'searchstring' => vB_Cleaner::TYPE_STR,
		));

		$phrases = $db->query_read("
			SELECT
			IF(pcust.phraseid IS NULL, pmast.phraseid, pcust.phraseid) AS phraseid,
			IF(pcust.phraseid IS NULL, pmast.text, pcust.text) AS xtext
			FROM " . TABLE_PREFIX . "phrase AS pmast
			LEFT JOIN " . TABLE_PREFIX . "phrase AS pcust ON (
					pcust.varname = pmast.varname AND
					pcust.fieldname = pmast.fieldname AND
					pcust.languageid = " . $params['languageid'] . "
			)
			WHERE pmast.languageid = -1
			HAVING " . $this->fetch_field_like_sql($params['searchstring'], 'xtext', false, true) . "
		");

		$phraseids = '0';

		while ($phrase = $db->fetch_array($phrases))
		{
			$phraseids .= ",$phrase[phraseid]";
		}

		$db->free_result($phrases);
		$sql = "
			SELECT phrase.*, language.title
			FROM " .TABLE_PREFIX . "phrase AS phrase
			LEFT JOIN " . TABLE_PREFIX . "language AS language USING(languageid)
			WHERE phrase.phraseid IN($phraseids)
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchPhrases($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['languageid']) AND isset($params['type']);
		}

		$cleaner = vB::getCleaner();
		$cleaned = $cleaner->cleanArray($params, array(
			'languageid' => vB_Cleaner::TYPE_INT,
			'fieldname' => vB_Cleaner::TYPE_STR,
			'type' => vB_Cleaner::TYPE_INT
		));

		$phrasetypeSQL = '';
		if (!empty($cleaned['fieldname']))
		{
			$phrasetypeSQL = $cleaned['fieldname'] == -1 ? 'AND special = 0' : ("AND p1.fieldname = '" . $db->escape_string($cleaned['fieldname']) . "'");
		}

		$sql = "
		SELECT p1.varname AS p1var, p1.text AS default_text, p1.fieldname, IF(p1.languageid = -1, 'MASTER', 'USER') AS type,
		p2.phraseid, p2.varname AS p2var, p2.text, NOT ISNULL(p2.phraseid) AS found,
		p1.product
		FROM " . TABLE_PREFIX . "phrase AS p1
		LEFT JOIN " . TABLE_PREFIX . "phrasetype AS phrasetype ON (p1.fieldname = phrasetype.fieldname)
		LEFT JOIN " . TABLE_PREFIX . "phrase AS p2 ON (p2.varname = p1.varname AND p2.fieldname = p1.fieldname AND p2.languageid = $cleaned[languageid])
		WHERE p1.languageid = $cleaned[type] $phrasetypeSQL
		ORDER BY p1.varname
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function fetchKeepNames($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['keepnames']);
		}
		$keepnames= array();
		foreach ($params['keepnames'] as $value)
		{
		$keepnames[] = "\n\t\t\t\t\t(varname = '" . $db->escape_string($value['varname']) . "' AND fieldname = '" . $db->escape_string($value['fieldname']) . "')";
		}
		$sql = "
		SELECT *
		FROM " . TABLE_PREFIX . "phrase
		WHERE " . implode("\nOR ", $keepnames);

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchCountPhrasesByLang($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		$fieldname = vB::getCleaner()->clean($params['fieldname'], vB_Cleaner::TYPE_STR);
		$sql = "SELECT COUNT(*) AS total FROM " . TABLE_PREFIX . "phrase AS phrase
		WHERE languageid IN(-1, 0)";
		if ($fieldname)
		{
			$sql .= " AND fieldname = '" . $db->escape_string($fieldname) . "'";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function fetchPhrasesOrderedPaged($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		$sql = "SELECT varname, fieldname FROM " . TABLE_PREFIX . "phrase AS phrase
		WHERE languageid IN(-1, 0)";

		$cleaned = vB::getCleaner()->cleanArray($params, array(
			'fieldname' => vB_Cleaner::TYPE_STR,
			vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT,
			vB_dB_Query::PARAM_LIMITPAGE => vB_Cleaner::TYPE_UINT
		));

		if ($cleaned['fieldname'])
		{
			$sql .= " AND fieldname = '" . $db->escape_string($cleaned['fieldname']) . "'";
		}
		$sql .= " ORDER BY fieldname, varname
		LIMIT " . $cleaned[vB_dB_Query::PARAM_LIMITPAGE] * $cleaned[vB_dB_Query::PARAM_LIMIT] . ", " . $cleaned[vB_dB_Query::PARAM_LIMIT];

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function updatePhraseDefLanguage($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['product']) ? true : false ;
		}

		$cleaned = vB::getCleaner()->cleanArray($params, array(
			'product' => vB_Cleaner::TYPE_STR,
			'skipped_groups' => vB_Cleaner::TYPE_ARRAY_STR
		));

		$sql = "UPDATE " . TABLE_PREFIX . "phrase SET languageid = -10
			WHERE languageid = -1
			AND (product = '" . $db->escape_string($cleaned['product']) . "'";
		if ($cleaned['product'] == 'vbulletin')
		{
			$sql .= " OR product = ''";
		}
		$sql .= ") ";
		if ($cleaned['skipped_groups'])
		{
			$cleaned['skipped_groups'] = array_map(array($db, 'escape_string'), $cleaned['skipped_groups']);
			$sql .= " AND " . TABLE_PREFIX . "phrase.fieldname NOT IN ('" . implode("', '", $cleaned['skipped_groups']) . "')";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function updatePhraseByProduct($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['product']) ? true : false ;
		}

		$cleaned = vB::getCleaner()->cleanArray($params, array(
			'product' => vB_Cleaner::TYPE_STR,
			'languageid' => vB_Cleaner::TYPE_INT,
			'skipped_groups' => vB_Cleaner::TYPE_ARRAY_STR
		));

		$sql = "UPDATE " . TABLE_PREFIX . "phrase, " . TABLE_PREFIX . "phrase AS phrase2
		SET " . TABLE_PREFIX . "phrase.languageid = -11
		WHERE " . TABLE_PREFIX . "phrase.languageid = " . $cleaned['languageid'] . "
		AND (" . TABLE_PREFIX . "phrase.product = '" . $db->escape_string($cleaned['product']) . "'";
		if ($cleaned['product'] == 'vbulletin')
		{
			$sql .= " OR product = ''";
		}
		$sql .= ")
			AND (phrase2.product = '" . $db->escape_string($cleaned['product']) . "'";
		if ($cleaned['product'] == 'vbulletin')
		{
			$sql .= " OR phrase2.product = ''";
		}
		$sql .= ")
		AND " . TABLE_PREFIX . "phrase.varname = phrase2.varname
		AND phrase2.languageid = 0
		AND " . TABLE_PREFIX . "phrase.fieldname = phrase2.fieldname";
		if ($cleaned['skipped_groups'])
		{
			$cleaned['skipped_groups'] = array_map(array($db, 'escape_string'), $cleaned['skipped_groups']);
			$sql .= " AND " . TABLE_PREFIX . "phrase.fieldname NOT IN ('" . implode("', '", $cleaned['skipped_groups']) . "')";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function updatePhraseLanguage($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['product']) AND isset($params['languageid']);
		}

		$cleaned = vB::getCleaner()->cleanArray($params, array(
			'product' => vB_Cleaner::TYPE_STR,
			'languageid' => vB_Cleaner::TYPE_INT,
			'skipped_groups' => vB_Cleaner::TYPE_ARRAY_STR
		));

		$sql = "UPDATE " . TABLE_PREFIX . "phrase SET languageid = -10
		WHERE languageid = $cleaned[languageid]
		AND (product = '" . $db->escape_string($cleaned['product']) . "'";
		if ($cleaned['product'] == 'vbulletin')
		{
			$sql .= " OR product = ''";
		}

		if ($cleaned['skipped_groups'])
		{
			$cleaned['skipped_groups'] = array_map(array($db, 'escape_string'), $cleaned['skipped_groups']);
			$sql .= " AND " . TABLE_PREFIX . "phrase.fieldname NOT IN ('" . implode("', '", $cleaned['skipped_groups']) . "')";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	/** Fetch list of users to prune
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function fetchPruneUsers($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['usergroupid']);
		}
		else
		{
			$cleaner = vB::getCleaner();
			$params = $cleaner->cleanArray($params, array(
				'usergroupid' => vB_Cleaner::TYPE_INT,
				'includesecondary' => vB_Cleaner::TYPE_BOOL,
				'daysprune' => vB_Cleaner::TYPE_INT,
				'minposts' => vB_Cleaner::TYPE_INT,
				'order'	=> vB_Cleaner::TYPE_STR,
				'joindate' => vB_Cleaner::TYPE_NOCLEAN //is cleaned below.
			));

			$sqlcond = array();
			if ($params['usergroupid'] != -1)
			{
				$cond = "user.usergroupid = " . $params['usergroupid'];

				if($params['includesecondary'])
				{
					$cond = "($cond OR find_in_set(" . $params['usergroupid'] . ", user.membergroupids))";
				}

				$sqlcond[] = $cond;
			}

			//days prune
			if ($params['daysprune'])
			{
				$daysprune = intval(TIMENOW - $params['daysprune'] * 86400);
				$sqlcond[] = "lastactivity < $daysprune";
			}

			//join date
			if (!empty($params['joindate']['month']) AND !empty($params['joindate']['year']))
			{
				$params['joindate'] = array(
					'month' => $cleaner->clean($params['joindate']['month'], vB_Cleaner::TYPE_UINT),
					'day' => $cleaner->clean($params['joindate']['day'], vB_Cleaner::TYPE_UINT),
					'year' => $cleaner->clean($params['joindate']['year'], vB_Cleaner::TYPE_UINT),
				);
				$joindateunix = mktime(0, 0, 0, $params['joindate']['month'], $params['joindate']['day'], $params['joindate']['year']);
				if ($joindateunix)
				{
					$sqlcond[] = "joindate < $joindateunix";
				}
			}

			//minimum posts
			if ($params['minposts'])
			{
				$sqlcond[] = "posts < " . $params['minposts'];
			}

			switch($params['order'])
			{
				case 'username':
					$orderby = 'ORDER BY username ASC';
					break;
				case 'email':
					$orderby = 'ORDER BY email ASC';
					break;
				case 'usergroup':
					$orderby = 'ORDER BY usergroup.title ASC';
					break;
				case 'posts':
					$orderby = 'ORDER BY posts DESC';
					break;
				case 'lastactivity':
					$orderby = 'ORDER BY lastactivity DESC';
					break;
				case 'joindate':
					$orderby = 'ORDER BY joindate DESC';
					break;
				default:
					$orderby = 'ORDER BY username ASC';
					break;
			}

			$sql = "
				SELECT DISTINCT
					user.userid, username, email, posts, lastactivity, joindate,
					user.usergroupid, moderator.moderatorid, usergroup.title
				FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "moderator AS moderator ON(moderator.userid = user.userid)
				LEFT JOIN " . TABLE_PREFIX . "usergroup AS usergroup ON(usergroup.usergroupid = user.usergroupid)
					" . ($sqlcond ? "WHERE " . implode(' AND ', $sqlcond) : '') . "
				GROUP BY user.userid $orderby";

			return $this->getResultSet($db, $sql, __FUNCTION__);
		}
	}

	public function replaceSetting($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (
					!isset($params['product']) OR
					!isset($params['varname']) OR
					!isset($params['grouptitle']) OR
					!isset($params['value']) OR
					!isset($params['datatype']) OR
					!isset($params['optioncode'])
			)
			{
				return false;
			}
			return true;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'product'		=> vB_Cleaner::TYPE_STR,
			'varname'		=> vB_Cleaner::TYPE_STR,
			'grouptitle'	=> vB_Cleaner::TYPE_STR,
			'value'			=> vB_Cleaner::TYPE_STR,
			'optioncode'	=> vB_Cleaner::TYPE_STR,
			'default_value'	=> vB_Cleaner::TYPE_STR,
			'datatype'		=> vB_Cleaner::TYPE_STR,
			'adminperm'		=> vB_Cleaner::TYPE_STR,
		));

		$fields = array('product', 'varname', 'grouptitle', 'value', 'optioncode', 'volatile', 'adminperm');
		$values = array(
			"'" . $db->escape_string($params['product']) . "'",
			"'" . $db->escape_string($params['varname']) . "'",
			"'" . $db->escape_string($params['grouptitle']) . "'",
			"'" . $db->escape_string($params['value']) . "'",
			"'" . $db->escape_string($params['optioncode']) . "'",
			1,
			"'" . $db->escape_string($params['adminperm']) . "'",

		);

		if (!empty($params['default_value']))
		{
			$fields[] = 'default_value';
			$values[] = "'" . $db->escape_string($params['default_value']) . "'";
		}

		if (!empty($params['datatype']))
		{
			$fields[] = 'datatype';
			$values[] = "'" . $db->escape_string($params['datatype']) . "'";
		}

		$sql = "REPLACE INTO " . TABLE_PREFIX . "setting
		(" . implode(', ', $fields) .
		")VALUES(
		" . implode(', ', $values) .
		")";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::getConfig();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function replaceTemplates($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['querybits']);
		}

		$fields = array_keys($params['querybits'][0]);
		$cleaned = array();
		$fieldmap = array(
			'templateid' => vB_Cleaner::TYPE_UINT,
			'styleid' => vB_Cleaner::TYPE_INT,
			'title' => vB_Cleaner::TYPE_STR,
			'template' => vB_Cleaner::TYPE_STR,
			'template_un' => vB_Cleaner::TYPE_STR,
			'templatetype' => vB_Cleaner::TYPE_STR,
			'dateline' => vB_Cleaner::TYPE_UNIXTIME,
			'username' => vB_Cleaner::TYPE_STR,
			'version' => vB_Cleaner::TYPE_STR,
			'product' => vB_Cleaner::TYPE_STR,
			'mergestatus' => vB_Cleaner::TYPE_STR,
			'textonly' => vB_Cleaner::TYPE_BOOL,
		);
		$cleaner = vB::getCleaner();
		foreach ($fields AS $field)
		{
			$clean = $db->clean_identifier($field);
			if (array_key_exists($clean, $fieldmap))
			{
				$cleaned[] = $clean;
			}
		}
		if (!empty($cleaned))
		{
			$sql = "
				REPLACE INTO " . TABLE_PREFIX . "template
				(" . implode(', ', $cleaned) . ")
				VALUES
			";

			$rows = array();
			foreach ($params['querybits'] as $querybit)
			{
				$values = array();
				foreach ($querybit as $key => $val)
				{
					$cleankey = $db->clean_identifier($key);
					if (in_array($cleankey, $cleaned))
					{
						$cleanval = $cleaner->clean($val, $fieldmap[$cleankey]);
						if ($fieldmap[$cleankey] == vB_Cleaner::TYPE_STR)
						{
							$values[] = "'" . $db->escape_string($cleanval) ."'";
						}
						else
						{
							$values[] = $cleanval;
						}
					}
				}
				$rows[] = implode(", ", $values);
			}

			if (empty($rows))
			{
				return false;
			}

			$sql .= "(" . implode("),\n(", $rows) . ")";
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$config = vB::getConfig();
			if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
			{
				echo "sql: $sql<br />\n";
			}

			return $db->query_write($sql);
		}
		else
		{
			return false;
		}
	}

	public function fetchSubs2Del($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['transactionids']);
		}

		$params['transactionids'] = vB::getCleaner()->clean($params['transactionids'], vB_Cleaner::TYPE_ARRAY_STR);
		$params['transactionids'] = array_map(array($db, 'escape_string'), $params['transactionids']);
		$sql = "
			SELECT paymentinfo.subscriptionsubid, subscription.subscriptionid, subscription.cost,
				paymentinfo.userid, paymentinfo.paymentinfoid, paymenttransaction.amount, paymenttransaction.transactionid,
				paymenttransaction.paymenttransactionid
			FROM " . TABLE_PREFIX . "paymenttransaction AS paymenttransaction
			INNER JOIN " . TABLE_PREFIX . "paymentinfo AS paymentinfo ON (paymentinfo.paymentinfoid = paymenttransaction.paymentinfoid)
			INNER JOIN " . TABLE_PREFIX . "subscription AS subscription ON (paymentinfo.subscriptionid = subscription.subscriptionid)
			INNER JOIN " . TABLE_PREFIX . "subscriptionlog AS subscriptionlog ON (subscriptionlog.subscriptionid = subscription.subscriptionid AND subscriptionlog.userid = paymentinfo.userid)
			WHERE transactionid IN ('" . implode("','", $params['transactionids']) . "')
				AND subscriptionlog.status = 1
				AND paymenttransaction.reversed = 0
			";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchUsersSubscriptions($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['userid']) AND !empty($params['subscriptionid']);
		}

		$bf_ugp_genericoptions = vB::getDatastore()->getValue('bf_ugp_genericoptions');

		$params = vB::getCleaner()->cleanArray($params, array(
			'userid' => vB_Cleaner::TYPE_UINT,
			'subscriptionid' => vB_Cleaner::TYPE_UINT,
			'adminoption' => vB_Cleaner::TYPE_BOOL
		));
		$sql = "
			SELECT user.*, subscriptionlog.pusergroupid, subscriptionlog.expirydate,
			IF (user.displaygroupid=0, user.usergroupid, user.displaygroupid) AS displaygroupid,
			IF (usergroup.genericoptions & " . $bf_ugp_genericoptions['isnotbannedgroup'] . ", 0, 1) AS isbanned,
			userban.usergroupid AS busergroupid, userban.displaygroupid AS bandisplaygroupid
			" . ($params['adminoption'] ? ",IF(avatar.avatarid = 0 AND NOT ISNULL(customavatar.userid), 1, 0) AS hascustomavatar" : "") . "
			FROM " . TABLE_PREFIX . "subscriptionlog AS subscriptionlog
			INNER JOIN " . TABLE_PREFIX . "user AS user USING (userid)
			INNER JOIN " . TABLE_PREFIX . "usergroup AS usergroup USING (usergroupid)
			LEFT JOIN " . TABLE_PREFIX . "userban AS userban ON (userban.userid = user.userid)
			" . ($params['adminoption'] ? "LEFT JOIN " . TABLE_PREFIX . "avatar AS avatar ON(avatar.avatarid = user.avatarid) LEFT JOIN " . TABLE_PREFIX . "customavatar AS customavatar ON(customavatar.userid = user.userid)" : "") . "
			WHERE subscriptionlog.userid = $params[userid] AND
				subscriptionlog.subscriptionid = $params[subscriptionid]
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchUsersForPromotion($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['time']);
		}

		$params['time'] = vB::getCleaner()->clean($params['time'], vB_Cleaner::TYPE_UNIXTIME);
		$sql = "
			SELECT user.joindate, user.userid, user.membergroupids, user.posts, user.reputation,
				user.usergroupid, user.displaygroupid, user.customtitle, user.username, user.ipoints,
				userpromotion.joinusergroupid, userpromotion.reputation AS jumpreputation, userpromotion.posts AS jumpposts,
				userpromotion.date AS jumpdate, userpromotion.type, userpromotion.strategy,
				usergroup.title, usergroup.usertitle AS ug_usertitle,
				usertextfield.`rank`
			FROM " . TABLE_PREFIX . "user AS user
			INNER JOIN " . TABLE_PREFIX . "userpromotion AS userpromotion ON (user.usergroupid = userpromotion.usergroupid)
			LEFT JOIN " . TABLE_PREFIX . "usergroup AS usergroup ON (userpromotion.joinusergroupid = usergroup.usergroupid)
			LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
			WHERE user.lastactivity >= " . $params['time'];

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function updateUserInfractions($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['joinusergroupid']) AND isset($params['pointlevel']) AND isset($params['ids']);
		}

		$cleaner = vB::getCleaner();
		foreach ($params['pointlevel'] AS $points => $info)
		{
			$points = $cleaner->clean($points, vB_Cleaner::TYPE_UINT);
			$info['ids'] = explode(',', $info['ids']);
			$info['ids'] = $cleaner->clean($info['ids'], vB_Cleaner::TYPE_ARRAY_UINT);
			$info['ids'] = implode(', ', $info['ids']);
			$info['id'] = $cleaner->clean($info['id'], vB_Cleaner::TYPE_UINT);
			$sqlval[] = "WHEN ipoints >= $points THEN '$info[ids]'";
			$sql_id[] = "WHEN ipoints >= $points THEN $info[id]";
		}

		$params = $cleaner->cleanArray($params, array(
			'joinusergroupid' => vB_Cleaner::TYPE_UINT,
			'ids' => vB_Cleaner::TYPE_STR
		));

		$params['ids'] = explode(',', $params['ids']);
		$params['ids'] = $cleaner->clean($params['ids'], vB_Cleaner::TYPE_ARRAY_UINT);
		$params['ids'] = implode(',', $params['ids']);
		$sql = "
			UPDATE " . TABLE_PREFIX . "user
			SET displaygroupid = IF(displaygroupid = usergroupid, $params[joinusergroupid], displaygroupid),
			usergroupid = $params[joinusergroupid],

			infractiongroupid =
			" . (!empty($sql_id) ? "
			CASE
				" . implode(" \r\n", $sql_id) . "
			ELSE 0
			END" : "0") . "

			,infractiongroupids =
			" . (!empty($sqlval) ? "
			CASE
				" . implode(" \r\n", $sqlval) . "
			ELSE ''
			END" : "'0'") . "

			WHERE userid IN ($params[ids])
		";

		return $db->query_write($sql);
	}

	public function updateSubscribeEvent($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['conditions']) AND isset($params['subscribeeventids']);
		}

		$cleaner = vB::getCleaner();
		foreach ($params['conditions'] AS $subscribeeventid => $dateline_from)
		{
			$subscribeeventid = $cleaner->clean($subscribeeventid, vB_Cleaner::TYPE_UINT);
			$dateline_from = $cleaner->clean($dateline_from, vB_Cleaner::TYPE_UNIXTIME);
			$sql[] = " WHEN subscribeeventid = $subscribeeventid THEN $dateline_from ";
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'subscribeeventids' => vB_Cleaner::TYPE_ARRAY_UINT
		));
		$sql = "
			UPDATE " . TABLE_PREFIX . "subscribeevent
			SET lastreminder =
			CASE
			" . implode(" \r\n", $sql) . "
			ELSE lastreminder
			END
			WHERE subscribeeventid IN (" . implode(', ', $params['subscribeeventids']) . ")
		";

		return $db->query_write($sql);

	}

	public function replaceValues($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['values']) AND isset($params['table']);
		}
		if (empty($params['values']))
		{
			return;
		}

		$cleaner = vB::getCleaner();
		$params = $cleaner->cleanArray($params, array(
			'table' => vB_Cleaner::TYPE_NOCLEAN,
			'values' => vB_Cleaner::TYPE_NOCLEAN
		));

		$keys = array_keys($params['values'][0]);
		$keys = array_map(array($db, 'clean_identifier'), $keys);
		$sql = "
		REPLACE INTO " . TABLE_PREFIX . $db->clean_identifier($params['table']) . "
		(" . implode(', ', $keys) . ")
		VALUES
		";

		$rows = array();
		foreach ($params['values'] as $querybit)
		{
			$values = array();
			foreach ($querybit as $val)
			{
				$val = $cleaner->clean($val, vB_Cleaner::TYPE_STR);
				$values[] = "'" . $db->escape_string($val) ."'";
			}
			$rows[] = implode(", ", $values);
		}
		$sql .= "
			(" . implode("),
			(", $rows) . ")";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::get_config();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$result = $db->query_write($sql);
		if (empty($params['returnId']))
		{
			return $result;
		}
		else
		{
			return $db->insert_id();
		}
	}

	/**
	* Creates an INSERT IGNORE query based on the params that are passed
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function insertignoreValues($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['values']) AND isset($params['table']);
		}
		if (empty($params['values']))
		{
			return;
		}

		$cleaner = vB::getCleaner();
		$params = $cleaner->cleanArray($params, array(
			'table' => vB_Cleaner::TYPE_NOCLEAN,
			'values' => vB_Cleaner::TYPE_NOCLEAN,
			'returnId' => vB_Cleaner::TYPE_BOOL
		));

		$keys = array_keys($params['values'][0]);
		$keys = array_map(array($db, 'clean_identifier'), $keys);

		$sql = "
		INSERT IGNORE INTO " . TABLE_PREFIX . $db->clean_identifier($params['table']) . "
		(" . implode(', ', $keys) . ")
		VALUES
		";
		$rows = array();
		foreach ($params['values'] as $querybit)
		{
			$values = array();
			foreach ($querybit as $val)
			{
				$val = $cleaner->clean($val, vB_Cleaner::TYPE_STR);
				$values[] = "'" . $db->escape_string($val) ."'";
			}
			$rows[] = implode(", ", $values);
		}
		$sql .= "
			(" . implode("),
			(", $rows) . ")";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::get_config();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$result = $db->query_write($sql);

		if (empty($params['returnId']))
		{
			return $result;
		}
		else
		{
			return $db->insert_id();
		}
	}

	/**
	* Fetches the mailing list for users regarding the user adminemail option.
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function fetchMailingList($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			// @TODO implement better validation here
			return true;
		}

		$params = $this->fetchMailingListClean($params);
		$where = $this->fetchMailingListWhere($params, $db);

		$activationfields = '';
		$activationjoin = '';
		$limit = '';
		if ($params['activation'])
		{
			$activationfields = ", user.userid, user.usergroupid, user.username, user.joindate, useractivation.activationid";
			$activationjoin = "LEFT JOIN " . TABLE_PREFIX .
				"useractivation AS useractivation ON (useractivation.userid = user.userid AND useractivation.type = 0)";

			$limit = "ORDER BY userid
				LIMIT " . $params[vB_dB_Query::PARAM_LIMITPAGE] . ", " . $params[vB_dB_Query::PARAM_LIMIT];
		}
		$sql = "
			SELECT user.email $activationfields
			FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "userfield AS userfield ON (userfield.userid = user.userid)
				LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
				$activationjoin
			WHERE $where
			$limit
			/** fetchMailingList" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function fetchMailingListCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			// @TODO implement better validation here
			return true;
		}

		$params = $this->fetchMailingListClean($params);
		$where = $this->fetchMailingListWhere($params, $db);

		$activationfields = '';
		$activationjoin = '';
		if ($params['activation'])
		{
			$activationfields = ", user.userid, user.usergroupid, user.username, user.joindate, useractivation.activationid";
			$activationjoin = "LEFT JOIN " . TABLE_PREFIX .
				"useractivation AS useractivation ON (useractivation.userid = user.userid AND useractivation.type = 0)";
		}

		$sql = "
			SELECT COUNT(*) AS total
			FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "userfield AS userfield ON (userfield.userid = user.userid)
				LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
				$activationjoin
			WHERE $where
			/** fetchMailingList" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	private function fetchMailingListClean($params)
	{
		$cleaner = vB::getCleaner();
		$params = $cleaner->cleanArray($params, array(
			vB_dB_Query::PARAM_LIMITPAGE	=> vB_Cleaner::TYPE_UINT,
			vB_dB_Query::PARAM_LIMIT	=> vB_Cleaner::TYPE_UINT,
			'activation' => vB_Cleaner::TYPE_BOOL,
			'orderby'	=> vB_Cleaner::TYPE_STR,
			'direction'	=> vB_Cleaner::TYPE_STR,
			'exceptions'	=> vB_Cleaner::TYPE_NOCLEAN,
			'options'	=> vB_Cleaner::TYPE_NOCLEAN,

			//filters is passed to the querybuilder object below and is not used directly in the query.
			'filters'	=> vB_Cleaner::TYPE_NOCLEAN,
		));

		if ($params['exceptions'])
		{
			$params['exceptions'] = $cleaner->cleanArray($params['exceptions'], array(
				'membergroup'	=> vB_Cleaner::TYPE_ARRAY_UINT,
				'aim'	=> vB_Cleaner::TYPE_STR,
			));
		}

		if ($params['options'])
		{
			$params['options'] = $cleaner->cleanArray($params['exceptions'], array(
				'adminemail'	=> vB_Cleaner::TYPE_BOOL,
			));
		}

		return $params;
	}

	private function fetchMailingListWhere($params, $db)
	{
		$where = "user.email <> ''\n";
		if (!empty($params['filters']))
		{
			$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
			$queryBuilder = new $className($db, false);
			$where .= " AND " . $queryBuilder->conditionsToFilter($params['filters']);
		}

		$exceptions = $params['exceptions'];
		if (isset($exceptions['membergroup']) AND is_array($exceptions['membergroup']))
		{
			foreach ($exceptions['membergroup'] AS $id)
			{
				$where .= " AND FIND_IN_SET(" . intval($id) . ", user.membergroupids)";
			}
		}

		if ($exceptions['aim'])
		{
			$where .= " AND REPLACE(" . TABLE_PREFIX . "aim, ' ', '') LIKE '%" .
				$db->escape_string_like(str_replace(' ', '', $exceptions['aim'])) . "%'";
		}

		// only using useroptions at the moment... we can extend this later...
		$options = vB::getDatastore()->getValue('bf_misc_useroptions');
		if ($params['options'] AND empty($params['options']['adminemail']))
		{
			$where .= "\n AND (options & $options[adminemail])\n";
		}

		return $where;
	}

	/**
	* Updates the plugin active status
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function updateHookStatus($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			foreach ($params['hookdata'] AS $pluginid => $info)
			{
				if (!is_numeric($pluginid))
				{
					return false;
				}

				if (!isset($info['active']))
				{
					return false;
				}

				if (!isset($info['hookorder']))
				{
					return false;
				}
			}

			return true;
		}

		//this idiom is not good.  It's intended to keep the hook updates to one query,
		//but in many cases multiple queries are faster.  Unpacking it is more effort
		//than it's worth here.
		$cond1 = $cond2 = "";
		foreach ($params['hookdata'] AS $hookid => $info)
		{
			$cond1 .= "\n WHEN $hookid THEN " . ( ((bool)$info['active']) ? 1 : 0);
			$cond2 .= "\n WHEN $hookid THEN " . intval($info['hookorder']);
		}

		$where = '';
		if($params['productid'])
		{
			$where = "WHERE product = '" . $db->escape_string($params['productid']) . "'";
		}

		$sql = "UPDATE " . TABLE_PREFIX . "hook
		SET active = CASE hookid
				$cond1
				\n ELSE active END,
		\n hookorder = CASE hookid
				$cond2
				\n ELSE hookorder END
		$where
		";

		return $db->query_write($sql);
	}

	/**
	* Remove the language columns from a package
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function removeLanguageFromPackage($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['productid']) AND is_string($params['productid'])) ? true : false;
		}

		$phrasetypes = $db->query_read("
			SELECT fieldname
			FROM " . TABLE_PREFIX . "phrasetype
			WHERE product = '" . $db->escape_string($params['productid']) . "'
		");

		$drops = array();
		while ($phrasetype = $db->fetch_array($phrasetypes))
		{
			$drops[] = 'DROP COLUMN phrasegroup_' . $phrasetype['fieldname'];
		}

		if (empty($drops))
		{
			return true;
		}
		$sql = "ALTER TABLE " . TABLE_PREFIX . "language\n
				" . implode(", ", $drops) . "
				/** removeLanguageFromPackage" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/
		";

		return $db->query_write($sql);
	}

	/**
	* Add the language columns from a package
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function addLanguageFromPackage($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['fieldname'])) ? true : false;
		}

		if (!$db->query_first("
			SHOW COLUMNS FROM " . TABLE_PREFIX . "language
			LIKE 'phrasegroup_" . $db->escape_string($params['fieldname']) . "'"
		))
		{
			$sql = "ALTER TABLE " . TABLE_PREFIX . "language
				ADD COLUMN phrasegroup_" . $params['fieldname'] . " MEDIUMTEXT NOT NULL
				/** addLanguageFromPackage" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/
			";

			return $db->query_write($sql);
		}
	}

	/**
	* Fetches userlist from a given criteria.
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function fetchUsersFromCriteria($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			// @TODO implement better validation here
			return true;
		}

		$where = "";
		if (!empty($params['filters']))
		{
			$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
			$queryBuilder = new $className($db, false);
			$where .= "WHERE " . $queryBuilder->conditionsToFilter($params['filters']);
		}

		$paginateSql = "";
		if (!empty($params[vB_dB_Query::PARAM_LIMIT]) OR !empty($params[vB_dB_Query::PARAM_LIMITPAGE]))
		{
			if (isset($params[vB_dB_Query::PARAM_LIMIT]) AND intval(vB_dB_Query::PARAM_LIMIT))
			{
				$perpage = intval($params[vB_dB_Query::PARAM_LIMIT]);
			}
			else
			{
				$perpage = 50;
			}

			if (isset($params[vB_dB_Query::PARAM_LIMITPAGE]) AND intval($params[vB_dB_Query::PARAM_LIMITPAGE]) AND (intval($params[vB_dB_Query::PARAM_LIMITPAGE]) > 1))
			{
				$startat = ($perpage * (intval($params[vB_dB_Query::PARAM_LIMITPAGE]) - 1)) . ',';
			}
			else
			{
				$startat = '0, ';
			}

			$paginateSql = $startat . $perpage;
		}

		$sql = "SELECT user.username
				FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "userfield AS userfield ON (userfield.userid = user.userid)
				LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
				$where
				$paginateSql
			/** fetchUsersFromCriteria" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	/**
	* Get referrals from a userid.
	* This can be also limited startdate and enddate (datelines).
	*
	*	@param	mixed
	*	@param	mixed 	a db pointer
	*	@param	bool
	*
	*	@result	mixed
	*/
	public function userReferrals($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['referrerid']);
		}
		else
		{
			$where = "WHERE referrerid = " . $params['referrerid'] . " AND usergroupid NOT IN (3, 4)";
			if (!empty($params['startdate']))
			{
				$where .= " AND joindate >= " . $params['startdate'];
			}

			if (!empty($params['enddate']))
			{
				$where .= " AND joindate <= " . $params['enddate'];
			}

			if (!empty($params['enddate']))
			{
			}
			$sql = "SELECT username, posts, userid, joindate, lastvisit, email
					FROM " . TABLE_PREFIX . "user
					$where
					ORDER BY joindate DESC
					/** userReferrals" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$result = new $resultclass($db, $sql);
			return $result;
		}
	}

	/**
	 * Your basic table truncate
	 *
	 *	@param	mixed
	 *	@param	mixed 	a db pointer
	 *	@param	bool
	 *
	 *	@result	mixed
	 */
	public function truncateTable($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['table'])) ? true : false;
		}

		$sql = "TRUNCATE TABLE " . TABLE_PREFIX . $params['table'] . "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']))
		{
			echo "$sql\n";
		}

		return $db->query_write($sql);
	}

	public function getFiledataBatch($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['filedataid']) AND
					!empty($params['type']) AND
					!empty($params['startbyte']) AND
					!empty($params['readsize']);
		}

		$sql = "
			SELECT fd.filedataid, SUBSTRING(" . $db->escape_string($params['filedata']) . ", " .
				intval($params['startbyte']) . ", " . intval($params['readsize']) . ") AS filedata
			FROM " . TABLE_PREFIX . "filedata AS fd
			LEFT JOIN " . TABLE_PREFIX . "filedataresize AS fdr ON (fd.filedataid = fdr.filedataid AND fdr.resize_type = '" . $db->escape_string($params['type']) . "')
			WHERE fd.filedataid = " . intval($params['filedataid']) . "
		";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::getConfig();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$result = new $resultclass($db, $sql);
		return $result;
	}

	/**
	 * Composes the terms for the flags to enforce the starter-node-specific permissions.
	 *
	 * @param	$excludeUserSpecific	bool	Exclude user specific queries. Used for precaching
	 * @param	$userid					bool	User whose context will be used. If not set, it'll be the current user.
	 *
	 **/
	protected function getNodePermTerms($excludeUserSpecific = false, $userid = null)
	{
		$userContext = vB::getUserContext($userid);

		if (empty($userContext))
		{
			$canModerate = false;
			$membersOf = false;
			$userid = -1;
		}
		else
		{
			if ($userContext->isSuperAdmin())
			{
				return array('joins' => array(), 'where' => '');
			}

			$where = array();
			$userid = vB::getCurrentSession()->get('userid');
			$channelAccess = $userContext->getAllChannelAccess();

			if (!empty($channelAccess['canmoderate']))
			{
				$where[] = "( starter.parentid in (" .
					implode(',', $channelAccess['canmoderate']) . ") OR starter.nodeid IN (" .
					implode(',', $channelAccess['canmoderate']) . "))\n";
			}

			if (!empty($channelAccess['canseedelnotice']))
			{
				$starterAnd = "AND (starter.parentid IN (" . implode(',', $channelAccess['canseedelnotice']) .
					") OR node.showpublished > 0)";
			}
			else
			{
				$starterAnd = '';
			}

			$nodeShowApprovedQuery = "node.showapproved > 0";
			if ($userid > 0)
			{
				$userid = intval($userid);
				$nodeShowApprovedQuery = "(node.showapproved > 0 OR node.userid = $userid)";
			}

			if (!empty($channelAccess['canview']))
			{
				$nodeviewthreshold = ($userid > 0 ? 0 : 1);

				$showParams = array(
					$nodeShowApprovedQuery,
					"node.viewperms > $nodeviewthreshold",
				);

				if (empty($channelAccess['canseedelnotice']))
				{
					$showParams[] = "node.showpublished > 0";
				}

				$where[] = "( (  (starter.parentid IN (" . implode(',', $channelAccess['canview']) .
					") $starterAnd) AND " . implode(" AND ", $showParams) . " ))\n";
			}

			if (!empty($channelAccess['canalwaysview']))
			{
				$where[] = "(starter.parentid IN (" . implode(',', $channelAccess['canalwaysview']) . "))\n";
			}

			if (!empty($channelAccess['starteronly']))
			{
				$starterOnly = implode(',', $channelAccess['starteronly']);
				$where[] = "( node.nodeid IN ($starterOnly) OR node.parentid in ($starterOnly) )\n";
			}

			if ($userid AND !empty($channelAccess['selfonly']))
			{
				$where[] = "( starter.parentid in (" . implode(',', $channelAccess['selfonly']) . ") AND starter.userid = $userid )\n";
			}

			if (!empty($channelAccess['member']))
			{
				$showParams = array(
					$nodeShowApprovedQuery,
				);

				if (empty($channelAccess['canseedelnotice']))
				{
					$showParams[] = "node.showpublished > 0";
				}

				$memberlist = implode(',', $channelAccess['member']);
				//if this node is a channel and we are a member we want to allow it.  Otherwise
				//if the parent of its starter is a channel we are a member of, we should be able to see it.
				$memberaccess = "(node.nodeid IN ($memberlist) OR starter.parentid IN ($memberlist))";

				$where[] = "($memberaccess $starterAnd AND " . implode(" AND ", $showParams) . " )\n";
			}

			//albums for which viewperms is zero.
			$following = vB_Api::instanceInternal('follow')->getFollowingParameters();

			if (empty($following['user']))
			{
				$following['user'] = array($userid);
			}
			else
			{
				$following['user'][] = $userid;
			}

			$where[] = "starter.parentid = " . vB_Library::instance('node')->fetchAlbumChannel() .
				" AND node.userid IN (" . implode(',', $following['user']) . ")";

			$joins = array('starter' => " LEFT JOIN " . TABLE_PREFIX . "node AS starter ON starter.nodeid = IF(node.starter = 0, node.nodeid, node.starter)");
		}

		if (empty($where))
		{
			return array(
				'where' => "\nAND ( nodeid = 0 )\n",
				'joins' => array()
			);
		}

		$terms = array(
			'where' => "\nAND (node.public_preview = 1 OR  ( " . implode (" OR ", $where) . "))\n",
			'joins' => $joins
		);

		return $terms;
	}


	public function saveDbCache($params, $db, $check_only = false)
	{
		$fields = array('cacheid', 'expires', 'created', 'locktime', 'serialized', 'data');
		if ($check_only)
		{
			if (empty($params['cache']) OR !is_array($params['cache']))
			{
				return false;
			}

			foreach($params['cache'] AS $key => $cacheData)
			{
				foreach($fields AS $field)
				{
					if (!isset($cacheData[$field]))
					{
						return false;
					}
				}

				if (!is_numeric($cacheData['expires']) OR !is_numeric($cacheData['created'])
					OR !is_numeric($cacheData['serialized']))
				{
					return false;
				}
			}
			//if we got here we're good.
			return true;
		}

		//First we need to find what cache events are already set for the current cacheid;
		$cacheInfo = $params['cache'];
		$keys = array_map(array($db, 'escape_string'), array_keys($cacheInfo));
		$sql = "/** saveDbCache */ SELECT * FROM " . TABLE_PREFIX . "cacheevent WHERE cacheid IN ('" .
			implode("','", $keys). "') ";
		unset ($keys);
		$deleteCacheEvents = array();
		$results = $db->query_read($sql);

		//We need to compare the existing cacheevent records against what we were passed.
		while ($eventInfo = $db->fetch_array($results))
		{
			$cacheid = $eventInfo['cacheid'];
			$event = $eventInfo['event'];

			if (!empty($params['cache'][$cacheid]) AND isset($params['cache'][$cacheid]['events'][$event]))
			{
				//This cache record already exists. We don't need to do a  new insert.
				unset($params['cache'][$cacheid]['events'][$event]);
			}
			else
			{
				$deleteCacheEvents[] = "(cacheid = '$cacheid' AND event = '$event')";
			}
		}

		//Delete the unnecessary events.
		if (!empty($deleteCacheEvents))
		{
			$sql = "/** saveDbCache */ DELETE FROM " . TABLE_PREFIX . "cacheevent WHERE " . implode(" OR \n", $deleteCacheEvents);
			$db->query_write($sql);
		}
		//Now it is just possible that we could have several really large cache inserts. So we need to be careful to keep the
		//length of the sql under a quarter megabyte.
		$insert = "/** saveDbCache */ INSERT INTO " . TABLE_PREFIX . "cache (" . implode(',', $fields) .")
			VALUES \n";
		$update = "ON DUPLICATE KEY UPDATE expires = VALUES(expires),  created = VALUES(created),
				locktime = VALUES(locktime), serialized = VALUES(serialized),data = VALUES(data)";
		$havemore = false;
		$strlen = 0;
		$values = array();
		$addCacheEvents = array();

		foreach ($cacheInfo AS $cacheid => $cache)
		{
			if (strlen($cache['data']) > 524288)
			{
				//just too big. Can't cache it.
				continue;
			}

			$newValues = "('" . $db->escape_string($cache['cacheid']) . "', " . intval($cache['expires']) . ", "  . intval($cache['created']) .
				", 0, '" . intval($cache['serialized']) . "', '". $db->escape_string($cache['data']) . "')\n";
			$strlen += strlen($newValues);
			$values[] = $newValues;
			$havemore = true;


			if ($strlen > 10000)
			{
				try
				{
					$db->query_write($insert . implode(",\n", $values) . "\n $update");
				}
				catch(vB_Exception_Database $e)
				{
					// if the query fails (likely due to exceeding max_allowed_packet),
					// it only means that the data won't be cached, which we can safely
					// ignore for regular users.

					// use saveDbCacheErrorState to avoid recursion if there are database
					// problems when calling hasAdminPermission below
					if (!$this->saveDbCacheErrorState)
					{
						$this->saveDbCacheErrorState = true;

						// @TODO -- optionally log to a file here to pinpoint problematic cache data?


						// show the error to admins
						if (vB::getUserContext()->hasAdminPermission('cancontrolpanel'))
						{
							$querystrlen = strlen($insert . implode(",\n", $values) . "\n $update");
							$data = $e->getData();
							// This text is purposely hard-coded since we may not have
							// access to the database to get a phrase
							$message = "Error saving DB cache, Query string length: $querystrlen, MySQL Error: $data[error], Error Number: $data[errno].\n\n";
							throw new vB_Exception_Database($message . $e->getSql(), $data, $e->getCode());
						}
					}
				}

				$values = array();
				$havemore = false;
				$strlen = 0;
			}

			if (!empty($cache['events']))
			{
				if (is_array($cache['events']))
				{
					foreach(array_unique($cache['events']) AS $thisEvent)
					{
						$addCacheEvents[] = "('" . $db->escape_string($cache['cacheid']) . "','" .
							$db->escape_string($thisEvent) . "')";
					}
				}
				else
				{
					$addCacheEvents[] = "('" . $db->escape_string($cache['cacheid']) . "','" .
						$db->escape_string($cache['events']) . "')";
				}
			}
		}

		if ($havemore)
		{
			$db->query_write($insert . implode(",\n", $values) . "\n $update" );
		}

		//add the cache events
		if (!empty($addCacheEvents))
		{
			$sql = "/** saveDbCache */REPLACE INTO " . TABLE_PREFIX . "cacheevent (cacheid, event) values\n " .
				implode(",\n", $addCacheEvents);
			$db->query_write($sql);
		}
		$config = vB::getConfig();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		return true;
	}


	public function saveDbCacheEvents($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['events']));
		}
		$addCacheEvents = array();
		foreach ($params['events'] AS $cacheid => $events)
		{
			if (!empty($events))
			{
				if (is_array($events))
				{
					foreach(array_unique($events) AS $thisEvent)
					{
						$addCacheEvents[] = "('" . $db->escape_string($cacheid) . "','" .
							$db->escape_string($thisEvent) . "')";
					}
				}
				else
				{
					$addCacheEvents[] = "('" . $db->escape_string($cacheid) . "','" .
						$db->escape_string($events) . "')";
				}
			}
		}

		//add the cache events
		if (!empty($addCacheEvents))
		{
			$sql = "/** saveDbCache */REPLACE INTO " . TABLE_PREFIX . "cacheevent (cacheid, event) values\n " .
				implode(",\n", $addCacheEvents);
			$db->query_write($sql);
		}
		$config = vB::getConfig();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}
		return true;
	}

	/**
	 * Get all the site threads limitted by the given parentids.
	 *
	 *	@param	mixed
	 *	@param	mixed 	a db pointer
	 *	@param	bool
	 *
	 *	@result	mixed
	 */
	public function getSiteThreads($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			foreach (array('startat', vB_dB_Query::PARAM_LIMIT) AS $param)
			{
				if (!isset($params[$param]) OR !is_numeric($params[$param]) AND ($params[$param] < 1))
				{
					return false;
				}
			}

			foreach (array('parents', 'exclude_ids') AS $param)
			{
				if (!isset($params[$param]) OR !is_array($params[$param]))
				{
					return false;
				}

				foreach ($params[$param] AS $val)
				{
					if (!is_numeric($val))
					{
						return false;
					}
				}
			}

			return true;
		}

		$sql = "
			SELECT nodeid, routeid, title, lastcontent
			FROM " . TABLE_PREFIX . "node
			WHERE nodeid = starter AND parentid IN ( " . implode(", ", $params['parents']) . ") AND showapproved > 0
				AND showpublished > 0 AND open = 1 AND inlist = 1 AND nodeid >= " . $params['startat'] . "
				" . (!empty($params['exclude_ids']) ? "AND userid NOT IN (" . implode(", ", $params['exclude_ids']) . ")" : "") . "
			ORDER BY nodeid
			LIMIT " . $params[vB_dB_Query::PARAM_LIMIT] . "
			/** getSiteThreads" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . '**/';

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$config = vB::get_config();

			if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
			{
				echo "sql: $sql<br />\n";
			}

			$result = new $resultclass($db, $sql);
			return $result;
	}

	public function fetchPermsOrdered($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
		$usergroupcond = empty($params['usergroupid']) ? '' : ' AND permission.groupid = ' . intval($params['usergroupid']);
		$nodecond = empty($params['nodeid']) ? '' : ' AND closure.parent = ' . intval($params['nodeid']);
		$sql = "
				SELECT permission.groupid, permission.forumpermissions, node.nodeid, node.htmltitle
				FROM " . TABLE_PREFIX . "node AS node
				INNER JOIN " . TABLE_PREFIX . "closure AS closure ON ( closure.child = node.nodeid $nodecond)
				INNER JOIN " . TABLE_PREFIX . "permission AS permission ON ( closure.parent = permission.nodeid $usergroupcond)
				WHERE node.contenttypeid = $channelcontentypeid
				ORDER BY closure.depth DESC
		". "/** fetchPermsOrdered" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . '**/';;

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::get_config();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function getInfractionsByType($params, $db, $check_only = false)
	{
		$params = vB::getCleaner()->cleanArray($params, array(
			'type' => vB_Cleaner::TYPE_STR,
			'replied_by_me' => vB_Cleaner::TYPE_BOOL,
			'userid' => vB_Cleaner::TYPE_INT,
		));

		if (!in_array($params['type'], array('user', 'post')))
		{
			unset($params['type']);
		}

		if (empty($params['replied_by_me']))
		{
			if (empty($params['type']))
			{
				return array();
			}
			$sql = 'SELECT i.* FROM ' . TABLE_PREFIX . 'infraction AS i WHERE i.infractednodeid ' . ($params['type'] == 'user' ? '=' : '<>') . ' 0';
		}
		else
		{
			$sql = 'SELECT i.* FROM ' . TABLE_PREFIX . 'infraction AS i
					INNER JOIN ' . TABLE_PREFIX . 'closure AS cl ON cl.parent = i.nodeid
					INNER JOIN ' . TABLE_PREFIX . 'node AS n ON n.nodeid = cl.child
					WHERE n.userid = ' . $params['userid'];
			if (!empty($params['type']))
			{
				$sql .= ' AND i.infractednodeid ' . ($params['type'] == 'user' ? '=' : '<>') . ' 0';
			}
		}


		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::get_config();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}
		$result = new $resultclass($db, $sql);
		return $result;

	}

	public function fetchMemberList($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return is_array($params['usergroupid']);
		}
		else
		{
			// clean params
			$params = vB::getCleaner()->cleanArray($params, array(
				'sortorder' => vB_Cleaner::TYPE_STR,
				'sortfield' => vB_Cleaner::TYPE_STR,
				'startswith' => vB_Cleaner::TYPE_STR,
				'username' => vB_Cleaner::TYPE_STR,
				'usergroupid' => vB_Cleaner::TYPE_ARRAY_UINT,
				vB_dB_Query::PARAM_LIMITPAGE => vB_Cleaner::TYPE_UINT,
				vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT,
			));

			$sortorder = (isset($params['sortorder']) AND strtolower($params['sortorder']) == 'asc') ? 'ASC' : 'DESC';
			if (isset($params['sortfield']))
			{
				switch ($params['sortfield'])
				{
					case 'username':
						$sqlsort = 'user.username';
						break;
					case 'joindate':
						$sqlsort = 'user.joindate';
						break;
					case 'posts':
						$sqlsort = 'user.posts';
						break;
					case 'reputation':
						$sqlsort = 'user.reputation';
						break;
					case 'lastvisit':
						$sqlsort = 'user.lastactivity';
						break;
					default:
						$sqlsort = 'user.username';
				}
			}
			else
			{
				$sqlsort = 'user.username';
			}

			$perpage = (isset($params[vB_dB_Query::PARAM_LIMIT])) ? intval($params[vB_dB_Query::PARAM_LIMIT]) : 0;

			if ($perpage == 0)
			{
				$perpage = 200;
			}
			else if ($perpage < 1)
			{
				$perpage = 1;
			}

			if (empty($params[vB_dB_Query::PARAM_LIMITPAGE]))
			{
				$params[vB_dB_Query::PARAM_LIMITPAGE] = 1;
			}

			$limitlower = ($params[vB_dB_Query::PARAM_LIMITPAGE] - 1) * $perpage;
			$limitupper = $perpage;

			$where = array();
			$where[] = 'usergroupid IN (' . implode(',', $params['usergroupid']) . ')';
			if (!empty($params['startswith']))
			{
				if ($params['startswith'] == '#')
				{
					$where[] = 'user.username REGEXP "^[^a-z].?"';
				}
				else
				{
					$where[] = 'user.username LIKE "' . $db->escape_string_like($params['startswith']) . '%"';
				}
			}
			if (!empty($params['username']))
			{
				$where[] = 'user.username LIKE "' . $db->escape_string_like($params['username']) . '%"';
			}

			$query_where = '';
			if (!empty($where))
			{
				$query_where = 'WHERE ' . implode(' AND ', $where);
			}

			$sql = "
				SELECT
					user.userid, user.username, user.usergroupid AS usergroupid, user.lastactivity, user.options,
					user.posts, user.joindate, user.usertitle,user.reputation,user.reputationlevelid,
					session.lastactivity AS lastvisit,
					IF(displaygroupid=0, user.usergroupid, displaygroupid) AS displaygroupid, infractiongroupid, user.usergroupid
				FROM " . TABLE_PREFIX . "user AS user
				LEFT JOIN " . TABLE_PREFIX . "session AS session ON session.userid = user.userid
				$query_where
				GROUP BY user.userid
				ORDER BY $sqlsort $sortorder
				LIMIT $limitlower, $limitupper
			";
			return $this->getResultSet($db, $sql, __FUNCTION__);
		}
	}

	public function fetchAdminusersFromUsergroup($params, $db, $check_only = false)
	{
		$params = vB::getCleaner()->cleanArray($params, array(
			'ausergroupids' => vB_Cleaner::TYPE_ARRAY_INT,
			'usergroupid' => vB_Cleaner::TYPE_INT
		));

		if ($check_only)
		{
			return !empty($params['ausergroupids']) AND !empty($params['usergroupid']);
		}

		$notinsetsql = '';

		foreach ($params['ausergroupids'] as $ausergroupid)
		{
			$notinsetsql .= " AND NOT FIND_IN_SET('$ausergroupid', membergroupids)";
		}

		$ausergroupidsstr = implode(',', $params['ausergroupids']);

		$sql = "SELECT userid FROM " . TABLE_PREFIX . "user
			WHERE usergroupid NOT IN ('$ausergroupidsstr')
				$notinsetsql
				AND (usergroupid = $params[usergroupid]
				OR FIND_IN_SET('$params[usergroupid]', membergroupids))";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$config = vB::get_config();

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}
		$result = new $resultclass($db, $sql);
		return $result;

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103829 $
|| #######################################################################
\*=========================================================================*/
