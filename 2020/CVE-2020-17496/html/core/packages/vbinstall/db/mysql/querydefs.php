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
*
* @package vBulletin
* @version $Revision: 103891 $
* @since $Date: 2020-01-16 15:00:32 -0800 (Thu, 16 Jan 2020) $

*/
class vBInstall_dB_MYSQL_QueryDefs extends vB_dB_MYSQL_QueryDefs
{

	/**
	* This class is called by the new vB_dB_Assertor database class
	* It does the actual execution. See the vB_dB_Assertor class for more information
	*
	* Note that there is no install package. Therefore the ONLY thing that should be in this are queries unique to
	* the install/upgrade process. Especially there should be no table definitions unless they are vB3/4 tables not used
	* in vB5.
	*
	**/

	/*Properties====================================================================*/

	//type-specific

	protected $db_type = 'MYSQL';

	protected $table_data = array(
		'attachmenttype' => array('key' => 'extension', 'structure' => array('extension', 'mimetype','size','width','height','display','contenttypes')),
		'attachment' => array('key' => 'attachmentid', 'structure' => array('attachmentid', 'contenttypeid',
			'contentid', 'userid', 'dateline', 'filedataid', 'state', 'counter', 'posthash', 'filename',
			'caption', 'reportthreadid', 'settings', 'displayorder')
		),
		'socialgroup' => array('key'=> 'groupid','structure' => array( 'groupid', 'socialgroupcategoryid', 'name', 'description',
			'creatoruserid', 'dateline', 'members', 'picturecount', 'lastpost', 'lastposter', 'lastposterid', 'lastgmid',
			'visible', 'deleted', 'moderation', 'type', 'moderatedmembers', 'options', 'lastdiscussionid', 'discussions', 'lastdiscussion',
			'lastupdate', 'transferowner')),
		'socialgroupcategory' => array('key'=> 'socialgroupcategoryid','structure' => array('socialgroupcategoryid',
			'creatoruserid', 'title', 'description', 'displayorder', 'lastupdate', 'groups')),
		'socialgroupmember' => array('key'=> false,'structure' => array('userid', 'groupid', 'dateline', 'type')),
		'groupmessage' => array('key' => 'gmid','structure' => array('gmid', 'discussionid', 'postuserid',
			'postusername', 'dateline', 'state', 'title', 'pagetext', 'ipaddress', 'allowsmilie', 'reportthreadid')),
		'discussion' => array('key'=> 'discussionid','structure' => array('discussionid', 'groupid',
			'firstpostid', 'lastpostid', 'lastpost', 'lastposter', 'lastposterid', 'visible', 'deleted', 'moderation', 'subscribers')),
		'socialgroupicon' => array('key'=> false,'structure' => array('groupid', 'userid', 'filedata', 'extension',
			'dateline', 'width', 'height', 'thumbnail_filedata mediumblob', 'thumbnail_width', 'thumbnail_height')),
		'upgradelog' => array('key'=> 'upgradelogid','structure' => array('script', 'steptitle', 'step', 'startat','perpage', 'dateline', 'only')),
		'cachelog' => array('key'=> false,'structure' => array('randomkey', 'cacheid',
			'cachetype', 'time', 'writes', 'hits', 'misses', 'rereads', 'remiss', 'clears', 'size')),
		'cms_permissions' => array('key' => 'permissionid', 'structure' => array('permissionid', 'usergroupid',
			'nodeid', 'permissions')),
		'style_temporary_helper' => array(
			'key' => false,
			'structure' => array(
				'styleid',
				'parentid',
				'guid',
				'children',
			)
		),


	);

	/**
	 * This is the definition for queries.
	 */
	protected $query_data = array(
		//simple max queries -- candidates for reuse
		//the "oldcontenttypeid" queries can definitely be collapsed into one query
		'getMaxNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(nodeid) AS maxid FROM {TABLE_PREFIX}node'
		),
		'getMaxNodeidForOldContent' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(nodeid) AS maxid FROM {TABLE_PREFIX}node WHERE oldcontenttypeid IN ({oldcontenttypeid})'
		),
		'getMaxOldidForOldContent' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid FROM {TABLE_PREFIX}node WHERE oldcontenttypeid IN ({oldcontenttypeid})'
		),
		'getMaxImportedArticleNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>"
				SELECT MAX(nodeid) AS maxid
				FROM {TABLE_PREFIX}node
				WHERE oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})"
		),
		'getMaxPMNodeid' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(nodeid) AS maxid FROM {TABLE_PREFIX}node WHERE oldcontenttypeid in (9981, 9989)'
		),
		'getMaxPMSenderid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(fromuserid) AS maxid FROM {TABLE_PREFIX}pmtext'
		),
		'getMaxPMRecipient' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(userid) AS maxid FROM {TABLE_PREFIX}pm'
		),
		'getThreadPostMaxThread' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(threadid) AS maxid FROM {TABLE_PREFIX}thread_post'
		),
		'getMaxUserid'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(userid) AS maxid FROM {TABLE_PREFIX}user"
		),
		'getMaxAttachNodeid'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(nodeid) AS maxid FROM {TABLE_PREFIX}attach"
		),

		//end simple max queries.

		'getMaxPMFolderUser' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(userid) AS maxid FROM {TABLE_PREFIX}messagefolder WHERE titlephrase = {titlephrase}'
		),
		'getMaxUseridWithVM' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT MAX(userid) AS maxid FROM {TABLE_PREFIX}user
				WHERE vmunreadcount > 0'
		),
		//the limit in the subquery *probably* isn't necesary but I don't entirely trust all versions of mysql
		//to optimize it correctly (the MariaDB version I'm testing on does) and it won't hurt anything thing.
		'getMaxNodeRedirectRoute' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(routeid) AS maxid
				FROM {TABLE_PREFIX}routenew AS routenew
				WHERE EXISTS (
					SELECT 1
					FROM {TABLE_PREFIX}node AS node
					WHERE node.routeid = routenew.routeid
					LIMIT 1
				) AND routenew.redirect301 IS NOT NULL
			'
		),

		'getNodeRedirectRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT routeid, redirect301
				FROM {TABLE_PREFIX}routenew AS routenew
				WHERE EXISTS (
					SELECT 1
					FROM {TABLE_PREFIX}node AS node
					WHERE node.routeid = routenew.routeid
					LIMIT 1
				) AND routenew.redirect301 IS NOT NULL
				AND routeid > {startat}
				ORDER BY routeid
			'
		),

		'createPMFoldersSent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}messagefolder(userid, titlephrase)
			SELECT distinct pmtext.fromuserid , \'sent_items\'
			FROM {TABLE_PREFIX}pmtext AS pmtext
			WHERE pmtext.fromuserid > {startat} AND pmtext.fromuserid < ({startat} + {batchsize} + 1) ORDER BY pmtext.fromuserid'),
		'getMaxMissingPMFoldersSent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(DISTINCT pmtext.fromuserid) as maxToFix
			FROM {TABLE_PREFIX}pmtext AS pmtext
			LEFT JOIN {TABLE_PREFIX}messagefolder AS folder ON pmtext.fromuserid = folder.userid AND folder.titlephrase = \'sent_items\'
			WHERE folder.folderid IS NULL AND pmtext.fromuserid <> 0'),
		'importMissingPMFoldersSent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}messagefolder(userid, titlephrase)
			SELECT DISTINCT pmtext.fromuserid, \'sent_items\'
			FROM {TABLE_PREFIX}pmtext AS pmtext
			LEFT JOIN {TABLE_PREFIX}messagefolder AS folder ON pmtext.fromuserid = folder.userid AND folder.titlephrase = \'sent_items\'
			WHERE folder.folderid IS NULL AND pmtext.fromuserid > {startat} AND pmtext.fromuserid < ({startat} + {batchsize} + 1) ORDER BY pmtext.fromuserid'),
		'createPMFoldersMsg' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}messagefolder(userid, titlephrase)
			SELECT DISTINCT pm.userid , \'messages\'
			FROM {TABLE_PREFIX}pm AS pm
			WHERE pm.folderid = 0 AND pm.userid > {startat} AND pm.userid < ({startat} + {batchsize} + 1)
			ORDER BY pm.userid'),
		'getMaxMissingPMMessagesFolder' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(DISTINCT pm.userid) as maxToFix
			FROM {TABLE_PREFIX}pm AS pm
			LEFT JOIN {TABLE_PREFIX}messagefolder AS folder ON pm.userid = folder.userid AND folder.titlephrase = \'messages\'
			WHERE folder.folderid IS NULL AND pm.userid > 0
			ORDER BY pm.userid'),
		'importMissingPMMessagesFolder' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}messagefolder(userid, titlephrase)
			SELECT DISTINCT pm.userid, \'messages\'
			FROM {TABLE_PREFIX}pm AS pm
			LEFT JOIN {TABLE_PREFIX}messagefolder AS folder ON pm.userid = folder.userid AND folder.titlephrase = \'messages\'
			WHERE folder.folderid IS NULL AND pm.userid > {startat} AND pm.userid < ({startat} + {batchsize} + 1)
			ORDER BY pm.userid'),
		'importPMStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title, description, deleteuserid, deletereason, sticky,
			publishdate, created, oldid, oldcontenttypeid, routeid, inlist, protected, showpublished, showapproved, showopen, lastcontent)
			SELECT pmt.fromuserid, pmt.fromusername, {privateMessageChannel}, {privatemessageType}, pmt.title, pmt.title, 0, 0, 0,
			pmt.dateline, pmt.dateline, pmt.pmtextid, 9989, {pmRouteid}, 0, 1,1,1,1, pmt.dateline
			FROM {TABLE_PREFIX}pmtext AS pmt
			INNER JOIN (SELECT DISTINCT pmtextid FROM {TABLE_PREFIX}pm
				WHERE pmtextid > {startat} AND pmtextid < ({startat} + {batchsize} + 1) AND parentpmid = 0
			)
			AS pm ON pm.pmtextid = pmt.pmtextid'),
		'getMaxMissingPMStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(pmt.pmtextid)  as maxToFix
			FROM {TABLE_PREFIX}pmtext as pmt
			INNER JOIN {TABLE_PREFIX}pm as pm ON pmt.pmtextid = pm.pmtextid AND pm.parentpmid = 0
			LEFT JOIN {TABLE_PREFIX}node as node ON node.oldid = pmt.pmtextid AND node.oldcontenttypeid = {contenttypeid}
			WHERE node.nodeid IS NULL
			ORDER BY pmt.pmtextid'),
		'importMissingPMStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title, description, deleteuserid, deletereason, sticky,
			publishdate, created, oldid, oldcontenttypeid, routeid, inlist, protected, showpublished, showapproved, showopen, lastcontent)
			SELECT pmt.fromuserid, pmt.fromusername, {privateMessageChannel}, {privatemessageType}, pmt.title, pmt.title, 0, 0, 0,
			pmt.dateline, pmt.dateline, pmt.pmtextid, 9989, {pmRouteid}, 0, 1,1,1,1, pmt.dateline
			FROM {TABLE_PREFIX}pmtext as pmt
			INNER JOIN {TABLE_PREFIX}pm as pm ON pmt.pmtextid = pm.pmtextid AND pm.parentpmid = 0
			LEFT JOIN {TABLE_PREFIX}node as node ON node.oldid = pmt.pmtextid AND node.oldcontenttypeid = {contenttypeid}
			WHERE node.nodeid IS NULL  AND pmt.pmtextid > {startat} AND pmt.pmtextid < ({startat} + {batchsize} + 1)
			ORDER BY pmt.pmtextid'),
		'getMaxPMStarter' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(pmtextid) AS maxid
			FROM {TABLE_PREFIX}pm WHERE parentpmid = 0; '),
		'setPMStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET starter = nodeid, lastcontentid = nodeid WHERE
 			oldcontenttypeid = {contenttypeid} AND oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'),
		'setResponseStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET starter = parentid, lastcontentid = nodeid WHERE
 			oldcontenttypeid = {contenttypeid} AND oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'),
		'setShowValues' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET showapproved = {value}, showopen = {value}, showpublished = {value} WHERE
 			oldcontenttypeid = {contenttypeid} AND oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'),
		'importPMText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT node.nodeid, pmtext.message
			FROM {TABLE_PREFIX}pmtext AS pmtext
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pmtext.pmtextid AND oldcontenttypeid = {contenttypeid}
			WHERE node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'importMissingPMText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT node.nodeid, pmtext.message
			FROM {TABLE_PREFIX}node AS node
			LEFT JOIN {TABLE_PREFIX}text AS txt ON node.nodeid = txt.nodeid
			INNER JOIN {TABLE_PREFIX}pmtext AS pmtext ON node.oldid = pmtext.pmtextid
			WHERE txt.nodeid IS NULL AND node.oldcontenttypeid = {contenttypeid} AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)
			ORDER BY node.oldid'),
		'importPMMessage' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}privatemessage (nodeid, msgtype)
			SELECT nodeid, \'message\'
			FROM {TABLE_PREFIX}node AS node
			WHERE node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1) AND node.oldcontenttypeid = {contenttypeid}'),
		'importMissingPMMessage' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}privatemessage (nodeid, msgtype)
			SELECT node.nodeid, \'message\'
			FROM {TABLE_PREFIX}node AS node
			LEFT JOIN {TABLE_PREFIX}privatemessage AS pm ON node.nodeid = pm.nodeid
			WHERE pm.nodeid IS NULL AND node.oldcontenttypeid = {contenttypeid} AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)
			ORDER BY node.oldid'),
		'importPMSent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}sentto (nodeid, userid, folderid, msgread)
			SELECT DISTINCT STRAIGHT_JOIN node.nodeid, node.userid, f.folderid, 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}pmtext AS pmt ON pmt.pmtextid = node.oldid AND node.oldcontenttypeid = {contenttypeid}
			INNER JOIN {TABLE_PREFIX}messagefolder AS f ON f.userid = node.userid AND f.titlephrase = \'sent_items\'
			WHERE node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'importMissingPMSent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}sentto (nodeid, userid, folderid, msgread)
			SELECT DISTINCT node.nodeid, node.userid, f.folderid, 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}pmtext AS pmt ON pmt.pmtextid = node.oldid AND node.oldcontenttypeid = {contenttypeid}
			INNER JOIN {TABLE_PREFIX}messagefolder AS f ON f.userid = node.userid AND f.titlephrase = \'sent_items\'
			LEFT JOIN {TABLE_PREFIX}sentto AS st ON node.nodeid = st.nodeid
			WHERE st.nodeid IS NULL AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)
			ORDER BY node.oldid'),
		'importPMInbox' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}sentto (nodeid, userid, folderid, msgread)
			SELECT DISTINCT node.nodeid, pm.userid, f.folderid,
			MAX(CASE WHEN pm.messageread > 0 THEN 1 ELSE 0 END) AS msgread
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmtextid = node.oldid AND node.oldcontenttypeid = {contenttypeid}
			INNER JOIN {TABLE_PREFIX}pmtext AS pmt ON pmt.pmtextid = pm.pmtextid AND pm.userid <> pmt.fromuserid
			INNER JOIN {TABLE_PREFIX}messagefolder AS f ON f.userid = pm.userid AND (CASE WHEN pm.folderid > 0 THEN f.oldfolderid = pm.folderid ELSE f.oldfolderid IS NULL END)
			AND (CASE WHEN pm.folderid > 0 THEN f.titlephrase IS NULL ELSE f.titlephrase = \'messages\' END)
			WHERE node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)
			GROUP BY node.nodeid, pm.userid, f.folderid'),
		'importMissingPMInbox' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}sentto (nodeid, userid, folderid, msgread)
			SELECT DISTINCT node.nodeid, pm.userid, f.folderid,
			MAX(CASE WHEN pm.messageread > 0 THEN 1 ELSE 0 END) AS msgread
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmtextid = node.oldid AND node.oldcontenttypeid = {contenttypeid}
			INNER JOIN {TABLE_PREFIX}pmtext AS pmt ON pmt.pmtextid = pm.pmtextid AND pm.userid <> pmt.fromuserid
			INNER JOIN {TABLE_PREFIX}messagefolder AS f ON f.userid = pm.userid AND (CASE WHEN pm.folderid > 0 THEN f.oldfolderid = pm.folderid ELSE f.oldfolderid IS NULL END)
			AND (CASE WHEN pm.folderid > 0 THEN f.titlephrase IS NULL ELSE f.titlephrase = \'messages\' END)
			LEFT JOIN {TABLE_PREFIX}sentto as st ON st.nodeid = node.nodeid AND pm.userid = st.userid
			WHERE st.nodeid IS NULL AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)
			GROUP BY node.nodeid, pm.userid, f.folderid'),
		'getMaxPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(pmtextid) AS maxid FROM {TABLE_PREFIX}pm WHERE parentpmid > 0'),
		'getMaxPMResponseToFix' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(pmtextid) AS maxid
			FROM {TABLE_PREFIX}node n
			INNER JOIN {TABLE_PREFIX}pm pm ON n.oldid = pm.pmtextid AND n.oldcontenttypeid = {contenttypeid}
			WHERE n.starter <> n.parentid
		'),
		'getMaxMissingPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(pmt.pmtextid) as maxToFix
			FROM {TABLE_PREFIX}pmtext pmt
			INNER JOIN
			(SELECT pm2.pmtextid, min(pm2.parentpmid) AS parentpmid
				FROM {TABLE_PREFIX}pm pm2
				LEFT JOIN {TABLE_PREFIX}node n ON n.oldid = pm2.pmtextid AND n.oldcontenttypeid = {contenttypeidResponse}
				WHERE n.nodeid IS NULL
				GROUP BY pm2.pmtextid HAVING min(parentpmid) > 0
			)
			AS response ON response.pmtextid = pmt.pmtextid
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmid = response.parentpmid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pm.pmtextid  AND node.oldcontenttypeid = {contenttypeidStarter}
		'),
		'getMinMissingPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT min(pmt.pmtextid) as minToFix
			FROM {TABLE_PREFIX}pmtext pmt
			INNER JOIN
			(SELECT pm2.pmtextid, min(pm2.parentpmid) AS parentpmid
				FROM {TABLE_PREFIX}pm pm2
				LEFT JOIN {TABLE_PREFIX}node n ON n.oldid = pm2.pmtextid AND n.oldcontenttypeid = {contenttypeidResponse}
				WHERE n.nodeid IS NULL
				GROUP BY pm2.pmtextid HAVING min(parentpmid) > 0
			)
			AS response ON response.pmtextid = pmt.pmtextid
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmid = response.parentpmid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pm.pmtextid  AND node.oldcontenttypeid = {contenttypeidStarter}
		'),
		'getMaxNodeRecordToFix' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(nodeid) AS maxid
			FROM {TABLE_PREFIX}node n
			WHERE n.starter <> n.parentid AND oldcontenttypeid = {contenttypeid}
		'),
		'importPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title, description, deleteuserid, deletereason, sticky,
			publishdate, created, oldid, oldcontenttypeid, routeid, inlist, protected, starter, showpublished, showapproved, showopen)
			SELECT pmt.fromuserid, pmt.fromusername, node.nodeid, {privatemessageType}, pmt.title, pmt.title, 0, 0, 0,
			pmt.dateline, pmt.dateline, pmt.pmtextid, 9981, node.routeid, 0, 1, node.starter, 1, 1, 1
			FROM {TABLE_PREFIX}pmtext AS pmt
			INNER JOIN
			(SELECT pmtextid, min(parentpmid) AS parentpmid FROM {TABLE_PREFIX}pm
				WHERE pmtextid > {startat} AND pmtextid < ({startat} + {batchsize} + 1) GROUP BY pmtextid HAVING min(parentpmid) > 0
			)
			AS response ON response.pmtextid = pmt.pmtextid
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmid = response.parentpmid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pm.pmtextid  AND node.oldcontenttypeid = 9989
			WHERE node.nodeid > {maxNodeid}'),
		'importMissingPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title, description, deleteuserid, deletereason, sticky,
			publishdate, created, oldid, oldcontenttypeid, routeid, inlist, protected, starter, showpublished, showapproved, showopen)
			SELECT pmt.fromuserid, pmt.fromusername, node.nodeid, {privatemessageType}, pmt.title, pmt.title, 0, 0, 0,
			pmt.dateline, pmt.dateline, pmt.pmtextid, {contenttypeidResponse}, node.routeid, 0, 1, node.starter, 1, 1, 1
			FROM {TABLE_PREFIX}pmtext pmt
			INNER JOIN
			(SELECT pm2.pmtextid, min(pm2.parentpmid) AS parentpmid
				FROM {TABLE_PREFIX}pm pm2
				LEFT JOIN {TABLE_PREFIX}node n ON n.oldid = pm2.pmtextid AND n.oldcontenttypeid = {contenttypeidResponse}
				WHERE pm2.pmtextid > {startat} AND pm2.pmtextid < ({startat} + {batchsize} + 1) AND n.nodeid IS NULL
				GROUP BY pm2.pmtextid HAVING min(parentpmid) > 0
			)
			AS response ON response.pmtextid = pmt.pmtextid
			INNER JOIN {TABLE_PREFIX}pm AS pm ON pm.pmid = response.parentpmid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pm.pmtextid  AND node.oldcontenttypeid = {contenttypeidStarter}'),
		'createClosureSelf' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure(parent, child, depth, publishdate)
			SELECT node.nodeid, node.nodeid, 0, node.publishdate FROM {TABLE_PREFIX}node AS node
			LEFT JOIN {TABLE_PREFIX}closure AS existing on node.nodeid = existing.child AND existing.depth = 0
			WHERE node.oldcontenttypeid = {oldcontenttype} AND existing.child IS NULL'),
		'createClosurefromParent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure(parent, child, depth, publishdate)
			SELECT parent.parent, node.nodeid, parent.depth + 1, node.publishdate FROM {TABLE_PREFIX}node AS node
 			 INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			LEFT JOIN {TABLE_PREFIX}closure AS existing on existing.child = node.nodeid AND existing.parent = parent.parent
			WHERE node.oldcontenttypeid = {oldcontenttype} AND existing.child IS NULL' ),
		'runClosureAgain' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT parent.parent FROM {TABLE_PREFIX}node AS node
 			 INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			LEFT JOIN {TABLE_PREFIX}closure AS existing on existing.child = node.nodeid AND existing.parent = parent.parent
			WHERE node.oldcontenttypeid = {oldcontenttype} AND existing.child IS NULL
			LIMIT 1'),
		'getMissingGroupCategories' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT cat.* FROM {TABLE_PREFIX}socialgroupcategory AS cat
			LEFT JOIN {TABLE_PREFIX}node AS node ON node.oldcontenttypeid = 9988
			AND node.oldid = cat.socialgroupcategoryid WHERE node.nodeid IS NULL'),
		'getMissingSocialGroups' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT sgroup.*, category.nodeid AS categoryid, user.userid, user.username, transfer.userid AS transferuserid,
			transfer.username AS transferusername, route.routeid
			FROM {TABLE_PREFIX}socialgroup AS sgroup
			INNER JOIN {TABLE_PREFIX}node AS category ON category.oldcontenttypeid = 9988 AND category.oldid = sgroup.socialgroupcategoryid
			INNER JOIN {TABLE_PREFIX}user AS user ON user.userid = sgroup.creatoruserid
			LEFT JOIN {TABLE_PREFIX}user AS transfer ON user.userid = sgroup.transferowner
			LEFT JOIN {TABLE_PREFIX}node AS node ON node.oldcontenttypeid = {socialgroupType} AND node.oldid = sgroup.groupid
			LEFT JOIN {TABLE_PREFIX}routenew AS route ON route.routeid = category.routeid
			WHERE node.nodeid IS NULL
			LIMIT {batch_size}'),
		'getSocialGroupsCount' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT COUNT(*) AS total
			FROM {TABLE_PREFIX}socialgroup AS sgroup
			INNER JOIN {TABLE_PREFIX}node AS category ON category.oldcontenttypeid = 9988 AND category.oldid = sgroup.socialgroupcategoryid
			LEFT JOIN {TABLE_PREFIX}node AS node ON node.oldcontenttypeid = {socialgroupType} AND node.oldid = sgroup.groupid
			WHERE node.nodeid IS NULL'),
		'getImportedGroupsCount' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT COUNT(*) AS total
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}closure AS cl ON (n.nodeid = cl.child)
			WHERE cl.parent = {parentid} AND n.contenttypeid = {channeltype} AND cl.depth > 1'),
		'getMaxSGDiscussionID' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(discussionid) AS maxid FROM {TABLE_PREFIX}discussion WHERE deleted = 0'),
		'getMaxSGPhotoID' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(attachmentid) AS maxid FROM {TABLE_PREFIX}attachment WHERE contenttypeid = {grouptypeid}'),
		'getMaxSGGallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(galleryid) AS maxid
			FROM {TABLE_PREFIX}socialgroup AS sg
			INNER JOIN (
				SELECT contentid AS galleryid
				FROM {TABLE_PREFIX}attachment
				WHERE contenttypeid = {grouptypeid}
			)
			AS gallerycheck ON gallerycheck.galleryid = sg.groupid'
		),
		'importSGDiscussions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, approved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT gm.postuserid, gm.postusername, n.nodeid AS parentid, {textTypeid}, gm.title,
			'', 0, '', 0 AS sticky, CASE WHEN (d.deleted = 1) THEN 0 ELSE gm.dateline END AS publishdate,
			d.discussionid, {discussionTypeid}, n.routeid, 1, 0,
			CASE WHEN (d.deleted = 0) THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (d.moderation = 0) THEN 1 ELSE 0 END AS showapproved,
			CASE WHEN (d.moderation = 0) THEN 1 ELSE 0 END AS approved,
			1, d.visible, d.visible,
			d.moderation, d.moderation, d.lastpost, d.lastposter, d.lastposterid,
			gm.ipaddress, gm.dateline
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.groupid AND n.oldcontenttypeid = {grouptypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			WHERE d.deleted = 0 AND d.discussionid > {startat} AND d.discussionid < ({startat} + {batchsize} + 1)" ),
		'getMissingSGDiscussions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT d.discussionid
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.groupid AND n.oldcontenttypeid = {groupTypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			LEFT JOIN {TABLE_PREFIX}node AS n2 ON n2.oldid = d.discussionid AND n2.oldcontenttypeid = {discussionTypeid}
			WHERE d.deleted = 0 AND n2.nodeid IS NULL
			ORDER BY d.discussionid
			LIMIT {batchsize}" ),
		'importMissingSGDiscussions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, approved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT gm.postuserid, gm.postusername, n.nodeid AS parentid, {textTypeid}, gm.title,
			'', 0, '', 0 AS sticky, CASE WHEN (d.deleted = 1) THEN 0 ELSE gm.dateline END AS publishdate,
			d.discussionid, {discussionTypeid}, n.routeid, 1, 0,
			CASE WHEN (d.deleted = 0) THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (d.moderation = 0) THEN 1 ELSE 0 END AS showapproved,
			CASE WHEN (d.moderation = 0) THEN 1 ELSE 0 END AS approved,
			1, d.visible, d.visible,
			d.moderation, d.moderation, d.lastpost, d.lastposter, d.lastposterid,
			gm.ipaddress, gm.dateline
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.groupid AND n.oldcontenttypeid = {grouptypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			WHERE d.deleted = 0 AND d.discussionid IN ({discussionList})"),
		'importSGGalleryNode' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT sg.creatoruserid, user.username, n.nodeid AS parentid, {gallerytypeid}, n.title,
			n.description, 0, '', 0 AS sticky, sg.dateline,
			gallerycheck.galleryid, 9983, n.routeid, 1, 0,
			1, 1, 1, gallerycheck.pubcount, gallerycheck.pubcount,
			gallerycheck.unpubcount, gallerycheck.unpubcount, 0, '', 0,
			n.ipaddress, sg.dateline
			FROM {TABLE_PREFIX}socialgroup AS sg
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = sg.groupid AND n.oldcontenttypeid = {grouptypeid}
			INNER JOIN (
				SELECT contentid AS galleryid, SUM(CASE WHEN state = 'visible' THEN 1 ELSE 0 END) AS pubcount, SUM(CASE WHEN state = 'moderation' THEN 1 ELSE 0 END) AS unpubcount
				FROM {TABLE_PREFIX}attachment
				WHERE contenttypeid = {grouptypeid} AND contentid > {startat} AND contentid < ({startat} + {batchsize} + 1)
				GROUP BY galleryid
			)
			AS gallerycheck ON gallerycheck.galleryid = sg.groupid
			INNER JOIN {TABLE_PREFIX}user AS user ON sg.creatoruserid = user.userid"),
		'getMissingSGGalleryNode' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT gallerycheck.galleryid
			FROM {TABLE_PREFIX}socialgroup AS sg
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = sg.groupid AND n.oldcontenttypeid = {groupTypeid}
			INNER JOIN (
				SELECT contentid AS galleryid
				FROM {TABLE_PREFIX}attachment
				WHERE contenttypeid = {groupTypeid}
				GROUP BY galleryid
			)
			AS gallerycheck ON gallerycheck.galleryid = sg.groupid
			INNER JOIN {TABLE_PREFIX}user AS user ON sg.creatoruserid = user.userid
			LEFT JOIN {TABLE_PREFIX}node AS n2 ON n2.oldid = gallerycheck.galleryid AND n2.oldcontenttypeid = {oldGalleryTypeid}
			WHERE n2.nodeid IS NULL
			LIMIT {batchsize}"),
		'importMissingSGGalleryNode' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT sg.creatoruserid, user.username, n.nodeid AS parentid, {galleryTypeid}, n.title,
			n.description, 0, '', 0 AS sticky, sg.dateline,
			gallerycheck.galleryid, 9983, n.routeid, 1, 0,
			1, 1, 1, gallerycheck.pubcount, gallerycheck.pubcount,
			gallerycheck.unpubcount, gallerycheck.unpubcount, 0, '', 0,
			n.ipaddress, sg.dateline
			FROM {TABLE_PREFIX}socialgroup AS sg
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = sg.groupid AND n.oldcontenttypeid = {groupTypeid}
			INNER JOIN (
				SELECT contentid AS galleryid, SUM(CASE WHEN state = 'visible' THEN 1 ELSE 0 END) AS pubcount, SUM(CASE WHEN state = 'moderation' THEN 1 ELSE 0 END) AS unpubcount
				FROM {TABLE_PREFIX}attachment
				WHERE contenttypeid = {groupTypeid} AND contentid IN ({galleryList})
				GROUP BY galleryid
			)
			AS gallerycheck ON gallerycheck.galleryid = sg.groupid
			INNER JOIN {TABLE_PREFIX}user AS user ON sg.creatoruserid = user.userid"),
		'fixLastGalleryData' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
						'query_string' => "UPDATE {TABLE_PREFIX}node AS n
				INNER JOIN (SELECT nodeid, parentid, publishdate, oldid, oldcontenttypeid, authorname, userid FROM {TABLE_PREFIX}node
				WHERE oldid > {startat} AND oldid < ({startat} + {batchsize} + 1) AND oldcontenttypeid = 9987 ORDER BY publishdate DESC, nodeid DESC)
				AS photo ON photo.parentid = n.nodeid
				SET n.lastcontentid = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.nodeid ELSE n.lastcontentid END),
				n.lastcontent = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.publishdate ELSE n.lastcontent END),
				n.lastcontentauthor = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.authorname ELSE n.lastcontentauthor END),
				n.lastauthorid = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.userid ELSE n.lastauthorid END)"),
		'fixMissingLastGalleryData' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
						'query_string' => "UPDATE {TABLE_PREFIX}node AS n
				INNER JOIN (SELECT nodeid, parentid, publishdate, oldid, oldcontenttypeid, authorname, userid FROM {TABLE_PREFIX}node
				WHERE oldid IN ({photoList}) AND oldcontenttypeid = 9987 ORDER BY publishdate DESC, nodeid DESC)
				AS photo ON photo.parentid = n.nodeid
				SET n.lastcontentid = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.nodeid ELSE n.lastcontentid END),
				n.lastcontent = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.publishdate ELSE n.lastcontent END),
				n.lastcontentauthor = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.authorname ELSE n.lastcontentauthor END),
				n.lastauthorid = (CASE WHEN photo.publishdate >= n.lastcontent THEN photo.userid ELSE n.lastauthorid END)"),
		'importSGGallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}gallery(nodeid, caption)
			SELECT n.nodeid, CONCAT({caption}, ' - ', n.title)
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = 9983
			WHERE a.contenttypeid = {grouptypeid} AND a.contentid > {startat} AND a.contentid < ({startat} + {batchsize} + 1)
			GROUP BY a.contentid"),
		'getMissingSGGallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT n.nodeid
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = {oldGalleryTypeid}
			LEFT JOIN {TABLE_PREFIX}gallery AS g ON n.nodeid = g.nodeid
			WHERE a.contenttypeid = {groupTypeid} AND g.nodeid IS NULL
			GROUP BY a.contentid
			LIMIT {batchsize}"),
		'importMissingSGGallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}gallery(nodeid, caption)
			SELECT n.nodeid, CONCAT({caption}, ' - ', n.title)
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = {oldGalleryTypeid}
			WHERE a.contenttypeid = {groupTypeid} AND n.nodeid IN ({nodeList})
			GROUP BY a.contentid"),
		'importSGText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, CONCAT({caption}, ' - ', n.title)
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = 9983
			WHERE a.contenttypeid = {grouptypeid} AND a.contentid > {startat} AND a.contentid < ({startat} + {batchsize} + 1)
			GROUP BY a.contentid"),
		'importMissingSGText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, CONCAT({caption}, ' - ', n.title)
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = {oldGalleryTypeid}
			WHERE a.contenttypeid = {groupTypeid} AND n.nodeid IN ({nodeList})
			GROUP BY a.contentid"),
		'importSGPhotoNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, starter, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT a.userid, u.username, n.nodeid AS parentid, n.nodeid AS starter, {phototypeid}, a.caption,
			'', 0, '', 0 AS sticky, CASE WHEN (a.state = 'visible') THEN a.dateline ELSE 0 END AS publishdate,
			a.attachmentid, 9987, 0, 0, 0,
			CASE WHEN (a.state = 'visible') THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (a.state = 'visible') THEN 1 ELSE 0 END AS showapproved,
			1, 0, 0, 0, 0, a.dateline, '', 0,
			n.ipaddress, a.dateline
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = a.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = 9983 AND a.contenttypeid = {grouptypeid}
			WHERE a.attachmentid > {startat} AND a.attachmentid < ({startat} + {batchsize} + 1)"),
		'getMissingSGPhotoNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT a.attachmentid
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = a.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = {oldGalleryTypeid} AND a.contenttypeid = {groupTypeid}
			LEFT JOIN {TABLE_PREFIX}node as n2 ON n2.oldid = a.attachmentid AND n2.oldcontenttypeid = {oldPhotoTypeid}
			WHERE n2.nodeid IS NULL
			LIMIT {batchsize}"),
		'importMissingSGPhotoNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, starter, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen,textcount, totalcount,
			textunpubcount, totalunpubcount, lastcontent, lastcontentauthor, lastauthorid,
			ipaddress, created)
			SELECT a.userid, u.username, n.nodeid AS parentid, n.nodeid AS starter, {photoTypeid}, a.caption,
			'', 0, '', 0 AS sticky, CASE WHEN (a.state = 'visible') THEN a.dateline ELSE 0 END AS publishdate,
			a.attachmentid, {oldPhotoTypeid}, 0, 0, 0,
			CASE WHEN (a.state = 'visible') THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (a.state = 'visible') THEN 1 ELSE 0 END AS showapproved,
			1, 0, 0, 0, 0, a.dateline, '', 0,
			n.ipaddress, a.dateline
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = a.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND n.oldcontenttypeid = {oldGalleryTypeid} AND a.contenttypeid = {groupTypeid}
			WHERE a.attachmentid IN ({photoList})"),
		'importSGPhotos' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}photo(nodeid, filedataid, caption, height, width)
			SELECT n.nodeid, a.filedataid, a.caption, fd.height, fd.width
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.attachmentid AND n.oldcontenttypeid = 9987
			INNER JOIN {TABLE_PREFIX}filedata AS fd ON a.filedataid = fd.filedataid
			WHERE a.contenttypeid = {grouptypeid} AND a.attachmentid > {startat} AND a.attachmentid < ({startat} + {batchsize} + 1)"),
		'importMissingSGPhotos' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}photo(nodeid, filedataid, caption, height, width)
			SELECT n.nodeid, a.filedataid, a.caption, fd.height, fd.width
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.attachmentid AND n.oldcontenttypeid = {oldPhotoTypeid}
			INNER JOIN {TABLE_PREFIX}filedata AS fd ON a.filedataid = fd.filedataid
			WHERE a.contenttypeid = {groupTypeid} AND a.attachmentid IN ({photoList})"),
		'updateDiscussionLastContentId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}discussion AS d ON d.discussionid = node.oldid
			INNER JOIN {TABLE_PREFIX}node AS lm ON lm.oldid = d.lastpostid AND lm.oldcontenttypeid = {messageTypeid}
			SET node.lastcontentid = lm.nodeid,
				node.lastcontentauthor = lm.authorname, node.lastcontent = lm.publishdate, node.lastauthorid = lm.userid
			WHERE node.oldcontenttypeid = {discussionTypeid} AND node.oldid > {startat}
			AND node.oldid < ({startat} + {batchsize} + 1)" ),
		'importSGDiscussionText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, gm.pagetext
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			WHERE d.deleted = 0 AND d.discussionid > {startat} AND d.discussionid < ({startat} + {batchsize} + 1)" ),
		'importMissingSGDiscussionText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, gm.pagetext
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			WHERE n.nodeid IN ({textList})" ),
		'getMissingSGDiscussionText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT n.nodeid
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid
			LEFT JOIN {TABLE_PREFIX}text as txt ON n.nodeid = txt.nodeid
			WHERE d.deleted = 0 AND txt.nodeid IS NULL
			ORDER BY n.nodeid
			LIMIT {batchsize}" ),
		'setStarterByNodeList' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node SET starter = nodeid WHERE
 			nodeid IN ({nodeList})"),
		'importSGPosts' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen, ipaddress, starter, created)
			SELECT gm.postuserid, gm.postusername, n.nodeid AS parentid, {textTypeid}, gm.title,
			'', 0, '', 0 AS sticky, CASE WHEN (gm.state = 'visible') THEN gm.dateline ELSE 0 END AS publishdate,
			gm.gmid, {messageTypeid}, n.routeid, 1, 0,
			CASE WHEN (gm.state = 'visible') THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (gm.state = 'visible') THEN 1 ELSE 0 END AS showapproved,
			1, gm.ipaddress, n.starter, gm.dateline
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}discussion AS d ON gm.discussionid = d.discussionid AND gm.gmid <> d.firstpostid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			WHERE gm.gmid > {startat} AND gm.gmid < ({startat} + {batchsize} + 1)"),
		'importSGPostText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, gm.pagetext
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.gmid AND n.oldcontenttypeid = {messageTypeid}
			WHERE gm.gmid > {startat} AND gm.gmid < ({startat} + {batchsize} + 1)" ),
		'getMaxSGPost' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(gmid) AS maxid
			FROM {TABLE_PREFIX}discussion AS d
			INNER JOIN {TABLE_PREFIX}groupmessage AS gm ON gm.gmid = d.firstpostid"),
		'getMissingSGPosts' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT gm.gmid
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}discussion AS d ON gm.discussionid = d.discussionid AND gm.gmid <> d.firstpostid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			LEFT JOIN {TABLE_PREFIX}node AS n2 ON n2.oldid = gm.gmid AND n2.oldcontenttypeid = {messageTypeid}
			WHERE n2.nodeid IS NULL
			ORDER BY gm.gmid
			LIMIT {batchsize}"),
		'importMissingSGPosts' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, showopen, ipaddress, starter, created)
			SELECT gm.postuserid, gm.postusername, n.nodeid AS parentid, {textTypeid}, gm.title,
			'', 0, '', 0 AS sticky, CASE WHEN (gm.state = 'visible') THEN gm.dateline ELSE 0 END AS publishdate,
			gm.gmid, {messageTypeid}, n.routeid, 1, 0,
			CASE WHEN (gm.state = 'visible') THEN 1 ELSE 0 END AS showpublished,
			CASE WHEN (gm.state = 'visible') THEN 1 ELSE 0 END AS showapproved,
			1, gm.ipaddress, n.starter, gm.dateline
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}discussion AS d ON gm.discussionid = d.discussionid AND gm.gmid <> d.firstpostid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.discussionid AND n.oldcontenttypeid = {discussionTypeid}
			WHERE gm.gmid IN ({messageList})"),
		'getMissingSGPostsText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT n.nodeid
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}discussion AS d ON gm.discussionid = d.discussionid AND gm.gmid <> d.firstpostid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.gmid AND n.oldcontenttypeid = {messageTypeid}
			LEFT JOIN {TABLE_PREFIX}text as txt ON n.nodeid = txt.nodeid
			WHERE txt.nodeid IS NULL AND d.deleted = 0
			ORDER BY n.nodeid
			LIMIT {batchsize}"),
		'importMissingSGPostText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, gm.pagetext
			FROM {TABLE_PREFIX}groupmessage AS gm
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gm.gmid AND n.oldcontenttypeid = {messageTypeid}
			WHERE n.nodeid IN ({nodeList})"),
		'addGroupOwners' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}groupintopic(userid, groupid, nodeid)
			SELECT n.userid, {groupid}, n.nodeid
			FROM {TABLE_PREFIX}node AS n
			LEFT JOIN {TABLE_PREFIX}groupintopic AS existing ON existing.userid = n.userid AND existing.groupid = {groupid} AND existing.nodeid = n.nodeid
			WHERE n.oldcontenttypeid = {socialgroupType} AND existing.groupid IS NULL' ),
		'addGroupMembers' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}groupintopic(userid, groupid, nodeid)
			SELECT socialgroupmember.userid, {groupid}, n.nodeid
			FROM {TABLE_PREFIX}socialgroupmember AS socialgroupmember INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = socialgroupmember.groupid AND n.oldcontenttypeid = {socialgroupType}
			LEFT JOIN {TABLE_PREFIX}groupintopic AS existing ON existing.userid = socialgroupmember.userid AND existing.nodeid = n.nodeid
			WHERE existing.groupid IS NULL' ),
		'getMissingSocialGroupPhotos' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT a.filedataid, a.contentid, a.caption, n.nodeid AS parentid, 9987 AS oldcontenttypeid, a.attachmentid AS oldid,
			n.userid, n.authorname, f.height, f.width
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.contentid AND a.contenttypeid = n.oldcontenttypeid AND a.contenttypeid = {groupcontenttype}
			INNER JOIN {TABLE_PREFIX}filedata AS f ON f.filedataid = a.filedataid
			LEFT JOIN {TABLE_PREFIX}node AS existing ON existing.oldid = a.attachmentid AND n.oldcontenttypeid = 9987
			WHERE existing.nodeid IS NULL ORDER BY a.contentid' ),
		'getMax4VM' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(vmid) AS maxid FROM {TABLE_PREFIX}visitormessage'),
		'ImportVisitorMessages' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
			description, deleteuserid, deletereason, sticky, publishdate, created,
			oldid, oldcontenttypeid, routeid, inlist, protected,
			showpublished, showapproved, approved, showopen, ipaddress, setfor)
			SELECT vm.postuserid, vm.postusername, {vmChannel}, {texttypeid}, vm.title,
			\'\', 0, \'\', 0, CASE WHEN vm.state <> \'deleted\' THEN vm.dateline ELSE 0 END AS publishdate,
			CASE WHEN vm.state=\'visible\' THEN vm.dateline ELSE 0 END AS created,
			vm.vmid AS oldid, {visitorMessageType} AS oldcontenttypeid, {vmRouteid}, 1, 0,
			CASE WHEN vm.state=\'deleted\' THEN 0 ELSE 1 END AS showpublished, CASE WHEN vm.state=\'moderation\' THEN 0 ELSE 1 END AS showapproved, CASE WHEN vm.state=\'moderation\' THEN 0 ELSE 1 END AS approved, 1, vm.ipaddress, vm.userid AS setfor
			FROM {TABLE_PREFIX}visitormessage AS vm
			WHERE vm.vmid > {startat} AND vm.vmid < ({startat} + {batchsize} + 1) ' ),
		'importVMText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT node.nodeid, vm.pagetext AS rawtext
			FROM {TABLE_PREFIX}visitormessage AS vm
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = vm.vmid AND node.oldcontenttypeid = {visitorMessageType}
			WHERE vm.vmid > {startat} AND vm.vmid < ({startat} + {batchsize} + 1)' ),
		'getMaxvB4Album' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(albumid) AS maxid
			FROM {TABLE_PREFIX}album' ),
		'getMaxvB5Album' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid	FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {albumtypeid}' ),
		'importAlbumNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node (publishdate, title, userid, authorname,htmltitle,
			parentid, created, oldid, oldcontenttypeid,`open`,
			showopen, approved, showapproved, showpublished, protected,
			routeid, contenttypeid, deleteuserid, deletereason, sticky)
			SELECT al.createdate, al.title, al.userid, u.username, al.title,
			{albumChannel}, al.createdate, al.albumid, {albumtype},1,
			1, 1, 1, 1, 0,
			{routeid}, {gallerytype}, 0, \'\', 0
			FROM {TABLE_PREFIX}album AS al INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = al.userid
			WHERE al.albumid > {startat} AND al.albumid < ({startat} + {batchsize} + 1)'
		),
		'importAlbums2Gallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}gallery(nodeid, caption)
			SELECT nodeid, title
			FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {albumtype}
			AND oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'
		),
		'getMaxvB4Photo' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(attachmentid) AS maxid
			FROM {TABLE_PREFIX}attachment WHERE contenttypeid = {albumtype}' ),
		'importPhotoNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(publishdate, title, userid, authorname,htmltitle,
			parentid, starter, created, oldid, oldcontenttypeid,`open`,
			showopen, approved, showapproved, showpublished, protected,
			routeid, contenttypeid, deleteuserid, deletereason, sticky )
			SELECT at.dateline,CASE when at.caption IS NULL then at.filename ELSE at.caption END,
			at.userid, u.username,	CASE when at.caption IS NULL then at.filename ELSE at.caption END,
			n.nodeid AS parentid, n.nodeid AS starter, at.dateline, at.attachmentid, 9986, 1,
			1, 1, 1, 1, 0,
			n.routeid, {phototype}, 0, \'\', 0
			FROM {TABLE_PREFIX}attachment AS at
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = at.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = at.contentid AND n.oldcontenttypeid = {albumtype} AND at.contenttypeid = {albumtype}
			WHERE at.attachmentid > {startat} AND at.attachmentid < ({startat} + {batchsize} + 1)'
		),
		'importPhotos2Gallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}photo(nodeid, filedataid, caption, height, width)
			SELECT n.nodeid, at.filedataid, CASE when at.caption IS NULL then at.filename ELSE at.caption END,
				f.height, f.width
			FROM {TABLE_PREFIX}attachment AS at
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = at.attachmentid AND n.oldcontenttypeid = 9986
			INNER JOIN {TABLE_PREFIX}filedata AS f ON f.filedataid = at.filedataid
			WHERE n.oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'
		),
		'createGenChannel' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}channel (nodeid, guid) SELECT nodeid, {guid}
			FROM {TABLE_PREFIX}node
			WHERE oldcontenttypeid = {oldcontenttypeid}'),
		'setModeratorNodeid' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}moderator AS m ON m.forumid = n.oldid AND n.oldcontenttypeid ={forumTypeId}
			 AND m.nodeid IS NULL
			SET m.nodeid = n.nodeid' ),
		'setModeratorlogThreadid' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}moderatorlog AS m ON m.threadid = n.oldid AND n.oldcontenttypeid ={threadTypeId}
			 AND m.nodeid IS NULL
			SET m.nodeid = n.nodeid' ),
		'getRootForumPerms' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT fp.usergroupid, f.forumid, fp.forumpermissions FROM
			{TABLE_PREFIX}forum AS f INNER JOIN {TABLE_PREFIX}forumpermission AS fp ON fp.forumid = f.forumid
			WHERE f.parentid < 1
			ORDER BY usergroupid, forumid' ),
		/** This method is used for other types besides posts **/
		'getMaxImportedPost' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {contenttypeid}'),
		'getMaxFixedPMResponse' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid
			FROM {TABLE_PREFIX}node
			WHERE oldcontenttypeid = {contenttypeid} AND starter = parentid'),
		'getMaxNodeRecordFixed' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(nodeid) AS maxid
			FROM {TABLE_PREFIX}node
			WHERE oldcontenttypeid = {contenttypeid} AND starter = parentid'),
		'getMaxImportedSGPhoto' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(n.oldid) AS maxid
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}attachment AS a ON node.oldid = a.attachmentid AND a.contenttypeid = {grouptypeid}
			WHERE n.oldcontenttypeid = {phototypeid}'
		),
		'getMaxBlogUserId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(userid) AS maxuserId FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {contenttypeid}'),
		'getBlogs4Import' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT b.userid, u.username, b.title, b.dateline, b.blogid
			FROM {TABLE_PREFIX}blog AS b
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = b.firstblogtextid
			INNER JOIN {TABLE_PREFIX}user u ON b.userid = u.userid
			WHERE b.userid > {maxexisting}
			GROUP BY b.userid LIMIT {blocksize}'),
		'importBlogStarters' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, title, htmltitle,
			publishdate, userid, authorname, oldid, oldcontenttypeid,
			showpublished, inlist, routeid, showapproved, textcount,
			totalcount, textunpubcount, totalunpubcount, lastcontent, lastcontentauthor,
			lastauthorid, created)
			SELECT {texttype}, parent.nodeid, bt.title, bt.title,
			case WHEN bt.state = \'visible\' THEN bt.dateline else 0 end, blog.userid, blog.username, bt.blogtextid, 9985,
			case WHEN bt.state = \'visible\' THEN 1 else 0 end , case WHEN bt.state = \'visible\' THEN 1 else 0 end,
			parent.routeid, 1, blog.comments_visible,
			blog.comments_visible, blog.comments_moderation, blog.comments_moderation, blog.lastcomment, blog.lastcommenter,
			bt.username, bt.dateline
			FROM {TABLE_PREFIX}blog AS blog
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = blog.firstblogtextid
			INNER JOIN {TABLE_PREFIX}node AS parent ON parent.userid = blog.userid AND parent.parentid = {bloghome}
				AND parent.oldcontenttypeid = 9999
			LEFT JOIN {TABLE_PREFIX}blog_text AS last ON last.blogtextid = blog.lastblogtextid
			WHERE bt.blogtextid > {startat} AND bt.blogtextid <({startat} + {batchsize} + 1)
			ORDER BY bt.blogtextid'),
		'setStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node
			SET starter = nodeid
			WHERE oldcontenttypeid IN ({contenttypeid}) AND oldid > {startat}'),
		'addClosureSelf' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT node.nodeid, node.nodeid, 0
			FROM {TABLE_PREFIX}node AS node
			WHERE node.oldcontenttypeid IN ({contenttypeid}) AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'addClosureParents' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT parent.parent, node.nodeid, parent.depth + 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			WHERE node.oldcontenttypeid IN ({contenttypeid}) AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'addClosureSelfInfraction' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT node.nodeid, node.nodeid, 0
			FROM {TABLE_PREFIX}node AS node
			WHERE node.oldcontenttypeid = {contenttypeid} AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'addClosureParentsInfraction' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT parent.parent, node.nodeid, parent.depth + 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			WHERE node.oldcontenttypeid = {contenttypeid} AND node.oldid > {startat} AND node.oldid < ({startat} + {batchsize} + 1)'),
		'getProcessedCount' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT ROW_COUNT() AS recs'),
		'importBlogResponses' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, starter, title, htmltitle,
			publishdate, userid, authorname, oldid, oldcontenttypeid, showpublished, showapproved, inlist, routeid, created)
			SELECT DISTINCT {texttypeid}, starter.nodeid, starter.nodeid,
			CASE WHEN IFNULL(bt.title, \'\') = \'\' THEN starter.title ELSE bt.title END,
			CASE WHEN IFNULL(bt.title, \'\') = \'\'THEN starter.title ELSE bt.title END,
			case WHEN bt.state = \'visible\' THEN bt.dateline else 0 end, bt.userid, bt.username, bt.blogtextid, 9984,
			case WHEN bt.state = \'visible\' THEN 1 else 0 end, case WHEN bt.state = \'visible\' THEN 1 else 0 end,
			1, starter.routeid, bt.dateline
			FROM {TABLE_PREFIX}blog AS blog
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogid = blog.blogid AND bt.blogtextid <> blog.firstblogtextid
			INNER JOIN {TABLE_PREFIX}node AS starter ON starter.oldid = blog.firstblogtextid AND starter.oldcontenttypeid = 9985
			WHERE bt.blogtextid > {startat}
			ORDER BY bt.blogtextid
			LIMIT {batchsize}'),
		'importBlogTextNoState' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, bt.pagetext
			FROM {TABLE_PREFIX}node AS n INNER JOIN {TABLE_PREFIX}blog_text AS bt
			ON bt.blogtextid = n.oldid AND n.oldcontenttypeid = {contenttypeid}
			WHERE bt.blogtextid > {startat}'),
		'importBlogText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext, htmlstate)
			SELECT n.nodeid, bt.pagetext, htmlstate
			FROM {TABLE_PREFIX}node AS n INNER JOIN {TABLE_PREFIX}blog_text AS bt
			ON bt.blogtextid = n.oldid AND n.oldcontenttypeid = {contenttypeid}
			WHERE bt.blogtextid > {startat}'),
		'updateForumLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}forum AS f ON f.forumid = n.oldid AND n.oldcontenttypeid = {forumTypeid}
			INNER JOIN {TABLE_PREFIX}node AS lp ON lp.oldid = f.lastpostid AND lp.oldcontenttypeid = {postTypeid}
			SET n.textcount = f.threadcount, n.totalcount = f.replycount, n.lastcontent = f.lastpost, n.lastcontentid = lp.nodeid'),
		'updateForumLastThreadOnly' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}forum AS f ON f.forumid = n.oldid AND n.oldcontenttypeid = {forumTypeid}
			INNER JOIN {TABLE_PREFIX}node AS lp ON lp.oldid = f.lastthreadid AND lp.oldcontenttypeid = {threadTypeid} AND n.lastcontent = 0
			SET n.textcount = f.threadcount, n.totalcount = f.replycount, n.lastcontent = f.lastpost, n.lastcontentid = lp.nodeid'),
		'updateThreadLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}thread AS th ON th.threadid = n.oldid
			INNER JOIN {TABLE_PREFIX}node AS lp ON lp.oldid = th.lastpostid AND lp.oldcontenttypeid = {postTypeid}
			INNER JOIN {TABLE_PREFIX}post AS last ON last.postid = th.lastpostid
			SET n.textcount = th.replycount, n.totalcount = th.replycount, n.textunpubcount = (th.hiddencount + th.deletedcount), n.totalunpubcount = (th.hiddencount + th.deletedcount),
			n.lastcontent = th.lastpost, n.lastcontentauthor = last.username, n.lastauthorid = last.userid, n.lastcontentid = lp.nodeid
			WHERE n.oldcontenttypeid = {threadTypeid} AND n.oldid > {startat} AND n.oldid < ({startat} + {batchsize} + 1)'),
		'insertCMSArticles' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, title, description, htmltitle, urlident,
			publishdate, oldid, oldcontenttypeid, created, inlist, routeid, showpublished, showapproved, showopen)
			SELECT {textTypeId}, node.nodeid, ni.title, ni.description, ni.html_title, n.url,
		 	n.publishdate, n.nodeid, n.contenttypeid, n.publishdate, 1, node.routeid, 1, 1, 1
			FROM {TABLE_PREFIX}cms_node AS n
			INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS ni ON ni.nodeid = n.nodeid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = n.parentnode AND node.oldcontenttypeid = {sectionTypeId}
			WHERE n.contenttypeid = {articleTypeId} AND n.nodeid > {startat} AND n.nodeid < ({startat} + {batchsize} + 1) ORDER BY n.nodeid'),
		'insertCMSText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, previewtext,
			previewimage, previewvideo, imageheight, imagewidth,
			rawtext, htmlstate)
			SELECT node.nodeid, a.previewtext,
			a.previewimage, a.previewvideo, a.imageheight, a.imagewidth,
			a.pagetext, a.htmlstate
			FROM {TABLE_PREFIX}cms_node AS n
			INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS ni ON ni.nodeid = n.nodeid
			INNER JOIN {TABLE_PREFIX}cms_article AS a ON a.contentid = n.contentid
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = n.nodeid AND node.oldcontenttypeid = {articleTypeId}
			WHERE n.nodeid > {startat} AND n.nodeid < ({startat} + {batchsize} + 1) ORDER BY n.nodeid'),
		'updateChannelRoutes' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
			INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Conversation\'
			SET n.routeid = cr.routeid
			WHERE n.oldcontenttypeid = {contenttypeid} AND n.oldid > {startat} AND n.oldid < ({startat} + {batchsize} + 1)'),
		'updateChannelRoutesByNodeList' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
			INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Conversation\'
			SET n.routeid = cr.routeid
			WHERE n.oldcontenttypeid = {contenttypeid} AND n.nodeid IN ({nodeList})'),
		'updateChannelCounts' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'Update {TABLE_PREFIX}node AS n INNER JOIN
			(
				SELECT parent.nodeid,
				SUM(CASE WHEN child.contenttypeid IN ({textTypeid}, {pollTypeid}) THEN child.showpublished ELSE 0 END) AS published,
				SUM(CASE WHEN child.contenttypeid IN ({textTypeid}, {pollTypeid}) AND child.showpublished=0 THEN 1 ELSE 0 END) AS unpublished,
				SUM(child.totalcount) AS totalcount, SUM(child.totalunpubcount) AS totalunpubcount
				FROM {TABLE_PREFIX}node AS parent INNER JOIN {TABLE_PREFIX}node AS child ON child.parentid = parent.nodeid
				WHERE parent.contenttypeid = {channelTypeid} AND child.contenttypeid IN ({textTypeid}, {pollTypeid}) GROUP BY parent.nodeid
			) AS sub ON sub.nodeid = n.nodeid
			SET n.textcount = sub.published,
			n.textunpubcount = sub.unpublished,
			n.totalcount = sub.published + sub.totalcount,
			n.textunpubcount = sub.unpublished + sub.totalunpubcount'),
		'updateChannelLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			/*
				While testing the upgrade against a very large database, the MYSQL optimizer
				seemed to sometimes flip this from using child as the driving table (a
				child,parent join and using primary nodeid keys on both) to using parent as
				the driving table (a parent,child join using the node_ctypid_userid_dispo_idx
				(contenttypeid,userid,displayorder) key on parent &
				node_parent_lastcontent(parentid,lastcontent) key on child).
				Apparently it decided that filtering the parent table first by contenttypeid,
				then doing a join onto children via the sorted parentid,lastcontent index was
				more optimal than filtering the child's nodeid index, then joining to parent
				via parent's nodeid index.
				In practice, however, this caused the actual query to take a very, very long time,
				and overall, 375 iterations of 500a29::step_20() took over 69hours 31minutes
				(about 667.4 seconds per iteration). Running the query manually confirmed that
				indeed this was very slow.
				Doing a ... child STRAIGHT_JOIN ... parent forces the optimizer to join in the
				order of child, parent, which EXPLAIN EXTENDED showed more rows processed on
				average	(e.g. ~6k child rows x few parent rows vs few hundred parent rows x few child,
				not sure why in the first case it's getting more child rows than the batchsize would
				allow...), but actual execution time was significantly faster (e.g ~.7s for 40k child
				rows)

				After changing this to a STRAIGHT_JOIN, restoring the pre-upgrade DB & rerunning,
				500a29::step_20() took about 3minutes 10seconds for 491 iterations, average 0.39s
				per iteration...

				Note that this query isn't complete, as it only sets the lastcontentid and NOT the lastcontent,
				meaning it's only grabbing the max child.nodeid rather than the child.nodeid with the max
				lastcontent, and because nowadays the lastcontent logic is a bit more complex (e.g. checking
				child's showpublished, showapproved, inlist). But in the spirit of strictly is it better, we
				believe that this change is better even if incomplete in the final sense.
			 */
			'query_string' => '
				UPDATE
					{TABLE_PREFIX}node AS child
					STRAIGHT_JOIN {TABLE_PREFIX}node AS parent
						ON child.parentid = parent.nodeid
				SET parent.lastcontentid = CASE WHEN child.lastcontent >= parent.lastcontent THEN child.lastcontentid ELSE parent.lastcontentid END
				WHERE parent.contenttypeid = {channeltypeid}
					AND child.nodeid > {startat} AND child.nodeid < ({startat} + {batchsize} + 1)
			'
		),
		'updateCategoryLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS parent
					INNER JOIN {TABLE_PREFIX}node AS child ON child.parentid = parent.nodeid AND child.contenttypeid = {channeltypeid}
				SET parent.lastcontentid = CASE WHEN child.lastcontent >= parent.lastcontent THEN child.lastcontentid ELSE parent.lastcontentid END
				WHERE parent.contenttypeid = {channeltypeid}
			'
		),
		'updateModeratorPermission' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}permission AS p
 			INNER JOIN {TABLE_PREFIX}usergroup AS ug ON ug.usergroupid = p.groupid
			SET p.moderatorpermissions = p.moderatorpermissions | {modPermissions} WHERE ug.systemgroupid IN ({systemgroups}) AND p.forumpermissions > 0'),
		'hidePasswordForums' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}permission
				(groupid, nodeid, forumpermissions,
				moderatorpermissions, createpermissions, edit_time,
				skip_moderate, maxtags, maxstartertags,
				maxothertags, maxattachments)
			SELECT pwd.usergroupid, node.nodeid, 0,
				1, 0, 5,
				0, 0, 0,
				0, 0
			FROM (SELECT ug.usergroupid, f.forumid
			FROM {TABLE_PREFIX}forum AS f, {TABLE_PREFIX}usergroup AS ug
			WHERE f.password IS NOT NULL AND f.password <> \'\') AS pwd
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = pwd.forumid AND node.oldcontenttypeid = {forumTypeid}
			LEFT JOIN {TABLE_PREFIX}permission AS ex ON ex.nodeid = node.nodeid AND ex.groupid = pwd.usergroupid
			WHERE ex.nodeid IS NULL'),
		'setForumPermissions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}permission
					(groupid, nodeid, forumpermissions, moderatorpermissions,
					createpermissions,

					edit_time,
					skip_moderate,

					maxtags,
					maxstartertags,

					maxothertags,
					maxattachments)
				SELECT
					fp.usergroupid, node.nodeid, fp.forumpermissions, 0,
					CASE WHEN (fp.forumpermissions & 16 > 0)
					THEN ( 2 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536 | 131072 | 262144) ELSE 0 END AS createpermissions,

					CASE WHEN p.nodeid IS NULL THEN {editTime} ELSE p.edit_time END,
					CASE WHEN p.nodeid IS NULL THEN 1 ELSE p.skip_moderate END,

					CASE WHEN p.nodeid IS NULL THEN {maxtags} ELSE p.maxtags END,
					CASE WHEN p.nodeid IS NULL THEN {maxstartertags} ELSE p.maxstartertags END,

					CASE WHEN p.nodeid IS NULL THEN {maxothertags} ELSE p.maxothertags END,
					CASE WHEN p.nodeid IS NULL THEN {maxattachments} ELSE p.maxattachments END
				FROM {TABLE_PREFIX}forumpermission AS fp
				INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = fp.forumid AND node.oldcontenttypeid = {forumTypeid}
				LEFT JOIN {TABLE_PREFIX}permission AS p ON p.groupid = fp.usergroupid AND p.nodeid = 1
				LEFT JOIN {TABLE_PREFIX}permission AS ex ON ex.nodeid = node.nodeid AND ex.groupid = fp.usergroupid
				WHERE ex.nodeid IS NULL ORDER BY node.nodeid, fp.usergroupid'),
		'clearUserStyle'=> array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}user SET styleid = 0'),
		'missingClosureByType'=> array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT nodeid
			FROM {TABLE_PREFIX}node AS node
			LEFT JOIN {TABLE_PREFIX}closure AS closure ON closure.child = node.nodeid AND closure.depth = 0
			WHERE closure.parent IS NULL AND oldcontenttypeid = {oldcontenttypeid} LIMIT {batchsize} '),
		'addClosureSelfForNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT node.nodeid, node.nodeid, 0
			FROM {TABLE_PREFIX}node AS node
			WHERE node.nodeid IN ({nodeid})'),
		'addClosureParentsForNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT parent.parent, node.nodeid, parent.depth + 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			WHERE node.nodeid IN ({nodeid})'),
		'updateBlogModerated' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'update {TABLE_PREFIX}node AS node INNER JOIN {TABLE_PREFIX}blog_text AS bt
			ON bt.blogtextid = node.oldid AND node.oldcontenttypeid = 9984
			SET node.showpublished = 0, node.showapproved = 0, node.publishdate = 0
			WHERE bt.state <> \'visible\''),
		'updateBlogCounts' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'update {TABLE_PREFIX}node AS node INNER JOIN
			(
			 select parentid, count(*) AS count, sum(showpublished) AS textcount
			 FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = 9984
			 GROUP BY parentid
			) as ch ON ch.parentid = node.nodeid
			SET node.textcount = ch.textcount,node.totalcount = ch.textcount,
			node.textunpubcount = (ch.count - ch.textcount),node.totalunpubcount = (ch.count - ch.textcount)'),
		'getMaxImportedSubscription' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid
			FROM {TABLE_PREFIX}subscribediscussion
			WHERE oldtypeid = {oldtypeid}'),
		'getMaxGroupDiscussionSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(sd.subscribediscussionid) AS maxid
			FROM {TABLE_PREFIX}subscribediscussion AS sd
			INNER JOIN {TABLE_PREFIX}discussion AS d ON sd.discussionid = d.discussionid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussiontypeid}
			WHERE sd.oldtypeid = 0'),
		'importDiscussionSubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}subscribediscussion(userid, discussionid, emailupdate, oldid, oldtypeid)
			SELECT sd.userid, n.nodeid, sd.emailupdate, sd.subscribediscussionid, {discussiontypeid}
			FROM {TABLE_PREFIX}subscribediscussion AS sd
			INNER JOIN {TABLE_PREFIX}discussion AS d ON sd.discussionid = d.discussionid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussiontypeid}
			WHERE sd.oldtypeid = 0 AND sd.subscribediscussionid > {startat} AND sd.subscribediscussionid < ({startat} + {batchsize} + 1)"
		),
		'getMaxForumSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(sf.subscribeforumid) AS maxid
			FROM {TABLE_PREFIX}subscribeforum AS sf
			INNER JOIN {TABLE_PREFIX}forum AS f ON f.forumid = sf.forumid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = f.forumid AND n.oldcontenttypeid = {forumtypeid}'),
		'importForumSubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}subscribediscussion(userid, discussionid, emailupdate, oldid, oldtypeid)
			SELECT sf.userid, n.nodeid, sf.emailupdate, sf.subscribeforumid, {forumtypeid}
			FROM {TABLE_PREFIX}subscribeforum AS sf
			INNER JOIN {TABLE_PREFIX}forum AS f ON sf.forumid = f.forumid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = f.forumid AND n.oldcontenttypeid = {forumtypeid}
			WHERE sf.subscribeforumid > {startat} AND sf.subscribeforumid < ({startat} + {batchsize} + 1)"
		),
		'getMaxThreadSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(st.subscribethreadid) AS maxid
			FROM {TABLE_PREFIX}subscribethread AS st
			INNER JOIN {TABLE_PREFIX}thread AS th ON th.threadid = st.threadid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = th.threadid AND n.oldcontenttypeid = {threadtypeid}'),
		'importThreadSubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}subscribediscussion(userid, discussionid, emailupdate, oldid, oldtypeid)
			SELECT st.userid, n.nodeid, st.emailupdate, st.subscribethreadid, {threadtypeid}
			FROM {TABLE_PREFIX}subscribethread AS st
			INNER JOIN {TABLE_PREFIX}thread AS th ON th.threadid = st.threadid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = th.threadid AND n.oldcontenttypeid = {threadtypeid}
			WHERE st.subscribethreadid > {startat} AND st.subscribethreadid < ({startat} + {batchsize} + 1)"
		),
		'getMaxGroupSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(sg.subscribegroupid) AS maxid
			FROM {TABLE_PREFIX}subscribegroup AS sg
			INNER JOIN {TABLE_PREFIX}socialgroup AS gr ON gr.groupid = sg.groupid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gr.groupid AND n.oldcontenttypeid = {grouptypeid}'),
		'importGroupSubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}subscribediscussion(userid, discussionid, emailupdate, oldid, oldtypeid)
			SELECT sg.userid, n.nodeid, (CASE sg.emailupdate
				WHEN 'none' THEN 0
				WHEN 'daily' THEN  2
				WHEN 'weekly' THEN 3 END) AS emailupdate, sg.subscribegroupid, {grouptypeid}
			FROM {TABLE_PREFIX}subscribegroup AS sg
			INNER JOIN {TABLE_PREFIX}socialgroup AS gr ON sg.groupid = gr.groupid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = gr.groupid AND n.oldcontenttypeid = {grouptypeid}
			WHERE sg.subscribegroupid > {startat} AND sg.subscribegroupid < ({startat} + {batchsize} + 1)"
		),
		'deleteGroupSubscribedDiscussion' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "DELETE sd.*
			FROM {TABLE_PREFIX}subscribediscussion AS sd
			INNER JOIN {TABLE_PREFIX}discussion AS d ON sd.discussionid = d.discussionid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = d.discussionid AND n.oldcontenttypeid = {discussiontypeid}
			WHERE sd.oldtypeid = 0"
		),
		'getNextBlogUserid' =>  array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT min(userid) AS userid FROM {TABLE_PREFIX}blog WHERE userid > {startat}'),
		'getMissedBlogStarters' =>  array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT bt.blogtextid, parent.nodeid, parent.routeid
			FROM {TABLE_PREFIX}blog AS blog
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = blog.firstblogtextid
			INNER JOIN {TABLE_PREFIX}node AS parent ON parent.userid = blog.userid
				AND parent.oldcontenttypeid = 9999
			LEFT JOIN {TABLE_PREFIX}node AS existing ON existing.oldid = bt.blogtextid AND existing.oldcontenttypeid = 9985
			WHERE blog.userid = {userid} AND existing.nodeid IS NULL'),
		'importMissingBlogStarters' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, title, htmltitle,
			publishdate, userid, authorname, oldid, oldcontenttypeid,
			showpublished, inlist, routeid, showapproved, textcount,
			totalcount, textunpubcount, totalunpubcount, lastcontent, lastcontentauthor,
			lastauthorid, created)
			SELECT {texttype}, {parentid}, bt.title, bt.title,
			case WHEN bt.state = \'visible\' THEN bt.dateline else 0 end, blog.userid, blog.username, bt.blogtextid, 9985,
			case WHEN bt.state = \'visible\' THEN 1 else 0 end, case WHEN bt.state = \'visible\' THEN 1 else 0 end,
			{routeid}, 1, blog.comments_visible,
			blog.comments_visible, blog.comments_moderation, blog.comments_moderation, blog.lastcomment, blog.lastcommenter,
			bt.username, bt.dateline
			FROM {TABLE_PREFIX}blog AS blog
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = blog.firstblogtextid
			LEFT JOIN {TABLE_PREFIX}blog_text AS last ON last.blogtextid = blog.lastblogtextid
			WHERE bt.blogtextid IN ({blogtextids})'),
		'fixMissingBlogStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node
			SET starter = nodeid WHERE oldcontenttypeid = 9985 AND nodeid > {startnodeid}'),
		'importMissingBlogText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext, htmlstate)
			SELECT n.nodeid, bt.pagetext, htmlstate
			FROM {TABLE_PREFIX}node AS n INNER JOIN {TABLE_PREFIX}blog_text AS bt
			ON bt.blogtextid = n.oldid AND n.oldcontenttypeid in (9984, 9985)
			WHERE n.nodeid > {startnodeid}'),
		'createMissingBlogClosureSelf' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure(parent, child, depth, publishdate)
			SELECT node.nodeid, node.nodeid, 0, node.publishdate FROM {TABLE_PREFIX}node AS node
			WHERE node.nodeid > {startnodeid}'),
		'createMissingBlogClosurefromParent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure(parent, child, depth, publishdate)
			SELECT parent.parent, node.nodeid, parent.depth + 1, node.publishdate FROM {TABLE_PREFIX}node AS node
 			 INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			LEFT JOIN {TABLE_PREFIX}closure AS existing on existing.child = node.nodeid AND existing.parent = parent.parent
			WHERE node.nodeid > {startnodeid} AND node.oldcontenttypeid = {oldcontenttypeid}'),
		'importMissingBlogResponses' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, starter, title, htmltitle,
			publishdate, userid, authorname, oldid, oldcontenttypeid, showpublished, showapproved, inlist, routeid, created)
			SELECT DISTINCT {texttype}, starter.nodeid, starter.nodeid,
			CASE WHEN IFNULL(bt.title, \'\') = \'\' THEN starter.title ELSE bt.title END,
			CASE WHEN IFNULL(bt.title, \'\') = \'\'THEN starter.title ELSE bt.title END,
			case WHEN bt.state = \'visible\' THEN bt.dateline else 0 end, bt.userid, bt.username, bt.blogtextid, 9984,
			case WHEN bt.state = \'visible\' THEN 1 else 0 end, case WHEN bt.state = \'visible\' THEN 1 else 0 end,
			1, starter.routeid, bt.dateline
			FROM {TABLE_PREFIX}blog_text AS firstbt
			INNER JOIN {TABLE_PREFIX}blog AS blog ON blog.blogid = firstbt.blogid
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogid = blog.blogid AND bt.blogtextid <> blog.firstblogtextid
			INNER JOIN {TABLE_PREFIX}node AS starter ON starter.oldid = blog.firstblogtextid AND starter.oldcontenttypeid = 9985
			WHERE firstbt.blogtextid  IN ({blogtextids})'),
		'fixBlogStarterLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS parent
			INNER JOIN {TABLE_PREFIX}blog AS blog ON blog.firstblogtextid = parent.oldid AND parent.oldcontenttypeid = 9985
			LEFT JOIN {TABLE_PREFIX}node AS node ON node.oldid = blog.lastblogtextid AND node.oldcontenttypeid = 9984
			SET parent.lastcontent = blog.lastcomment,
			parent.textcount = blog.comments_visible,
			parent.totalcount = blog.comments_visible,
			parent.textunpubcount = blog.comments_moderation,
			parent.totalunpubcount = blog.comments_moderation,
			parent.lastauthorid = CASE WHEN node.userid IS NULL THEN parent.userid ELSE node.userid END,
			parent.lastcontentauthor = blog.lastcommenter,
			parent.lastcontentid =  CASE WHEN node.nodeid IS NULL THEN parent.nodeid ELSE node.nodeid END'),
		'fixBlogChannelCount' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS blog INNER JOIN
			(SELECT parentid, max(publishdate) AS lastdate,
			sum(totalcount) AS totalcount,
			sum(totalunpubcount) AS totalunpubcount,
			sum(showpublished) AS published,
			count(nodeid) AS total
			FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = 9985 AND showpublished = 1  GROUP BY parentid)
			AS blogstarter ON blogstarter.parentid = blog.nodeid
			SET blog.lastcontent = blogstarter.lastdate,
			blog.totalcount = blogstarter.totalcount + blogstarter.published,
			blog.totalunpubcount = blogstarter.totalunpubcount  + blogstarter.total - blogstarter.published,
			blog.textcount = blogstarter.published,
			blog.textunpubcount = blogstarter.total - blogstarter.published'),
		'fixBlogChannelLast' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS blog INNER JOIN
			{TABLE_PREFIX}node AS starter ON starter.parentid = blog.nodeid AND starter.lastcontent = blog.lastcontent AND starter.showpublished = 1
			AND starter.oldcontenttypeid = 9985
			SET blog.lastauthorid = starter.lastauthorid,
			blog.lastcontentauthor = starter.lastcontentauthor,
			blog.lastcontentid = starter.lastcontentid'),
		'getMaxImportedBlogUserSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(bsu.blogsubscribeuserid) AS maxid
			FROM {TABLE_PREFIX}blog_subscribeuser AS bsu
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldcontenttypeid = 9999 AND n.userid = bsu.bloguserid AND n.contenttypeid = {channeltypeid}
			INNER JOIN {TABLE_PREFIX}groupintopic AS gt ON (gt.groupid = {membergroupid} AND gt.nodeid = n.nodeid AND gt.userid = bsu.userid)'),
		'getMaxBlogUserSubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(bsu.blogsubscribeuserid) AS maxid
			FROM {TABLE_PREFIX}blog_subscribeuser AS bsu
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldcontenttypeid = 9999 AND n.userid = bsu.bloguserid AND n.contenttypeid = {channeltypeid}'),
		'importBlogUserSubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}groupintopic(userid, groupid, nodeid)
			SELECT bsu.userid, {membergroupid}, n.nodeid
			FROM {TABLE_PREFIX}blog_subscribeuser AS bsu
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldcontenttypeid = 9999 AND n.userid = bsu.bloguserid AND n.contenttypeid = {channeltypeid}
			WHERE bsu.blogsubscribeuserid > {startat} AND bsu.blogsubscribeuserid < ({startat} + {batchsize} + 1)"
		),
		'getMaxBlogEntrySubscriptionId' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(bse.blogsubscribeentryid) AS maxid
			FROM {TABLE_PREFIX}blog_subscribeentry AS bse
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = bse.blogid AND n.oldcontenttypeid = 9985'),
		'importBlogEntrySubscriptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}subscribediscussion(userid, discussionid, emailupdate, oldid, oldtypeid)
			SELECT bse.userid, n.nodeid,
			(CASE bse.type
				WHEN 'usercp' THEN 0
				WHEN 'email' THEN  1
				END) as emailupdate, bse.blogsubscribeentryid, {blogentryid}
			FROM {TABLE_PREFIX}blog_subscribeentry AS bse
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = bse.blogid AND n.oldcontenttypeid = 9985
			WHERE bse.blogsubscribeentryid > {startat} AND bse.blogsubscribeentryid < ({startat} + {batchsize} + 1)"
		),
		'fixNodeRouteid' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}node AS starter ON node.starter = starter.nodeid AND node.contenttypeid <> {channelContenttypeid}
			INNER JOIN {TABLE_PREFIX}node AS channel ON channel.nodeid = starter.parentid
			INNER JOIN {TABLE_PREFIX}routenew AS route ON route.routeid = channel.routeid
			INNER JOIN {TABLE_PREFIX}routenew AS convRoute ON convRoute.prefix = route.prefix AND convRoute.class =\'vB5_Route_Conversation\'
			SET node.routeid = convRoute.routeid
			WHERE node.nodeid > {startat} AND node.nodeid < ({startat} + {batchsize} + 1)'),
		'setUgpAsDefault' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}usergroup
			SET systemgroupid = usergroupid
			WHERE (~genericoptions & {bf_value}) AND usergroupid = {ugpid}'),
		'setDefaultUsergroups' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}usergroup
			SET systemgroupid = usergroupid
			WHERE usergroupid <= 7'),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'alterSystemgroupidField' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'ALTER TABLE {TABLE_PREFIX}usergroup
			MODIFY COLUMN `systemgroupid` SMALLINT UNSIGNED NOT NULL DEFAULT 0'),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'getMaxvB5AlbumText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(n.oldid) AS maxid
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}gallery AS g ON n.nodeid = g.nodeid
			INNER JOIN {TABLE_PREFIX}text AS t ON t.nodeid = g.nodeid
			WHERE n.oldcontenttypeid = {albumtypeid}'),
		'getMaxvB4AlbumMissingText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(a.albumid) AS maxid
			FROM {TABLE_PREFIX}album AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.albumid
			LEFT JOIN {TABLE_PREFIX}text AS t ON t.nodeid = n.nodeid
			WHERE n.oldcontenttypeid = {albumtypeid} AND t.nodeid IS NULL'),
		'addMissingTextAlbumRecords' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, a.description
			FROM {TABLE_PREFIX}album AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON a.albumid = n.oldid
			LEFT JOIN {TABLE_PREFIX}text AS t ON t.nodeid = n.nodeid
			WHERE n.oldcontenttypeid = {albumtypeid} AND t.nodeid IS NULL
			AND a.albumid > {startat} AND a.albumid < ({startat} + {batchsize} + 1)"
		),
		'getMinvB5AlbumMissingStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT min(oldid) AS minid
			FROM {TABLE_PREFIX}node
			WHERE oldcontenttypeid = {albumtypeid} AND (nodeid <> starter)"
		),
		'updateModeratorNodeid' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}moderator AS m
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = m.forumid AND n.oldcontenttypeid = {forumtype}
			SET m.nodeid = n.nodeid'
		),
		'getMinCustomAvatarToFix' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT min(ca.userid) AS minid
			FROM {TABLE_PREFIX}customavatar AS ca
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = ca.userid
			WHERE ca.extension = ''"
		),
		'fixCustomAvatars' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}customavatar AS ca
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = ca.userid
			SET ca.filename = CONCAT('avatar', ca.userid, '_', u.avatarrevision, '.gif'), ca.extension = 'gif'
			WHERE ca.extension = '' AND ca.userid > {startat} AND ca.userid < ({startat} + {batchsize} + 1)"
		),
		'getMaxImportedBlogStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid	FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = 9985' ),
		'getMaxSGDiscussion' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(oldid) AS maxid	FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {discussionTypeid}' ),
		'updateRootChannelperm' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}permission AS p
			INNER JOIN {TABLE_PREFIX}usergroup AS ug ON ug.usergroupid = p.groupid AND p.nodeid = 1
			SET p.forumpermissions = p.forumpermissions |{bitmask} WHERE ug.forumpermissions & {bitmask} > 0;"
		),
		'importRedirectThreads' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}node(contenttypeid, parentid, routeid, title, htmltitle, userid, authorname,
				oldid, oldcontenttypeid, created,
				starter, inlist,
				publishdate,
			 	unpublishdate,
				showpublished,
				showopen,
				approved,
				showapproved,
				textcount, totalcount, textunpubcount, totalunpubcount, lastcontent,
				lastcontentauthor, lastauthorid, prefixid, iconid, sticky,
				deleteuserid, deletereason)
			SELECT {redirectTypeId}, node.nodeid, node.routeid, th.title, th.title, th.postuserid, th.postusername,
				th.threadid, 9980, th.dateline,
				1, 1,
				th.dateline,
				tr.expires,
				(CASE WHEN th.visible < 2 THEN 1 ELSE 0 END),
				th.open,
				(CASE th.visible WHEN 0 THEN 0 ELSE 1 END),
				(CASE th.visible WHEN 0 THEN 0 ELSE 1 END),
				th.replycount,th.replycount, th.hiddencount, th.hiddencount, th.lastpost,
				th.postuserid, th.postusername, th.prefixid, th.iconid, th.sticky,
				dl.userid, dl.reason
			FROM {TABLE_PREFIX}thread AS th
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = th.forumid AND node.oldcontenttypeid = {forumTypeId}
			LEFT JOIN {TABLE_PREFIX}node AS n ON n.oldid = th.threadid AND n.oldcontenttypeid = 9980
			LEFT JOIN {TABLE_PREFIX}threadredirect as tr ON tr.threadid = th.threadid
			LEFT JOIN {TABLE_PREFIX}deletionlog AS dl ON dl.primaryid = th.threadid AND dl.type = 'thread'
			WHERE th.open = 10 AND n.nodeid IS NULL
		"),
		'fetchRedirectThreads' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT nodeid, title, oldid
			FROM {TABLE_PREFIX}node
			WHERE oldcontenttypeid = 9980"
		),
		'updateNodeStarter' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node
			SET starter = nodeid
			WHERE oldcontenttypeid = {contenttypeid}"
		),
		'insertNodeClosure' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT node.nodeid, node.nodeid, 0
			FROM {TABLE_PREFIX}node AS node
			WHERE node.oldcontenttypeid = {contenttypeid}"
		),
		'insertNodeClosureRoot' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT parent.parent, node.nodeid, parent.depth + 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			WHERE node.oldcontenttypeid = {contenttypeid}"
		),
		'updateRedirectRoutes' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
			INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Conversation\'
			SET n.routeid = cr.routeid
			WHERE n.oldcontenttypeid = {contenttypeid}'
		),
		'insertRedirectRecords' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}redirect(nodeid, tonodeid)
			SELECT node.nodeid, redirectto.nodeid
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}thread AS th ON th.threadid = node.oldid
			INNER JOIN {TABLE_PREFIX}node AS redirectto ON redirectto.oldid = th.pollid AND redirectto.oldcontenttypeid = {contenttypeid}
			WHERE node.nodeid IN ({nodes})
		"),
		'removeSGSystemgroups' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "DELETE FROM {TABLE_PREFIX}usergroup WHERE systemgroupid IN (12, 13, 14)"
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'addMaxChannelsField' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'ALTER TABLE {TABLE_PREFIX}permission ADD COLUMN maxchannels SMALLINT(5) UNSIGNED NOT NULL DEFAULT 0 AFTER maxattachments'
		),
		'getRootChannels' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT n.nodeid, n.title, n.routeid, c.category, c.guid, r2.routeid, r2.class
				FROM {TABLE_PREFIX}channel AS c
				INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = c.nodeid
				LEFT JOIN {TABLE_PREFIX}routenew AS r1 ON r1.routeid = n.routeid
				LEFT JOIN {TABLE_PREFIX}routenew AS r2 ON r1.prefix = r2.prefix AND r2.class = 'vB5_Route_Conversation'
				WHERE c.guid IN ({rootGuids})"),
		'getTotalUsersWithFolders' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT COUNT(userid) AS totalusers
			FROM {TABLE_PREFIX}usertextfield WHERE pmfolders <> "";'),
		'getUsersWithFolders' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT userid, pmfolders
			FROM {TABLE_PREFIX}usertextfield WHERE pmfolders <> ""
			LIMIT {startat}, {batchsize}'),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'alterRouteRegexSize' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'ALTER TABLE {TABLE_PREFIX}routenew
			MODIFY COLUMN `regex` VARCHAR({regexSize}) NOT NULL'
		),
		'updateNonCustomConversationRoutes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}routenew
			SET regex = CONCAT(prefix, '/', {regex})
			WHERE class = 'vB5_Route_Conversation' AND (prefix != regex OR regex != CONCAT(prefix, '/', {regex}))"
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'fixStrikeIPFields' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'ALTER TABLE {TABLE_PREFIX}strikes
			MODIFY COLUMN ip_4 INT UNSIGNED NOT NULL DEFAULT 0,
			MODIFY COLUMN ip_3 INT UNSIGNED NOT NULL DEFAULT 0,
			MODIFY COLUMN ip_2 INT UNSIGNED NOT NULL DEFAULT 0,
			MODIFY COLUMN ip_1 INT UNSIGNED NOT NULL DEFAULT 0'
		),
		'500b28_updatePostHistory1' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}postedithistory AS p
				 INNER JOIN {TABLE_PREFIX}node AS n ON (p.postid = n.oldid AND n.oldcontenttypeid = {posttypeid} AND p.postid <> 0)
				 SET p.nodeid = n.nodeid'
		),
		'500b28_updatePostHistory2' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}postedithistory AS p
				 INNER JOIN {TABLE_PREFIX}thread_post AS tp ON (p.postid = tp.postid AND p.postid <> 0)
				 INNER JOIN {TABLE_PREFIX}node AS n ON (tp.threadid = n.oldid AND n.oldcontenttypeid = {threadtypeid})
				 SET p.nodeid = n.nodeid'
		),
		'500b28_updatePostHistory3' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => 'DELETE FROM {TABLE_PREFIX}postedithistory
				 WHERE nodeid = 0'
		),
		'500b28_updateFiledata1' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(filedataid) AS maxid FROM {TABLE_PREFIX}filedata"
		),
		'500b28_updateFiledata2' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(filedataid) AS maxid FROM {TABLE_PREFIX}filedataresize"
		),
		'500b28_updateFiledata3' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "REPLACE INTO {TABLE_PREFIX}filedataresize
				(filedataid, resize_type, resize_filedata, resize_filesize, resize_dateline, resize_width, resize_height, reload)
			SELECT filedataid, 'thumb', thumbnail, thumbnail_filesize, thumbnail_dateline, thumbnail_width, thumbnail_height, '1'
			FROM {TABLE_PREFIX}filedata AS fd
			WHERE fd.filedataid > {maxvB5} AND fd.filedataid < {process}
			ORDER BY fd.filedataid"
		),
		'501a2_updateSpamlog1' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}spamlog AS p
				 INNER JOIN {TABLE_PREFIX}node AS n ON (p.postid = n.oldid AND n.oldcontenttypeid = {posttypeid} AND p.postid <> 0)
				 SET p.nodeid = n.nodeid'
		),
		'501a2_updateSpamlog2' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}spamlog AS p
				 INNER JOIN {TABLE_PREFIX}thread_post AS tp ON (p.postid = tp.postid AND p.postid <> 0)
				 INNER JOIN {TABLE_PREFIX}node AS n ON (tp.threadid = n.oldid AND n.oldcontenttypeid = {threadtypeid})
				 SET p.nodeid = n.nodeid'
		),
		'501a2_updateSpamlog3' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => 'DELETE FROM {TABLE_PREFIX}spamlog
				 WHERE nodeid = 0'
		),
		'grantOwnerForumPerm' =>array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}permission AS perm
			INNER JOIN {TABLE_PREFIX}usergroup AS ug ON ug.usergroupid = perm.groupid
			SET perm.forumpermissions2 = perm.forumpermissions2 | {permission}
			WHERE ug.systemgroupid = {systemgroupid} AND moderatorpermissions > 0"
		),
		'updateAllTextHtmlStateDefault' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}text AS text
				SET text.htmlstate = 'off'
				WHERE (text.htmlstate = '' OR text.htmlstate IS NULL) AND
					text.nodeid > {startat} and text.nodeid < ({startat} + {batchsize} + 1)"
		),
		'updateAllowHtmlChannelOption' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}channel AS channel
			INNER JOIN {TABLE_PREFIX}node AS node ON channel.nodeid = node.nodeid
			SET channel.options = channel.options | {allowhtmlpermission}
			WHERE !(channel.options & {allowhtmlpermission})"
		),
		//normally an OR is a red flag, but in this case the primary filter is going to be on
		//the nodeid range so the fields involved in the OR clause wouldn't be part of an
		//index scan in any event.  This allows us to combine two queries into one scan of the
		//index/batched walk through and should make things considerably faster
		'updateImportedForumPostHtmlState' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}text AS text
					INNER JOIN {TABLE_PREFIX}node AS node USE INDEX (nodeid) ON text.nodeid = node.nodeid
					INNER JOIN {TABLE_PREFIX}node AS starter ON starter.nodeid = node.starter
					INNER JOIN {TABLE_PREFIX}channel AS channel ON channel.nodeid = starter.parentid
				SET text.htmlstate = 'off'
				WHERE ((text.htmlstate = '' OR text.htmlstate IS NULL) OR (!(channel.options & {allowhtmlpermission}) AND node.oldcontenttypeid IN ({oldcontenttypeids})))
					AND text.nodeid > {startat} AND text.nodeid < ({startat} + {batchsize} + 1)
			"
		),
		'updateStarterPostHtmlState' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}text AS text
					INNER JOIN {TABLE_PREFIX}node AS node USE INDEX (nodeid) ON text.nodeid = node.nodeid
					INNER JOIN {TABLE_PREFIX}thread_post AS thread_post ON thread_post.nodeid = text.nodeid
					INNER JOIN {TABLE_PREFIX}post AS post ON post.postid = thread_post.postid
				SET text.htmlstate = post.htmlstate
				WHERE thread_post.threadid >= {startat} AND thread_post.threadid < {nextthreadid} AND text.htmlstate IS NULL
			"
		),
		'updateImportedBlogPostHtmlState' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}text AS text
			INNER JOIN {TABLE_PREFIX}node AS node USE INDEX (nodeid) ON text.nodeid = node.nodeid
			SET text.htmlstate = 'off'
			WHERE node.oldcontenttypeid in ({oldcontenttypeids})
				AND text.nodeid > {startat} AND text.nodeid < ({startat} + {batchsize} + 1)"
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'alterChannelOptions' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'ALTER TABLE {TABLE_PREFIX}channel MODIFY COLUMN `options` INT(10) UNSIGNED NOT NULL DEFAULT 1984'
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'alterTextHtmlstate' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}text MODIFY COLUMN `htmlstate` ENUM('off', 'on', 'on_nl2br') NOT NULL DEFAULT 'off'"
		),
		'500rc1_checkDuplicateRequests' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT p.aboutid
				FROM {TABLE_PREFIX}sentto AS s
				INNER JOIN {TABLE_PREFIX}node AS n ON (n.nodeid = s.nodeid)
				INNER JOIN {TABLE_PREFIX}privatemessage AS p ON (n.nodeid = p.nodeid)
				WHERE
					s.userid = {userid}
					AND
					s.folderid = {folderid}
					AND
					s.deleted = 0
					AND
					p.aboutid = {aboutid}
					AND
					p.about = {about}
			'
		),
		'fixRedirectContentTypeId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS node
				SET node.contenttypeid = {redirectContentTypeId}
				WHERE node.oldcontenttypeid = {redirectOldContentTypeId} AND node.contenttypeid = 0
					AND node.oldid >= {startat} and node.oldid < {nextoldid}"
		),
		'fixFperms2' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}permission SET
			forumpermissions2 = forumpermissions2 | IF(forumpermissions & {oldp1} = {oldp1}, {newp1}, 0),
			forumpermissions2 = forumpermissions2 | IF(forumpermissions & {oldp2} = {oldp2}, {newp2}, 0),
			forumpermissions2 = forumpermissions2 | IF(forumpermissions & {oldp3} = {oldp3}, {newp3}, 0)"
		),
		'getMaxBlogUserIdToFix' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(bu.bloguserid) AS maxid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid} AND (bu.title <> \'\' AND bu.title <> n.title)
			'
		),
		'getMaxFixedBlogUserId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(bu.bloguserid) AS maxid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid} AND (bu.title <> \'\' AND bu.title = n.title)
			'
		),
		'getBlogsUserToFix' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT n.nodeid, bu.bloguserid, bu.title, bu.description
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid} AND (bu.title <> \'\' AND bu.title <> n.title)
				AND bu.bloguserid > {startat} AND bu.bloguserid <= ({startat} + {batchsize})
				ORDER BY bu.bloguserid
			'
		),
		'getMaxBlogUserIdToFixOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(bu.bloguserid) AS maxid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid}
				AND
				(
					(n.nodeoptions = 138 AND (bu.options <> 6 OR bu.allowsmilie <> 1))
					OR
					(
					    n.viewperms = 2 AND
					    ( ~bu.options_member & 1 OR ~bu.options_guest & 1 )
					)
					OR
					(
					    n.commentperms = 1 AND
					    (~bu.options_member & 2)
					)
				)
			'
		),
		'getMaxOptionsFixedBlogUserId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(bu.bloguserid) AS maxid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid}
				AND
				(
					(n.nodeoptions <> 138 OR n.commentperms <> 1 OR n.viewperms <> 2)
					OR
					(
						(n.nodeoptions = 138 AND (bu.options = 6 OR bu.allowsmilie = 1))
						AND
						(
						    n.viewperms = 2 AND
						    (bu.options_member & 1 OR bu.options_guest & 1)
						)
						AND
						(
						    n.commentperms = 1 AND
						    (bu.options_member & 2)
						)
					)
				)
			'
		),
		'getBlogsUserToFixOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT n.nodeid, bu.bloguserid, bu.title, bu.description, bu.options_member, bu.options_guest,
				bu.allowsmilie, bu.options, n.commentperms, n.viewperms, n.nodeoptions
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON bu.bloguserid = n.userid
				WHERE n.oldcontenttypeid = {contenttypeid}
				AND
				(
					(n.nodeoptions = 138 AND (bu.options <> 6 OR bu.allowsmilie <> 1))
					OR
					(
					    n.viewperms = 2 AND
					    ( ~bu.options_member & 1 OR ~bu.options_guest & 1 )
					)
					OR
					(
					    n.commentperms = 1 AND
					    (~bu.options_member & 2)
					)
				)
				AND bu.bloguserid > {startat} AND bu.bloguserid <= ({startat} + {batchsize})
				ORDER BY bu.bloguserid
			'
		),
		'setCanAlwaysPerms' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}permission p
				INNER JOIN {TABLE_PREFIX}usergroup ugp ON ugp.usergroupid = p.groupid
				SET p.forumpermissions2 = p.forumpermissions2 | 1 | 2 | 4 | 128
				WHERE ugp.systemgroupid IN ({groupids})
			'
		),
		'getUsergroupsWithAllowHtml' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT usergroupid, vbblog_entry_permissions, vbblog_comment_permissions
			FROM {TABLE_PREFIX}usergroup AS ug
			WHERE (vbblog_entry_permissions & {blog_entry_bitfield}) OR (vbblog_comment_permissions & {blog_comment_bitfield})
			"
		),
		'importBlogEntryHtmlState' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}text AS text
			INNER JOIN {TABLE_PREFIX}node AS node ON text.nodeid = node.nodeid
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = node.oldid
			SET text.htmlstate = bt.htmlstate
			WHERE node.oldcontenttypeid in ({oldcontenttypeids})
				AND bt.userid IN ({usersWithAllowHTML})
				AND text.nodeid > {startat} AND text.nodeid < ({startat} + {batchsize} + 1)"
		),
		'importBlogCommentHtmlState' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}text AS text
			INNER JOIN {TABLE_PREFIX}node AS node ON text.nodeid = node.nodeid
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = node.oldid
			SET text.htmlstate = bt.htmlstate
			WHERE node.oldcontenttypeid in ({oldcontenttypeids})
				AND bt.userid IN ({usersWithAllowHTML})
				AND text.nodeid > {startat} AND text.nodeid < ({startat} + {batchsize} + 1)"
		),
		'getMaxBlogMemberToImport' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(n.nodeid) AS maxnodeid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON n.userid = bu.bloguserid
				INNER JOIN {TABLE_PREFIX}blog_groupmembership bg ON bg.bloguserid = bu.bloguserid
				LEFT JOIN {TABLE_PREFIX}groupintopic git ON git.nodeid = n.nodeid AND git.userid = bg.userid
				WHERE n.oldcontenttypeid = {contenttypeid} AND bg.state = \'active\' AND git.nodeid IS NULL
			'
		),
		'importBlogMembers' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				INSERT INTO {TABLE_PREFIX}groupintopic(groupid, nodeid, userid)
				SELECT {groupid}, n.nodeid, bg.userid
				FROM {TABLE_PREFIX}node n
				INNER JOIN {TABLE_PREFIX}blog_user bu ON n.userid = bu.bloguserid
				INNER JOIN {TABLE_PREFIX}blog_groupmembership bg ON bg.bloguserid = bu.bloguserid
				LEFT JOIN {TABLE_PREFIX}groupintopic git ON git.nodeid = n.nodeid AND git.userid = bg.userid
				WHERE n.oldcontenttypeid = {contenttypeid} AND bg.state = \'active\' AND git.nodeid IS NULL
				LIMIT {batchsize}
			'
		),
		'getMaxPmStarterToCreate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT max(node.nodeid) AS maxid
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}node AS reply ON reply.parentid = node.nodeid
			INNER JOIN {TABLE_PREFIX}sentto AS s ON s.nodeid = reply.nodeid
			INNER JOIN {TABLE_PREFIX}messagefolder AS folder ON folder.userid = node.userid AND folder.folderid = s.folderid
			LEFT JOIN {TABLE_PREFIX}sentto AS existing ON existing.nodeid = node.nodeid AND
			        existing.userid = node.userid AND existing.folderid = folder.folderid
			WHERE existing.nodeid IS NULL
			AND node.contenttypeid = {pmtypeid} AND reply.oldcontenttypeid = {contenttypeid}"
		),
		'createStarterPmRecords' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}sentto (nodeid, userid, folderid, msgread)
			SELECT DISTINCT node.nodeid, node.userid, folder.folderid, 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}node AS reply ON reply.parentid = node.nodeid
			INNER JOIN {TABLE_PREFIX}sentto AS s ON s.nodeid = reply.nodeid
			INNER JOIN {TABLE_PREFIX}messagefolder AS folder ON folder.userid = node.userid AND folder.folderid = s.folderid
			LEFT JOIN {TABLE_PREFIX}sentto AS existing ON existing.nodeid = node.nodeid AND
			        existing.userid = node.userid AND existing.folderid = folder.folderid
			WHERE existing.nodeid IS NULL
			AND node.contenttypeid = {pmtypeid} AND reply.oldcontenttypeid = {contenttypeid}
			LIMIT {batchsize}"
		),
		'getPagetemplateidByTitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT pagetemplateid
				FROM {TABLE_PREFIX}pagetemplate AS pt
				WHERE title = {templatetitle}
			'
		),
		'getMaxPageidForOldSocialGroups' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(pageid) AS maxid
				FROM {TABLE_PREFIX}page AS page
				WHERE page.routeid IN (
						SELECT routeid FROM {TABLE_PREFIX}node AS node WHERE node.oldcontenttypeid in ({oldcontenttypeid})
				)
			'
		),
		'updateImportedGroupsPagetemplateid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}page AS page
				SET page.pagetemplateid = {changeto}
				WHERE page.pagetemplateid = {changefrom}
					AND page.routeid IN (
						SELECT routeid FROM {TABLE_PREFIX}node AS node WHERE node.oldcontenttypeid in ({oldcontenttypeid})
					)
					AND page.pageid > {startat} AND page.pageid < ({startat} + {batchsize} + 1)"
		),
		'moveMsnInfo' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}user
			SET skype = msn, msn = ''
			WHERE skype = '' OR skype = msn
			LIMIT {batchsize}"
		),
		'getTotalPendingFriends' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT COUNT(userid) AS totalusers
			FROM {TABLE_PREFIX}userlist AS ul WHERE ul.type = 'follow' AND ul.friend = 'pending'"
		),
		'getCurrentPendingRequest' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT pm.nodeid
				FROM {TABLE_PREFIX}privatemessage AS pm
				INNER JOIN {TABLE_PREFIX}sentto AS sentto On (pm.nodeid = sentto.nodeid AND userid = {relationid})
				WHERE pm.msgtype = 'request' AND pm.about = 'follow' AND pm.aboutid = {userid}"
		),
		// Joins on user ensure that the users still exist
		'convertPendingFriends' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT ul.*, ul2.userid AS ignored
				FROM {TABLE_PREFIX}userlist AS ul
				LEFT JOIN {TABLE_PREFIX}userlist AS ul2 ON (ul.userid = ul2.relationid AND ul.relationid = ul2.userid AND ul2.type = 'ignore' AND ul2.friend = 'denied')
				INNER JOIN {TABLE_PREFIX}user AS user1 ON (user1.userid = ul.userid)
				INNER JOIN {TABLE_PREFIX}user AS user2 ON (user2.userid = ul.relationid)
				WHERE ul.type = 'follow' AND ul.friend = 'pending'
				ORDER BY ul.userid, ul.relationid
				LIMIT {startat}, {batchsize}"
		),
		'convertFriends' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}userlist
			SET type = 'follow'
			WHERE type = 'buddy'"
		),
		'getMaxInfractedNodeWrong' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			WHERE i.infractednodeid > 0'
		),
		'getMaxFixedInfractedNodeWrong' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			WHERE i.infractednodeid = 0'
		),
		'fixInfractedNodeWrong' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}infraction AS i SET i.infractednodeid = 0
			WHERE i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'importThreadsInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}thread_post AS tp on i.postid = tp.postid
			INNER JOIN {TABLE_PREFIX}node AS n ON tp.threadid = n.oldid
			SET i.infractednodeid = tp.nodeid WHERE
			n.oldcontenttypeid = {threadTypeId} AND
			i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getMaxThreadNodeidForInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}thread_post tp ON i.postid = tp.postid
			INNER JOIN {TABLE_PREFIX}node n ON tp.threadid = n.oldid
			WHERE n.oldcontenttypeid = {threadTypeId}'
		),
		'getMaxThreadNodeidFixedForInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}thread_post tp ON i.postid = tp.postid
			INNER JOIN {TABLE_PREFIX}node n ON tp.threadid = n.oldid
			WHERE i.infractednodeid != 0 AND n.oldcontenttypeid = {threadTypeId}'
		),
		'importPostInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node n ON n.oldid = i.postid
			SET i.infractednodeid = n.nodeid WHERE
			n.oldcontenttypeid = {postTypeId} AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getMaxPostNodeidForInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node n ON n.oldid = i.postid
			WHERE n.oldcontenttypeid = {postTypeId}'
		),
		'getMaxPostNodeidFixedForInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN node n ON n.oldid = i.postid
			WHERE i.infractednodeid != 0 AND n.oldcontenttypeid = {postTypeId}'
		),
		'importThreadNodesToInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
			INNER JOIN {TABLE_PREFIX}thread_post AS t ON t.postid = i.postid
			SET n.contenttypeid = \'{infractionTypeId}\',
			n.oldid = i.infractionid, n.oldcontenttypeid = {oldInfractionTypeId}
			WHERE i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1) AND n.oldcontenttypeid = {oldTypeId}'
		),
		'getNodeIdsToMove' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT n.nodeid FROM {TABLE_PREFIX}node AS n
			WHERE n.oldcontenttypeid = {oldTypeId} AND n.nodeid > {startat}
			AND n.nodeid < ({startat} + {batchsize} + 1)'
		),
		'getMaxThreadNodeidForInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
			INNER JOIN {TABLE_PREFIX}thread_post AS t ON t.postid = i.postid
			WHERE n.oldcontenttypeid = {oldTypeId}'
		),
		'getMaxThreadNodeidFixedForInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
			INNER JOIN {TABLE_PREFIX}thread_post AS t ON t.postid = i.postid
			WHERE n.parentid = {infractionChannel} AND n.oldcontenttypeid = {oldTypeId}'
		),
		'importPostNodesToInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS n
					INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
				SET n.contenttypeid = {infractionTypeId},
					n.oldid = i.infractionid, n.oldcontenttypeid = {oldInfractionTypeId}
				WHERE i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1) AND n.oldcontenttypeid = {oldTypeId}
			"
		),
		'getMaxPostNodeidForInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
			WHERE n.oldcontenttypeid = {oldTypeId}'
		),
		'getMaxPostNodeidFixedForInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.oldid = i.threadid
			WHERE n.parentid = {infractionChannel} AND n.oldcontenttypeid = {oldTypeId}'
		),
		'addNodesForOrphanInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, oldid, oldcontenttypeid, parentid, publishdate, created,userid,authorname, showpublished)
			SELECT {infractionTypeId}, i.infractionid, {oldInfractionTypeId}, {infractionChannelId}, i.dateline, i.dateline,i.userid,u.username, 1
			FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}user AS u ON i.userid = u.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = i.infractednodeid
			WHERE n.oldcontenttypeid = {oldTypeId} AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)
			AND i.threadid = 0'
		),
		'getMaxOrphanInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = i.infractednodeid WHERE n.oldcontenttypeid = {oldTypeId}
			AND i.threadid = 0 AND i.nodeid = 0'
		),
		'getMaxFixedOrphanInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.nodeid = i.infractednodeid
			WHERE n.oldcontenttypeid = {oldTypeId} AND i.threadid = 0 AND i.nodeid = 0'
		),
		'addNodesForOrphanProfileInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(contenttypeid, oldid, oldcontenttypeid, parentid, publishdate, created,userid,authorname, showpublished)
			SELECT {infractionTypeId}, i.infractionid, {oldInfractionTypeId}, {infractionChannelId}, i.dateline, i.dateline,i.userid,u.username, 1
			FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}user AS u ON i.userid = u.userid
			WHERE i.postid = 0 AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getMaxOrphanProfileInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i WHERE i.postid=0 AND i.nodeid = 0'
		),
		'getMaxFixedOrphanProfileInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = i.infractionid
			WHERE n.oldcontenttypeid = {oldTypeId}'
		),
		'addNodeidIntoInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = i.infractionid AND n.oldcontenttypeid IN ({oldInfractionTypeId})
			AND n.contenttypeid = {infractionTypeId}
			SET i.nodeid = n.nodeid
			WHERE i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getMaxNodeidIntoInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = i.infractionid
			WHERE n.oldcontenttypeid IN ({oldInfractionTypeId})
			AND n.contenttypeid = {infractionTypeId} AND i.nodeid = 0'
		),
		'getMaxNodeidFixedIntoInfraction' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = i.infractionid
			WHERE n.oldcontenttypeid IN ({oldInfractionTypeId})
			AND n.contenttypeid = {infractionTypeId} AND i.nodeid != 0'
		),
		'getInfractedNodeTitles' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT n.title, n.routeid, i.infractionlevelid AS ilevelid, u.username AS iusername, u.userid AS iuserid,
			i.points AS ipoints, i.nodeid AS nodeid, i.infractednodeid AS infractednodeid, i.note AS note, t.rawtext AS irawtext
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.nodeid = i.infractednodeid
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = i.infracteduserid
			INNER JOIN {TABLE_PREFIX}text AS t ON t.nodeid = i.infractednodeid
			WHERE n.oldcontenttypeid = {oldTypeId} AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getInfractedForPostNodeTitles' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT s.title, n.routeid, i.infractionlevelid AS ilevelid, u.username AS iusername, u.userid AS iuserid,
			i.points AS ipoints, i.nodeid AS nodeid, i.infractednodeid AS infractednodeid, i.note AS note, t.rawtext AS irawtext
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.nodeid = i.infractednodeid
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = i.infracteduserid
			INNER JOIN {TABLE_PREFIX}node s ON n.starter = s.nodeid
			INNER JOIN {TABLE_PREFIX}text AS t ON t.nodeid = i.infractednodeid
			WHERE n.oldcontenttypeid = {oldTypeId} AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'getInfractedProfileInfo' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT i.infractionlevelid AS ilevelid, u.username AS iusername, u.userid AS iuserid,
			i.points AS ipoints, i.nodeid AS nodeid, i.infractednodeid AS infractednodeid, i.note AS note
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i ON n.nodeid = i.nodeid
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = i.infracteduserid
			WHERE i.infractednodeid = 0 AND i.postid=0 AND
			n.oldcontenttypeid = {oldTypeId} AND i.infractionid > {startat} AND i.infractionid < ({startat} + {batchsize} + 1)'
		),
		'setTitleForInfractionNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n SET n.title = {infractionNodeTitle}, urlident = {urlident}
			WHERE n.nodeid = {infractionNodeId}'
		),
		'setTextForInfractionNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}text(nodeid, rawtext) VALUES({nodeid}, {infractionText})'
		),
		'getMaxInfractionWithoutNodeTitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON i.nodeid = n.nodeid WHERE n.title IS NULL
			AND n.contenttypeid = {infractionTypeId} AND n.oldcontenttypeid IN ({oldTypeId})'
		),
		'getMaxInfractionFixedNodeTitle' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i
			INNER JOIN {TABLE_PREFIX}node AS n ON i.nodeid = n.nodeid WHERE n.title IS NOT NULL
			AND n.contenttypeid = {infractionTypeId} AND n.oldcontenttypeid IN ({oldTypeId})'
		),
		'totalStarters' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT COUNT(n.nodeid) AS totalCount FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}infraction AS i on i.nodeid = n.nodeid'
		),
		'setTextCountForInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET textcount = {textCount} WHERE nodeid={infractionNodeid}'
		),
		'setInfractionConversationRouteId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET routeid = {infractionRouteId} WHERE parentid = {infractionNodeId} AND routeid = 0'
		),
		'getUiForumId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT value FROM {TABLE_PREFIX}setting WHERE varname = \'uiforumid\''
		),
		'getInfractionChannelNodeId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT n.nodeid AS nodeid, c.guid AS guid FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}channel AS c ON c.nodeid = n.nodeid
			WHERE n.oldcontenttypeid = {oldForumTypeId} AND n.oldid = {forumId}'
		),
		'setGuidToInfractionChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n, {TABLE_PREFIX}channel AS ch SET ch.guid={guidInfraction}
			WHERE n.nodeid={infractionChannelId} AND n.nodeid = ch.nodeid'
		),
		'getMaxImportedAttachment' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(a.attachmentid) AS maxid
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}blog AS b ON a.contentid = b.blogid
			WHERE a.contenttypeid = {contentTypeId}'
		),
		'insertBlogAttachmentNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node (userid, authorname, contenttypeid, parentid, routeid, title, htmltitle,
				publishdate, oldid, oldcontenttypeid, created,
				starter, inlist, showpublished, showapproved, showopen)
			SELECT a.userid, u.username, {attachTypeId}, n.nodeid, n.routeid, \'\', \'\',
				a.dateline, a.attachmentid,	{oldContentTypeId}, a.dateline,
				n.starter, 0, 1, 1, 1
			FROM {TABLE_PREFIX}attachment AS a
				INNER JOIN {TABLE_PREFIX}blog_text AS bt ON a.contentid = bt.blogid
				INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = bt.blogtextid AND n.oldcontenttypeid = {blogStarterOldContentTypeId}
				LEFT JOIN {TABLE_PREFIX}user AS u ON a.userid = u.userid
			WHERE a.attachmentid > {startAt} AND a.attachmentid < ({startAt} + {batchSize}) AND a.contenttypeid = {blogEntryTypeId}
			ORDER BY a.attachmentid'
		),
		'insertBlogAttachments' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}attach
			(nodeid, filedataid, visible, counter, posthash, filename, caption, reportthreadid, settings)
				SELECT n.nodeid, a.filedataid,
				 CASE WHEN a.state = \'moderation\' then 0 else 1 end AS visible, a.counter, a.posthash, a.filename, a.caption, a.reportthreadid, a.settings
			FROM {TABLE_PREFIX}attachment AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.attachmentid AND n.oldcontenttypeid = {oldContentTypeId}
			WHERE a.attachmentid > {startAt}  AND a.attachmentid < ({startAt} + {batchSize}) AND a.contenttypeid = {blogEntryTypeId}'
		),
		'updateImportedBlogChannelOldid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}blog AS blog ON blog.blogid = node.oldid
			SET node.oldid = blog.userid, node.oldcontenttypeid = {oldcontenttypeid_new}
			WHERE node.oldcontenttypeid  = {oldcontenttypeid}
				AND node.nodeid > {startat} AND node.nodeid < ({startat} + {batchsize} + 1)"
		),
		'updateImportedBlogEntryOldid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.blogtextid = node.oldid
			SET node.oldid = bt.blogid, node.oldcontenttypeid = {oldcontenttypeid_new}
			WHERE node.oldcontenttypeid  = {oldcontenttypeid}
				AND node.nodeid > {startat} AND node.nodeid < ({startat} + {batchsize} + 1)"
		),
		'getMaxInfractionIdPDeleted' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(i.infractionid) AS maxid FROM {TABLE_PREFIX}infraction AS i WHERE i.nodeid = 0'
		),
		'removedPDeletedInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => 'DELETE FROM {TABLE_PREFIX}infraction WHERE nodeid = 0
				AND infractionid LIMIT {batchsize}'
		),
		'revertImportedBlogResponseOldid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}blog_text AS bt ON bt.dateline = node.created AND bt.blogid = node.oldid
			SET node.oldid = bt.blogtextid, node.oldcontenttypeid = {oldcontenttypeid_new}
			WHERE node.oldcontenttypeid  = {oldcontenttypeid}
				AND node.nodeid > {startat} AND node.nodeid < ({startat} + {batchsize} + 1)"
		),
		'getMissingAlbums' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT a.albumid FROM {TABLE_PREFIX}album AS a
				INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = a.userid
				LEFT JOIN {TABLE_PREFIX}node AS n ON n.oldid = a.albumid AND n.oldcontenttypeid = {oldcontenttypeid}
				WHERE nodeid IS NULL
				LIMIT {batchsize}'
		),
		'importMissingAlbumNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node
					(publishdate, title, userid, authorname,htmltitle,
					parentid, created, oldid, oldcontenttypeid,`open`,
					showopen, approved, showapproved, showpublished, protected,
					routeid, contenttypeid, deleteuserid, deletereason, sticky)
				SELECT al.createdate, al.title, al.userid, u.username, al.title,
					{albumChannel}, al.createdate, al.albumid, {oldcontenttypeid},1,
					1, 1, 1, 1, 0,
					{routeid}, {gallerytypeid}, 0, \'\', 0
				FROM {TABLE_PREFIX}album AS al INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = al.userid
				WHERE al.albumid IN ({albumIdList})'
		),
		'setStarterForImportedAlbums' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node
				SET starter = nodeid
				WHERE oldcontenttypeid = {oldcontenttypeid} AND oldid IN ({albumIdList})'
		),
		'addMissingTextAlbumRecords_502rc1' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT n.nodeid, a.description
			FROM {TABLE_PREFIX}album AS a
			INNER JOIN {TABLE_PREFIX}node AS n ON a.albumid = n.oldid
			LEFT JOIN {TABLE_PREFIX}text AS t ON t.nodeid = n.nodeid
			WHERE n.oldcontenttypeid = {oldcontenttypeid} AND t.nodeid IS NULL
			AND a.albumid IN ({albumIdList})"
		),
		'importMissingAlbums2Gallery' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}gallery(nodeid, caption)
				SELECT nodeid, title
				FROM {TABLE_PREFIX}node WHERE oldcontenttypeid = {oldcontenttypeid}
				AND oldid IN ({albumIdList})'
		),
		'getMissingPhotos' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT at.attachmentid FROM {TABLE_PREFIX}attachment AS at
				INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = at.userid
				INNER JOIN {TABLE_PREFIX}node AS albumnode ON albumnode.oldid = at.contentid AND albumnode.oldcontenttypeid = {albumtypeid}
				LEFT JOIN {TABLE_PREFIX}node AS n ON n.oldid = at.attachmentid AND n.oldcontenttypeid = {oldcontenttypeid}
				WHERE n.nodeid IS NULL AND at.contenttypeid = {albumtypeid}
				LIMIT {batchsize}'
		),
		'importMissingPhotoNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(publishdate, title, userid, authorname,htmltitle,
			parentid, starter, created, oldid, oldcontenttypeid,`open`,
			showopen, approved, showapproved, showpublished, protected,
			routeid, contenttypeid, deleteuserid, deletereason, sticky )
			SELECT at.dateline,CASE when at.caption IS NULL then at.filename ELSE at.caption END,
			at.userid, u.username,	CASE when at.caption IS NULL then at.filename ELSE at.caption END,
			n.nodeid AS parentid, n.nodeid AS starter, at.dateline, at.attachmentid, 9986, 1,
			1, 1, 1, 1, 0,
			n.routeid, {phototypeid}, 0, \'\', 0
			FROM {TABLE_PREFIX}attachment AS at
			INNER JOIN {TABLE_PREFIX}user AS u ON u.userid = at.userid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = at.contentid AND n.oldcontenttypeid = {albumtypeid} AND at.contenttypeid = {albumtypeid}
			WHERE at.attachmentid IN ({attachmentIdList})'
		),
		'importMissingPhotos2Photo' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}photo(nodeid, filedataid, caption, height, width)
			SELECT n.nodeid, at.filedataid, CASE when at.caption IS NULL then at.filename ELSE at.caption END,
				f.height, f.width
			FROM {TABLE_PREFIX}attachment AS at
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = at.attachmentid AND n.oldcontenttypeid = 9986
			INNER JOIN {TABLE_PREFIX}filedata AS f ON f.filedataid = at.filedataid
			WHERE n.oldid IN ({attachmentIdList})'
		),
		'getNoclosureNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT nodeid FROM {TABLE_PREFIX}node AS n
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.parent = cl.child AND cl.child = n.nodeid
				WHERE {startat} < n.nodeid AND n.nodeid < ({startat} + {batchsize} + 1) AND cl.child IS NULL'
		),
		'getOrphanNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT nodeid FROM {TABLE_PREFIX}node AS n
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.depth > 0 AND cl.child = n.nodeid
				WHERE {startat} < n.nodeid AND n.nodeid < ({startat} + {batchsize} + 1) AND cl.child IS NULL'
		),
		'addMissingClosureSelf' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
				SELECT node.nodeid, node.nodeid, 0
				FROM {TABLE_PREFIX}node AS node
				WHERE node.nodeid IN ({nodeIdList})'
		),
		'addMissingClosureParents' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
				SELECT parent.parent, node.nodeid, parent.depth + 1
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
				WHERE node.nodeid IN ({nodeIdList})'
		),
		'getMaxOldidMissingNodeStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT MAX(oldid) AS maxid
				FROM {TABLE_PREFIX}node
				WHERE oldcontenttypeid IN ({oldcontenttypeids})
					AND (starter <> nodeid OR lastcontentid <> nodeid)'
		),
		'setNodeStarter' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node SET starter = nodeid, lastcontentid = nodeid
				WHERE oldcontenttypeid IN ({oldcontenttypeids})
					AND (starter <> nodeid OR lastcontentid <> nodeid)
					AND oldid > {startat} AND oldid < ({startat} + {batchsize} + 1)'
		),
		'getMissingVM' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT vmid FROM {TABLE_PREFIX}visitormessage AS vm
				LEFT JOIN {TABLE_PREFIX}node AS node ON node.oldcontenttypeid = {vmtypeid} AND node.oldid = vm.vmid
				WHERE nodeid IS NULL
				LIMIT {batchsize}'
		),
		'ImportMissingVisitorMessages' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}node(userid, authorname, parentid, contenttypeid, title,
				description, deleteuserid, deletereason, sticky, publishdate,
				created,
				oldid, oldcontenttypeid, routeid, inlist, protected,
				showpublished, showapproved, approved, showopen, ipaddress, setfor)
			SELECT vm.postuserid, vm.postusername, {vmChannel}, {texttypeid}, vm.title,
				\'\', 0, \'\', 0, CASE WHEN vm.state <> \'deleted\' THEN vm.dateline ELSE 0 END AS publishdate,
				CASE WHEN vm.state=\'visible\' THEN vm.dateline ELSE 0 END AS created,
				vm.vmid AS oldid, {visitorMessageType} AS oldcontenttypeid, {vmRouteid}, 1, 0,
				CASE WHEN vm.state=\'deleted\' THEN 0 ELSE 1 END AS showpublished, CASE WHEN vm.state=\'moderation\' THEN 0 ELSE 1 END AS showapproved, CASE WHEN vm.state=\'moderation\' THEN 0 ELSE 1 END AS approved, 1, vm.ipaddress, vm.userid AS setfor
			FROM {TABLE_PREFIX}visitormessage AS vm
			WHERE vm.vmid IN ({vmIds})'
		),
		'importMissingVMText' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}text(nodeid, rawtext)
			SELECT node.nodeid, vm.pagetext AS rawtext
			FROM {TABLE_PREFIX}visitormessage AS vm
			INNER JOIN {TABLE_PREFIX}node AS node ON node.oldid = vm.vmid AND node.oldcontenttypeid = {visitorMessageType}
			WHERE vm.vmid IN ({vmIds})'
		),
		'addClosureSelfForOldids' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT node.nodeid, node.nodeid, 0
			FROM {TABLE_PREFIX}node AS node
			WHERE node.oldcontenttypeid = {contenttypeid}
				AND node.oldid IN ({oldids})'
		),
		'addClosureParentsForOldids' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => 'INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
			SELECT parent.parent, node.nodeid, parent.depth + 1
			FROM {TABLE_PREFIX}node AS node
			INNER JOIN {TABLE_PREFIX}closure AS parent ON parent.child = node.parentid
			WHERE node.oldcontenttypeid = {contenttypeid}
				AND node.oldid IN ({oldids})'
		),
		'updateChannelRoutesAndStarter_503a3' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
			INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Conversation\'
			SET n.routeid = cr.routeid, n.starter = n.nodeid
			WHERE n.oldcontenttypeid = {contenttypeid}
				AND n.oldid IN ({oldids})'
		),
		'fixMissingPageArgumentsForChannels' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT routeid, arguments
			FROM {TABLE_PREFIX}routenew
			WHERE class = 'vB5_Route_Channel'
			AND regex LIKE '%P<pagenum>%'
			AND arguments NOT LIKE '%\$pagenum%'
			LIMIT {batchsize}"
		),
		'fixCorruptOpenFlags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}node AS ch ON ch.nodeid = node.parentid
				SET node.open = 0
				WHERE node.showopen = 0 AND ch.showopen = 1
					AND node.oldcontenttypeid = {oldcontenttypeid}
					AND {startat} < node.oldid AND node.oldid < ({startat} + {batchsize} + 1)'
		),
		'importClosedThreadOpenFlags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}thread AS th ON th.threadid = node.oldid
				SET node.open = 0
				WHERE node.open = 1 AND th.open = 0
					AND node.oldcontenttypeid = {oldcontenttypeid}
					AND {startat} < node.oldid AND node.oldid < ({startat} + {batchsize} + 1)'
		),
		'fixIncorrectShowopenFlags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS cl ON cl.child = node.nodeid
				INNER JOIN {TABLE_PREFIX}node AS parent ON parent.nodeid = cl.parent
				SET node.showopen = 0
				WHERE parent.open = 0 AND parent.oldcontenttypeid = {oldcontenttypeid}
					AND cl.depth > 0
					AND {startat} < node.nodeid AND node.nodeid < ({startat} + {batchsize} + 1)'
		),
		'findOrphanChildlessChannels' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT nodeid FROM {TABLE_PREFIX}node AS n
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.parent = n.nodeid AND depth > 0
				WHERE parentid = 0 AND routeid = 0 AND nodeid <> 1 AND contenttypeid = {contenttypeid}
					AND cl.depth IS NULL'
		),
		'getMaxPollNodeid' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT max(nodeid) AS maxToFix
			FROM  {TABLE_PREFIX}poll'
		),
		'fixNodeidInPolloption' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}polloption AS opt
			INNER JOIN {TABLE_PREFIX}node AS poll ON opt.nodeid = poll.nodeid
			LEFT JOIN {TABLE_PREFIX}node AS n ON poll.parentid = n.nodeid
			SET opt.nodeid = n.nodeid
			WHERE poll.oldcontenttypeid = {contenttypeid}
			AND poll.nodeid > {startat} AND poll.nodeid < ({startat} + {batchsize} + 1)'
		),
		'getStrayPollsAndOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT n.nodeid, c.nodeid AS pollnodeid, poll.options
			FROM {TABLE_PREFIX}node AS n
			INNER JOIN {TABLE_PREFIX}node AS c ON c.parentid = n.nodeid AND n.oldcontenttypeid = {threadcontenttypeid} AND c.oldcontenttypeid = {pollcontenttypeid}
			INNER JOIN {TABLE_PREFIX}poll AS poll ON poll.nodeid = c.nodeid
			WHERE poll.nodeid > {startat} AND poll.nodeid < ({startat} + {batchsize} + 1)'
		),
		'fixPollContentTypes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => 'UPDATE {TABLE_PREFIX}node as n
			INNER JOIN {TABLE_PREFIX}node as poll ON n.nodeid = poll.parentid
			SET n.contenttypeid = poll.contenttypeid, n.oldcontenttypeid = poll.oldcontenttypeid
			WHERE poll.oldcontenttypeid = {contenttypeid}
			AND poll.nodeid > {startat} AND poll.nodeid < ({startat} + {batchsize} + 1)'
		),
		'getChannelsMissingPageRegex' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT routeid, prefix, arguments
				FROM {TABLE_PREFIX}routenew
				WHERE class = 'vB5_Route_Channel'
				AND regex NOT LIKE '%\(\?\:/page%'
				AND guid NOT IN ('vbulletin-4ecbdacd6a4ad0.58738735')"
		),

		'checkPagePhrase' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT COUNT(*) FROM {TABLE_PREFIX}phrase WHERE varname = {varname} AND languageid = 0'
		),
		// get the max routeid in routenew table
		'getMaxRouteid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(routeid) AS routeid FROM {TABLE_PREFIX}routenew
				WHERE class = 'vB5_Route_Conversation'"
		),
		// grab conversation routes
		'getConversationRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT routeid, prefix, regex FROM {TABLE_PREFIX}routenew
				WHERE class = 'vB5_Route_Conversation'
					AND routeid > {startat} AND routeid < ({startat} + {batchsize} + 1)"
		),
		// grab conversation routes with [, or ] in the prefix OR whose nodes have [ or ] in the urlIdent
		'getConversationRoutesRequiringOldRegex' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT r.routeid, r.prefix, r.regex FROM {TABLE_PREFIX}routenew AS r
				INNER JOIN {TABLE_PREFIX}node AS n ON n.routeid = r.routeid AND n.urlident REGEXP '\\\\[|\\\\]'
				WHERE r.class = 'vB5_Route_Conversation'
					AND n.nodeid > {startat} AND n.nodeid < ({startat} + {batchsize} + 1)"
		),
		'getMaxChildNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(nodeid) AS maxid FROM {TABLE_PREFIX}node
				WHERE parentid = {parentid}"
		),
		'updateBlogNodeOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node
				SET nodeoptions = (nodeoptions | {setNewOption})
				WHERE parentid = {blogChannelId}
					AND nodeid > {startat} AND nodeid < ({startat} + {batchsize} + 1)"
		),
		'fetchBlogGroupintopicMissingSubscriptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT git.userid, git.nodeid FROM {TABLE_PREFIX}groupintopic AS git
				INNER JOIN {TABLE_PREFIX}node AS n ON git.nodeid = n.nodeid
					AND n.parentid = {blogChannelId}
				LEFT JOIN {TABLE_PREFIX}subscribediscussion AS sub
					ON sub.userid = git.userid AND sub.discussionid = git.nodeid
				WHERE sub.userid IS NULL"
		),
		'createCacheLogTable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_CREATE,
			'query_string' => 'CREATE TABLE IF NOT EXISTS  {TABLE_PREFIX}cachelog (
				randomkey float ,
				cacheid varbinary(64),
				cachetype SMALLINT,
				time INT(10),
			 	writes SMALLINT,
			 	hits SMALLINT,
			 	misses SMALLINT,
			 	rereads SMALLINT,
			 	size INT,
			 	remiss SMALLINT,
			 	clears SMALLINT,
			 	stacktrace TEXT
			 )'
		),
		'importTagContent' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'query_string' => 'INSERT IGNORE INTO {TABLE_PREFIX}tagnode(tagid, nodeid, userid, dateline)
						SELECT c.tagid, n.nodeid, c.userid, c.dateline
						FROM {TABLE_PREFIX}node n
						INNER JOIN {TABLE_PREFIX}tagcontent c ON c.contenttypeid = n.oldcontenttypeid AND c.contentid = n.oldid'
		),
		'updateNodeTags' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'query_string' => 'UPDATE {TABLE_PREFIX}node n
						INNER JOIN (
							SELECT tn.nodeid, GROUP_CONCAT(t.tagtext ORDER BY t.tagtext ASC) AS taglist
							FROM {TABLE_PREFIX}tagnode tn
							INNER JOIN {TABLE_PREFIX}tag t ON t.tagid = tn.tagid
							GROUP BY tn.nodeid
						) j ON j.nodeid = n.nodeid
						SET n.taglist = j.taglist'
		),
		'movePageMetadataPhrases' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}phrase SET
					fieldname = 'pagemeta'
				WHERE languageid > 0 AND fieldname = 'global'
					AND (
						varname LIKE 'page_%_title'
						OR
						varname LIKE 'page_%_metadesc'
					)
				"
		),
		'getMaxThreadid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT max(threadid) AS maxid FROM {TABLE_PREFIX}thread"
		),
		'importThreadviews' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"INSERT INTO {TABLE_PREFIX}nodeview (nodeid, count)
				SELECT node.nodeid, (t.views + IFNULL(tv.views, 0)) AS count
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}thread AS t ON node.oldid = t.threadid
				LEFT JOIN
					(SELECT COUNT(*) AS views, threadid
						FROM {TABLE_PREFIX}threadviews GROUP BY threadid
					) AS tv ON tv.threadid = t.threadid
				WHERE node.oldcontenttypeid = {oldcontenttypeid}
					AND t.threadid > {startat} AND t.threadid < ({startat} + {batchsize} + 1)
					AND (t.views + IFNULL(tv.views, 0)) > 0
				"
		),
		'getMaxBlogid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT max(blogid) AS maxid FROM {TABLE_PREFIX}blog"
		),
		'importBlogviews' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"INSERT INTO {TABLE_PREFIX}nodeview (nodeid, count)
				SELECT node.nodeid, (b.views + IFNULL(bv.views, 0)) AS count
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}blog AS b ON node.oldid = b.blogid
				LEFT JOIN
					(SELECT COUNT(*) AS views, blogid
						FROM {TABLE_PREFIX}blog_views GROUP BY blogid
					) AS bv ON bv.blogid = b.blogid
				WHERE node.oldcontenttypeid = {oldcontenttypeid}
					AND b.blogid > {startat} AND b.blogid < ({startat} + {batchsize} + 1)
					AND (b.views + IFNULL(bv.views, 0)) > 0
				"
		),
		'fixRefCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
			"UPDATE {TABLE_PREFIX}filedata AS f
			INNER JOIN
				(SELECT f.filedataid, count(a.nodeid) + count(p.nodeid) AS usecount
				FROM {TABLE_PREFIX}filedata AS f
				LEFT JOIN {TABLE_PREFIX}attach AS a ON a.filedataid = f.filedataid
				LEFT JOIN {TABLE_PREFIX}photo AS p ON p.filedataid = f.filedataid
				WHERE f.refcount = 0  AND f.filedataid >= {startat} AND f.filedataid < ({startat} + {batchsize} + 1)
				GROUP by f.filedataid) AS used
			ON used.filedataid = f.filedataid
			SET f.refcount = used.usecount
			WHERE f.refcount = 0 AND f.filedataid >= {startat}
			AND f.filedataid < ({startat} + {batchsize} + 1)
			"
		),
		'getNextZeroRefcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT filedataid FROM {TABLE_PREFIX}filedata	WHERE refcount = 0
				AND filedataid >= {startat} ORDER BY filedataid LIMIT 1"
		),
		'getvBCMSSectionContenttypeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT c.contenttypeid FROM {TABLE_PREFIX}contenttype AS c
				INNER JOIN {TABLE_PREFIX}package AS p ON p.packageid = c.packageid AND p.productid = 'vbcms'
				WHERE c.class = 'Section'"
		),
		'checkOldCMSTable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT nodeid FROM {TABLE_PREFIX}cms_node LIMIT 1"
		),
		'findOldImportedCMSHome' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT n.nodeid FROM {TABLE_PREFIX}node AS n
				INNER JOIN {TABLE_PREFIX}node AS p ON p.parentid = 0 AND n.oldid = p.nodeid
				WHERE n.oldcontenttypeid = {oldcontenttypeid} AND n.parentid = {parentid}"
		),
		'getOldCMSHome' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT n.publishdate, n.userid, u.username AS authorname,
					ni.description, ni.title, ni.html_title,
					n.nodeid AS oldid, {oldcontenttypeid} AS oldcontenttypeid
				FROM {TABLE_PREFIX}cms_node  AS n
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS ni ON n.nodeid = ni.nodeid
				LEFT JOIN {TABLE_PREFIX}user AS u ON u.userid = n.userid
				LEFT JOIN {TABLE_PREFIX}node AS existing ON existing.oldid = n.nodeid AND existing.oldcontenttypeid = {oldcontenttypeid}
				WHERE n.nodeid = 1 AND existing.nodeid IS NULL"
		),
		'getOldCMSSections' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT
					IF(n.setpublish = 0, 0, n.publishdate) AS publishdate,
					n.userid, u.username AS authorname, ni.creationdate AS created,
					ni.description, ni.title, ni.html_title AS htmltitle,
					parent.nodeid AS parentid, n.nodeid AS oldid, {oldcontenttypeid} AS oldcontenttypeid,
					n.nodeleft AS displayorder
				FROM {TABLE_PREFIX}cms_node  AS n
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS ni ON n.nodeid = ni.nodeid
				LEFT JOIN {TABLE_PREFIX}user AS u ON u.userid = n.userid
				LEFT JOIN {TABLE_PREFIX}node AS existing ON existing.oldid = n.nodeid AND existing.oldcontenttypeid = {oldcontenttypeid}
				INNER JOIN {TABLE_PREFIX}node AS parent ON parent.oldid = n.parentnode AND parent.oldcontenttypeid = {oldcontenttypeid}
				WHERE n.contenttypeid =  {sectiontypeid} AND existing.nodeid IS NULL
				LIMIT {batchsize}"
		),
		'getvBCMSArticleContenttypeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT c.contenttypeid FROM {TABLE_PREFIX}contenttype AS c
				INNER JOIN {TABLE_PREFIX}package AS p ON p.packageid = c.packageid AND p.productid = 'vbcms'
				WHERE c.class = {class}"
		),
		'getMaxMissingArticleNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(cn.nodeid) AS maxid
				FROM {TABLE_PREFIX}cms_node AS cn
				LEFT JOIN {TABLE_PREFIX}node AS n
					ON cn.nodeid = n.oldid AND n.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
				WHERE n.nodeid IS NULL AND cn.contenttypeid IN ({articleTypeId}, {staticPageTypeId})"
		),
		'getMinMissingArticleNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MIN(cn.nodeid) AS minid
				FROM {TABLE_PREFIX}cms_node AS cn
				LEFT JOIN {TABLE_PREFIX}node AS n
					ON cn.nodeid = n.oldid AND n.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
				WHERE n.nodeid IS NULL AND cn.contenttypeid IN ({articleTypeId}, {staticPageTypeId})"
		),
		'getOldCMSArticles' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT
					{textTypeId} AS contenttypeid,
					category.nodeid AS parentid,
					cms_nodeinfo.title,
					cms_nodeinfo.description,
					cms_nodeinfo.html_title AS htmltitle,
					cms_node.url AS urlident,
					IF(cms_node.setpublish = 0, 0, cms_node.publishdate) AS publishdate,
					cms_nodeinfo.creationdate AS created,
					cms_node.lastupdated AS lastupdate,
					cms_node.nodeid AS oldid,
					{oldcontenttypeid_article} oldcontenttypeid,
					1 AS inlist,
					cms_node.userid,
					u.username AS authorname,
					article.previewtext,
					article.previewimage,
					article.previewvideo,
					cms_node.publicpreview AS public_preview,
					article.imageheight,
					article.imagewidth,
					article.pagetext AS rawtext,
					article.htmlstate,
					IFNULL(sectionorder.displayorder, 0) AS displayorder
				FROM {TABLE_PREFIX}cms_node AS cms_node
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
					ON cms_nodeinfo.nodeid = cms_node.nodeid
				INNER JOIN {TABLE_PREFIX}node AS category
					ON category.oldid = cms_node.parentnode AND category.oldcontenttypeid = {oldcontenttypeid_section}
				INNER JOIN {TABLE_PREFIX}cms_article AS article
					ON article.contentid = cms_node.contentid
				LEFT JOIN {TABLE_PREFIX}node AS existing
					ON existing.oldid = cms_node.nodeid
					AND existing.oldcontenttypeid = {oldcontenttypeid_article}
				LEFT JOIN {TABLE_PREFIX}user AS u ON u.userid = cms_node.userid
				LEFT JOIN {TABLE_PREFIX}cms_sectionorder AS sectionorder
					ON sectionorder.nodeid = cms_node.nodeid
					AND sectionorder.sectionid = cms_node.parentnode
				WHERE cms_node.contenttypeid = {articleTypeId}
					AND existing.nodeid IS NULL
					AND {startat} < cms_node.nodeid AND cms_node.nodeid < ({startat} + {batchsize} + 1)"
		),
		'getOldCMSStaticPages' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT
					{textTypeId} AS contenttypeid,
					category.nodeid AS parentid,
					cms_nodeinfo.title,
					cms_nodeinfo.description,
					cms_nodeinfo.html_title AS htmltitle,
					cms_node.url AS urlident,
					IF(cms_node.setpublish = 0, 0, cms_node.publishdate) AS publishdate,
					cms_nodeinfo.creationdate AS created,
					cms_node.lastupdated AS lastupdate,
					cms_node.nodeid AS oldid,
					{oldcontenttypeid_staticpage} AS oldcontenttypeid,
					1 AS inlist,
					cms_node.userid,
					u.username AS authorname,
					previewtext.value AS previewtext,
					previewimage.value AS previewimage,
					cms_node.publicpreview AS public_preview,
					htmltext.value AS rawtext,
					'on' AS htmlstate,
					IFNULL(sectionorder.displayorder, 0) AS displayorder
				FROM {TABLE_PREFIX}cms_node AS cms_node
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
					ON cms_nodeinfo.nodeid = cms_node.nodeid
				INNER JOIN {TABLE_PREFIX}node AS category
					ON category.oldid = cms_node.parentnode AND category.oldcontenttypeid = {oldcontenttypeid_section}
				INNER JOIN {TABLE_PREFIX}cms_nodeconfig AS htmltext
					ON htmltext.nodeid = cms_node.nodeid AND htmltext.name = 'pagetext'
				LEFT JOIN {TABLE_PREFIX}cms_nodeconfig AS previewimage
					ON htmltext.nodeid = previewimage.nodeid AND previewimage.name = 'preview_image'
				LEFT JOIN {TABLE_PREFIX}cms_nodeconfig AS previewtext
					ON htmltext.nodeid = previewtext.nodeid AND previewtext.name = 'previewtext'
				LEFT JOIN {TABLE_PREFIX}node AS existing
					ON existing.oldid = cms_node.nodeid
					AND existing.oldcontenttypeid = {oldcontenttypeid_staticpage}
				LEFT JOIN {TABLE_PREFIX}user AS u ON u.userid = cms_node.userid
				LEFT JOIN {TABLE_PREFIX}cms_sectionorder AS sectionorder
					ON sectionorder.nodeid = cms_node.nodeid
					AND sectionorder.sectionid = cms_node.parentnode
				WHERE cms_node.contenttypeid = {staticPageTypeId}
					AND existing.nodeid IS NULL
					AND {startat} < cms_node.nodeid AND cms_node.nodeid < ({startat} + {batchsize} + 1)"
		),
		'setStarterAndLastcontentidSelfByNodeList' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node
				SET starter = nodeid, lastcontentid = nodeid
				WHERE nodeid IN ({nodeList})"),
		/*
			Alternatively if we don't want to rely on parent.routeid being set in the interim, we could join by:
			INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.contentid = n.parentid AND pr.class = \'vB5_Route_Channel\'
			for starter nodes, since the channel route's routenew.contentid will point to the parent channelid.
		 */
		'updateChannelRouteidToArticleRouteidByNodelist' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				'UPDATE {TABLE_PREFIX}node AS n
				INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
				INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Article\'
				SET n.routeid = cr.routeid
				WHERE n.nodeid IN ({nodeList})'),
		'updateChannelCountsAndLastContentAndPropagateUp' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				'UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS closure ON closure.parent = node.nodeid
				SET node.lastcontent =
						CASE WHEN {lastcontent} >= node.lastcontent THEN
							{lastcontent}
						ELSE node.lastcontent END,
					node.lastcontentid =
						CASE WHEN {lastcontent} >= node.lastcontent THEN
							{lastcontentid}
						ELSE node.lastcontentid END,
					node.lastcontentauthor =
						CASE WHEN {lastcontent} >= node.lastcontent THEN
							{lastcontentauthor}
						ELSE node.lastcontentauthor END,
					node.lastauthorid =
						CASE WHEN {lastcontent} >= node.lastcontent THEN
							{lastauthorid}
						ELSE node.lastauthorid END,
					node.textcount =
						CASE WHEN node.nodeid = {channelid} THEN
							node.textcount + {textcount}
						ELSE node.textcount END,
					node.textunpubcount =
						CASE WHEN node.nodeid = {channelid} THEN
							node.textunpubcount + {textunpubcount}
						ELSE node.textunpubcount END,
					node.totalcount = node.totalcount + {totalcount},
					node.totalunpubcount = node.totalunpubcount + {totalunpubcount}
				WHERE closure.child = {channelid}'),
		'updateArticleRoutes' =>array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				'UPDATE {TABLE_PREFIX}node AS n
				INNER JOIN {TABLE_PREFIX}routenew AS pr ON pr.routeid = n.routeid AND pr.class = \'vB5_Route_Channel\'
				INNER JOIN {TABLE_PREFIX}routenew AS cr ON cr.prefix = pr.prefix AND cr.class = \'vB5_Route_Article\'
				SET n.routeid = cr.routeid
				WHERE n.oldcontenttypeid IN ({oldcontenttypeids}) AND n.oldid > {startat} AND n.oldid < ({startat} + {batchsize} + 1)'
		),
		'getMaxMissingArticleAttachmentid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(a.attachmentid) AS maxid
				FROM {TABLE_PREFIX}attachment AS a
				LEFT JOIN {TABLE_PREFIX}node AS n
					ON a.attachmentid = n.oldid AND n.oldcontenttypeid = {oldcontenttypeid_articleattachment}
				WHERE n.nodeid IS NULL AND a.contenttypeid = {articletypeid}"
		),
		'getMinMissingArticleAttachmentid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MIN(a.attachmentid) AS minid
				FROM {TABLE_PREFIX}attachment AS a
				LEFT JOIN {TABLE_PREFIX}node AS n
					ON a.attachmentid = n.oldid AND n.oldcontenttypeid = {oldcontenttypeid_articleattachment}
				WHERE n.nodeid IS NULL AND a.contenttypeid = {articletypeid}"
		),
		'insertArticleAttachmentNodes' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' =>
				'INSERT INTO {TABLE_PREFIX}node (
					userid, authorname, contenttypeid, parentid, routeid,
					title, htmltitle,
					publishdate, oldid, oldcontenttypeid, created,
					starter, inlist, showpublished, showapproved, showopen)
				SELECT
					a.userid, u.username, {attachtypeid}, article.nodeid, article.routeid,
					\'\', \'\',
					a.dateline, a.attachmentid,	{oldcontenttypeid_articleattachment}, a.dateline,
					article.starter, 0, 1, 1, 1
				FROM {TABLE_PREFIX}attachment AS a
					INNER JOIN {TABLE_PREFIX}cms_node AS cnode
						ON a.contentid = cnode.nodeid
					INNER JOIN {TABLE_PREFIX}node AS article
						ON article.oldid = cnode.nodeid AND article.oldcontenttypeid = {oldcontenttypeid_article}
					LEFT JOIN {TABLE_PREFIX}user AS u ON a.userid = u.userid
				WHERE  {startat} < a.attachmentid AND a.attachmentid < ({startat} + {batchsize} + 1)
					AND a.contenttypeid = {articletypeid}'
		),
		'insertArticleAttachments' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' =>
				'INSERT INTO {TABLE_PREFIX}attach
					(nodeid, filedataid,
					visible, counter,
					posthash, filename,
					caption, settings)
				SELECT
					n.nodeid, a.filedataid,
					 CASE WHEN a.state = \'moderation\' then 0 else 1 end AS visible, a.counter,
					 a.posthash, a.filename,
					 a.caption, a.settings
				FROM {TABLE_PREFIX}attachment AS a
				INNER JOIN {TABLE_PREFIX}node AS n
					ON n.oldid = a.attachmentid AND n.oldcontenttypeid = {oldcontenttypeid_articleattachment}
				WHERE {startat} < a.attachmentid AND a.attachmentid < ({startat} + {batchsize} + 1)
					AND a.contenttypeid = {articletypeid}'
		),
		'getUnmovedArticleCommentNodeids' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT comment.nodeid
				FROM {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
				INNER JOIN {TABLE_PREFIX}post AS post
					ON post.threadid = cms_nodeinfo.associatedthreadid AND cms_nodeinfo.associatedthreadid <> 0
						AND post.parentid <> 0
				INNER JOIN {TABLE_PREFIX}node AS parent
					ON parent.oldid = cms_nodeinfo.nodeid
					AND parent.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
				INNER JOIN {TABLE_PREFIX}node AS comment
					ON post.postid = comment.oldid AND comment.oldcontenttypeid = {posttypeid}
				LIMIT {batchsize}"
		),
		'getMaxUnmovedArticleCommentNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(comment.nodeid) AS maxid
				FROM {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
				INNER JOIN {TABLE_PREFIX}post AS post
					ON post.threadid = cms_nodeinfo.associatedthreadid AND cms_nodeinfo.associatedthreadid <> 0
						AND post.parentid <> 0
				INNER JOIN {TABLE_PREFIX}node AS parent
					ON parent.oldid = cms_nodeinfo.nodeid
					AND parent.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
				INNER JOIN {TABLE_PREFIX}node AS comment
					ON post.postid = comment.oldid AND comment.oldcontenttypeid = {posttypeid}"
		),
		'moveArticleCommentNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node AS comment
				INNER JOIN {TABLE_PREFIX}post AS post
					ON post.postid = comment.oldid AND post.parentid <> 0
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
					ON post.threadid = cms_nodeinfo.associatedthreadid AND cms_nodeinfo.associatedthreadid <> 0
				INNER JOIN {TABLE_PREFIX}node AS parent
					ON parent.oldid = cms_nodeinfo.nodeid
					AND parent.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
				SET comment.parentid = parent.nodeid,
					comment.starter = parent.nodeid,
					comment.oldcontenttypeid = {oldcontenttypeid_articlecomment},
					comment.routeid = parent.routeid
				WHERE comment.oldcontenttypeid = {posttypeid}
					AND comment.nodeid IN ({nodeids})"
		),
		'removeArticleCommentClosureParents' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' =>
				'DELETE cl.* FROM {TABLE_PREFIX}closure AS cl
				INNER JOIN {TABLE_PREFIX}node AS node
					ON cl.child = node.nodeid
				WHERE node.oldcontenttypeid = {oldcontenttypeid_articlecomment}
					AND cl.depth > 0
					AND node.nodeid IN ({nodeids})'
		),
		'addArticleCommentClosureParents' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' =>
				'INSERT IGNORE INTO {TABLE_PREFIX}closure (parent, child, depth)
				SELECT parent.parent, node.nodeid, parent.depth + 1
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS parent
					ON parent.child = node.parentid
				WHERE node.oldcontenttypeid = {oldcontenttypeid_articlecomment}
					AND node.nodeid IN ({nodeids})'
		),
		'getImportedArticleNodeids' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT nodeid
				FROM {TABLE_PREFIX}node
				WHERE oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
					AND {startat} < nodeid
				ORDER BY nodeid LIMIT {batchsize};"
		),
		'updateImportedArticleTextcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node AS article
				LEFT JOIN
					(SELECT COUNT(nodeid) AS total, parentid FROM {TABLE_PREFIX}node
					WHERE oldcontenttypeid = {oldcontenttypeid_articlecomment}
						AND parentid IN ({nodeids})
					GROUP  BY parentid
					) AS comment ON comment.parentid = article.nodeid
				SET article.textcount = IFNULL(comment.total, article.textcount),
					article.totalcount = IFNULL(comment.total, article.totalcount)
				WHERE article.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
					AND article.nodeid IN ({nodeids})
					AND article.textcount < 1"
		),
		'importArticleViewcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"INSERT IGNORE INTO {TABLE_PREFIX}nodeview (nodeid, count)
				SELECT article.nodeid, cms_nodeinfo.viewcount AS count
				FROM {TABLE_PREFIX}node AS article
				INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
					ON article.oldid = cms_nodeinfo.nodeid
				WHERE article.oldcontenttypeid IN ({oldcontenttypeid_article}, {oldcontenttypeid_staticpage})
					AND article.nodeid IN ({nodeids})
					AND cms_nodeinfo.viewcount > 0
				"
		),
		'getStaticPageNodeidsToUpdate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(nodeid) AS maxid, MIN(nodeid) AS minid
				FROM {TABLE_PREFIX}node
				WHERE oldcontenttypeid = {oldcontenttypeid_staticpage}
					AND ! (nodeoptions & {option_disable_bbcode})"
		),
		'updateStaticPageNodeOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node
				SET nodeoptions = (nodeoptions | {new_option})
				WHERE oldcontenttypeid = {oldcontenttypeid_staticpage}
					AND nodeid > {startat} AND nodeid < ({startat} + {batchsize} + 1)"
		),
		'findCMSCommentForumNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT DISTINCT(node.nodeid)
				FROM {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
				INNER JOIN {TABLE_PREFIX}thread AS thread
					ON thread.threadid = cms_nodeinfo.associatedthreadid
				INNER JOIN {TABLE_PREFIX}node AS node
					ON node.oldid = thread.forumid AND node.oldcontenttypeid = {forumtypeid}"
		),
		'getImportedCMSSections' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT MAX(nodeid) AS maxid, MIN(nodeid) AS minid
				FROM {TABLE_PREFIX}node
					WHERE oldcontenttypeid = {oldcontenttypeid_section}"
		),
		'updateImportedSectionTotalcount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node AS category
				INNER JOIN
					(SELECT COUNT(DISTINCT(child)) AS totalcount, parent FROM {TABLE_PREFIX}node
					INNER JOIN {TABLE_PREFIX}closure
						ON nodeid = child AND depth > 0
					WHERE contenttypeid IN ({contenttypeids})
						AND showopen AND showpublished
					GROUP BY parent)
				AS textchildren	ON textchildren.parent = category.nodeid
				SET category.totalcount = textchildren.totalcount
				WHERE category.oldcontenttypeid =  {oldcontenttypeid_section}
					AND {startat} < category.nodeid AND category.nodeid < ({startat} + {batchsize} + 1)"
		),
		'updateAdminPerms' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}administrator
			SET adminpermissions = (adminpermissions | {new})
			WHERE adminpermissions & {existing} > 1"
		),
		'setCMSAdminPermFromvB4' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}administrator
			SET adminpermissions = (adminpermissions | {newvalue})
			WHERE vbcmspermissions > 0"
		),
		'setCMSAdminPermFromvExisting' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}administrator
			SET adminpermissions = (adminpermissions | {newvalue})
			WHERE  (adminpermissions | {existing}) > 0"
			),
		'importPublicPreview' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
			"UPDATE {TABLE_PREFIX}node AS vb5 INNER JOIN {TABLE_PREFIX}cms_node AS cms
			ON cms.nodeid = vb5.oldid AND vb5.oldcontenttypeid IN ({oldcontenttypes})
			SET vb5.public_preview = 1 WHERE cms.publicpreview > 0"
		),
		'importCMSTags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}tagnode(tagid, nodeid, userid, dateline)
			SELECT DISTINCT tc.tagid, n.nodeid, tc.userid, tc.dateline
			FROM {TABLE_PREFIX}node AS n INNER JOIN {TABLE_PREFIX}cms_node AS cms ON cms.nodeid = n.oldid AND n.oldcontenttypeid IN ({cmstypes})
			INNER JOIN {TABLE_PREFIX}tagcontent AS tc ON tc.contenttypeid = cms.contenttypeid AND tc.contentid = cms.contentid
			LEFT JOIN {TABLE_PREFIX}tagnode AS tn ON tn.nodeid = n.nodeid AND tn.tagid = tc.tagid
			 WHERE cms.nodeid > {startat} AND cms.nodeid < ({startat} + {batchsize} + 1)
			 AND tn.nodeid IS NULL"),
		'maxCMSNode' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT MAX(nodeid) AS maxId FROM {TABLE_PREFIX}cms_node"),
		'importCMSCategoryTags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}tag(tagtext, dateline)
				SELECT DISTINCT cat.category, {timenow}
				FROM {TABLE_PREFIX}cms_category AS cat LEFT JOIN {TABLE_PREFIX}tag AS tag ON tag.tagtext = cat.category WHERE tagid IS NULL"),
		'assignCMSCategoryTags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "INSERT INTO {TABLE_PREFIX}tagnode(tagid, nodeid, userid, dateline)
			SELECT DISTINCT t.tagid, n.nodeid, {userid}, {timenow}
			FROM {TABLE_PREFIX}cms_category AS cat INNER JOIN {TABLE_PREFIX}tag AS t ON t.tagtext = cat.category
			INNER JOIN {TABLE_PREFIX}cms_nodecategory AS nc ON nc.categoryid = cat.categoryid
			INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = nc.nodeid AND n.oldcontenttypeid IN ({cmstypes})
			LEFT JOIN {TABLE_PREFIX}tagnode AS chk ON chk.nodeid = n.nodeid AND chk.tagid = t.tagid
			WHERE nc.nodeid > {startat} AND nc.nodeid < ({startat} + {batchsize} + 1)
			AND chk.nodeid IS NULL"),
		'importCMSnodeOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node AS node INNER JOIN
			{TABLE_PREFIX}cms_node AS cms ON cms.nodeid = node.oldid AND oldcontenttypeid IN ({cmstypes})
			SET node.nodeoptions =
			(
				(
					nodeoptions |
					(CASE WHEN cms.showtitle = 0 		THEN {optiontitle} ELSE 0 END) |
					(CASE WHEN cms.showuser = 0 		THEN {optionauthor} ELSE 0 END) |
					(CASE WHEN cms.showpublishdate = 0 	THEN {optionpubdate} ELSE 0 END) |
					(CASE WHEN cms.showpreviewonly = 1 	THEN {optionfulltext} ELSE 0 END) |
					(CASE WHEN cms.showviewcount = 1 	THEN {optionpageview} ELSE 0 END)
				) &
				~({optioncomment})
			) |
			(CASE WHEN cms.comments_enabled = 1 THEN {optioncomment} ELSE 0 END)"),
		'fetchCMSNodeTags' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT n.nodeid, t.tagtext
				FROM {TABLE_PREFIX}node AS n
					INNER JOIN {TABLE_PREFIX}tagnode AS tn ON tn.nodeid = n.nodeid
					INNER JOIN {TABLE_PREFIX}tag AS t ON t.tagid = tn.tagid
				WHERE n.oldid > {startat} AND n.oldid < ({startat} + {batchsize} + 1) AND n.oldcontenttypeid IN ({cmstypes})
			"
		),
		'importToThread_post' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => "
				INSERT INTO {TABLE_PREFIX}thread_post(nodeid, threadid, postid)
				SELECT n.nodeid, th.threadid, th.firstpostid
				FROM {TABLE_PREFIX}thread AS th
					INNER JOIN {TABLE_PREFIX}node AS n ON n.oldid = th.threadid AND n.oldcontenttypeid = {threadTypeId}
				WHERE th.threadid > {maxvB5} AND th.threadid < ({maxvB5} + {process})
				ORDER BY th.threadid
				ON DUPLICATE KEY UPDATE postid = th.firstpostid, threadid = th.threadid
			"
		),
		'getBlogsWithNullDisplayorder' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT nodeid FROM {TABLE_PREFIX}node
				WHERE parentid = {blogChannelId}
					AND displayorder IS NULL
					LIMIT {batchsize}"
		),
		'updateNodesDisplayorder' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node
				SET displayorder = 1
				WHERE nodeid IN ({nodeids})"
		),
		'getSocialGroupsWithNullDisplayorder' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				"SELECT nodeid FROM {TABLE_PREFIX}node AS n
				INNER JOIN {TABLE_PREFIX}closure AS cl
					ON cl.child = n.nodeid AND cl.parent = {sgChannelId} AND cl.depth IN (1, 2)
				WHERE n.displayorder IS NULL
					LIMIT {batchsize}"
		),
		'getLinkPreviewFiledataidsWithRefcountZero' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT filedata.filedataid
				FROM {TABLE_PREFIX}filedata AS filedata
				INNER JOIN {TABLE_PREFIX}link AS link ON(link.filedataid = filedata.filedataid)
				WHERE filedata.refcount = 0
				ORDER BY filedata.filedataid
				LIMIT 0, {batchsize}
			"
		),
		'getNodesWithUrlPreviewImage' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT text.nodeid, text.previewimage
				FROM {TABLE_PREFIX}text AS text
				WHERE
					text.previewimage <> ''
					AND text.previewimage IS NOT NULL
					AND text.previewimage NOT REGEXP '^[[:digit:]]+$'
				ORDER BY text.nodeid
				LIMIT 0, {batchsize}
			"
		),
		'getNodesWithMissingPreviewImage' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT node.nodeid
				FROM {TABLE_PREFIX}closure AS closure
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = closure.child)
				INNER JOIN {TABLE_PREFIX}node AS childnode ON (childnode.parentid = node.nodeid)
				INNER JOIN {TABLE_PREFIX}text AS text ON (text.nodeid = node.nodeid)
				INNER JOIN {TABLE_PREFIX}attach AS attach ON (attach.nodeid = childnode.nodeid)
				INNER JOIN {TABLE_PREFIX}filedata AS filedata ON (filedata.filedataid = attach.filedataid)
				WHERE
					closure.child > {last_processed_nodeid}
					AND
					closure.parent = {root_article_channel}
					AND
					childnode.contenttypeid = {attach_contenttypeid}
					AND
					(text.previewimage IS NULL OR text.previewimage = '')
					AND
					LOWER(filedata.extension) IN ('gif', 'jpg', 'jpeg', 'jpe', 'png', 'bmp', 'tiff', 'tif', 'psd', 'pdf')
				LIMIT {batchsize}
			"
		),
		'getPhotoNodesWithMissingPreviewImage' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT DISTINCT node.nodeid
				FROM {TABLE_PREFIX}closure AS closure
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = closure.child)
				INNER JOIN {TABLE_PREFIX}node AS childnode ON (childnode.parentid = node.nodeid)
				INNER JOIN {TABLE_PREFIX}text AS text ON (text.nodeid = node.nodeid)
				WHERE
					node.contenttypeid = {gallery_contenttypeid}
					AND
					closure.child > {last_processed_nodeid}
					AND
					closure.parent = {root_channel}
					AND
					(text.previewimage IS NULL OR text.previewimage = '')
				LIMIT {batchsize}
			"
		),
		'updateChannelOptions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}channel
				SET options = options | {setOption}
				WHERE nodeid IN ({nodeids})"
		),
		'getStrayPolls' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => 'SELECT poll.pollid, importedthread.nodeid, poll.options
			FROM {TABLE_PREFIX}poll AS poll
			INNER JOIN {TABLE_PREFIX}thread AS thread
				ON poll.pollid = thread.pollid
			INNER JOIN {TABLE_PREFIX}node AS importedthread
				ON importedthread.oldid = thread.threadid AND importedthread.oldcontenttypeid = {pollcontenttypeid}
			LEFT JOIN {TABLE_PREFIX}node AS importedpoll
				ON importedpoll.nodeid = poll.nodeid AND importedpoll.oldcontenttypeid = {pollcontenttypeid}
			WHERE importedpoll.nodeid IS NULL
				AND poll.pollid <> 0
				AND poll.nodeid > {startat} AND poll.nodeid < ({startat} + {batchsize} + 1)'
		),
		'updatePasswordTokenAndSecret' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET token = concat(password, ' ', salt),
					scheme = 'legacy',
					secret = salt
			"
		),
		'unsetChannelModeratorPermissionCanremoveposts' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}permission
				SET moderatorpermissions = (moderatorpermissions & ~131072)
				WHERE  groupid = {channel_moderators_usergroupid}"
		),
		'setPrivateAlbums' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}node AS node
					INNER JOIN {TABLE_PREFIX}album AS album ON album.albumid = node.oldid AND node.oldcontenttypeid = {albumtype} AND node.contenttypeid = {gallerytype}
					INNER JOIN {TABLE_PREFIX}node AS photo ON photo.parentid = node.nodeid AND photo.contenttypeid = {phototype}
					SET photo.viewperms = 0, node.viewperms = 0
					WHERE album.state IN ('private', 'profile')"
		),
		'deleteOrphanedSubscriptionRecords' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "DELETE {TABLE_PREFIX}subscribediscussion
				FROM {TABLE_PREFIX}subscribediscussion
				LEFT JOIN {TABLE_PREFIX}user ON ({TABLE_PREFIX}user.userid = {TABLE_PREFIX}subscribediscussion.userid)
				WHERE {TABLE_PREFIX}user.userid IS NULL",
		),
		'findDuplicateRouteNames' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT name, count(*) as count, min(routeid) as min_routeid
				FROM {TABLE_PREFIX}routenew
				WHERE NOT (name is NULL)
				GROUP BY name
				HAVING count>1
				",
		),
		'setEmptyStringsToNullRoutenew' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}routenew
				SET name=NULL
				WHERE name = ''
				",
		),
		'fixAttachPublicview' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}filedata AS filedata
				INNER JOIN {TABLE_PREFIX}attach AS attach USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}channel AS channel USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}sigpicnew AS sigpic USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}style AS style
					ON (filedata.filedataid = style.filedataid OR filedata.filedataid = style.previewfiledataid)
				SET filedata.publicview = 0
				WHERE filedata.publicview = 1
					AND channel.nodeid IS NULL
					AND style.styleid IS NULL
					AND sigpic.userid IS NULL",
		),
		'fixAttachPublicviewSkipFiledataids' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}filedata AS filedata
				INNER JOIN {TABLE_PREFIX}attach AS attach USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}channel AS channel USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}sigpicnew AS sigpic USING (filedataid)
				LEFT JOIN {TABLE_PREFIX}style AS style
					ON (filedata.filedataid = style.filedataid OR filedata.filedataid = style.previewfiledataid)
				SET filedata.publicview = 0
				WHERE filedata.publicview = 1
					AND channel.nodeid IS NULL
					AND style.styleid IS NULL
					AND sigpic.userid IS NULL
					AND filedata.filedataid NOT IN ({skipfiledataids})",
		),
		'fixUnreferencedFiledataPublicview' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}filedata AS filedata
				SET filedata.publicview = 0
				WHERE filedata.publicview = 1
					AND filedata.refcount = 0",
		),
		'getAttachmentsWithParentAndAuthor' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT attach.nodeid, attach.filename, attach.settings, node.parentid, node.userid
				FROM {TABLE_PREFIX}attach AS attach
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = attach.nodeid)
				ORDER BY attach.nodeid
				LIMIT {startat}, {batchsize}
			"
		),
		'fetch516Notifications' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT ntemp.*, node.parentid, node.starter
				FROM {TABLE_PREFIX}notification_temporary AS ntemp
				LEFT JOIN {TABLE_PREFIX}node AS node
					ON (node.nodeid = ntemp.sentbynodeid)
				WHERE ntemp.deleted = 0
				ORDER BY notificationid
				LIMIT {batchsize}
			"
		),
		'fetch516NotificationTypeData' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}notificationtype_temporary AS type
				INNER JOIN {TABLE_PREFIX}notificationcategory AS cat
					ON (type.categoryid = cat.categoryid)
			"
		),
		'delete516Notifications' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}notification_temporary
				SET deleted = 1
				WHERE notificationid IN ({deleteids})
			"
		),
		'fetchOldContentNotifications' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT sentto.userid AS recipient,
					about_node.userid AS sender,
					message_node.userid AS message_sender,
					about_node.starter AS starter,
					about_node.nodeid AS sentbynodeid,
					about_node.parentid AS parentid,
					message_node.publishdate AS lastsenttime,
					privatemessage.about AS about,
					privatemessage.nodeid AS delete_nodeid,
					userlist.type AS skip,
					ISNULL(user.userid) AS skip_missing_recipient
				FROM {TABLE_PREFIX}privatemessage AS privatemessage
				INNER JOIN {TABLE_PREFIX}sentto AS sentto
					ON sentto.nodeid = privatemessage.nodeid
				INNER JOIN {TABLE_PREFIX}node AS message_node
					ON message_node.nodeid = sentto.nodeid
				INNER JOIN {TABLE_PREFIX}node AS about_node
					ON about_node.nodeid = privatemessage.aboutid
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist
					ON userlist.userid = sentto.userid
						AND userlist.relationid = message_node.userid
						AND userlist.type = 'ignore'
				LEFT JOIN {TABLE_PREFIX}user AS user
					ON user.userid = sentto.userid
				WHERE privatemessage.msgtype = 'notification'
					AND privatemessage.about IN (
						'reply', 'comment', 'threadcomment',
						'subscription', 'usermention', 'vm'
					)
					AND privatemessage.deleted = 0
				ORDER BY privatemessage.nodeid
				LIMIT {batchsize}
			"
		),
		'fetchFirstComment' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.nodeid, node.userid
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist
					ON userlist.userid = {recipient}
						AND userlist.relationid = node.userid
						AND userlist.type = 'ignore'
				WHERE node.parentid = {parentid}
					AND node.contenttypeid IN ({contenttypeids})
					AND userlist.type IS NULL
					AND node.userid <> {recipient}
				ORDER BY node.publishdate
				LIMIT 1
			"
		),
		// The cron privatemessage_cleanup will take care of actually removing these messages
		'flagNotificationsForDelete' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}privatemessage AS pm,
					{TABLE_PREFIX}sentto AS sentto
				SET pm.deleted = 1, sentto.deleted = 1
				WHERE pm.nodeid IN ({deleteNodeids})
					AND pm.msgtype = 'notification'
					AND pm.nodeid = sentto.nodeid
			",
		),
		'fetchOldContentlessNotifications' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT sentto.userid AS recipient,
					message_node.userid AS sender,
					about_node.nodeid AS sentbynodeid,
					message_node.publishdate AS lastsenttime,
					privatemessage.about AS about,
					privatemessage.nodeid AS delete_nodeid,
					userlist.type AS skip,
					ISNULL(user.userid) AS skip_missing_recipient
				FROM {TABLE_PREFIX}privatemessage AS privatemessage
				INNER JOIN {TABLE_PREFIX}sentto AS sentto
					ON sentto.nodeid = privatemessage.nodeid
				INNER JOIN {TABLE_PREFIX}node AS message_node
					ON message_node.nodeid = sentto.nodeid
				INNER JOIN {TABLE_PREFIX}node AS about_node
					ON about_node.nodeid = privatemessage.aboutid
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist
					ON userlist.userid = sentto.userid
						AND userlist.relationid = message_node.userid
						AND userlist.type = 'ignore'
				LEFT JOIN {TABLE_PREFIX}user AS user
					ON user.userid = sentto.userid
				WHERE privatemessage.msgtype = 'notification'
					AND privatemessage.about IN ('vote', 'rate')
					AND privatemessage.deleted = 0
				ORDER BY privatemessage.nodeid
				LIMIT {batchsize}
			"
		),
		'fetchOldUserrelationNotifications' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT sentto.userid AS recipient,
					message_node.userid AS sender,
					message_node.publishdate AS lastsenttime,
					privatemessage.about AS about,
					privatemessage.nodeid AS delete_nodeid,
					userlist.type AS skip,
					ISNULL(recipient.userid) AS skip_missing_recipient,
					ISNULL(sender.userid) AS skip_missing_sender
				FROM {TABLE_PREFIX}privatemessage AS privatemessage
				INNER JOIN {TABLE_PREFIX}sentto AS sentto
					ON sentto.nodeid = privatemessage.nodeid
				INNER JOIN {TABLE_PREFIX}node AS message_node
					ON message_node.nodeid = sentto.nodeid
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist
					ON userlist.userid = sentto.userid
						AND userlist.relationid = message_node.userid
						AND userlist.type = 'ignore'
				LEFT JOIN {TABLE_PREFIX}user AS recipient
					ON recipient.userid = sentto.userid
				LEFT JOIN {TABLE_PREFIX}user AS sender
					ON sender.userid = message_node.userid
				WHERE privatemessage.msgtype = 'notification'
					AND privatemessage.about IN ('follow', 'following')
					AND privatemessage.deleted = 0
				ORDER BY privatemessage.nodeid
				LIMIT {batchsize}
			"
		),
		'fetchImportedVMNodes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.nodeid, node.userid, node.setfor
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN {TABLE_PREFIX}userlist AS userlist
					ON userlist.userid = node.setfor
						AND userlist.relationid = node.userid
						AND userlist.type = 'ignore'
				WHERE userlist.type IS NULL
					AND node.userid <> node.setfor
					AND node.setfor = {recipient}
					AND node.parentid = {vmChannelId}
					AND node.oldcontenttypeid = {vmTypeId}
					AND node.showpublished > 0
					AND node.showapproved > 0
				ORDER BY node.publishdate DESC
				LIMIT {vmunreadcount}
			"
		),
		'flagRemainingNotificationsForDelete' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}privatemessage
				SET deleted = 1
				WHERE msgtype = 'notification' AND deleted = 0
				LIMIT 1000"
		),
		'removeAutoincrementPhoto' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}photo MODIFY nodeid INT UNSIGNED NOT NULL"
		),
		'removeAutoincrementPoll' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}poll MODIFY nodeid INT UNSIGNED NOT NULL"
		),
		'checkDuplicatAttachRecords' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT nodeid, count(*) AS count FROM {TABLE_PREFIX}attach GROUP BY nodeid HAVING count > 1 LIMIT 1"
		),
		'fixShowApproved' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}node SET showapproved=0 WHERE showapproved=1 AND approved=0 LIMIT {batch_size}"
		),
		'fetchNotificationsWithDeletedRecipients' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
			SELECT notificationid
			FROM {TABLE_PREFIX}notification AS notification
			LEFT JOIN {TABLE_PREFIX}user AS user
				ON (user.userid = notification.recipient)
			WHERE user.userid IS NULL
			ORDER BY notificationid
			LIMIT {batchsize}"
		),
		'fetchDeletedSenderForNotificationsOfTypeX' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
			SELECT sender
			FROM {TABLE_PREFIX}notification AS notification
			LEFT JOIN {TABLE_PREFIX}user AS user
				ON (user.userid = notification.sender)
			WHERE notification.sender <> 0 AND
				user.userid IS NULL AND
				notification.typeid = {typeid}
			ORDER BY notification.sender
			LIMIT 1"
		),
		'fetchNotificationsWithDeletedSendersOfTypesX' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
			SELECT notificationid
			FROM {TABLE_PREFIX}notification AS notification
			LEFT JOIN {TABLE_PREFIX}user AS user
				ON (user.userid = notification.sender)
			WHERE notification.sender <> 0 AND
				user.userid IS NULL AND
				notification.typeid IN ({typeids})
			ORDER BY notificationid
			LIMIT {batchsize}"
		),
		'fetchNotificationsWithDeletedSendersOfTypesNOTX' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
			SELECT notificationid
			FROM {TABLE_PREFIX}notification AS notification
			LEFT JOIN {TABLE_PREFIX}user AS user
				ON (user.userid = notification.sender)
			WHERE notification.sender <> 0 AND
				user.userid IS NULL AND
				notification.typeid NOT IN ({typeids})
			ORDER BY notificationid
			LIMIT {batchsize}"
		),
		'getPhotos' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT photo.nodeid, photo.caption, node.title
				FROM {TABLE_PREFIX}photo AS photo
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = photo.nodeid)
				ORDER BY photo.nodeid
				LIMIT {startat}, {batchsize}
			"
		),
		'getStylesWithGUID' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT styleid
				FROM {TABLE_PREFIX}style AS style
				WHERE guid IS NOT NULL
			"
		),
		'getDuplicateWidgetGuids' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT guid, COUNT(widgetid) AS count
				FROM {TABLE_PREFIX}widget AS widget
				GROUP BY guid
				HAVING COUNT(widgetid) > 1
				LIMIT 1
			"
		),
		'deleteDupeThemeTemplates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => '
				DELETE FROM {TABLE_PREFIX}template
				WHERE styleid = {styleid}
					AND title != "css_additional.css"
			'
		),
		'deleteDupeThemeStylevars' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => '
				DELETE FROM {TABLE_PREFIX}stylevar
				WHERE styleid = {styleid}
					AND stylevarid != "titleimage"
			'
		),
		'findBannedUserWithStatuses' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT user.userid
				FROM {TABLE_PREFIX}user AS user
				INNER JOIN {TABLE_PREFIX}userban AS userban ON userban.userid = user.userid
				WHERE user.status <> \'\' AND
					userban.liftdate > {timenow}
				LIMIT 10000
			'
		),
		'showUserColumnStatus' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SHOW COLUMNS
				FROM {TABLE_PREFIX}USER LIKE 'status'
			"
		),
		'createTempUserStatusTable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_CREATE,
			'query_string' => "
				CREATE TABLE IF NOT EXISTS {TABLE_PREFIX}temp_user_status (
					userid INT UNSIGNED NOT NULL DEFAULT 0,
					status VARCHAR(1000) DEFAULT NULL,
					PRIMARY KEY (userid)
				)
			"
		),
		'showUserColumnStatus' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SHOW COLUMNS
				FROM {TABLE_PREFIX}USER LIKE 'status'
			"
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'alterUserStatusToVarchar' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				ALTER TABLE {TABLE_PREFIX}user MODIFY COLUMN status VARCHAR(1000) NOT NULL DEFAULT ''
			"
		),
		'selectShowOpenMismatch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.nodeid
				FROM {TABLE_PREFIX}node AS node
					JOIN {TABLE_PREFIX}node AS starter ON (node.starter = starter.nodeid)
				WHERE node.showopen = 1 AND
					starter.open = 0
				LIMIT {limit}
			"
		),
		'checkIndexLimitAdcriteria'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}adcriteria WHERE char_length(criteriaid) > 191 LIMIT 1"
		),
		'alterIndexLimitAdcriteria' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}adcriteria MODIFY criteriaid VARCHAR(191) NOT NULL DEFAULT ''"
		),
		'checkIndexLimitBbcode'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}bbcode WHERE char_length(bbcodetag) > 191 LIMIT 1"
		),
		'alterIndexLimitBbcode' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}bbcode MODIFY bbcodetag VARCHAR(191) NOT NULL DEFAULT ''"
		),
		'checkIndexLimitFaq'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}faq WHERE char_length(faqname) > 191 LIMIT 1"
		),
		'alterIndexLimitFaq' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}faq MODIFY faqname VARCHAR(191) BINARY NOT NULL DEFAULT ''"
		),
		'checkIndexLimitNoticecriteria'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}noticecriteria WHERE char_length(criteriaid) > 191 LIMIT 1"
		),
		'alterIndexLimitNoticecriteria' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}noticecriteria MODIFY criteriaid VARCHAR(191) NOT NULL DEFAULT ''"
		),
		'checkIndexLimitNotificationtype'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}notificationtype WHERE char_length(typename) > 191 OR char_length(class) > 191 LIMIT 1"
		),
		'alterIndexLimitNotificationtype' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}notificationtype
				MODIFY typename VARCHAR(191) NOT NULL,
				MODIFY class VARCHAR(191) NOT NULL
			"
		),
		'checkIndexLimitNotificationevent'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}notificationevent WHERE char_length(eventname) > 191 LIMIT 1"
		),
		'alterIndexLimitNotificationevent' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}notificationevent MODIFY eventname VARCHAR(191) NOT NULL"
		),
		'alterIndexLimitNotificationtype' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}notificationtype
				MODIFY typename VARCHAR(191) NOT NULL,
				MODIFY class VARCHAR(191) NOT NULL
			"
		),
		'checkIndexLimitPhrase'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}phrase WHERE char_length(varname) > 191 LIMIT 1"
		),
		'alterIndexLimitPhrase' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}phrase MODIFY varname VARCHAR(191) BINARY NOT NULL DEFAULT ''"
		),
		'checkIndexLimitStylevar'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}stylevar WHERE char_length(stylevarid) > 191 LIMIT 1"
		),
		'alterIndexLimitStylevar' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}stylevar MODIFY stylevarid VARCHAR(191) NOT NULL"
		),
		'checkIndexLimitUserstylevar'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}userstylevar WHERE char_length(stylevarid) > 191 LIMIT 1"
		),
		'alterIndexLimitUserstylevar' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}userstylevar MODIFY stylevarid VARCHAR(191) NOT NULL"
		),
		'checkIndexLimitStylevardfn'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT 1 FROM {TABLE_PREFIX}stylevardfn WHERE char_length(stylevarid) > 191 LIMIT 1"
		),
		'alterIndexLimitStylevardfn' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}stylevardfn MODIFY stylevarid VARCHAR(191) NOT NULL"
		),
		'unsetUsergroupPmpermissionsBit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}usergroup ug
				SET ug.pmpermissions = ug.pmpermissions & ~{bit}
				WHERE ug.usergroupid IN ({groupids})
			'
		),
		'setUsergroupPmpermissionsBit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}usergroup ug
				SET ug.pmpermissions = ug.pmpermissions | {bit}
				WHERE ug.usergroupid IN ({groupids})
			'
		),
		'setUserPmchatOption' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' =>
				"UPDATE {TABLE_PREFIX}user
				SET options = options | 134217728
				WHERE userid > {startat} AND userid < ({startat} + {batchsize} + 1)"
		),
		'getDatabaseCharacterSet'=> array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SELECT @@character_set_database AS db_charset"
		),
		'getOrphanedTagAssociations' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT tagnode.nodeid
				FROM {TABLE_PREFIX}tagnode AS tagnode
					LEFT JOIN {TABLE_PREFIX}node AS node ON (tagnode.nodeid = node.nodeid)
				WHERE tagnode.nodeid > {startatnodeid} AND node.nodeid IS NULL
				ORDER BY tagnode.nodeid
				LIMIT {batchsize}"
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'renameLegacyEventTable' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}event RENAME {TABLE_PREFIX}legacyevent",
		),
		'setVbforumEventPermission' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}permission
				SET createpermissions = (createpermissions | {eventbit})
				WHERE (createpermissions & {textbit}) > 0
			",
		),
		// @TODO Change QUERY_UPDATE to QUERY_ALTER when it gets working.
		'addWidgetParentid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}widget ADD COLUMN parentid INT UNSIGNED NOT NULL DEFAULT '0'",
		),
		'updateOrphanInfractions' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}infraction AS infraction
					LEFT JOIN {TABLE_PREFIX}node AS node ON (infraction.infractednodeid = node.nodeid)
				SET infraction.infractednodeid = 0
				WHERE node.nodeid IS NULL
			",
		),
		'updateOrphanReports' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}report AS report
					LEFT JOIN {TABLE_PREFIX}node AS reported_node ON (report.reportnodeid = reported_node.nodeid)
				SET report.reportnodeid = 0
				WHERE report.reportnodeid > 0 AND reported_node.nodeid IS NULL
			",
		),
		'pollFixPollVote' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}pollvote AS pollvote
					JOIN {TABLE_PREFIX}polloption AS polloption ON (pollvote.polloptionid = polloption.polloptionid)
				SET pollvote.nodeid = polloption.nodeid
				WHERE polloption.nodeid > {startat} AND polloption.nodeid < ({startat} + {batchsize} + 1)
			",
		),
		'getAlldayEventsMissingEnddates' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT *
				FROM {TABLE_PREFIX}event AS event
				INNER JOIN {TABLE_PREFIX}node AS node ON (node.nodeid = event.nodeid)
				WHERE event.allday = 1 AND event.eventenddate = 0
				ORDER BY node.userid ASC
				LIMIT {batchsize}
			",
		),
		'updateChannelProtected' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS closure
					ON closure.child = node.nodeid
				SET node.protected = {protected}
				WHERE closure.parent = {channelid}
					AND node.protected <> {protected}
			"
		),
		'updateRouteidForStarterNodeWithParentAndRoute' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS node
				SET node.routeid = {newRouteid}
				WHERE node.routeid = {oldRouteid}
					AND node.parentid = {parentid}
					AND node.nodeid = node.starter
			"
		),
		'getRequireModerateNeedingConversionCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(permissionid) AS count
				FROM {TABLE_PREFIX}permission
				WHERE skip_moderate <> 1&~require_moderate
			",
		),
		'convertRequireModerateToSkipModerate' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}permission
				SET skip_moderate = 1&~require_moderate
			",
		),

		'fixAttachmentUser' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS node
				 JOIN {TABLE_PREFIX}attachment AS attachment ON (node.oldcontenttypeid IN ({oldcontenttypeid}) AND node.oldid = attachment.attachmentid)
				SET node.userid = attachment.userid
				WHERE node.userid IS NULL AND node.nodeid >= {startat} AND node.nodeid < {nextid}
			",
		),
		'fixAttachmentUsername' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS node
				 JOIN {TABLE_PREFIX}user AS user ON (node.userid = user.userid)
				SET node.authorname = user.username
				WHERE node.oldcontenttypeid IN ({oldcontenttypeid}) AND node.authorname IS NULL AND node.nodeid >= {startat} AND node.nodeid < {nextid}
			",
		),
		'fixReplyCommentStarter' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}node AS parent
						JOIN {TABLE_PREFIX}closure AS closure ON (parent.nodeid = closure.parent)
						JOIN {TABLE_PREFIX}node child ON (closure.child = child.nodeid)
					SET child.starter = parent.starter
					WHERE
						parent.contenttypeid != {channeltypeid} AND
						parent.starter = parent.nodeid AND
						child.starter != parent.starter AND
						child.nodeid >= {startat} AND child.nodeid < {nextid}
			",
		),
		'getWidgetInstanceAdminDetails' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SHOW FULL FIELDS FROM {TABLE_PREFIX}widgetinstance LIKE 'adminconfig';
			",
		),
		'makeWidgetInstanceConfBinary' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_ALTER,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}widgetinstance MODIFY adminconfig MEDIUMTEXT
				CHARACTER SET binary NOT NULL;
		"),
		'makeWidgetInstanceConfUtf8' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_ALTER,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}widgetinstance MODIFY adminconfig MEDIUMTEXT
				CHARACTER SET utf8 NOT NULL;
		"),
		'makeWidgetInstanceConfUtf8mb4' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_ALTER,
			'query_string' => "ALTER TABLE {TABLE_PREFIX}widgetinstance MODIFY adminconfig MEDIUMTEXT
				CHARACTER SET utf8mb4 NOT NULL;
		"),

		'updtWidgetInstanceConf' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "UPDATE {TABLE_PREFIX}widgetinstance
				SET adminconfig = CAST(CAST(CAST(adminconfig AS binary) AS char CHARACTER SET latin1)
				AS char CHARACTER SET utf8)
		"),

		'updateUserchangeLogIp' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}userchangelog
				SET ipaddress = INET_NTOA(ipaddress)"
		),

		'checkUserOptionBirthdayEmails' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT userid
				FROM {TABLE_PREFIX}user
				WHERE (options & {birthdayemailmask}) = {birthdayemailmask}
				LIMIT 1
			",
		),

		'updateUserOptionBirthdayEmails' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}user
				SET options = options + {birthdayemailmask}
				WHERE NOT (options & {birthdayemailmask})
			"
		),

		'updateNotificationDateCriteria' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}noticecriteria
				SET condition3 = condition2,
					condition2 = condition1,
					criteriaid = 'is_date_range'
				WHERE criteriaid = 'is_date'
			"
		),

		// Grep Bookmark End Stored Queries
	);

	public function updatePhotoTitleAndCaption($params, $db, $check_only = false)
	{
		$expectedFields = array(
			'nodeid'	=> vB_Cleaner::TYPE_UINT,
			'caption' 	=> vB_Cleaner::TYPE_STR,
			'title' 	=> vB_Cleaner::TYPE_STR,
		);
		if ($check_only)
		{
			foreach ($expectedFields AS $key => $clean)
			{
				if (!array_key_exists($key, $params))
				{
					return false;
				}
			}
			return true;
		}

		$params = vB::getCleaner()->cleanArray($params, $expectedFields);
		$sql = "
			UPDATE " . TABLE_PREFIX . "photo AS photo
				INNER JOIN " . TABLE_PREFIX . "node AS node ON (node.nodeid = photo.nodeid)
			SET photo.caption 	= '" . $db->escape_string($params['caption']) . "',
				node.title 		= '" . $db->escape_string($params['title']) . "'
			WHERE photo.nodeid = " . $params['nodeid'] . "
		";

		$sql .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql <br />\n";
		}

		return $db->query_write($sql);
	}

	public function insertOldNotification($params, $db, $check_only = false)
	{
		$expectedFields = array(
			'recipient' 		=> vB_Cleaner::TYPE_UINT,
			'sender' 			=> vB_Cleaner::TYPE_UINT,
			'lookupid' 			=> vB_Cleaner::TYPE_STR,
			'lookupid_hashed' 	=> vB_Cleaner::TYPE_STR,
			'sentbynodeid' 		=> vB_Cleaner::TYPE_UINT,
			'typeid' 			=> vB_Cleaner::TYPE_UINT,
			'lastsenttime' 		=> vB_Cleaner::TYPE_UINT,
		);
		if ($check_only)
		{
			if (!isset($params['notifications']) OR !is_array($params['notifications']))
			{
				return false;
			}
			foreach ($params['notifications'] AS $row)
			{
				foreach ($expectedFields AS $key => $clean)
				{
					if (!array_key_exists($key, $row))
					{
						return false;
					}
				}
			}
			return true;
		}


		$cleaned = array();
		$nullables = array(
				'sender',
				'lookupid',
				'lookupid_hashed',
				'sentbynodeid',
		);
		foreach ($params['notifications'] AS $key => $row)
		{
			$clean = vB::getCleaner()->cleanArray($row, $expectedFields);
			foreach ($clean AS $field => $value)
			{
				// Because of the 'NULL' handling below, we need to pre-quote the strings.
				// It's probably safest to just assume anything not UINT should be cleaned, in case we add
				// other types of columns later.
				if ($expectedFields[$field] != vB_Cleaner::TYPE_UINT)
				{
					$clean[$field] = "'" . $db->escape_string($value) . "'";
				}
			}
			foreach ($nullables AS $field)
			{
				if (is_null($row[$field]))
				{
					// We should think of a better way to do this... but in the insert SQL string generation below,
					// this has to be string 'NULL' in order to be inserted like (1, 2, NULL, NULL, '', ...)
					$clean[$field] = 'NULL';
				}
			}
			$cleaned[] = $clean;
		}
		unset($params);


		if (!empty($cleaned))
		{
			$sql = "
INSERT INTO " . TABLE_PREFIX . "notification
	(recipient, sender, lookupid, lookupid_hashed, sentbynodeid, typeid, lastsenttime)
VALUES
";
			$valuesSql = array();
			foreach ($cleaned AS $row)
			{
				$valuesSql[] = "\n({$row['recipient']}, {$row['sender']}, {$row['lookupid']}, {$row['lookupid_hashed']}, "
								. "{$row['sentbynodeid']}, {$row['typeid']}, {$row['lastsenttime']})";
			}
			$sql .= implode(",", $valuesSql);

			$sql .= "
\nON DUPLICATE KEY UPDATE
	sender = 		IF(VALUES(lastsenttime) > lastsenttime, VALUES(sender), 		sender),
	sentbynodeid = 	IF(VALUES(lastsenttime) > lastsenttime, VALUES(sentbynodeid),	sentbynodeid),
	typeid = 		IF(VALUES(lastsenttime) > lastsenttime, VALUES(typeid), 		typeid),
	lastsenttime =  IF(VALUES(lastsenttime) > lastsenttime, VALUES(lastsenttime), 	lastsenttime)
";

			$sql .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		}
		else
		{
			return false;
		}


		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql <br />\n";
		}

		return $db->query_write($sql);
	}

	/*
	*	get users in usergroups (either primary, or additional usergroups)
	*/
	public function getUsersInUsergroups($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['usergroupids']) OR !is_array($params['usergroupids']))
			{
				return false;
			}
			return true;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'usergroupids' => vB_Cleaner::TYPE_ARRAY_UINT,
		));

		$whereSql = "";
		foreach($params['usergroupids'] AS $usergroupid)
		{
			$whereSql .= " OR FIND_IN_SET( " . intval($usergroupid) . ", user.membergroupids) ";
		}
		$sql = "SELECT user.userid FROM " . TABLE_PREFIX . "user AS user
			WHERE user.usergroupid in (" . implode($params['usergroupids'], ',') . ") " . $whereSql;

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function updateUrlIdent($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['nodes']) OR !is_array($params['nodes']))
			{
				return false;
			}
			foreach ($params['nodes'] AS $node)
			{
				if (!isset($node['nodeid']) OR !isset($node['urlident']))
				{
					return false;
				}
			}
			return true;
		}

		$caseSql = "WHEN -1 THEN '' \n";
		foreach($params['nodes'] AS $node)
		{
			$caseSql .= "WHEN " . intval($node['nodeid']) . " THEN '" . $db->escape_string($node['urlident']) . "' \n";
		}
		$updateSql = "UPDATE " . TABLE_PREFIX . "node
			SET urlident = CASE nodeid
			$caseSql ELSE urlident END";

		return $db->query_write($updateSql);
	}

	public function updateWidgetDefs($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return true;
		}
		else
		{
			$temptable = TABLE_PREFIX . 'tempids';
		}

		// Make sure temp table doesnt exist
		$db->query_write("
			DROP TABLE IF EXISTS $temptable
		");

		// Create temp table
		$db->query_write("
			CREATE TABLE $temptable (
				widgetid INT(10) NULL,
				PRIMARY KEY (widgetid)
			)
		");

		// Populate temp table with orphan widget ids
		$db->query_write("
			INSERT INTO $temptable
			SELECT widgetid
			FROM " . TABLE_PREFIX . "widgetdefinition
			LEFT JOIN " . TABLE_PREFIX . "widget USING (widgetid)
			WHERE guid IS NULL
			GROUP BY widgetid
		");

		// Delete orphan records from widgetdefinition
		$db->query_write("
			DELETE FROM " . TABLE_PREFIX . "widgetdefinition
			WHERE widgetid IN
			(
				SELECT widgetid
				FROM $temptable
			)
		");

		// Zap temp table
		$db->query_write("
			DROP TABLE $temptable
		");
	}

	/**
	 * Used to map maximumsocialgroups limit permission to the new maxchannels channel limit permission.
	 * We basically pass everything globally defined to sg channel node permissions.
	 */
	public function updateUGPMaxSGs($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			// only array to update
			if (!isset($params['groups']) OR !is_array($params['groups']) OR empty($params['groups']))
			{
				return false;
			}

			// ugp info should be ugpid => val
			foreach ($params['groups'] AS $ugpid => $param)
			{
				if (!is_numeric($ugpid))
				{
					return false;
				}

				if (!is_numeric($param))
				{
					return false;
				}
			}

			return true;
		}
		else
		{
			$sql = "UPDATE " . TABLE_PREFIX . "permission SET maxchannels = CASE groupid\n";
			foreach ($params['groups'] AS $id => $val)
			{
				$sql .= "WHEN $id THEN $val\n";
			}

			$sql .= "END
				WHERE groupid IN (" . implode(", ", array_keys($params['groups'])) . ") AND nodeid = " . vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_SOCIALGROUP_PARENT) . "
			/** getSubscriptionUsersLog" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

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

	/**
	 * Update regex for routes from vbulletin-routes.xml that have already been imported (yet still need to be updated).
	 */
	public function updateRouteRegex($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['routes']) OR !is_array($params['routes']))
			{
				return false;
			}
			foreach ($params['routes'] AS $route)
			{
				if (!isset($route['guid']) OR !isset($route['regex']))
				{
					return false;
				}
			}
			return true;
		}

		$caseSql = "WHEN -1 THEN '' \n";
		foreach($params['routes'] AS $route)
		{
			$caseSql .= "WHEN '" . $db->escape_string($route['guid']) . "' THEN '" . $db->escape_string($route['regex']) . "' \n";
		}
		$updateSql = "UPDATE " . TABLE_PREFIX . "routenew
			SET regex = CASE guid
			$caseSql ELSE regex END";

		return $db->query_write($updateSql);
	}

	public function updateConversationRouteRegex($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['routes']) OR !is_array($params['routes']))
			{
				return false;
			}
			foreach ($params['routes'] AS $route)
			{
				if (!isset($route['routeid']) OR !isset($route['regex']))
				{
					return false;
				}
			}
			return true;
		}

		$caseSql = "WHEN -1 THEN '' \n";
		foreach($params['routes'] AS $route)
		{
			$caseSql .= "WHEN " . intval($route['routeid']) . " THEN '" . $db->escape_string($route['regex']) . "' \n";
		}
		$updateSql = "UPDATE " . TABLE_PREFIX . "routenew
			SET regex = CASE routeid
			$caseSql ELSE regex END";

		return $db->query_write($updateSql);
	}

	public function tableExists($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['tablename']) AND is_string($params['tablename']));
		}

		$sql = "SHOW TABLES LIKE '" . TABLE_PREFIX . $params['tablename'] . "'";

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}


	public function getDbStructure($params, $db, $check_only = false)
	{
		//This cannot be a stored query only because the parameter tablename will be escaped.
		if ($check_only)
		{
			return (isset($params['dbName']) AND is_string($params['dbName']));
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'dbName' => vB_Cleaner::TYPE_STR,
		));

		$queryBuilder = $this->getQueryBuilder($db);
		// Note the escapeField wraps it in backticks (`)
		$dbname_clean = $queryBuilder->escapeField($params['dbName']);
		unset($params['dbName']);

		$sql = "SHOW CREATE DATABASE " . $dbname_clean;

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	public function getTableStructure($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['tablename']) AND is_string($params['tablename']));
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'tablename' => vB_Cleaner::TYPE_STR,
		));

		$queryBuilder = $this->getQueryBuilder($db);
		// Note the escapeTable prepends the table prefix & wraps the whole thing in backticks (`)
		$tablename_clean = $queryBuilder->escapeTable($params['tablename']);
		unset($params['tablename']);

		$sql = "SHOW CREATE TABLE " . $tablename_clean;

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	// add subscription records
	public function addSubscriptionRecords($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['subscriptions']) OR !is_array($params['subscriptions']))
			{
				return false;
			}
			foreach ($params['subscriptions'] AS $subscription)
			{
				if (!isset($subscription['nodeid'])OR !isset($subscription['userid']))
				{
					return false;
				}
			}
			return true;
		}

		$singleRow = array_pop($params['subscriptions']);
		$valuesSQL = "(" . intval($singleRow['userid']) . ", " . intval($singleRow['nodeid']) . ")";
		foreach($params['subscriptions'] AS $subscription)
		{
			$valuesSQL .= ",\n (" . intval($subscription['userid']) . ", " . intval($subscription['nodeid']) . ")";
		}
		$insertSQL = "INSERT INTO " . TABLE_PREFIX . "subscribediscussion
			(userid, discussionid)
			VALUES
			$valuesSQL";

		return $db->query_write($insertSQL);
	}

	public function updatePagetemplateScreenlayoutid($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['pagetemplaterecords']) OR !is_array($params['pagetemplaterecords']))
			{
				return false;
			}
			foreach ($params['pagetemplaterecords'] AS $pagetemplaterecord)
			{
				if (empty($pagetemplaterecord['pagetemplateid']) OR empty($pagetemplaterecord['screenlayoutid']))
				{
					return false;
				}
			}
			return true;
		}

		// SECURITY NOTE params are cleaned explicitly before being inserted into the MySQL query string.

		$caseSql = "\tWHEN -1 THEN '' \n";
		foreach($params['pagetemplaterecords'] AS $key => $pagetemplaterecord)
		{
			$caseSql .= "\t\t\t\tWHEN " . intval($pagetemplaterecord['pagetemplateid']) . " THEN '" . intval($pagetemplaterecord['screenlayoutid']) . "' \n";
			unset($params[$key]); // Do NOT use anything from this after this point, because we didn't clean this using the cleaner.
		}
		unset($params);	// Do NOT use anything from this after this point, because we didn't clean this using the cleaner.
		$updateSql = "
			UPDATE " . TABLE_PREFIX . "pagetemplate
			SET screenlayoutid = CASE pagetemplateid
			$caseSql
			ELSE screenlayoutid END";

		return $db->query_write($updateSql);
	}

	public function updateEventEnddates($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (!isset($params['events']) OR !is_array($params['events']))
			{
				return false;
			}
			foreach ($params['events'] AS $pagetemplaterecord)
			{
				if (empty($pagetemplaterecord['nodeid']) OR empty($pagetemplaterecord['eventenddate']))
				{
					return false;
				}
			}
			return true;
		}

		// SECURITY NOTE params are cleaned explicitly before being inserted into the MySQL query string.

		$eventStartCaseSql = "\tWHEN -1 THEN '' \n";
		$eventEndCaseSql = "\tWHEN -1 THEN '' \n";
		foreach($params['events'] AS $__key => $__data)
		{
			$eventStartCaseSql .= "\t\t\t\tWHEN " . intval($__data['nodeid']) . " THEN '" . intval($__data['eventstartdate']) . "' \n";
			$eventEndCaseSql .= "\t\t\t\tWHEN " . intval($__data['nodeid']) . " THEN '" . intval($__data['eventenddate']) . "' \n";
			unset($params[$__key]); // Do NOT use anything from this after this point, because we didn't clean this using the cleaner.
		}
		unset($params);	// Do NOT use anything from this after this point, because we didn't clean this using the cleaner.
		$updateSql = "
			UPDATE " . TABLE_PREFIX . "event
			SET eventenddate = CASE nodeid
				$eventEndCaseSql
				ELSE eventenddate END,
				eventstartdate = CASE nodeid
				$eventStartCaseSql
				ELSE eventstartdate END
			WHERE allday = 1 AND eventenddate = 0
		";

		return $db->query_write($updateSql);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103891 $
|| #######################################################################
\*=========================================================================*/
