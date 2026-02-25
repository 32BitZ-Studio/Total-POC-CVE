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
* @version $Revision: 103448 $
* @since $Date: 2019-11-15 16:25:38 -0800 (Fri, 15 Nov 2019) $

*/
class vBAdmincp_dB_MYSQL_QueryDefs extends vB_dB_MYSQL_QueryDefs
{

	/*
	 * This class is called by the vB_dB_Assertor database class
	 *
	 * It does the actual execution. See the vB_dB_Assertor class for more information
	 */

	/*Properties====================================================================*/

	//type-specific

	protected $db_type = 'MYSQL';

	protected $table_data = array();

	/**
	 * This is the definition for queries.
	 */
	protected $query_data = array(
		'updateThreadCounts' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN (
					SELECT node.starter,
						SUM(CASE WHEN node.parentid = node.starter AND (node.showpublished > 0 AND node.showapproved > 0) THEN 1 ELSE 0 END) AS textcount,
						SUM(CASE WHEN node.parentid = node.starter AND (node.showpublished = 0 OR node.showapproved = 0) THEN 1 ELSE 0 END) AS textunpubcount,
						SUM(CASE WHEN node.nodeid != node.starter AND (node.showpublished > 0 AND node.showapproved > 0) THEN 1 ELSE 0 END) AS totalcount,
						SUM(CASE WHEN node.nodeid != node.starter AND (node.showpublished = 0 OR node.showapproved = 0) THEN 1 ELSE 0 END) AS totalunpubcount,
						MAX(node.publishdate) AS lastcontent
					FROM {TABLE_PREFIX}node AS node
					WHERE node.starter between {start} and {end} AND node.contenttypeid NOT IN ({nonTextTypes})
					GROUP BY node.starter
				) AS counts
				ON node.nodeid = counts.starter
				SET node.textcount = counts.textcount,
					node.textunpubcount = counts.textunpubcount,
					node.totalcount = counts.totalcount,
					node.totalunpubcount = counts.totalunpubcount,
					node.lastcontent = counts.lastcontent
			'
		),
		'updateThreadLast' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}node AS lastcontent
					ON lastcontent.starter = node.nodeid AND lastcontent.publishdate = node.lastcontent
				SET node.lastcontentid = lastcontent.nodeid,
					node.lastcontentauthor = lastcontent.authorname,
					node.lastauthorid = lastcontent.userid
				WHERE node.starter between {start}
					AND {end}
					AND lastcontent.contenttypeid NOT IN ({nonTextTypes})
			'
		),
		'getMaxNodeid' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(nodeid) AS maxid
				FROM {TABLE_PREFIX}node
			'
		),
		'getMaxStarter' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(starter) AS maxstarter
				FROM {TABLE_PREFIX}node
			'
		),
		'getNextStarter' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT min(starter) AS next
				FROM {TABLE_PREFIX}node
				WHERE starter > {startat}
			'
		),
		'getNextChannels' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT nodeid
				FROM {TABLE_PREFIX}channel
				WHERE nodeid > {startat}
				LIMIT {blocksize}
			'
		),
		'getMaxChannel' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT max(nodeid) AS maxid
				FROM {TABLE_PREFIX}channel
			'
		),
		// Do not use this with non-channel $nodeids. The starter checks will report incorrect textcount/textunpubcount
		// if this is used with a non-channel (e.g. topic or reply) nodeid.
		'updateChannelCounts' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS channel
				INNER JOIN (
					SELECT parentid,
						SUM(CASE WHEN
									showpublished AND
									showapproved AND
									contenttypeid <> {channelTypeid}
								THEN 1 else 0
							END) AS textcount,
						SUM(CASE WHEN
									showpublished AND showapproved
									OR contenttypeid = {channelTypeid}
								THEN 0 else 1
							END) AS textunpubcount,
						SUM(totalcount) AS childcount,
						SUM(totalunpubcount) AS childunpub,
						MAX(COALESCE(lastcontent, publishdate, 0)) AS lastcontent
					FROM {TABLE_PREFIX}node
					WHERE parentid IN ({nodeids})
					GROUP BY parentid
				) AS starter ON starter.parentid = channel.nodeid
				SET channel.textcount = starter.textcount,
					channel.textunpubcount = starter.textunpubcount,
					channel.totalcount = starter.childcount + starter.textcount,
					channel.totalunpubcount = starter.childunpub,
					channel.lastcontent = starter.lastcontent
			'
		),
		'updateChannelLast' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS channel
				INNER JOIN {TABLE_PREFIX}node AS starter
					ON starter.parentid = channel.nodeid AND starter.lastcontent = channel.lastcontent
				SET channel.lastcontentid = starter.lastcontentid,
					channel.lastcontentauthor = starter.lastcontentauthor,
					channel.lastauthorid = starter.lastauthorid
				WHERE channel.nodeid IN ({nodeids})
			'
		),
		'rows_affected' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>'
				SELECT ROW_COUNT() AS qty
			'
		),

		/**
		 *	The "use index" hints force the child channel to be the driver.  This is due to the
		 *	fact that the query is looking at *all* children of the parent channels in the
		 *	closure table (even though they are implicitly filtered out in the join to the
		 *	child table we have to look at all those rows).  This way means that we look at
		 *	every row in the channel table (we'd be looking at most of them anyway) but
		 *	do not have to deal with any non channel content.  Its messy but its a lot faster
		 *	for a site with lots of content (and for a site without much content, the speed
		 *	of the query isn't going to matter).  The only situation were this is worse is a
		 *	site will tons of channels and no content -- not an optimal siutation all around.
		 */
		'getChannelTypes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT ch.guid, child.nodeid
				FROM {TABLE_PREFIX}channel AS ch USE INDEX (PRIMARY)
				INNER JOIN {TABLE_PREFIX}closure AS cl ON cl.parent = ch.nodeid
				INNER JOIN {TABLE_PREFIX}channel AS child USE INDEX () ON child.nodeid = cl.child
				WHERE ch.guid IN ({guids})
				ORDER BY child.nodeid, cl.depth DESC
			'
		),
		'getContentTypes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT DISTINCT contenttypeid
				FROM {TABLE_PREFIX}node
				ORDER BY contenttypeid
			'
		),
		'getMissingClosureParents' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT DISTINCT node.nodeid
				FROM {TABLE_PREFIX}node as node
				INNER JOIN {TABLE_PREFIX}closure AS clp ON clp.child = node.parentid
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.child = node.nodeid AND cl.parent = clp.parent
				WHERE node.nodeid >= {start}
					AND node.nodeid <= {end}
					AND cl.child IS NULL
			'
		),
		'getMissingClosureSelf' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT DISTINCT node.nodeid
				FROM {TABLE_PREFIX}node as node
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.child = node.nodeid AND cl.parent = node.nodeid
				WHERE node.nodeid >= {start}
					AND node.nodeid <= {end}
					AND cl.child IS NULL
			'
		),
		'insertMissingClosureSelf' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => '
				INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
				SELECT node.nodeid, node.nodeid, 0
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.child = node.nodeid AND cl.depth = 0
				WHERE node.nodeid IN ({nodeid})
					AND cl.child IS NULL
			'
		),
		'insertMissingClosureParent' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'query_string' => '
				INSERT INTO {TABLE_PREFIX}closure (parent, child, depth)
				SELECT clp.parent, node.nodeid, clp.depth + 1
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS clp ON clp.child = node.parentid
				LEFT JOIN {TABLE_PREFIX}closure AS cl ON cl.child = node.nodeid AND cl.parent = clp.parent
				WHERE node.nodeid IN ({nodeid})
					AND cl.child IS NULL
			'
		),
		'getMaxId' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT MAX(nodeid) AS maxid
				FROM {TABLE_PREFIX}node
			'
		),
		'getNextNode' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT min(nodeid) AS nextid
				FROM {TABLE_PREFIX}node
				WHERE contenttypeid = {contenttypeid}
					AND nodeid > {start}
			'
		),
		'getCurrentSettings' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT setting.*, sg.adminperm AS groupperm
				FROM {TABLE_PREFIX}setting AS setting
				LEFT JOIN {TABLE_PREFIX}settinggroup AS sg ON sg.grouptitle = setting.grouptitle
				WHERE varname IN ({varname})
			'
		),
		'getCMSChannels' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' =>
				'SELECT node.nodeid, node.htmltitle, node.title, node.parentid, node.showpublished, node.textcount,
					node.displayorder, node.description, closure.depth
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}closure AS closure
					ON closure.child = node.nodeid AND closure.parent = {articleChannelId}
				WHERE node.contenttypeid = {channelcontenttype}
				ORDER BY closure.depth ASC,
					CASE WHEN node.displayorder < 1 THEN 1 ELSE -1 END DESC,
					node.displayorder DESC,
					node.nodeid DESC
			'
		),
		//note that the "vbulletin" product doesn't have a formal product record so we need
		//to left join the product table and explicitly check for the vbulletin product
		'getPagesForSitemap' => array(vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT route.prefix, route.routeid, page.guid, page.pageid
				FROM {TABLE_PREFIX}routenew AS route
					INNER JOIN {TABLE_PREFIX}page AS page ON (page.routeid = route.routeid)
					LEFT JOIN {TABLE_PREFIX}product AS product ON (page.product = product.productid)
				WHERE route.class = 'vB5_Route_Page' AND
					(route.name IS NULL OR route.name NOT IN ({skipped_names})) AND
					(page.product = 'vbulletin' OR product.active = 1)
				ORDER BY page.pageid
			"
		),
		'getPagesForSitemapWithLimit' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT routenew.prefix, routenew.routeid, page.guid, page.pageid
				FROM {TABLE_PREFIX}routenew AS routenew
					INNER JOIN {TABLE_PREFIX}page AS page ON (page.routeid = routenew.routeid)
					LEFT JOIN {TABLE_PREFIX}product AS product ON (page.product = product.productid)
				WHERE routenew.class = 'vB5_Route_Page' AND
					(routenew.name IS NULL OR routenew.name NOT IN ({skipped_names})) AND
					page.pageid >= {startat} AND
					(page.product = 'vbulletin' OR product.active = 1)
				ORDER BY page.pageid
				LIMIT {perpage}
			"
		),
		'getQueuedMessageCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT COUNT(mailqueueid) AS queued
				FROM {TABLE_PREFIX}mailqueue
			'
		),
		'fixChildNodeRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => '
				UPDATE {TABLE_PREFIX}node AS starter
				INNER JOIN {TABLE_PREFIX}node AS child ON child.starter = starter.starter
				SET child.routeid = {routeid}
				WHERE starter.parentid = {nodeid}
					AND starter.starter > 0
			'
		),
		'getChannelRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.title, node.nodeid, routenew.routeid, routenew.redirect301, routenew.controller,
					routenew.prefix, routenew.arguments, routenew.guid AS routeguid, channel.guid AS channelguid
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}channel AS channel ON channel.nodeid = node.nodeid
				LEFT JOIN {TABLE_PREFIX}routenew AS routenew ON node.routeid = routenew.routeid AND routenew.class = 'vB5_Route_Channel'
				ORDER BY nodeid
			"
		),
		'getChannelPrefixes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.urlident, node.nodeid, routenew.routeid, node.parentid,
					routenew.prefix, routenew.regex, convRoute.regex AS convRegex,
					convRoute.routeid AS convRouteId
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}routenew AS routenew ON routenew.routeid = node.routeid
				INNER JOIN {TABLE_PREFIX}closure AS closure ON closure.child = node.nodeid AND closure.parent = 1
				LEFT JOIN {TABLE_PREFIX}routenew AS convRoute ON convRoute.prefix = routenew.prefix  AND convRoute.class = 'vB5_Route_Conversation'
				WHERE node.contenttypeid = {channeltype}
				ORDER BY closure.depth, routenew.prefix
			"
		),
		'getUnmatchedRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT routenew.routeid, routenew.prefix, routenew.arguments
				FROM {TABLE_PREFIX}routenew AS routenew
				LEFT JOIN {TABLE_PREFIX}node AS node ON routenew.routeid = node.routeid
				WHERE node.nodeid IS NULL
					AND routenew.class IN ('vB5_Route_Channel', 'vB5_Route_Conversation')
				ORDER BY routenew.routeid
			"
		),
		'getForumRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT routenew.*
				FROM {TABLE_PREFIX}routenew AS routenew
				WHERE routenew.class IN ('vB5_Route_Channel', 'vB5_Route_Conversation')
				ORDER BY prefix, class
			"
		),
		'getBadRedirects' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT routenew.routeid, routenew.class, routenew.arguments
				FROM {TABLE_PREFIX}routenew AS routenew
				LEFT JOIN {TABLE_PREFIX}routenew AS redirect ON redirect.routeid = routenew.redirect301
				WHERE routenew.redirect301 > 0
					AND redirect.routeid IS NULL
				ORDER BY routenew.routeid
			"
		),
		'deleteDupChannelPages' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE FROM {TABLE_PREFIX}page
				WHERE routeid = {routeid} AND pageid <> {pageid}
			"
		),
		'getConversationRouteMatch' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT routenew.*, convroute.routeid AS convrouteid,
					convroute.arguments AS convarguments, convroute.regex AS convregex
				FROM {TABLE_PREFIX}routenew AS routenew
				LEFT JOIN {TABLE_PREFIX}routenew AS convroute ON convroute.prefix = routenew.prefix  AND convroute.class = 'vB5_Route_Conversation'
				WHERE routenew.class = 'vB5_Route_Channel'
				ORDER BY routenew.prefix
			"
		),
		'getBothChannelRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT page.pageid, node.title, node.nodeid, routenew.class, chRoute.class AS channelClass,
					routenew.class, chRoute.routeid AS channelroute, routenew.routeid,
					routenew.prefix, routenew.arguments, routenew.guid AS routeguid,
					page.pageid, pagetemplate.pagetemplateid
				FROM {TABLE_PREFIX}routenew AS routenew
				LEFT JOIN {TABLE_PREFIX}page AS page ON page.routeid = routenew.routeid
				LEFT JOIN {TABLE_PREFIX}routenew AS chRoute ON chRoute.prefix = routenew.prefix  AND chRoute.class = 'vB5_Route_Channel'
				LEFT JOIN {TABLE_PREFIX}node AS node ON node.routeid = chRoute.routeid AND node.contenttypeid = {channeltype}
				LEFT JOIN {TABLE_PREFIX}pagetemplate AS pagetemplate ON pagetemplate.pagetemplateid = page.pagetemplateid
				WHERE routenew.class IN ('vB5_Route_Channel', 'vB5_Route_Conversation')
				ORDER BY prefix
			"
		),
		'getPagesWithBadRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT page.pageid
				FROM {TABLE_PREFIX}page AS page
				LEFT JOIN {TABLE_PREFIX}routenew AS routenew ON routenew.routeid = page.routeid
				WHERE routenew.routeid IS NULL
					AND page.pageid > 0
			'
		),
		'needChannelRoutes' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT node.*, channel.guid, channel.category
				FROM {TABLE_PREFIX}node AS node
				INNER JOIN {TABLE_PREFIX}channel AS channel ON channel.nodeid = node.nodeid
				WHERE node.contenttypeid = {channeltype}
					AND routeid = 0
				ORDER BY nodeid
			'
		),
		'getNextUsers' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT *
				FROM {TABLE_PREFIX}user
				WHERE userid > {startat}
				LIMIT {blocksize}
				ORDER BY userid
			'
		),
		'checkDuplicateEmails' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => '
				SELECT email, count(*) AS count
				FROM {TABLE_PREFIX}user
				GROUP BY email
				HAVING count > 1
			'
		),
		'getIndexNewStartersCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node AS node
					LEFT JOIN {TABLE_PREFIX}closure AS special ON (node.nodeid = special.child AND special.parent = {specialchannelid})
				WHERE node.open <> 10 AND node.nodeid = node.starter AND special.parent IS NULL AND created >= {starttime}
			"
		),
		'getIndexNewPostsCount' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT COUNT(*) AS count
				FROM {TABLE_PREFIX}node AS node
					LEFT JOIN {TABLE_PREFIX}closure AS special ON (node.nodeid = special.child AND special.parent = {specialchannelid})
				WHERE node.open <> 10 AND special.parent IS NULL AND inlist=1 AND created >= {starttime}
			"
		),
		'getTableStatus' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "SHOW TABLE STATUS
			"
		),
	);

	public function getTagsForAdminCount($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['synonyms_in_list']));
		}
		else
		{
			$params = $this->cleanTagsForAdminParam($params);
			$sql = $this->getTagsForAdminSql($db, 'COUNT(*) AS count', $params);
			return $this->getResultSet($db, $sql, __FUNCTION__);
		}
	}

	public function getTagsForAdmin($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['synonyms_in_list']) AND isset($params['sort']));
		}
		else
		{
			$params = $this->cleanTagsForAdminParam($params);

			$order = 'ORDER BY tag.tagtext ASC';
			if($params['sort'] == 'dateline')
			{
				$order = 'ORDER BY tag.dateline DESC';
			}
			$limit = 'LIMIT ' . $params[vB_dB_Query::PARAM_LIMITSTART] . ', ' . $params[vB_dB_Query::PARAM_LIMIT];

			$sql = $this->getTagsForAdminSql($db, 'tag.*', $params);
			$sql .= $order . "\n" . $limit . "\n";
			return $this->getResultSet($db, $sql, __FUNCTION__);
		}
	}

	private function cleanTagsForAdminParam($params)
	{
		$cleaner = vB::getCleaner();
		return $cleaner->cleanArray($params, array(
			'synonyms_in_list' => vB_Cleaner::TYPE_BOOL,
			'orphaned_only' => vB_Cleaner::TYPE_BOOL,
			'sort' => vB_Cleaner::TYPE_STR,
			vB_dB_Query::PARAM_LIMIT => vB_Cleaner::TYPE_UINT,
			vB_dB_Query::PARAM_LIMITSTART => vB_Cleaner::TYPE_UINT,
		));
	}

	private function getTagsForAdminSql($db, $fields, $params)
	{
		$where = array();
		$join = array();

		if(!$params['synonyms_in_list'])
		{
			$where['canonical_only'] = 'canonicaltagid = 0';
		}

		if($params['orphaned_only'])
		{
			//synonyms never have node associations, but we don't want to consider them "orphaned"
			$where['canonical_only'] = 'canonicaltagid = 0';
			$where[] = 'isnull(tagnode.tagid)';
			$join[] = 'LEFT JOIN ' . TABLE_PREFIX . 'tagnode AS tagnode ON (tag.tagid = tagnode.tagid)';
		}

		$sql = "
			SELECT $fields
			FROM "  . TABLE_PREFIX . "tag AS tag
		" . implode("\n", $join) . "\n";

		if($where)
		{
			$sql .= ' WHERE ' . implode(' AND ', $where)  . "\n";
		}

		return $sql;
	}


	/**
	 * Gets the damaged nodeids
	 */
	public function getDamagedNodes($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['start']) AND isset($params['end'])  AND isset($params['contenttypeid']) ;
		}
		else
		{
			$cleaner = vB::getCleaner();
			$params = $cleaner->cleanArray($params, array(
				'start' => vB_Cleaner::TYPE_UINT,
				'end' => vB_Cleaner::TYPE_UINT,
				'contenttypeid' => vB_Cleaner::TYPE_UINT
			));

			$contentLib = vB_Library_Content::getContentLib($params['contenttypeid']);
			$tables = $contentLib->fetchTableName();
			$sql = "SELECT DISTINCT node.nodeid FROM "  . TABLE_PREFIX . "node AS node \n";
			$where = array();
			foreach ($tables AS $table)
			{
				$sql .= "LEFT JOIN "  . TABLE_PREFIX . "$table AS $table ON $table.nodeid = node.nodeid\n";
				$where[] = "$table.nodeid IS NULL\n";
			}
			$sql .= "WHERE (" . implode (' OR ', $where) .")\n AND node.contenttypeid = " . $params['contenttypeid'] .
				" AND node.nodeid >= " . $params['start'] . " AND node.nodeid <=" .
				$params['end'] . "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$config = vB::getConfig();
			if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
			{
				echo "sql: $sql<br />\n";
			}
			$result = new $resultclass($db, $sql);

			return $result;
		}
	}

	/**
	 * Gets CMS Content nodes
	 */
	public function getFullFilteredCMSContentNodeids($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['channelids']) AND is_array($params['channelids']));
		}
		else
		{
			$cleaner = vB::getCleaner();
			$setParamKeys = array_keys($params);
			$params = $cleaner->cleanArray($params,
				array(
					'channelids' => vB_Cleaner::TYPE_ARRAY_INT,
					// filters
					'contenttypeid' => vB_Cleaner::TYPE_UINT,	// int, can't be zero (empty)
					'authorname' => vB_Cleaner::TYPE_STR,
					'tag' => vB_Cleaner::TYPE_UINT,	// tagid
					'showpublished' => vB_Cleaner::TYPE_UINT,	// int, can be zero
					'public_preview' => vB_Cleaner::TYPE_UINT,	// int, can be zero
					'publishdate' => vB_Cleaner::TYPE_NOCLEAN, // array('op' => str, 'value' => int)
					'viewcount' => vB_Cleaner::TYPE_NOCLEAN, // array('op' => str, 'value' => int), NOT NODE TABLE
					'textcount' => vB_Cleaner::TYPE_NOCLEAN, // array('op' => str, 'value' => int)
				)
			);
			// we don't want unpassed values to be inserted into the params array, so unset them here
			// Otherwise, (!empty($params[$key])) doesn't play nicely with values that can be zeros like showpublished & public_preview
			foreach ($params AS $key => $value)
			{
				if (!in_array($key, $setParamKeys))
				{
					unset($params[$key]);
				}
			}

			// array cleaning
			foreach (array('publishdate', 'views', 'comments') AS $key)
			{
				if (isset($params[$key]) AND is_array($params[$key]) AND isset($params[$key]['op']) AND isset($params[$key]['value']))
				{
					$params[$key] = array(
						'op' => $cleaner->clean($params[$key]['op'],  vB_Cleaner::TYPE_STR),
						'value' => $cleaner->clean($params[$key]['value'],  vB_Cleaner::TYPE_INT),
					);
				}
				else
				{
					unset($params[$key]);
				}
			}


			$filters = array();
			$opMapping = array('eq' => ' = ', 'gt' => ' > ', 'lt' => ' < ');
			// nodefields, equal-to filters
			foreach (array('contenttypeid', 'authorname', 'showpublished', 'public_preview') AS $key)
			{
				if (isset($params[$key]))
				{
					$filters['where'][] = "\tnode." . $key . " = '" . $params[$key] . "'\n";
				}
			}
			// nodefields, selective operation filters
			foreach (array('publishdate', 'textcount') AS $key)
			{
				if (!empty($params[$key]))
				{
					$filters['where'][] = "\tnode." . $key . $opMapping[$params[$key]['op']] . "'" . $params[$key]['value'] . "'\n";
				}
			}
			// tags, equal-to filters
			if (!empty($params['tag']))
			{
				// performance note:
				// there should only be a single row in tagnode with the nodeid & tagid combination,
				// so this *should* not result in duplicate rows, allowing us to not use GROUP BY
				$filters['join'][] = "INNER JOIN " . TABLE_PREFIX . "tagnode AS tagnode_filter \n" .
									"ON tagnode_filter.nodeid = node.nodeid AND tagnode_filter.tagid = '" . $params['tag'] . "'";
			}
			// viewcount, condition on nodeview table
			if (!empty($params['viewcount']))
			{
				//$filters['join'][] = "LEFT JOIN " . TABLE_PREFIX . "nodeview AS nodeview" .
				//					"ON nodeview.nodeid = node.nodeid \n";
				$filters['where'][] = "\t IFNULL(nodeview.count, 0)" . $opMapping[$params['viewcount']['op']] . "'" . $params['viewcount']['value'] . "'\n";
			}

			// glue together
			if (!empty($filters['where']))
			{
				$filters['where'] = "AND\t" . implode("AND\t", $filters['where']);
			}
			else
			{
				$filters['where'] = '';
			}
			if (!empty($filters['join']))
			{
				$filters['join'] = implode("\n", $filters['join']) . "\n";
			}
			else
			{
				$filters['join'] = '';
			}

			// exclude channels, we want content only
			$channeltypeid = vB_Api::instanceInternal('ContentType')->fetchContentTypeIdFromClass('Channel');

			// build up SQL
			$sql = "SELECT node.nodeid, node.taglist, node.publishdate, \n" .
					"node.title, node.htmltitle, node.parentid, node.showpublished, node.public_preview, \n" .
					"node.authorname, node.userid, node.displayorder, node.textcount, \n" .
					"node.routeid, node.contenttypeid, IFNULL(nodeview.count, 0) AS viewcount \n" .
					"FROM "  . TABLE_PREFIX . "node AS node \n" .
					"LEFT JOIN " . TABLE_PREFIX . "nodeview AS nodeview \n" .
									"ON nodeview.nodeid = node.nodeid \n";
			$sql .= $filters['join'];


			$sql .= "WHERE node.parentid IN (" . implode(',', $params['channelids']) . ") AND node.contenttypeid <> " . $channeltypeid . " AND node.nodeid = node.starter \n" .
				$filters['where'];

			// The CASE in the ORDER BY code is necessary to force displayorder=0 to the end of the list.
			$sql .= "ORDER BY CASE WHEN  node.displayorder < 1 THEN 1 ELSE -1 END ASC, node.displayorder ASC \n" .
						""; //	"LIMIT " . ($params['perpage'] * ($params['page'] - 1)) . ", " . $params['perpage'] . "\n";

			$sql .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

			$resultclass = 'vB_dB_' . $this->db_type . '_result';
			$config = vB::getConfig();

			if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
			{
				echo "sql: $sql<br />\n";
			}

			$result = new $resultclass($db, $sql);

			return $result;
		}
	}

	/*
	 *	Grab all starters visible for guests.
	 *	Unfortunately, I don't think the clauses returned by getNodePermTerms gives me a way to
	 *	grab channels as well... So at the moment, vB_SiteMap_Node->generate_sitemap() fetches the
	 *	channels separately
	*/
	public function getGuestVisibleNodes($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (isset($params['startat']) AND isset($params['perpage']));
		}
		else
		{
			$cleaner = vB::getCleaner();
			$params = $cleaner->cleanArray($params, array(
				'startat' => vB_Cleaner::TYPE_UINT,
				'perpage' => vB_Cleaner::TYPE_UINT,
			));

			//requires a join to the starter node table (with alias starter);
			$permflags = $this->getNodePermTerms(false, 0);

			// exclude channels, we want content only
			$channeltypeid = vB_Api::instanceInternal('ContentType')->fetchContentTypeIdFromClass('Channel');
			$pmid = vB_Api::instanceInternal('ContentType')->fetchContentTypeIdFromClass('PrivateMessage');

			// build up SQL
			$sql = "SELECT node.routeid, node.nodeid, node.lastcontent, node.parentid, node.urlident, \n" .
					"\troutenew.prefix, routenew.ishomeroute, routenew.arguments \n" .
				"FROM " . TABLE_PREFIX . "node AS node \n" .
					"INNER JOIN " . TABLE_PREFIX . "node AS starter ON starter.nodeid = node.starter AND starter.nodeid = node.nodeid \n" .
					"INNER JOIN " . TABLE_PREFIX . "routenew AS routenew ON routenew.routeid = node.routeid \n" .
				"WHERE node.contenttypeid <> $pmid \n" .
					$permflags['where'] .
				"AND node.nodeid >= ".$params['startat'] . " LIMIT " .$params['perpage'] ." \n";

			$sql .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

			return $this->getResultSet($db, $sql);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103448 $
|| #######################################################################
\*=========================================================================*/
