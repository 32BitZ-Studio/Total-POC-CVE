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
 * The vB core class.
 * Everything required at the core level should be accessible through this.
 *
 * The core class performs initialisation for error handling, exception handling,
 * application instatiation and optionally debug handling.
 *
 * @TODO: Much of what goes on in global.php and init.php will be handled, or at
 * least called here during the initialisation process.  This will be moved over as
 * global.php is refactored.
 *
 * @package vBulletin
 * @version $Revision: 103395 $
 * @since $Date: 2019-11-06 17:16:44 -0800 (Wed, 06 Nov 2019) $
 */
class vBDBSearch_dB_MYSQL_QueryDefs extends vB_dB_MYSQL_QueryDefs
{
	/**
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
	 *
	 **/
	/** @TODO remove this line when debugging is not required so often anymore */
	const DEBUG = false;
	/*Properties====================================================================*/
	private static $temp_table_created = false;
	protected $db_type = 'MYSQL';

	/**
	 * This is the definition for tables we will process through.  It saves a
	 * database query to put them here.
	 */
	protected $table_data = array(
		'words' => array(
			'key' => 'wordid',
			'structure' => array('wordid', 'word'),
			'forcetext' => array('word')
		),
		'searchlog' => array(
			'key' => 'searchlogid',
			'structure' => array('searchlogid','userid','ipaddress','searchhash','sortby','sortorder','searchtime','dateline','completed','json','results','results_count'),
			'forcetext' => array('searchhash')
		),
		'tagsearch' => array(
			'key' => 'tagid',
			'structure' => array('tagid','dateline')
		),
		/**
		 * searchtowords_x table data is populated in the constructor
		 */
	);

	/**
	 * This is the definition for queries we will process through.  We could also
	 * put them in the database, but this eliminates a query.
	 */
	protected $query_data = array(
		// Keep below in sync with the join in  vBDBSearch_dB_MYSQL_QueryDefs->process_marked_filter().
		// If this is expected to change often, we should refactor this out into a common location to reduce maintenance effort
		// The reason it doesn't have the markinglimit publishdate cutoffs is because that's already done in sphinx, and only
		// nodeids that are newer than markinglimit & satisfies other sphinx filters should get to this query.
		'getUnreadNodesIn' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "
				SELECT node.nodeid
				FROM {TABLE_PREFIX}node AS node
				LEFT JOIN (
					SELECT read_closure.child AS nodeid
					FROM {TABLE_PREFIX}node AS node
					USE INDEX (node_pubdate)
					INNER JOIN {TABLE_PREFIX}closure AS read_closure
						ON node.nodeid = read_closure.child
					INNER JOIN {TABLE_PREFIX}noderead AS noderead
					ON noderead.nodeid = read_closure.parent
						AND noderead.userid = {currentuserid}
					WHERE node.nodeid IN ({nodeids})
					AND node.publishdate <= noderead.readtime
					GROUP BY (read_closure.child)
				) AS noderead ON noderead.nodeid = node.nodeid
				WHERE noderead.nodeid IS NULL AND node.nodeid IN ({nodeids})
				LIMIT {limit}"
		),

		'addNewTrendingTopics' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				INSERT IGNORE INTO {TABLE_PREFIX}trending(nodeid, weight)
				SELECT nodeid, 0
				FROM {TABLE_PREFIX}node AS node
					LEFT JOIN {TABLE_PREFIX}closure AS special ON (node.nodeid = special.child AND special.parent = {specialchannelid})
				WHERE special.parent IS NULL AND node.lastcontent >= {timecut} AND
					node.nodeid = node.starter AND node.contenttypeid NOT IN ({excludetypes})
			"
		),

		'deleteOldTrendingTopics' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'query_string' => "
				DELETE trending
				FROM {TABLE_PREFIX}trending AS trending JOIN {TABLE_PREFIX}node AS node ON (trending.nodeid = node.nodeid)
				WHERE node.lastcontent < {timecut}
			"
		),

		/*
		 *	This needs explanation.
		 *
		 *	We're trying to calculate the posts/hour for the topics in the trending table.
		 *	This requires the counts.  We join to a subquery because the updates have *all*
		 *	kinds of restrictions no using tables in other context.  That get any children
		 *	that are "in list" (replies and comments) within the lookback period.  We also
		 *	make sure the the staters are updated within the lookback period to trim the
		 *	query set (we don't bother with excluding "special" because that's extra work
		 *	and the join with trending will filter out anything we don't want captured)
		 *
		 *	The weight is calculated as "posts/hour" with a couple of twists.
		 *
		 *	First we consider the timespan we're looking at to be either the lookback period
		 *	OR the lifetime of the topic whichever is shorter (this gives a boost to recent
		 *	topics that haven't had as much time to garther large numbers of posts).
		 *
		 *	Second we set a minimum for the timespan (based on configuration passed to us)
		 *	This prevents a new topic from getting elevated simply because it's new and
		 *	thus a couple of posts turns into an ungodly number of posts/hour.  We already
		 *	have a recent topics feature, this is intended to show topics with some momentum.
		 */

		//DO NOT CONTEMPLATE CHANGING THIS QUERY WITHOUT UNDERSTANDING THE NEXT QUERY

		'setTrendingWeights' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'query_string' => "
				UPDATE {TABLE_PREFIX}trending AS trending
					JOIN {TABLE_PREFIX}node AS node ON (trending.nodeid = node.nodeid)
					LEFT JOIN (
						SELECT starter.nodeid, COUNT(*) AS count
						FROM {TABLE_PREFIX}node AS starter
							JOIN {TABLE_PREFIX}node AS reply ON (starter.nodeid = reply.starter)
						WHERE
							starter.lastcontent >= {timecut} AND
							starter.contenttypeid NOT IN ({excludetypes}) AND
							reply.created >= {timecut} AND
							reply.inlist = 1
						GROUP BY 1
					) AS counts ON (trending.nodeid = counts.nodeid)
				SET trending.weight = (IFNULL(counts.count, 0) /
					GREATEST({minlifetime}, ({timenow} - GREATEST(node.created, {timecut})) / 3600)) * 1000
			"
		),


	  /*
		 *	This is technically for sphinx ... but sphinx search is currently linked at the hip
		 *	with db search, doesn't have its own query file, and most importantly this absolutely
		 *	needs to be kept in sync with the query above or bad things will happen.  So
		 *	having it *right* *here* is beneficial.
		 *
		 *	We need to exclude special directly here because we don't have the insert query to rely on.
		 */
		'getTrendingWeights' => array(
			vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'query_string' => "
				SELECT node.nodeid,
					((IFNULL(counts.count, 0) / GREATEST({minlifetime}, ({timenow} - GREATEST(node.created, {timecut})) / 3600)) * 1000) AS weight
				FROM {TABLE_PREFIX}node AS node
					LEFT JOIN {TABLE_PREFIX}closure AS special ON (node.nodeid = special.child AND special.parent = {specialchannelid})
					LEFT JOIN (
						SELECT starter.nodeid, COUNT(*) AS count
						FROM {TABLE_PREFIX}node AS starter
							JOIN {TABLE_PREFIX}node AS reply ON (starter.nodeid = reply.starter)
						WHERE
							starter.lastcontent >= {timecut} AND
							starter.contenttypeid NOT IN ({excludetypes}) AND
							reply.created >= {timecut} AND
							reply.inlist = 1
						GROUP BY 1
					) AS counts ON (node.nodeid = counts.nodeid)
				WHERE special.parent IS NULL AND node.lastcontent >= {timecut} AND
					node.nodeid = node.starter AND node.contenttypeid NOT IN ({excludetypes})
			"
		),

		// Get an explicit list of channels to include for the inc_exc_channel filter
		'getDescendantChannelsIn' => array(
				vB_dB_Query::QUERYTYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'query_string' => "
				SELECT channel.nodeid
				FROM {TABLE_PREFIX}channel AS channel
				INNER JOIN {TABLE_PREFIX}closure AS closure
					ON channel.nodeid = closure.child
				WHERE closure.parent IN ({include_channels})"
		),
	);

	public function __construct()
	{
		$prefixes = vBDBSearch_Core::get_table_name_suffixes();
		foreach ($prefixes as $prefix)
		{
			$tablename = 'searchtowords_' . $prefix;
			if (array_key_exists($tablename, $this->table_data))
			{
				continue;
			}
			$this->table_data[$tablename] = array(
				'key' => array('wordid','nodeid'),
				'structure' => array('wordid', 'nodeid', 'is_title', 'score', 'position')
			);
		}
	}

	public function getSearchResults($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['criteria']);
		}
		//No cleaning done we only expect the criteria object

		$this->db = $db;
		$criteria = &$params['criteria'];
		$cacheKey = $params['cacheKey'];

		$this->filters = array(
			'make_equals_filter'    => $criteria->get_equals_filters(),
			'make_notequals_filter' => $criteria->get_notequals_filters(),
			'make_range_filter'     => $criteria->get_range_filters(),
			'complex'               => $criteria->get_complex_filters(),
		);

		$this->process_sort($criteria);

		$this->process_keywords_filters($criteria);

		if (!empty($this->filters['make_equals_filter']['view']))
		{
			$this->process_view_filters($this->filters['make_equals_filter']['view'], $criteria);
			unset($this->filters['make_equals_filter']['view']);
		}

		if (!empty($this->filters['make_equals_filter']['follow']))
		{
			$this->process_follow_filters($this->filters['make_equals_filter']['follow'], $criteria);
			unset($this->filters['make_equals_filter']['follow']);
		}

		// channel
		if (!empty($this->filters['make_equals_filter']['my_channels']))
		{
			$this->process_my_channels_filter($this->filters['make_equals_filter']['my_channels']);
			unset($this->filters['make_equals_filter']['my_channels']);
		}

		// channel include exclude
		if (!empty($this->filters['complex']['inc_exc_channel']))
		{
			$this->process_inc_exc_channel_filter($this->filters['complex']['inc_exc_channel']);
			unset($this->filters['complex']['inc_exc_channel']);
		}

		//handle equals filters
		$this->process_filters($criteria, 'make_equals_filter', $db, $cacheKey ? true : false);
		//handle notequals filters
		$this->process_filters($criteria, 'make_notequals_filter', $db, $cacheKey ? true : false);
		//handle range filters
		$this->process_filters($criteria, 'make_range_filter', $db, $cacheKey ? true : false);

		$query_joins = "";
		if (count($this->join))
		{
			$query_joins = implode(" \n\t\t\t\t", $this->join) . " ";
		}
		if (!$this->done_permission_check)
		{
			$permflags = $this->getNodePermTerms($cacheKey ? true : false);
			if ((strpos($query_joins, 'AS starter') !== false) AND (!empty($permflags['joins']['starter'])))
			{
				//we don't need the starter join. We already have that.
				unset($permflags['joins']['starter']);
			}

			if (!empty($permflags['joins']))
			{
				$query_joins .= " \n\t\t\t\t" . implode("\n", $permflags['joins']) . "\n";
			}
		}
		else
		{
			$permflags = array('joins' => false, 'where' => false);
		}
		$query_where = "";
		if (count($this->where))
		{
			$query_where = "WHERE " . implode(" AND \n\t\t\t\t", $this->where);
		}
		else if (!empty($permflags['where']))
		{
			$query_where = " WHERE " ;
		}
		$query_where .= $permflags['where'] . "\n";

		$query_limit = false;
		if (!$criteria->getNoLimit())
		{
			if ($criteria->getLimitCount() > 0)
			{
				$query_limit = "LIMIT " . intval($criteria->getLimitOffset()) . ", " . intval($criteria->getLimitCount());
			}
			else
			{
				$maxresults = vB::getDatastore()->getOption('maxresults');
				$maxresults = ($maxresults > 0) ? $maxresults : 0;
				if (!empty($maxresults))
				{
					$query_limit = "LIMIT " . $maxresults;
				}
			}
		}

		$query_what = $this->what;

		// Add starter info to result set so that we know what to remove for the second pass.
		if ($cacheKey)
		{
			$userdata = vB::getUserContext()->getAllChannelAccess();
			if (!empty($userdata['selfonly']))
			{
				$query_what .= ", starter.parentid, starter.userid";
				if (strpos($query_joins, 'node AS starter') === false)
				{
					$query_joins .= "\nLEFT JOIN " . TABLE_PREFIX . "node AS starter ON starter.nodeid = IF(node.starter = 0, node.nodeid, node.starter)\n";
				}
			}
		}

		$ordercriteria = array();
		$union_what = array($query_what);
		$union_order = array();

		if ($criteria->get_include_sticky())
		{
			if (!empty($this->join['closure']))
			{
				$ordercriteria[] = 'closure.depth ASC';
			}
			$ordercriteria[] = 'node.sticky DESC';
			$union_what[] = 'node.sticky';
			$union_order[] = 'sticky DESC';
		}


		// Additional, complex expressions we need to select in order to ORDER BY.
		// For simple SELECTs, we can currently just ORDER BY expressions in mysql & mariadb, but
		// I think we still need this because we cannot ORDER BY unselected columns in UNIONs
		if (!empty($this->sortable_what))
		{
			foreach ($this->sortable_what AS $__sortkey => $__column)
			{
				$query_what .= ", " . $__column;
				$union_what[] = $__column;
			}
		}

		foreach ($this->sort AS $field => $dir)
		{
			//fall back to default search when no table is joined in that contains score fields
			if ($field == 'rank' AND strpos($query_joins, 'temp_search') === false AND strpos($query_joins, 'searchtowords_') === false)
			{
				$field = 'node.created';
			}

			if ($field === "isstarter")
			{
				$ordercriteria[] = 'isstarter ' . $dir;
				$union_order[] = 'isstarter ' . $dir;
			}
			else if ($field != 'rank')
			{
				/*
					I'm guessing the whole array_pop($field_pieces) logic was done to handle the
					"Table 'node' from one of the SELECTs cannot be used in global ORDER clause"
					mysql error, but I don't think the current solution is quite complete.
					Hypothetically (we wouldn't currently have this), if we had something like
					 (SELECT node.nodeid, node.publishdate, closure.publishdate ...)
					 UNION
					 ...
					 (SELECT node.nodeid, node.publishdate, closure.publishdate ...)
					 ORDER BY publishdate;
					That publishdat in the ORDER clause would be ambiguous and mysql would throw
					an error. We should probably fully disambiguate the columns with an alias and
					order by that alias so that this disambiguation is complete.
					I don't think this has been a problem right now because we very rarely have
					selects complex enough where we're selecting ambiguous columns for sorting
					(and we usually only select node.nodeid unless we're adding columns for
					sorting purposes...), but it may bite us later if we expand the
					$this->sortable_what logic that was added recently.
					The sortable_what logic was added in order to handle the "isstarter" sorting
					as a "proper" sort field instead of (previously) always tacking it onto the
					"include_starter" filter condition, as always sorting by isstarter when we're
					just trying to include starters or searching only for starters causes serious
					performance issues for search modules.
					The isstarter sorting was meant mainly for fetching a single topic tree, then
					guaranteeing that the starter of that topic was first, before any replies,
					even if certain operations resulted in the starter having a later created
					date (or other sortables) than the replies.
					Search modules are generally looking much broader than a single topic, and
					usually doesn't care about starters being before replies (or is sometimes ONLY
					fetching starters/topics to begin with), but the inclusion of the isstarter
					in the ordering prevents mysql being able to utilize LIMIT optimizations.

					All that said, I think it's out of scope to touch this logic now when I'm just
					trying to clean up over-usage of the "isstarter" sorting, so I'm just leaving
					this wall of text as kind of a todo.
				 */
				$ordercriteria[] = $field . " " . $dir;
				$field_pieces = explode('.', $field);
				// We may have already added a "complex" select column to union_what, e.g.
				//   IF(node.nodeid = node.starter, 1, 0) as isstarter
				// so we don't want to add an incorrect, duplicate sort column, e.g.
				//   IF(node.nodeid = node.starter, 1, 0) as isstarter, ..., isstarter
				// in such a case.
				if (!isset($this->sortable_what[$field]))
				{
					$union_what[] = $field;
				}
				$union_order[] = array_pop($field_pieces) . " " . $dir;
			}
			else
			{
				//we need to use the temporary table to compute the final score
				if (!empty($this->join['temp_search']) AND strpos($this->join['temp_search'], 'temp_search AS temp_search'))
				{
					$scorefield = "(
						score *
						(words_nr / (words_nr + " . $this->occurance_factor. ")) *
						GREATEST(1, 5 - ((UNIX_TIMESTAMP() - node.created)/" . $this->date_factor . ")) *
						IF(is_title > 0 , " . $this->title_boost . ", 1) / GREATEST(
							(4 * (words_nr - 1) / distance) + 1
							, 1)
					)";
				}
				else // we can compute the score using the searchtowords table
				{
					$scorefield = "(
					score *
					GREATEST(1, 5 - ((UNIX_TIMESTAMP() - node.created)/" . $this->date_factor . ")) *
					IF(is_title > 0 , " . $this->title_boost . ", 1))";
				}
				$ordercriteria[] = $scorefield . $dir;
				$union_what[] = $scorefield . ' AS `rank`';
				$union_order[] = '`rank` ' . $dir;
			}
		}
		/*
		This was initially removed because this prevents usage of the (parentid, inlist, lastcontent) sorting for
		topic list fetching (widget_channeldisplay, vB_Api_Search::getChannelTopics()).
		Basically, for most default sorting of fetching a channel's topics, we need a
			ORDER BY node.lastcontent DESC, node.nodeid ASC
			LIMIT ...
		but we cannot have a descending (or opposite order) composite index (... lastcontent [ASC], nodeid DESC)
		until mysql 8, and we have not fully dropped support for older mysql versions yet.
		As such, if we're trying to take advantage of the SORT..LIMIT utilizing the composite index, we cannot have
		multiple sorts going in the opposite order.

		It was then added back because unittests (that add a lot of nodes at the same time) depend on this sorting
		for its tests, and that also suggests that there might be other areas where this might be important (e.g.
		default nodes imported during an upgrade/install, which often have the same created dates).
		*/
		$hint = "";
		if ($criteria->getSearchContext() === "channeldisplay")
		{
			/*
			An index with a parentid in it, like
				node_parent_inlist_lastcontent(parentid, inlist, lastcontent),
			is much more useful for "default" channeldisplay queries that are of the form
				...
				WHERE node.parentid = {channelid} ...
				ORDER BY node.lastcontent DESC.
			However, without the node.nodeid ASC secondary sorting, the optimizer sometimes
			decides to use the
				node_lastcontent(lastcontent),
			index, which is 10-100 times worse in testing (3s vs 0.03-0.3s).
			As such, let's hint the optimizer to *not* use that index for channeldisplay queries.
			NOTE: This is currently ignored for UNIONs due to lack of use/test cases in the
			channeldisplay context.
			 */
			$hint = "IGNORE INDEX (node_lastcontent)";
		}

		// we need to use union in some case to be able to take advantage of the table indexes
		if (!empty($this->union_condition))
		{
			$unions = array();
			$counter = 0;
			foreach ($this->union_condition AS $conditions)
			{
				$qjoins = $query_joins;
				// we need to duplicate the temp_search table because in mysql you can have only one instance of a temp table in query
				if ($counter > 0 AND strpos($query_joins, 'temp_search AS temp_search') !== false)
				{
					$tablename = "temp_search$counter";
					if ($this->db->query_first("SHOW TABLES LIKE '" . TABLE_PREFIX . "$tablename'"))
					{
						$this->db->query_write($query = "TRUNCATE TABLE " . TABLE_PREFIX . $tablename);
					}
					else
					{
						$this->db->query_write($query = "CREATE TABLE " . TABLE_PREFIX . "$tablename LIKE " . TABLE_PREFIX . "temp_search");
					}
					$this->db->query_write($query = "INSERT INTO " . TABLE_PREFIX . "$tablename SELECT * FROM " . TABLE_PREFIX . "temp_search");
					$qjoins = str_replace('temp_search AS temp_search', "$tablename AS temp_search", $query_joins);
				}
				$unions[] = "
			(
				SELECT " . implode(", ", $union_what) . "
				FROM " . TABLE_PREFIX . $this->from . "
				$qjoins
				" . $query_where . "\t\t\t\tAND " . implode(" AND \n\t\t\t\t", $conditions) . "
			)";
				$counter ++;
			}
			$query = implode("\n\t\t\tUNION", $unions) . "
			" . ($criteria->getDoCount() ? "" : "ORDER BY " . implode(',', $union_order));
		}
		else
		{
			$query = "
			SELECT $query_what
			FROM " . TABLE_PREFIX . $this->from . "
			$hint
			$query_joins
			$query_where "
			. ($criteria->getDoCount() ? "" : "
			ORDER BY " . implode(',', $ordercriteria));
		}
		$query .= "
			$query_limit
			" . "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$resultclass = 'vB_dB_' . $this->db_type . '_Result';
		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		$useSlave = false;
		$buffered = false;
		$results = new $resultclass($db, $query, $useSlave, $buffered);

		return $results;
	}

	public function getNodesWithSubChannel($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['nodeids']);
		}
		$params = vB::getCleaner()->cleanArray($params, array(
			'nodeids' => vB_Cleaner::TYPE_ARRAY_UINT,
		));

		$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');

		$query = "
					SELECT IF( node.contenttypeid = $channelcontentypeid, channelnode.nodeid, node.nodeid ) AS nodeid
					FROM " . TABLE_PREFIX . "node as node
					JOIN " . TABLE_PREFIX . "closure AS channel_closure ON (node.nodeid = channel_closure.parent)
					LEFT JOIN " . TABLE_PREFIX . "node AS channelnode ON (
						node.contenttypeid = $channelcontentypeid AND
						channelnode.nodeid = channel_closure.child AND
						channelnode.nodeid <> channel_closure.parent
					)
					WHERE
					" . $this->make_equals_filter('node', 'nodeid', $params['nodeids']) . " AND
						(
							node.contenttypeid <> $channelcontentypeid OR
							channelnode.nodeid IS NOT NULL
						)";
		$resultclass = 'vB_dB_' . $this->db_type . '_Result';
		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']))
		{
			echo "$query;\n";
		}

		return new $resultclass($db, $query);
	}

	public function PostProcessorAddComments($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['nodeids']) AND !empty($params['criteria']);
		}

		$params = vB::getCleaner()->cleanArray($params, array(
				'criteria' => vB_Cleaner::TYPE_NOCLEAN,
				'nodeids' => vB_Cleaner::TYPE_ARRAY_UINT,
		));
		$this->db = $db;
		$this->process_sort($params['criteria']);
		$this->process_keywords_filters($params['criteria']);

		$query_joins = "";
		if (count($this->join))
		{
			$query_joins = implode(" \n\t\t\t\t", $this->join) . " ";
		}

		$query_where = "WHERE " . $this->make_equals_filter('node', 'parentid', $params['nodeids']);

		if (count($this->where))
		{
			$query_where .= ' AND ' . implode(" AND \n\t\t\t\t", $this->where);
		}

		$query = "
		(SELECT node.nodeid
			FROM " . TABLE_PREFIX . "node AS node
			WHERE " . $this->make_equals_filter('node', 'nodeid', $params['nodeids']) . "
		)UNION(
		SELECT node.nodeid
			FROM " . TABLE_PREFIX . "node AS node
			$query_joins
			$query_where
		) \n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$resultclass = 'vB_dB_' . $this->db_type . '_Result';
		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		// Use unbuffered queries to reduce memory allocations for large nodeids.
		$useSlave = false;
		$buffered = false;
		return new $resultclass($db, $query, $useSlave, $buffered);
	}

	public function cacheResults($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			if (isset($params['fields']) /*AND isset($params['user'])*/)
			{
				return true;
			}
			return false;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
				'fields' => vB_Cleaner::TYPE_ARRAY
		));

		$fields = array_keys($params['fields']);
		$values = $params['fields'];

		vB::getCleaner()->clean($fields, vB_Cleaner::TYPE_ARRAY_STR);
		vB::getCleaner()->clean($values, vB_Cleaner::TYPE_ARRAY_STR);

		$db->query_write("
			REPLACE INTO " . TABLE_PREFIX . "searchlog
				(" . implode(',', $fields) . ")
			VALUES
				(" . implode(',', self::quote_smart($values)) . ")
		");

		return $db->insert_id();
	}

	/**
	 * gets the list of ids for indexed words in a text
	 * @param int $nodeid
	 * @return array word ids
	 */
	public function fetch_indexed_words($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return isset($params['nodeid']);
		}

		$type = vB_Cleaner::TYPE_UINT;
		if(is_array($params['nodeid']))
		{
			$type = vB_Cleaner::TYPE_ARRAY_UINT;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'nodeid' => $type
		));

		$nodeids = $params['nodeid'];
		if(!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$suffixes = vBDBSearch_Core::get_table_name_suffixes();

		$unions = array();
		foreach ($suffixes as $suffix)
		{
			$unions[] = "
				SELECT $suffix.*, '$suffix' as suffix
				FROM " . TABLE_PREFIX . "searchtowords_$suffix AS $suffix
				WHERE $suffix.nodeid IN (" . implode(',', $nodeids) . ")";
		}
		$query = implode("\nUNION ALL\n", $unions);
		return $this->getResultSet($db, $query, __FUNCTION__);
	}

	public function updateSearchtowords($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['suffix']) AND !empty($params['nodeid']) AND !empty($params['wordid']);
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'suffix' => vB_Cleaner::TYPE_STR,
			'nodeid' => vB_Cleaner::TYPE_UINT,
			'wordid' => vB_Cleaner::TYPE_UINT,
			'score' => vB_Cleaner::TYPE_NUM,
			'is_title' => vB_Cleaner::TYPE_BOOL,
			'position' => vB_Cleaner::TYPE_UINT
		));

		$accepted_fields = array('score', 'is_title','position');
		$fields = array_intersect_key($params, array_flip($accepted_fields));
		if (empty($fields))
		{
			return false;
		}

		$field_values = array();
		foreach ($fields as $key => $value)
		{
			$field_values[] = $key . '=' . $this->quote_smart($value);
		}

		$sql = "
				UPDATE " . TABLE_PREFIX . "searchtowords_" . $params['suffix']. "
				SET
					" . implode(",\n\t\t\t\t\t", $field_values) . "
				WHERE
					wordid = " . intval($params['wordid']) . " AND
					nodeid = " . intval($params['nodeid']) . "
		" . "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$sql;\n";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	/**
	 * Inserts multiple words into the "words" table, ignoring any that
	 * already exist.
	 */
	public function insertWords($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['words']);
		}

		if (empty($params['words']))
		{
			return false;
		}

		$params = vB::getCleaner()->cleanArray($params, array(
			'words' => vB_Cleaner::TYPE_ARRAY_STR,
		));

		$escapedWords = array();
		foreach ($params['words'] AS $word)
		{
			$escapedWords[] = "('" . $db->escape_string(strval($word)) . "')";
		}
		$escapedWords = implode(', ', $escapedWords);

		$sql = "
			INSERT IGNORE INTO " . TABLE_PREFIX . "words
			(word)
			VALUES
			$escapedWords
			/**" . __FUNCTION__ . "**/
		";

		return $db->query_write($sql);
	}

	public function updateNodeCrc($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return !empty($params['crc']);
		}

		//there really isn't a good way to clean this according to standard rules
		//since it's an assoc array.  We'll just do it by hand;
		$crc = $params['crc'];

		//make sure that we don't have anything we don't know about;
		unset($params);

		$values = array();
		foreach($crc AS $nodeid => $value)
		{
			$safeNodeid = intval($nodeid);
			$safeValue = "'" . $db->escape_string($value) . "'";

			$values[] = "($safeNodeid, $safeValue)";
		}

		//this deliberately bounces off the index to manage multiple updates.
		//it's important that we only pass nodeids that exist to this query
		//or we're going to get some really odd rows.
		//
		//note that this query isn't valid in STRICT mode (which we disable for vbulletin)
		//because the inserts fail due to not provding values for columns without default
		//values.
		$query = "INSERT INTO " . TABLE_PREFIX . "node (nodeid, crc32)
			VALUES " . implode(",\n", $values) . "
			ON DUPLICATE KEY UPDATE crc32 = VALUES(crc32)";

		$query .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		return $db->query_write($query);
	}

	public function insertUpdateSearchWords($params, $db, $check_only = false)
	{
		if ($check_only)
		{
			return (!empty($params['values']) AND !empty($params['suffix']));
		}

		//handle the cleaning manually for both efficiency and because the
		//cleaner doens't handle nested array structures gracefully.
		//
		//All of the values should be ints.  Let's update in place to avoid
		//unnecesary memory duplication.
		$values = $params['values'];
		foreach($values AS $index => $dummy)
		{
			foreach($values[$index] AS $key => $field)
			{
				$values[$index][$key] = intval($values[$index][$key]);
			}
		}

		$suffix = $params['suffix'];

		//make sure that we don't have anything we don't know about;
		unset($params);

		//we'll assume that the fields are present and the order is consistant
		//in the values array.  Sorting each individual field is less fragile
		//but more processing and we're trying to shave fractions of a second per node.
		$queryBuilder = $this->getQueryBuilder($db);
		$fields = $queryBuilder->escapeFields(array_keys($values[0]));
		$fields =	implode(', ', $fields);

		$tablename = $queryBuilder->escapeTable("searchtowords_$suffix");
		$query = "INSERT INTO $tablename ($fields)
			VALUES
		";

		for($index = 0; $index < count($values) -1; $index++)
		{
			$query .= '(' . implode(', ', $values[$index]) . "),\n";
		}

		$query .= '(' . implode(', ', $values[$index]) . ")\n";

		$query .= "
			ON DUPLICATE KEY UPDATE
				nodeid = VALUES(nodeid),
				wordid = VALUES(wordid),
				is_title = VALUES(is_title),
				score = VALUES(score),
				position = VALUES(position)
		";

		$query .= "\n/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		return $db->query_write($query);
	}


	private function doStarterJoin($skipChannels = false, $joinType = 'left')
	{
		/*
			This is mostly used when the "view" = "topic" filter is used. We need
			to switch some filtering or sorting over to use starter fields, and this
			can be triggered from multiple places, so it's been placed in this
			function to reduce code duplication & improve maintainability.
		 */
		switch ($joinType)
		{
			case 'inner':
				$join = 'INNER JOIN';
				break;
			case 'straight':
				$join = 'STRAIGHT_JOIN';
				break;
			case 'left':
			default:
				$join = 'LEFT JOIN';
				break;
		}
		if ($skipChannels)
		{
			/*
				When we do *filtering* on a starter field, we will likely want starter to be the driving table
				since it'll have the most restricted # of results (vs. node, which is usually our driving table).

				In that case, the join from starter -> node fails if we have the IF() in the join condition as
				it can't use an index properly, so mysql will go back to using node as the driving table, which
				could have a much larger # of records than starter in the case we swapped out the date filter
				from node.publishdate to starter.lastcontent.

				For view topics, we don't care about channels' starters so we don't care about starter = 0
				nodes in the results, so to improve performance, we'll just get rid of that expression which
				allows the optimizer to drive using the small set of starters then join on node via index.
			 */

			// Override any other starter joins we might've done to ensure that we skip the channel check.
			$this->join['starter'] = $join . ' ' . TABLE_PREFIX . "node AS starter " .
				"ON starter.nodeid = node.starter";
		}
		else
		{
			if (!isset($this->join['starter']))
			{
				$this->join['starter'] = $join . ' ' . TABLE_PREFIX . "node AS starter " .
					"ON starter.nodeid = IF(node.starter = 0, node.nodeid, node.starter)";
			}
		}
	}


	/**
	 *	Handle processing for the equals / range filters
	 * @param object $criteria vB_Search_Criteria
	 * @param array $filter_method string The name of the method to call to create a
	 *		where snippet for this kind of filter (currently equals and range -- not planning
	 *		to add more).  This should be the name of a private method on this class.
	 * @param bool $excludeUserSpecific Exclude user specific queries. Used for precaching
	 */
	private function process_filters(vB_Search_Criteria &$criteria, $filter_method, &$db, $excludeUserSpecific = false)
	{
		$viewTopics = $criteria->has_topic_view_filter();
		foreach ($this->filters[$filter_method] as $field => $value)
		{
			//if this is a null filter we that forces a 0-result query
			switch ($field)
			{
				case 'null':
					$this->where[] = "false /** Field is NULL in process_filters **/";
				break;
				case 'tag':
					$this->process_tag_filters($value);
				break;
				case 'channelid':
					$this->process_channel_filters($value, $criteria->getDepth(), $criteria->getIncludeStarter(), $criteria->getDepthExact(), $excludeUserSpecific);
				break;
				case 'exclude':
					$this->process_exclude_filters($value);
				break;
				case 'follow':
					$this->process_follow_filters($value, $criteria);
				break;
				case 'unpublishdate':
					$this->where[] = "(node.showpublished = 1)";
				break;
				case 'publishdate':
					// skip adding a date restriction, workaround for activity stream
					if ($value != 'all')
					{
						if ($viewTopics)
						{
							if ($criteria->getSearchContext() === "channeldisplay")
							{
								// if we're doing channeldisplay, nodes will be starters already.
								// todo: we probably won't hit this filter for channeldisplay / fetchTopics()
								$this->where[] = $this->$filter_method('node', 'lastcontent', $value);
							}
							else
							{
								// If it's a date range for "topic" view, use starter.lastcontent as the
								// most relevant field instead of node.publishdate or starter.publishdate.
								$this->doStarterJoin(true);
								$this->where[] = $this->$filter_method('starter', 'lastcontent', $value);
							}
						}
						else
						{
							$this->where[] = $this->$filter_method('node', 'publishdate', $value);
						}
					}
				break;
				case 'starter_only':
					$this->process_starter_only_filter($value);
				break;
				case 'reply_only':
					$this->process_reply_only_filter($value);
				break;
				case 'comment_only':
					$this->process_comment_only_filter($value);
				break;
				case 'include_visitor_messages':
					$this->process_visitor_message_filter($value, 'include');
				break;
				case 'visitor_messages_only':
					$this->process_visitor_message_filter($value, 'only');
				break;
				case 'sentto':
					$this->process_visitor_message_filter($value, 'for');
					break;
				case 'trending':
					//implicitly force the start to be a trending topic
					if($value)
					{
						$this->join['trending'] = "JOIN " . TABLE_PREFIX . "trending AS trending \n\t\t\t\t" .
							"\tON trending.nodeid = node.starter  \n\t\t\t\t";
					}
					break;
				case 'exclude_visitor_messages':
					$this->process_visitor_message_filter($value, 'exclude');
				break;
				case 'include_private_messages':
					$this->process_private_message_filter($value, 'include');
				break;
				case 'private_messages_only':
					$this->process_private_message_filter($value, 'only');
				break;
				case 'OR':
					foreach ($value as $fld => $val)
					{
						$fld = $this->db->clean_identifier($fld);
						$qbits[] = $this->make_equals_filter('node', $fld, $val);
					}
					$this->where[''] = "(" . implode(' OR ', $qbits) . ")";
				break;
				case 'marked':
					$this->process_marked_filter($value);
				break;
				case 'my_channels':
					$this->process_my_channels_filter($value);
				break;
				case 'eventstartdate':
				case 'eventenddate':
					// join event table for required filtering.
					if (!isset($this->join['eventdate']))
					{
						$this->join['eventdate'] = "JOIN " . TABLE_PREFIX . "event AS event \n\t\t\t\t" .
															"\tON event.nodeid = node.nodeid  \n\t\t\t\t";

						$eventContentTypeId = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Event');
						$this->where['eventdate'] = "node.contenttypeid = '" . intval($eventContentTypeId) . "' \n";
					}
					$this->where[] = $this->$filter_method('event', $field, $value);
				break;
				default:
					$dbfield = $field;
					if (isset(self::$field_map[$field]))
					{
						$dbfield = self::$field_map[$field];
					}
					$dbfield = $this->db->clean_identifier($dbfield);
					$where = $this->$filter_method('node', $dbfield, $value);
					$this->where[] = $where;
				break;
			}
		}
	}

	private function process_one_word_rank($word, $is_title_only = false)
	{
		$table = "searchtowords_$word[suffix]";
		$this->join['temp_search'] = "JOIN " . TABLE_PREFIX . "$table AS $table ON $table.nodeid = node.nodeid AND $table.wordid = $word[wordid]" . ($is_title_only ? " AND $table.is_title = 1" : '');
	}

	/**
	 * building the query for the case when there is an OR joiner between the words or when the results are sorted by relevance
	 * @param array $searchwords the list of words to search for, keys are word ids
	 * @param boolean $is_title_only search in title only
	 */
	private function process_existing_words_or($searchwords, $is_title_only = false)
	{
		// this will contain the list of distances in case of a rank sort
		$nodeids = array();
		$not_nodeids = array();
		$prev_node_ids = array();
		$first_run = true;
		if (!self::$temp_table_created)
		{
			$length = strlen(vB::getDatastore()->getOption('postmaxchars')) + 4;
			$this->db->query_write($query = "
					CREATE TEMPORARY TABLE IF NOT EXISTS " . TABLE_PREFIX . "temp_search (
					nodeid INT(11) NOT NULL DEFAULT 0,
					score INT(11) NOT NULL DEFAULT 0,
					prev_position INT(11) NOT NULL DEFAULT 0,
					words_nr TINYINT(2) NOT NULL DEFAULT 1,
					distance DECIMAL($length,4) NOT NULL DEFAULT 1,
					is_title TINYINT(1) NOT NULL DEFAULT 0,
					PRIMARY KEY USING HASH (nodeid)
					) ENGINE = MEMORY");
		}
		else
		{
			$this->db->query_write($query = "TRUNCATE TABLE " . TABLE_PREFIX . "temp_search");
		}

		$config = vB::getConfig();
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}
		self::$temp_table_created = true;
		foreach ($searchwords as $wordid => $word)
		{
			$add_where = $is_title_only ? " AND searchtowords_$word[suffix].is_title = 1" : "";
			// limit the current matches to the list of existing matches (skip this if it is the first iteration)
			if (!$first_run AND $word['joiner'] != 'OR' AND $word['joiner'] != 'NOT' AND is_numeric($wordid))
			{
				$this->db->query_write($query = "
					DELETE FROM " . TABLE_PREFIX . "temp_search
					WHERE nodeid NOT IN (
						SELECT nodeid
						FROM " . TABLE_PREFIX . "searchtowords_$word[suffix] AS searchtowords_$word[suffix]
						WHERE wordid = $wordid $add_where
					)");

				if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
				{
					echo "$query;\n";
				}
			}

			// there migh be words that are not found in the words table; there is no point to look those up in the searchtowords tables
			if (is_numeric($wordid))
			{
				if ($word['joiner'] == 'NOT')
				{
					$this->where[] = "node.nodeid NOT IN (
						SELECT nodeid FROM " . TABLE_PREFIX . "searchtowords_$word[suffix] WHERE wordid = $wordid $add_where
					)";
				}
				else
				{
					$query = "
					INSERT INTO " . TABLE_PREFIX . "temp_search
						(nodeid, score, prev_position, is_title)
						SELECT nodeid, score, position, is_title
						FROM " . TABLE_PREFIX . "searchtowords_$word[suffix] AS searchtowords_$word[suffix]
						WHERE wordid = $wordid $add_where
					";
					if (!$first_run)
					{
						$query .= "ON DUPLICATE KEY UPDATE";
						$temptable = TABLE_PREFIX . "temp_search";
						if ($word['joiner'] != 'OR')
						{
							$query.= "
							$temptable.distance = $temptable.distance +
								EXP(LEAST(709,(ABS($temptable.prev_position - VALUES(prev_position))-1)/" . $this->word_distance_factor . "))
							,
							$temptable.prev_position = VALUES(prev_position),
							$temptable.words_nr = $temptable.words_nr + 1,";
						}
						$query .= "
						$temptable.score = $temptable.score + VALUES(score),
						$temptable.is_title = LEAST($temptable.is_title, VALUES(is_title))
					";
					}
					$this->db->query_write($query);

					if (self::DEBUG)
					{
						echo "$query;\n";
					}
					if (!$first_run AND $word['joiner'] != 'OR' AND $word['joiner'] != 'NOT')
					{
						$this->db->query_write($query = "
							DELETE FROM " . TABLE_PREFIX . "temp_search
							WHERE words_nr = 1
						");

						if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
						{
						echo "$query;\n";
						}
					}
				}
			}
			$first_run = false;
		}

		$this->join['temp_search'] = "JOIN " . TABLE_PREFIX . "temp_search AS temp_search ON temp_search.nodeid = node.nodeid" . ($is_title_only ? " AND temp_search.is_title = 1" : '');
	}

	/**
	 *
	 * computes the relevancy score
	 * @param array $distances the relative distance of each word to the start of the text
	 * @param array $weight_sums the indexed score
	 * @param array $title_words list of words that are in the title
	 * @param boolean $is_and_joiner flag for joiner type, true if AND joiner, false otherwise
	 * @return array
	 */
	private function compute_sort_score(&$distances, &$weight_sums, &$title_words, $is_and_joiner)
	{
		$scores = array();
		$result_set = $this->db->query_read_slave("
			SELECT node.nodeid, node.created
			FROM " . TABLE_PREFIX . "node AS node
			WHERE " . self::make_equals_filter('node', 'nodeid', array_keys($distances)));

		while($node_details = $this->db->fetch_array($result_set))
		{
			$weight_sum = isset($weight_sums[$node_details['nodeid']]) ? $weight_sums[$node_details['nodeid']] : 1;
			if (!empty($distances[$node_details['nodeid']]))
			{
				$words_distances = explode(',', $distances[$node_details['nodeid']]);
			}
			else
			{
				$scores[$node_details['nodeid']] = 1;
				continue;
			}
			//in case of AND joiner compute the distance, otherwise the distance factor is 1
			$distance = $is_and_joiner ? $this->compute_distance($words_distances, $this->word_distance_factor) : 1;
			$timenow = vB::getRequest()->getTimeNow();

			$date_weight = max(1, 5 - (($timenow - $node_details['created'])/(913 * 86400)));
			$scores[$node_details['nodeid']] = (int) round($weight_sum * $date_weight * (empty($title_words[$node_details['nodeid']]) ? 1 : $this->title_boost) / max($distance, 1));
		}
		$this->db->free_result($result_set);
		return $scores;
	}

	/**
	 *
	 * computes the distance factor based on the relative distances of each word
	 * @param array $words_distances
	 * @param int $a distance factor influence
	 * @return int distance
	 */
	function compute_distance($words_distances, $a)
	{
		$distance = 0;
		$prev_position = 0;
		$words_distances = array();
		foreach ($words_distances as $position)
		{
			//$weight_sum += 	$score_details['score'];
			//$is_title += 	$score_details['is_title'];
			if ($prev_position > 0)
			{
				$distance += exp((abs($prev_position - $position)-1)/$a);
			}
			$prev_position = $position;
		}
		if ($distance == 0)
		{
			return 1;
		}
		return ((4 * (count($words_distances) - 1)) / $distance) + 1;
	}

	// building the query for for the case when there is no OR joiner
	private function process_existing_words_and($searchwords, $is_title_only = false)
	{
		//$prev_tablename = false;
		$i = 1;
		foreach ($searchwords as $wordid => $word)
		{
			$i++;
			$results = array();

			//the wordid is not guarenteed to numeric -- for words that aren't found we end up using the
			//word value.  That doesn't really make any sense because we aren't going to find it, but
			//that's another problem.  This causes injection of user contributed strings direction
			//into the query, which is bad.  Howeever we only need to ensure that the tabled names are
			//unique as they aren't generated outside of this function.
			$tablename = $word['suffix'] . '_' . $i;

			if ($word['joiner'] == 'NOT')
			{
				$this->where[] = "node.nodeid NOT IN
				(
					SELECT $tablename.nodeid
					FROM " . TABLE_PREFIX . "searchtowords_$word[suffix] $tablename
					WHERE $tablename.wordid = " . intval($wordid) . "
				)";
			}
			elseif ($word['joiner'] != 'OR') //in case of an AND (or missing joiner)
			{
				$criteria = "JOIN " . TABLE_PREFIX . "searchtowords_$word[suffix] $tablename ON $tablename.nodeid = node.nodeid AND $tablename.wordid = " . intval($wordid);
				if ($is_title_only)
				{
					$criteria .= " AND $tablename.is_title = 1";
				}
				$this->join[$tablename] = $criteria;
			}
		}
	}

	/**
	 * Process the filters for the query string
	 *
	 * @param vB_Search_Criteria $criteria search criteria to process
	 */
	protected function process_keywords_filters(vB_Search_Criteria &$criteria)
	{
		$keywords = $criteria->get_keywords();
		// nothing to process
		if (empty($keywords))
		{
			return;
		}

		$words = array();
		// get the map table names for the keywords. these tables will be joined into the search query
		$has_or_joiner = false;
		foreach ($keywords as $word_details) {
			$suffix = vBDBSearch_Core::get_table_name($word_details['word']);
			//$words[$suffix][$clean_word] = array('wordid'=>false,'joiner'=>$word['joiner']);
			$words[$word_details['word']] = array
				(
					'suffix'=>$suffix,
					'word'=>$word_details['word'],
					'joiner'=>$word_details['joiner']
				);
			if ($word_details['joiner'] == "OR")
			{
				$has_or_joiner = true;
			}
		}
		// nothing to process
		if (empty($words))
		{
			return;
		}

		$query = "
			SELECT *
			FROM " . TABLE_PREFIX . "words as words
			WHERE " . self::make_equals_filter('words', 'word', array_keys($words));

		$set = $this->db->query_read_slave($query);

		$config = vB::getConfig();
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		$wordids = array();
		while($word_details = $this->db->fetch_array($set))
		{
			$wordids[$word_details['word']] = $word_details['wordid'];
		}
		$this->db->free_result($set);
		$word_details = array();
		foreach ($words as $word => $details)
		{
			// if the word was not found
			if (!isset($wordids[$word]))
			{
				// and it's not with a NOT or OR operator
				if (!$has_or_joiner AND $details['joiner'] != 'NOT')
				{
					// this word is not indexed so there is nothing to return
					$this->where[] = "0 /** word is not indexed **/";
					$this->sort = array('node.created' => 'ASC');
					return;
				}
				// still need to add this word to the mix (either as a NOT operator or maybe as an OR). we use the word itself as a key to make it unique
				$key = $word;
				$details['wordid'] = 0;
			}
			else
			{
				$key = $details['wordid'] = $wordids[$word];
			}

			$word_details[$key] = $details;
		}
		unset($wordids);
		unset($words);

		if (count($word_details) == 1)
		{
			$this->process_one_word_rank(array_pop($word_details), $criteria->is_title_only());
		}
		elseif ($has_or_joiner OR isset($this->sort['rank']))
		{
			$this->process_existing_words_or($word_details, $criteria->is_title_only());
		}
		else
		{
			$this->process_existing_words_and($word_details, $criteria->is_title_only());
		}
	}

	/**
	 *	Process the filters for the requested tag
	 *
	 *	This processing makes the assumption that if the type is groupable the tags
	 *	will apply only to the group
	 *
	 *	@param array $tagids the ids of the tags to filter on.
	 */
	protected function process_tag_filters($tagids)
	{
		if (empty($tagids))
		{
			return;
		}
		if (is_numeric($tagids))
		{
			$tagids = array($tagids);
		}
		foreach ($tagids as $index => $tagid)
		{
			$tagid = intval($tagid);
			$this->join["tag$tagid"] = "JOIN " . TABLE_PREFIX . "tagnode AS tagnode$tagid ON
					(node.nodeid = tagnode$tagid.nodeid)";
			$this->where[] = $this->make_equals_filter("tagnode$tagid", 'tagid', $tagid);
		}
	}

	/**
	 *	Process the exclude filter
	 *
	 *	@param array $nodeids the ids of the nodes (and it's children) to exclude
	 */
	protected function process_exclude_filters($nodeids)
	{
		if (empty($nodeids))
		{
			return;
		}
		if (is_numeric($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$nodeids = vB::getCleaner()->clean($nodeids, vB_Cleaner::TYPE_ARRAY_UINT);
		if (empty($this->join['closure']))
		{
			$this->join['closure'] = "JOIN " . TABLE_PREFIX . "closure AS closure ON node.nodeid = closure.child";
		}
		$this->join['exclude_closure'] = "LEFT JOIN  " . TABLE_PREFIX . "closure AS exclude_closure
			ON (exclude_closure.child = closure.child AND
				exclude_closure.parent IN (" . implode(',',$nodeids) . " ))\n";

		$this->where[] = "exclude_closure.child IS NULL ";
	}

	protected function process_channel_filters($channelid, $depth = false, $include_starter = false, $depth_exact = false, $excludeUserSpecific = false)
	{
		//first let's see if this is valid.
		$userdata = vB::getUserContext()->getAllChannelAccess();

		// result set is being pre-cached so include all nodes from selfonly.
		// Nodes from selfonly will be filtered out on second pass
		if ($excludeUserSpecific AND !empty($userdata['selfonly']))
		{
			$userdata['canalwaysview'] = $userdata['canalwaysview'] + $userdata['selfonly'];
			$userdata['selfonly'] = array();
		}

		if (
				!empty($depth)
					AND
				$depth == 1
					AND
				is_numeric($channelid)
					AND
				(
					in_array($channelid, $userdata['canview'])
						OR
					in_array($channelid, $userdata['canalwaysview'])
						OR
					in_array($channelid, $userdata['canmoderate'])
						OR
					in_array($channelid, $userdata['selfonly'])
				)
			)
		{
			$channelid = intval($channelid);
			// The user can moderate the channel.
			if (in_array($channelid, $userdata['canmoderate']))
			{
				$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
				$this->done_permission_check = true;
				return;
			}
			$userId = (int) vB::getUserContext()->fetchUserId();
			$gitWhere = '';

			// The user can't moderate but is a channel member.
			if (!empty($userId))
			{
				$gitInfo = vB_Api::instanceInternal('user')->getGroupInTopic($userId);

				if (is_array($gitInfo) AND array_key_exists($channelid, $gitInfo))
				{
					$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
					if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
					{
						$this->where[] = "node.showpublished = 1";
					}
					// Allow user to see their own, unapproved nodes
					$this->where[] = "(node.showapproved = 1 OR node.userid = $userId)";

					if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $channelid))
					{
						$this->where[] = "(node.starter = 0 OR node.nodeid = node.starter)";
					}
					$this->done_permission_check = true;
					return;
				}

				if (!empty($gitInfo))
				{
					$gitWhere = " OR node.nodeid IN (" . implode(',', array_keys($gitInfo)) . ") ";
				}
			}

			//if the user can't moderate, and doesn't have canviewthread, they just get titles and for the starters
			if (!empty($userId) AND in_array($channelid, $userdata['canview']) AND !vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $channelid))
			{
				$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "node.showpublished = 1";
				}
				// Allow user to see their own, unapproved nodes
				$this->where[] = "(node.showapproved = 1 OR node.userid = $userId)";
				$this->where[] = "(node.viewperms > 0 $gitWhere)";
				$this->where[] = "(node.starter = 0 OR node.nodeid = node.starter)";
				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, is logged in, isn't a channel member, and has forum permission "can view others".
			if (!empty($userId) AND in_array($channelid, $userdata['canview']))
			{
				$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "node.showpublished = 1";
				}
				// Allow user to see their own, unapproved nodes
				$this->where[] = "(node.showapproved = 1 OR node.userid = $userId)";
				$this->where[] = "(node.viewperms > 0 $gitWhere)";
				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, isn't a channel member,  is logged in, and has forum permission "can view posts" but not"can view others".
			if (!empty($userId) AND in_array($channelid, $userdata['selfonly']))
			{
				$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "node.showpublished = 1";
				}
				// They can only see their own nodes. Allow them to see their own nodes in moderation
				//$this->where[] = "node.showapproved = 1";
				$this->where[] = "node.userid = $userId";
				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, isn't logged in, and has forum permission "can view others"
			if (empty($userId) AND in_array($channelid, $userdata['canview']))
			{
				$this->where[] = $this->make_equals_filter('node', 'parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "node.showpublished = 1";
				}
				// guests can't see any unapproved nodes since we can't distinguish guests
				$this->where[] = "node.showapproved = 1";
				$this->where[] = "node.viewperms = 2";
				$this->done_permission_check = true;
				return;
			}
		}

		/* Force a hint if we have more than six parentids
		 as MySQL tries to swap indexes, making it very slow. */
		$hint = '';
		if (is_array($channelid) AND count($channelid) > 6)
		{
			$hint = 'USE INDEX (child)';
		}

		// if it got here we need to do it the slow way
		$this->where[] = $this->make_equals_filter('closure', 'parent', $channelid);
		$this->join['closure'] = "JOIN " . TABLE_PREFIX . "closure AS closure $hint ON node.nodeid = closure.child";

		if (empty($include_starter))
		{
			$this->where[] = 'node.nodeid <> closure.parent';
		}

		if (!empty($depth))
		{
			$depth = intval($depth);
			if ($depth_exact !== false)
			{
				$this->where[] = 'closure.depth = ' . $depth;
			}
			else
			{
				$this->where[] = 'closure.depth <= ' . $depth;
			}
		}

		/*
			Note on try/catch vB_Exception_Api('invalid_node_id') (VBV-19063)
			If a search module references a deleted channel, we don't want the entire module to die.
			The channel perm checks can cause the node library's getBare() function to throw a "invalide_node_id"
			exception. In such a case let's just treat that as a "can't view threads" node. While currently we can
			probably just outright ignore it, since the queries shouldn't be able to find that channel, I think
			this is safer than ignoring it in case something about the downstream functions change.
			We don't check this in the big if block above, because those check for numeric channelid's
			existence in one of the userdata arrays, and I'm assuming that those arrays are better
			about not keeping orphaned channel references (so far we haven't had similar exceptions coming
			out of the perm check calls in the above block).
		 */
		$canviewthreads = false;
		$cannotviewthreadsChannelids = array();
		if (is_array($channelid))
		{
			$canviewthreads = true;
			foreach ($channelid as $chid)
			{
				try
				{
					if(!vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', intval($chid)))
					{
						$cannotviewthreadsChannelids[] = intval($chid);
						$canviewthreads = false;
					}
				}
				catch (vB_Exception_Api $e)
				{
					if (!$e->has_error('invalid_node_id'))
					{
						throw $e;
					}
					$cannotviewthreadsChannelids[] = intval($chid);
					$canviewthreads = false;
				}
			}
		}
		elseif (is_numeric($channelid))
		{
			try
			{
				$canviewthreads = vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', intval($channelid));
			}
			catch (vB_Exception_Api $e)
			{
				if (!$e->has_error('invalid_node_id'))
				{
					throw $e;
				}
				$canviewthreads = false;
			}
		}

		if (!$canviewthreads)
		{
			if (empty($cannotviewthreadsChannelids))
			{
				$this->where[] = "(node.starter = 0 OR node.nodeid = node.starter)";
			}
			else
			{
				$inCannotView = $this->make_equals_filter("closure", "parent", $cannotviewthreadsChannelids);
				$notInCannotView = $this->make_notequals_filter("closure", "parent", $cannotviewthreadsChannelids);
				unset($cannotviewthreadsChannelids);
				$this->where[] = "({$inCannotView} AND (node.starter = 0 OR node.nodeid = node.starter) OR {$notInCannotView})";
			}
		}
	}

	protected function process_view_filters($view, vB_Search_Criteria &$criteria)
	{
		if (empty($view))
		{
			return;
		}
		switch ($view)
		{
			/**
			 * only include the latest reply or comment (or the starter itself if no replies/comments yet) per starter in all the channels.
			 * Filters out the Channel nodes from the Search API nodes results.
			 * @include replies/comments in the second phase
			 */
			case vB_Api_Search::FILTER_VIEW_ACTIVITY :
				$datecheck = false;
				// search for publishdate through filters
				foreach ($this->filters AS $type)
				{
					if (is_array($type) AND !$datecheck)
					{
						$datecheck = array_key_exists('publishdate', $type);
					}
				}

				$channelAccess = vb::getUserContext()->getAllChannelAccess();

				if (!empty($this->filters['make_equals_filter']['starter_only']))
				{
					$this->what = "node.nodeid";
				}
				else if ((!empty($channelAccess['starteronly'])))
				{
					$starterOnly = implode(',', $channelAccess['starteronly']);
					$this->what = "DISTINCT CASE WHEN starter.nodeid IN ($starterOnly) OR starter.parentid in ($starterOnly)
					THEN starter.nodeid ELSE node.lastcontentid END AS nodeid";
				}
				else if (!empty($this->filters['last']))
				{
					$this->what = "node.nodeid";
				}
				else
				{
					$this->what = "DISTINCT node.lastcontentid AS nodeid";
				}
				$this->where[] = "node.nodeid = node.starter AND node.contenttypeid <> " .
					vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
				unset($channelAccess);

				if (!$datecheck)
				{
					$age = vB::getDatastore()->getOption('max_age_channel');

					if (empty($age))
					{
						$age = 60;
					}

					$this->where[] = "node.created > " . (vB::getRequest()->getTimeNow() - ($age * 86400));
				}
				// in activity stream we don't want deleted content even if viewed by a moderator
				$this->where[] = "node.showpublished = 1";
			break;
			/**
			 * The Topic view should only display the starter nodes for the specified channel.
			 * Filters out the Channel nodes from the Search API nodes results.
			 */
			case vB_Api_Search::FILTER_VIEW_TOPIC :
				$method = false;
				if (isset($this->filters['make_notequals_filter']['sticky']))
				{
					$method = 'make_notequals_filter';
				}

				if (isset($this->filters['make_equals_filter']['sticky']))
				{
					$method = 'make_equals_filter';
				}


				/*
					Note, "topic" view should always return the starter data, not the matched node, because
					otherwise it'll display nonsensical reply/comment info as a "topic" - VBV-17630
				 */
				//
				if ($criteria->getSearchContext() === "channeldisplay")
				{
					// We only want to filter/fetch starters. That also means that
					// we don't need to join on starter, since the only nodes we want are starters.
					$this->where[] = "node.nodeid = node.starter";
					$this->join['starter'] = ""; // disable join on starter.
					if ($criteria->getDoCount())
					{
						$this->what = "COUNT(node.starter) AS count";
					}
					else
					{
						$this->what = "node.starter AS nodeid";
					}

					if (!empty($method))
					{
						$this->where[] = $where = $this->$method('node', 'sticky', $this->filters[$method]['sticky']);
						unset($this->filters[$method]['sticky']);
					}

					// if we already have contenttype filters, skip the "not channel" contenttypeid filter since
					// multiple contenttypeid conditions would be unnecessary at best (since as soon as we have
					// a node.contenttypeid = something in the WHERE, that implicitly filters out any other types)
					// & prevents possible composite index utilization at worst due to range scan on contenttypeid
					$json = $criteria->getJSON();
					if (empty($json['type']))
					{
						$this->where[] = "node.contenttypeid <> " . vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
					}
				}
				else
				{
					if (!empty($method))
					{
						$this->doStarterJoin();
						$this->where[] = $where = $this->$method('starter', 'sticky', $this->filters[$method]['sticky']);
						unset($this->filters[$method]['sticky']);
					}
					$this->what = "DISTINCT node.starter AS nodeid";
					$this->where[] = "node.contenttypeid <> " . vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
				}
			break;
			/**
			 * The Conversation Detail view should only display the descendant nodes of (and including) the specified starter.
			 * Filters out the Comment node from the Search API nodes results.
			 */
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD :
				if (empty($this->join['closure']))
				{
					$this->join['closure'] = "JOIN " . TABLE_PREFIX . "closure AS closure ON node.nodeid = closure.child";
				}
				$this->where[] = "(node.starter = node.nodeid OR node.starter = node.parentid)";
				$this->where[] = 'closure.depth <= 1';
			break;
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD_SEARCH :
// 				if (empty($this->join['closure']))
// 				{
// 					$this->join['closure'] = "JOIN " . TABLE_PREFIX . "closure AS closure ON node.nodeid = closure.child";
// 				}
				$this->what = " DISTINCT IF (node.parentid = 0 OR node.parentid = node.starter OR node.nodeid = node.starter, node.nodeid, node.parentid) AS nodeid";
			break;
			/**
			 * The Conversation Detail view should only display the descendant nodes of (and including) the specified starter.
			 * the Comment nodes are not filtered out.
			 * This should be handled by the channel filter
			 */
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_STREAM :
			break;
		}
	}

	protected function process_follow_filters($value, vB_Search_Criteria &$criteria)
	{
		$type = $value['type'];
		$userid = intval($value['userid']);
		$assertor = vB::getDbAssertor();

		if (
				$type == vB_Api_Search::FILTER_FOLLOWING_BOTH OR
				$type == vB_Api_Search::FILTER_FOLLOWING_ALL OR
				$type == vB_Api_Search::FILTER_FOLLOWING_CHANNEL OR
				$type == vB_Api_Search::FILTER_FOLLOWING_CONTENT
			)
		{
			/* following nodes */
			$subscriptions = $assertor->getRows('vBForum:subscribediscussion', array('userid' => $userid), false, 'discussionid');
			$nodes = (!$subscriptions OR !empty($subscriptions['errors'])) ? array() : $subscriptions;
			$nodeids = array_keys($nodes);
			if (empty($nodeids) AND (
						$type == vB_Api_Search::FILTER_FOLLOWING_CHANNEL OR
						$type == vB_Api_Search::FILTER_FOLLOWING_CONTENT OR
						$type == vB_Api_Search::FILTER_FOLLOWING_BOTH
					)
			)
			{
				$this->where[] = "0 /** no subscriptions for user **/";
				return;
			}
		}
		if ($type == vB_Api_Search::FILTER_FOLLOWING_ALL OR $type == vB_Api_Search::FILTER_FOLLOWING_USERS)
		{
			$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
			$userids = $cache->read("vbUserlistFollowFriend_$userid");
			if ($userids === false)
			{
				$userids = $assertor->getColumn('userlist', 'relationid',	array('userid' => $userid, 'type' => 'follow', 'friend' => 'yes'));
				$cache->write("vbUserlistFollowFriend_$userid", $userids, 60, 'followChg_' . $userid);
			}

			if (empty($userids) AND $type == vB_Api_Search::FILTER_FOLLOWING_USERS)
			{
				$this->where[] = "0 /** no following for user **/";
				return;
			}
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_ALL AND empty($nodeids) AND empty($userids))
		{
			$this->where[] = "0 /** no following for user **/";
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_CHANNEL)
		{
			$this->filters['make_equals_filter']['channelid'] = $nodeids;
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
			$this->where[] = $this->make_notequals_filter('node', 'contenttypeid', $channelcontentypeid);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_CONTENT)
		{
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');

			$this->where[] = $this->make_equals_filter('node', 'nodeid', $nodeids);
			$this->where[] = $this->make_notequals_filter('node', 'contenttypeid', $channelcontentypeid);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_USERS OR ($type == vB_Api_Search::FILTER_FOLLOWING_ALL AND empty($nodeids)))
		{
			$this->where[] = $this->make_equals_filter('node', 'userid', $userids);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_BOTH)
		{
			$nodes = $assertor->assertQuery('vBDBSearch:getNodesWithSubChannel', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'nodeids'=>$nodeids
			));
			$allNodeIds = array();
			foreach ($nodes as $nodeid)
			{
				$allNodeIds[] = $nodeid['nodeid'];
			}
			if (empty($allNodeIds))
			{
				$this->where[] = "0 /** no following for user **/";
				return;
			}
			$this->filters['make_equals_filter']['nodeid'] = $allNodeIds;
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_ALL)
		{

			$nodes = $assertor->assertQuery('vBDBSearch:getNodesWithSubChannel', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
					'nodeids'=>$nodeids
			));
			$allNodeIds = array();
			foreach ($nodes as $nodeid)
			{
				$allNodeIds[] = $nodeid['nodeid'];
			}
			if (empty($allNodeIds))
			{
				$this->where[] = "0 /** no following for user **/";
				return;
			}
			$this->filters['make_equals_filter']['OR'] = array('nodeid' => $allNodeIds, 'userid' => $userids);
			return;
		}
	}

	protected function process_starter_only_filter($starter)
	{
		if ($starter)
		{
			$this->where[] = "node.starter = node.nodeid";
		}
	}

	protected function process_reply_only_filter($reply)
	{
		if ($reply)
		{
			$this->where[] = "node.starter = node.parentid";
		}
	}


	protected function process_comment_only_filter($comment)
	{
		if ($comment)
		{
			$this->where[] = "node.starter <> node.nodeid";
			$this->where[] = "node.starter <> node.parentid";
			$this->where[] = "node.starter <> 0";
		}
	}


	protected function process_visitor_message_filter($userid, $type)
	{
		$userid = intval($userid);
		if ($type == 'include')
		{
			$this->union_condition[0][] = "node.userid = $userid";
			$this->union_condition[1][] = "node.setfor = $userid";
			//$this->where[] = "(node.userid = $userid OR node.setfor = $userid)";
		}
		else if ($type == 'only')
		{
			$this->union_condition[0][] = "node.userid = $userid AND node.setfor <> 0";
			$this->union_condition[1][] = "node.userid <> 0 AND node.setfor  = $userid";
		}
		else if ($type == 'for')
		{
			$this->where[] = $this->make_equals_filter('node', 'setfor', $userid);
		}
		else if ($type == 'exclude')
		{
			$this->where[] = $this->make_equals_filter('node', 'setfor', 0);
		}
	}

	protected function process_private_message_filter($userid, $type)
	{
		$userid = intval($userid);
		$pmcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('PrivateMessage');
		if ($type == 'include')
		{
			if (empty($userid))
			{
				$this->where[] = "node.contenttypeid <> $pmcontentypeid";
			}
			else
			{
				$this->join['sentto'] = "LEFT JOIN " . TABLE_PREFIX . "sentto AS sentto ON node.nodeid = sentto.nodeid AND sentto.userid = $userid AND sentto.deleted = 0";
				$this->where[] = "( node.contenttypeid <> $pmcontentypeid OR sentto.nodeid IS NOT NULL) ";
			}
		}
		elseif ($type == 'only')
		{
			if (empty($userid))
			{
				$this->where[] = "0 /** login to see private messages **/";
			}
			$this->join['sentto'] = "INNER JOIN " . TABLE_PREFIX . "sentto AS sentto ON node.contenttypeid = $pmcontentypeid AND node.nodeid = sentto.nodeid AND sentto.userid = $userid AND sentto.deleted = 0";
		}
	}

	protected function process_sort(vB_Search_Criteria &$criteria)
	{
		$sort_array = $criteria->get_sort();

		$this->sort = array();
		$this->sortable_what = array();

		// keep this in sync with the sphinx search implementation
		$sort_map = array (
			'user'           => 'authorname',
			'author'         => 'authorname',
			'publishdate'    => 'publishdate',
			'created'        => 'created',
			'started'        => 'created',
			'last_post'      => 'lastcontent',
			'lastcontent'    => 'lastcontent',
			'title'          => 'title',
			'textcount'      => 'textcount',
			'replies'        => 'textcount',
			'displayorder'   => 'displayorder',
			'rank'           => 'score',
			'relevance'      => 'score',
			'votes'          => 'votes',
			'eventstartdate' => 'eventstartdate',
			'trending'       => 'trending.weight',
		);

		// Certain sort fields must be changed to use the starter.{sort_field} when
		// view == topics to make the result list *seem* correct to the user.
		// This only works as long as process_view_filters() & subsequent unset()
		// is called *after* process_sort()
		$viewTopics = $criteria->has_topic_view_filter();
		$is_starter_only = (
			$criteria->has_bool_filter_for("starter_only") AND
			$criteria->get_bool_filter_for("starter_only") === true
		);
		$searchContext = $criteria->getSearchContext();

		foreach ($sort_array AS $sort => $direction)
		{
			$direction = strtoupper($direction);
			if (!in_array($direction, array('ASC', 'DESC')))
			{
				$direction = 'ASC';
			}

			// "starter first" sorting to guarantee that the starter is always first
			// when pulling a topic tree in cases where the starter may have a later
			// created date or a greater  nodeid than a reply (e.g. due to topic merge)
			if ($sort == "isstarter")
			{
				// Edge case optimization: If we have starter only filter, we do not
				// need to sort by isstarter since *everything* will be isstarter.
				if (!$is_starter_only)
				{
					// Note that the criteria object currently sets the isstarter sorting first,
					// when include_starter & channel filters are set, but it really should be
					// each template/widget def that should be defining it.

					/*
						This is currently handled specially in getSearchResults(), around the
						foreach ($this->sort AS $field => $dir) loop because we need to
						SELECT another column (aliased to isstarter) so we can sort by it,
						and we don't want the aliased column to be automatically prefixed
						by anything (to node.isstarter for example).
					 */
					$this->sort['isstarter'] = $direction;
					$this->sortable_what['isstarter'] = 'IF(node.nodeid = node.starter, 1, 0) as isstarter';
				}

				// handled.
				continue;
			}

			// use the starter's title
			if ($sort == 'title')
			{

				if ($searchContext === "channeldisplay")
				{
					// if we're doing channeldisplay, nodes will be starters already.
					// Also, we're actually explicitly *skipping* the starter join, so trying to sort by starter.title
					// will cause an error.
					$this->sort['node.title'] = $direction;
				}
				else
				{
					$this->join['starter'] =  "LEFT JOIN " . TABLE_PREFIX . "node AS starter ON starter.nodeid = IF(node.starter = 0, node.nodeid, node.starter)";
					$this->sort['starter.title'] = $direction;
				}
				continue;
			}

			// if we don't have a sort, or we have an unrecognized sort type default to relevance descending
			if (!$sort OR (!isset($sort_map[$sort])))
			{
				$sort = 'relevance';
				$direction = 'DESC';
			}

			if ($sort == "eventstartdate")
			{
				/*
					VBV-17351
					If they want to sort by event start date, then it's assumed they
					only want events.
					We don't explicitly set the "type" search json field because that could
					change the initial search query & change the context.
					E.g. they click on today's posts, then decide to sort by event start, then
					go back to sort by posted date.
					If we set the type to events, that gets added to the search JSON in the URL
					then when they go back to a non-event sorting, they'll still only see events
					instead of the original search.
				 */
				if (!isset($this->join['eventdate']))
				{
					$this->join['eventdate'] = "JOIN " . TABLE_PREFIX . "event AS event \n\t\t\t\t" .
						"\tON event.nodeid = node.nodeid  \n\t\t\t\t";
				}
			}

			if ($sort == 'trending')
			{
				if (!isset($this->join['trending']))
				{
					$this->join['trending'] = "JOIN " . TABLE_PREFIX . "trending AS trending \n\t\t\t\t" .
						"\tON trending.nodeid = node.starter  \n\t\t\t\t";
				}
			}

			//look for a core sort option
			if (isset($sort_map[$sort]))
			{
				$sort_field = $sort_map[$sort];
				// process rank sortings
				if ($sort_field == 'score')
				{
					$sort_field = 'rank';
				}
				else if ($sort_field == 'eventstartdate')
				{
					// no-op so we don't qualify this with 'node.' below
					// since it's on the event table not the node table
				}
				//if we have a period in the field we've already set a table.
				else if (strpos($sort_field, '.') === false)
				{
					if ($viewTopics)
					{
						if ($searchContext === "channeldisplay")
						{
							// if we're doing channeldisplay, nodes will be starters already.
							$sort_field = "node.$sort_field";
						}
						else
						{
							$this->doStarterJoin();
							$sort_field = "starter.$sort_field";
						}
					}
					else
					{
						$sort_field = "node.$sort_field";
					}
				}

				$this->sort[$sort_field] = $direction;
			}

			/*
				If it's a "created ASC/DESC" sort, it also implies a nodeid sort in case
				two nodes were created in the same second.
				This is useful for thread views where we can guarantee sorting order in
				the case where two replies might've been created within the same second
				(topic merges can also generate this edge case).

				We skip this in $viewTopics since that implies we're only displaying
				starters (even if we get a non-starter node in the search result, we're
				only going to return *its* starter), so sorting by nodeid isn't really
				important there (AFAIK).

				This replaces the previous behavior of "always adding nodeid ASC at the
				end" (VBV-4898).
			 */
			if ($sort === "created" AND !$viewTopics)
			{
				/*
					The search *used* to tack on a node.nodeid ASC sort for
					every single query.
					That caused problems with performance, and does not seem
					to be the intended behavior of the nodeid sorting.
					We think it was originally meant to handle race conditions
					of reply sorting (see above), in which case, if we're
					sorting by created DESC, we want to flip the nodeid
					sorting to be DESC as well.
					As such, we now just "follow" the created sorting direction
					instead of always nodeid ASC.

				 */
				$this->sort['nodeid2'] = $direction;
				/*
					This is needed for UNIONs were we have to select a column
					to sort outside of the union. It means that it adds an extra
					selected column for non-union (most?) queries, but it simplifies
					the sortable_what code.

					If this approach is problematic or insufficient in the future,
					we'll need to track separate sort & sortable_what arrays,
					for union & non-union queries.

					The reason we do node.nodeid AS nodeid2 instead of just nodeid
					is because sometimes, the query looks like
					SELECT DISTINCT starter.nodeid AS nodeid ...
					FROM node AS node
					LEFT JOIN starter AS starter ON (node.starter = node.nodeid)
					...
					ORDER BY created ASC, nodeid(2)
					(when the "topic" view is selected)

					And if we try to sort by nodeid, the optimizer won't be able to
					do index sorting since the order by columns are coming from
					two tables (`...node` AS `node` and `...node` AS `starter`)

					We could potentially drop the sortable_what & change the sorted
					column to just `nodeid` if $is_starter_only also guaranteed that
					the "nodeid" column will be node.nodeid & unambiguous. But at this
					point in time, I'm not certain that's true (e.g. view:topic with
					starter_only:1 will be problematic, I believe), and trying to
					flatten that logic out is out of scope ATM.
				 */
				$this->sortable_what['nodeid2'] = 'node.nodeid AS nodeid2';
			}
		}
	}

	protected function process_marked_filter($marked)
	{
		$currentUserId = vB::getCurrentSession()->get('userid');

		// FILTER_MARKED_READ is unimplemented.


		if ($marked == vB_API_Search::FILTER_MARKED_UNREAD AND !empty($currentUserId))
		{
			// if markinglimit isn't greater than 0, just disable filter. They're using this option wrong, and we
			// won't bother trying to set a minimum to make sense of it.
			// TODO: We may want to limit extremely large values of markinglimit, to not accidentally pummel the DB.
			// I'm not implementing said limit ATM since vB4 did not have a hard coded limit, as far as I'm aware.
			$markinglimit = vB::getDatastore()->getOption('markinglimit');
			if ($markinglimit <= 0)
			{
				$this->where[] = "0 ";
				return;
			}
			$timenow = vB::getRequest()->getTimeNow();
			$cutoff = $timenow - ($markinglimit * 86400);

			$this->join['noderead'] =
			"LEFT JOIN (
				SELECT read_closure.child AS nodeid
				FROM " . TABLE_PREFIX . "node AS node
				USE INDEX (node_pubdate)
				INNER JOIN " . TABLE_PREFIX . "closure AS read_closure
					ON node.nodeid = read_closure.child
				INNER JOIN " . TABLE_PREFIX . "noderead AS noderead
				ON noderead.nodeid = read_closure.parent
					AND noderead.userid = $currentUserId
					AND noderead.readtime > $cutoff
				WHERE node.publishdate > $cutoff
					AND node.publishdate <= noderead.readtime
				GROUP BY (read_closure.child)
			) AS noderead ON noderead.nodeid = node.nodeid";
			// Apply marking limit cutoff
			// Only return those with no noderead record OR outdated (outdated record matches happens most frequently when using channel marking) noderead record
			$this->where[] = "node.publishdate > $cutoff AND noderead.nodeid IS NULL
			";
			// The idea behind the change to the subquery & where is to minimize the subquery result set & get rid of noderead.readtime < node.publishdate
			// in the outer where clause, trading in possibly longer subquery time for a smaller set for the JOIN & a slightly less complex WHERE on the outer
			// query. Note, do NOT get rid of GROUP BY (read_closure.child). This is required to ensure that the LEFT JOIN will NOT cause duplicate nodes

			// Please use an exclude_type filter along side unread_only if you want to exclude channels.

		}
	}

	/**
	 * Processes the "my_channels" filter, which will return channels that this user belongs to for the specified channel
	 * type ("blog"|"group"). Please note that this function itself returns nothing! It's used in conjunction with
	 * getSearchResults()
	 * The channels that the user belongs to is built up by usercontext, look for "mychannels" in getAllChannelAccess()
	 *
	 * @param	string[]	$param		Must have key 'type' holding a string ("blog"|"group")
	 *									Ex. array('type' => 'blog')
	 */
	protected function process_my_channels_filter($params)
	{
		switch($params['type'])
		{
			case 'blog':
				$blogChannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_BLOG_PARENT);
				$parentid = intval($blogChannel['nodeid']);
				break;
			case 'group':
				$sgChannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_SOCIALGROUP_PARENT);
				$parentid = intval($sgChannel['nodeid']);
				break;
			default:
				$parentid = false;
				break;
		}

		/*
		 * This is an experimental method to fetch the $parentid by specifying a channelid instead of 'type'. It has a bit
		 * more overhead, but might be useful if we ever want to add this searchJSON to any channel page and not restrict it
		 * to specific hard-coded 'types'
		 * First, add the following function to Class vB_Channel:
				// This function is entirely reliant on the assumption that $channelTypes will be an invertible mapping.
				// That is, array_flip(array_flip(self::$channelTypes)) == self::$channelTypes, and there are no 'duplicate'
				// top level channels of the same 'type' (ex. two 'blog' top channels or 'article' channels).
				public static function getChanneltypeGuid()
				{
					if (empty(self::$channelTypeGuids))
					{
						self::$channelTypeGuids = array_flip(self::$channelTypes);
					}

					return self::$channelTypeGuids;
				}
		 * then add the following to this function, overriding the above $parentid logic as appropriate
				// first, determine what channel type this channelid is
				$channelid = intval($params['channelid']);
				$channelTypes = vB::getDatastore()->getValue('vBChannelTypes');
				if (!isset($channelTypes[$channelid]))
				{
					$this->where[] = "0 ";
					return ;
				}
				$channelType = $channelTypes[$channelid];
				// now, grab the 'top-most' channel for this channel type
				$typeToGuid = vB_Channel::getChanneltypeGuid();
				$channel = $this->library->fetchChannelByGUID($typeToGuid[$channelType]);
				if (empty($channel['nodeid']))
				{
					$this->where[] = "0 ";
					return;
				}
				$parentid = $channel['nodeid'];
		 */


		/*
		 * Channel ownership is defined as having a groupintopic record.
		 *	The GIT data is stored in allChannelAccess, and should already be a unique list,
		 *	so let's grab that instead of trying to do a complex join with distinct() to try to filter out dupes.
		 *	usercontext->getAllChannelAccess() is called in getSearchResults() or getNodePermTerms anyways and is
		 *	cached so calling it should not add much overhead here.
		 */
		$userContext = vB::getUserContext();
		$channelAccess = $userContext->getAllChannelAccess();

		// userid isn't used in the query, but is used implicitly to reject the notion of "guest" owned channels.
		// If that ever becomes a thing we'll have to fix this, and fix any erroneous git records with userid=0
		$userid = $userContext->fetchUserId();

		if (empty($userid) OR empty($channelAccess['mychannels']) OR empty($parentid))
		{
			$this->where[] = "0 /** Missing Data for my_channels filter, or user belongs to no channels **/";
			return;
		}

		$this->join['my_channels'] = "JOIN " . TABLE_PREFIX . "channel AS my_channels \n\t\t\t\t" .
											"\tON my_channels.nodeid = node.nodeid  \n\t\t\t\t" .
											"\tAND my_channels.nodeid IN (" . implode(',', $channelAccess['mychannels']). ")";
		$closureJoin =		"JOIN " . TABLE_PREFIX . "closure AS my_channels_closure \n\t\t\t\t" .
										"\tON my_channels_closure.child = my_channels.nodeid \n\t\t\t\t" .
										"\t\tAND my_channels_closure.parent = " . $parentid . "\n\t\t\t\t" .
										"\t\tAND my_channels_closure.depth > 0";
		if (empty($this->join['closure']))
		{
			$this->join['closure'] = $closureJoin;
		}
		else
		{
			$this->join['my_channels'] .= "\n\t\t\t\t" . $closureJoin;
		}
	}

	/**
	 * Processes the include/exclude channels filter...
	 * Please note that this function itself returns nothing! It's used in conjunction with getSearchResults()
	 *
	 * @param	string[]	$param		Must have key 'filterType', 'filterChannels', 'includeChildren'.
	 *                                  See vB_Library_Widget::cleanFilterNodes()
	 */
	protected function process_inc_exc_channel_filter($params)
	{
		$filterType = $params['filterType'];
		$filterChannels = $params['filterChannels'];
		$includeChildren = $params['includeChildren'];



		//convert into an explicit list of channels we will include.
		$filterChannels = vB_Library::instance('search')->convertToParentChannels($filterType, $filterChannels, $includeChildren);

		if (empty($filterChannels))
		{
			return;
		}

		/*
			side note, some forums have hundreds to thousands of channels, and this
			list might get a bit long. Not sure at the moment if that will be a
			bottleneck or not.
		 */

		/*
			We do a
				SELECT ...
				FROM node AS node ...
				STRAIGHT_JOIN node AS starter ...
			here because if we do a LEFT or INNER join, the optimizer frequently drives
			the query with the `starter` using the node_parent key and as soon as any
			ORDER BY exists (which all search queries have) it uses a temporary table
			in order to perform the sort, which turns out to be very slow.
			Doing the node straight_join starter forces `node` to drive the table which
			already has optimal indices (e.g. node_lastcontent for order by
			node.lastcontent) that can be used to short circuit the sorting, which greatly
			speeds up the query execution.
		 */
		$skipChannels = true;
		$joinType = 'straight';
		$this->doStarterJoin($skipChannels, $joinType);
		$this->where[] = $this->make_equals_filter('starter', 'parentid', $filterChannels);


		/*
			todo:
			ATM the default sentto join is being processed. When using the includ/exclude filters, I don't think we'd
			ever have a case where we actually ever want to include any of the "special" channels unless they're
			explicitly listed in the includes list.

			We should remove the unnecessary sentto join (possibly via additional criteria automatically set at the search API
			level?)
		 */
	}


	private static function make_equals_filter($table, $field, $value)
	{
		if (is_array($value) AND count($value)==1)
		{
			$value = array_pop($value);
		}

		$value = self::quote_smart($value);

		if (is_array($value))
		{
			return "$table.$field IN (" . implode(',', $value) . ")";
		}
		else
		{
			return "$table.$field = $value";
		}
	}

	private static function make_notequals_filter($table, $field, $value)
	{
		if (is_array($value) AND count($value)==1)
		{
			$value = array_pop($value);
		}
		$value = self::quote_smart($value);
		if (is_array($value))
		{
			return "$table.$field NOT IN (" . implode(',', $value) . ")";
		}
		else
		{
			return "$table.$field <> $value";
		}
	}

	private static function make_range_filter($table, $field, $values)
	{
		//null mean infinity in a given direction
		if (!is_null($values[0]) AND !is_null($values[1]))
		{
			$values = self::quote_smart($values);
			return "($table.$field BETWEEN $values[0] AND $values[1])";
		}
		else if (!is_null($values[0]))
		{
			$value = self::quote_smart($values[0]);
			return "$table.$field >= $value";
		}
		else if (!is_null($values[1]))
		{
			$value = self::quote_smart($values[1]);
			return "$table.$field <= $value";
		}
	}

	/**
	 *	Function to turn a php variable into a database constant
	 *
	 *	Checks the type of the variable and handles accordingly.
	 * numeric types are left unaffected, they don't need special handling.
	 * booleans are converted to 0/1
	 * strings are escaped and quoted
	 * nulls are converted to the string 'null'
	 * arrays are recursively quoted and returned as an array.
	 *
	 *	@param $db object, used for quoting strings
	 * @param $value value to be quoted.
	 */
	private static function quote_smart($value)
	{
		if (is_string($value))
		{
			return "'" . vB::getDbAssertor()->escape_string($value) . "'";
		}

		//numeric types are safe.
		else if (is_int($value) OR is_float($value))
		{
			return $value;
		}

		else if (is_null($value))
		{
			return 'null';
		}

		else if (is_bool($value))
		{
			return $value ?  1 : 0;
		}

		else if (is_array($value))
		{
			foreach ($value as $key => $item)
			{
				$value[$key] = self::quote_smart($item);
			}
			return $value;
		}

		//unhandled type
		//this is likely to cause as sql error and unlikely to cause db corruption
		//might be better to throw an exception.
		else
		{
			return false;
		}
	}

	protected $rawlimit = "";
	protected $word_distance_factor = 7; //between 3 to 25
	protected $date_factor = 78883200; //913*24*3600
	protected $title_boost = 2;
	protected $occurance_factor = 1.5;
	protected $corejoin = array();
	protected $join = array();
	protected $what = "node.nodeid";
	protected $sortable_what = array();
	protected $maintable = "node";
	protected $union_condition = array();
	protected $where = array();
	protected $from = "node as node";
	protected $score_order = array();
	protected $sort = "";
	protected $ranksort = "";
	protected $direction = "";
	protected $filtes = array();
	protected $done_permission_check = false;
	private static $field_map = array
	(
		'rank' => 'score',
		'relevance' => 'score',
		'author' => 'userid'
	);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103395 $
|| #######################################################################
\*=========================================================================*/
