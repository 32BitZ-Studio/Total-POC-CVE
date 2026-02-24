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

class vBSphinxSearch_Core extends vB_Search_Core
{
	const DEBUG = false;

	private $sphinxDB;
	private $table;
	private $what = array('id');
	private $where = array();
	private $groupby = '';

	private static $field_map = array
	(
		'rank' => 'score',
		'relevance' => 'score',
		'author' => 'userid'
	);

	private $attributes_definition = array
	(
		'contenttypeid'		=> 'rt_attr_uint',
		'lastcontentid'		=> 'rt_attr_uint',
		'parentid'			=> 'rt_attr_uint',
		'starter'			=> 'rt_attr_uint',
		// Keep these in sync with the "starter" sort fields, see get_sort_field_for_topic_view()
		// These fields are those of the matched node's starter.
		'starterparent'		=> 'rt_attr_uint', //the starter's parent id - the channelid
		'starteruser'		=> 'rt_attr_uint', // the starter's user id
		'starterlastcontent' => 'rt_attr_timestamp', // ...
		'starterpublishdate' => 'rt_attr_timestamp',
		'startercreated'	=> 'rt_attr_timestamp',
		'startertextcount'	=> 'rt_attr_uint',
		'starterdisplayorder' => 'rt_attr_uint',
		'startervotes'		=> 'rt_attr_uint',
		// TODO: propagate starter's string sorting field changes to descendants on starter update - VBV-17652
		'startertitlesort'  => 'rt_attr_string',
		'starterauthorname' => 'rt_attr_string',
		'closure'			=> 'rt_attr_multi', // it's the list of all the node's parents and the node itself
		'depth'				=> 'rt_attr_json', // the depth of the node's each parent
		'userid'			=> 'rt_attr_uint',
		'authorname'		=> 'rt_attr_string',
		'setfor'			=> 'rt_attr_uint',
		'sentto'			=> 'rt_attr_multi', //populated from the sentto table
		'showpublished'		=> 'rt_attr_uint',
		'approved'			=> 'rt_attr_uint',
		'showapproved'		=> 'rt_attr_uint',
		'viewperms'			=> 'rt_attr_uint',
		'featured'			=> 'rt_attr_uint',
		'inlist'			=> 'rt_attr_uint',
		'protected'			=> 'rt_attr_uint',
		'votes'				=> 'rt_attr_uint',
		'lastcontent'		=> 'rt_attr_timestamp',
		'created'			=> 'rt_attr_timestamp',
		'publishdate'		=> 'rt_attr_timestamp',
		'unpublishdate'		=> 'rt_attr_timestamp',
		'prefixid'			=> 'rt_attr_uint',
		'tagid'				=> 'rt_attr_multi', //populated from the tagnode table
		'textcount'			=> 'rt_attr_uint',
		'trendingweight'			=> 'rt_attr_uint',
		'eventstartdate'    => 'rt_attr_timestamp',
		'eventenddate'    => 'rt_attr_timestamp',
		'titlesort'    => 'rt_attr_string',
	);

	public function __construct()
	{
		$config = vB::getConfig();
		$this->table = $config['Database']['dbname'];
	}

	private function initConnection()
	{
		if(!$this->sphinxDB)
		{
			$config = vB::getConfig();
			$this->connect($config);
		}
	}

	/**
	 *	Connects to the sphinx daemon.
	 *
	 *	@param array $config The configuration array from vB:getConfig
	 *
	 *	@throws vB_Exception_Api 'sphinx_not_configured' if the host or port are not set.
	 */
	private function connect($config)
	{
		if (empty($config['Misc']['sphinx_host']) OR empty($config['Misc']['sphinx_port']))
		{
			throw new vB_Exception_Api('sphinx_not_configured');
		}

		$noDbConfig = array();
		$this->sphinxDB = new vBSphinxSearch_Connection($noDbConfig, $config);
		$this->sphinxDB->connect('', $config['Misc']['sphinx_host'], $config['Misc']['sphinx_port'], '', '', false);
	}

	private function attributeIsString($fieldname)
	{
		switch($this->attributes_definition[$fieldname])
		{
			case 'rt_attr_string':
			case 'rt_attr_json':
				$isString = true;
				break;
			default:
				$isString = false;
				break;
		}

		return $isString;
	}

	private function propagateStarterInheritedFields($node, $changes)
	{
		$isStarter = ($node['starter'] == $node['nodeid']);
		if ($isStarter)
		{
			// Take care of updating any of the children's starter_x fields.
			// We do it here in case there's no text change and we short-circuit
			// out of this function before we reach the end of function.

			$map = $this->get_starter_inherited_fields();
			$childrenFields = array();
			$setSQL = array();
			foreach ($map AS $__starterkey => $__childkey)
			{
				$needsChange = (
					empty($changes['existing']) OR
					isset($changes['changes'][$__childkey])
				);
				// VBV-17652
				// We can't do updates on strings yet, only delete/re-insert.
				// Along with enabling sorting by starter.title & starter.author, we should
				// also add code to do delete/re-insert OR update (depending on minimum
				// supported sphinxsearch version) for the two string fields so that on
				// starter update, the replies/comment search indices' startertitlesort &
				// starterauthor fields are properly updated.
				$isStringChange = $this->attributeIsString($__childkey);
				if ($needsChange AND !$isStringChange)
				{
					$__key =  $this->sphinxDB->clean_identifier($__childkey);
					$__value = $this->quote_smart($__childkey, $node[$__childkey], false);
					$setSQL[] = "$__key = $__value";
				}
			}

			if (!empty($setSQL))
			{
				$setSQL = " SET " . implode(", ", $setSQL);
				$query = "UPDATE " . $this->table . $setSQL . " WHERE starter = " . intval($node['starter']);
				$this->sphinxDB->query_write($query);
			}
		}
	}

	/**************INDEXING**************************/

	public function indexText($node, $title, $text, $forceupdate = false)
	{
		$this->initConnection();

		$changes = $this->compute_changes($node);

		$assertor = vB::getDbAssertor();
		$this->propagateStarterInheritedFields($node, $changes);
		// compute_changes() sets the starter_x fields for the current node, & it'll be INSERTed
		// below. The REPLACE case should not matter as this node (unless it's a channel) should
		// have the same starter, and be updated by the above UPDATE query.

		// no meaningful words, no index
		if ((empty($changes['existing']) OR !empty($changes['reindex'])) AND empty($title) AND empty($text))
		{
			// updating the CRC32 value so it would not be picked up by the indexer again
			$assertor->update('vBForum:node', array('CRC32' => 1), array('nodeid' => $node['nodeid']));
			return false;
		}

		if (empty($title) AND empty($text))
		{
			$crc = 1;
		}
		else
		{
			$crc = $this->crc_uint_string($title . $text);
		}

		// check if the same content has already been indexed (update)
		if (!empty($changes['existing']) AND !$forceupdate AND $node['CRC32'] == $crc AND empty($changes['changes']))
		{
			// no need to index if the content hasn't changed
			return false;
		}

		// text has changed, update the existing node with the new CRC
		if ($node['CRC32'] != $crc)
		{
			$assertor->update('vBForum:node', array('CRC32' => $crc), array('nodeid' => $node['nodeid']));
		}

		$values = array("'" . $this->sphinxEscapeString($title) . "'", "'" . $this->sphinxEscapeString($text) . "'");

		foreach ($this->attributes_definition as $key => $type)
		{
			//need to do a name switch due to name conflicts with title
			if($key == 'titlesort')
			{
				$value = isset($node['title']) ? $node['title'] : '';
			}
			else
			{
				$value = isset($node[$key]) ? $node[$key] : '';
			}

			//this is a string but sphinx needs it to be an int
			if ($key == 'prefixid')
			{
				$value = $this->crc_uint_string($value);
			}

			$values[] = $this->quote_smart($key, $value, false);
		}

		$query = (empty($changes['existing']) ? 'INSERT' : 'REPLACE') . " INTO " . $this->table . "(
				id, title, content, " . implode(', ', array_keys($this->attributes_definition)) . "
			)
			VALUES (
				$node[nodeid], " . implode(', ', $values) . "
			)
		";


		$this->sphinxDB->query_write($query);

		$config = vB::getConfig();
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		if ($err = $this->sphinxDB->error())
		{
			throw new vB_Exception_Database($err);
		}

		return true;
	}

	/**
	 *	Index a batch of nodes
	 */
	public function indexTextBatch($nodes, $titles, $texts, $forceupdate = false)
	{
		//this exists because we need it for the dbsearch implemenation and we need
		//to maintain a common interface.  For not just index each node individually as before.
		foreach($nodes AS $nodeid => $node)
		{
			$this->indexText($node, $titles[$nodeid], $texts[$nodeid], $forceupdate);
		}
	}

	public function reIndexAll($silent = false)
	{
		$this->initConnection();

		$config = vB::getConfig();
		$command = $config['Misc']['sphinx_path'] . '/bin/indexer --config ' . $config['Misc']['sphinx_config'] .
			' --sighup-each --rotate ' . ($silent ? '--quiet ' : '') . ($this->table . '_disk');

		if ($silent)
		{
			$this->exec_command($command, $silent);
		}
		else
		{
			$this->exec_command_feedback($command, $silent);
		}
		// need to restart the service
		$this->restart($silent);
		$this->sphinxDB->query_write($query = "TRUNCATE RTINDEX " . $this->table);
		$this->sphinxDB->query_write("ATTACH INDEX " . ($this->table . '_disk') . " TO RTINDEX " . $this->table);
		vB::getDbAssertor()->update('vBForum:node', array('CRC32' => 1), vB_dB_Query::CONDITION_ALL);
		return true;
	}

	/**
	 *	Updates the trending post data based
	 *
	 *	@param int $lookback -- the time, in hours, that we consider threads and replies for trending
	 *	@param int $minimum -- the minimum time, in hours, that we will take as the thread lifetime.
	 *		Threads created more recently than this will be consider to have been created minimum hours
	 *		ago for purposes of scoring
	 */
	public function indexTrending($lookback, $minimum)
	{
		$this->initConnection();

		//sphinx delegates some searches to the DB implementation.
		//we need to keep the DB info up to date or that's not going to work
		$vBDBSearch_Core = new vBDBSearch_Core();
		$vBDBSearch_Core->indexTrending($lookback, $minimum);

		$lookback = (int) $lookback;
		$minimum = (int) $minimum;

		$db = vB::getDbAssertor();

		$channelApi = vB_Api::instance('content_channel');
		$channels = $channelApi->fetchTopLevelChannelIds();

		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');

		$timenow = vB::getRequest()->getTimenow();
		$timecut = $timenow - ($lookback * 3600);

		$query = 'UPDATE ' . $this->table . ' SET trendingweight = 0 WHERE trendingweight > 0';
		$this->sphinxDB->query_write($query);

		$result = $db->assertQuery('vBDbSearch:getTrendingWeights', array(
			'timenow' => $timenow,
			'timecut' => $timecut,
			'excludetypes' => $channelTypeId,
			'minlifetime' => $minimum,
			'specialchannelid' => $channels['special'],
		));

		foreach($result AS $row)
		{
			$query = 'UPDATE ' . $this->table . ' SET trendingweight = ' . intval($row['weight']) . ' WHERE starter = ' . intval($row['nodeid']);
			$this->sphinxDB->query_write($query);
		}
	}

	public function attributeChanged($nodeid)
	{
		$this->initConnection();

		try
		{
			$node = vB_Library::instance('node')->getNodeBare($nodeid);
		}
		catch (Exception $e)
		{
			return;
		}

		$changes = $this->compute_changes($node);
		if (!empty($changes['reindex']))
		{
			return $this->index($nodeid, false);
		}
		else
		{
			// If we're not completely reindexing, we still might have to update some int/timestamp fields.
			$this->propagateStarterInheritedFields($node, $changes);
		}

		//this is a string but sphinx needs it to be an int
		if (isset($changes['changes']['prefixid']))
		{
			$changes['changes']['prefixid'] = $this->crc_uint_string($changes['changes']['prefixid']);
		}

		$values = array();
		foreach ($changes['changes'] as $key => $value)
		{
			$values[] = "$key = " . $this->quote_smart($key, $value, false);
		}

		if (empty($values))
		{
			return false;
		}

		$query = "UPDATE " . $this->table . " SET " . implode(', ', $values) . " WHERE id = " . intval($nodeid);
		$this->sphinxDB->query_write($query);

		$config = vB::getConfig();
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

	}

	/**************DELETING**************************/

	public function emptyIndex()
	{
		$this->initConnection();

		$config = vB::getConfig();
		parent::emptyIndex();
		$this->sphinxDB->query_write($query = "TRUNCATE RTINDEX " . $this->table);
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}
	}

	public function delete($nodeid, $node = false)
	{
		$this->initConnection();

		$nodeid = intval($nodeid);
		$config = vB::getConfig();
		$res = $this->sphinxDB->query($query = '
			SELECT id
			FROM ' . $this->table . "
			WHERE closure = $nodeid
			/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/"
		);

		$children = array($nodeid);
		while($row = $this->sphinxDB->fetch_array($res))
		{
			$children[] = $row['id'];
		}

		$this->sphinxDB->query_write($query = "DELETE FROM " . $this->table . " WHERE id IN (" . implode(',',$children) . ")");
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		//delete any trending information for this node.  We add it for the DB Implementation, we need to remove it.
		$assertor = vB::getDbAssertor();
		$assertor->delete('vBForum:trending', array('nodeid' => $nodeid));
	}


	public function deleteBulk($nodeids)
	{
		$this->initConnection();

		if (empty($nodeids))
		{
			return;
		}

		$config = vB::getConfig();
		$res = $this->sphinxDB->query($query = '
			SELECT id
			FROM ' . $this->table . "
			WHERE closure IN (" . implode(',', $nodeids) . ")
			/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/"
		);

		while($row = $this->sphinxDB->fetch_array($res))
		{
			$nodeids[] = $row['id'];
		}

		$this->sphinxDB->query_write($query = "DELETE FROM " . $this->table . " WHERE id IN (" . implode(',',$nodeids) . ")");
		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}
	}

	/**************SEARCHING**************************/

	public function getResults(vB_Search_Criteria $criteria)
	{
		$config = vB::getConfig();
		$vBDBSearch_Core = new vBDBSearch_Core();
		$keywords = $criteria->get_raw_keywords();

		// if there are no keywords, fall back to DB search
		if (empty($keywords))
		{
			return $vBDBSearch_Core->getResults($criteria);
		}

		//do this *after* we fall back.  That way if there is an error on the connection
		//we won't be affected if the search isn't going to sphinx.
		$this->initConnection();

		$results = $this->getTwoPassResults($criteria);

		//getTwoPassResults will return an array of results or a string cache key
		if (is_array($results))
		{
			// Note that vB_Search_Core::getTwoPassCacheKey() does not return a cachekey
			// if $criteria has any post processors, so this is only hit when there's no post processors
			// and we can return the nodeids right away.
			$nodeids = array();
			foreach ($results AS $nodeid)
			{
				$nodeids[$nodeid] = $nodeid;
			}
			return $nodeids;
		}
		else
		{
			$cacheKey = $results;
		}

		$this->filters = array(
			'make_equals_filter'    => $criteria->get_equals_filters(),
			'make_notequals_filter' => $criteria->get_notequals_filters(),
			'make_range_filter'     => $criteria->get_range_filters(),
			'complex'               => $criteria->get_complex_filters(),
		);

		$this->process_sort($criteria);

		if (!empty($this->filters['make_equals_filter']['view']))
		{
			$this->process_view_filters($this->filters['make_equals_filter']['view']);
			unset($this->filters['make_equals_filter']['view']);
		}

		if (!empty($this->filters['make_equals_filter']['follow']))
		{
			$this->process_follow_filters($this->filters['make_equals_filter']['follow'], $criteria);
			unset($this->filters['make_equals_filter']['follow']);
		}

		// my channels
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
		$this->process_filters($criteria, 'make_equals_filter', $cacheKey ? true : false);
		//handle notequals filters
		$this->process_filters($criteria, 'make_notequals_filter', $cacheKey ? true : false);
		//handle range filters
		$this->process_filters($criteria, 'make_range_filter', $cacheKey ? true : false);

		$this->setNodePermTerms($cacheKey ? true : false);

		$field = $criteria->is_title_only() ? '@title ' : '';
		$keywords = $this->adjustKeywordsForSphinx($keywords);

		//this won't matter if Sphinx case folding is set up correctly, but we lowercase the text
		//before we index it so we should do the same before we search on it just to be consistent.
		$string = vB::getString();
		$keywords = $string->strtolower($keywords);

		array_unshift($this->where, "MATCH('$field" . $this->sphinxEscapeKeywords($keywords) . "')");

		$post_processors = $criteria->get_post_processors();

		$query_limit = false;

		//note that without a limit clause sphinx will default to a limit of 20
		//currently with the "no limit" searches we don't use keywords and delegate
		//to the DB search so it isn't a problem, but its something we need to sort
		//out at some point.
		if(!$criteria->getNoLimit())
		{
			$maxresults = vB::getDatastore()->getOption('maxresults');
			$maxresults = ($maxresults > 0) ? $maxresults : 0;

			/*	This is a hacky compromise (ew) and not fully tested, and we may end up taking it out or modifying it.
			 *	This is to handle the possibility that a post sphinx-search process (like when using the unread_only
			 *	filter) can severely limit the # of search results after it was already limited by $maxresults. Users
			 *	might be expecting that the very end result set is limited by the maxresults option, meaning we should
			 *	place the LIMIT after the post processes, but if we don't place a limit on sphinx search, it might
			 *	happily return all the nodes ever (not a very useful search in that case, but could happen). So the
			 *	compromise is to use an "expected post process cull ratio" so that the final result is closer to the
			 *	$maxresults. This means that any post processors should limit the max results themselves!
			 */
			if (!empty($post_processors))
			{
				// 1.5 is a completely arbitrary value. We have absolutely no research to show that 1.5 is the best ratio, but
				// it just seems like a nice and conservative starting point.
				$maxresults = $maxresults * 1.5;
			}

			//this probably doesn't do what the person who wrote it thinks it does.  The default limit
			//for sphinx is 20
			if (!empty($maxresults))
			{
				$query_limit = "LIMIT " . $maxresults . " OPTION max_matches=" . $maxresults;
			}
		}

		$groupby = '';
		if (!empty($this->groupby))
		{
			$groupby = '
				GROUP BY ' . $this->groupby;
		}


		// TODO: sticky sort is first in DB search.
		// isstarter sort is next in DB search, but it's left out of
		// $this->sort.
		// Note, isstarter sort has been moved into process_sort()
		// now that it's no longer just part of an include_starter filter.
		// TODO: what is "include_starter" actually supposed to do in sphinxsearch?

		$query = '
			SELECT ' . implode(', ', $this->what) . '
			FROM ' . $this->table . '
			WHERE ' . implode(' AND ', $this->where) . $groupby . '
			ORDER BY ' . implode(', ', $this->sort) . "
				$query_limit
			/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		$res = $this->sphinxDB->query($query);

		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		if ($cacheKey)
		{
			$this->what[] = 'starteruser';
			$this->what[] = 'starterparent';
		}

		$nodeids = array();
		while($row = $this->sphinxDB->fetch_array($res))
		{
			$value = current($row);
			$nodeids[$value] = $value;
		}
		if (empty($nodeids))
		{
			return array();
		}

		if (empty($post_processors))
		{
			if ($cacheKey)
			{
				if (!empty($this->filters['make_equals_filter']['channelid']))
				{
					vB_Search_Core::saveSecondPassResults($nodeids, $cacheKey, $this->filters['make_equals_filter']['channelid']);

				}
				else
				{
					vB_Search_Core::saveSecondPassResults($nodeids, $cacheKey);
				}
			}
		}
		else
		{
			foreach ($post_processors AS $post_processor)
			{
				$vBSphinxSearch_Core = new vBSphinxSearch_Core(); // why do we need a new instance every time...?
				$nodeids = $vBSphinxSearch_Core->$post_processor($nodeids, $criteria);
			}

			if (empty($nodeids))
			{
				return array();
			}
			$criteria->reset_post_processors();
		}
		return $nodeids;
	}

	protected function postProcessorGetLimitValue(vB_Search_Criteria $criteria)
	{
		if(!$criteria->getNoLimit())
		{
			$maxresults = vB::getDatastore()->getOption('maxresults');
			$maxresults = ($maxresults > 0) ? $maxresults : 0;
			return $maxresults;
		}
		return 0;
	}

	/**
	 *	Handle processing for the equals / range filters
	 * @param object $criteria vB_Search_Criteria
	 * @param array $filter_method string The name of the method to call to create a
	 *		where snippet for this kind of filter (currently equals and range -- not planning
	 *		to add more).  This should be the name of a private method on this class.
	 * @param  bool $excludeUserSpecific Exclude user specific queries. Used for precaching
	 */
	private function process_filters(vB_Search_Criteria &$criteria, $filter_method, $excludeUserSpecific = false)
	{
		$viewTopics = $criteria->has_topic_view_filter();

		foreach ($this->filters[$filter_method] as $field => $value)
		{
			switch ($field)
			{
				//if this is a null filter we that forces a 0-result query
				case 'prefixid':
					if(is_array($value))
					{
						$value = array_map(array($this, 'crc_uint_string'), $value);
					}
					else
					{
						$value = $this->crc_uint_string($value);
					}

					$where = $this->$filter_method('prefixid', $value);
					$this->where[] = $where;
					break;
				case 'null':
					$this->where[] = "id = 0 /** field is null **/";
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
							$this->where[] = $this->$filter_method('starterlastcontent', $value);
						}
						else
						{
							$this->where[] = $this->$filter_method('publishdate', $value);
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
				case 'exclude_visitor_messages':
					$this->process_visitor_message_filter($value, 'exclude');
					break;
				case 'include_private_messages':
					$this->process_private_message_filter($value, 'include');
					break;
				case 'private_messages_only':
					$this->process_private_message_filter($value, 'only');
					break;
/** @todo OR operator is not supported by sphinx*/
 				case 'OR':
// 					foreach ($value as $fld => $val)
// 					{
// 						$fld = $this->sphinxDB->clean_identifier($fld);
// 						$qbits[] = $this->make_equals_filter($fld, $val);
// 					}
// 					$this->where[''] = "(" . implode(' OR ', $qbits) . ")";
 					break;
				case 'marked':
					$this->process_marked_filter($value);
					if ($value == vB_API_Search::FILTER_MARKED_UNREAD)
					{
						$criteria->add_post_processors('postProcessorMarkedUnreadFilter'); // only required in sphinx search, not DB search.
					}
					break;

				case 'my_channels':
					$this->process_my_channels_filter($value);
					break;
				case 'trending':
					if ($value)
					{
						$this->where['trending'] = "trendingweight > 0";
					}
					break;
				case 'eventstartdate':
				case 'eventenddate':
					if (!isset($this->where['eventdate']))
					{
						$eventContentTypeId = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Event');
						$this->where['eventdate'] = "contenttypeid = " . intval($eventContentTypeId) . " ";
					}
					$this->where[] = $this->$filter_method($field, $value);
					break;

				default:
					$dbfield = $field;
					if (isset(self::$field_map[$field]))
					{
						$dbfield = self::$field_map[$field];
					}
					$dbfield = $this->sphinxDB->clean_identifier($dbfield);
					$where = $this->$filter_method($dbfield, $value);
					$this->where[] = $where;
					break;
			}
		}
	}

	/**************PROCESSING**************************/

	/**
	 *	Process the filters for the requested tag
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
		$this->where[] = $this->make_equals_filter('tagid', $tagids);
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

		$nodeids = vB::getCleaner()->clean($nodeids, vB_Cleaner::TYPE_ARRAY_UINT);

		$this->where[] = $this->make_notequals_filter('closure', $nodeids);
		$this->where[] = $this->make_notequals_filter('id', $nodeids);
	}

	protected function process_starter_only_filter($starter)
	{
		if ($starter)
		{
			$this->what[] = "(starter = id) as starter_id";
			$this->where[] = "starter_id > 0 AND starter > 0";
		}
	}

	protected function process_reply_only_filter($reply)
	{
		if ($reply)
		{
			$this->what[] = "(starter = parentid) as is_reply";
			$this->where[] = "is_reply > 0";
		}
	}


	protected function process_comment_only_filter($comment)
	{
		if ($comment)
		{
			$this->what[] = "(starter <> parentid AND starter <> id AND starter <> 0) as is_comment";
			$this->where[] = "is_comment > 0";
		}
	}


	protected function process_visitor_message_filter($userid, $type)
	{
		$userid = intval($userid);
		if ($type == 'include')
		{
			$this->what[] = "(userid = $userid OR setfor = $userid) as user_setfor";
			$this->where[] = "user_setfor = 1";
		}
		elseif ($type == 'only')
		{
			$this->what[] = "((userid = $userid AND  setfor <> 0) OR (setfor = $userid AND userid <> 0)) as user_setfor";
			$this->where[] = "user_setfor = 1";
		}
		elseif ($type == 'for')
		{
			$this->where[] = $this->make_equals_filter('setfor', $userid);
		}
		elseif ($type == 'exclude')
		{
			$this->where[] = $this->make_equals_filter('setfor', 0);
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
				$this->where[] = "contenttypeid <> $pmcontentypeid";
			}
			else
			{
				$this->what[] = "(contenttypeid <> $pmcontentypeid OR IN(sentto,$userid)) as user_sentto";
				$this->where[] = "user_sentto = 1";
			}
		}
		elseif ($type == 'only')
		{
			if (empty($userid))
			{
				$this->where[] = "id=0 /** login to see private messages **/";
			}
			$this->where[] = $this->make_equals_filter('sentto', $userid);
			$this->where[] = $this->make_equals_filter('contenttypeid', $pmcontentypeid);
		}
	}

	private function get_starter_inherited_fields()
	{
		/*
			Unfortunately, we can't just do starter.$sort_field like in the
			DB search implementation because the sphinx RT index can't do
			joins, so all of the "starter" fields that we want to do sorting/filtering
			on has to be pre-saved into the node's realtime index record.

			Thus, we need to keep track of each field, and if necessary update the
			sphinx disk & realtime indices' structures to include that field.
		 */
		$inherited = array(
			// these are not used for sorting, but still need to be propagated down.
			// Note that the naming convention is also slightly different (not intentionally)
			// so these are handled manually below
			//'userid',
			//'parentid',
			// these are used for sorting
			'lastcontent',
			'publishdate',
			'created',
			'textcount',
			'displayorder',
			'votes',
		);
		/*
			Uninherited fields:

			// This isn't something stored in the index, but rather something calculated via the weight() function
			// for matching.
			'rank',

			// eventstartdate only exists for starters atm.
			'eventstartdate',
			// trendingweight is associated with the node's starter & is automatically updated via cron
			// for a starter's descendants. So we can use it as it is even for title view.
			'trendingweight',
			// currently, most non-cutting-edge versions of sphinx require
			// a delete + insert instead of an update for updating a string field.
			// Skip these for now.
			'authorname',
			'titlesort',
		 */

		$return = array();
		foreach ($inherited AS $__key)
		{
			$return[$__key] = "starter" . $__key;
		}

		$return['userid'] = "starteruser";
		$return['parentid'] = "starterparent";
		$return['authorname'] = "starterauthorname";
		$return['title'] = "startertitlesort";

		return $return;
	}

	private function get_sort_field_for_topic_view($sort_field)
	{
		// Keep this in sync with get_starter_inherited_fields() &
		// $this->attributes_definition;

		/*
			userid => starteruser & parentid => starterparent aren't used for sort, but
			we don't have to unset them here since $sort_map in process_sort()
			don't have those as possible $sort_fields.
		 */
		$map = $this->get_starter_inherited_fields();
		if (isset($map[$sort_field]))
		{
			return $map[$sort_field];
		}
		else
		{
			// special case, titlesort refers to the starter.title, which is saved in
			// the index as startertitle.
			if ($sort_field == "titlesort" AND isset($map['title']))
			{
				return $map['title'];
			}

			return $sort_field;
		}
	}

	protected function process_sort(vB_Search_Criteria &$criteria)
	{
		$sort_array = $criteria->get_sort();

		$this->sort = array();

		// keep this in sync with the database search implementation
		// Also keep this in sync with the "starter" sort fields, see get_sort_field_for_topic_view()
		$sort_map = array (
			'user'           => 'authorname',
			'author'         => 'authorname',
			'publishdate'    => 'publishdate',
			'created'        => 'created',
			'started'        => 'created',
			'last_post'      => 'lastcontent',
			'lastcontent'    => 'lastcontent',
			// todo: should this be startertitlesort for *all* views to keep in sync with
			// vbdbsearch behavior? ATM it maps to startertitle via get_sort_field_for_topic_view()
			// only if $viewTopics below is true.
			'title'          => 'titlesort',
			'textcount'      => 'textcount',
			'replies'        => 'textcount',
			'displayorder'   => 'displayorder',
			'rank'           => 'rank', // this is "score" in the db implementation
			'relevance'      => 'rank', // this is "score" in the db implementation
			'votes'          => 'votes',
			'eventstartdate' => 'eventstartdate',
			'trending'       => 'trendingweight',
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

		foreach ($sort_array AS $sort => $direction)
		{
			$direction = strtoupper($direction);
			if (!in_array($direction, array('ASC', 'DESC')))
			{
				$direction = 'ASC';
			}

			// See vbdbsearch's querydef for more details.
			// Handle sorting by "starters first"
			if ($sort == "isstarter")
			{
				if (!$is_starter_only)
				{
					$this->sort[] =  'is_starter2 ' . $direction;
					$this->what[] = '(id = starter) as is_starter2';
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
					Also see the DB search implementation.
					Since sphinx index already has the eventstartdate column, not having
					special handling will not cause an error like in the DB search, but
					having both Sphinx search & DB search return the same type of data
					as much as possible is ideal.
					So filter events only in some fashion to emulate the JOIN ... event AS event USING nodeid
					behavior.
				 */
				if (!isset($this->where['eventdate']))
				{
					$eventContentTypeId = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Event');
					$this->where['eventdate'] = "contenttypeid = " . intval($eventContentTypeId) . " ";
				}
			}

			if ($sort == "trending")
			{
				if (!isset($this->where['trending']))
				{
					$this->where['trending'] = "trendingweight > 0";
				}
			}

			//look for a core sort option
			if (isset($sort_map[$sort]))
			{
				$sort_field = $sort_map[$sort];
				// process rank sortings
				if ($sort_field == 'rank')
				{
					$this->what[] = "weight() as rank";
				}
				else
				{
					if ($viewTopics)
					{
						// sort by the starter's field if search result is only going to list starters.
						$sort_field = $this->get_sort_field_for_topic_view($sort_field);
					}
					else
					{
						$sort_field = "$sort_field";
					}
				}

				$this->sort[] = $sort_field . ' ' . $direction;
			}
		}
	}

	protected function process_marked_filter($marked) /** two stage */
	{
		$currentUserId = vB::getCurrentSession()->get('userid');

		//this can't be made to happen in the current UI because the general
		//search filter processing won't function without a valid non guest user.
		if (empty($currentUserId))
		{
			$this->where[] = "id=0 /** no user in session **/";
			return;
		}


		// FILTER_MARKED_READ is unimplemented


		if ($marked == vB_API_Search::FILTER_MARKED_UNREAD)
		{
			$markinglimit = vB::getDatastore()->getOption('markinglimit');
			if ($markinglimit <= 0)
			{
				$this->where[] = "id=0 /** invalid markinglimit **/";
				return;
			}
			$timenow = vB::getRequest()->getTimeNow();
			$cutoff = $timenow - ($markinglimit * 86400);
			// All we can do with sphinx now is to add a filter on publishdate. The actual complex joins that decide the unread status comes
			// in at function postProcessorMarkedUnreadFilter()
			$this->where[] = $this->make_range_filter('publishdate', array($cutoff, NULL));

		}
	}

	public function postProcessorMarkedUnreadFilter($nodeids, vB_Search_Criteria $criteria)
	{
		//does not need the sphinx connection.  If that changes add $this->initConnection(); here

		$nodeids = vB::getCleaner()->clean($nodeids, vB_Cleaner::TYPE_ARRAY_UINT);
		$currentUserId = vB::getCurrentSession()->get('userid');

		// After discussion with other devs, we're probably expecting 1-2k nodeids *AT MOST*. We
		// could be wrong, of course - the admin could've set the search results limit to something
		// higher, and the sphinx search might've returned enough to fill that higher limit. However,
		// going with the expected # of values in that range, using the IN() list instead of
		// creating temporary tables should be Okay. If search breaks due to hitting the max packet size or
		// is too slow due to the IN(), we may need revisit this. Please update this comment then.

		$limit = $this->postProcessorGetLimitValue($criteria);
		// if there's no limit found, let's just hard-code a limit to 1000. This is because the stored query *must*
		// have an integer for the limit of some kind or else the query will break
		if (empty($limit))
		{
			$limit = 1000;
		}

		$orderby = implode(', ', $this->sort);

		$assertor = vB::getDbAssertor();
		$nodes = $assertor->assertQuery(
			'vBDBSearch:getUnreadNodesIn',
			array(
				'currentuserid'=> $currentUserId,
				'nodeids' => $nodeids,
				'limit' => $limit,
			)
		);

		/*
		 *	There are a few ways to go about the sorting.
		 *	Easiest is to add				ORDER BY FIELD(node.nodeid, {nodeids})
		 *	to the db query, but I'm not certain on its performance for lage # of nodeids in the result.
		 *	Hardest would be to make the db query a method query, pass in the criteria object and have it
		 *	reconstruct its own ORDER BY clauses (hopefully using some indices), but that involves taking
		 *	care of any addition joins/unions that might come out of it, which is very messy.
		 *	Another, easy way is to loop through the result set and sort it. IMO this is preferred at the moment
		 *	because 1) it will not take a long time to implement, 2) it takes most of performance optimizations
		 *	out of the query and into sorting in PHP, which is easier to work with (and involves less second guessing
		 *	the mysql optimizer and more bigO calculations). So I'm going to go with that
		 *
		 *	A few things helping us with this is the fact that function getResults() which calls this function ensures
		 *	that $nodeids is both keyed & valued by nodeid
		 */
		// Below should be ~O(n), assuming the array copy doesn't do anything crazy
		$notfound = $nodeids;
		foreach ($nodes AS $row)
		{
			unset($notfound[$row['nodeid']]);
		}
		foreach ($notfound AS $nodeid)
		{
			unset($nodeids[$nodeid]);
		}

		return $nodeids;
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
			!empty($depth) AND ($depth == 1) AND
			is_numeric($channelid) AND
			(
				in_array($channelid, $userdata['canview']) OR
				in_array($channelid, $userdata['canalwaysview']) OR
				in_array($channelid, $userdata['canmoderate']) OR
				in_array($channelid, $userdata['selfonly'])
			)
		)
		{
			$channelid = intval($channelid);
			// The user can moderate the channel.
			if (in_array($channelid, $userdata['canmoderate']))
			{
				$this->where[] = $this->make_equals_filter('parentid', $channelid);
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
					$this->where[] = $this->make_equals_filter('parentid', $channelid);
					if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
					{
						$this->where[] = "showpublished > 0";
					}
					// Allow user to see their own, unapproved nodes
					$this->where[] = "(showapproved > 0 OR userid = $userId)";

					if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $channelid))
					{
						$this->what[] = "(id = starter OR starter = 0) as is_starter";
						$this->where[] = "is_starter = 1";
					}
					$this->done_permission_check = true;
					return;
				}

				if (!empty($gitInfo))
				{
					$gitWhere = " OR id IN (" . implode(',', array_keys($gitInfo)) . ") ";
				}
			}

			//if the user can't moderate, and doesn't have canviewthread, they just get titles and for the starters
			if (!empty($userId) AND in_array($channelid, $userdata['canview']) AND !vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $channelid))
			{
				$this->where[] = $this->make_equals_filter('parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "node.showpublished > 0";
				}
				// Allow user to see their own, unapproved nodes
				$this->where[] = "(showapproved > 0 OR userid = $userId)";

				$this->what[] = "(viewperms > 0 $gitWhere) AS vp";
				$this->where[] = "vp = 1";

				$this->what[] = "(id = starter OR starter = 0) AS is_starter";
				$this->where[] = "is_starter = 1";

				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, is logged in, isn't a channel member, and has forum permission "can view others".
			if (!empty($userId) AND in_array($channelid, $userdata['canview']))
			{
				$this->where[] = $this->make_equals_filter('parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "showpublished > 0";
				}
				// Allow user to see their own, unapproved nodes
				$this->where[] = "(showapproved > 0 OR userid = $userId)";
				$this->what[] = "(viewperms > 0 $gitWhere) as vp";
				$this->where[] = "vp = 1";
				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, isn't a channel member,  is logged in, and has forum permission "can view posts" but not"can view others".
			if (!empty($userId) AND in_array($channelid, $userdata['selfonly']))
			{
				$this->where[] = $this->make_equals_filter('parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "showpublished > 0";
				}
				// They can only see their own nodes. Allow them to see their own nodes in moderation
				//$this->where[] = "showapproved  > 0";
				$this->where[] = "userid = $userId";
				$this->done_permission_check = true;
				return;
			}

			// The user can't moderate, isn't logged in, and has forum permission "can view others"
			if (empty($userId) AND in_array($channelid, $userdata['canview']))
			{
				$this->where[] = $this->make_equals_filter('parentid', $channelid);
				if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canseedelnotice', $channelid))
				{
					$this->where[] = "showpublished > 0";
				}
				// guests can't see any unapproved nodes since we can't distinguish guests
				$this->where[] = "showapproved > 0";
				$this->where[] = "viewperms = 2";
				$this->done_permission_check = true;
				return;
			}
		}

		$this->where[] = $this->make_equals_filter('closure', $channelid);
		// if it got here we need to do it the slow way

		if (!empty($depth))
		{
			$depth = intval($depth);
			$channelsIDs = (array) $channelid;
			foreach ($channelsIDs as $n)
			{
				if ($depth_exact !== false)
				{
					$this->where[] = "depth.n$n = $depth";
				}
				else
				{
					$this->where[] = "depth.n$n <= $depth";
				}
			}
		}

		$canviewthreads = true;
		$cannotviewthreadsChannelids = array();
		if (is_array($channelid))
		{
			foreach ($channelid as $chid)
			{
				if(!vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', intval($chid)))
				{
					$cannotviewthreadsChannelids[] = intval($chid);
					$canviewthreads = false;
				}
			}
		}
		elseif (is_numeric($channelid) AND !vB::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $channelid))
		{
			$canviewthreads = false;
		}
		if (!$canviewthreads)
		{
			if (empty($cannotviewthreadsChannelids))
			{
				$this->what[] = "(id = starter OR starter = 0) as is_starter";
				$this->where[] = "is_starter = 1";
			}
			else
			{
				/*
					You cannot use OR in the WHERE clause in sphinx, so we have to get a bit
					convoluted.

					Note the difference between SELECT...IN(expr, value1, value2...) function
					vs the WHERE... expr IN(value1, value2) operator.

					http://sphinxsearch.com/docs/current/comparison-functions.html
				 */
				$inCannotViewChannels = "IN (closure," . implode(',', $cannotviewthreadsChannelids) . ")";
				unset($cannotviewthreadsChannelids);

				$this->what[] = "(" .
									"{$inCannotViewChannels} AND (id = starter OR starter = 0) " .
									"OR NOT {$inCannotViewChannels}" .
								") AS canViewOrIsStarter";
				$this->where[] = "canViewOrIsStarter = 1";
			}
		}
	}

	protected function process_view_filters($view)
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

				$this->what[] = "(id = starter) as id_starter2";
				$this->where[] = "id_starter2 = 1";

 				$this->where[] = "contenttypeid <> " . vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');

				$channelAccess = vb::getUserContext()->getAllChannelAccess();

				if (!empty($this->filters['make_equals_filter']['starter_only']))
				{
					array_unshift($this->what, 'starter');
				}
				else if ((!empty($channelAccess['starteronly'])))
				{
					$starterOnly = implode(',', $channelAccess['starteronly']);
					array_unshift($this->what, "IF(IN(starter, $starterOnly) OR IN(starterparent, $starterOnly), starter, lastcontentid) AS last");
					$this->groupby = 'last';
				}
				else
				{
	 				array_unshift($this->what, 'lastcontentid');
	 				$this->groupby = 'lastcontentid';
				}
				unset($channelAccess);

				if (!$datecheck)
				{
					$age = vB::getDatastore()->getOption('max_age_channel');

					if (empty($age))
					{
					$age = 60;
					}

					$this->where[] = "created > " . (vB::getRequest()->getTimeNow() - ($age * 86400));
				}
				// in activity stream we don't want deleted content even if viewed by a moderator
				$this->where[] = "showpublished > 0";
			break;

				/**
				* The Topic view should only display the starter nodes for the specified channel.
				* Filters out the Channel nodes from the Search API nodes results.
				*/
			case vB_Api_Search::FILTER_VIEW_TOPIC :
				/*
					VBV-12581 Search Results are improperly ordered....
				*/
				array_unshift($this->what, 'starter');
				$this->groupby = 'starter';
				$this->where[] = "contenttypeid <> " . vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
			break;
				/**
				 * The Conversation Detail view should only display the descendant nodes of (and including) the specified starter.
				 * Filters out the Comment node from the Search API nodes results.
				 */
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD :
				$this->what[] = "(id = starter OR starter = parentid) as starter_node";
				$this->where[] = "starter_node = 1";
				break;
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD_SEARCH :
				array_unshift($this->what, "IF(parentid = 0 OR id = starter OR starter = parentid, id, parentid) as starter_node");
				$this->groupby = 'starter_node';
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

	protected function process_follow_filters($value, vB_Search_Criteria &$criteria) /** multi stage */
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
				$this->where[] = "id=0 /** no subscriptions for user **/";
				return;
			}
		}
		if (($type == vB_Api_Search::FILTER_FOLLOWING_ALL) OR ($type == vB_Api_Search::FILTER_FOLLOWING_USERS))
		{
			/* following users */
			$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
			$userids = $cache->read("vbUserlistFollowFriend_$userid");
			if ($userids === false)
			{
				$userids = $assertor->getColumn('userlist', 'relationid',	array('userid' => $userid, 'type' => 'follow', 'friend' => 'yes'));
				$cache->write("vbUserlistFollowFriend_$userid", $userids, 60, 'followChg_' . $userid);
			}

			if (empty($userids) AND $type == vB_Api_Search::FILTER_FOLLOWING_USERS)
			{
				$this->where[] = "id=0 /** no following for user **/";
				return;
			}
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_ALL AND empty($nodeids) AND empty($userids))
		{
			$this->where[] = "id=0 /** no following for user **/";
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_CHANNEL)
		{
			$this->filters['make_equals_filter']['channelid'] = $nodeids;
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
			$this->where[] = $this->make_notequals_filter('contenttypeid', $channelcontentypeid);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_CONTENT)
		{
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');

			$this->where[] = $this->make_equals_filter('id', $nodeids);
			$this->where[] = $this->make_notequals_filter('contenttypeid', $channelcontentypeid);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_USERS OR ($type == vB_Api_Search::FILTER_FOLLOWING_ALL AND empty($nodeids)))
		{
			$this->where[] = $this->make_equals_filter('userid', $userids);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_BOTH)
		{
			$nodes = $assertor->assertQuery('vBDBSearch:getNodesWithSubChannel', array('nodeids'=>$nodeids));

			$allNodeIds = array();
			foreach ($nodes as $nodeid)
			{
				$allNodeIds[] = $nodeid['nodeid'];
			}

			//I don't think we can get here because if nodeids is empty we'll bail earlier and if it
			//isn't then we should get at least the values for nodeids back from the query.  We'll
			//leave it in as it might be useful if the data gets a little inconsistant.
			if (empty($allNodeIds))
			{
				$this->where[] = "id=0 /** no following for user **/";
				return;
			}

			$this->where[] = $this->make_equals_filter('id', $allNodeIds);
			return;
		}

		if ($type == vB_Api_Search::FILTER_FOLLOWING_ALL)
		{
			$nodes = $assertor->assertQuery('vBDBSearch:getNodesWithSubChannel', array('nodeids'=>$nodeids));
			$allNodeIds = array();
			foreach ($nodes as $nodeid)
			{
				$allNodeIds[] = $nodeid['nodeid'];
			}

			//I don't think we can get here because if nodeids is empty we'll bail earlier and if it
			//isn't then we should get at least the values for nodeids back from the query.  We'll
			//leave it in as it might be useful if the data gets a little inconsistant.
			if (empty($allNodeIds))
			{
				$this->where[] = "id=0 /** no following for user **/";
				return;
			}

			/** @todo OR operator is not supported by sphinx*/
			// $this->filters['make_equals_filter']['OR'] = array('nodeid' => $allNodeIds, 'userid' => $userids);
			// workarond for missiong support for OR operator
			$nodeids = $assertor->getColumn('vBForum:node', 'nodeid', array('userid' => $userids));
			$this->where[] = $this->make_equals_filter('id', $allNodeIds + $nodeids);
			return;
		}
	}



	/**
	 * The "my_channels" filter returns channels of the specified type that the current user
	 * belongs to.
	 * @see vBDBSearch_dB_MYSQL_QueryDefs->process_my_channels_filter() for more information
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

		$userContext = vB::getUserContext();
		$channelAccess = $userContext->getAllChannelAccess();
		$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');

		// userid isn't used in the query, but is used implicitly to reject the notion of "guest" owned channels.
		// If that ever becomes a thing we'll have to fix this, and fix any erroneous git records with userid=0
		$userid = $userContext->fetchUserId();

		if (empty($userid) OR empty($channelAccess['mychannels']) OR empty($parentid))
		{
			$this->where[] = "0 /** Missing Data for my_channels filter, or user belongs to no channels **/";
			return;
		}

		$this->where['my_channels_closure'] = $this->make_equals_filter('closure', $parentid);
		$this->where['my_channels_nodeid'] = $this->make_equals_filter('id', $channelAccess['mychannels']);
		$this->where['my_channels_contenttypeid'] = $this->make_equals_filter('contenttypeid', $channelcontentypeid);
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

		$this->what[] = 'IN(starterparent,' . implode(',', $filterChannels) . ') AS chn_filter_cond';
		$this->where[] = 'chn_filter_cond = 1';
	}

	public function PostProcessorAddComments($nodeids, vB_Search_Criteria $criteria)
	{
		$this->initConnection();

		$this->process_sort($criteria);

		$this->where[] = $this->make_equals_filter('parentid', $nodeids);
		$this->where[] = $this->make_notequals_filter('id', $nodeids);
		$keywords = $this->adjustKeywordsForSphinx($criteria->get_raw_keywords());

		//this won't matter if Sphinx case folding is set up correctly, but we lowercase the text
		//before we index it so we should do the same before we search on it just to be consistent.
		$string = vB::getString();
		$keywords = $string->strtolower($keywords);

		array_unshift($this->where, "MATCH('" . $this->sphinxEscapeKeywords($keywords) . "')");

		$groupby = '';
		if (!empty($this->groupby))
		{
			$groupby = '
			GROUP BY ' . $this->groupby;
		}

		$limit = $this->postProcessorGetLimitValue($criteria);

		//see comments in getResults regarding limits and sphinx
		$query_limit = '';
		if ($limit)
		{
			$query_limit = "LIMIT " . $limit . " OPTION max_matches=" . $limit;
		}

		$query = '
			SELECT ' . implode(', ', $this->what) . '
			FROM ' . $this->table . '

			WHERE ' . implode(' AND ', $this->where) . $groupby . '
			ORDER BY ' . implode(', ', $this->sort) . "
				$query_limit
			/**" . __FUNCTION__ . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . '**/';

		$res = $this->sphinxDB->query($query);
		while($row = $this->sphinxDB->fetch_array($res))
		{
			$value = current($row);
			$nodeids[$value] = $value;
		}

		$config = vB::getConfig();

		if (!empty($config['Misc']['debug_sql']) OR self::DEBUG)
		{
			echo "$query;\n";
		}

		return $nodeids;
	}

	/**************HELPER FUNCTIONS**************************/

	private function adjustKeywordsForSphinx($keywords)
	{
		//Sphinx doesn't recognize 'OR' as a valid operator.  Not only does this break our
		//search tests, it will confuse users who try to use db search queries on sphinx.
		$keywords = str_ireplace(' OR ', ' | ', $keywords);

		//Also fix "NOT" as a opeartor
		$keywords = preg_replace('# NOT *#i', ' -', $keywords);

		//a trailing not operator will cause an error.  Let's strip it if we have one
		//to be consistant with the DB search.
		$keywords = preg_replace('#- *$#i', '', $keywords);

		return $keywords;
	}

	private function compute_changes(&$node)
	{
		$existing = $this->sphinxDB->query_first($query = "SELECT * FROM " . $this->table . " WHERE id = " . $node['nodeid']);
		$assertor = vB::getDbAssertor();
		$node['tagid'] = $assertor->getColumn('vBForum:tagnode', 'tagid', array('nodeid' => $node['nodeid']),'tagid');
		$closure = $assertor->assertQUery('vBForum:closure', array('child' => $node['nodeid']),'child');
		$parents = array();
		$depth = array();
		foreach ($closure as $value)
		{
			$node['closure'][] = $value['parent'];
			$depth[] = '"n' . $value['parent'] . '":' . $value['depth'];
		}
		//building a json structure for the depth field that contains the depth of each parent
		$node['depth'] = '{' . implode(',', $depth) . '}';
		$nodeLib = vB_Library::instance('node');
		$node['starterparent'] = $nodeLib->getChannelId($node);
		if (!empty($node['starter']))
		{
			$starter = $nodeLib->getNodeBare($node['starter']);
		}
		else
		{
			$starter = array();
		}
		$map = $this->get_starter_inherited_fields();
		foreach ($map AS $__starterkey => $__childkey)
		{
			// For now, all of these are some form of integer with a default of 0.
			// If that changes (e.g. we get a string w/ a different default) we'll
			// have to handle that here case by case.
			if (!empty($starter[$__starterkey]))
			{
				$node[$__childkey] = $starter[$__starterkey];
			}
			else
			{
				// These fields are only used for topic view + sorting by lastcontent.
				// So if the search result is a channel & doesn't have a starter, this
				// sorting field shouldn't be used so it should just be 0 or ""... hypothetically.
				if ($this->attributeIsString($__childkey))
				{
					/*
						Non-int & unconventional naming cases:
						'startertitlesort'  => 'rt_attr_string',
						'starterauthorname' => 'rt_attr_string',
					 */
					$node[$__childkey] = "";
				}
				else
				{
					$node[$__childkey] = 0;
				}
			}
		}

		//populate the sentto only when the node is a private message
		if ($node['contenttypeid'] == vB_Api::instanceInternal('ContentType')->fetchContentTypeIdFromClass('PrivateMessage'))
		{
			$node['sentto'] = $assertor->getColumn('vBForum:sentto', 'userid', array('nodeid' => $node['nodeid'], 'deleted' => 0),'userid');
		}
		$update = array();
		$need_reindex = false;
		if (!empty($existing))
		{
			unset ($existing['id']);

			foreach ($existing as $attribute => $value)
			{
				//some attributes are not defined if they are not relevant: sentto
				if (!isset($node[$attribute]))
				{
					continue;
				}

				//because of the nature of sphinx and strings we need to have two title
				//fields (one to sort and one for keywords) which means we have a naming
				//conflict.
				if($attribute == 'titlesort')
				{
					$nodevalue = $node['title'];
				}
				else
				{
					$nodevalue = $node[$attribute];
				}

				//when both old and new values are empty we don't need to update it
				if (empty($nodevalue) AND empty($value))
				{
					continue;
				}

				//multi type attributes are comma separated values, we need to convert them to arrays
				if ($this->attributes_definition[$attribute] == 'rt_attr_multi')
				{
					$value = explode(',', $value);
					$existing[$attribute] = $value;
				}

				// json values need to be matched individually
				if ($this->attributes_definition[$attribute] == 'rt_attr_json')
				{
					$old_depth = @json_decode($value, true);
					$new_depth = @json_decode($nodevalue, true);
					if (empty($new_depth))
					{
						continue;
					}

					//when both keys and values match between the old and new values, we can ignore updating this attribute
					if (!empty($new_depth) AND (count( array_intersect_assoc($old_depth, $new_depth)) == count($new_depth)))
					{
						continue;
					}
				}

				// checking array values for changes
				if (is_array($nodevalue) AND is_array($value) AND (count(array_intersect($nodevalue, $value)) == count($value)))
				{
					continue;
				}

				// this is an attribute that needs to be updated
				if ($nodevalue != $value)
				{
					$update[$attribute] = $nodevalue;
					//we need to update one of the string attributes. string attributes can't be updated using UPDATE,
					//we need to use REPLACE which means re-indexing the whole node
					//JSON attributes are treated basically like strings and need to be treated the same way.
					//There are suggestions that you can update scalar values within a JSON attribute by accessing the key directly,
					//but I couldn't get that to work and it probably doesn't help us much because typically the keys are going to change
					//and not just the values.
					if (in_array($this->attributes_definition[$attribute], array('rt_attr_string', 'rt_attr_json')))
					{
						$need_reindex = true;
					}
				}
			}
		}
		return array('changes' => $update, 'existing' => $existing, 'reindex' => $need_reindex);
	}

	private function make_equals_filter($field, $value)
	{
		$value = $this->quote_smart($field, $value);

		if (is_array($value))
		{
			return "$field IN (" . implode(',', $value) . ")";
		}
		else
		{
			return "$field = $value";
		}
	}

	private function make_notequals_filter($field, $value)
	{
		$value = $this->quote_smart($field, $value);

		if (is_array($value))
		{
			return "$field NOT IN (" . implode(',', $value) . ")";
		}
		else
		{
			return "$field <> $value";
		}

	}

	private function make_range_filter($field, $values)
	{
		//null mean infinity in a given direction
		if (!is_null($values[0]) AND !is_null($values[1]))
		{
			$values = $this->quote_smart($field, $values);
			return "($field BETWEEN $values[0] AND $values[1])";
		}
		else if (!is_null($values[0]))
		{
			$value = $this->quote_smart($field, $values[0]);
			return "$field >= $value";
		}
		else if (!is_null($values[1]))
		{
			$value = $this->quote_smart($field, $values[1]);
			return "$field <= $value";
		}
	}

	private function crc_uint_string($value)
	{
		return sprintf('%u', crc32($value));
	}

	private function quote_smart($field, $value, $is_handled = true)
	{
		if ($is_handled AND is_array($value) AND count($value) == 1)
		{
			$value = array_pop($value);
		}

		if ($this->attributes_definition[$field] == 'rt_attr_string')
		{
			if (empty($value))
			{
				return "''";
			}

			if (is_array($value))
			{
				foreach ($value as $k => $v)
				{
					$value[$k] = "'" . $this->sphinxEscapeString($v) . "'";
				}
				return $value;
			}
			else
			{
				return "'" . $this->sphinxEscapeString($value) . "'";
			}
		}

		if ($this->attributes_definition[$field] == 'rt_attr_json')
		{
			if (empty($value))
			{
				return "''";
			}
			else
			{
				return "'$value'";
			}
		}


		if ($this->attributes_definition[$field] == 'rt_attr_multi')
		{
			if (!$is_handled AND empty($value)){
				return '()';
			}

			if ($is_handled OR !is_array($value))
			{
				return $value;
			}

			return '(' . implode(',', $value) . ')';
		}

		if (empty($value))
		{
			return 0;
		}

		if (is_bool($value))
		{
			return $value ?  1 : 0;
		}

		return $value;
	}

	private function exec_command($command, $silent = false)
	{
		exec($command, $output);
		$haserror = false;
		foreach ($output as $string)
		{
			if (!$silent)
			{
				echo $string . "\n";
			}

			if ((strpos($string, 'ERROR') === 0) OR (strpos($string, 'FATAL') === 0))
			{
				$haserror = true;
			}
		}

		if ($haserror)
		{
			throw new vB_Exception_Api('sphinx_error_x', array(implode("\n", $output)), '', false, false, false, true);
		}
	}

	private function exec_command_feedback($command, $silent = false)
	{
		$output = '';
		$fp=popen($command, "r");
		stream_set_blocking($fp, 0);
		while(!feof($fp))
		{
			$buffer = fread($fp, 100);
			if (empty($buffer))
			{
				echo '.';
				flush();
				sleep(5);
			}
			else
			{
				$output .= $buffer;
			}
		}
		pclose($fp);
		if ((strpos($output, 'ERROR') === 0) OR (strpos($output, 'FATAL') === 0))
		{
				throw new vB_Exception_Api('sphinx_error_x', $output);
		}
		elseif (!$silent)
		{
			echo $output;
		}
	}

	private function restart($silent = false)
	{
		$config = vB::getConfig();
		// close the current connection before restarting the service
		$this->sphinxDB->close();

		// restart the service
		//windows
		if (stripos(@php_uname('s'), "win") !== false)
		{
			$this->exec_command('net stop SphinxSearch', $silent);
			$this->exec_command('net start SphinxSearch', $silent);
		}
		//unix
		else
		{
			$this->exec_command($config['Misc']['sphinx_path'] . '/bin/searchd --config ' . $config['Misc']['sphinx_config'] . ' --stopwait', $silent);
			$this->exec_command($config['Misc']['sphinx_path'] . '/bin/searchd --config ' . $config['Misc']['sphinx_config'], $silent);
		}
		// need to reconnect after restarting the service
		$this->connect($config);
	}

	/**
	 * Composes the terms for the flags to enforce the starter-node-specific permissions.
	 *
	 * @param	$excludeUserSpecific	bool	Exclude user specific queries. Used for precaching
	 **/
	protected function setNodePermTerms($excludeUserSpecific = false)
	{
		$userContext = vB::getUserContext();

		if (empty($userContext))
		{
			$this->where[] = 'id = 0 /* no user context */';
			return;
		}
		if ($userContext->isSuperAdmin())
		{
			return;
		}

		$userid = vB::getCurrentSession()->get('userid');
		$channelAccess = $userContext->getAllChannelAccess();

		$condition = array();

		if (!empty($channelAccess['canmoderate']))
		{
			$condition[] = '(IN(starterparent,' . implode(',', $channelAccess['canmoderate']) . ') OR IN(starter,' . implode(',', $channelAccess['canmoderate']) . '))';
		}

		$starterAnd = '';

		if (!empty($channelAccess['canseedelnotice']))
		{
			$starterAnd = 'AND (IN(starterparent, ' . implode(',', $channelAccess['canseedelnotice']) . ') OR showpublished > 0)';
		}

		$sphinxShowApprovedQuery = "showapproved > 0";
		if ($userid > 0)
		{
			$userid = intval($userid);
			$sphinxShowApprovedQuery = "(showapproved > 0 OR userid = $userid)";
		}

		if (!empty($channelAccess['canview']))
		{
			$showParams = array(
				$sphinxShowApprovedQuery,
				$userid > 0 ? 'viewperms > 0' : 'viewperms > 1',
			);

			if (empty($channelAccess['canseedelnotice']))
			{
				$showParams[] = 'showpublished > 0';
			}

			$condition[] = '(((IN(starterparent,' . implode(',', $channelAccess['canview']) . ") $starterAnd) AND " . implode(' AND ', $showParams) . "))\n";
		}

		if (!empty($channelAccess['canalwaysview']))
		{
			$condition[] = 'IN(starterparent,' . implode(',', $channelAccess['canalwaysview']) . ')';
		}

		if (!empty($channelAccess['starteronly']))
		{
			$starterOnly = implode(',', $channelAccess['starteronly']);
			$condition[] = "(IN(id,$starterOnly) OR IN(parentid, $starterOnly))";
		}

		if (!empty($channelAccess['selfonly']))
		{
			if ($excludeUserSpecific)
			{
				$condition[] = 'IN(starterparent,' . implode(',', $channelAccess['selfonly']) . ')';
			}
			else if($userid)
			{
				// Result set it not being pre-cached
				$condition[] = '(IN(starterparent,' . implode(',', $channelAccess['selfonly']) . ") AND starteruser = $userid)";
			}
		}

		/* 'owndeleted' is not currently set by ->getAllChannelAccess();
		 This code should be deleted if it serves no purpose
		if (!empty($channelAccess['owndeleted']))
		{
			$condition[] = '(IN(starterparent,' . implode(',', $channelAccess['owndeleted']) . ") AND userid = $userid)";
		}*/


		if (!empty($channelAccess['member']))
		{
			$showParams = array(
				$sphinxShowApprovedQuery,
			);

			if (empty($channelAccess['canseedelnotice']))
			{
				$showParams[] = 'showpublished > 0';
			}

			$condition[] = '((IN(starterparent,' . implode(',', $channelAccess['member']) . ") $starterAnd) AND " . implode(' AND ', $showParams) . ")\n";
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

		$condition[] = "(starterparent = " . vB_Library::instance('node')->fetchAlbumChannel() . " AND (IN (userid," . implode(',', $following['user']) . ")))";

		if (empty($condition))
		{
			$this->where[] = 'id = 0 /* no permissions */';
			return;
		}

		$this->what[] = '(' . implode (' OR ', $condition) . ') AS permconditions';
		$this->where[] = 'permconditions = 1';
	}


	/*
	 * The mysql_real_escape_string function does not correctly handle escaping sphinx strings.  So we do it the hard way.
	 */
	public function sphinxEscapeString($toEscape)
	{
		$this->initConnection();
		//handle sphinx special chars
		$from = array('\\', '(',')','|','-','!','@','~','"','&', '/', '^', '$', '=');
		$to   = array('\\\\', '\(','\)','\|','\-','\!','\@','\~','\"', '\&', '\/', '\^', '\$', '\=');

		//we need to do both sphinx and mysql escaping see advice in http://sphinxsearch.com/bugs/view.php?id=1713
		return $this->sphinxDB->escape_string(str_replace ($from, $to, $toEscape));
	}

	/**
	 *	We need to escape some characters from the keyword string to avoid allowing the user to break
	 *	sphinx queries.  However we want to allow some things, like the | character for OR. This is
	 *	a clone of the full escape function we a few operators removed so we can let them through
	 *
	 *	Escaping is a mess and not well documented in Sphinx -- and complicated because we're passing
	 *	things through the mysql library as well.
	 *
	 *	Currently allowed operators: |
	 */
	public function sphinxEscapeKeywords($toEscape)
	{
		$this->initConnection();
		//handle sphinx special chars
		$from = array('\\', '(',')','!','@','~','"','&', '/', '^', '$', '=');
		$to   = array('\\\\', '\(','\)','\!','\@','\~','\"', '\&', '\/', '\^', '\$', '\=');

		//we need to do both sphinx and mysql escaping see advice in http://sphinxsearch.com/bugs/view.php?id=1713
		return $this->sphinxDB->escape_string(str_replace ($from, $to, $toEscape));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103395 $
|| #######################################################################
\*=========================================================================*/
