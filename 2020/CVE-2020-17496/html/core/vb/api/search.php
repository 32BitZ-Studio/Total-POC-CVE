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
 * vB_Api_Search
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Search extends vB_Api
{
	private static $badwords;
	private static $allbadwords;
	private static $goodwords;
	protected $search_json;
	protected $criteria;
	protected $channelCache = null;
	const FILTER_STARTER_ONLY = 'starter_only';
	const FILTER_LASTVISIT = 'lastVisit';
	const FILTER_TOPICAGE = 'topicAge';
	const FILTER_CHANNELAGE = 'channelAge';
	const FILTER_LASTDAY = 'lastDay';
	const FILTER_LASTWEEK = 'lastWeek';
	const FILTER_LASTMONTH = 'lastMonth';
	const FILTER_LASTYEAR = 'lastYear';
	const FILTER_DATEALL = 'all';
//	const FILTER_VIEW_CHANNEL = 'channel';
	const FILTER_VIEW_ACTIVITY = 'activity';
	const FILTER_VIEW_TOPIC = 'topic';
	const FILTER_VIEW_CONVERSATION_THREAD = 'conversation_thread';
	const FILTER_VIEW_CONVERSATION_THREAD_SEARCH = 'conversation_thread_search';
	const FILTER_VIEW_CONVERSATION_STREAM = 'conversation_stream';
	const FILTER_FOLLOWING_USERS = 'followMembers';
	const FILTER_FOLLOWING_CHANNEL = 'followChannel';
	const FILTER_FOLLOWING_ALL = 'followAll';
	const FILTER_FOLLOWING_BOTH = 'followBoth';
	const FILTER_FOLLOWING_CONTENT = 'followContent';
	const FILTER_FOLLOW = 'follow';
	// FILTER_MARKED_READ is unimplemented. To implement this, add a JSON->filter translation
	// in json2criteria(), & add the filter in DB & sphinx searches. For an ex., see the
	// FILTER_MARKED_UNREAD implementation.
	const FILTER_MARKED_READ = 'read';
	const FILTER_MARKED_UNREAD = 'unread';
	const FILTER_SHOW_TEXT = 'vBForum_Text';
	const FILTER_SHOW_GALLERY = 'vBForum_Gallery';
	const FILTER_SHOW_VIDEO = 'vBForum_Video';
	const FILTER_SHOW_LINK = 'vBForum_Link';
	const FILTER_SHOW_POLL = 'vBForum_Poll';
	const FILTER_SHOW_EVENT = 'vBForum_Event';

	const SEARCH_TYPE_SYSTEM = 0; // for system searches
	const SEARCH_TYPE_USER = 1; // for user request searches
	const IGNORE_CACHE = false;
	protected static $cache_ttl_sec;

	protected static $showFilterList = array(
		vB_Api_Search::FILTER_SHOW_TEXT,
		vB_Api_Search::FILTER_SHOW_GALLERY,
		vB_Api_Search::FILTER_SHOW_VIDEO,
		vB_Api_Search::FILTER_SHOW_LINK,
		vB_Api_Search::FILTER_SHOW_POLL,
		vB_Api_Search::FILTER_SHOW_EVENT,
	);

	/**
	 * Returns the cache ttl in seconds
	 *
	 * @return	int		time in seconds
	 */
	public static function getCacheTTL()
	{
		if (!isset(self::$cache_ttl_sec))
		{
			self::$cache_ttl_sec = vB::getDatastore()->getOption('search_cache_ttl');
		}
		return self::$cache_ttl_sec;
	}
	/**
	 * Search for nodes
	 * @param string|array|object   $search_json list of parameters that can be encoded in a json string
	 * @param int                   $searchType
	 *
	 * @return int result_id
	 */

	// TODO: $searchType shouldn't have a default value, but be explicitely declared in each call
	public function getSearchResult($search_json, $searchType = 0)
	{
		if (!is_string($search_json))
		{
			$search_json = json_encode($search_json);
		}

		$criteria = $this->json2criteria($search_json);

		//there's an error in the json criteria, not doing a search
		if (!empty($search_json['error']))
		{
			$return_structure = vB_Search_Core::instance()->cacheResults(array(), $criteria, 0, $searchType);
			$return_structure['ignored_keywords'] = $criteria->get_ignored_keywords();
			$return_structure['totalRecords'] = 0;
			return $return_structure;
		}
		elseif (!$criteria->getIgnoreCache())
		{
			//check if there is a cached result set with this criteria
			$searchlog = vB_Search_Core::instance()->getFromCache($criteria, $search_json);
			if ($searchlog !== false)
			{
				//found a cached result set, no need to do a new search
				return $searchlog;
			}
		}

		// this searchJSON will contain the custom fields
		if (!empty($search_json['custom']))
		{
			$criteria->setJSON($search_json);
		}

		return $this->getSearchResultsCriteria($criteria, $searchType);
	}

	/**
	 * Search for nodes
	 * @param vB_Search_Criteria $criteria a criteria object
	 * @return int result_id
	 */
	protected function getSearchResultsCriteria(vB_Search_Criteria $criteria, $searchType)
	{
		//first let's see if this is valid.
		$userdata = vB::getUserContext()->getReadChannels();

		if (empty($userdata['canRead']) AND empty($userdata['selfOnly']))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$json = $criteria->getJSON();

		$results = array();
		$records_nr = 0;

		$time_before = $time_after = microtime(true);

		if ($searchType == self::SEARCH_TYPE_USER)
		{
			// user requested this search, so we need to check flooding
			vB_Search_Core::instance()->floodCheck();
		}

		if (empty($json['error']))
		{
			$results = vB_Search_Core::instance()->getResults($criteria);
			$time_after = microtime(true);
		}

		$return_structure = vB_Search_Core::instance()->cacheResults($results, $criteria, $time_after - $time_before, $searchType);

		//need to duplicate the cache so it can be picked up in case the custom field is not provided.
		//having a custom field generated a different hash but has the same results
		if (!empty($json['custom']))
		{
			unset($json['custom']);
			$criteria->setJSON($json);
			vB_Search_Core::instance()->cacheResults($results, $criteria, $time_after - $time_before, $searchType);
		}

		$return_structure['ignored_keywords'] = $criteria->get_ignored_keywords();
		$return_structure['totalRecords'] = count($results);

		return $return_structure;
	}

	/**
	 * Search for nodeids and returns the resultid as well as the page value
	 *
	 * (avoids having to make a call for the resultid and immediately make another to fetch the page value)
	 *
	 * @param string|array|object $search_json list of parameters that can be encoded in a json string
	 * @param int $pagenumber pagination - the page number
	 * @param int $perpage pagination - the number of results per page
	 * @return array node_ids
	 */
	public function getInitialNodes($search_json, $perpage = false, $pagenumber = false, $getStarterInfo = false)
	{
		if (!is_string($search_json))
		{
			$search_json = json_encode($search_json);
		}

		$result = $this->getSearchResult($search_json);

		return $this->getMoreNodes($result, $perpage, $pagenumber, $getStarterInfo);
	}

	/**
	 * Search for nodes and returns the resultid as well as the page value
	 *
	 * (avoids having to make a call for the resultid and immediately make another to fetch the page value)
	 *
	 * @param string|array|object $search_json list of parameters that can be encoded in a json string
	 * @param int $perpage pagination - the number of results per page
	 * @param int $pagenumber pagination - the page number
	 * @param bool $getStarterInfo
	 * @param int $searchType
	 * @return array search_result_structure
	 */
	public function getInitialResults($search_json, $perpage = false, $pagenumber = false, $getStarterInfo = false, $searchType = 0)
	{
		if (!is_string($search_json))
		{
			$search_json = json_encode($search_json);
		}

		// this returns the nodeids in $result['results']
		$result = $this->getSearchResult($search_json, $searchType);

		try
		{
			// this adds all the actual node information based on nodeids
			return $this->getMoreResults($result, $perpage, $pagenumber, $getStarterInfo);
		}
		catch (vB_Exception_NodePermission $e)
		{
			if (!empty($result['from_cache']))
			{
				vB_Library::instance('search')->purgeCacheForCurrentUser();
				// for the second attempt, we consider it a system search request (no need to perform flood check again)
				return $this->getInitialResults($search_json, $perpage, $pagenumber, $getStarterInfo, self::SEARCH_TYPE_SYSTEM);
			}
			else
			{
				$nodeid = $e->getNodeId();
				if (empty($nodeid) OR !is_numeric($nodeid))
				{
					throw $e;
				}

				$newSet = vB_Search_Core::instance()->removeNodeFromResult($nodeid, $result, $perpage, $pagenumber, $getStarterInfo);

				if ($newSet === false)
				{
					throw $e;
				}
				else
				{
					return $newSet;
				}
			}
		}
	}

	/**
	 * Very similar to getInitialResults(), but meant for use by channeldisplay template & activity/get requests.
	 * Handles pagination differently and skips two-pass cache.
	 *
	 * @param string|array       $search_json   list of parameters that can be encoded in a json string
	 * @param int                $perpage       pagination - the number of results per page
	 * @param int                $pagenumber    pagination - the page number
	 * @param bool               $skipCount
	 * @return array
	 *            results	array of node information for $pagenumber
	 *            totalcount integer total (not just $pagenumber) number of topics
	 */
	public function getChannelTopics($search_json, $perpage = false, $pagenumber = false, $skipCount = false)
	{
		if (is_string($search_json))
		{
			$search_json = json_decode($search_json);
		}

		if (empty($search_json))
		{
			throw new vB_Exception_Api('invalid_search_syntax');
		}

		if (empty($search_json['channel']) OR !is_numeric($search_json['channel']))
		{
			throw new vB_Exception_Api('invalid_search_syntax');
		}

		// disable two pass for this for now. We're doing pagination via limits & count queries and two pass won't
		// work correctly with that.
		$search_json['disable_two_pass'] = 1;
		/*
			If $perpage is false/0, that means "infinite". ATM we don't support true infinity and have a
			hard-coded limit of 999 (see where json2criteria handles "context" related search params).
			Since this is only used for sticky posts with "no limit", this should be large enough appx for
			sticky-infinity.
		 */
		$perpage = intval($perpage);
		if ($perpage < 0)
		{
			$perpage = 15;
		}

		$pagenumber = intval($pagenumber);
		if ($pagenumber < 1)
		{
			$pagenumber = 1;
		}

		$search_json['pagenumber'] = $pagenumber;
		$search_json['perpage'] = $perpage;

		// We should not be getting keyword searches through here. And this assumption
		// also means json2criteria($search_json); will never set $search_json['error']
		// so we don't have to check for that & cache an empty result.
		unset($search_json['keywords']);

		$criteria = $this->json2criteria($search_json);

		// Todo: caching?
		/*
		if (!$criteria->getIgnoreCache())
		{
			//check if there is a cached result set with this criteria
			$searchlog = vB_Search_Core::instance()->getFromCache($criteria, $search_json);
			if ($searchlog !== false)
			{
				//found a cached result set, no need to do a new search
				$result = $searchlog;
			}
		}
		*/


		/*
			A lot of the logic below is duplicated from getSearchResultsCriteria()
		 */
		//first let's see if this is valid.
		$userdata = vB::getUserContext()->getReadChannels();
		if (empty($userdata['canRead']) AND empty($userdata['selfOnly']))
		{
			throw new vB_Exception_Api('no_permission');
		}

		// this will give us array({nodeid}=>{nodeid},...{nodeid_n}=>{nodeid_n})
		$nodeids = vB_Search_Core::instance()->getResults($criteria);
		$return_structure = array();
		/*
			todo: try/catch vB_Exception_NodePermission?
			See getInitialResults(). It seems to catch node-permission
			exceptions and removes the singular node from the result and returns the rest... but it's not
			very clear what kind of situations it's meant to handle. Perhaps race conditions where a
			user loses permission to view a node between search & load?? But if so, shouldn't it
			re-check the new resultset for permissions again? For now, skipping this.
		 */
		$return_structure['nodeIds'] = $nodeids;
		$return_structure['results'] = vB_Library::instance('Node')->getFullContentforNodes($nodeids);

		/*
			"totalpages" & "pagenumber" are required by frontend activity/get
		 */
		if ($perpage > 0 AND !$skipCount)
		{
			$return_structure['totalRecords'] = $this->getChannelTopicCount($search_json, $criteria);
			// ceil() returns a float. Cast to int to get rid of unnecessary decimal "123.0" that can
			// crop up in unit tests.
			$return_structure['totalpages'] = (int) ceil($return_structure['totalRecords']/$perpage);
			$return_structure['pagenumber'] = min($pagenumber, $return_structure['totalpages']);
		}
		else
		{
			$return_structure['totalRecords'] = count($nodeids);
			$return_structure['totalpages'] = 1;
			$return_structure['pagenumber'] = 1;
		}

		return $return_structure;
	}

	private function getChannelTopicCount($search_structure, $criteria)
	{
		/*
			We need to apply the same filters (e.g. contenttype, date range) as the topic fetch,
			and get the count of
				showpublished = 0 & showapproved = 0 nodes user can see
			and subtract
				ignored users' topics for current user
			and add that diff to the channel.textcount, which is the immediate published & approved topics
			for this channel.
		 */
		$assertor = vB::getDbAssertor();

		/*
			Note that there are a number of other search params than date & type that could affect the search result,
			like filtering by userid or by following/subscriptions. This function is meant to be used exclusively by
			channel topic listings, so we only care about the subset of search params that can be set by the currently
			existing filter UI on channel display templates. While this potentially makes maintenance more difficult
			since a change in the conversation toolbar filter UI may require a change here, I've opted to simplify
			this function as much as possible for now.

			For no date filters:
			Unfortunately, since we don't currently have separate textcounts by type, as *soon* as we have a
			type filter we're likely better off doing the full COUNT query.

			For date filters (e.g. "last month"):
			It does not make sense to try to maintain multiple time-windowed counts of various types. However,
			chances are that having a date filter is going to significantly reduce the counts anyways, assuming
			a stable topic posting rate. So while we *must* query the full count here, it isn't as bad as trying
			to do the count without a date filter.
			Of course, in practice the performance depends a lot on what the *other* filters used are, and what
			the optimizer is doing.

			As for sticky_only, most of the times it's really fast to count for stickies this way and not
			worth going through the other multiple counts.
			Edit: introduced a $skipCount param to getChannelTopics() that widget_channeldisplay template &
			activity/get use for stickynodes, since we're always trying to get all/infinite stickies to display
			on the first page & can just count the fetched records for "page 1" of stickies rather than doing a
			"full" count.
		 */
		$hasTypeFilter = (
			!empty($search_structure['type']) OR
			!empty($search_structure['exclude_type'])
		);
		$hasDateRangeFilter = (
			!empty($search_structure['date']) AND
			$search_structure['date'] !== "all"
		);
		$isStickyQuery = !empty($search_structure['sticky_only']);
		if ($hasTypeFilter OR $hasDateRangeFilter OR $isStickyQuery)
		{
			return $this->doFullCountQueryForTopics($search_structure, $criteria);
		}


		$channel = vB_Library::instance('node')->getNodeBare($search_structure['channel']);
		if (!isset($channel['textcount']))
		{
			throw new vB_Exception_Api('invalid_search_syntax');
		}

		$totalTopicsCount = $channel['textcount'];
		$ignoredCount = 0;
		$unpublishedCount = 0;
		$unapprovedCount = 0;
		$unpublishedAndUnapprovedCount = 0; // see note below
		$stickyCount = 0;

		/*
		 * Blocked users
		 */
		$ignoredUsers = $this->getIgnoredUsersList();
		if (!empty($ignoredUsers))
		{
			$search_structure_copy = $search_structure;
			// important, we don't want to conflict the userid EQ filter below
			$search_structure_copy['include_blocked'] = 1;
			$criteria2 = $this->json2criteria($search_structure_copy);
			$criteria2->setDoCount(true);
			/*
				This userid filter changes the query into a "find filtered posts.. by ignored users only"
				this is restrictive, but we *do* care about other filters JUST IN CASE
				we have a user-search filter on (though this currently does not exist on the channeldisplay UI AFAIK)
			 */
			$is_restrictive = true;
			$is_additive = true;
			$criteria2->add_filter('userid', vB_Search_Core::OP_EQ, $ignoredUsers, $is_restrictive, $is_additive);
			/*
				The unapproved/unpublished queries below will not include any ignored/blacklisted users.
				So subtracting the ignored users' topic count is supposed to compenstate only for the channel's
				textcount (which does not include any unapproved or unpublished topics).
				As such, we only want to get the counts of approved AND published ignored users' topics here,
				otherwise we'd have to compenstate for any "unapproved OR unpublished ignored users' topics".
			 */
			$criteria2->add_filter('showpublished', vB_Search_Core::OP_EQ, '1', $is_restrictive, $is_additive);
			$criteria2->add_filter('showapproved', vB_Search_Core::OP_EQ, '1', $is_restrictive, $is_additive);

			$ignoredCount = $assertor->getRow(
				'vBDBSearch:getSearchResults',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
					'criteria' => $criteria2,
					'cacheKey' => false,
				)
			);
			$ignoredCount = intval($ignoredCount['count']);
			unset($criteria2);
		}

		/*
			For unpublished & unapproved counts, we'll just rely on existing permission checks in the
			querydefs, and rely on any "conflicting" filters just returning 0 rows (e.g. if a guest
			tries to get showpublished = 0 nodes, the showpublished = 1 filter that's automatically
			set by the querydefs will block it).
			We don't have to worry about overlapping ignored users' posts & these posts since
			json2criteria() by default should filter them out since we're not setting 'include_blocked'
			for these.
			However we *do* have to worry about overlapping showpublished = 0 AND showapproved = 0,
			so we do 3 sums separately:
				!showpublished & showapproved, showpublished & !showapproved, !showpublished & !showapproved
		 */

		/*
		 * Unpublished / soft-deleted
		 */
		$search_structure_copy = $search_structure;
		$criteria2 = $this->json2criteria($search_structure_copy);
		$criteria2->setDoCount(true);
		$is_restrictive = true;
		$is_additive = true;
		$criteria2->add_filter('showpublished', vB_Search_Core::OP_EQ, '0', $is_restrictive, $is_additive);
		$criteria2->add_filter('showapproved', vB_Search_Core::OP_EQ, '1', $is_restrictive, $is_additive);
		$unpublishedCount = $assertor->getRow(
			'vBDBSearch:getSearchResults',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'criteria' => $criteria2,
				'cacheKey' => false,
			)
		);
		$unpublishedCount = intval($unpublishedCount['count']);
		unset($criteria2);

		/*
		 * Unapproved
		 */
		$search_structure_copy = $search_structure;
		$criteria2 = $this->json2criteria($search_structure_copy);
		$criteria2->setDoCount(true);
		$is_restrictive = true;
		$is_additive = true;
		$criteria2->add_filter('showpublished', vB_Search_Core::OP_EQ, '1', $is_restrictive, $is_additive);
		$criteria2->add_filter('showapproved', vB_Search_Core::OP_EQ, '0', $is_restrictive, $is_additive);
		$unapprovedCount = $assertor->getRow(
			'vBDBSearch:getSearchResults',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'criteria' => $criteria2,
				'cacheKey' => false,
			)
		);
		$unapprovedCount = intval($unapprovedCount['count']);
		unset($criteria2);

		/*
		 * Unpublished AND unapproved
		 */
		$search_structure_copy = $search_structure;
		$criteria2 = $this->json2criteria($search_structure_copy);
		$criteria2->setDoCount(true);
		$is_restrictive = true;
		$is_additive = true;
		$criteria2->add_filter('showpublished', vB_Search_Core::OP_EQ, '0', $is_restrictive, $is_additive);
		$criteria2->add_filter('showapproved', vB_Search_Core::OP_EQ, '0', $is_restrictive, $is_additive);
		$unpublishedAndUnapprovedCount = $assertor->getRow(
			'vBDBSearch:getSearchResults',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'criteria' => $criteria2,
				'cacheKey' => false,
			)
		);
		$unpublishedAndUnapprovedCount = intval($unpublishedAndUnapprovedCount['count']);
		unset($criteria2);

		/*
		 * Sticky count. We need to subtract stickies from total count
		 * unless we're actually looking for stickies.
		 */
		if (!empty($search_structure['exclude_sticky']))
		{
			$search_structure_copy = $search_structure;
			unset($search_structure_copy['exclude_sticky']);
			$search_structure_copy['sticky_only'] = 1;
			$criteria2 = $this->json2criteria($search_structure_copy);
			$criteria2->setDoCount(true);
			$stickyCount = $assertor->getRow(
				'vBDBSearch:getSearchResults',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
					'criteria' => $criteria2,
					'cacheKey' => false,
				)
			);
			$stickyCount = intval($stickyCount['count']);
			unset($criteria2);
		}

		$totalTopicsCount = $totalTopicsCount - $stickyCount - $ignoredCount
							+ $unpublishedCount + $unapprovedCount + $unpublishedAndUnapprovedCount;

		// totalTopicsCount cannot be negative. If it is negative, then one possible issue is that
		// the channel's textcount is incorrect (e.g. right after an upgrade) & they need to rebuild it.
		// If the node data is all correct, then next possibility is that we forgot to check for a filter
		// that wouldn't fit in this scheme (e.g. filter by specific author, which ATM isn't possible
		// with current channeldisplay toolbar UI)
		$totalTopicsCount = max($totalTopicsCount, 0);


		return $totalTopicsCount;
	}

	private function doFullCountQueryForTopics($search_structure, $criteria)
	{
		$criteria->setDoCount(true);
		$assertor = vB::getDbAssertor();
		$count = $assertor->getRow(
			'vBDBSearch:getSearchResults',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'criteria' => $criteria,
				'cacheKey' => false,
			)
		);

		return intval($count['count']);
	}

	// used by getChannelTopicCount()
	private function getIgnoredUsersList()
	{
		$ignoredUsers = array();
		$currentUserId = vB::getCurrentSession()->get('userid');
		// user specific (if logged in)
		if (!empty($currentUserId))
		{
			$currentUserInfo = vB_User::fetchUserinfo($currentUserId);
			if (!empty($currentUserInfo['ignorelist']))
			{
				$ignoredUsers = explode(' ', $currentUserInfo['ignorelist']);
			}
		}
		$globalignore = trim(vB::getDatastore()->getOption('globalignore'));
		if (!empty($globalignore))
		{
			$blocked = preg_split('#\s+#s', $globalignore, -1, PREG_SPLIT_NO_EMPTY);
			// both arrays have num keys so they should be appended rather than overwritten.
			$ignoredUsers = array_merge($ignoredUsers, $blocked);

			//the user can always see their own posts, so if they are in the blocked list we remove them
			if (!empty($currentUserId))
			{
				$bbuserkey = array_search($currentUserId , $ignoredUsers);

				if ($bbuserkey !== FALSE AND $bbuserkey !== NULL)
				{
					unset($ignoredUsers["$bbuserkey"]);
				}
			}
			$ignoredUsers = array_unique($ignoredUsers);
		}

		return $ignoredUsers;
	}

	/**
	 * Get the node_ids from a search resultId
	 * @param int $resultId id of the search result
	 * @param int $perpage pagination - the number of results per page
	 * @param int $pagenumber pagination - the page number
	 * @return array result structure without node content (only nodeids)
	 */
	public function getMoreNodes($resultId, $perpage = false, $pagenumber = false)
	{
		$cacheLife = self::getCacheTTL();

		if (is_array($resultId))
		{
			$cache = $resultId;
			$resultId = $cache['resultId'];
			if (!is_numeric($resultId))
			{
				throw new vB_Exception_Api('invalid_search_syntax');
			}
		}

		if (is_numeric($resultId))
		{
			$cache = vB_Search_Core::instance()->getCache($resultId);
			if (empty($cache))
			{
				throw new vB_Exception_Api('invalid_search_resultid');
			}

			//remember $cacheLife is minutes and everything else is seconds.
			if ($cache['dateline'] < vB::getRequest()->getTimeNow() - ($cacheLife * 60))
			{
				$json = json_decode($cache['json'], true);
				$json['sort'] = array($cache['sortby'] => $cache['sortorder']);
				$cache['json'] = json_encode($json);
				return $this->getInitialNodes($cache['json'], $perpage, $pagenumber);
			}
		}
		else
		{
			throw new vB_Exception_Api('invalid_search_syntax', array($resultId));
		}

		$return_structure['resultId'] = $resultId;
		$pagenumber = intval($pagenumber);
		$return_structure['pagenumber'] = $pagenumber;

		$return_structure['totalRecords'] = $cache['results_count'];
		$return_structure['searchJSON'] = $cache['json'];
		$return_structure['searchJSONStructure'] = json_decode($cache['json'],true);
		$return_structure['searchtime'] = vb_number_format($cache['searchtime'], 4);
		$return_structure['hasMore'] = false;

		$perpage = intval($perpage);
		if (!empty($perpage))
		{
			$return_structure['perpage'] = $perpage;
			$pagenumber = max($pagenumber, 1);
			$return_structure['totalpages'] = ceil($return_structure['totalRecords']/$perpage);
			$return_structure['pagenumber'] = min($pagenumber, $return_structure['totalpages']);
			$start = (($return_structure['pagenumber'] - 1) * $perpage);
			$return_structure['from'] = $start+1;
		}
		else
		{
			$return_structure['perpage'] = $return_structure['totalRecords'];
			$return_structure['totalpages'] = 1;
			$return_structure['pagenumber'] = 1;
			$return_structure['from'] = 1;
			$start = 0;
		}

		$return_structure['nodeIds'] = array();
		if (!empty($cache['results']))
		{
			$return_structure['nodeIds'] = explode(',', $cache['results']);
		}
		if (!empty($cache['ignored_keywords']))
		{
			$return_structure['ignored_keywords'] = $cache['ignored_keywords'];
		}
		$return_structure['hasMore'] = count($return_structure['nodeIds']) > ($return_structure['from'] - 1 + $return_structure['perpage']);

		if ($start > count($return_structure['nodeIds']))
		{
			return $return_structure;
			//throw new Exception('no_more_results');
		}
		if (!empty($return_structure['nodeIds']))
		{
			$return_structure['nodeIds'] = array_slice($return_structure['nodeIds'], $start, $return_structure['perpage']);
			$return_structure['nodeIds'] = array_combine($return_structure['nodeIds'], $return_structure['nodeIds']);
		}

		$return_structure['to'] = $start + count($return_structure['nodeIds']);

		$nextUrl = $prevUrl = '';
		$baseurl = vB::getDatastore()->getOption('frontendurl');
		$search_params = array (
			'r' => $resultId
		);
		$url = $baseurl . vB5_Route::buildUrl('search', array(),$search_params);

		if ($return_structure['pagenumber'] < $return_structure['totalpages'])
		{
			$search_params['p'] = $return_structure['pagenumber'] + 1;
			$nextUrl = $baseurl . vB5_Route::buildUrl('search', array(),$search_params);
		}
		if ($return_structure['pagenumber'] > 1)
		{
			$search_params['p'] = $return_structure['pagenumber'] - 1;
			$prevUrl = $baseurl . vB5_Route::buildUrl('search', array(),$search_params);
		}

		$return_structure['pagination'] = array(
			'startcount' => $return_structure['from'],
			'endcount' => $return_structure['to'],
			'totalcount' => $return_structure['totalRecords'],
			'currentpage' => $return_structure['pagenumber'],
			'prevurl' => $prevUrl,
			'nexturl' => $nextUrl,
			"baseurl" => $url,
			'totalpages' =>$return_structure['totalpages']
		);

		return $return_structure;
	}

	/**
	 * Get the nodes from a search resultId
	 *
	 * @param  int   $resultId id of the search result
	 * @param  int   $perpage pagination - the number of results per page
	 * @param  int   $pagenumber pagination - the page number
	 *
	 * @return array List of nodes in the resultId
	 */
	public function getMoreResults($resultId, $perpage = false, $pagenumber = false, $getStarterInfo = false)
	{
		$return_structure = $this->getMoreNodes($resultId, $perpage, $pagenumber);

		$return_structure['results'] = vB_Library::instance('Node')->getFullContentforNodes($return_structure['nodeIds'], array('withParent' => $getStarterInfo, 'showVM' => 1));
		//note that getFullContentforNodes returns an element ['content']['permissions']['canviewthreads']

		foreach($return_structure['results'] AS $key => $result)
		{
			$return_structure['results'][$key] = vB_Api_Content::getContentApi($result['contenttypeid'])->cleanPreviewContent($return_structure['results'][$key]);
		}

		return $return_structure;
	}

	public function getInfo($resultId)
	{
		$assertor = vB::getDbAssertor();
		$cache = vB_Search_Core::instance()->getCache($resultId);
		$return_structure['resultId'] = $resultId;
		if (empty($cache))
		{
			throw new Exception('results_not_found');
		}
		$return_structure['totalRecords'] = $cache['results_count'];
		$return_structure['searchJSONStructure'] = $searchJSONStructure = json_decode($cache['json'], true);
		$re_encode = false;
		if (isset($searchJSONStructure['ignored_words']))
		{
			unset($searchJSONStructure['ignored_words']);
			$re_encode = true;
		}
		if (isset($searchJSONStructure['original_keywords']))
		{
			$searchJSONStructure['keywords'] = $searchJSONStructure['original_keywords'];
			unset($searchJSONStructure['original_keywords']);
			$re_encode = true;

		}
		if (isset($searchJSONStructure['error']))
		{
			unset($searchJSONStructure['error']);
			$re_encode = true;
		}

		$return_structure['searchJSON'] = $re_encode ? json_encode($searchJSONStructure) : $cache['json'];
		return $return_structure;
	}

	/**
	 * Get the page number where the specified node is at on the node list.
	 * @param int $nodeid			The node id
	 * @param array $starter	The starter array
	 * @param int $perpage 			The number of nodes per page the node list is using
	 * @param int $depth			The depth - 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 * @param string $sort			The sort order of the node list, 'asc' or 'desc'
	 * @param bool $include_starter	The flag to indicate if the starter node should be included in the node list or not
	 * @param string $type			The content type filter to use. Must be one of the strings defined in self::$showFilterList
	 * @return int					The page number of the specified node. 0 means the node was not found.
	 */
	public function getPageNumber($nodeid, $starter, $perpage = 20, $depth = 0, $sort = 'asc', $include_starter = true, $type = '')
	{
		if (!is_array($starter))
		{
			 throw new vB_Exception_Api('invalid_data_w_x_y_z', array($starter, 'starter', __CLASS__, __FUNCTION__));
		}

		$pagenum = 0;
		/* 	since comments' nodeid don't reflect what page they are on, we need to check
		 *	the closure table then return the page number of its parent instead if it's a
		 * 	comment. For forums, depth = 1 returns its parent, and the depth between thread
		 * 	starter and the comment is 2. So we return the parent & use that node if it's not
		 * 	the starter node
		 * 	since blog comments are akin to forum replies, we don't have to worry about them
		 */
		$closureQry = vB::getDbAssertor()->getRow('vBForum:closure',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'depth' => 1,
				'child' => $nodeid,
				vB_dB_Query::COLUMNS_KEY => array('parent'),
			)
		);

		// if the parent is not the starter, it's a comment. Use parent's nodeid to get the page it lives on
		if ( isset($closureQry['parent']) AND ($starter['nodeid'] != $closureQry['parent']) )
		{
			$nodeid = intval($closureQry['parent']);
		}

		if (intval($nodeid) > 0 AND !empty($starter) AND intval($starter['nodeid']) > 0)
		{
			$node = vB_Library::instance('node')->getNodeBare($nodeid);
			if (!empty($node))
			{
				//fetch records that fall between the starter's publishdate and the target node's publishdate
				//sort in asc order so that the last record is the node we're looking for
				//then from that, we can calculate the page number of the target node against the total nodes in the starter
				//it is important to have 'nolimit' to get the correct 'totalpages'
				//This is problematic from an efficiency and robustness standpoint, but
				$searchParams = array(
					'channel'			=> $starter['nodeid'],
					'depth'				=> $depth,
					'include_starter'	=> $include_starter,
					'date'				=> array(
						//	The starter isn't guarenteed to be in the same publish order as the children -- especially if topics
						//	have been merged or other oddities.  Moreover, having a start date doesn't really help -- we
						//	want everything from the beginning of the topic.  There is the potential for an "off by one"
						//	error if the target node comes before the starter in that manages to push the node to the wrong
						//	page.
//						'from'			=> ($include_starter) ? $starter['publishdate'] : $starter['publishdate'] + 1,
						'to'			=> $node['publishdate'],
					),
					'sort'				=> array(
						'created'		=> 'asc',
					),
					'nolimit'			=> 1,
				);

				// add the $type to the search json
				if (in_array($type, self::$showFilterList))
				{
					$searchParams['type'] = $type;
				}

				$search_json = json_encode($searchParams);
				if ($perpage <= 0 )
				{
					$perpage = 20;
				}

				$results = $this->getInitialResults($search_json, $perpage, 1);
				if (!empty($results) AND $results['totalpages'] > 0)
				{
					$pagenum = 	$results['totalpages'];

					//when sort is desc, the page number should be reversed and should be relative to the actual overall count of nodes in the starter
					if (strtolower($sort) == 'desc')
					{
						$totalrecords = ($depth == 1) ? $starter['textcount_1'] : $starter['totalcount_1']; //_1 means it includes the starter node itself
						$totalpages = ceil($totalrecords/$perpage);
						$searchtotal = $results['totalRecords'];
						$remainder = $totalrecords % $perpage;
						if ($remainder > 0)
						{
							$searchtotal -= $remainder;
							$pagenum = ceil($searchtotal/$perpage) + 1;
						}
						$pagenum = $totalpages - $pagenum + 1;
					}
				}
			}
		}

		return $pagenum;
	}


	/**
	 * Returns the Channel structure
	 * @param bool	flat				(optional) If supplied, the return structure will be flattened
	 * @param array queryOptions		(optional) filters for query. Available values:
	 *	- exclude_categories bool
	 *	- include_protected bool
	 *	- exclude_subtrees int|array -- exclude any subtrees rooted at the channel given by the id.  Allows
	 *			either a single channel or an array list.
	 * @param bool	skipcache			(optional) If supplied will skip cache & query the DB
	 * @param int 	topLevelChannel		(optional) If supplied will return the structure for the specified top level channel only.
	 *
	 * @return array channel structure
	 */
	public function getChannels(
		$flat = false,
		$queryOptions = array(
			'exclude_categories' => false,
			'include_protected' => false,
			'exclude_subtrees' => array(),
		),
		$skipcache = false,
		$topLevelChannel = 0
	)
	{
		//Calls from templates have traditionally not handled empty arrays properly.
		//since this is an API function we should be resistant to bad parameters
		if(!is_array($queryOptions))
		{
			$queryOptions = array();
		}

		//This is a public function so make sure that we have a proper value passed for the options.
		//This allows us to assume that exclude_subtrees is always an array later.
		if(empty($queryOptions['exclude_subtrees']))
		{
			$queryOptions['exclude_subtrees'] = array();
		}
		else if (!is_array($queryOptions['exclude_subtrees']))
		{
			$queryOptions['exclude_subtrees'] = array($queryOptions['exclude_subtrees']);
		}

		$no_perm_check = false;

		// admincp needs to display all the channels, regardless of the permissions
		if (!empty($queryOptions['no_perm_check']) AND vB::getUserContext()->hasAdminPermission('canadminpermissions'))
		{
			$no_perm_check = true;
		}

		if ($this->channelCache === null OR $skipcache OR $no_perm_check)
		{
			$rootid = (int) vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);

			$this->channelCache = vB::getDbAssertor()->getRows(
				'vBForum:getChannel',
				array(
					'channel' => $rootid,
					'include_parent'			=> 1,
					'includeProtected'			=> 1,
					'contenttypeid'				=> vB_Types::instance()->getContentTypeId('vBForum_Channel'),
					vB_dB_Query::PARAM_LIMIT	=> vB::getDatastore()->getOption('maxresults'),
					'no_limit'					=> true,
					'no_perm_check'				=> $no_perm_check,
					'sort' => array(
						'parentid'			=> 'asc',
						'displayorder'		=>	'asc'
					)
				)
			);

			foreach($this->channelCache AS $key => $channel)
			{
				unset($this->channelCache[$key]['ipaddress']);
			}
		}

		if (empty($this->channelCache))
		{
			return $this->channelCache;
		}

		if (!empty($queryOptions['exclude_categories']))
		{
			$categoryIds = $channelIds = array();
			foreach($this->channelCache AS $channel)
			{
				$channelIds[] = $channel['nodeid'];
			}
			if (!empty($channelIds))
			{
				$categories = vB::getDbAssertor()->assertQuery('vBForum:channel', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::COLUMNS_KEY => array('nodeid'),
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'nodeid', 'value' => $channelIds),
						array('field' => 'category', 'value' => 1)
					)
				));

				if ($categories)
				{
					foreach($categories AS $category)
					{
						$categoryIds[] = $category['nodeid'];
					}
				}
			}
		}

		if (empty($queryOptions['include_protected']))
		{
			$protectedIds = $channelIds = array();
			foreach($this->channelCache AS $channel)
			{
				$channelIds[] = $channel['nodeid'];
			}
			if (!empty($channelIds))
			{
				$protected = vB::getDbAssertor()->assertQuery('vBForum:node', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::COLUMNS_KEY => array('nodeid'),
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'nodeid', 'value' => $channelIds),
						array('field' => 'protected', 'value' => 1)
					)
				));

				if ($protected)
				{
					foreach($protected as $prot)
					{
						$protectedIds[] = $prot['nodeid'];
					}
				}
			}
		}

		//we do this is a seperate loops because if a child is in the list before it's parent
		//then we won't know the parent is excluded if we try to do it in a single list.
		//We also want the channel records set so that we can reference them by id
		$excluded = array();
		$results = array();
		foreach ($this->channelCache AS $channel)
		{
			$channelid = $channel['nodeid'];

			if (!empty($queryOptions['exclude_categories']) AND in_array($channelid, $categoryIds))
			{
				$excluded[$channelid] = true;
			}

			else if (empty($queryOptions['include_protected']) AND in_array($channelid, $protectedIds))
			{
				$excluded[$channelid] = true;
			}

			$channel['displayorder'] = intval($channel['displayorder']);
			$results[$channelid] = $channel;
		}

		foreach($queryOptions['exclude_subtrees'] AS $excludedchannelid)
		{
			$excluded[$excludedchannelid] = true;
		}

		$resultsTree = array();
		foreach ($this->channelCache AS $channel)
		{
			//if we are excluding it, don't add it to the tree.  We build a bunch of subtree, but
			//use of references mean that they'll eventually all link up with only the ones
			//we want in $resultsTree.
			//
			//excluded channels will be referenced in the results array, but won't ever get
			//incorporated into any trees.  Note that top level channels that are excluded
			//won't get copied into resultsTree (it is likely that we'll only ever have
			//one such top level channel)
			$channelid = $channel['nodeid'];
			if(isset($excluded[$channelid]))
			{
				continue;
			}

			//if this is in an excluded subtree then skip it like it was excluded
			//directly.  We have to do this bottom up because we can't walk
			//the tree top down.
			//Only do the looping if we actually have excluded subtrees
			if($queryOptions['exclude_subtrees'])
			{
				$depth = $channel['depth'];
				$parentid = $channel['parentid'];
				while($depth > 0)
				{
					if(in_array($parentid, $queryOptions['exclude_subtrees']))
					{
						continue 2;
					}
					$parentid = $results[$parentid]['parentid'];
					$depth--;
				}
			}

			//find the first non excluded ancestor.  This "flattens" the tree to
			//include visible children of excluded parents -- the tree will be treated
			//as if the channel was a direct child of it's first visible anscestor.
			$depth = $channel['depth'];
			$parentid = $channel['parentid'];
			while($depth > 0 AND isset($excluded[$parentid]))
			{
				$parentid = $results[$parentid]['parentid'];
				$depth--;
			}

			//if we moved the channel up the tree, fix the depth so that indentation
			//as such will be right.
			if ($depth != $results[$channelid]['depth'])
			{
				$results[$channelid]['depth'] = $depth;
			}

			//add this item to a tree
			if($depth > 0)
			{
				$results[$parentid]['channels'][$channelid] = &$results[$channelid];
			}
			//top level, let's store this tree in the final results.
			else
			{
				$resultsTree[$channelid] = &$results[$channelid];
			}
		}

		if ($topLevelChannel)
		{
			$root = vB_Library::instance('Content_Channel')->getMainChannel();

			if (isset($resultsTree[$root['nodeid']]['channels'][$topLevelChannel]))
			{
				$temp = $resultsTree[$root['nodeid']]['channels'][$topLevelChannel];
				$resultsTree = array();
				$resultsTree[$topLevelChannel] = $temp;
				unset($temp);
			}
			else
			{
				// find the specified $topLevelChannel if it's somewhere deeper in the results tree.
				$temp = $this->getChannelFromTree($resultsTree, $topLevelChannel);
				if ($temp !== null)
				{
					$resultsTree = array();
					$resultsTree[$topLevelChannel] = $temp;
				}
				unset($temp);
			}
		}

		if ($flat)
		{
			return self::flattenTree($resultsTree, 'channels');
		}

		return $resultsTree;
	}

	/**
	 * This takes the channel tree produced by getChannels, finds the specified channel
	 * recursively, then returns that channel's sub tree.  Used internally by getChannels.
	 *
	 * @param	array	Results tree
	 * @param	int	The nodeid to find
	 *
	 * @param	mixed	Subtree array or null if $topLevelChannel was not found.
	 */
	protected function getChannelFromTree($resultsTree, $topLevelChannel)
	{
		foreach ($resultsTree AS $nodeid => $channel)
		{
			if ($nodeid == $topLevelChannel)
			{
				return $channel;
			}
			else if (isset($channel['channels']))
			{
				$temp = $this->getChannelFromTree($channel['channels'], $topLevelChannel);
				if ($temp !== null)
				{
					return $temp;
				}
			}
		}

		return null;
	}

	private function flattenTree($tree, $branchName)
	{
		$leaves = array();
		foreach ($tree as $key => $branches)
		{
			$branch = array();
			if (!empty($branches[$branchName]))
			{
				$branch = $branches[$branchName];
			}
			$leaves[$key] = $branches;
			if (!empty($branch))
			{
				$templeaves = self::flattenTree($branch,$branchName);
				foreach ($templeaves as $index => $leaf)
				{
					$leaves[$index] = $leaf;
				}
			}
		}
		return $leaves;
	}

	public function getForumChannels($flat = false, $queryOptions = array('exclude_categories' => false), $skipcache = false)
	{
		$root = vB_Library::instance('Content_Channel')->getForumHomeChannel();
		return $this->getChannels($flat, $queryOptions, $skipcache, $root['nodeid']);
	}

	public function getSearchableContentTypes()
	{
		return vB_Types::instance()->getSearchableContentTypes();
	}

	private function json2criteria(&$json)
	{
		if (is_string($json))
		{
			$search_structure = json_decode($json, true);

			//$json is inherently utf-8, but our tags are not
			//we'll assume that if it comes in as an array, everything is fine.
			if(isset($search_structure['tag']))
			{
				$search_structure['tag'] = vB::getString()->toDefault($search_structure['tag'], 'utf-8');
			}
		}
		else
		{
			$search_structure = $json;
		}

		if (empty($search_structure) OR !is_array($search_structure))
		{
			throw new vB_Exception_Api('invalid_search_syntax', array($json));
		}

		$criteria = new vB_Search_Criteria();

		$def_sort_field = 'created';
		$def_sort_dir = 'DESC';

		$currentUserId = vB::getCurrentSession()->get('userid');

		$criteria->setUser($currentUserId);

		$normalized_criteria = array();
		if (!empty($search_structure['keywords']))
		{
			$words = $criteria->add_keyword_filter($search_structure['keywords'], !empty($search_structure['title_only']));
			$def_sort_field = 'lastcontent';
			if (!empty($words))
			{
				$normalized_criteria['keywords'] = '';
				$separator = '';
				foreach ($words as $word)
				{
					if (!empty($word['joiner']))
					{
						$normalized_criteria['keywords'] .= $separator . strtoupper($word['joiner']);
						$separator = ' ';
					}
					$normalized_criteria['keywords'] .= $separator . $word['word'];
					$separator = ' ';
				}
				if (!empty($search_structure['title_only']))
				{
					$normalized_criteria['title_only'] = 1;
				}
			}
			else
			{
				$normalized_criteria['error']= 'ignored_search_keywords';
			}
			$ignored_words = $criteria->get_ignored_keywords();
			if (!empty($ignored_words))
			{
				$normalized_criteria['ignored_words'] = $ignored_words;
				$normalized_criteria['original_keywords'] = $search_structure['keywords'];
			}
		}

		// events_during - enhanced calendar feature. Find events with either the startdate or enddate
		// inside the events_during range.
		if (!empty($search_structure['events_during']) AND
			is_array($search_structure['events_during']) AND
			!empty($search_structure['events_during']['from']) AND
			!empty($search_structure['events_during']['to'])
		)
		{
			$vboptions = vB::getDatastore()->getValue('options');
			// Make sure event_max_duration is at least 1 day
			$maxDurationSeconds = max($vboptions['event_max_duration'], 1) * 86400;
			$__rangeStart = $this->computeDateLine($search_structure['events_during']['from']);
			$__rangeEnd = $this->computeDateLine($search_structure['events_during']['to']);

			if ($__rangeStart < $__rangeEnd)
			{
				/*
				(RS - 31 < ES AND RE > ES AND RS < EE AND RE + 31 > EE)

				(
				RS - 31 < ES AND
				RE      > ES AND
				=> RS - 31 < ES < RE
				RS      < EE AND
				RE + 31 > EE
				=> RS < EE < RE + 31
				)
				 */
				$search_structure['eventstartdate'] = array(
					'from' => $__rangeStart - $maxDurationSeconds,
					'to' => $__rangeEnd,
				);
				$search_structure['eventenddate'] = array(
					'from' => $__rangeStart,
					'to' => $__rangeEnd + $maxDurationSeconds,
				);
			}
		}



		// eventenddate. Currently, we only support this in conjunction with eventstartdate for the "events_during"
		// complex filter. If we want to support the simple/single filter & the "future" filters, refactor the eventstartdate
		// code after this block to reduce code duplication.
		if (!empty($search_structure['eventenddate']) AND is_array($search_structure['eventenddate']))
		{
			$__dateline = 0;
			if ( !empty($search_structure['eventenddate']['from']) )
			{
				$__dateline = $this->computeDateLine($search_structure['eventenddate']['from']);
				if(!empty($__dateline))
				{
					$criteria->add_filter('eventenddate', vB_Search_Core::OP_GTE, $__dateline);
					$normalized_criteria['eventenddate']['from'] = $search_structure['eventenddate']['from'];
				}
			}

			if ( !empty($search_structure['eventenddate']['to']) )
			{
				$__dateline = $this->computeDateLine($search_structure['eventenddate']['to']);
				if(!empty($__dateline))
				{
					$criteria->add_filter('eventenddate', vB_Search_Core::OP_LTE, $__dateline);
					$normalized_criteria['eventenddate']['to'] = $search_structure['eventenddate']['to'];
				}
			}
			unset($__dateline);

			/*
				this filter's processing explicitly filters contenttypeid, so trying to find
				an event type & filter by another (or the same) contenttype makes no sense.
				Unset the contenttypeid filter.
			 */
			unset($search_structure['contenttypeid']);

			// when searching for events, sort them by end date by default. note that if both eventstardate &
			// eventenddate are filtered, the startdate sorting will override enddate sorting.
			$def_sort_field = 'eventstartdate';
			$def_sort_dir = 'ASC';
		}


		// eventstartdate
		if (!empty($search_structure['eventstartdate']))
		{
			$__dateline = 0;
			if (is_array($search_structure['eventstartdate']))
			{
				if ( !empty($search_structure['eventstartdate']['from']) )
				{
					$__dateline = $this->computeDateLine($search_structure['eventstartdate']['from']);
					if(!empty($__dateline))
					{
						$criteria->add_filter('eventstartdate', vB_Search_Core::OP_GTE, $__dateline);
						$normalized_criteria['eventstartdate']['from'] = $search_structure['eventstartdate']['from'];
					}
				}

				if ( !empty($search_structure['eventstartdate']['to']) )
				{
					$__dateline = $this->computeDateLine($search_structure['eventstartdate']['to']);
					if(!empty($__dateline))
					{
						$criteria->add_filter('eventstartdate', vB_Search_Core::OP_LTE, $__dateline);
						$normalized_criteria['eventstartdate']['to'] = $search_structure['eventstartdate']['to'];
					}
				}
			}
			else if ($search_structure['eventstartdate'] == 'future')
			{
				// convenience method to return all future/upcoming events
				$__dateline = vB::getRequest()->getTimeNow();
				$criteria->add_filter('eventstartdate', vB_Search_Core::OP_GTE, $__dateline);
				$normalized_criteria['eventstartdate'] = $__dateline;
			}
			else
			{
				$__dateline = intval($search_structure['eventstartdate']);
				if(!empty($__dateline))
				{
					$criteria->add_filter('eventstartdate', vB_Search_Core::OP_GTE, $__dateline);
					$normalized_criteria['eventstartdate'] = $__dateline;
				}
			}
			unset($__dateline);

			/*
				this filter's processing explicitly filters contenttypeid, so trying to find
				an event type & filter by another (or the same) contenttype makes no sense.
				Unset the contenttypeid filter.
			 */
			unset($search_structure['contenttypeid']);

			// when searching for events, sort them by start date by default
			$def_sort_field = 'eventstartdate';
			$def_sort_dir = 'ASC';
		}

		if (!empty($search_structure['contenttypeid']))
		{
			$search_structure['type'] = vB_Types::instance()->getContentTypeClasses($search_structure['contenttypeid']);
			if (count($search_structure['type']) == 1)
			{
				$search_structure['type'] = array_pop($search_structure['type']);
			}
			unset($search_structure['contenttypeid']);
		}

		if(!empty($search_structure['type']))
		{
			$contentypeids = $criteria->add_contenttype_filter($search_structure['type']);
			$normalized_criteria['type'] = $search_structure['type'];
			$pmcontentypeid = vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage');
			if (in_array($pmcontentypeid, $contentypeids))
			{
				if (count($contentypeids) == 1)
				{
					$search_structure['private_messages_only'] = 1;
				}
				else
				{
					$search_structure['include_private_messages'] = 1;
				}
			}
			$vmcontentypeid = vB_Types::instance()->getContentTypeID('vBForum_VisitorMessage');
			if (in_array($vmcontentypeid, $contentypeids))
			{
				if (count($contentypeids) == 1)
				{
					$search_structure['visitor_messages_only'] = 1;
				}
				else
				{
					$search_structure['include_visitor_messages'] = 1;
				}
			}
			$photocontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Photo');
			if (in_array($photocontentypeid, $contentypeids))
			{
				$search_structure['include_attach'] = 1;
			}
		}
		elseif (
				empty($search_structure['exclude_type'])
				OR (is_string($search_structure['exclude_type']) AND $search_structure['exclude_type'] != 'vBForum_PrivateMessage')
				OR (is_array($search_structure['exclude_type']) AND !in_array('vBForum_PrivateMessage',$search_structure['exclude_type']))
			)
		{
			$search_structure['include_private_messages'] = 1;
		}
		elseif(
				!empty($search_structure['exclude_type'])
				AND (
						(is_string($search_structure['exclude_type']) AND $search_structure['exclude_type'] == 'vBForum_VisitorMessage')
						OR (is_array($search_structure['exclude_type']) AND in_array('vBForum_VisitorMessage',$search_structure['exclude_type']))
					)
			)
		{
			$search_structure['exclude_visitor_messages'] = 1;
		}

		if (empty($search_structure['type'])
			AND
			empty($search_structure['exclude_visitor_messages'])
			AND
			(
				empty($search_structure['exclude_type'])
				OR (is_string($search_structure['exclude_type']) AND $search_structure['exclude_type'] != 'vBForum_VisitorMessage')
				OR (is_array($search_structure['exclude_type']) AND !in_array('vBForum_VisitorMessage',$search_structure['exclude_type']))
			)
		)
		{
			$search_structure['include_visitor_messages'] = 1;
		}

		// author by username
		if (!empty($search_structure['author']))
		{
			//reducing users from array to single
			if (is_array($search_structure['author']) AND count($search_structure['author']) == 1)
			{
				$search_structure['author'] = array_pop($search_structure['author']);
				$search_structure['exactname'] = 1;
			}

			// only one username
			if (is_string($search_structure['author']))
			{
				// it's an exact username - no partial match
				if (!empty($search_structure['exactname']))
				{
					$search_structure['author'] = trim($search_structure['author']);
					switch ($search_structure['author'])
					{
						case 'myFriends':
							$userid = array();
							if (!empty($currentUserId))
							{
								$userid = vB::getDbAssertor()->getColumn('userlist', 'relationid',array(
										'userid' => $currentUserId,
										'friend' => 'yes'
									),
									false,
									'relationid'
								);
							}
							if($userid)
							{
								$criteria->add_filter('userid', vB_Search_Core::OP_EQ, $userid, true);
							}
							else
							{
								$criteria->add_null_filter('no friends found');
							}
							break;
						case 'iFollow':
							if (empty($search_structure[self::FILTER_FOLLOW]))
							{
								$search_structure[self::FILTER_FOLLOW] = self::FILTER_FOLLOWING_USERS;
							}
							elseif ($search_structure[self::FILTER_FOLLOW] == self::FILTER_FOLLOWING_CHANNEL)
							{
								$search_structure[self::FILTER_FOLLOW] = self::FILTER_FOLLOWING_BOTH;
							}
							break;
						case 'currentUser':
							$criteria->add_filter('userid', vB_Search_Core::OP_EQ, $currentUserId, true);
							break;
						default:
							$criteria->add_user_filter($search_structure['author'], !empty($search_structure['exactname']));
							break;
					}
					$normalized_criteria['author'] = strtolower($search_structure['author']);
					$normalized_criteria['exactname'] = 1;
				}
				// this is a partial match - need more than 3 chars
				elseif (vb_String::vbStrlen($search_structure['author']) >= 3)
				{
					$criteria->add_user_filter($search_structure['author'], !empty($search_structure['exactname']));
					$normalized_criteria['author'] = strtolower($search_structure['author']);
				}
			}
			// this is a list of usernames
			elseif (is_array($search_structure['author']))
			{
				$user_names = array();
				foreach ($search_structure['author'] as $author)
				{
					$author = vB_String::htmlSpecialCharsUni($author);
					$user = vB_Api::instanceInternal("User")->fetchByUsername($author);
					$userid = false;
					if (!empty($user['userid']))
					{
						$user_ids[] = $user['userid'];
						$user_names[] = $user['username'];
					}
				}
				if (!empty($user_ids))
				{
					$criteria->add_filter('userid', vB_Search_Core::OP_EQ, $user_ids, true);
				}
				else
				{
					$criteria->add_null_filter('no record matches usernames');
				}
				sort($user_names);
				$normalized_criteria['author'] = $user_names;
			}
		}

		// author by userid
		if (!empty($search_structure['authorid']))
		{
			//reducing users from array to single
			if (is_array($search_structure['authorid']) AND count($search_structure['authorid']) == 1)
			{
				$search_structure['authorid'] = array_pop($search_structure['authorid']);
			}

			if (is_numeric($search_structure['authorid']))
			{

				if (!empty($search_structure['visitor_messages_only']))
				{
					$criteria->add_filter('visitor_messages_only', vB_Search_Core::OP_EQ, $search_structure['authorid']);
					$normalized_criteria['visitor_messages_only'] = 1;
				}
				elseif (!empty($search_structure['include_visitor_messages']))
				{
					$criteria->add_filter('include_visitor_messages', vB_Search_Core::OP_EQ, $search_structure['authorid']);
					$normalized_criteria['include_visitor_messages'] = 1;
				}
				else
				{
					$criteria->add_filter('userid', vB_Search_Core::OP_EQ, $search_structure['authorid'], true);
				}

				if (!empty($search_structure['exclude_visitor_messages']))
				{
					$criteria->add_filter('exclude_visitor_messages', vB_Search_Core::OP_EQ, $search_structure['authorid']);
					$normalized_criteria['exclude_visitor_messages'] = 1;
				}

				$normalized_criteria['authorid'] = $search_structure['authorid'];
			}
			elseif (is_array($search_structure['authorid']))
			{
				$user_ids = array();
				foreach ($search_structure['authorid'] as $author)
				{
					if (is_numeric($author))
					{
						$user_ids[] = intval($author);
					}
				}
				$criteria->add_filter('userid', vB_Search_Core::OP_EQ, $user_ids, true);
				sort($user_ids);
				$normalized_criteria['authorid'] = $user_ids;
			}
		}
		else if (!empty($search_structure['exclude_visitor_messages']))
		{
			$criteria->add_filter('exclude_visitor_messages', vB_Search_Core::OP_EQ, 0);
			$normalized_criteria['exclude_visitor_messages'] = 1;
		}

		if(!empty($search_structure['trending']))
		{
			$criteria->add_filter('trending',  vB_Search_Core::OP_EQ, 1);
			$normalized_criteria['trending'] = 1;
		}

		// channel owner filter
		if (!empty($search_structure['my_channels']))
		{
			$temp = array();
			// restrict 'type' to string 'blog' or 'group', else default to 'blog'
			if (isset($search_structure['my_channels']['type'])
				AND (
					$search_structure['my_channels']['type'] == 'blog' OR
					$search_structure['my_channels']['type'] == 'group'
				)
			)
			{
				$temp['type'] = $search_structure['my_channels']['type'];
			}
			else
			{
				$temp['type'] = 'blog';
			}

			$normalized_criteria['my_channels'] = $temp;
			$criteria->add_filter('my_channels', vB_Search_Core::OP_EQ, $temp);
			unset($temp);
		}


		if (!empty($search_structure['private_messages_only']))
		{
			$criteria->add_filter('private_messages_only', vB_Search_Core::OP_EQ, $currentUserId);
			$normalized_criteria['private_messages_only'] = 1;
		}

		// visitor message recipient
		if (!empty($search_structure['sentto']))
		{
			//reducing users from array to single
			if (is_array($search_structure['sentto']) AND count($search_structure['sentto']) == 1)
			{
				$search_structure['sentto'] = array_pop($search_structure['sentto']);
			}

			if (is_numeric($search_structure['sentto']))
			{
				$criteria->add_filter('sentto', vB_Search_Core::OP_EQ, intval($search_structure['sentto']));
				$normalized_criteria['visitor_messages_only'] = 1;
				$normalized_criteria['sentto'] = intval($search_structure['sentto']);
			}
			elseif (is_array($search_structure['sentto']))
			{
				$user_ids = array_map('intval', $search_structure['sentto']);
				sort($user_ids);
				$criteria->add_filter('sentto', vB_Search_Core::OP_EQ, $user_ids);
				$normalized_criteria['visitor_messages_only'] = 1;
				$normalized_criteria['sentto'] = $user_ids;
			}
		}

		if (!empty($search_structure['tag']))
		{

			if (is_array($search_structure['tag']))
			{
				foreach ($search_structure['tag'] AS $index => $tag)
				{
					$search_structure['tag'][$index] = vB_String::htmlSpecialCharsUni(trim($tag));
				}
			}
			else
			{
				$search_structure['tag'] = vB_String::htmlSpecialCharsUni(trim($search_structure['tag']));
			}
			$existing_tags = $criteria->add_tag_filter($search_structure['tag']);
			$normalized_criteria['tag'] = array_keys($existing_tags);
			vB_Api::instanceInternal('Tags')->logSearchTags($existing_tags);
		}

		if (!empty($search_structure['date']))
		{
			if ($search_structure['date'] == self::FILTER_LASTVISIT)
			{
				$current_user = vB::getCurrentSession()->fetch_userinfo();
				$dateline = $current_user['lastvisit'];

				if(empty($dateline))
				{
					$dateline = vB::getRequest()->getTimeNow() - (86400 * 14);
				}
				$criteria->add_date_filter(vB_Search_Core::OP_GTE, $dateline);
				$normalized_criteria['date'] = self::FILTER_LASTVISIT;
			}
			if ($search_structure['date'] == self::FILTER_TOPICAGE)
			{
				$age = vB::getDatastore()->getOption('max_age_topic');
				if ((intval($age) == 0) )
				{
					$age = 60;
				}
				$criteria->add_date_filter(vB_Search_Core::OP_GTE, vB::getRequest()->getTimeNow() - (86400 * $age));
				$normalized_criteria['date'] = self::FILTER_TOPICAGE;
			}
			if ($search_structure['date'] == self::FILTER_CHANNELAGE)
			{
				$age = vB::getDatastore()->getOption('max_age_channel');
				if ((intval($age) == 0) )
				{
					$age = 60;
				}
				$criteria->add_date_filter(vB_Search_Core::OP_GTE, vB::getRequest()->getTimeNow() - (86400 * $age));
				$normalized_criteria['date'] = self::FILTER_CHANNELAGE;
			}

			// forcing to get the whole date spectrum; activity stream view enforces a date range so this is the workaround
			if (!empty($search_structure['date']) AND is_string($search_structure['date']) AND $search_structure['date'] == self::FILTER_DATEALL)
			{
				$criteria->add_date_filter(vB_Search_Core::OP_EQ, self::FILTER_DATEALL);
				$normalized_criteria['date'] = self::FILTER_DATEALL;
			}

			if (is_array($search_structure['date']) AND !empty($search_structure['date']['from']))
			{
				$dateline = $this->computeDateLine($search_structure['date']['from']);
				if(!empty($dateline))
				{
					$criteria->add_date_filter(vB_Search_Core::OP_GTE, $dateline);
					$normalized_criteria['date']['from'] = $search_structure['date']['from'];
				}
			}

			if (is_array($search_structure['date']) AND !empty($search_structure['date']['to']))
			{
				$dateline = $this->computeDateLine($search_structure['date']['to'], true);
				if(!empty($dateline))
				{
					$criteria->add_date_filter(vB_Search_Core::OP_LTE, $dateline);
					$normalized_criteria['date']['to'] = $search_structure['date']['to'];
				}
			}
		}

		if (!empty($search_structure['last']))
		{

			if (is_array($search_structure['last']) AND !empty($search_structure['last']['from']))
			{
				$dateline = $this->computeDateLine($search_structure['last']['from']);
				if(!empty($dateline))
				{
					$criteria->add_last_filter(vB_Search_Core::OP_GTE, $dateline);
					$normalized_criteria['last']['from'] = $search_structure['last']['from'];
				}
			}


			if (is_array($search_structure['last']) AND !empty($search_structure['last']['to']))
			{
				$dateline = $this->computeDateLine($search_structure['last']['to'], true);
				if(!empty($dateline))
				{
					$criteria->add_last_filter(vB_Search_Core::OP_LTE, $dateline);
					$normalized_criteria['last']['to'] = $search_structure['last']['to'];
				}
			}
		}

		if (!empty($search_structure['exclude']))
		{
			$criteria->add_exclude_filter($search_structure['exclude']);
			$normalized_criteria['exclude'] = $search_structure['exclude'];
		}

		// ----- Sort order -----

		if (empty($search_structure['sort']))
		{
			$search_structure['sort'] = array(
				$def_sort_field => $def_sort_dir,
			);
		}

		if (!is_array($search_structure['sort']))
		{
			$sort_dir = $def_sort_dir;
			if (strtolower($search_structure['sort']) == 'title')
			{
				$sort_dir = 'ASC';
			}
			$search_structure['sort'] = array($search_structure['sort'] => $sort_dir);
		}

		foreach ($search_structure['sort'] as $sort_field => $sort_dir)
		{
			$criteria->set_sort($sort_field, strtoupper($sort_dir));
		}

		if ($sort_field != $def_sort_field OR $sort_dir != $def_sort_dir)
		{
			$normalized_criteria['sort'] = array($sort_field => strtoupper($sort_dir));
		}

		// ----- View / display -----

		if (!empty($search_structure['view']))
		{
			if ($search_structure['view'] == vB_Api_Search::FILTER_VIEW_CONVERSATION_STREAM AND !empty($search_structure['channel']))
			{
				$search_structure['depth'] = 2;
				$search_structure['include_starter'] = true;
			}
			elseif ($search_structure['view'] == vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD AND !empty($search_structure['channel']))
			{
				$search_structure['depth'] = 1;
				$search_structure['include_starter'] = true;
			}
			else
			{
				$criteria->add_view_filter($search_structure['view']);
				$normalized_criteria['view'] = $search_structure['view'];
			}
		}

		if (!empty($search_structure['starter_only']))
		{
			$criteria->add_filter('starter_only', vB_Search_Core::OP_EQ, true);
			$search_structure['include_starter'] = true;
			$normalized_criteria['starter_only'] = 1;
		}

		if (!empty($search_structure['reply_only']))
		{
			$criteria->add_filter('reply_only', vB_Search_Core::OP_EQ, true);
			$search_structure['include_starter'] = false;
			$normalized_criteria['reply_only'] = 1;
		}

		if (!empty($search_structure['comment_only']))
		{
			$criteria->add_filter('comment_only', vB_Search_Core::OP_EQ, true);
			$search_structure['include_starter'] = false;
			$normalized_criteria['comment_only'] = 1;
		}

		// this is kind of tacky, but let's just hook into the existing channel search by converting the GUID to channelid.
		if (!empty($search_structure['channelguid']))
		{
			$channel = vB_Library::instance('content_channel')->fetchChannelByGUID($search_structure['channelguid']);
			if (!empty($channel['nodeid']))
			{
				$search_structure['channel'] = $channel['nodeid'];
			}
		}


		if (!empty($search_structure['channel']))
		{
			$criteria->add_channel_filter(
					$search_structure['channel'],
					empty($search_structure['depth']) ? false : $search_structure['depth'],
					empty($search_structure['include_starter']) ? false : true,
					empty($search_structure['depth_exact']) ? false : true
			);

			$normalized_criteria['channel'] = $search_structure['channel'];

			if (!empty($search_structure['depth']))
			{
				$normalized_criteria['depth'] = $search_structure['depth'];
			}

			if (!empty($search_structure['depth_exact']))
			{
				$normalized_criteria['depth_exact'] = true;
			}

			if (!empty($search_structure['include_starter']))
			{
				$normalized_criteria['include_starter'] = 1;
			}
		}
		elseif (!empty($search_structure['module_filter_nodes']))
		{
			$criteria->add_inc_exc_channel_filter($search_structure['module_filter_nodes']);
			// todo clean in here instead of criteria & set cleaned params to normalized_criteria?
			$normalized_criteria['module_filter_nodes'] = $search_structure['module_filter_nodes'];
			// todo: add $normalized_criteria['filterChannels'] to "is restrctive" check?
		}

		if (!empty($search_structure['featured']))
		{
			$criteria->add_filter('featured', vB_Search_Core::OP_EQ, $search_structure['featured']);
			$normalized_criteria['featured'] = 1;
		}

		if (!empty($search_structure[self::FILTER_FOLLOW]))
		{
			if (is_string($search_structure[self::FILTER_FOLLOW]) AND !empty($currentUserId))
			{
				$criteria->add_follow_filter($search_structure[self::FILTER_FOLLOW], $currentUserId);
				$normalized_criteria[self::FILTER_FOLLOW] = $search_structure[self::FILTER_FOLLOW];
			}
			elseif (is_array($search_structure[self::FILTER_FOLLOW]))
			{
				$userid = reset($search_structure[self::FILTER_FOLLOW]);
				$type = key($search_structure[self::FILTER_FOLLOW]);
				$criteria->add_follow_filter($type, $userid);
				$normalized_criteria[self::FILTER_FOLLOW] = $search_structure[self::FILTER_FOLLOW];
			}
		}

		if (!empty($search_structure['my_following']) AND !empty($currentUserId))
		{
			$criteria->add_follow_filter(self::FILTER_FOLLOWING_CHANNEL, $currentUserId);
			$normalized_criteria['my_following'] = $search_structure['my_following'];
		}

		if (!empty($search_structure['exclude_type']))
		{
			$criteria->add_contenttype_filter($search_structure['exclude_type'], vB_Search_Core::OP_NEQ);
			$normalized_criteria['exclude_type'] = $search_structure['exclude_type'];
		}

		if (!empty($search_structure['sticky_only']))
		{
			$criteria->add_filter('sticky', vB_Search_Core::OP_EQ, '1');
			$normalized_criteria['sticky_only'] = 1;
		}

		if (!empty($search_structure['exclude_sticky']))
		{
			$criteria->add_filter('sticky', vB_Search_Core::OP_NEQ, '1');
			$normalized_criteria['exclude_sticky'] = 1;
		}

		if (!empty($search_structure['include_sticky']))
		{
			$criteria->set_include_sticky();
			$normalized_criteria['include_sticky'] = 1;
		}

		if (empty($search_structure['include_blocked']) OR empty($currentUserId) OR !vB::getUserContext()->hasPermission('moderatorpermissions', 'canbanusers'))
		{
			//block people on the global ignore list.
			$globalignore = trim(vB::getDatastore()->getOption('globalignore'));
			if (!empty($globalignore))
			{
				$blocked = preg_split('#\s+#s', $globalignore, -1, PREG_SPLIT_NO_EMPTY);
				//the user can always see their own posts, so if they are in the blocked list we remove them
				if (!empty($currentUserId))
				{
					$bbuserkey = array_search($currentUserId , $blocked);

					if ($bbuserkey !== FALSE AND $bbuserkey !== NULL)
					{
						unset($blocked["$bbuserkey"]);
					}
				}
				//Make sure we didn't just empty the list
				if (!empty($blocked))
				{
					$criteria->add_filter('userid', vB_Search_Core::OP_NEQ, $blocked, false, true);
				}
			}
		}
		elseif (!empty($currentUserId) AND vB::getUserContext()->hasPermission('moderatorpermissions', 'canbanusers'))
		{
			$normalized_criteria['include_blocked'] = 1;
		}

		if (empty($search_structure['include_blocked']) AND !empty($currentUserId))
		{
			$currentUserInfo = vB_User::fetchUserinfo($currentUserId);
			if (!empty($currentUserInfo['ignorelist']))
			{
				$criteria->add_filter('userid', vB_Search_Core::OP_NEQ, explode(' ', $currentUserInfo['ignorelist']), false, true);
			}
		}

		if (!empty($search_structure['ignore_protected']))
		{
			$criteria->add_filter('protected', vB_Search_Core::OP_NEQ, '1');
			$normalized_criteria['ignore_protected'] = 1;
		}

		if (!empty($search_structure['deleted_only']) AND !empty($currentUserId) AND vB::getUserContext()->hasPermission('moderatorpermissions', 'canremoveposts'))
		{
			$criteria->add_filter('showpublished', vB_Search_Core::OP_EQ, '0');
			$criteria->add_filter('deleteuserid', vB_Search_Core::OP_NEQ, '0');
			$normalized_criteria['deleted_only'] = 1;
		}

		if (!empty($search_structure['exclude_deleted']))
		{
			$criteria->add_filter('showpublished', vB_Search_Core::OP_EQ, '1');
			$normalized_criteria['exclude_deleted'] = 1;
		}

		/*
			this suggests that as far as search queries go inlist is used exclusively to pull attach / photos
			Note that inlist is used elsewhere for things like determining what can update a parent's lastcontent.
		 */
		if (empty($search_structure['include_attach']))
		{
			$criteria->add_filter('inlist', vB_Search_Core::OP_EQ, 1);
		}
		else
		{
			$normalized_criteria['include_attach'] = 1;
		}

		if (!empty($search_structure['unapproved_only']) AND !empty($currentUserId) AND vB::getUserContext()->hasPermission('moderatorpermissions', 'canmanagethreads'))
		{
			$criteria->add_filter('approved', vB_Search_Core::OP_NEQ, '1');
			$normalized_criteria['unapproved_only'] = 1;
		}
		if (!empty($search_structure['unread_only']) AND !empty($currentUserId) AND vB::getDatastore()->getOption('threadmarking') > 0)
		{
			$criteria->add_filter('marked', vB_Search_Core::OP_EQ, self::FILTER_MARKED_UNREAD);
			$normalized_criteria['unread_only'] = 1;
		}

		if (!empty($search_structure['specific']))
		{
			$criteria->add_filter('nodeid', vB_Search_Core::OP_EQ, $search_structure['specific']);
			$normalized_criteria['specific'] = $search_structure['specific'];
		}

		if (!empty($search_structure['prefix']))
		{
			$normalized_criteria['prefix'] = $search_structure['prefix'];
			$criteria->add_filter('prefixid', vB_Search_Core::OP_EQ, $search_structure['prefix']);
		}

		if (!empty($search_structure['has_prefix']))
		{
			$normalized_criteria['has_prefix'] = 1;
			$criteria->add_filter('prefixid', vB_Search_Core::OP_NEQ, '');
		}

		if (!empty($search_structure['no_prefix']))
		{
			$normalized_criteria['no_prefix'] = 0;
			$criteria->add_filter('prefixid', vB_Search_Core::OP_EQ, '');
		}

		// private messages are included by default. Use the exclude_type filter to exlude them
		// they are not included if a specific channel is requested OR looking for visitor messages
		// Note, "DEFAULT_CHANNEL_PARENT" is the special channel, not the forum channel. So this is Root, Special, PM channels
		$channelLib = vB_Library::instance('Content_Channel');
		$pmChannelAncestors = array(
			$channelLib->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL),
			$channelLib->fetchChannelIdByGUID(vB_Channel::DEFAULT_CHANNEL_PARENT),
			$channelLib->fetchChannelIdByGUID(vB_Channel::PRIVATEMESSAGE_CHANNEL),
		);
		$channelIncludesPMs = (
			!empty($normalized_criteria['channel']) AND
			(
				is_numeric($normalized_criteria['channel']) AND
				in_array($normalized_criteria['channel'], $pmChannelAncestors)
					OR
				is_array($normalized_criteria['channel']) AND
				count(array_intersect($normalized_criteria['channel'], $pmChannelAncestors)) > 0
			)
		);
		if (
				!empty($search_structure['include_private_messages'])
				AND empty($normalized_criteria['private_messages_only'])
				AND empty($normalized_criteria['sentto'])
				AND (
						empty($normalized_criteria['channel'])
						OR $channelIncludesPMs
				)
				AND empty($normalized_criteria['my_channels'])
		)
		{
			$criteria->add_filter('include_private_messages', vB_Search_Core::OP_EQ, $currentUserId);
		}

		if (!empty($search_structure['context']))
		{
			$criteria->setSearchContext($search_structure['context']);
			$normalized_criteria['context'] = $search_structure['context'];
			// If we have a context we must have pagenumber & perpage.
			unset($search_structure['nolimit']);
			if (!empty(intval($search_structure['perpage'])) AND !empty(intval($search_structure['pagenumber'])))
			{
				$normalized_criteria['pagenumber'] = intval($search_structure['pagenumber']);
				$normalized_criteria['perpage'] = intval($search_structure['perpage']);
			}
			else
			{
				// If perpage is empty, that indicates an "infinity" which we currently will not support.
				// This is only intentionally used ATM for sticky posts, and I think we can safely assume
				// most forums are not gonna have more than a few sticky posts per forum, much less over 1k.
				$normalized_criteria['pagenumber'] = 1;
				$normalized_criteria['perpage'] = 999;
			}
			$criteria->setLimitOffset(($normalized_criteria['pagenumber'] - 1) * $normalized_criteria['perpage']);
			$criteria->setLimitCount($normalized_criteria['perpage']);
		}

		if (
				!empty($search_structure['nolimit'])
				AND !empty($normalized_criteria['channel'])
				AND (empty($normalized_criteria['view']) OR $normalized_criteria['view'] != self::FILTER_VIEW_ACTIVITY)
				AND empty($search_structure['author'])
				AND empty($search_structure['authorid'])
				AND empty($search_structure['keywords'])
				AND empty($search_structure['sentto'])
				AND empty($search_structure['private_messages_only'])
				AND empty($search_structure['tag'])
				AND empty($search_structure['featured'])
				AND empty($search_structure['my_following'])
				AND empty($search_structure['unapproved_only'])
				AND empty($search_structure['unread_only'])
			)
		{
			$normalized_criteria['nolimit'] = 1;
			$criteria->setNoLimit();
		}

		// Two pass caching can be disabled by either ignore_cache which
		// also disabled the searchlog table or by specifying 'disable_two_pass'
		// Two pass caching can be forced on when 'ignore_cache' has been called
		// by specifying 'force_two_pass' (for unit testing the two pass cache functionality itself)

		if (!empty($search_structure['ignore_cache']) OR self::IGNORE_CACHE)
		{
			$normalized_criteria['disable_two_pass'] = 1;
			$criteria->setIgnoreCache(true);
		}

		if (!empty($search_structure['disable_two_pass']))
		{
			$normalized_criteria['disable_two_pass'] = 1;
		}

		if (!empty($search_structure['force_two_pass']) AND !empty($normalized_criteria['disable_two_pass']))
		{
			unset($normalized_criteria['disable_two_pass']);
		}

		//checking for a restrictive filter
		if (
				empty($normalized_criteria['keywords'])
				AND empty($normalized_criteria['authorid'])
				AND empty($normalized_criteria['author'])
				AND empty($normalized_criteria['private_messages_only'])
				AND empty($normalized_criteria['visitor_messages_only'])
				AND empty($normalized_criteria['sentto'])
				AND empty($normalized_criteria['tag'])
				AND (empty($normalized_criteria['date']) OR (is_string($normalized_criteria['date']) AND $normalized_criteria['date'] == self::FILTER_DATEALL))
				AND (empty($normalized_criteria['last']) OR (is_string($normalized_criteria['last']) AND $normalized_criteria['last'] == self::FILTER_DATEALL))
				AND empty($normalized_criteria['channel'])
				AND empty($normalized_criteria['featured'])
				AND empty($normalized_criteria[self::FILTER_FOLLOW])
				AND empty($normalized_criteria['my_following'])
				AND empty($normalized_criteria['sticky_only'])
				AND empty($normalized_criteria['deleted_only'])
				AND empty($normalized_criteria['unapproved_only'])
				AND empty($normalized_criteria['unread_only'])
				AND empty($normalized_criteria['specific'])
				AND empty($normalized_criteria['prefix'])
				AND empty($normalized_criteria['has_prefix'])
				AND empty($normalized_criteria['no_prefix'])
				AND empty($normalized_criteria['my_channels'])
				AND empty($normalized_criteria['eventstartdate'])
				AND empty($normalized_criteria['module_filter_nodes'])
		)
		{
			//temporary solution for VBV-10061
			if ($normalized_criteria['view'] == self::FILTER_VIEW_ACTIVITY)
			{
				$dateline = $this->computeDateLine(self::FILTER_LASTMONTH);
				if(!empty($dateline))
				{
					$criteria->add_date_filter(vB_Search_Core::OP_GTE, $dateline);
				}
			}
			else
			//end of temporary solution
			{
				throw new vB_Exception_Api('criteria_not_restrictive', array($normalized_criteria));
			}
		}
		$criteria->setJSON($normalized_criteria);
		$json = $normalized_criteria;
		// allow the clients to send custom fields that will be preserved
		if (!empty($search_structure['custom']))
		{
			$json['custom'] = $search_structure['custom'];
		}

		return $criteria;
	}

	private function computeDateLine($date, $round_to_eod = false)
	{
		$dateline = false;
		$timeNow = vB::getRequest()->getTimeNow();
		if (is_numeric($date))
		{
			if($date >= 100000000)//unix timestamp
			{
				$dateline = $date;
			}
			else
			{
				$dateline = $timeNow - ($date * 86400); //24 x 60 x 60 = 1 day
			}
		}
		elseif (is_string($date))
		{
			switch ($date){
				case self::FILTER_LASTDAY :
					$dateline = $timeNow - 86400; //24 x 60 x 60 = 1 day
				break;
				case self::FILTER_LASTWEEK :
					$dateline = $timeNow - 604800; //7 x 24 x 60 x 60 = 7 days
				break;
				case self::FILTER_LASTMONTH :
					$dateline = strtotime('-1 month', $timeNow);
				break;
				case self::FILTER_LASTYEAR :
					$dateline = strtotime('-1 year', $timeNow);
				break;
				default:
					if ($parseddate = strtotime($date))
					{
						if ($round_to_eod)
						{
							$h = date('G', $parseddate);
							$m = intval(date('i', $parseddate));
							$s = intval(date('s', $parseddate));
							if (empty($h) AND empty($m) AND empty($s))
							{
								$parseddate += 86399; // end of the day
							}
						}
						$dateline = $parseddate;
					}
				break;
			}
		}
		return $dateline;
	}

	public static function is_index_word($word, $isLower = false)
	{
		$badwords = self::get_all_bad_words();
		$goodwords = self::get_good_words();

		if (!$isLower)
		{
			$word = vB_String::vBStrToLower($word);
		}
		// is the word in the goodwords array?
		if (in_array($word, $goodwords))
		{
			return 1;
		}
		else
		{
			// is the word outside the min/max char lengths for indexing?
			$wordlength = vB_String::vbStrlen($word);
			$options = vB::getDatastore()->get_value('options');
			if ($wordlength < $options['minsearchlength'] OR $wordlength > $options['maxsearchlength'])
			{
				return 0;
			}
			// is the word a common/bad word?
			else if (in_array($word, $badwords))
			{
				return false;
			}
			// word is good
			else
			{
				return 1;
			}
		}
	}

	public static function get_good_words()
	{
		if (!isset(self::$goodwords))
		{
			$options = vB::getDatastore()->get_value('options');
			$goodwords = trim($options['goodwords']);
			if (!empty($goodwords))
			{
				self::$goodwords = preg_split('#[ \r\n\t]+#s', strtolower($goodwords), -1, PREG_SPLIT_NO_EMPTY);
			}
			else
			{
				self::$goodwords = array();
			}
		}
		return self::$goodwords;
	}

	public static function get_all_bad_words()
	{
		if (!isset(self::$allbadwords))
		{
			$options = vB::getDatastore()->get_value('options');
			self::$allbadwords = array_merge(self::get_bad_words(), preg_split('/\s+/s', $options['badwords'], -1, PREG_SPLIT_NO_EMPTY));
		}
		return self::$allbadwords;
	}

	public static function get_bad_words()
	{
		if (!isset(self::$badwords))
		{
			$badwords = array(
				'&amp',
				'&quot',
				'a',
				'able',
				'about',
				'above',
				'according',
				'accordingly',
				'across',
				'actually',
				'after',
				'afterwards',
				'again',
				'against',
				'aint',
				'all',
				'allow',
				'allows',
				'almost',
				'alone',
				'along',
				'already',
				'also',
				'although',
				'always',
				'am',
				'among',
				'amongst',
				'an',
				'and',
				'another',
				'any',
				'anybody',
				'anyhow',
				'anyone',
				'anything',
				'anyway',
				'anyways',
				'anywhere',
				'apart',
				'appear',
				'appreciate',
				'appropriate',
				'are',
				'arent',
				'around',
				'as',
				'aside',
				'ask',
				'asking',
				'associated',
				'at',
				'available',
				'away',
				'awfully',
				'b',
				'be',
				'became',
				'because',
				'become',
				'becomes',
				'becoming',
				'been',
				'before',
				'beforehand',
				'behind',
				'being',
				'believe',
				'below',
				'beside',
				'besides',
				'best',
				'better',
				'between',
				'beyond',
				'both',
				'brief',
				'but',
				'by',
				'c',
				'came',
				'can',
				'cannot',
				'cant',
				'cause',
				'causes',
				'certain',
				'certainly',
				'changes',
				'clearly',
				'cmon',
				'co',
				'com',
				'come',
				'comes',
				'concerning',
				'consequently',
				'consider',
				'considering',
				'contain',
				'containing',
				'contains',
				'corresponding',
				'could',
				'couldnt',
				'course',
				'cs',
				'currently',
				'd',
				'definitely',
				'described',
				'despite',
				'did',
				'didnt',
				'different',
				'do',
				'does',
				'doesnt',
				'doing',
				'done',
				'dont',
				'down',
				'downwards',
				'during',
				'e',
				'each',
				'edu',
				'eg',
				'eight',
				'either',
				'else',
				'elsewhere',
				'enough',
				'entirely',
				'especially',
				'et',
				'etc',
				'even',
				'ever',
				'every',
				'everybody',
				'everyone',
				'everything',
				'everywhere',
				'ex',
				'exactly',
				'example',
				'except',
				'f',
				'far',
				'few',
				'fifth',
				'first',
				'five',
				'followed',
				'following',
				'follows',
				'for',
				'former',
				'formerly',
				'forth',
				'four',
				'from',
				'further',
				'furthermore',
				'g',
				'get',
				'gets',
				'getting',
				'given',
				'gives',
				'go',
				'goes',
				'going',
				'gone',
				'got',
				'gotten',
				'greetings',
				'h',
				'had',
				'hadnt',
				'happens',
				'hardly',
				'has',
				'hasnt',
				'have',
				'havent',
				'having',
				'he',
				'hello',
				'help',
				'hence',
				'her',
				'here',
				'heres',
				'hereafter',
				'hereby',
				'herein',
				'hereupon',
				'hers',
				'herself',
				'hes',
				'hi',
				'him',
				'himself',
				'his',
				'hither',
				'hopefully',
				'how',
				'howbeit',
				'however',
				'i',
				'id',
				'ie',
				'if',
				'ignored',
				'ill',
				'im',
				'immediate',
				'in',
				'inasmuch',
				'inc',
				'indeed',
				'indicate',
				'indicated',
				'indicates',
				'inner',
				'insofar',
				'instead',
				'into',
				'inward',
				'is',
				'isnt',
				'ist',
				'it',
				'itd',
				'itll',
				'its',
				'itself',
				'ive',
				'j',
				'just',
				'k',
				'keep',
				'keeps',
				'kept',
				'know',
				'knows',
				'known',
				'l',
				'last',
				'lately',
				'later',
				'latter',
				'latterly',
				'least',
				'less',
				'lest',
				'let',
				'lets',
				'like',
				'liked',
				'likely',
				'little',
				'look',
				'looking',
				'looks',
				'ltd',
				'm',
				'mainly',
				'many',
				'may',
				'maybe',
				'me',
				'mean',
				'meanwhile',
				'merely',
				'might',
				'more',
				'moreover',
				'most',
				'mostly',
				'much',
				'must',
				'my',
				'myself',
				'n',
				'name',
				'namely',
				'nd',
				'near',
				'nearly',
				'necessary',
				'need',
				'needs',
				'neither',
				'never',
				'nevertheless',
				'new',
				'next',
				'nine',
				'no',
				'nobody',
				'non',
				'none',
				'noone',
				'nor',
				'normally',
				'not',
				'nothing',
				'novel',
				'now',
				'nowhere',
				'o',
				'obviously',
				'of',
				'off',
				'often',
				'oh',
				'ok',
				'okay',
				'old',
				'on',
				'once',
				'one',
				'ones',
				'only',
				'onto',
				'or',
				'originally',
				'other',
				'others',
				'otherwise',
				'ought',
				'our',
				'ours',
				'ourselves',
				'out',
				'outside',
				'over',
				'overall',
				'own',
				'p',
				'particular',
				'particularly',
				'per',
				'perhaps',
				'placed',
				'please',
				'plus',
				'possible',
				'posted',
				'presumably',
				'probably',
				'provides',
				'q',
				'que',
				'quite',
				'quote',
				'qv',
				'r',
				'rather',
				'rd',
				're',
				'really',
				'reasonably',
				'regarding',
				'regardless',
				'regards',
				'relatively',
				'respectively',
				'right',
				's',
				'said',
				'same',
				'saw',
				'say',
				'saying',
				'says',
				'second',
				'secondly',
				'see',
				'seeing',
				'seem',
				'seemed',
				'seeming',
				'seems',
				'seen',
				'self',
				'selves',
				'sensible',
				'sent',
				'seriously',
				'seven',
				'several',
				'shall',
				'she',
				'should',
				'shouldnt',
				'since',
				'six',
				'so',
				'some',
				'somebody',
				'somehow',
				'someone',
				'something',
				'sometime',
				'sometimes',
				'somewhat',
				'somewhere',
				'soon',
				'sorry',
				'specified',
				'specify',
				'specifying',
				'still',
				'sub',
				'such',
				'sup',
				'sure',
				't',
				'take',
				'taken',
				'tell',
				'tends',
				'th',
				'than',
				'thank',
				'thanks',
				'thanx',
				'that',
				'thats',
				'the',
				'their',
				'theirs',
				'them',
				'themselves',
				'then',
				'thence',
				'there',
				'theres',
				'thereafter',
				'thereby',
				'therefore',
				'therein',
				'theres',
				'thereupon',
				'these',
				'they',
				'theyd',
				'theyll',
				'theyre',
				'theyve',
				'think',
				'third',
				'this',
				'thorough',
				'thoroughly',
				'those',
				'though',
				'three',
				'through',
				'throughout',
				'thru',
				'thus',
				'to',
				'together',
				'too',
				'took',
				'toward',
				'towards',
				'tried',
				'tries',
				'truly',
				'try',
				'trying',
				'ts',
				'twice',
				'two',
				'u',
				'un',
				'under',
				'unfortunately',
				'unless',
				'unlikely',
				'until',
				'unto',
				'up',
				'upon',
				'us',
				'use',
				'used',
				'useful',
				'uses',
				'using',
				'usually',
				'v',
				'value',
				'various',
				'very',
				'via',
				'viz',
				'vs',
				'w',
				'want',
				'wants',
				'was',
				'wasnt',
				'way',
				'we',
				'wed',
				'welcome',
				'well',
				'went',
				'were',
				'weve',
				'werent',
				'what',
				'whats',
				'whatever',
				'when',
				'whence',
				'whenever',
				'where',
				'whereafter',
				'whereas',
				'whereby',
				'wherein',
				'whereupon',
				'wherever',
				'wheres',
				'whether',
				'which',
				'while',
				'whither',
				'who',
				'whoever',
				'whole',
				'whom',
				'whos',
				'whose',
				'why',
				'will',
				'willing',
				'wish',
				'with',
				'within',
				'without',
				'wonder',
				'wont',
				'would',
				'would',
				'wouldnt',
				'x',
				'y',
				'yes',
				'yet',
				'you',
				'youd',
				'youll',
				'your',
				'youre',
				'yours',
				'yourself',
				'yourselves',
				'youve',
				'z',
				'zero'
			);
			// Legacy Hook 'search_stopwords' Removed //
			self::$badwords = $badwords;
		}
		return self::$badwords;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104026 $
|| #######################################################################
\*=========================================================================*/
