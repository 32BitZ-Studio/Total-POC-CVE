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
 * vB_Library_Node
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Node extends vB_Library
{
	protected $nodeFields = array();
	protected $contentLibs = array();

	protected $albumChannel = false;
	protected $VMChannel = false;
	protected $PMChannel = false;
	protected $SGChannel = false;
	protected $ReportChannel = false;
	protected $forumChannel = false;
	protected $infractionChannel = false;
	protected $articleChannel = false;

	private $channelTypeId;

	//cache so we only load it once.  Do not use directly use getExcludedLastContentTypes
	private $excludedLastContentTypes;

	private $options = array(
		'allow_post'             => vB_Api_Node::OPTION_ALLOW_POST,
		'moderate_comments'      => vB_Api_Node::OPTION_MODERATE_COMMENTS,
		'approve_membership'     => vB_Api_Node::OPTION_AUTOAPPROVE_MEMBERSHIP,
		'invite_only'            => vB_Api_Node::OPTION_NODE_INVITEONLY,
		'autoparselinks'         => vB_Api_Node::OPTION_NODE_PARSELINKS,
		'disablesmilies'         => vB_Api_Node::OPTION_NODE_DISABLE_SMILIES,
		'approve_subscription'   => vB_Api_Node::OPTION_AUTOAPPROVE_SUBSCRIPTION,
		'moderate_topics'        => vB_Api_Node::OPTION_MODERATE_TOPICS,
		'auto_subscribe_on_join' => vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN,
		'disable_bbcode'         => vB_Api_Node::OPTION_NODE_DISABLE_BBCODE,
		'hide_title'             => vB_Api_Node::OPTION_NODE_HIDE_TITLE,
		'hide_author'            => vB_Api_Node::OPTION_NODE_HIDE_AUTHOR,
		'hide_publishdate'       => vB_Api_Node::OPTION_NODE_HIDE_PUBLISHDATE,
		'display_fullincategory' => vB_Api_Node::OPTION_NODE_DISPLAY_FULL_IN_CATEGORY,
		'display_pageviews'      => vB_Api_Node::OPTION_NODE_DISPLAY_PAGEVIEWS,
		'hide_comment_count'     => vB_Api_Node::OPTION_NODE_HIDE_COMMENT_COUNT,
	);

	protected function __construct()
	{
		$this->pmContenttypeid = vB_Types::instance()->getContentTypeId('vBForum_PrivateMessage');
		$structure = vB::getDbAssertor()->fetchTableStructure('vBForum:node');
		$this->nodeFields = $structure['structure'];
		$this->channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
	}

	/**
	 * Return the list of fields in the node table
	 *
	 */
	public function getNodeFields()
	{
		return $this->nodeFields;
	}

	/**
	 * gets the node option bitfields
	 *
	 * 	@return	array 	associative array of bitfield name => value
	 */
	public function getOptions()
	{
		return $this->options;
	}

	/**
	 * This clear cache for all children of a node list
	 *
	 * 	@param	mixed	array of nodes
	 */
	public function clearChildCache($nodeids)
	{
		$childrenArray = $this->fetchClosurechildren($nodeids);
		$events = array();
		foreach ($childrenArray AS $children)
		{
			foreach ($children AS $child)
			{
				$events[] = 'nodeChg_' . $child['child'];
			}
		}
		vB_Cache::allCacheEvent($events);
	}


	/**
	 * opens a node for posting
	 *
	 * 	@param	mixed	integer or array of integers
	 *
	 *	@return	mixed	Either array 'errors' => error string or array of id's.
	 **/
	public function openNode($nodeids)
	{
		$db = vB::getDbAssertor();
		$loginfo = array();
		$db->assertQuery('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'open' => 1,
			'showopen' => 1,
			'nodeid' => $nodeids
		));

		foreach ($nodeids as $nodeid)
		{
			$node = $this->getNode($nodeid);
			$result = $db->assertQuery('vBForum:openNode', array('nodeid' => $nodeid));

			$loginfo[] = array(
				'nodeid'		=> $node['nodeid'],
				'nodetitle'		=> $node['title'],
				'nodeusername'	=> $node['authorname'],
				'nodeuserid'	=> $node['userid']
			);

			if (!empty($result['errors']))
			{
				break;
			}
		}

		$this->clearCacheEvents($nodeids);
		$this->clearChildCache($nodeids);

		if (!empty($result['errors']))
		{
			return array('errors' => $result['errors']);
		}

		vB_Library_Admin::logModeratorAction($loginfo, 'node_opened_by_x');

		return $nodeids;
	}

	/**
	 * Closes a node for posting. Closed nodes can still be viewed but nobody can reply to one.
	 *
	 * 	@param	mixed	integer or array of integers
	 *
	 *	@return	mixed	Either array 'errors' => error string or array of id's.
	 */
	public function closeNode($nodeids)
	{
		$db = vB::getDbAssertor();
		$loginfo = array();
		$db->assertQuery('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'open' => 0,
			'showopen' => 0,
			'nodeid' => $nodeids
		));

		foreach ($nodeids as $nodeid)
		{
			$node = $this->getNode($nodeid);
			$result = $db->assertQuery('vBForum:closeNode', array('nodeid' => $nodeid));

			$loginfo[] = array(
				'nodeid'		=> $node['nodeid'],
				'nodetitle'		=> $node['title'],
				'nodeusername'	=> $node['authorname'],
				'nodeuserid'	=> $node['userid']
			);

			if (!empty($result['errors']))
			{
				break;
			}
		}

		$this->clearCacheEvents($nodeids);
		$this->clearChildCache($nodeids);

		if (!empty($result['errors']))
		{
			return array('errors' => $result['errors']);
		}

		vB_Library_Admin::logModeratorAction($loginfo, 'node_closed_by_x');

		return $nodeids;
	}

	/**
	 * Adds a new node. The record must already exist as an individual content item.
	 *
	 *	@param	integer	The id in the primary table
	 *	@param	integer	The content type id of the record to be added
	 *	@param	mixed		Array of field => value pairs which define the record.
	 *
	 * 	@return	boolean
	 */
	public function addNode($contenttypeid, $data)
	{
		$params = array(vB_dB_Query::TYPE_KEY=> vB_dB_Query::QUERY_METHOD, 'contenttypeid' => $contenttypeid);

		foreach ($this->nodeFields as $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$params[$fieldname] = $data[$fieldname];
			}
		}

		$result = vB::getDbAssertor()->assertQuery('vBForum:addNode', $params);

		//If this is not a channel, we should set the lastcontentid to this nodeid,
		// and lastcontent to now.
		if (($data['contenttypeid'] <> vB_Types::instance()->getContentTypeID('vBForum_Channel')) AND empty($data['lastcontentid']))
		{
			vB::getDbAssertor()->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY=> vB_dB_Query::QUERY_UPDATE,
				'nodeid' => $result, 'lastcontent' => vB::getRequest()->getTimeNow(), 'lastcontentid' => $result));
		}

		if (!empty($result))
		{
			vB_Library::instance('search')->index($result);

		}

		return($result);
	}

	/**
	 * Updates the ancestors counts and last data from a given node being deleted.
	 * Counts and last data are info from the node table records:
	 * totalcount, totalunpubcount, textcount, textunpubcount
	 * lastcontentid, lastcontent, lastauthor, lastauthorid.
	 * Is critical that the ancestors are in DESC order so we can properly update.
	 *
	 * @param	array		The node being deleted information.
	 * @param	array		Information from the node's ancestors needed to update last (nodeid, contenttypeid needed).
	 * @param	bool		Flag indicating if we are soft/hard-deleting
	 *
	 */
	public function resetAncestorCounts($existing, $ancestorsData, $hard)
	{
		if (empty($ancestorsData))
		{
			//This can happen with a defective node while it is being deleted.
			return;
		}

		// now update last content and counts for parents
		$ancestorsId = array();
		$toUpdate = array();
		foreach ($ancestorsData AS $ancestor)
		{
			$ancestorsId[] = $ancestor['nodeid'];
			$toUpdate[$ancestor['nodeid']] = array('nodeid' => $ancestor['nodeid'], 'contenttypeid' => $ancestor['contenttypeid']);
		}

		// make sure we have unique ancestors and they're in the right order
		krsort($toUpdate);
		$ancestorsId = array_unique($ancestorsId);

		// reset last content for all parents that have the deleted node
		if ($existing['showpublished'] AND $hard)
		{
			$totalChange = -1 - $existing['totalcount'];
			$totalUnpubChange = 0;
			$textChange = -1;
			$textUnpubChange = 0;
		}
		else if (!$existing['showpublished'] AND $hard)
		{
			$totalChange = 0;
			$totalUnpubChange = -1 - $existing['totalunpubcount'];
			$textChange = 0;
			$textUnpubChange = -1;
		}
		else if ($existing['showpublished'] AND !$hard)
		{
			$totalChange = -1 - $existing['totalcount'];
			$totalUnpubChange = 1 + $existing['totalcount'];
			$textChange = -1;
			$textUnpubChange = 1;
		}
		else
		{
			$totalChange = 0;
			$totalUnpubChange = 0;
			$textChange = 0;
			$textUnpubChange = 0;

		}
		//Update total counts.
		vB::getDbAssertor()->assertQuery('vBForum:UpdateAncestorCount',
			array(
				'totalChange' => $totalChange,
				'totalUnpubChange' => $totalUnpubChange,
				'nodeid' => $ancestorsId)
		);
		//text counts for parent only.
		vB::getDbAssertor()->assertQuery('vBForum:UpdateParentTextCount',
			array(
				'textChange' => $textChange,
				'textUnpubChange' => $textUnpubChange,
				'nodeid' => $existing['parentid'])
		);

		//And the "last" data. We have to work bottom-to-top.
		$searchLIB = vB_Library::instance('search');
		foreach ($toUpdate AS $ancestor)
		{
			if ($ancestor['contenttypeid'] == $this->channelTypeId)
			{
				$this->fixNodeLast($ancestor['nodeid']);
			}
			else
			{
				vB::getDbAssertor()->assertQuery('vBForum:updateLastData', array('parentid' => $ancestor['nodeid'], 'timenow' => vB::getRequest()->getTimeNow()));
			}

			vB_Cache::allCacheEvent("nodeChg_" . $ancestor['nodeid']);
			$searchLIB->attributeChanged($ancestor['nodeid']);
		}

	}


	/**
	 * Permanently/Temporarily deletes a set of nodes
	 *
	 * @param	array	The nodeids of the records to be deleted
	 * @param	bool	hard/soft delete
	 * @param	string	the reason for soft delete (not used for hard delete)
	 * @param	bool	Log the deletes in moderator log
	 * @param	bool	Report node content to spam service
	 *
	 * @return	array nodeids that were deleted
	 */
	public function deleteNodes($deleteNodeIds, $hard, $reason, $modlog = true, $reportspam = false)
	{
		$loginfo = array();
		$starters = array();
		$channels = array();
		$needRebuild = false;

		$db = vB::getDbAssertor();

		if (!is_array($deleteNodeIds))
		{
			$deleteNodeIds = array($deleteNodeIds);
		}

		$deleteNodeIds = array_unique($deleteNodeIds);

		$vboptions = vB::getDatastore()->getValue('options');
		if ((!$vboptions['vb_antispam_type'] OR !$vboptions['vb_antispam_key']) AND !$vboptions['vb_antispam_sfs_key'])
		{
			$reportspam = false;
		}

		//if we are doing a hard delete we need to first delete the type-specific data.
		if ($reportspam)
		{
			$nodes = $this->getContentforNodes($deleteNodeIds);
			$akismet = vB_Akismet::instance();
			$stopForumSpam = vB_StopForumSpam::instance();
			foreach ($nodes AS $node)
			{
				if ($node['content']['rawtext'])
				{
					$text = vB_String::stripBbcode($node['content']['rawtext'], true);
					$akismet->markAsSpam(
						array(
							'comment_type'    => 'comment',
							'comment_author'  => $node['content']['authorname'],
							'comment_content' => $text,
							'user_ip'         => $node['content']['ipaddress']
					));

					if ($vboptions['vb_antispam_sfs_key'])
					{
						$userinfo = vB_User::fetchUserinfo($node['content']['userid']);	// must have email address
						$stopForumSpam->markAsSpam($userinfo['username'], $node['content']['ipaddress'], $text, $userinfo['email']);
					}
				}
			}
		}
		else
		{
			$nodes = $this->getNodes($deleteNodeIds, false);
		}

		if ($hard)
		{
			$infractionTypeid = vB_Types::instance()->getContentTypeId('vBForum_Infraction');

			foreach ($nodes AS $node)
			{
				if ($node['contenttypeid'] == $infractionTypeid)
				{
					throw new vB_Exception_Api('cannot_delete_infraction_nodes');
				}

				//see if we need a rebuild
				if ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'))
				{
					$needRebuild = true;
				}

				try
				{
					$channels[] = $this->getChannelId($node);
					$starters[] = $node['starter'];

					// content delete method handle counts updating
					vB_Api_Content::getContentApi($node['contenttypeid'])->delete($node['nodeid']);
				}
				//Note that if one of the nodes to be deleted is a child of a node we've already deleted, we'll get an exception here.
				catch(vB_Exception_Api $e)
				{
					//nothing to do.

					// Actually, it's possible that the content API will throw a no_permission exception if it fails the
					// validate() check for "action delete." In that case, we're just silently continuing, which could
					// result in a node not being deleted with 0 indication that something went wrong.
					// We should think of a better way to output this situation to the moderator.

					// If the node did not get deleted. Possibly due to lack of permission to delete.
					// 1. check if node still exists (which means there was actually a problem deleting, not that it was a non-existent node)
					// 2. if "yes", remove the node from $deleteNodeIds so the return value doesn't include it and so no further processing happens
					// 3. skip to the next iteration of this loop, so this nodeid is not included in the mod log.
					$check = $db->getRows('vBForum:node', array('nodeid' => $node['nodeid']));
					if (count($check) == 1)
					{
						// $deleteNodeIds can be an array or a single nodeid
						if (is_array($deleteNodeIds))
						{
							$key = array_search($node['nodeid'], (array)$deleteNodeIds, true);
							if ($key !== false)
							{
								unset($deleteNodeIds[$key]);
							}
						}
						else if ($deleteNodeIds == $node['nodeid'])
						{
							$deleteNodeIds = '';
						}

						continue;
					}
				}

				// Note: Do not decrement user post count here. That is done
				// in the content library for hard-deletes.

				if ($modlog)
				{
					$loginfo[] = array(
						'nodeid'       => $node['nodeid'],
						'nodetitle'    => $node['title'],
						'nodeusername' => $node['authorname'],
						'nodeuserid'   => $node['userid'],
					);
				}
			}

			vB_Library_Admin::logModeratorAction($loginfo, 'node_hard_deleted_by_x');

			//the content library delete *should* handle the cache clearing -- but it's
			//not 100% clear it does so until we can validate the tests its safer to keep
			//doing it here.
			$starters = array_unique($starters);
			// reset last content for all parents that have the deleted nodes
			$events = array();

			foreach ($channels AS $channel)
			{
				$events[] = "nodeChg_" . $channel;
			}

			foreach ($starters AS $starter)
			{
				$events[] = "nodeChg_" . $starter;
			}

			foreach ($deleteNodeIds AS $nodeid)
			{
				$events[] = "nodeChg_" . $nodeid;
			}
			$events = array_unique($events);
			vB_Cache::allCacheEvent($events);
		}
		else
		{
			$fields = array (
				'unpublishdate' => vB::getRequest()->getTimeNow(),
				'deletereason' => $reason,
				'deleteuserid' => vB::getCurrentSession()->get('userid'),
				'approved'     => 1,
				'showapproved' => 1,
			);
			$result = $db->update('vBForum:node', $fields, array('nodeid' => $deleteNodeIds));

			$topLevel = array_flip($this->removeDescendants($db, $deleteNodeIds));

			foreach ($nodes AS $origNode)
			{
				//see if we need a rebuild
				if ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'))
				{
					$needRebuild = true;
				}

				//we only want to runt this once on a given subtree.
				if (isset($topLevel[$origNode['nodeid']]))
				{
					$nodeUpdates = $this->unpublishChildren($origNode['nodeid']);
					$this->updateChangedNodeParentCounts($origNode, $nodeUpdates);
				}

				// Update user post count (soft delete)
				vB_Library_Content::getContentLib($origNode['contenttypeid'])->decrementUserPostCount($origNode, 'unpublish');

				if ($modlog)
				{
					$loginfo[] = array(
						'nodeid'		=> $origNode['nodeid'],
						'nodetitle'		=> $origNode['title'],
						'nodeusername'	=> $origNode['authorname'],
						'nodeuserid'	=> $origNode['userid']
					);
				}

				if (!empty($node['setfor']))
				{
					vB_Cache::allCacheEvent('fUserContentChg_' . $origNode['setfor']);
				}
			}

			vB_Library_Admin::logModeratorAction($loginfo, 'node_soft_deleted_by_x');

			$this->clearCacheEvents($deleteNodeIds);
			$this->clearChildCache($deleteNodeIds);
		}

		vB_Library::instance('search')->purgeCacheForCurrentUser();

		if ($needRebuild)
		{
			vB::getUserContext()->rebuildGroupAccess();
			vB_Channel::rebuildChannelTypes();
		}

		return $deleteNodeIds;
	}

	/**
	 * lists the nodes that should be displayed on a specific page.
	 *	@param	integer	The node id of the parent where we are listing
	 *	@param	integer	page number to return
	 *	@param	integer	items per page
	 *	@param	integer	depth- 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 *	@param	mixed	if desired, will only return specific content types.
	 *	@param	mixed	recognizes 'sort', 'exclude', 'userid', 'featured'
	 *	@param	mixed	array of filters (date - last day, last week, last month, all time or/and following - members, channels or both), showchannel (include channel title)
	 *	@param	bool	Include joinable content
	 *
	 * 	@return	mixed	array of id's
	 */
	public function listNodes($parentid, $page, $perpage, $depth, $contenttypeid, $options, $withJoinableContent = false)
	{
		//Let's see if we have a cached record.
		$options['parentid'] = $parentid;
		$options['depth'] = $depth;

		if ($contenttypeid)
		{
			$options['contenttypeid'] = $contenttypeid;
		}

		$searchApi = vB_Api::instanceInternal('search');

		//now see if we have a cached value.
		$hashkey = 'SrchResults' . vB::getUserContext()->fetchUserId() . crc32(serialize($options)) ;

		if (($srchResultId = vB_Cache::instance()->read($hashkey)))
		{
			$srchResults = $searchApi->getMoreNodes($srchResultId, $perpage, $page);
			if (!empty($srchResults['nodeIds']))
			{
				$resultNodes = $this->getNodes($srchResults['nodeIds'], $withJoinableContent);

				$result = array();
				if (is_array($resultNodes) AND !isset($resultNodes['errors']))
				{
					foreach ($srchResults['nodeIds'] AS $nodeid)
					{
						if (empty($resultNodes[$nodeid]))
						{
							continue;
						}
						$result[$nodeid] = $resultNodes[$nodeid];
					}
				}

				return $result;
			}
			else
			{
				return array();
			}
		}

		$results = $this->listNodesInternal($parentid, $page, $perpage, $depth, $contenttypeid, $options, $withJoinableContent);

		if (!empty($results['nodeIds']))
		{
			$nodes = $this->getNodes($results['nodeIds'], $withJoinableContent);

			foreach ($results['nodeIds'] as $nodeid)
			{
				if (empty($nodes[$nodeid]))
				{
					unset($results['nodeIds'][$nodeid]);
				}
				$results['nodeIds'][$nodeid] = $nodes[$nodeid];
			}

			return $results['nodeIds'];
		}
		else
		{
			return array();
		}
	}

	public function listNodesInternal($parentid, $page, $perpage, $depth, $contenttypeid, $options, $withJoinableContent = false)
	{
		//Let's see if we have a cached record.
		$options['parentid'] = $parentid;
		$options['depth'] = $depth;

		if ($contenttypeid)
		{
			$options['contenttypeid'] = $contenttypeid;
		}

		$searchApi = vB_Api::instanceInternal('search');

		//now see if we have a cached value.
		$hashkey = 'SrchResults' . vB::getUserContext()->fetchUserId() . crc32(serialize($options)) ;

		if (($srchResultId = vB_Cache::instance()->read($hashkey)))
		{
			$srchResults = $searchApi->getMoreNodes($srchResultId, $perpage, $page);
			return $srchResults;
		}

		//We need to do a new search. We need a criteria object.
		$criteria = array();
		//Let's set the values.

		//contenttype
		if (intval($contenttypeid) > 0)
		{
			$criteria['contenttypeid'] = $contenttypeid;
		}

		//channel
		if ($parentid)
		{
			$criteria['channel'] = $parentid;
		}
		else if (!empty($options['channel']))
		{
			$criteria['channel'] = $parentid;
		}

		//exclude
		if (!empty($options['exclude']))
		{
			$criteria['exclude'] = $options['exclude'];
		}

		//depth
		if ($depth)
		{
			if (!empty($options['depth_exact']))
			{
				$criteria['depth_exact'] = 1;
			}
			$criteria['depth'] = $depth;
		}
		else if (!empty($options['channel']))
		{
			$criteria['channel'] = $parentid;
		}

		//featured
		if (!empty($options['featured']) AND (bool)$options['featured'])
		{
			$criteria['featured'] = 1;
		}

		//time filter
		if (!empty($options[vB_Api_Node::FILTER_TIME]))
		{
			//only allow a subset of the values that the search will accept for a from date. If it not one of
			//values we accept assume "all values" aka no date filter.
			switch ($options[vB_Api_Node::FILTER_TIME])
			{
				case vB_Api_Search::FILTER_LASTDAY:
				case vB_Api_Search::FILTER_LASTWEEK:
				case vB_Api_Search::FILTER_LASTMONTH:
				case vB_Api_Search::FILTER_LASTYEAR:
					$criteria['date'] = array('from' => $options[vB_Api_Node::FILTER_TIME]);
					break;
			}
		}

		if (isset($options['include_starter']))
		{
			$criteria['include_starter'] = $options['include_starter'];
			/*
				Previously, the "include_starter" implied an "isstarter DESC" sort.
				The sorting was moved to its own sorting option, so now if we want
				the same effect, we need to prepend $options['sort'] with an
				array("isstarter" => "DESC") array.
				The proper way to sort by starters first would be to have the
				caller specify the isstarter sorting, but given that the context of
				this function seems to be "find me all nodes under this parentid",
				perhaps assuming the isstarter sorting here is the correct (or
				more useful) one.
				It seems like the only calls to this function with specified
				"include_starter" is from unit tests, so this may not matter a
				whole lot. As such, I'm going to skip setting the isstarter sorting
				here, but we may need to revisit later if this causes regressions.
			 */
		}

		if (isset($options['includeProtected']) AND !($options['includeProtected']))
		{
			$criteria['ignore_protected'] = 1;
		}

		$userdata = vB::getUserContext()->getReadChannels();

		$exclude = $userdata['cantRead'];

		if (isset($options[vB_Api_Search::FILTER_FOLLOW]))
		{
			if (empty($options['followerid']))
			{
				throw new vB_Exception_Api('invalid_request');
			}
			switch($options[vB_Api_Search::FILTER_FOLLOW])
			{
				case vB_Api_Search::FILTER_FOLLOWING_USERS:
					$criteria[vB_Api_Search::FILTER_FOLLOW] = array(vB_Api_Search::FILTER_FOLLOWING_USERS => $options['followerid']);
					break;
				case vB_Api_Search::FILTER_FOLLOWING_CHANNEL:
					$criteria[vB_Api_Search::FILTER_FOLLOW] = array(vB_Api_Search::FILTER_FOLLOWING_CHANNEL => $options['followerid']);
					break;
				case vB_Api_Search::FILTER_FOLLOWING_CONTENT:
					$criteria[vB_Api_Search::FILTER_FOLLOW] = array(vB_Api_Search::FILTER_FOLLOWING_CONTENT => $options['followerid']);
					break;
				case vB_Api_Search::FILTER_FOLLOWING_BOTH:
					$criteria[vB_Api_Search::FILTER_FOLLOW] = array(vB_Api_Search::FILTER_FOLLOWING_BOTH => $options['followerid']);
					break;
				default:
					throw new vB_Exception_Api('invalid_request');

			}
			$criteria['include_starter'] = 1;
			// See note above for more details, but NOT setting a isstarter sorting here because
			// I don't think that's correct for this case.
		}

		//userid
		if (!empty($options['userid']))
		{
			$criteria['authorid'] = $options['userid'];
		}

		//my_channels
		if (!empty($options['my_channels']) AND in_array($options['my_channels'], array('group', 'blog'), true))
		{
			$criteria['my_channels'] = array('type' => $options['my_channels']);
		}

		//sort order
		if (!empty($options['sort']))
		{
			$criteria['sort'] = $options['sort'];
		}

		if (!empty($options['nolimit']))
		{
			$criteria['nolimit'] = $options['nolimit'];
		}

		// we don't want to store a cached value into another cache
		$criteria['ignore_cache'] = true;
		$results = $searchApi->getInitialNodes($criteria, $perpage, $page);

		//cache the result id.
		vB_Cache::instance()->write($hashkey, $results['resultId'], 5, 'nodeChg_' . $parentid);

		return $results;
	}


	/**
	 * Gets one node.
	 *
	 * @param  int   The Node ID
	 *
	 * @return mixed Array of node records
	 */
	public function getNodeBare($nodeid)
	{
		if (empty($nodeid))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}
		$node = vB_Library_Content::fetchFromCache($nodeid, vB_Library_Content::CACHELEVEL_NODE);

		if ($node AND !empty($node['found']) AND !empty($node['found'][$nodeid]))
		{
			$node = $node['found'][$nodeid];
		}
		else
		{
			$node = vB::getDbAssertor()->getRow('vBForum:node', array('nodeid' => $nodeid));

			if (empty($node) OR !empty($node['errors']))
			{
				throw new vB_Exception_Api('invalid_node_id');
			}

			// censor textual node items
			vB_Library_Node::censorNode($node);

			vB_Library_Content::writeToCache(array($node), vB_Library_Content::CACHELEVEL_NODE);
		}

		return $node;
	}

	/**
	 * Censors the different text items that need censoring
	 *
	 * @param array (reference) The array of node information
	 */
	public static function censorNode(&$node)
	{
		$nodes = array();
		$nodes[] =& $node;
		vB_Library_Node::censorNodes($nodes);
	}

	/**
	 * Censors the different text items in each node that need censoring
	 *
	 * @param array (reference) The array of node information
	 */
	public static function censorNodes(&$nodes)
	{
		$items = array('title', 'htmltitle');

		foreach ($nodes as $key => $node)
		{
			foreach ($items AS $item)
			{
				if (!empty($node[$item]))
				{
					$nodes[$key][$item] = vB_String::fetchCensoredText($node[$item]);
				}
			}
		}
	}

	/**
	 * Gets one node.
	 * @param	integer The node id
	 * @param	boolean Whether to include list of parents
	 * @param	boolean Whether to include attachments
	 * @param	boolean	Include joinable content
	 *
	 * @return Array.  A node record, optionally including attachment and ancestry.
	 **/
	public function getNode($nodeid, $withParents = false, $withJoinableContent = false)
	{
		if ($withJoinableContent)
		{
			$node = $this->getNodeFullContent($nodeid);
			$node = reset($node);
		}
		else
		{
			$node = $this->getNodeBare($nodeid);
		}

		if ($withParents)
		{
			$node['parents'] = $this->getNodeParents($nodeid);
			$node['parents_reversed'] = array_reverse($node['parents']);
		}

		foreach ($this->options as $key => $bitmask)
		{
			$node[$key] = ($bitmask & $node['nodeoptions']) ? 1 : 0;
		}

		return $node;
	}

	/**
	 * get the ancestors of a node
	 * @param int $nodeid
	 * @return array
	 */
	public function getNodeParents($nodeid)
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$hashKey = "nodeParents_$nodeid";
		$parents = $cache->read($hashKey);
		if (empty($parents))
		{
			$parents = array();
			$ancestors = $this->fetchClosureParent($nodeid);

			foreach ($ancestors AS $closure)
			{
				$parents[$closure['depth']] = $closure['parent'];
			}
			$cache->write($hashKey, $parents, 1440, 'nodeChg_' . $nodeid);

		}

		return $parents;
	}

	/**
	 * Gets the node info for a list of nodes
	 *	@param	array of node ids
	 *	@param	bool	Include joinable content
	 *
	 * 	@return	mixed	array of node records
	 */
	public function getNodes($nodeList, $withJoinableContent = false)
	{
		static $cachedNodeList = array();

		if (empty($nodeList))
		{
			return array();
		}

		if (!is_array($nodeList))
		{
			$nodeList = array($nodeList);
		}
		//if we are passed options we can't precache.
		$cachedNodeList = array_unique(array_merge($cachedNodeList, $nodeList));
		vB_Library::instance('page')->registerPrecacheInfo('node', 'getNodes', $cachedNodeList);

		$cached = vB_Library_Content::fetchFromCache($nodeList, vB_Library_Content::CACHELEVEL_NODE);
		if (empty($cached['notfound']))
		{
			//We found everything, so we're done.
			return $cached['found'];
		}

		if ($withJoinableContent)
		{
			$indexed = vB::getDbAssertor()->getRows(
				'vBForum:fetchNodeWithContent', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
					'nodeid' => $cached['notfound']
				),
				false,
				'nodeid'
			);
		}
		else
		{
			$indexed = vB::getDbAssertor()->getRows(
				'vBForum:node',
				array('nodeid' => $cached['notfound']),
				false,
				'nodeid'
			);
		}

		vB_Library_Content::writeToCache($indexed, vB_Library_Content::CACHELEVEL_NODE);
		//now we need to merge and sort them.
		$merged = array();
		foreach ($nodeList AS $nodeid)
		{
			if (array_key_exists($nodeid, $cached['found']))
			{
				$merged[$nodeid] = $cached['found'][$nodeid];
			}
			else if (array_key_exists($nodeid, $indexed))
			{
				$merged[$nodeid] = $indexed[$nodeid];
			}
		}
		unset($cached, $indexed);
		return $merged;
	}

	/**
	 * Convert node path or id string to node id.
	 *
	 * @param string|int $nodestring Node String. If $nodestring is a string, it should be a route path to the node
	 * @return int Node ID
	 */
	public function assertNodeidStr($nodestring)
	{
		if (!is_numeric($nodestring))
		{
			// $to_parent is a string. So we think it's a path to the node.
			// We need to convert it back to nodeid.
			$route = vB_Api::instanceInternal('route')->getRoute($nodestring, '');
			if (!empty($route['arguments']['nodeid']))
			{
				$nodestring = $route['arguments']['nodeid'];
			}
			elseif (!empty($route['redirect']))
			{
				$route2 = vB_Api::instanceInternal('route')->getRoute(substr($route['redirect'], 1), '');
				if (!empty($route2['arguments']['nodeid']))
				{
					$nodestring = $route2['arguments']['nodeid'];
				}else if (!empty($route2['arguments']['contentid']))
				{
					$nodestring = $route2['arguments']['contentid'];
				}
			}

			unset($route, $route2);
		}
		else
		{
			$nodestring = intval($nodestring);
		}

		return $nodestring;
	}


	/**
	 * Sets the publishdate and (optionally) the unpublish date of a node
	 *	@param	integer	The node id
	 *	@param	integer	The timestamp for publish date
	 *	@param	integer	The timestamp for unpublish date if applicable
	 *
	 *	@return	boolean
	 */
	public function setPublishDate($nodeid, $datefrom, $dateto = null)
	{
		$data = array(vB_dB_Query::TYPE_KEY=> vB_dB_Query::QUERY_UPDATE,
			'nodeid' => $nodeid, 'publishdate' => $datefrom);

		if (intval($dateto))
		{
			$data['unpublishdate'] = $dateto;
		}
		else
		{
			$data['unpublishdate'] = 0;
		}
		$timeNow = vB::getRequest()->getTimeNow();

		if (($datefrom <= $timeNow) AND (!intval($dateto) OR ($dateto > $timeNow)))
		{
			$data['showpublished'] = 1;
		}
		else
		{
			$data['showpublished'] = 0;
		}
		//We need to use the content object to set this because there may be
		// type-specific data needed.

		$node = $this->getNode($nodeid);

		if (empty($this->contentLibs[$node['nodeid']]))
		{
			$this->contentLibs[$node['nodeid']] =
				vB_Library::instance('Content_' . vB_Types::instance()->getContentTypeClass($node['contenttypeid']));
		}

		$ret = $this->contentLibs[$node['nodeid']]->update($nodeid, $data);
		vB_Library::instance('search')->attributeChanged($nodeid);
		return $ret;
	}

	/**
	 * Sets the unpublish date
	 *	@param	integer	The node id
	 *	@param	integer	The timestamp for unpublish
	 *
	 *	@return	boolean
	 */
	public function setUnPublishDate($nodeid, $dateto = false)
	{
		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'nodeid' => $nodeid);

		if (intval($dateto))
		{
			$data['unpublishdate'] = $dateto;
		}
		else
		{
			$data['unpublishdate'] = vB::getRequest()->getTimeNow();
		}
		//We need to use the content object to set this because there may be
		// type-specific data needed.
		$node = $this->getNode($nodeid);
		if (empty($this->contentLibs[$node['nodeid']]))
		{
			$this->contentLibs[$node['nodeid']] =
				vB_Library::instance('Content_' . vB_Types::instance()->getContentTypeClass($node['contenttypeid']));
		}

		$ret = $this->contentLibs[$node['nodeid']]->update($nodeid, $data);
		vB_Library::instance('search')->attributeChanged($nodeid);
		return $ret;
	}

	/**
	 * sets a node to not published
	 *	@param	integer	The node id
	 *
	 *	@return	boolean
	 */
	public function setUnPublished($nodeid)
	{
		if (!intval($nodeid))
		{
			throw new Exception('invalid_node_id');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
		{
			throw new Exception('no_publish_permissions');
		}

		$node = $this->getNode($nodeid);

		if (empty($this->contentLibs[$node['nodeid']]))
		{
			$this->contentLibs[$node['nodeid']] =
				vB_Library::instance('Content_' . vB_Types::instance()->getContentTypeClass($node['contenttypeid']));
		}

		$data = array('publishdate' => 0, 'showpublished' => 0);

		$this->clearCacheEvents(array_unique(array($nodeid, $node['parentid'], $node['starter'])));
		$ret = $this->contentLibs[$node['nodeid']]->update($nodeid, $data);
		vB_Library::instance('search')->attributeChanged($nodeid);
		return $ret;
	}

	/**
	 * sets a list of nodes to be featured
	 *	@param	array	The node ids
	 *	@param	boot	set or unset the featured flag
	 *
	 *	@return	array nodeids that have permission to be featured
	 */
	public function setFeatured($nodeids, $set = true)
	{
		if (!$nodeids)
		{
			return array();
		}
		else if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$loginfo = array();
		foreach ($nodeids as $nodeid)
		{
			$node = $this->getNode($nodeid);

			$loginfo[] = array(
				'nodeid'		=> $node['nodeid'],
				'nodetitle'		=> $node['title'],
				'nodeusername'	=> $node['authorname'],
				'nodeuserid'	=> $node['userid'],
			);
		}

		vB::getDbAssertor()->assertQuery('vBForum:node',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'nodeid' => $nodeids, 'featured' => $set));

		$this->clearCacheEvents($nodeids);

		vB_Library_Admin::logModeratorAction($loginfo, ($set ? 'node_featured_by_x' : 'node_unfeatured_by_x'));
		$searchLIB = vB_Library::instance('search'); // Do not call instance() in a loop for no reason.
		foreach ($nodeids as $nodeid)
		{
			$searchLIB->attributeChanged($nodeid);
		}
		return $nodeids;
	}

	/**
	 * clears the unpublishdate flag.
	 *	@param	integer	The node id
	 *
	 *	@return	boolean
	 */
	public function clearUnpublishDate($nodeid)
	{
		$result = vB::getDbAssertor()->assertQuery('vBForum:node',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'nodeid' => $nodeid, 'unpublishdate' => -1));

		$node = $this->getNode($nodeid);
		if (empty($this->contentLibs[$node['nodeid']]))
		{
			$this->contentLibs[$node['nodeid']] =
				vB_Library::instance('Content_' . vB_Types::instance()->getContentTypeClass($node['contenttypeid']));
		}

		$data = array('unpublishdate' => 0);

		return $this->contentLibs[$node['nodeid']]->update($nodeid, $data);

	}

	/**
	 * This takes a list of nodes, and returns node records for all that are valid nodeids.
	 *
	 * 	@param array|int $nodeList array of ints or single int
	 *	@param bool $withJoinableContent Include joinable content
	 *
	 *	@return void
	 **/
	protected function cleanNodeList(&$nodeList, $withJoinableContent = false)
	{
		if (!is_array($nodeList))
		{
			$nodeList = array($nodeList);
		}

		$nodeList = array_unique($nodeList);

		//many of them may be in cache.
		$cached = vB_Library_Content::fetchFromCache($nodeList, vB_Library_Content::CACHELEVEL_NODE);
		$listIndex = array_flip($nodeList);

		if (!empty($cached['found']))
		{
			foreach ($cached['found'] as $node)
			{
				$nodeid = $node['nodeid'];
				if (isset($listIndex[$nodeid]))
				{
					$nodeList[$listIndex[$nodeid]] = $node;
					unset($listIndex[$nodeid]);
				}
			}
		}

		if (!empty($cached['notfound']))
		{
			if ($withJoinableContent)
			{
				$nodes = vB::getDbAssertor()->assertQuery(
					'vBForum:fetchNodeWithContent', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
						'nodeid' => $cached['notfound']
					)
				);
			}
			else
			{
				$nodes = vB::getDbAssertor()->assertQuery('vBForum:node', array('nodeid' => $cached['notfound']));
			}
			foreach ($nodes as $node)
			{
				$nodeid = $node['nodeid'];
				if (isset($listIndex[$nodeid]))
				{
					$nodeList[$listIndex[$nodeid]] = $node;
					unset($listIndex[$nodeid]);
				}
			}
		}

		//if we filtered out a node in the query, remove it from the list.
		foreach($listIndex as $key => $value)
		{
			unset($nodeList[$value]);
		}
	}


	/**
	 * Gets the content info for a list of nodes
	 *	@param	mixed	array of node ids
	 *
	 * 	@return	mixed	array of content records
	 */
	public function getContentforNodes($nodeList, $options = array())
	{
		static $cachedNodeList = array();
		if (empty($nodeList))
		{
			return array();
		}
		//if we are passed options we can't precache.
		if (empty($options))
		{
			if (!is_array($nodeList))
			{
				$nodeList = array($nodeList);
			}
			//if we are passed options we can't precache.
			$cachedNodeList = array_unique(array_merge($cachedNodeList, $nodeList));
			vB_Library::instance('page')->registerPrecacheInfo('node', 'getContentforNodes', $cachedNodeList);
		}

		$this->cleanNodeList($nodeList, true);
		return $this->addContentInfo($nodeList, $options);
	}

	/**
	 * 	Gets the content info for a list of nodes
	 *
	 *	@param array $nodeList Ids of the nodes to be fetched
	 *
	 * 	@return array array of content records -- preserves the original keys
	 **/
	public function getFullContentforNodes($nodeList, $options = array())
	{
		//we can short cut a fair amount of processing if we are requesting no nodes.
		//this is an odd request but not exactly an error...
		if (empty($nodeList))
		{
			return array();
		}

		static $cachedNodeList = array();

		//if we are passed options we can't precache.
		if (empty($options))
		{
			if (!is_array($nodeList))
			{
				$nodeList = array($nodeList);
			}
			//if we are passed options we can't precache.
			$cachedNodeList = array_unique(array_merge($cachedNodeList, $nodeList));
			vB_Library::instance('page')->registerPrecacheInfo('node', 'getFullContentforNodes', $cachedNodeList);
		}

		$this->cleanNodeList($nodeList, true);
		return $this->addFullContentInfo($nodeList, $options);
	}

	/**
	 * Gets the channel title and routeid
	 *	@param	int		The node id.
	 *	@return	mixed	Array of channel info
	 */
	public function getChannelInfoForNode($channelId)
	{
		$channelInfo = $this->getNodeBare($channelId);
		return array('title' => $channelInfo['title'], 'routeid' => $channelInfo['routeid']);
	}

	/**
	 * Adds optional content information. At the time of this writing it
	 * understands showVM and withParent
	 *
	 * @param mixed The assembled array of node info
	 * @param mixed Optional array of optional information
	 */
	protected function addOptionalContentInfo(&$nodeList, $options = false)
	{
		//We always need to add avatar information,
		$userApi = vB_Api::instanceInternal('user');
		$useridAvatarsToFetch = array();
		$userinfo = array();
		foreach($nodeList AS $key => $node)
		{
			if (empty($node['content']))
			{
				$nodeList[$key]['content'] = array();
			}

			if (!empty($node['userid']))
			{
				$useridAvatarsToFetch[] = $node['userid'];
			}

			if (!empty($node['lastauthorid']) AND $node['lastauthorid'] > 0)
			{
				$useridAvatarsToFetch[] = $node['lastauthorid'];
			}

			if (!empty($node['deleteuserid']) AND !isset($nodeList[$key]['content']['deleteusername']))
			{
				$nodeList[$key]['content']['deleteusername'] = $userApi->fetchUserName($node['deleteuserid']);
			}

			if (isset($node['content']['userinfo']['hascustomavatar']))
			{
				$userinfo[$node['content']['userinfo']['userid']] = $node['content']['userinfo'];
			}
		}

		$avatarsurl = $userApi->fetchAvatars($useridAvatarsToFetch, true, $userinfo);

		foreach ($nodeList AS $nodeKey => $nodeInfo)
		{

			if (!empty($nodeInfo['userid']))
			{
				$nodeList[$nodeKey]['content']['avatar'] = $avatarsurl[$nodeInfo['userid']];
			}

			if (!empty($nodeInfo['lastauthorid']) AND $nodeInfo['lastauthorid'] > 0 AND !empty($avatarsurl[$nodeInfo['lastauthorid']]))
			{
				$nodeList[$nodeKey]['content']['avatar_last_poster'] = $avatarsurl[$nodeInfo['lastauthorid']];
			}
		}

		if (!empty($options['showVM']) AND !empty($nodeList))
		{
			$nodeids = array();
			//We need to flag which are visitor messages
			foreach($nodeList AS $key => $node)
			{
				$nodeids[$node['nodeid']] = $node['nodeid'];
				$nodeList[$key]['content']['isVisitorMessage'] = 0;
			}
			//We have all the nodes. Now query for which are VM's
			$vMs = $this->fetchClosureParent(array_keys($nodeids), vB_Api::instanceInternal('node')->fetchVMChannel());
			foreach ($vMs AS $closureRecord)
			{
				//Remember the nodes are keys into nodeids, which are keys into nodeList.
				$key = $nodeids[$closureRecord['child']];
				$nodeList[$key]['content']['isVisitorMessage'] = 1;

				// comments/replies don't have a set for so we might want to get that from parent...
				if (!empty($nodeList[$key]['content']['setfor']))
				{
					$setfor = $nodeList[$key]['content']['setfor'];
				}
				else
				{
					$parentid = $nodeList[$key]['parentid'];
					if (!$parentid)
					{
						$parentid = $nodeList[$key]['content']['parentid'];
					}

					$parentInfo = $this->getNode($parentid);
					$setfor = $parentInfo['setfor'];
				}

				$vm_userInfo = vB_User::fetchUserinfo($setfor);
				$vmAvatar = $userApi->fetchAvatar($setfor, true, $vm_userInfo);
				$vm_userInfo = array(
					'userid' => $vm_userInfo['userid'],
					'username' => $vm_userInfo['username'],
					'rank' => $vm_userInfo['rank'],
					'usertitle' => $vm_userInfo['usertitle'],
					'joindate' => $vm_userInfo['joindate'],
					'posts' => $vm_userInfo['posts'],
					'customtitle' => $vm_userInfo['customtitle'],
					'userfield' => array(),
				);
				// fetchAvatar() may return false instead of an array, which causes array_merge() to throw a warning.
				// TODO: instead of skipping $vmAvatar, generate a "default" array in case templates expect the avatar
				// related keys in the future. Or better yet, have fetchAvatar() return a consistent structure that
				// includes "default" data.
				if (!empty($vmAvatar))
				{
					$vm_userInfo = array_merge($vm_userInfo, $vmAvatar);
				}
				$nodeList[$key]['content']['vm_userInfo'] = $vm_userInfo;
			}
		}

		if (!empty($options['withParent']) AND !empty($nodeList))
		{
			//We need to pull parent node information, but only for comments- not starters or replies:
			$parentids = array();
			$indexes = array();
			foreach($nodeList AS $key => $node)
			{
				//Note that we can't use an indexed array to lookup the same way as for showVM, because we
				// often will have multiple records with the same parent.
				if (($node['nodeid'] != $node['starter']) AND ($node['parentid'] != $node['starter']) AND ($node['contenttypeid'] != $this->channelTypeId))
				{
					$parentids[] = $node['parentid'];
				}
			}

			//If we had no comments in the list, we're done.
			if (!empty($parentids))
			{
				$parents = $this->getFullContentforNodes(array_unique($parentids));

				foreach ($parents AS $key => $parent)
				{
					$indexes[$parent['nodeid']] = $key;
				}
				foreach($nodeList AS $key => $node)
				{
					if (array_key_exists($node['parentid'], $indexes))
					{
						$parentKey = $indexes[$node['parentid']];
						$nodeList[$key]['content']['parentConversation'] = $parents[$parentKey];
					}
				}
			}
		}
	}

	/**
	 * Adds optional content information for a single node.
	 * 	At the time of this writing it understands showVM and withParent
	 *
	 *	@param	mixed	the assembled array of node info
	 * 	@param	mixed	optional array of optional information
	 */
	protected function addOptionalNodeContentInfo(&$node, $options = false)
	{
		//We always need to add avatar information
		$userApi = vB_Api::instanceInternal('user');
		$useridAvatarsToFetch = array();
		if (!empty($node['userid']))
		{
			$useridAvatarsToFetch[] = $node['userid'];
		}
		if (!empty($node['lastauthorid']) AND $node['lastauthorid'] > 0)
		{
			$useridAvatarsToFetch[] = $node['lastauthorid'];
		}

		if (!empty($node['deleteuserid']) AND !isset($node['deleteusername']))
		{
			$node['deleteusername'] = $userApi->fetchUserName($node['deleteuserid']);
		}

		if (!empty($useridAvatarsToFetch))
		{
			$avatarsurl = $userApi->fetchAvatars($useridAvatarsToFetch, true);

			if (!empty($node['userid']))
			{
				$node['avatar'] = $avatarsurl[$node['userid']];
			}

			if (!empty($node['lastauthorid']) AND $node['lastauthorid'] > 0 AND !empty($avatarsurl[$node['lastauthorid']]))
			{
				$node['avatar_last_poster'] = $avatarsurl[$node['lastauthorid']];
			}
		}

		if (!empty($options['showVM']) AND !empty($node))
		{
			//We have the node. Now query for which are VM's
			$vMs = $this->fetchClosureParent($node['nodeid'], vB_Api::instanceInternal('node')->fetchVMChannel());
			if (!empty($vMs))
			{
				foreach ($vMs AS $closureRecord)
				{
					$key = $closureRecord['child'];
					if ($key == $node['nodeid'])
					{
						$node['isVisitorMessage'] = 1;
						$vm_userInfo = vB_User::fetchUserinfo($node['setfor']);
						$node['vm_userInfo'] = array(
							'userid' => $vm_userInfo['userid'],
							'username' => $vm_userInfo['username'],
							'rank' => $vm_userInfo['rank'],
							'usertitle' => $vm_userInfo['usertitle'],
							'joindate' => $vm_userInfo['joindate'],
							'posts' => $vm_userInfo['posts'],
							'customtitle' => $vm_userInfo['customtitle'],
							'userfield' => array(),
						);
						$vmAvatar = $userApi->fetchAvatar($node['setfor'], true, $vm_userInfo);
						if (is_array($vmAvatar))
						{
							$node['vm_userInfo'] = array_merge($node['vm_userInfo'], $vmAvatar);
						}
					}
				}
			}
			else
			{
				$node['isVisitorMessage'] = 0;
				$node['vm_userInfo'] = array();
			}
		}

		if (!empty($options['withParent']) AND !empty($node))
		{
			$parentid = 0;

			if (($node['nodeid'] != $node['starter']) AND ($node['parentid'] != $node['starter']) AND ($node['contenttypeid'] != $this->channelTypeId))
			{
				$parentid = $node['parentid'];
			}

			//If we had no comments in the list, we're done.
			if (!empty($parentid))
			{
				$parent = $this->getNodeFullContent($parentid);
				$node['parentConversation'] = $parent;
			}
		}
	}

	/**
	 * This gets the attachment information filedata for a node. Which may be empty.
	 *
	 *	@param		int		the nodeid we are checking
	 *	@return		mixed	either false or an array of filedata.
	 */
	public function fetchAttachInfo($parentIds)
	{

		return $this->fetchNodeAttachments($parentIds);

	}


	/**
	 * This gets the attachment information for a node. Which may be empty.
	 *
	 *	@param		mixed	int or array of ints- the nodeid we are checking
	 *
	 *	@return		mixed	either false or an array of attachments with the following fields:
	 *						** attach fields **
	 *						- filedataid
	 *						- nodeid
	 *						- parentid
	 *						- visible
	 *						- counter
	 *						- posthash
	 *						- filename
	 *						- caption
	 *						- reportthreadid
	 *						- settings
	 *						- hasthumbnail
	 *
	 *						** filedata fields **
	 *						- userid
	 *						- extension
	 *						- filesize
	 *						- thumbnail_filesize
	 *						- dateline
	 *						- thumbnail_dateline
	 *
	 *						** link info **
	 *						- url
	 *						- urltitle
	 *						- meta
	 *
	 *						** photo info **
	 *						- caption
	 *						- height
	 *						- width
	 *						- style
	 */
	public function fetchNodeAttachments($parentids)
	{
		if (!is_array($parentids))
		{
			$parentids = array($parentids);
		}

		//First let's see what we have in cache.
		$found = array();
		$notfound = array();
		$cache = vB_Cache::instance(vB_Cache::CACHE_LARGE);
		$cacheids = array();
		foreach ($parentids AS $parentid)
		{
			$cacheids[$parentid] = "vBAtchmnts_$parentid";
		}

		$attachments = $cache->read($cacheids);

		foreach ($parentids AS $parentid)
		{
			$cacheid = $cacheids[$parentid];

			if (!$attachments OR !isset($attachments[$cacheid]) OR $attachments[$cacheid] === false)
			{
				$notfound[$parentid] = array() ;
			}
			else if (!empty($attachments[$cacheid]))
			{
				foreach($attachments[$cacheid] AS $attach)
				{
					$found[] = $attach;
				}
			}
		}

		if (!empty($notfound))
		{
			$types = vB_Types::instance();
			try
			{
				$attachments = vB::getDbAssertor()->getRows(
					'vBForum:fetchNodeAttachments',
					array(
						'nodeid' => array_keys($notfound),
						'attachcontenttypeid' => $types->getContentTypeID('vBForum_Attach'),
						'photocontenttypeid' => $types->getContentTypeID('vBForum_Photo'),
					)
				);
				usort($attachments, function($a, $b) {return $a['displayorder'] <=> $b['displayorder'];});
			}
			catch(exception $e)
			{
				//this can happen during a preload. Just continue;
				$attachments = array();
			}

			$updateFiledataInfo = array();
			foreach($attachments AS &$attachment)
			{
				$found[] =& $attachment;
				$notfound[$attachment['parentid']][] =& $attachment;

				if ($attachment['filedataid'] > 0)
				{
					$updateFiledataInfo[$attachment['filedataid']][] =& $attachment;
				}
			}

			//now fetch missing filedata info
			if (!empty($updateFiledataInfo))
			{
				$filedataInfo = vB::getDbAssertor()->assertQuery('vBForum:getFiledataWithThumb', array('filedataid' => array_keys($updateFiledataInfo)));
				if ($filedataInfo)
				{
					foreach($filedataInfo AS $filedata)
					{
						foreach($updateFiledataInfo[$filedata['filedataid']] AS &$attachment)
						{
							// these fields are required for text parsing
							$keys = array('userid', 'extension', 'filesize', 'dateline', 'resize_filesize', 'resize_dateline');
							foreach($keys AS $key)
							{
								$attachment[$key] = $filedata[$key];
							}

							// todo: is there a reason to not return the filename?
							// $attachment['filename'] = $filedata['filehash'] . '.' . $filedata['extension'];
							/*
								This is code inherited from filedata::fetchImageByFiledataid() but is not correct.
								'refcount' is the # of data references to the single filedata record (e.g.
								attachments sharing same filedata, channel icons, etc) while 'counter' is supposed
								to be the view counter, which we were not tracking prior to VBV-14161.
								The 'counter' is actually from the `attach` record not the `filedata` record.
							$attachment['counter'] = $filedata['refcount'];
							 */
							$attachment['hasthumbnail'] = ($filedata['resize_filesize'] > 0);
						}
					}
				}
			}

			//cache what we've found- but not false. Use empty array so we can distinguish
			// cached data from uncached.
			foreach ($notfound AS $parentid => $attachments)
			{
				$hashKey = "vBAtchmnts_$parentid";

				if (empty($attachments))
				{
					$attachments = array();
				}

				$cache->write($hashKey, $attachments, 1440, "nodeChg_$parentid");
			}
		}

		return $found;
	}

	/**
	 * 	Takes an array of node information and adds contentInfo
	 *	@param	integer	The node id of the parent where we are listing
	 *	@param	integer	page number to return
	 *	@param	integer	items per page
	 *	@param	integer	depth- 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 *	@param	mixed	if desired, will only return specific content types.
	 *	@param	mixed	'sort', or 'exclude' recognized.
	 *
	 * 	@return	mixed	array of id's
	 */
	public function addFullContentInfo($nodeList, $options = array())
	{
		//Now separate by content type	$contenttypes = array();
		if (empty($nodeList))
		{
			return array();
		}

		$nodeIds = array();
		$needVote = array();
		$cacheVote = array();
		$needRead = array();
		$parentids = array();
		$attachCounts = array();
		$photoCounts = array();
		$channels = array();
		$grabAttachCounts = array();

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$userids = array();
		foreach ($nodeList AS $key => $node)
		{
			if (empty($node['nodeid']))
			{
				continue;
			}

			if (!isset($contenttypes[$node['contenttypeid']]))
			{
				$contenttypes[$node['contenttypeid']] = array();
			}
			$contenttypes[$node['contenttypeid']][$key] = $node['nodeid'];
			$nodeIds[] = $node['nodeid'];

			if ($this->channelTypeId != $node['contenttypeid'])
			{
				// only fetch attachments for non channels.
				$grabAttachCounts[] = $node['nodeid'];
			}

			if (!isset($node['nodeVoted']))
			{
				$needVote[] = $node['nodeid'];
			}
			else
			{
				$cacheVote[$node['nodeid']] = $node['nodeVoted'];
			}

			if (!isset($node['readtime']))
			{
				$needRead[$node['nodeid']] = $node['nodeid'];
				$nodeList[$key]['readtime'] = 0;
			}
			$parentids[$node['parentid']] = $node['parentid'];
			$needRead = array_merge($parentids, $needRead);

			if (!isset($userids[$node['userid']]))
			{
				$userids[$node['userid']] = $node['userid'];
			}
		}

		vB_Library::instance('user')->preloadUserInfo($userids);

		// pre-cache parents
		$parents = $this->getNodes($parentids);
		$parentrouteids = array();
		foreach ($parents as $parent)
		{
			$parentrouteids[] = $parent['routeid'];
		}

		//pre-load parent routes
		vB5_Route::preloadRoutes($parentrouteids);
		// get votes

		$nodeVotes = array();
		if (!empty($needVote))
		{
			$nodeVotes = vB_Library::instance('reputation')->fetchNodeVotes($needVote);
		}

		if (!empty($cacheVote))
		{
			vB_Library::instance('reputation')->cacheNodeVotes($cacheVote);
		}

		if (!empty($nodeIds))
		{
			$attachments = $this->fetchNodeAttachments($nodeIds);

			$nodeAttachments = array();
			foreach ($attachments as $key => $attach)
			{
				$nodeAttachments[$attach['parentid']][$attach['filedataid']] = & $attachments[$key];
			}
		}

		// Fetch read marking data
		$threadmarking = vB::getDatastore()->getOption('threadmarking');
		$userid = vB::getCurrentSession()->get('userid');
		if ($threadmarking AND $userid AND !empty($nodeIds) AND !empty($needRead))
		{
			$reads = vB::getDbAssertor()->getRows('noderead', array(
				'userid' => $userid,
				'nodeid' => $needRead,
			));

			$parentsreads = array();
			foreach ($reads AS $read)
			{
				if (!empty($nodeList[$read['nodeid']]))
				{
					$nodeList[$read['nodeid']]['readtime'] = $read['readtime'];
				}
				else
				{
					$parentsreads[$read['nodeid']] = $read['readtime'];
				}
			}

			foreach ($nodeList as $nodeid => $node)
			{
				if (empty($parentsreads[$node['parentid']])) {
					$parentsreads[$node['parentid']] = 0;
				}
				$nodeList[$nodeid]['parentreadtime'] = $parentsreads[$node['parentid']];
			}

		}

		//For each type, get the content detail.

		if (!empty($grabAttachCounts))
		{
			$attachCountQry = vB::getDbAssertor()->getRows('vBForum:getDescendantAttachCount', array('nodeid' => $grabAttachCounts));
			foreach ($attachCountQry as $count)
			{
				$attachCounts[$count['nodeid']] = $count['count'];
			}

			$photoCountQry = vB::getDbAssertor()->getRows('vBForum:getDescendantPhotoCount', array('nodeid' => $grabAttachCounts,	// this is .1 seconds
				'photoTypeid' => vB_Types::instance()->getContentTypeID('vBForum_Photo')));
			foreach ($photoCountQry as $count)
			{
				$photoCounts[$count['nodeid']] = $count['count'];
			}
		}
		// precache closure
		$this->fetchClosureParent($nodeIds);
		$optionMask = $this->options;

		foreach ($contenttypes as $contenttypeid => $nodes)
		{
			if (!empty($nodes))
			{
				$contentLib = vB_Library_Content::getContentLib($contenttypeid);

				$contentList = $contentLib->getFullContent($nodes);

				foreach ($nodes as $key => $nodeid)
				{
					if (isset($contentList[$nodeid]))
					{
						if (!empty($contentList[$nodeid]['node_no_permission']))
						{
							unset($nodeList[$nodeid]);
							continue;
						}

						if (isset($nodeList[$key]['nodeVoted']))
						{
							// node came into the function with nodeVoted already set
							$contentList[$nodeid]['nodeVoted'] = $nodeList[$key]['nodeVoted'];
						}
						else
						{
							// node came into this function w/o nodeVoted set so fetchNodeVotes retrieved it up there^
							$contentList[$nodeid]['nodeVoted'] = in_array($nodeid, $nodeVotes) ? 1 : 0;
						}
						$nodeList[$key]['content'] = $contentList[$nodeid];

						if (!empty($contentList[$nodeid]['contenttypeclass']))
						{
							$nodeList[$key]['contenttypeclass'] = $contentList[$nodeid]['contenttypeclass'];
						}

						if ($contentList[$nodeid]['contenttypeid'] == $this->channelTypeId)
						{
							$channels[$contentList[$nodeid]['nodeid']] = $contentList[$nodeid]['nodeid'];
						}
						else if (!empty($contentList[$nodeid]['channelid']) AND !isset($channels[$contentList[$nodeid]['channelid']]))
						{
							$channels[$contentList[$nodeid]['channelid']] = $contentList[$nodeid]['channelid'];
						}
					}


					foreach ($optionMask as $bitname => $bitmask)
					{
						$nodeList[$key][$bitname] = ($bitmask & $node['nodeoptions']) ? 1 : 0;
					}


					if (isset($nodeAttachments[$nodeid]))
					{
						$nodeList[$key]['content']['attachments'] = & $nodeAttachments[$nodeid];
					}
					else
					{
						$nodeList[$key]['content']['attachments'] = array();
					}


					if (empty($attachCounts[$nodeid]))
					{
						$nodeList[$key]['attachcount'] = 0;
					}
					else
					{
						$nodeList[$key]['attachcount'] = $attachCounts[$nodeid];
					}
					if (!empty($photoCounts[$nodeid]))
					{
						$nodeList[$key]['attachcount'] += $photoCounts[$nodeid];
					}
				}

			}
		}

		// censor textual node items
		vB_Library_Node::censorNodes($nodeList);

		$this->addOptionalContentInfo($nodeList, $options);
		//Note- it is essential that the parentids be passed along with the nodeList. This allows all the permissions to
		// be pulled in one function call, and saves a lot of processing in the usercontext object.
		$this->markSubscribed($nodeList);
		$this->markJoined($nodeList);

		return $nodeList;
	}

	/**
	 *	Cleans the node list according the to permissions set in the node record
	 *	for the current user.  For use by various APIs that return node information
	 *	to consolidate the cleaning in one place.
	 *
	 *	Currently removes the ipaddress fields when the user should not be able to
	 *	view them.
	 *
	 *	The passed node array is cleaned in place to avoid unnecesary copies of large
	 *	objects instead of returned.
	 *
	 *	@param array $nodelist
	 *	@return none
	 */
	public function removePrivateDataFromNodeList(&$nodelist)
	{
		foreach ($nodelist AS $key => $node)
		{
			$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
			$contentLib->removePrivateDataFromNode($nodelist[$key]);
		}
	}

	/**
	 * 	Takes an array of node information and adds contentInfo
	 *	@param	integer	The node id of the parent where we are listing
	 *	@param	integer	page number to return
	 *	@param	integer	items per page
	 *	@param	integer	depth- 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 *	@param	mixed	if desired, will only return specific content types.
	 *	@param	mixed	'sort', or 'exclude' recognized.
	 *
	 * 	@return	mixed	array of id's
	 * 	@deprecated Use addFullContentInfo instead
	 */
	public function addContentInfo($nodeList, $options = array())
	{
		return $this->addFullContentInfo($nodeList, $options);
	}

	/**
	* This gets a content record based on nodeid. Useful from ajax.
	*
	*	@param	int
	*	@param	int	optional
	*	@param	mixed options	Options to get optional info (showVM, withParent)
	*
	*	@return array. An array of node record arrays as $nodeid => $node
	* @deprecated Use getNodeFullContent instead
	*/
	public function getNodeContent($nodeid, $contenttypeid = false, $options = array())
	{
		return $this->getNodeFullContent($nodeid, $contenttypeid, $options);
	}


	/**
	 * returns id of the Albums Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchAlbumChannel()
	{
		if ($this->albumChannel)
		{
			return $this->albumChannel;
		}
		$albumChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::ALBUM_CHANNEL);
		$this->albumChannel = $albumChannel['nodeid'];
		return $this->albumChannel;

	}

	/**
	 * returns id of the Private Message Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchPMChannel()
	{
		if ($this->PMChannel)
		{
			return $this->PMChannel;
		}
		$PMChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::PRIVATEMESSAGE_CHANNEL);
		$this->PMChannel = $PMChannel['nodeid'];
		return $this->PMChannel;

	}

	/**
	 * returns id of the Vistor Message Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchVMChannel()
	{
		if ($this->VMChannel)
		{
			return $this->VMChannel;
		}
		$VMChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::VISITORMESSAGE_CHANNEL);
		$this->VMChannel = $VMChannel['nodeid'];
		return $this->VMChannel;

	}

	public function getSGChannel()
	{
		if (!empty($this->sgChannel))
		{
			return $this->sgChannel;
		}
		// use default pagetemplate for social groups
		$sgChannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_SOCIALGROUP_PARENT);
		$this->sgChannel = $sgChannel['nodeid'];
		return $this->sgChannel;
	}

	/**
	 * returns id of the Report Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchReportChannel()
	{
		if ($this->ReportChannel)
		{
			return $this->ReportChannel;
		}
		$ReportChannel = vB_Library::instance('Content_Channel')->fetchChannelByGUID(vB_Channel::REPORT_CHANNEL);

		//there should always be a report channel, but the upgrader works on incomplete DBs
		if ($ReportChannel)
		{
			$this->ReportChannel = $ReportChannel['nodeid'];
		}
		else
		{
			$this->ReportChannel = null;
		}
		return $this->ReportChannel;
	}

	/**
	 * Returns the nodeid of the root forums channel
	 *
	 * @return	integer	The nodeid for the root forums channel
	 */
	public function fetchForumChannel()
	{
		if ($this->forumChannel)
		{
			return $this->forumChannel;
		}

		$forumChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::DEFAULT_FORUM_PARENT);
		$this->forumChannel = $forumChannel['nodeid'];

		return $this->forumChannel;
	}

	/**
	 * Returns the nodeid of the infraction channel
	 *
	 * @return	integer	The nodeid for the infraction channel
	 */
	public function fetchInfractionChannel()
	{
		if ($this->infractionChannel)
		{
			return $this->infractionChannel;
		}

		$infractionChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::INFRACTION_CHANNEL);
		if (!empty($infractionChannel))
		{
			$this->infractionChannel = $infractionChannel['nodeid'];
		}
		return $this->infractionChannel;
	}

	/**
	 * Returns the nodeid of the CMS/Articles channel
	 *
	 * @return	integer	The nodeid for the CMS channel
	 */
	public function fetchArticleChannel()
	{
		if ($this->articleChannel)
		{
			return $this->articleChannel;
		}

		$articleChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
		if (!empty($articleChannel))
		{
			$this->articleChannel = $articleChannel['nodeid'];
		}
		return $this->articleChannel;
	}

	/**
	 * Returns a content record based on nodeid including channel and starter information
	 *
	 * @param  int  Node ID
	 * @param  int  (optional) Content type ID
	 * @param  bool (optional) Array of options
	 *
	 * @return array Content record
	 */
	public function getNodeFullContent($nodeid, $contenttypeid = false, $options = array())
	{
		$db = vB::getDbAssertor();

		if ($contenttypeid)
		{
			$contentLib = vB_Library_Content::getContentLib($contenttypeid);
		}
		else
		{
			$node = $this->getNodeBare($nodeid);
			if (empty($node) OR !empty($node['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}

			$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
		}
		$result = $contentLib->getFullContent($nodeid);

		$totalphotocount = isset($result[$nodeid]['photo']) ? count($result[$nodeid]['photo']) : 0;

		if (!empty($options['attach_options']['perpage']) AND $result[$nodeid]['photocount'] > $options['attach_options']['perpage'])
		{
			$page = empty($options['attach_options']['page']) ? 1 : $options['attach_options']['page'];
			$from = ($page -1) * $options['attach_options']['perpage'];
			$result[$nodeid]['photo'] = array_slice($result[$nodeid]['photo'], $from, $options['attach_options']['perpage']);
			$result[$nodeid]['pagenav'] = array(
				'startcount' => $from,
				'totalcount' => $totalphotocount,
				'currentpage' => $page,
				'totalpages' => ceil($totalphotocount / $options['attach_options']['perpage']),
				'perpage' => $options['attach_options']['perpage']
			);

		}

		$attachments = $this->fetchNodeAttachments($nodeid);
		$result[$nodeid]['attachments'] = array();
		foreach ($attachments AS $attachment)
		{
			if (!empty($attachment))
			{
				//$result[$nodeid]['attachments'][$attachment['filedataid']] = $attachment;
				// Above was commented out & replaced by below @ 5.1.1 Alpha 8. If this doesn't cause problems, let's remove
				// it in a couple versions.
				// filedataid shouldn't be the key, because we could have multiple attachments (which should have different
				// nodeids) that use the same filedataid. Instead, use nodeid as the key.
				$result[$nodeid]['attachments'][$attachment['nodeid']] = $attachment;
			}
		}
		$totalattachcount = $result[$nodeid]['attachcount'] = count($result[$nodeid]['attachments']);
		if (!empty($options['attach_options']['perpage']) AND !empty($result[$nodeid]['attachcount']) AND
			$result[$nodeid]['attachcount'] > $options['attach_options']['perpage'])
		{
			$page = empty($options['attach_options']['page']) ? 1 : $options['attach_options']['page'];
			$from = ($page -1) * $options['attach_options']['perpage'];
			$result[$nodeid]['attachments'] = array_slice($result[$nodeid]['attachments'], $from, $options['attach_options']['perpage']);

			$result[$nodeid]['attachpagenav'] = array(
				'startcount' => $from,
				'totalcount' => $totalattachcount,
				'currentpage' => $page,
				'totalpages' => ceil($totalattachcount / $options['attach_options']['perpage']),
				'perpage' => $options['attach_options']['perpage']
			);
		}
		$this->addOptionalNodeContentInfo($result[$nodeid], $options);

		if ($result[$nodeid]['contenttypeid'] == $this->channelTypeId)
		{
			$channelid = $nodeid;
		}
		else
		{
			$channelid = $result[$nodeid]['channelid'];
		}
		$perms = vB::getUserContext()->fetchPermsForChannels(array($channelid));
		$thisPerms = $perms[$channelid];
		foreach ($perms['global'] AS $key => $perm)
		{
			$thisPerms[$key] = $perm;
		}
		$this->markSubscribed($result);
		$this->markJoined($result);

		return $result;
	}

	/**
	 * This returns all the albums in a channel. Those can be photogalleries or text with attachments.
	 *
	 *	@param		int
	 *
	 *	@return		mixed		array of node records. Each node includes the node content and userinfo, and attachment records.
	 */
	public function getAlbums($nodeid)
	{
		//first query to get the id's.
		$nodeids = array();
		$nodeQry = vB::getDbAssertor()->assertQuery('vBForum:fetchNodesWithAttachments', array(
			'channel' => $nodeid,
			'contenttypeid' => array(
				vB_Types::instance()->getContentTypeId('vBForum_Attach'),
				vB_Types::instance()->getContentTypeId('vBForum_Photo'),
			)
		));

		foreach($nodeQry AS $node)
		{
			$nodeids[] = $node['nodeid'];
		}

		if (empty($nodeids))
		{
			return array();
		}

		$content = $this->getFullContentforNodes($nodeids, true);
		//let's set everything with key nodeid.
		//We want to know the difference between attachments and photos in the template.
		//The array of photos in the gallery is "photo". For text let's call it "album".
		$sortable = array();
		foreach ($content as $key => $node)
		{
			$sortable[$node['nodeid']] = $node;
			$sortable[$node['nodeid']]['album'] = array();
		}

		if (!empty($nodeids))
		{
			$attachments = $this->fetchNodeAttachments($nodeids);

			foreach ($attachments as $key => $attach)
			{
				$sortable[$attach['parentid']]['album'][$attach['nodeid']] = $attach;
			}
		}

		foreach ($content as $key => &$node)
		{
			if (empty($node['attachments']))
			{
				$node['attachcount'] = 0;
			}
			else
			{
				$node['attachcount'] = count($node['attachments']);
			}
		}

		//now we need photocount
		foreach ($sortable as $key => $node)
		{
			$sortable[$key]['photocount'] = count($node['album']);
			$sortable[$key]['starteruserid'] = $node['content']['starteruserid'];
			$sortable[$key]['starterauthorname'] = $node['content']['starterauthorname'];
			$sortable[$key]['starterroute'] = $node['content']['starterroute'];
		}
		//Now galleries.
		$nodeQry = vB::getDbAssertor()->assertQuery('vBForum:fetchGalleriesInChannel',
			array('channel' => $nodeid, 'contenttypeid' => vB_Types::instance()->getContentTypeId('vBForum_Gallery')) );

		$nodeids = array();

		foreach($nodeQry AS $node)
		{
			$nodeids[] = $node['nodeid'];
		}

		if (!empty($nodeids))
		{
			$galleries = vB_Api::instanceInternal('content_gallery')->getFullContent($nodeids);

			//now let's merge and sort them.
			foreach ($galleries as $gallery)
			{
				//we only have text objects that we know have attachments, but there
				//could be a gallery with no photos.
				if (!empty($gallery['photo']))
				{
					$sortable[$gallery['nodeid']] = $gallery;
				}
			}
		}
		if (empty($sortable))
		{
			throw new vB_Exception_Api('invalid_data');
		}
		ksort($sortable);
		//Now we have a non-associative array of $content and an associative array of albums. We need to merge.
		return $sortable;
	}

	/**
	 * Sets the approved field
	 * @param array $nodeids
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	public function approve($nodeids)
	{
		return $this->setApproved($nodeids, true);
	}

	/**
	 * Unsets the approved field
	 * @param array $nodeids
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	public function unapprove($nodeids)
	{
		return $this->setApproved($nodeids, false);
	}

	/**
	 * Gets the list of unapproved posts for the current user
	 *
	 * @param	int		User id. If not specified will take current User
	 * @param	mixed	Options used for pagination:
	 * 						page 		int		number of the current page
	 * 						perpage		int		number of the results expected per page.
	 * 						totalcount	bool	flag to indicate if we need to get the pending posts totalcount
	 *
	 * @return	mixed	Array containing the pending posts nodeIds with contenttypeid associated.
	 */
	public function listPendingPosts($userId = false, $options = array())
	{
		$userId = intval($userId);
		if (!$userId)
		{
			$userId = vB::getCurrentSession()->get('userid');
		}

		if (!$userId)
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		// let's get mod permissions
		$params = array();
		$moderateInfo = vB::getUserContext()->getCanModerate();
		$result = array();

		if (empty($moderateInfo['can']) AND empty($moderateInfo['canpublish']))
		{
			$result = array('nodes' => array());
		}
		else
		{
			// let's take pagination info first...
			$params[vB_dB_Query::PARAM_LIMITPAGE] = (isset($options['page']) AND intval($options['page'])) ? $options['page'] : 1;

			$params[vB_dB_Query::PARAM_LIMIT] = (isset($options['perpage']) AND intval($options['perpage'])) ? $options['perpage'] : 20;

			$params['canModerate'] = $moderateInfo['can'];
			$params['canPublish'] = $moderateInfo['canpublish'];

			if (!empty($options['time']))
			{
				$now = vB::getRequest()->getTimeNow();
				switch ($options['time'])
				{
					case 'today':
						$params['cutofftime'] = $now - 86400; //24 hours
					break;
					case 'thisweek':
						$params['cutofftime'] = $now - 604800; //1 week
					break;
					case 'thisweek':
						$params['cutofftime'] = $now - 2592000; //30 days
					break;
				}
			}

			if (!empty($options['type']))
			{
				$params['type'] = $options['type'];
			}

			$pendingPosts = vB::getDbAssertor()->assertQuery('vBForum:fetchPendingPosts', $params);

			$pending = array();
			foreach ($pendingPosts AS $post)
			{
				$pending[intval($post['nodeid'])] = array('nodeid' => intval($post['nodeid']), 'contenttypeid' => intval($post['contenttypeid']));
			}

			$result = array('nodes' => $pending);

			// if totalcount flag is set...
			if ($options['totalcount'])
			{
				$page = $params[vB_dB_Query::PARAM_LIMITPAGE];
				$perpage = $params[vB_dB_Query::PARAM_LIMIT];
				unset($params[vB_dB_Query::PARAM_LIMITPAGE]);
				unset($params[vB_dB_Query::PARAM_LIMIT]);

				$countInfo = vB::getDbAssertor()->getRow('vBForum:fetchPendingPostsCount', $params);

				$result['totalcount'] = intval($countInfo['ppCount']);
				$pagecount = ceil($result['totalcount']/$perpage);
				if ($page > 1)
				{
					$prevpage = $page - 1;
				}
				else
				{
					$prevpage = false;
				}

				if ($page < $pagecount)
				{
					$nextpage = $page + 1;
				}
				else
				{
					$nextpage =false;
				}

				$pageInfo = array('totalcount' => $result['totalcount'], 'pages' => $pagecount, 'nextpage' => $nextpage, 'prevpage' => $prevpage, 'perpage' => $perpage, 'currentpage' => $page);
				$result['pageInfo'] = $pageInfo;
			}
		}

		return $result;
	}

	/**
	 * This was a function wrapper for listPendingPosts but used for current user.
	 * Now returns different information due to post processing steps.
	 *
	 */
	public function listPendingPostsForCurrentUser($options = array())
	{
		$result = $this->listPendingPosts(vB::getCurrentSession()->get('userid'), $options);

		if (isset($result['totalcount']))
		{
			$totalCount = intval($result['totalcount']);
		}

		if (isset($result['pageInfo']))
		{
			$pageInfo = $result['pageInfo'];
		}


		$contenttypes = array();
		$nodes = array();

		foreach ($result['nodes'] AS $node)
		{
			$contenttypeid = $node['contenttypeid'];
			$nodeid = $node['nodeid'];

			if (!isset($contenttypes[$contenttypeid]))
			{
				$contenttypes[$contenttypeid] = array();
			}
			$contenttypes[$contenttypeid][] = $nodeid;
			$nodes[$nodeid] = $node;
		}

		//For each type, get the content detail.
		foreach ($contenttypes as $contenttypeid => $nodeList)
		{
			if (!empty($nodes))
			{
				$contentApi = vB_Api_Content::getContentApi($contenttypeid);
				$contentList = $contentApi->getFullContent($nodeList);
				foreach ($nodes as $nodeid => $node)
				{
					foreach ($contentList as $key => $content)
					{
						if ($content['nodeid'] == $nodeid)
						{
							$nodes[$nodeid]['content'] = $content;
							//unfortunately what a node array looks like is all over the map.
							//if the userid isn't at the root level then the avatar doesn't get filled
							//in correctly below. Cleaning that up is a big lift be we can at least bring
							//this closer to standard.
							$nodes[$nodeid]['userid'] = $nodes[$nodeid]['content']['userid'];
							break;
						}
					}
				}
			}
		}

		$userApi = vB_Api::instanceInternal('user');
		$pmContentType = vB_Types::instance()->getContentTypeId('vBForum_PrivateMessage');
		//We need a list of parents for nodes that are neither starters nor replies.
		$parents = array();
		//add parent, visitormessage, and author information
		foreach ($nodes AS $nodeid => $node)
		{
			if (($node['content']['starter'] != $node['content']['nodeid']) AND ($node['content']['starter'] != $node['content']['parentid']))
			{
				$parents[$nodeid] = $node['content']['parentid'];
			}

			$nodes[$nodeid]['isVisitorMessage'] = $nodes[$nodeid]['content']['isVisitorMessage'] = !empty($node['content']['setfor']);

			$nodes[$nodeid]['userinfo'] = array(
				'avatar'	=> $userApi->fetchAvatar($node['content']['userid'], array('avatar'), $node['content']['userinfo']),
				'userid'	=> $node['content']['userid'],
				'username'	=> $node['content']['userinfo']['username']
			);
		}

		//See if we need to add some parent information
		if (!empty($parents))
		{
			$parentInfo = vB_Api::instanceInternal('node')->getNodes($parents);

			foreach ($parents AS $nodeid => $parentid)
			{
				foreach ($parentInfo AS $info)
				{
					if ($info['nodeid'] == $parentid)
					{
						$nodes[$nodeid]['parent'] = $info;
					}
				}
			}
		}
		$this->addOptionalContentInfo($nodes, $options);
		$this->markSubscribed($nodes);
		$return = array('nodes' => $nodes);
		if (isset($totalCount))
		{
			$return['totalcount'] = $totalCount;
		}
		else
		{
			$return['totalcount'] = count($nodes);
		}

		if (isset($pageInfo) AND !empty($pageInfo))
		{
			$return['pageInfo'] = $pageInfo;
		}
		return $return;
	}

	/**
	 * Sets or unsets the approved field
	 * @param array $nodeids
	 * @param boolean $approved - set or unset the approved field
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	public function setApproved($approveNodeIds, $approved = true)
	{
		if (empty($approveNodeIds))
		{
			return false;
		}

		$loginfo = array();
		$nodeIds = array();

		foreach ($approveNodeIds AS $idx => $id)
		{
			$nodeInfo = $this->getNode($id);
			if ($nodeInfo['deleteuserid'])
			{
				// Do not do approve/unapprove actions on deleted posts
				continue;
			}

			if (!empty($nodeInfo['errors']))
			{
				continue;
			}

			if (!$nodeInfo['approved'] AND !$approved)
			{
				continue;
			}

			if ($nodeInfo['approved'] AND $approved)
			{
				continue;
			}

			$nodeIds[] = $nodeInfo['nodeid'];

			$loginfo[] = array(
				'nodeid'       => $nodeInfo['nodeid'],
				'nodetitle'    => $nodeInfo['title'],
				'nodeusername' => $nodeInfo['authorname'],
				'nodeuserid'   => $nodeInfo['userid']
			);
		}

		if (empty($nodeIds))
		{
			return false;
		}

		$nodes = $this->getNodes($nodeIds);

		$errors = array();
		$assertor = vB::getDbAssertor();

		$result = $assertor->update('vBForum:node', array('approved' => $approved), array('nodeid' => $nodeIds));

		if (!empty($result['errors']))
		{
			$errors[] = $result['errors'];
		}

		$method = empty($approved) ? 'unapproveNode' : 'approveNode';
		$result = $assertor->assertQuery('vBForum:' . $method, array('nodeid' => $nodeIds));

		// Report as ham if this node was spam..
		if ($method == 'approveNode')
		{
			$vboptions = vB::getDatastore()->getValue('options');
			if ($vboptions['vb_antispam_type'] AND $vboptions['vb_antispam_key'])
			{
				$spamids = array();
				$spamcheck = $assertor->getRows('spamlog', array(
					'nodeid' => $nodeIds,
				));

				foreach ($spamcheck AS $spam)
				{
					$spamids[] = $spam['nodeid'];
				}

				if ($spamids)
				{
					$nodes = $this->getContentforNodes($spamids);
					$akismet = vB_Akismet::instance();
					foreach ($nodes AS $node)
					{
						if ($node['content']['rawtext'])
						{
							$text = vB_String::stripBbcode($node['content']['rawtext'], true);
							$akismet->markAsHam(
								array(
									'comment_type'    => 'comment',
									'comment_author'  => $node['content']['authorname'],
									'comment_content' => $text,
									'user_ip'         => $node['content']['ipaddress']
							));
						}
					}
					$assertor->delete('spamlog', array('nodeid' => $spamids));
				}
			}
		}

		if (!empty($result['errors']))
		{
			$errors[] = $result['errors'];
		}

		$nodeIds = array_unique($nodeIds);

		//these fixes will handle all children of an affected node.
		//updateing things twice for a given subtree causes bad results so let's trim our list.
		$toplevelids = $this->removeDescendants($assertor, $nodeIds);
		foreach ($toplevelids AS $nodeid)
		{
			$orignode = $nodes[$nodeid];

			if ($orignode['showpublished'])
			{
				$nodeUpdates = $this->publishChildren($orignode['nodeid']);
			}
			else
			{
				$nodeUpdates = $this->unpublishChildren($orignode['nodeid']);
			}

			/*
				updateLastForSubtree() updates the lastcontent, lastcontentid etc for the
				unapproved node & descendants, while updateChangedNodeParentCounts() updates
				the affected ancestors (via fixNodeLast()).
			*/

			//we must update the last nodes for the subtree before handling the parents, otherwise it won't work.
			$this->updateLastForSubtree($nodeid);

			//note that
			$this->updateChangedNodeParentCounts($orignode, $nodeUpdates);

			// Update the user post count (approve / unapprove)
			vB_Cache::allCacheEvent('nodeChg_' . $nodeid);
			$contentLib = vB_Library_Content::getContentLib($orignode['contenttypeid']);
			if ($approved)
			{
				$contentLib->incrementUserPostCount($orignode);
			}
			else
			{
				$contentLib->decrementUserPostCount($orignode, 'unapprove');
			}
		}

		$searchLib = vB_Library::instance('search');
		foreach ($nodeIds AS $nodeid)
		{
			$searchLib->attributeChanged($nodeid);
		}

		$this->clearCacheEvents($nodeIds);
		$this->clearChildCache($nodeIds);

		if (!empty($errors))
		{
			return array('errors' => $errors);
		}

		vB_Library_Admin::logModeratorAction($loginfo, ($approved ? 'node_approved_by_x' : 'node_unapproved_by_x'));

		return $nodeIds;
	}

	/**
	 * Approves a post. Since the publish date might be affected user will need moderate and
	 * publish posts permissions.
	 *
	 * @param	int		Id from the node we are approving.
	 * @param	int		Boolean used to set or unset the approved value
	 *
	 * @deprecated
	 * @return	bool	Flag to indicate if approving went succesfully done (true/false).
	 */
	public function setApprovedPost($nodeid = false, $approved = false)
	{
		return $this->setApproved($nodeid, $approved);
	}


	/**
	 * Clears the cache events from a given list of nodes.
	 * Useful to keep search results updated due node changes.
	 *
	 * This will aggressively detect and clear cache for associated nodes
	 * (but not any decendants)
	 *
	 * @param	array		List of node ids to clear cached results.
	 * @return boolean
	 */
	public function clearCacheEvents($nodeIds)
	{
		if (empty($nodeIds))
		{
			return false;
		}

		if (!is_array($nodeIds))
		{
			$nodeIds = array($nodeIds);
		}

		$cachedNodes = array();
		$notCached = array();
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		foreach($nodeIds AS $nodeid)
		{
			$cachedNodes['nodeChg_' . $nodeid] = 'nodeChg_' . $nodeid;

			$hashKey = 'node_' . $nodeid . "_lvl3data";
			$cached = $cache->read($hashKey);

			//We need the parent, starter, and channel. Let's see if we have those in fast cache.
			if ($cached)
			{
				foreach(array('starter', 'parentid', 'channelid') AS $field)
				{
					$cachedNodes['nodeChg_' . $cached[$field]] = 'nodeChg_' . $cached[$field];
				}
			}
			else
			{
				$notCached[] = $nodeid;
			}
		}

		if (!empty($notCached))
		{
			$parents = $this->fetchClosureParent($notCached);
			foreach ($parents AS $parent)
			{
				$cachedNodes['nodeChg_' . $parent['parent']] = 'nodeChg_' . $parent['parent'];
			}
		}

		try
		{
			vB_Cache::allCacheEvent($cachedNodes);
		}
		catch (Exception $ex)
		{
			throw new vB_Exception_Api($ex->getMessage());
		}

		return true;
	}

	/**
	 * Fire the node changed event for just the nodes in the list
	 *
	 * Does not attempt to
	 *
	 * @param int|array $nodeIds
	 */
	public function nodesChanged($nodeIds)
	{
		if (empty($nodeIds))
		{
			return;
		}

		if (!is_array($nodeIds))
		{
			$nodeIds = array($nodeIds);
		}

		$events = array();
		foreach($nodeIds AS $nodeId)
		{
			$events['nodeChg_' . $nodeId] = 1;
		}

		vB_Cache::allCacheEvent(array_keys($events));
	}

	/**
	 * Mark multiple nodes read
	 *
	 * @param $nodeids Node Ids
	 *
	 * @return	array	Returns an array of nodes that were marked as read
	 */
	public function markReadMultiple($nodeids)
	{
		$nodes_marked = array();
		foreach ($nodeids as $nodeid)
		{
			$nodeid = intval($nodeid);

			if ($nodeid)
			{
				$nodes_marked = array_merge($this->markRead($nodeid), $nodes_marked);
			}
		}

		return $nodes_marked;
	}

	/**
	 * Mark multiple nodes unread
	 *
	 * @param $nodeids Node Ids
	 *
	 * @return	array	Returns an array of nodes that were marked as unread
	 */
	public function markUnreadMultiple($nodeids)
	{
		$nodes_marked = array();
		foreach ($nodeids as $nodeid)
		{
			$nodeid = intval($nodeid);

			if ($nodeid)
			{
				$nodes_marked = array_merge($this->markUnread($nodeid), $nodes_marked);
			}
		}

		return $nodes_marked;
	}

	/**
	* Marks a node as read using the appropriate method.
	*
	* @param int $nodeid The ID of node being marked. The node should be a channel or starter.
	*
	* @return	array	Returns an array of nodes that were marked as read
	*/
	public function markRead($nodeid)
	{
		$datastore = vB::getDatastore();
		$db = vB::getDbAssertor();

		$userid = vB::getCurrentSession()->get('userid');
		$threadMarking = $datastore->getOption('threadmarking');


		if (!empty($nodeid) AND !empty($userid))
		{
			$node = $this->getNodeBare($nodeid);
			// read notifications regardless of threadmarking
			vB_Library::instance("notification")->triggerNotificationEvent('read_topic', array('nodeid' => $node['starter']));
		}
		else
		{
			return array();
		}

		if (!$threadMarking)
		{
			//!$threadMarking  means Cookie based read marking. Handled by presentation.
			return array();
		}

		//node marking only makes sense for channels and starters
		if ($node['contenttypeid'] == $this->channelTypeId)
		{
			return $this->markChannelsRead($nodeid);
		}
		else if ($node['starter'] != $node['nodeid'])
		{
			return array();
		}
		$timenow = vB::getRequest()->getTimeNow();
		$nodes_marked = array($nodeid);

		// Automatic channel read marking (marking forums read when all posts are read)
		// This is actually a very complicated thing to think about.  We want to mark a channel read
		// when all of it decendents are read.  But each starter has it's own read record and each of
		// it's parents does as well and in theory we should be checking each of them to determine if
		// a starter is read.  Thus a channel high in the tree could have numerous thresholds to look
		// at for figuring out if the starters underneath it are read and the logic to figure that out
		// becomes both insanely complex and time consuming.  We'll simplify using the following rules
		// (which is similar to how it worked in vB4).
		//
		// A channel will be marked read if:
		// 1) All of the starters that have it as a parent are marked read (either due to their own
		// 	readmarking, due to the parent channel's readmarking, or because they are older than
		// 	the overall. marking limit).
		// 2) All of the channels that have it as a parent are read.  Due to the child channels readmarking or the global marking limit.
		// 	We will only consider child channels that the user can view -- if there are unread hidden channels
		// 	they will not prevent their parent from being marked read.
		//
		//	We will not look at the children of the child channels.  If they child channels are marked
		//	read then all of there children should be.  If they are not marked read (their lastupdate is
		//	greater than their readmarking) then they aren't read even if all of their children are
		//	(this can happen if the last child was read when automatic read marking is off which
		//	shouldn't be a common occurance).
		//
		//	It's also possible that we can get wrong results if our data is out of sync (due to a
		//	script timeout or other failure a automatic readmarking doesn't get registered or the
		//	channel lastcontent doesn't get updated.  We can't worry about that excessively.
		//
		if ($threadMarking == 2)
		{
			$cutoff = $timenow - ($datastore->getOption('markinglimit') * 86400);
			$channelPerms = vB::getUserContext()->getAllChannelAccess();

			$parents = $this->getParentIds($nodeid);
			foreach($parents AS $parentid)
			{
				$result = $db->getRow('vBForum:getChannelRead', array(
					'channelid' => $parentid,
					'userid' => $userid,
					'channelcontenttypeid' => $this->channelTypeId,
					'canview' => array_merge($channelPerms['canview'], $channelPerms['canalwaysview'], $channelPerms['canmoderate']),
					'cutoff' => $cutoff,
					'nodesmarked' => $nodes_marked,
				));

				//if this forum isn't read, then the parent won't be either.
				if ($result['count'] > 0)
				{
					break;
				}

				$nodes_marked[] = $parentid;
			}
		}

		$db->assertQuery('vBForum:nodeMarkread', array('nodeid' => $nodes_marked, 'userid' => $userid, 'readtime' => $timenow));
		return $nodes_marked;
	}

	/**
	 * Marks a node as unread using the appropriate method.
	 *
	 * @param int $nodeid The ID of node being marked
	 *
	 * @return	array	Returns an array of nodes that were marked as unread
	 */
	public function markUnread($nodeid)
	{
		$userid = vB::getCurrentSession()->get('userid');
		$threadMarking = vB::getDatastore()->getOption('threadmarking');

		if (empty($userid) OR !$threadMarking OR empty($nodeid))
		{
			//!$threadMarking  means Cookie based read marking. Handled by presentation.
			return array();
		}

		$node = $this->getNodeBare($nodeid);

		//node marking only makes sense for channels and starters
		if ($node['contenttypeid'] == $this->channelTypeId)
		{
			return $this->markChannelsUnread($nodeid);
		}
		else if ($node['starter'] != $node['nodeid'])
		{
			return array();
		}

		$nodes_marked = array($nodeid);

		if ($threadMarking == 2)
		{
			vB::getDbAssertor()->delete('noderead', array('nodeid' => $nodes_marked, 'userid' => $userid));
		}
		return $nodes_marked;
	}

	/**
	* Marks a channel, its child channels and all contained topics as read
	*
	* @param int $nodeid The node ID of channel being marked. If 0, all channels will be marked as read
	*
	* @return	array	Returns an array of channel ids that were marked as read
	*/
	public function markChannelsRead($nodeid = 0)
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!$userid)
		{
			// Guest call
			return array();
		}

		// read notifications regardless of threadmarking
		if ($nodeid)
		{
			vB_Library::instance("notification")->triggerNotificationEvent('read_channel', array('nodeid' => $nodeid));
		}
		else
		{
			$rootchannelid = vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);
			vB_Library::instance("notification")->triggerNotificationEvent('read_channel', array('nodeid' => $rootchannelid));
		}

		$threadmarking = vB::getDatastore()->getOption('threadmarking');

		if (!$threadmarking)
		{
			return array();
		}
		$timenow = vB::getRequest()->getTimeNow();
		//Here's a trick. If the oldest content in a topic is older than the age limit, don't bother marking it.
		$cutoff = $timenow - (vB::getDatastore()->getOption('markinglimit') * 86400);
		$return_channels = array();

		if ($nodeid)
		{
			$node = $this->getNode($nodeid);
			if ($node['contenttypeid'] != $this->channelTypeId)
			{
				return array();
			}
		}
		else
		{
			//this will be set above but only if $nodeid is 0
			$nodeid = $rootchannelid;
		}
		$assertor = vB::getDbAssertor();
		$channelPerms = vB::getUserContext()->getAllChannelAccess();
		$canview = array_merge($channelPerms['canview'], $channelPerms['canalwaysview'], $channelPerms['canmoderate']);
		$toMarkQry = $assertor->assertQuery(
			'getChannelsToMark',
			array('nodeid' => $nodeid,
			'canview' => $canview,
			'cutoff' => $cutoff
		));

		foreach ($toMarkQry AS $nodes)
		{
			$return_channels[] = $nodes['nodeid'];
		}
		// mark the channel and all child channels read
		$assertor->assertQuery('channelsMarkRead', array(
			'nodeid' => $nodeid,
			'userid' => $userid,
			'readtime' => $timenow,
			'canview' => $canview,
			'cutoff' => $cutoff
		));

		if ($threadmarking == 2)
		{
			$assertor->assertQuery('startersMarkRead', array(
				'nodeid' => $nodeid,
				'userid' => $userid,
				'readtime' => $timenow,
				'canview' => $canview,
				'cutoff' => $cutoff
			));
		}

		return $return_channels;
	}

	/**
	 * Marks a channel as unread
	 *
	 * @param int $nodeid The node ID of channel being marked. If 0, all channels will be marked as unread
	 *
	 * @return	array	Returns an array of channel ids that were marked as unread
	 */
	public function markChannelsUnread($nodeid = 0)
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!$userid)
		{
			// Guest call
			return array();
		}

		$threadmarking = vB::getDatastore()->getOption('threadmarking');

		if (!$threadmarking)
		{
			return array();
		}
		$timenow = vB::getRequest()->getTimeNow();
		$return_channels = array();

		if ($nodeid)
		{
			$node = $this->getNode($nodeid);
			if ($node['contenttypeid'] != $this->channelTypeId)
			{
				return array();
			}
		}
		else
		{
			$nodeid = 1;
		}
		$assertor = vB::getDbAssertor();
		$channelPerms = vB::getUserContext()->getAllChannelAccess();
		$canview = array_merge($channelPerms['canview'], $channelPerms['canalwaysview'], $channelPerms['canmoderate']);
		$toMarkQry = $assertor->assertQuery('getChannelsToMark', array('nodeid' => $nodeid, 'canview' => $canview, 'cutoff' => 0));

		foreach ($toMarkQry AS $nodes)
		{
			$return_channels[] = $nodes['nodeid'];
		}

		// mark the channel unread
		vB::getDbAssertor()->delete('noderead', array('nodeid' => $return_channels, 'userid' => $userid));

		return $return_channels;
	}

	/**
	 * marks nodes with "subscribed" true/false
	 *
	 * @param	array	list of nodes, normally with a content array.
	 **/
	public function markSubscribed(&$nodes)
	{
		$following = vB_Api::instanceInternal('follow')->getFollowingParameters();
		$check = array();
		foreach ($nodes AS $key => &$node)
		{
			if (array_key_exists('content', $node))
			{
				$node['content']['subscribed'] = 0;
			}
			else
			{
				$node['subscribed'] = 0;
			}
			$check[$node['nodeid']]	= $key;
		}

		//if this user isn't following anyone, we don't need to do this check.
		if (!empty($following['user']) )
		{
			foreach ($nodes AS $key => &$node)
			{
				//work around inconsistencies in node array formatting
				$userid = isset($node['userid']) ? $node['userid'] : $node['content']['userid'];
				if (in_array($userid, $following['user']))
				{
					$node['content']['subscribed'] = 1;
				}
			}
		}

		//if there's nothing to check and no followed content, we're done.
		if (empty($check) or (empty($following['content']) AND empty($following['member'])))
		{
			return;
		}
		//We have both followed nodes and content, so we need to run a query and check.
		$followNodes = array_merge($following['content'], $following['member']);
		$clParents = $this->fetchClosureParent(array_keys($check));
		$parents = array();
		foreach ($clParents AS $parent)
		{
			//We have a child value in $closureRec['child'] is an index into $check, which gives an index into $nodes;
			if (in_array($parent['parent'], $followNodes))
			{
				$nodeKey = $check[$parent['child']];
				//This node is followed.
				if (array_key_exists('content', $nodes[$nodeKey]))
				{
					$nodes[$nodeKey]['content']['subscribed'] = 1;
				}
				else
				{
					$nodes[$nodeKey]['subscribed'] = 0;
				}
			}
		}
	}

	/**
	 * Returns closure table information given a child id
	 *
	 *	@param	mixed	child nodeid or array of nodeids
	 * 	@param	int		optional parent nodeid
	 *
	 * 	@return	mixed	array of closure table records
	 */
	public function fetchClosureParent($childids, $parentid = false)
	{
		static $cachedChildIds = array();
		//find what we have in fastcache.
		if (!is_array($childids))
		{
			$childids = array($childids);
		}

		$cachedChildIds = array_unique(array_merge($cachedChildIds, $childids));
		vB_Library::instance('page')->registerPrecacheInfo('node', 'fetchClosureParent', $cachedChildIds);
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);

		$found = array();
		$notfound = array();
		foreach ($childids AS $childid)
		{
			$data = $cache->read("vBClParents_$childid");
			//todo: Shouldn't we check for if $data !== false, since we mark "no data" with 0's???
			if ($data)
			{
				//we marked any id's that don't have data with zero. In that case we return no results.
				if ($data === 0 )
				{
					continue;
				}

				if (($parentid === false) OR !is_numeric($parentid))
				{
					$found = array_merge($found, $data);
				}
				else
				{
					foreach ($data as $closure)
					{
						if ($closure['parent'] == $parentid)
						{
							$found[] = $closure;
							break;
						}
					}
				}
			}
			else
			{
				$notfound[$childid] = $childid;
			}
		}

		//if we got everything, we're done.
		if (empty($notfound))
		{
			return $found;
		}

		//Search for what's left
		//Note that even if we were passed a parentid we still get the complete ancestry and cache it.
		$closureRecs = vB::getDbAssertor()->assertQuery('vBForum:closure',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'child' => $notfound
			),
			array(
				'field' => (array('child', 'depth')),
				'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC)
			)
		);

		//Now we build the results and cache the values;
		$cacheValues = array();
		$cacheEvents = array();
		foreach ($closureRecs AS $closure)
		{
			$__childid = $closure['child'];
			$__parentid = $closure['parent'];

			if (empty($parentid) OR $parentid == $__parentid)
			{
				$found[] = $closure;
				unset($notfound[$__childid]);
			}

			// the cached arrays are unkeyed according to the fetch/lookup above. Which is a shame because we could just key by parentid and not have
			// to loop through $data and skip a O(n). Going to leave it unkeyed for stability for now.
			$cacheValues[$__childid][] = $closure;
			$cacheEvents[$__childid][] = 'nodeChg_' . $__parentid;
		}

		foreach ($cacheValues AS $__childid => $cacheValue)
		{
			$cache->write("vBClParents_{$__childid}", $cacheValue, 1440, $cacheEvents[$__childid]);
		}


		//Any remaining records in $notfound are for nodes that aren't in the closure table.
		// we'll cache those with value zero so we don't query again.
		foreach ($notfound AS $childid)
		{
			$cache->write("vBClParents_$childid", 0, 1440, "nodeChg_$childid");
		}

		return $found;
	}


	/**
	 * 	Returns closure table information given a child id
	 *
	 *	@param	mixed	parent nodeid or array of nodeids
	 *
	 * 	@return	mixed	array of closure table records
	 */
	public function fetchClosurechildren($parentids)
	{
		//find what we have in fastcache.
		if (!is_array($parentids))
		{
			$parentids = array($parentids);
		}
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$found = array();
		$notfound = array();
		foreach ($parentids AS $parentid)
		{
			$data = $cache->read("vBClChildren_$parentid");
			//we marked any id's that don't have data with zero. In that case we return no results.
			if ($data)
			{
				$found[$parentid] = $data;
			}
			else if ($data !== 0)
			{
				$notfound[$parentid] = $parentid;
			}
		}

		//if we got everything, we're done.
		if (empty($notfound))
		{
			return $found;
		}

		//Search for what's left
		//Note that even if we were passed a parentid we still get the complete ancestry and cache it.
		$closureRecs = vB::getDbAssertor()->assertQuery('vBForum:closure', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'parent' => $notfound), array('field' => array('parent', 'depth'),
			'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_DESC)));

		//Now we build the results and cache the values;
		$thisParent = false;
		foreach ($closureRecs AS $closure)
		{
			//If we changed child id values and this isn't the first value, write to cache
			// and start building the ancestry for the new child.
			if ($thisParent != $closure['parent'])
			{
				if ($thisParent)
				{
					$cache->write("vBClChildren_$thisParent", $cacheValue, 1440, $cacheEvents);
					unset($notfound[$thisParent]);
					$found[$thisParent] = $cacheValue;
				}

				$cacheValue = array();
				$cacheEvents = array();
				$thisParent = $closure['parent'];
			}

			$cacheValue[] = $closure;
			$cacheEvents[] = 'nodeChg_' . $closure['child'];
		}

		if ($thisParent)
		{
			$found[$thisParent] = $cacheValue;
			$cache->write("vBClChildren_$thisParent", $cacheValue, 1440, $cacheEvents);
			unset($notfound[$thisParent]);
		}


		//Any remaining records in $notfound are for nodes that aren't in the closure table.
		// we'll cache those with value zero so we don't query again.
		foreach ($notfound AS $parentid)
		{
			$cache->write("vBClChildren_$parentid", 0, 1440, "nodeChg_$parentid");
		}

		return $found;
	}

	/**
	 * 	This creates a request for access to a channel
	 *
	 *	@param		int		$channelid		the nodeid of the channel to which access is requested.
	 *	@param		string	$requestType	the type of request. See vB_Api_Node::REQUEST_<> constants
	 *	@param		int		$recipient		the userid of the member who will get the request
	 *	@param		string	$recipientname	(Optional) the username of the member who will get the request
	 *	@param		boolean	$skipFloodCheck	(Optional) whether request private message should skip flood check or not
	 *
	 *	@return		mixed 	If it is 1 or true, then it means that the follow request was successful.
	 *							If it is integer and greater than 1, then the request is pending.
	 */
	public function requestChannel($channelid, $requestType, $recipient = 0, $recipientname = null, $skipFloodCheck = false)
	{
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];

		if (!($userid > 0))
		{
			throw new vB_Exception_API('not_logged_no_permission');
		}

		$validRequests = array(
			vB_Api_Node::REQUEST_TAKE_OWNER,
			vB_Api_Node::REQUEST_TAKE_MODERATOR,
			vB_Api_Node::REQUEST_TAKE_MEMBER,
			vB_Api_Node::REQUEST_GRANT_OWNER,
			vB_Api_Node::REQUEST_GRANT_MODERATOR,
			vB_Api_Node::REQUEST_GRANT_MEMBER,
			vB_Api_Node::REQUEST_SG_TAKE_OWNER,
			vB_Api_Node::REQUEST_SG_TAKE_MODERATOR,
			vB_Api_Node::REQUEST_SG_TAKE_MEMBER,
			vB_Api_Node::REQUEST_SG_GRANT_OWNER,
			vB_Api_Node::REQUEST_SG_GRANT_MODERATOR,
			vB_Api_Node::REQUEST_SG_GRANT_MEMBER,
			vB_Api_Node::REQUEST_TAKE_SUBSCRIBER,
			vB_Api_Node::REQUEST_GRANT_SUBSCRIBER,
			vB_Api_Node::REQUEST_SG_TAKE_SUBSCRIBER,
			vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER,
		);

		//make sure the parameters are valid
		if (!intval($channelid) OR !intval($channelid) OR !in_array($requestType,	$validRequests))
		{
			throw new vB_Exception_API('invalid_data');
		}


		$node = $this->getNode($channelid);

		if ($node['contenttypeid'] != vB_Types::instance()->getContentTypeId('vBForum_Channel'))
		{
			throw new vB_Exception_API('invalid_request');
		}

		//Let's make sure the user can grant this request.
		if (in_array($requestType, array(
				vB_Api_Node::REQUEST_TAKE_OWNER,
				vB_Api_Node::REQUEST_TAKE_MODERATOR,
				vB_Api_Node::REQUEST_TAKE_MEMBER,
				vB_Api_Node::REQUEST_SG_TAKE_OWNER,
				vB_Api_Node::REQUEST_SG_TAKE_MODERATOR,
				vB_Api_Node::REQUEST_SG_TAKE_MEMBER,
			)))
		{
			//Can we grant the transfer?
			$userContext = vB::getUserContext();
			if (!$userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $channelid))
			{
				throw new vB_Exception_API('no_permission');
			}

			if ($recipient <= 0)
			{
				$recipient = $this->getRecipientFromName($recipientname);
			}
		}
		else
		{
			// join is not valid when invite only...
			if (in_array($requestType, array(vB_Api_Node::REQUEST_GRANT_MEMBER, vB_Api_Node::REQUEST_SG_GRANT_MEMBER)) AND
				(($node['nodeoptions'] & vB_Api_Node::OPTION_NODE_INVITEONLY) > 0))
			{
				throw new vB_Exception_Api('invalid_invite_only_request');
			}

			//if this is set to auto-approve we don't need to send a request.
			if (in_array($requestType, array(vB_Api_Node::REQUEST_GRANT_MEMBER, vB_Api_Node::REQUEST_SG_GRANT_MEMBER)) AND
				(($node['nodeoptions'] & vB_Api_Node::OPTION_AUTOAPPROVE_MEMBERSHIP) > 0))
			{
				$isBlog = vB_Api::instanceInternal('blog')->isBlogNode($channelid);
				$group = vB::getDbAssertor()->getRow('usergroup', array('systemgroupid' => vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID));
				if ($isBlog)
				{
					// clear follow cache
					vB_Api::instanceInternal('follow')->clearFollowCache(array($userid));
				}

				// return boolean true if successful
				$result = vB_User::setGroupInTopic($userid, $channelid, $group['usergroupid']);

				// for join requests, check for auto-subscribe & add subscription for user
				if ( ($result === true) AND ($node['nodeoptions'] & vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN) )
				{
					vB_Api::instanceInternal('follow')->add($channelid, vB_Api_Follow::FOLLOWTYPE_CHANNELS, $userid, true);
				}

				return $result;
			}

			if (in_array($requestType, array(vB_Api_Node::REQUEST_GRANT_SUBSCRIBER, vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER)))
			{
				// subscribe means join in blog's context
				try
				{
					//	@TODO check if using only the canview perms is fair enough... there might be cases where sg owner set
					//	canview perms for everyone that includes no joined members, even not logged users...
					if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $channelid))
					{
						throw new vB_Exception_Api('invalid_special_channel_subscribe_request');
					}

					// check the auto accept first
					if (($node['nodeoptions'] & vB_Api_Node::OPTION_AUTOAPPROVE_SUBSCRIPTION) > 0)
					{
						// return int  1 - Following for auto-approved subscriptions
						return $response = vB_Api::instanceInternal('follow')->add($channelid, vB_Api_Follow::FOLLOWTYPE_CONTENT);
					}

					//see if this is set to invite only
					if (($node['nodeoptions'] & vB_Api_Node::OPTION_NODE_INVITEONLY) > 0  )
					{
						throw new vB_Exception_Api('invalid_special_channel_subscribe_request');
					}

					$owner = vB_Api::instanceInternal('blog')->fetchOwner($channelid);
					if (!$owner)
					{
						$recipient = $node['userid'];
					}
					else
					{
						$recipient = $owner;
					}
				}
				catch (vB_Exception_Api $ex)
				{
					throw $ex;
				}
			}

			//if the channel is set to OPTION_AUTOAPPROVE_SUBSCRIPTION we may not need, or have, a valid
			//recipient, so let's not look it up until we know we need it.
			if ($recipient <= 0)
			{
				$recipient = $this->getRecipientFromName($recipientname);
			}

			//Can the recipient grant the transfer?
			$userContext = vB::getUserContext($recipient);
			if (!$userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $channelid ))
			{
				throw new vB_Exception_API('no_permission');
			}
		}

		$messageLib = vB_Library::instance('content_privatemessage');
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		$data = array(
			'msgtype' => 'request',
			'about' => $requestType,
			'sentto' => $recipient,
			'aboutid' => $channelid,
			'sender' => $userInfo['userid'],
		);

		// return int nodeid of created pending request
		if ($skipFloodCheck)
		{
			$result = $messageLib->addMessageNoFlood($data);
			return $result;
		}
		else
		{
			$result = $messageLib->add($data);
			return $result['nodeid'];
		}
	}

	private function getRecipientFromName($recipientname)
	{
		if (!empty($recipientname))
		{
			// fetch by username
			$recipient = vB::getDbAssertor()->getField('user', array('username' => $recipientname));

			if (!$recipient)
			{
				throw new vB_Exception_API('invalid_username');
			}
		}
		else
		{
			throw new vB_Exception_API('invalid_username');
		}

		return $recipient;
	}

	/**
	 * Adds the joined flag if the current user is member of content's parent.
	 *
	 * @params	array	Array of the content node list.
	 *
	 */
	protected function markJoined(&$nodes)
	{
		$userid = vB::getCurrentSession()->get('userid');

		foreach ($nodes AS $key => $node)
		{
			$nodes[$key]['joined'] = $nodes[$key]['content']['joined'] = false;
		}

		$parents = array();
		foreach ($nodes AS $key => $node)
		{
			if (empty($node['parents']))
			{
				$nodes[$key]['parents'] = $this->getNodeParents($node['nodeid']);
			}
		}

		// guests can't be members
		if ($userid < 1)
		{
			return false;
		}

		$joinedInfo = vB::getUserContext()->fetchGroupInTopic();
		foreach ($nodes AS $key => $node)
		{
			if (isset($joined[$node['nodeid']]))
			{
				$nodes[$key]['joined'] = $nodes[$key]['content']['joined'] = 1;
			}
			else if (!empty($node['parents']))
			{

				foreach($node['parents'] AS $parent)
				{
						//We get this information in two ways- parent can be an array or an integer.
					if (is_array($parent))
					{
						$parentid = $parent['parent'];
					}
					else if (is_numeric($parent))
					{
						$parentid = $parent;
					}
					else
					{
						continue;
					}

					if (isset($joinedInfo[$parentid]))
					{
						$nodes[$key]['joined'] = $nodes[$key]['content']['joined'] = 1;
						break;
					}
				}
			}
		}
	}


	/**
	 * Returns the ancestry
	 *
	 * 	@param	int		nodeid
	 * 	@return	mixed	array of partial node records -- in ascending order of depth
	 */
	public function getParents($nodeid)
	{
		return vB::getDbAssertor()->getRows('vBForum:getParents', array('nodeid' => $nodeid));
	}

	private function getParentIds($nodeid)
	{
		$parents = $this->getParents($nodeid);
		$parentids = array();
		//The first record will be the node itself.
		foreach ($parents AS $parent)
		{
			if ($parent['nodeid'] == $nodeid)
			{
				continue;
			}
			$parentids[] = $parent['nodeid'];
		}

		return $parentids;
	}

	private function removeDescendants($db, $nodeids)
	{
		$ids = array_unique($nodeids);

		$filter =  array(
			'parent' => $ids,
			'child' => $ids,
			array('field' => 'depth', 'value' => 0, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_GT)
		);

		$children = $db->getColumn('vBForum:closure', 'child', array(vB_Db_Query::CONDITIONS_KEY => $filter), false, 'child');
		return array_diff($ids, $children);
	}

	/**
	 * Returns node children
	 *
	 * 	@param	int		nodeid
	 * 	@return	mixed	array of partial node records
	 */
	public function getChildren($nodeid)
	{
		$cacheKey = "vB_Childs_$nodeid";
		$childs = vB_Cache::instance(vB_Cache::CACHE_FAST)->read($cacheKey);
		if ($childs !== false)
		{
			return $childs;
		}

		$childs = vB::getDbAssertor()->getRows('vBForum:getChildren', array('nodeid' => $nodeid));
		vB_Cache::instance(vB_Cache::CACHE_FAST)->write($cacheKey, $childs, 1440, "nodeChg_$nodeid");
		return $childs;
	}

	/**
	 * Check if the user has permission for edit the thread title also check the option editthreadtitlelimit
	 * if we pass the time and we are not moderators we can edit the thread title
	 * @param integer $nodeid
	 *
	 */
	public function canEditThreadTitle($nodeid, $node = false)
	{
		static $threadLimit = false;
		$userid = vB::getCurrentSession()->get('userid');

		if ($userid == 0)
		{
			return false;
		}

		$userContext = vB::getUserContext();

		if ($userContext->isSuperAdmin())
		{
			return true;
		}

		if ($threadLimit === false)
		{
			$threadLimit = vB::getDatastore()->getOption('editthreadtitlelimit');
		}

		//grab the options and the info of the node
		if (empty($node))
		{
			$node = $this->getNode($nodeid);
		}

		//check if user have moderator permissions or pass the time limit
		//The original creator can change for some period
		//A user with caneditothers should be able to bypass the time limit, VBV-12182
		if (vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid))
		{
			return true;
		}
		else if (($node['userid'] == $userid)
			AND (($threadLimit == 0 ) OR ($node['publishdate'] + ($threadLimit * 60) > vB::getRequest()->getTimeNow()))
			)
		{
			return true;
		}
		else if (
			($node['userid'] != $userid) AND
			vB::getUserContext()->getChannelPermission('forumpermissions2', 'caneditothers', $nodeid)
		)
		{
			return true;
		}

		return false;
	}

	/**
	 * Gets a list of the content types that change text type
	 * @return array(int)
	 */
	public function getTextChangeTypes()
	{
		static $changeTypes = false;

		if ($changeTypes)
		{
			return $changeTypes;
		}
		$hashKey = 'vb_textchangetypes';
		$changeTypes = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($hashKey);

		if (empty($changeTypes))
		{
			$changeTypes = array();
			$types = vB_Types::instance()->getContentTypes();
			foreach ($types AS $type)
			{
				try
				{
					$contentLib = vB_Library_Content::getContentLib($type['id']);

					if (!empty($contentLib))
					{
						$textCountChange = $contentLib->getTextCountChange();

						if ($textCountChange > 0)
						{
							$changeTypes[$type['id']] = $type['id'];
						}
					}
				}
				catch (exception $e) //This is a normal occurence- just keep going.
				{}
			}
		}
		return $changeTypes;
	}

	/**
	 * Set the node options
	 *
	 * @param	mixed	array|int $nodeid
	 *
	 * @return either 1 or an error message.
	 */
	public function setNodeOptions($nodeid, $options = false)
	{
		if (empty($nodeid) OR !intval($nodeid) OR ($options === false))
		{
			return;
		}

		$optionsInfo = $this->options;
		if (is_numeric($options))
		{
			$newOptions = 0;
			//Still check each bitfield
			foreach ($optionsInfo as $key => $value)
			{
				if ($options & $value)
				{
					$newOptions += $value;
				}
			}
		}
		else
		{
			$current = $this->getNode($nodeid);
			$newOptions = $current['nodeoptions'];
			foreach ($optionsInfo as $key => $value)
			{
				if (isset($options[$key]))
				{
					if (intval($options[$key]))
					{
						$newOptions = $newOptions | $value;
					}
					else
					{
						$newOptions = $newOptions & ~intval($value);
					}
				}
			}
		}
		//And we set the value.
		$result = vB::getDbAssertor()->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'nodeid' => $nodeid, 'nodeoptions' => $newOptions));
		$this->clearCacheEvents($nodeid);
		return $result;
	}

	/**
	 * gets the node option as an array of values
	 *
	 * 	@param	int		nodeid of the desired record
	 *
	 *	@return	array 	associative array of bitfield name => 0 or 1
	 */
	public function getNodeOptions($nodeid)
	{
		if (empty($nodeid) OR !intval($nodeid))
		{
			return;
		}

		$node = $this->getNode($nodeid);
		$options = array();

		$nodeOptionsBitfields = $this->options;
		foreach ($nodeOptionsBitfields  as $key => $value)
		{
			if ($node['nodeoptions'] & $value)
			{
				$options[$key] = 1;
			}
			else
			{
				$options[$key] = 0;
			}
		}

		return $options;
	}

	/**
	 * Gets the starter's parent (channel) node
	 * @param array/int $node the node or nodeid
	 */
	public function getChannelId($node)
	{
		if (is_numeric($node))
		{
			$node = $this->getNodeBare($node);
		}

		// this is the channel
		if ($node['starter'] == 0)
		{
			return $node['nodeid'];
		}

		// this is the starter, so the channel is the parent
		if ($node['starter'] == $node['nodeid'])
		{
			return $node['parentid'];
		}

		// this must be a reply
		return $this->getChannelId($node['starter']);
	}

	/**
	 * Undelete a set of nodes
	 * @param array $nodeids
	 * @param boolean is rebuild needed
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have been deleted
	 */
	public function undeleteNodes($nodeids, $needRebuild = false)
	{
		if (empty($nodeids))
		{
			return false;
		}

		$errors = array();
		$events = array();
		$loginfo = array();

		$counts = $updates = array();
		$nodeids = array_unique($nodeids);

		$assertor = vB::getDbAssertor();

		$result = $assertor->assertQuery('vBForum:node', array(
			'nodeid' => $nodeids,
			'deleteuserid' => 0,
			'deletereason' => '',
			'unpublishdate' => 0,
			'showpublished' => 1,
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
		));

		if (!empty($result['errors']))
		{
			$errors[] = $result['errors'];
		}

		$searchLIB = vB_Library::instance('search');
		foreach ($nodeids AS $nodeid)
		{
			$events[] = $nodeid;

			$result = $this->publishChildren($nodeid);

			if (!empty($result['errors']))
			{
				$errors[] = $result['errors'];
			}

			// Clear cache for this node or user post count won't update
			vB_Cache::allCacheEvent('nodeChg_' . $nodeid);
			$node = $this->getNode($nodeid);

			// Update user post count (un(soft)delete)
			vB_Library_Content::getContentLib($node['contenttypeid'])->incrementUserPostCount($node);

			$loginfo[] = array(
				'nodeid'       => $node['nodeid'],
				'nodetitle'    => $node['title'],
				'nodeusername' => $node['authorname'],
				'nodeuserid'   => $node['userid'],
			);

			$parents = $this->fetchClosureParent($nodeid);

			//should look into using updateChangedNodeParentCounts and the result from publishChildren
			//to do this.  But that's beyond the current scope.
			foreach ($parents as $parent)
			{
				$nodeInfo = $this->getNodeBare($parent['parent']);

				if ($nodeInfo['contenttypeid'] == $this->channelTypeId)
				{
				 	$this->fixNodeLast($parent['parent']);
				}
				else
				{
					$this->updateLastForSubtree($parent['parent']);
				}

				switch($parent['depth'])
				{
					case 0: // Actual node.
						vB_Node::fixNodeCount($parent['parent']);
					break;

					case 1: // Immediate parent.
						$parentinfo = $this->getNodeBare($parent['parent']);

						$counts = array(
							'totalcount' => $parentinfo['totalcount'],
							'totalunpubcount' => $parentinfo['totalunpubcount'],
						);

						vB_Node::fixNodeCount($parent['parent']);
						$parentinfo = $this->getNodeBare($parent['parent']);

						$counts = array(
							'totalcount' => $parentinfo['totalcount'] - $counts['totalcount'],
							'totalunpubcount' => $parentinfo['totalunpubcount'] - $counts['totalunpubcount'],
						);
					break;

					default: // Higher parents.
						$updates['totalcount'][$parent['parent']] = $counts['totalcount'];
						$updates['totalunpubcount'][$parent['parent']] = $counts['totalunpubcount'];
					break;
				}
			}

			$assertor->assertQuery('vBForum:updateNodeTotals', array('updates' => $updates));
			$searchLIB->attributeChanged($nodeid);
		}

		$searchLIB->purgeCacheForCurrentUser();
		if ($needRebuild)
		{
			vB::getUserContext()->rebuildGroupAccess();
			vB_Channel::rebuildChannelTypes();
		}

		$this->clearCacheEvents($nodeids);
		$this->clearChildCache($nodeids);

		if (!empty($errors))
		{
			return array('errors' => $errors);
		}

		vB_Library_Admin::logModeratorAction($loginfo, 'node_restored_by_x');

		return $nodeids;
	}

	/**
	 * Returns the userids of the moderators of that node
	 *
	 * @param int $nodeid
	 * @return array
	 */
	public function getNodeModerators($nodeid)
	{
		$nodeid = intval($nodeid);
		$moderators = vB::getDbAssertor()->getRows('vBForum:getNodeModerators', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'nodeid' => $nodeid
		));

		return $moderators;
	}

	/**
	 * Returns forum super moderators and admins
	 * @param int $nodeid
	 * @return array - the userid, username, email of the moderators of the node
	 */
	public function getForumSupermoderatorsAdmins($userids = array())
	{
		// To prevent SQL error if empty array is passed
		$userids = (empty($userids) ? array(-1) : $userids);
		$admins = vB::getDbAssertor()->getRows('vBForum:getSuperModeratorsAdmins', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'userids' => $userids
		));

		return $admins;
	}


	/**
	 * Clone Nodes and their children deeply into a new parent Node.
	 *
	 * @param array $nodeids Source nodeIDs
	 * @param string|int $to_parent Parent node id. If to_parent is a string, it should be a route path to the node
	 * @param string $newtitle If parent is a channel, the oldest post will be promoted to a Thread with the new title.
	 * @return mixed array of origional nodeids as keys, cloned nodeids as values
	 */
	public function cloneNodes($nodeids, $to_parent, $newtitle = '')
	{
		$parentid = $this->assertNodeidStr($to_parent);

		$loginfo = array();
		$parent = $this->getNodeFullContent($parentid);
		$parent = $parent[$parentid];
		$channelTypeid = vB_Types::instance()->getContentTypeId('vBForum_Channel');

		$nodes = vB::getDbAssertor()->getRows('vBForum:node',
			array ('nodeid' => $nodeids),
			array (
				'field' => array('publishdate'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			)
		);

		/*
		 *	Set up information for moderator log
		 */
		foreach ($nodes as $node)
		{
			//Only channels can be moved to categories, UI shouldn't allow this
			if (($node['contenttypeid'] != $channelTypeid) AND (!empty($parent['category'])))
			{
				throw new vB_Exception_Api('invalid_request');
			}

			$oldparent = $this->getNode($node['parentid']);

			$extra = array(
				'fromnodeid'	=> $oldparent['nodeid'],
				'fromtitle'		=> $oldparent['title'],
				'tonodeid'		=> $parent['nodeid'],
				'totitle'		=> $parent['title'],
			);

			$loginfo[] = array(
				'nodeid'		=> $node['nodeid'],
				'nodetitle'		=> $node['title'],
				'nodeusername'	=> $node['authorname'],
				'nodeuserid'	=> $node['userid'],
				'action'		=> $extra,
			);
		}

		/*
		 *	Actually clone the node.
		 */
		$retval = $this->cloneNodesInternal($nodes, $parent, $newtitle);

		vB_Library_Admin::logModeratorAction($loginfo, 'node_copied_by_x');
		return $retval;
	}

	public function cloneNodesInternal($nodes, $parent, $newtitle)
	{
		$db = vB::getDbAssertor();
		$parentid = $parent['nodeid'];

		// A var that stores the relationship 'oldnodeid' => 'newcopiednodeid'
		$oldnewnodes = array();

		reset($nodes);
		$firstNode = current($nodes);

		$newtitleset = false;
		foreach ($nodes as $node)
		{
			$children = $db->assertQuery(
				'vBForum:closure',
				array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,	'parent' => intval($node['nodeid'])),
				array('field' => array('depth'), 'direction' => array(vB_dB_Query::SORT_ASC))
			);

			foreach ($children as $k => $closure)
			{
				$child = $this->getNode($closure['child'], false, false);
				// Clone node record
				$newnodeid = $db->assertQuery('vBForum:cloneNodeRecord', array('table' => 'node', 'oldnodeid' => $child['nodeid']));
				if (!$newnodeid)
				{
					continue;
				}

				$oldnewnodes[$child['nodeid']] = $newnodeid;

				$fields = array();

				//if this is the first node, set it to the new parent
				if ($child['nodeid'] == $firstNode['nodeid'])
				{
					$fields['parentid'] = $parentid;
				}

				//other top level nodes should be moved under the first node
				else if ($closure['depth'] == 0)
				{
					$fields['parentid'] = $oldnewnodes[$firstNode['nodeid']];
				}

				//otherwise its the clone of the original node's parent
				else
				{
					$fields['parentid'] = $oldnewnodes[$child['parentid']];
				}

				if (!empty($fields))
				{
					$db->update('vBForum:node', $fields, array('nodeid' => $newnodeid));
				}

				//Now create the new closure records -- we'll call moved node logic below that
				//will recreate the closure records, but it assumes that there are valid closure records in place
				//so we need to create them.
				// Make sure that level 0 closure of this node exists.
				$db->insert('vBForum:closure', array('parent' => $newnodeid, 'child' => $newnodeid,
					'depth' => 0, 'publishdate' =>  (int) $closure['publishdate']));
				$db->assertQuery('vBForum:insertMovedNodeClosureRecords', array('nodeid' => $newnodeid, 'parentid' => $fields['parentid']));

				// get the relevant tables for the content type
				$api = vB_Api_Content::getContentApi($child['contenttypeid']);
				$tables = $api->fetchTableName();

				$data = array('table' => '', 'oldnodeid' => $child['nodeid'], 'newnodeid' => $newnodeid);
				foreach($tables AS $table)
				{
					$data['table'] = $table;
					$db->assertQuery('vBForum:cloneNodeRecord', $data);
				}

				vB_Cache::allCacheEvent('nodeChg_' . $newnodeid);
			}

			if (!$newtitleset AND !empty($newtitle) AND intval($node['inlist']) AND !intval($node['protected']))
			{
			// Update the title of the oldest inlist node
				$db->assertQuery('vBForum:node', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'title' => $newtitle,
					'htmltitle' => vB_String::htmlSpecialCharsUni(vB_String::stripTags($newtitle), false),
					'urlident' => vB_String::getUrlIdent($newtitle),
					vB_dB_Query::CONDITIONS_KEY => array(
						'nodeid' => $oldnewnodes[$node['nodeid']],
					)
				));
				$newtitleset = true;
			}
		}

		//We've already created the parent structure and the closure structure so in same ways this is
		//overkill.  However moveNodesInternal cleans up a bunch of stuff related to having a new
		//parent that we need to take into account.  A little redundant work is better than not
		//getting all of the details right.  It may be worth refactoring moveNodesInternal
		//to pull out just the logic needed here, but this works and its not a common operation.
		$newparent = $this->getNode($oldnewnodes[$firstNode['nodeid']], false, false);
		$this->moveNodesInternal(array($newparent['nodeid']), $parent);

		$nodeids = array();
		foreach($nodes AS $node)
		{
			if ($node['nodeid'] != $firstNode['nodeid'])
			{
				$nodeids[] = $oldnewnodes[$node['nodeid']];
			}
		}

		if ($nodeids)
		{
			//need to grab the new values for this node.  We could blow out the cache and
			//call get node, but that's overkill for what we need.
			$newparent = $db->getRow('vBForum:node',
				array (
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $newparent['nodeid']
				)
			);
			$this->moveNodesInternal($nodeids, $newparent);
		}

		$this->updateLastForSubtree($newparent['nodeid']);

		//fix the published status of the new tree based on its new location.
		//this includes updating the parents
		$this->updateSubTreePublishStatus($newparent, $parent['showpublished']);

		foreach($oldnewnodes as $newnodeid)
		{
			vB_Cache::allCacheEvent('nodeChg_' . $newnodeid);
		}

		return $oldnewnodes;
	}

	/**
	 * Moves nodes to a new parent
	 *
	 * @param	array	Node ids
	 * @param	int	New parent node id
	 * @param	bool	Make topic
	 * @param	bool	New title
	 * @param	bool	Mod log
	 * @param	array	Information to leave a thread redirect. If empty, no redirect is created.
	 *			If not empty, should contain these items:
	 *				redirect (string) - perm|expires	Permanent or expiring redirect
	 *				frame (string) - h|d|w|m|y	Hours, days, weeks, months, years (valid only for expiring redirects)
	 *				period (int) - 1-10	How many hours, days, weeks etc, for the expiring redirect
	 *
	 * @return
	 */
	public function moveNodes($nodeids, $to_parent, $makeTopic = false, $newtitle = false, $modlog = true, array $leaveRedirectData = array())
	{
		$movedNodes = array();
		$oldnodeInfo = array();
		$to_parent = $this->assertNodeidStr($to_parent);
		$userContext = vB::getUserContext();

		$currentUserid = vB::getCurrentSession()->get('userid');

		$channelAPI = vB_Api::instanceInternal('content_channel');

		$newparent = $this->getNode($to_parent);

		$checkNodes = $this->getNodes(array_merge((array)$nodeids, (array)$to_parent));
		$nodes = vB::getDbAssertor()->getRows('vBForum:node',
			array('nodeid' => $nodeids),
			array(
				'field' => array('publishdate'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			),
			'nodeid'
		);

		$needRebuild = false;
		$firstTitle = false;

		$loginfo = array();
		$parent = $this->getNodeFullContent($to_parent);
		$parent = $parent[$to_parent];
		$cacheEvents = array($to_parent);
		$oldparents = array();
		$channelTypeid = vB_Types::instance()->getContentTypeId('vBForum_Channel');
		$infractionTypeid = vB_Types::instance()->getContentTypeId('vBForum_Infraction');

		foreach ($nodes AS $node)
		{
			if ($node['contenttypeid'] == $infractionTypeid)
			{
				throw new vB_Exception_Api('cannot_move_infraction_nodes');
			}

			if ($node['contenttypeid'] == $channelTypeid)
			{
				$needRebuild = true;

				// If any of the moved nodes are channels, the target must be a channel.
				if ($newparent['contenttypeid'] != $channelTypeid)
				{
					throw new vB_Exception_Api('invalid_request');
				}
				// We should not allow the moving of channels from one root channel to another.
				if ($channelAPI->getTopLevelChannel($newparent['nodeid']) != $channelAPI->getTopLevelChannel($node['nodeid']))
				{
					throw new vB_Exception_Api('cant_change_top_level');
				}
			}

			//Only channels can be moved to categories, UI shouldn't allow this
			if ($parent['contenttypeid'] == $channelTypeid)
			{
				$newrouteid = vB_Api::instanceInternal('route')->getChannelConversationRoute($to_parent);
				if (($node['contenttypeid'] != $channelTypeid) AND (empty($newrouteid) OR !empty($parent['category'])))
				{
					// The node we want to move is not a channel and the parent cannot have conversations
					// (e.g. categories, the root blog channel, the root forum channel)
					throw new vB_Exception_Api('cannot_move_topic_to_category');
				}
			}

			if (empty($movedNodes))
			{
				if (empty($node['title']) AND !empty($node['starter']))
				{
					$starter = $this->getNodeBare($node['starter']);
					$firstTitle = $starter['title'];
				}
				else
				{
					$firstTitle = $node['title'];
				}
			}

			$movedNodes[] = $node['nodeid'];
			$oldnodeInfo[$node['nodeid']] = $node;
			$oldparents[$node['nodeid']] = $node['parentid'];
			if ($modlog)
			{
				$oldparent = $this->getNode($node['parentid']);

				$extra = array(
					'fromnodeid'	=> $oldparent['nodeid'],
					'fromtitle'		=> $oldparent['title'],
					'tonodeid'		=> $newparent['nodeid'],
					'totitle'		=> $newparent['title'],
				);

				$loginfo[] = array(
					'nodeid'		=> $node['nodeid'],
					'nodetitle'		=> $node['title'],
					'nodeusername'	=> $node['authorname'],
					'nodeuserid'	=> $node['userid'],
					'action'		=> $extra,
				);
			}

			if (!in_array($node['parentid'], $cacheEvents) )
			{
				$cacheEvents[] = $node['parentid'];
			}

			if (!in_array($node['starter'], $cacheEvents) AND intval($node['starter']))
			{
				$cacheEvents[] = $node['starter'];
			}
		}

		if (empty($movedNodes))
		{
			return false;
		}

		//can't move a node to its decendant, we like proper trees.
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBForum:closure', array (
			'parent' => $movedNodes,
			'child' => $to_parent,
			vB_dB_Query::PARAM_LIMIT => 1
		));

		if (!empty($row))
		{
			throw new vB_Exception_Api('move_node_to_child') ;
		}

		//back out counts for the nodes about to be moved.
		//keep track of the parentids to so we can update the last content after
		//we've moved things around.
		$lastContentParents = array();
		foreach($movedNodes AS $nodeid)
		{
			$node = $this->getNode($nodeid);
			$movedNodeParents = $this->getParents($nodeid);

			$parentids = array();
			foreach($movedNodeParents AS $movedNodeParent)
			{
				if ($movedNodeParent['nodeid'] != $nodeid)
				{
					$parentids[] = $movedNodeParent['nodeid'];
					$lastContentParents[] = $movedNodeParent['nodeid'];
				}
			}

			$this->updateAddRemovedNodeParentCounts($node, $node, $node['showpublished'], false, $parentids);
		}

		if (($parent['contenttypeid'] == $channelTypeid) AND $makeTopic)
		{

			if (empty($newtitle))
			{
				if (!empty($firstTitle))
				{
					$newtitle = $firstTitle;
				}
				else
				{
					throw new vB_Exception_Api('notitle');
				}
			}

			$newchildid = $movedNodes[0];
			$this->moveNodesInternal(array($newchildid), $newparent);

			// We need to promote give the new node the correct title
			$newrouteid = vB_Api::instanceInternal('route')->getChannelConversationRoute($to_parent);
			$db->assertQuery('vBForum:node', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'routeid' => $newrouteid,
				'title' => $newtitle,
				'htmltitle' => vB_String::htmlSpecialCharsUni(vB_String::stripTags($newtitle), false),
				'urlident' => vB_String::getUrlIdent($newtitle),
				'description' => $newtitle,
				vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $newchildid)
			));

			//these got updated, but never changed in the stored record.  getNode won't return the
			//correct values because we haven't busted the cache yet.  And, in any event, it's faster
			//to update here than to go back to the database.  This prevents the grandchildren from
			//getting bad values when we update below.
			$checkNodes[$newchildid]['routeid'] = $newrouteid;
			$checkNodes[$newchildid]['starter'] = $newchildid;

			if (count($movedNodes) > 1)
			{
				$grandchildren = array_slice($movedNodes, 1);
				$this->moveNodesInternal($grandchildren, $checkNodes[$newchildid]);
			}

			//moving the grandchildren under the first node may have changed it's last child info
			$db->assertQuery('vBForum:updateLastData', array('parentid' => $newchildid, 'timenow' => vB::getRequest()->getTimeNow()));
			$node = $this->getNode($newchildid);
			$this->updateSubTreePublishStatus($node, $newparent['showpublished']);
		}
		else
		{
			$this->moveNodesInternal($movedNodes, $newparent);
			foreach($movedNodes as $nodeid)
			{
				$node = $this->getNode($nodeid);
				$this->updateSubTreePublishStatus($node, $newparent['showpublished']);
			}
		}


		// Leave a thread redirect if required
		if (!empty($leaveRedirectData))
		{
			$redirectLib = vB_Library::instance('content_redirect');
			$redirectData = array();

			// handle expiring redirects -- this is the same for all the moved nodes.
			if (isset($leaveRedirectData['redirect']) AND $leaveRedirectData['redirect'] == 'expires')
			{
				$period = (int) ($leaveRedirectData['period'] ?? 1);
				$period = max(min($period, 10), 1);

				$frame = (string) ($leaveRedirectData['frame'] ?? 'm');
				$frames = array(
					'h' => 3600,
					'd' => 86400,
					'w' => 86400 * 7,
					'm' => 86400 * 30,
					'y' => 86400 * 365,
				);

				if (!isset($frames[$frame]))
				{
					$frame = 'm';
				}

				$redirectData['unpublishdate'] = vB::getRequest()->getTimeNow() + ($period * $frames[$frame]);
			}


			$copyFields = array('title', 'urlident', 'parentid', 'userid', 'publishdate', 'created');
			foreach($nodes AS $node)
			{
				foreach($copyFields AS $field)
				{
					$redirectData[$field] = $node[$field];
				}
				$redirectData['tonodeid'] = $node['nodeid'];

				// skip any text spam checks, because a redirect has no text to check.
			 	$redirectLib->add($redirectData, array('skipSpamCheck' => true));
			}
		}

		//dedup the array (so we don't update a node more than once) but we need to
		//do so in a particular way.  We always want to keep the *last* occurance
		//of any id in the array.  This ensures that a node is not updated before
		//any of its decendants (which could cause bad results).
		$seen = array();
		foreach($lastContentParents AS $key => $parentid)
		{
			if (isset($seen[$parentid]))
			{
				unset($lastContentParents[$seen[$parentid]]);
			}
			$seen[$parentid] = $key;
		}

		//we can't do this before we move the nodes because the parent/child relationships haven't
		//changed yet.
		foreach($lastContentParents AS $parentid)
		{
			$this->fixNodeLast($parentid);
		}

		// afterMove requires some ancestors info which we just changed above, let's clear cache before updating
		$searchLib = vB_Library::instance('search');
		$cache = vB_Cache::instance();
		foreach ($movedNodes AS $nodeid)
		{
			$cache->allCacheEvent('nodeChg_' . $nodeid);

			//some search information may have changed, let's check
			$searchLib->attributeChanged($nodeid);
		}

		$searchLib->purgeCacheForCurrentUser();
		vB_Library_Admin::logModeratorAction($loginfo, 'node_moved_by_x');

		$cacheEvents = array_unique(array_merge($movedNodes, $cacheEvents, array($to_parent)));
		$this->clearChildCache($cacheEvents);
		$this->clearCacheEvents($cacheEvents);

		if ($needRebuild)
		{
			vB::getUserContext()->rebuildGroupAccess();
			vB_Channel::rebuildChannelTypes();
		}

		return $movedNodes;
	}

	/*
	 *	This assumes that the subtree values have been backed out of any counts
	 *	and, at this point, only need to be added to the new location.  The move
	 *	function specifically removes counts prior to moving nodes while clone
	 *	is adding new nodes and doesn't need to worry about it.
	 */
	protected function updateSubTreePublishStatus($node, $isParentPublished)
	{
		//if the parent is not published then we *always* want to unpublish nodes
		$publish = ($isParentPublished AND $this->isPublished($node));

		if ($publish)
		{
			$nodeUpdates = $this->publishChildren($node['nodeid']);
		}
		else
		{
			$nodeUpdates = $this->unpublishChildren($node['nodeid']);
		}

		$this->updateAddRemovedNodeParentCounts($node, $nodeUpdates, $publish, true);
	}

	/**
	 * Update the ancestors of a changed node based on the new counts
	 *
	 * @param array $origNode -- the original node array of the node that changed
	 * 	prior to updating it's status
	 * @param array $counts -- the return from the "publish children" function
	 * 	used to update the node's subtree.
	 */
	private function updateChangedNodeParentCounts($origNode, $counts)
	{
		$textChangeTypes = $this->getTextChangeTypes();

		$textChange = 0;
		$textUnPubChange = 0;

		//if the node isn't a node type that we track for counts then we
		//shouldn't be worried about any change to its "count" status.
		if (isset($textChangeTypes[$origNode['contenttypeid']]))
		{
			//a node counts as published if its published and approved.  Otherwise it counts as upublished.
			//this is only for the count rollups, the actual published and approved statuses have different meanings.
			$origIsPub = ($origNode['showpublished'] AND $origNode['showapproved']);
			$newIsPub = ($counts['showpublished'] AND $counts['showapproved']);

			//if the original is published but the new one isn't then we need to add one to the
			//unpub and subtract one from the pubcount for the parent.
			if ($origIsPub AND !$newIsPub)
			{
				$textChange = -1;
				$textUnPubChange = 1;
			}

			//if the situation is reversed, then do the reverse
			else if (!$origIsPub AND $newIsPub)
			{
				$textChange = 1;
				$textUnPubChange = -1;
			}

			//if they're both published or unpublished then we didn't change anything.
		}

		$totalChange = ($counts['totalcount'] - $origNode['totalcount']) + $textChange;
		$totalUnPubChange = ($counts['totalunpubcount'] - $origNode['totalunpubcount']) + $textUnPubChange;

		$this->updateParentCounts(
			$origNode['nodeid'],
			$textChange,
			$textUnPubChange,
			$totalChange,
			$totalUnPubChange,
			$counts['showpublished'],
			true
		);
	}

	/**
	 *	Add or remove node counts for a given node its parents
	 *
	 *	Note this should be called before removing a node entire from the tree (or moving it to a new location) and after adding it to the tree
	 *	(or moving it to a new location).  It corrects the counts of parents based on the change made, but it affects the parents of the node
	 *	at the time the function is called -- we always want to remove the count of the nodes old parents (prior to a move or delete) and add
	 *	to the new parents (after a more or an add).
	 *
	 *	@param array $node -- the node array
	 *	@param arrray $counts -- the "count" array ('showpublished', 'showapproved', 'textcount', 'textunpubcount', 'totalcount', 'totalunpubcount') either from
	 *		the node record or the publishChildren function (it is permissable to pass the node array here if the counts are accurate, but the function
	 *		guarentees it will only access the listed fields so updated information form publishChildren can be passed instead).
	 *	@param bool $publish -- controls if the parent lastcontent is also updated.
	 *	@param bool $add -- true to add the counts, false to remove
	 *	@param array $parendids -- array of parent ids for the node. If empty we will look it up from the node record.
	 */
	public function updateAddRemovedNodeParentCounts($node, $counts, $publish, $add, $parentids = array())
	{
		$textChangeTypes = $this->getTextChangeTypes();
		$mult = ($add ? 1 : -1);

		$textChange = 0;
		$textUnPubChange = 0;
		if (isset($textChangeTypes[$node['contenttypeid']]))
		{
			//if this node is published and approved then add to the parent text
			//otherwise add to text unpublished.
			if ($publish AND $counts['showpublished'] AND $counts['showapproved'])
			{
				$textChange = 1;
			}
			else
			{
				$textUnPubChange = 1;
			}
		}

		$totalChange = ($counts['totalcount'] + $textChange);
		$totalUnPubChange = ($counts['totalunpubcount'] + $textUnPubChange);

		if (!$parentids)
		{
			$parentids = $this->getParentIds($node['nodeid']);
		}

		$this->updateParentCountsList(
			$parentids,
			$mult * $textChange,
			$mult * $textUnPubChange,
			$mult * $totalChange,
			$mult * $totalUnPubChange,
			$publish
		);
	}


	/**
	 * 	Handles the actual move of nodes to the new parent.
	 *
	 * 	Makes all nodes ids direct children of new parent.  Also cleans up some, but not all,
	 * 	of the various denormalized data surrounding moving a node.
	 *
	 * 	This was refactored from the "moveNodes" method query and should continue to be refactored
	 * 	so it only handles updating the parent field and the closure table records directly involved
	 * 	in moving a node.  The public function shoudl handle clearning up the denormalized data.
	 *
	 *	@param array $nodeids nodes to move
	 * 	@param array $newparent the standard node array for the parent node
	 **/
	protected function moveNodesInternal($nodeids, $newparent)
	{
		$db = vB::getDbAssertor();
		$to_parent = $newparent['nodeid'];

		//First delete the closure records from this to the top;
		$db->assertQuery('vBForum:deleteMovedNodeClosureRecords', array('nodeids' => $nodeids));
		$db->delete('vBForum:closure', array(
			'child' => $nodeids,
		 	array('field' => 'depth', 'value' => 0, 'operator' =>  vB_dB_Query::OPERATOR_GT),
		));

		//Now set the parentid for the node being moved.
		$db->update('vBForum:node', array('parentid' => $to_parent), array('nodeid' => $nodeids));

		foreach ($nodeids as $nodeid)
		{
			//Now create the new closure records- the moved node itself
			$db->assertQuery('vBForum:insertMovedNodeClosureRecords', array('nodeid' => $nodeid, 'parentid' => $to_parent));

			//Next the children of the moved node;
			$db->assertQuery('vBForum:insertMovedNodeChildrenClosureRecords', array('nodeid' => $nodeid));
		}

		//We need to set starter and routeids.
		$channelTypeid = vB_Types::instance()->getContentTypeId('vBForum_Channel');

		if ($newparent['contenttypeid'] == $channelTypeid)
		{
			//this is a channel
			//each node is a starter, and their children are responses.
			// We shouldn't update the starter node, so we update them separately

			//Do non-channel nodes
			//Due to the changes in VBV-4806, this query is no longer needed, except that the next query isn't run if newrouteid is blank
			$db->assertQuery('vBForum:updateMovedNodeStarter', array('nodeids' => $nodeids, 'channelTypeid' => $channelTypeid));

			$newrouteid = vB_Api::instanceInternal('route')->getChannelConversationRoute($to_parent);

			// some channels don't have a route, like the Main Forum -- all channels should have a route, otherwise we have serious
			// problems when we move nodes to them
			if (!empty($newrouteid))
			{
				// We also need to update starter's routeid. See VBV-4806.
				// Note that we don't update the child if the route is null.  That's really not the correct behavior.
				$db->assertQuery('vBForum:updateMovedNodeChildrenStarter',
					array('nodeids' => $nodeids, 'channelTypeid' => $channelTypeid, 'routeid' => $newrouteid));
			}
			//Note that we don't need to change anything about children of channels. They are already starters.
		}
		else
		{
			//this is not a channel, so it has a starter. Each node should inherit this starter.
			$db->assertQuery('vBForum:updateMovedNodeChildrenStarterNonChannel',
				array('nodeids' => $nodeids, 'starter' => $newparent['starter'], 'routeid' => $newparent['routeid']));
		}

		$timenow =  vB::getRequest()->getTimeNow();

		// update show fields
		$db->assertQuery('vBForum:updateMovedNodeShowFields',
			array('nodeids' => $nodeids, 'parentid' => $to_parent, 'timenow' => $timenow));

		//showopen
		$db->assertQuery('vBForum:updateMovedNodeShowOpen', array('nodeids' => $nodeids));

		//showapproved
		$db->assertQuery('vBForum:updateMovedNodeShowApproved', array('nodeids' => $nodeids));
	}



	/**
	 * Checks for any content that needs to be published or unpublished.
	 */
	public function timedCountUpdates($maxrows = 25)
	{
		$timeNow = vB::getRequest()->getTimeNow();
		//First get a list of expired items.
		$needUpdate = vB::getDbAssertor()->assertQuery('vBForum:getNeedUpdate',
			array('maxrows' => $maxrows, 'timenow' => $timeNow));

		if (!$needUpdate->valid())
		{
			return array('success' => true);
		}

		$textChangeTypes = $this->getTextChangeTypes();
		$processed = array();
		$assertor = vB::getDbAssertor();
		$pmtype = vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage');
		//Only if a channel changes we need to rebuild the group access

		$needRebuild = false;
		foreach ($needUpdate as $node)
		{
			$processed[] = $node['nodeid'];
			//never do private messages.
			if ($node['contenttypeid'] == $pmtype)
			{
				continue;
			}
			//Check to see if we actually need an update.
			if ($node['parentpublished'] > 0)
			{
				$newpublished = (($node['publishdate'] <= $timeNow) AND (empty($node['unpublishdate']) OR ($node['unpublishdate'] > $timeNow)));
			}
			else
			{
				$newpublished = FALSE;
			}
			$parentTextChange = false;

			if ($newpublished != (bool)$node['showpublished'])
			{
				if ($node['contenttypeid'] == $this->channelTypeId)
				{
					$needRebuild = true;
				}
				//First set all the children to the correct value.
				//then update the counts.
				if ($newpublished)
				{
					$nodeUpdates = $this->publishChildren($node['nodeid']);

					if (!empty($nodeUpdates) AND isset($nodeUpdates['totalcount']))
					{
						if (isset($textChangeTypes[$node['contenttypeid']]))
						{
							$textChange = 1;
						}
						else
						{
							$textChange = 0;
						}
						$textUnPubChange = -1 * $textChange;
						$totalPubChange = $nodeUpdates['totalcount'] - $node['totalcount'] + $textChange;
						$totalUnPubChange = -1 * $totalPubChange;
						$parentTextChange = true; //update counts for the parent
					}
				}
				else // from published to unpublished
				{
					$nodeUpdates = $this->unpublishChildren($node['nodeid']);

					if (!empty($nodeUpdates) AND isset($nodeUpdates['totalunpubcount']))
					{
						if (isset($textChangeTypes[$node['contenttypeid']]))
						{
							$textUnPubChange = 1;
						}
						else
						{
							$textUnPubChange = 0;
						}
						$textChange = -1 * $textUnPubChange;
						$totalUnPubChange = $nodeUpdates['totalunpubcount'] - $node['totalunpubcount'] + $textUnPubChange;
						$totalPubChange = -1 * $totalUnPubChange;
						$parentTextChange = true; //update counts for the parent
					}
				}

				// clear cache for node & children. Events for parents are taken care of in updateParentCounts()
				$this->clearCacheEvents($node['nodeid']);
				$this->clearChildCache($node['nodeid']);

				$this->updateLastForSubtree($node['nodeid']);
				//update counts for the parent
				if (!empty($parentTextChange))
				{
						$this->updateParentCounts($node['nodeid'], $textChange, $textUnPubChange, $totalPubChange, $totalUnPubChange, $newpublished);
				}
			}
		}

		//Now below we're going to reset the nextupdate date. So let's clear it for the nodes we're going to process now.
		$assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'nodeid' => $processed, 'nextupdate' => 0));

		if ($needRebuild)
		{
			vB::getUserContext()->rebuildGroupAccess();
		}
		return array('success' => true);
	}

	/**
	 *	Updates the showpublished & count fields of $parentid & its descendents for publishing
	 *
	 *	Caller MUST ensure that $parentid is actually published (i.e. a valid publishdate is set
	 *	and a positive unpublishdate is removed or in the future).  This claimed but not entirely
	 *	true of the previous version of the function (which would set the parent node showpublished
	 *	to true regardless of the dates which meant that it would work if the dates were corrected
	 *	after the call to publish children).  This version of the function requires that the
	 *	dates are set correctly before it is called.
	 *
	 *	Caller MUST also ensure that approved and showapproved flags are correctly set in the entire substree headed by
	 *	$parentid, otherwise the counts may end up being off.
	 *
	 * 	@param	int		$parentid	nodeid of node being published
	 * 	@return	mixed	An array that contains the updated
	 *								count fields of $parentid, or an array with key 'errors' if the
	 *								assertor hit an error while updating
	 *
	 */
	public function publishChildren($parentid)
	{
		$db = vB::getDbAssertor();
		$maxDepth = $db->getRow('vBForum:selectMaxDepth', array('rootnodeid' => $parentid));
		$maxDepth = $maxDepth['maxDepth'];

		$timeNow = vB::getRequest()->getTimeNow();
		$excluded = vB_Node::getExcludedTypes();

		//from the top down, update the showpublished fields
		for ($depth = 0; $depth <= $maxDepth; $depth++)
		{
			$db->assertQuery('vBForum:updatePublishedForDepth',
				array('rootnodeid' => $parentid, 'depth' => $depth, 'timenow' => $timeNow));
		}

		//from the bottom up, recompute totals for nodes with children -- nodes without children
		//should have 0's for the count fields and should already be correct.  Note that we skip the
		//last depth because we no longer need it
		for ($depth = ($maxDepth-1); $depth >= 0; $depth--)
		{
			$db->assertQuery('vBForum:updateCountsForDepth',
				array('rootnodeid' => $parentid, 'depth' => $depth, 'timenow' => $timeNow, 'excluded' => $excluded ));
		}

		//grab the new parent node values to make this work like the old function
		$node = $db->getRow('vBForum:node', array('nodeid' => $parentid,
			vB_dB_Query::COLUMNS_KEY => array('showpublished', 'showapproved', 'textcount', 'textunpubcount', 'totalcount', 'totalunpubcount')));
		return $node;
	}

	/**
	 *	Updates the showpublished & count fields of $parentid & its descendents for unpublishing
	 *	Caller MUST ensure that $parentid is actually unpublished (i.e. a valid unpublishdate is set)
	 *
	 * 	@param	int		$parentid	nodeid of node being unpublished
	 * 	@return	mixed				Can be false (for no updates), an array that contains the updated
	 *								count fields of $parentid, or an array with key 'errors' if the
	 *								assertor hit an error while updating
	 */
	public function unpublishChildren($parentid)
	{
		/*
		 * The new publishChildren actually sets the values properly based on the dates regardless either way.
		 * It's possible that we could use the fact that unpublish is simpler to shave a little time off
		 * setting the showpublish flags, but right now using battle hardened code is more critical.
		 */
		return $this->publishChildren($parentid);
	}



	protected function updateLastForSubtree($rootid)
	{
		// these ones don't affect count fields or lastcontent.
		$excluded = vB_Node::getExcludedTypes();
		$db = vB::getDbAssertor();

		/*
			Note, this function only affects $rootid & its descendants, not ancestors.

			So when called on the unapproved node, this only affects the unapproved node & children.

			Unapproved topics getting lastcontent set to 0 :

				updateLastContentDateForTree sets the lastcontent (date) for the unapproved topic to 0

				updateLastContentBlankNodeForTree sets the lastcontentid ETC (data fields) to 0 if lastcontent is 0

				I think this is meant for channels to be updated properly when there's no showpublished & showapproved children



			Usually, the channels are updated by a different function (fixNodeLast() called by updateChangedNodeParentCounts() &
			others) that's called after this.
		 */

		/*
			The old process involved, for $rootid & its descendants:
			1)	Set lastcontent (date) to max publishdate (or 0 if null) of latest
				descendant (or self) node who was
				inlist = 1, showpublished = 1, showapproved = 1, contenttypeid NOT IN ({$excluded})
				via vBForum:updateLastContentDateForTree
				(So node.lastcontent would either be latest or 0)
			2)	Set lastcontentid, lastcontentauthor, lastauthorid, lastprefixid
				to any descendant (or self) node whose publishdate equaled the lastcontent above AND
				inlist = 1, showpublished = 1, showapproved = 1, contenttypeid NOT IN ({$excluded})
				via vBForum:updateLastContentNodeForTree
				(There was also a set to 0 if null condition, which was never triggered because all
				joins were INNER joins with no chance of any null rows)
			3)	Set lastcontentid, lastcontentauthor, lastauthorid, lastprefixid to 0 / '' for
				any descendant (or $rootid) whose lastcontent was set to 0 from Step 1
				via vBForum:updateLastContentBlankNodeForTree

			This meant that if a topic was unapproved via node API/LIB, the topic's lastcontent etc was
			set to empty, resulting in the topic's relocating from their previous places in forum's
			topic-lists (which sort by lastcontent date by default) to the end of the topic-lists, or
			in many cases disappear entirely due to the size of the forum.
			(See Issue VBV-13326, Issue VBV-18798)

			The initial fix changed Step 1 to set lastcontent to its own publishdate instead of 0, and
			changed Step 2 to do a LEFT JOIN on the node children so that the IFNULL clause on the SET
			would allow it to set lastcontentid, author etc to itself, but that backfired in that when
			an unapproved topic with an approved reply was re-approved, the multiple possible
			matches/rows from the LEFT JOIN caused the update to be ambiguous and seemed to consistently
			result in the IFNULL condition taking precedence (or running last) such that even when
			lastcontent (date) was set on the topic correctly to the reply, the other lastcontent data was
			set to the topic.

			The newest fix changes the process so that
			1)	First we set $rootid & descendants' lastcontent ETC to either itself or 0, depending on
				inlist & contenttypeid IN ({$excluded}). We don't check showapproved & showpublished here
				so that we don't unintentionally blank out the lastcontent for non-channels (furthermore
				channel updates are frequently handled outside this function, as part of ancestor updates).
			2)	Run vBForum:updateLastContentDateForTree (modified to NOT reset any lastcontent to 0 if it
				wasn't set to 0 by Step 1)
			3)	Run the vBForum:updateLastContentNodeForTree (modified to remove the unused IFNULL clauses)
				to match lastcontentid ETC to the lastcontent (date) set in Step 2
			4)	No need for vBForum:updateLastContentBlankNodeForTree (old Step 3) since we blanked out
				lastcontent OR set it to itself in Step 1.
		 */

		/*
			vbForum:resetLastContentSelfForTree note:
			We actually need all of the "excluded" last content types to at least set the lastcontent to itself,
			otherwise fixNodeLast() does not work properly.
			The case where this matters is when an attachment is approved. Without the attachment having a valid
			lastcontent, the "parent" (the actual post with text) will get its lastcontent reset via fixNodeLast()
			(downstream of updateChangedNodeParentCounts()).
			The only case where it *shouldn't* be allowed to use itself for lastcontent is channel, as evidenced by
			vB_Library_Content::add() only explicitly skipping setting the node's lastcontent to itself when the
			contenttype is channel OR the publishdate is empty.

			We may also want to filter out any unpublished/soft-deleted or futurepublished nodes, but I'm leaving that
			out for now due to JIRA scope.
		 */
		$db->assertQuery('vbForum:resetLastContentSelfForTree',
			array(
				'rootid' => $rootid,
				'excluded' => $this->channelTypeId,
			)
		);
		$db->assertQuery('vbForum:updateLastContentDateForTree', array('rootid' => $rootid, 'excluded' => $excluded));
		$db->assertQuery('vbForum:updateLastContentNodeForTree', array('rootid' => $rootid, 'excluded' => $excluded));
		//$db->assertQuery('vbForum:updateLastContentBlankNodeForTree', array('rootid' => $rootid));
	}


	/**
	 *	Determines if a node record is published or not.  Note that this only checks if the record is published, not if
	 *	it should be shown as published.
	 */
	public function isPublished($node)
	{
		/*
		 *	The logic in the this function is duplicated in at least one DB query.  If we change it here we
		 *	*must* hunt down the other locations and make them consistant.  Otherwise we will upset customers
		 *	and drive ourselves mad.
		 */
		$timeNow = vB::getRequest()->getTimeNow();
		$ispublished = (										// publish this node if
			($node['publishdate'] > 0) 							// it has been published ...
				AND ($node['publishdate'] <= $timeNow) 				// ... and isn't waiting future publishing
				AND (empty($node['unpublishdate']) OR ($node['unpublishdate'] > $timeNow)) // and node wasn't soft-deleted or unpublished
		);	// don't forget the parentheses! "=" assignment op has higher precedence than "AND" logical op

		return $ispublished;
	}

	/**
	 * Updates the parent counts and data when saving a node.
	 *
	 *	@param int $nodeid -- ID of the node who's parents should be updated
	 *	@param int $textChange -- change in the "text" count.  This is the badly named field for published direct children.
	 *	@param int $textUnPubChange -- Change in the direct unpublished children
	 *	@param int $totalPubChange -- Change in the count of the published decendants
	 *	@param int $totalUnPubChange -- Change in the count of the unpublished decendants
	 *	@param bool $published
	 *	@param bool $updatelastcontent
	 */
	public function updateParentCounts
	(
		$nodeid,
		$textChange,
		$textUnPubChange,
		$totalPubChange,
		$totalUnPubChange,
		$published,
		$updatelastcontent = true
	)
	{
		$parentids = $this->getParentIds($nodeid);
		return $this->updateParentCountsList(
			$parentids,
			$textChange,
			$textUnPubChange,
			$totalPubChange,
			$totalUnPubChange,
			$published,
			$updatelastcontent
		);
	}

	/**
	 * Updates the parent counts and data when saving a node.
	 *
	 *	@param array $parentids -- $ids of the node to updates parents.  Should not include the node itself
	 *	@param int $textChange -- change in the "text" count.  This is the badly named field for published direct children.
	 *	@param int $textUnPubChange -- Change in the direct unpublished children
	 *	@param int $totalPubChange -- Change in the count of the published decendants
	 *	@param int $totalUnPubChange -- Change in the count of the unpublished decendants
	 *	@param bool $published (no longer appears to do anything)
	 *	@param bool $updatelastcontent
	 */
	private function updateParentCountsList
	(
		$parentids,
		$textChange,
		$textUnPubChange,
		$totalPubChange,
		$totalUnPubChange,
		$published,
		$updatelastcontent = true
	)
	{
		$parentids = array_unique($parentids);

		if (!empty($parentids))
		{
			$assertor = vB::getDbAssertor();
			$assertor->assertQuery('vBForum:UpdateParentTextCount', array(
				'nodeid' => $parentids[0],
				'textChange' => $textChange,
				'textUnpubChange' => $textUnPubChange
			));

			$assertor->assertQuery('vBForum:UpdateAncestorCount', array(
				'nodeid' => $parentids,
				'totalChange' => $totalPubChange,
				'totalUnpubChange' => $totalUnPubChange
			));

			$this->clearCacheEvents($parentids);
			if ($updatelastcontent)
			{
				$searchLIB = vB_Library::instance('search');
				foreach ($parentids AS $parentid)
				{
				 	$this->fixNodeLast($parentid);
					$searchLIB->attributeChanged($parentid);
				}
			}
		}
	}

	/**
	 * Calculates the last node info for a given node
	 *
	 * this mostly exists as a public function for testing purposes.
	 * generally you will want to call fixNodeLast
	 *
	 * @param int $nodeid
	 *
	 * @return array -- array('lastcontent', 'lastcontentid', 'lastcontentauthor', 'lastauthorid')
	 * 	values suitable for updating to the node record
	 */
	public function calculateNodeLastInfo($nodeid)
	{
		/*
			On one hand, we don't want excluded types & non inlist items to affect parent lastcontent,
			but the way this was written was for channels to "quickly" fetch their most recent sub-topic OR
			sub-channel's lastcontent, and push the change upwards. So we want channels to be fetched by the
			query, even though channels are a non-text type & excluded.
			Problem is, this function can be called on a channel OR a non-channel (e.g. topic or reply when
			an attachment is approved). If $nodeid is a channel, we want to be able to select for channels,
			but when $nodeid is NOT a channel, we don't want an excluded child updating its lastcontent.
			Let's assume that a channel will never ever be a child of a "text" type, so that always allowing
			channel descendants to be selected will not cause an issue when this function is called on a topic
			or reply.
		 */
		$excludedTypes = $this->getExcludedLastContentTypes();
		$excludedTypes = array_diff($excludedTypes, array($this->channelTypeId));
		$db = vB::getDbAssertor();
		$result = $db->getRow('vBForum:node',
			array(
				vB_dB_Query::CONDITIONS_KEY => array(
					'parentid' => $nodeid,
					'showpublished' => 1,
					'showapproved' => 1,
					array('field' => 'contenttypeid', 'value' => $excludedTypes, 'operator' => vB_dB_Query::OPERATOR_NE),
				),
				vB_dB_Query::PARAM_LIMIT => 1,
				vB_dB_Query::COLUMNS_KEY => array('lastcontent', 'lastcontentid', 'lastcontentauthor', 'lastauthorid')
			),
			array(
				'field' => array('lastcontent', 'lastcontentid'),
				'direction' => array(vB_dB_Query::SORT_DESC, vB_dB_Query::SORT_DESC)
			)
		);

		return $result;
	}

	public function fixNodeLast($nodeid)
	{
		$excludedTypes = $this->getExcludedLastContentTypes();

		$db = vB::getDbAssertor();
		$row = $this->calculateNodeLastInfo($nodeid);
		if ($row)
		{
			return $db->update('vBForum:node', $row, array('nodeid' => $nodeid));
		}
		else
		{
			return $db->assertQuery('vBForum:updateLastContentSelf', array(
				'nodeid' => $nodeid,
				'excluded' => $excludedTypes,
			));
		}
	}

	/**
	 * Merges "posted" info into the topics array, used by the display_Topics template.
	 * This adds the "content.posted" element to the node record. The value is the number of
	 * times the passed userid has posted in the topic (replies and comments); zero if none.
	 *
	 * @param  array  Nodes
	 * @param  int    User ID
	 *
	 * @return array  Same array of nodes, with the "posted" element added to the "content" sub-array
	 */
	public function mergePostedStatusForTopics($nodes, $userid)
	{
		$userid = (int) $userid;

		$nodeids = array();
		foreach ($nodes AS $node)
		{
			$nodeids[] = $node['nodeid'];
		}

		$posts = vB::getDbAssertor()->getRows('vBForum:getUserPostsInTopic', array(
			'nodeids' => $nodeids,
			'userid' => $userid,
		));

		$info = array();
		foreach ($posts AS $post)
		{
			$parent = $post['parent'];

			$info[$parent] = array();
			$info[$parent]['count'] = $post['count'];
			$info[$parent]['lastpost'] = $post['lastpost'];
		}

		foreach ($nodes AS $k => $node)
		{
			$nodeid = $node['nodeid'];

			if (isset($info[$nodeid]))
			{
				$nodes[$k]['content']['dot_postcount'] = $info[$nodeid]['count'];
				$nodes[$k]['content']['dot_lastpostdate'] = $info[$nodeid]['lastpost'];
			}
			else
			{
				$nodes[$k]['content']['dot_postcount'] = 0;
				$nodes[$k]['content']['dot_lastpostdate'] = 0;
			}
		}

		return $nodes;
	}

	private function getExcludedLastContentTypes()
	{
		if (is_null($this->excludedLastContentTypes))
		{
			$this->excludedLastContentTypes = array();
			$types = vB_Types::instance()->getContentTypes();
			foreach ($types as $className => $type)
			{
				if (class_exists('vB_Library_Content_' . $type['class'], true))
				{
					$contentAPI = vB_Library::instance('Content_' . $type['class']);
					if (!$contentAPI->getCanBeLastContent())
					{
						$this->excludedLastContentTypes[] = $type['id'];
					}
				}
			}
		}

		return $this->excludedLastContentTypes;
	}
	
	/**
	 * Fetch nodeview count(s) for nodeid(s)
	 * @param	array	$nodeids		array of nodeid(s) for which we're grabbing the count(s)
	 * @return 	array					array with keys $nodeids & corresponding counts for the values
	 *										array(<nodeid1> => <view count of nodeid1>, <nodeid2> => <view count of nodeid2>...)
	 */
	public function getNodeviews($nodeids)
	{
		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$nodeids = array_map('intval', $nodeids);

		// anyone can see the # of views a node has.


		$viewsQry = vB::getDbAssertor()->assertQuery('vBForum:nodeview', array('nodeid' =>  $nodeids));

		// if a record for a nodeid wasn't found in nodeviews, then it has 0 count.
		$nodes = array_combine($nodeids, array_fill(0, count($nodeids), 0));
		foreach ($viewsQry AS $row)
		{
			$nodes[$row['nodeid']] = $row['count'];
		}

		return $nodes;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104244 $
|| #######################################################################
\*=========================================================================*/
