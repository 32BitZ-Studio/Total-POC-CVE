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
 * vB_Api_Socialgroup
 *
 * @package vBApi
 * @access public
 */
class vB_Api_SocialGroup extends vB_Api_Blog
{

	protected $sgChannel = false;

	/**
	 * @uses fetch the id of the global Social Group Channel
	 * @return int nodeid of actual Main Social Group Channel
	 */
	public function getSGChannel()
	{
		return vB_Library::instance('node')->getSGChannel();
	}

	public function getMembersCount($nodeid)
	{
		$node = vB_Api::instanceInternal('node')->getNode($nodeid, true, false);
		if (!intval($nodeid) OR !$this->isSGNode($nodeid, $node))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		return $this->doMembersCount($nodeid);
	}

	/**
	 * Determines if the given node is a blog-related node (blog entry).
	 *
	 * @param	int	$nodeid
	 * @return	bool
	 */
	public function isSGNode($nodeId, $node = false)
	{
		$nodeId = (int) $nodeId;

		if ($nodeId < 0)
		{
			return false;
		}

		$sgChannelId = (int) $this->getSGChannel();

		if (empty($node))
		{
			$nodeLib = vB_Library::instance('node');
			$node = $nodeLib->getNode($nodeId, true, false);
		}

		if (!empty($node['parents']))
		{
			$parents = $node['parents'];
		}
		else
		{
			$nodeLib = vB_Library::instance('node');
			$parents = $nodeLib->getParents($nodeId);
		}

		if (is_numeric(current($parents)))
		{
			return in_array($sgChannelId, $parents);
		}

		foreach ($parents as $parent)
		{

			if ($parent['nodeid'] == $sgChannelId)
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Determines if the given node is a Social group channel.
	 *
	 * @param	int	$nodeid
	 * @return	bool
	 */
	public function isSGChannel($nodeid)
	{
		if (!intval($nodeid))
		{
			return false;
		}
		$nodeInfo = vB_Api::instance('node')->getNodeContent($nodeid);
		if ($this->isSGNode($nodeid)
			AND ($nodeInfo[$nodeid]['contenttypeid'] == vB_Types::instance()->getContentTypeId('vBForum_Channel')))
		{
			return true;
		}
		return false;
	}

	/**
	 * gets Get info on every SG Channel
	 *
	 *	@param	array	Array of options to filter the info (used to show all/my groups).
	 *	@param	array	Array of route info of the social group parent channel to be used for building pagination URLs.
 	 * 	@return mixed 	Array containing the social group channel info we need.
	 */
	public function getSGInfo($options = array(), $routeInfo = array())
	{
		$response = array();
		$nodeApi = vB_Api::instanceInternal('node');

		$sgParentChannel = $this->getSGChannel();
		if (!empty($options['sgparent']) AND intval($options['sgparent']) AND (intval($options['sgparent'] != $sgParentChannel)))
		{
			$sgParent = intval($options['sgparent']);
			$depth = 1;
		}
		else
		{
			$sgParent = $sgParentChannel;
			$depth = 2;
		}

		// category check
		if (!$this->isSGNode($sgParent))
		{
			throw new vB_Exception_Api('invalid_sg_parent');
		}

		//Get base data
		$channelContentType = vB_Types::instance()->getContentTypeId('vBForum_Channel');
		$params = array(
			'starter_only' => 1,
			'view' => 'activity',
			'depth_exact' => 1,
			'nolimit' =>1,
		);
		$queryParams = array('sgParentChannel' => $sgParent, 'depth' => $depth);

		// userid=<userid> will retrieve the users owned channels
		if (!empty($options['userid']))
		{
			$queryParams['userid'] = $params['userid'] = intval($options['userid']);
		}

		// my_channels=<userid> will retrieve the users owned channels
		// all other channels they are a member of
		if (!empty($options['my_channels']))
		{
			// send my_channels: {type: group} to the search engine
			$params['my_channels'] = 'group';
			// send the userid to the totalcount query
			$queryParams['my_channels'] = intval($options['my_channels']);
		}

		// sort
		$sortField = 'title';
		$sortOrder = 'asc';
		if (!empty($options['sort_field']) AND in_array($options['sort_field'], array('title', 'textcount', 'lastcontent', 'created'), true))
		{
			$sortField = (string) $options['sort_field'];
			if (!empty($options['sort_order']) AND in_array($options['sort_order'], array('asc', 'desc'), true))
			{
				$sortOrder = (string) $options['sort_order'];
			}
		}
		$params['sort'] = array($sortField => $sortOrder);

		$page = (!empty($options['page']) AND intval($options['page'])) ? intval($options['page']) : 1;
		$perpage = (!empty($options['perpage']) AND intval($options['perpage'])) ? intval($options['perpage']) : 20;
		$cacheParams = array_merge($params,
			array(
				'page' => $page,
				'perpage' => $perpage,
				'sgparent' => $sgParent,
				'depth' => $depth,
			)
		);
		$cacheKey = 'sgResults_' . (vB::getUserContext()->fetchUserId() ? vB::getUserContext()->fetchUserId() : 0) . crc32(serialize($cacheParams));
		if ($result = vB_Cache::instance(vB_Cache::CACHE_FAST)->read($cacheKey) OR !vB::getUserContext()->hasPermission('socialgrouppermissions', 'canviewgroups'))
		{
			//we don't cache the pagination URLs as they may vary for the same content depending on the specified routeInfo (routeId, arguments, queryParameters)
			$pageInfo = $result['pageInfo'];
			$paginationURLs = $this->buildPaginationURLs($pageInfo['currentpage'], $pageInfo['totalpages'], $routeInfo);
			if ($paginationURLs)
			{
				$pageInfo = array_merge($pageInfo, $paginationURLs);
				$result['pageInfo'] = $pageInfo;
			}

			return $result;
		}

		// pull the groups for this page and the total count
		$nodeContent = $nodeApi->listNodeContent($sgParent, $page, $perpage, $depth, $channelContentType, $params);
		$totalCount = vB::getDbAssertor()->getRow('vBForum:getSocialGroupsTotalCount', $queryParams);

		//We need the nodeids to collect some data
		$cacheEvents = array('nodeChg_' . $sgParent);
		$lastids = array();
		$lastNodes = array();
		$channelids = array();
		$categories = array();
		$contributorIds = array();
		$sgCategories = array_keys($this->getCategories());
		$sgParentChannel = $this->getSGChannel();

		foreach ($nodeContent AS $key => $node)
		{
			if ($node['parentid'] == $sgParentChannel)
			{
				$categories[] = $node['nodeid'];
				unset($nodeContent[$node['nodeid']]);
			}
			else
			{
				if ($node['lastcontentid'] > 0)
				{
					$lastids[] = $node['lastcontentid'];
				}
				if (in_array($node['parentid'], $sgCategories))
				{
					$categories[] = $node['parentid'];
				}
				$channelids[] = $node['nodeid'];
				$contributorIds[$node['userid']] = $node['userid'];
				$cacheEvents[] = 'nodeChg_' . $node['nodeid'];
			}
		}
		$categories = array_unique($categories);

		if (empty($channelids))
		{
			//for display purposes, we set totalpages to 1 even if there are no records because we don't want the UI to display Page 1 of 0
			$result = array('results' => array(), 'totalcount' => 0, 'pageInfo' => array('currentpage' => $page, 'perpage' => $perpage, 'nexturl' => '', 'prevurl' => '', 'totalpages' => 1, 'totalrecords' => 0, 'sgparent' => $sgParent));
			vB_Cache::instance(vB_Cache::CACHE_FAST)->write($cacheKey, $result, 60, array_unique($cacheEvents));

			return $result;
		}

		$mergedNodes = vB_Library::instance('node')->getNodes(array_unique(array_merge($lastids, $categories)));
		foreach ($lastids AS $lastid)
		{
			if (empty($mergedNodes[$lastid]))
			{
				continue;
			}
			$lastNodes[$lastid] = $mergedNodes[$lastid];

			$contributorIds[$mergedNodes[$lastid]['userid']] = $mergedNodes[$lastid]['userid'];
		}
		foreach ($categories AS $category)
		{
			if (empty($mergedNodes[$category]))
			{
				continue;
			}
			$categoriesInfo[$category] = $mergedNodes[$category];
		}

		// update category info
		foreach ($nodeContent AS $key => $node)
		{
			// add category info
			if (isset($categoriesInfo[$node['parentid']]))
			{
				$nodeContent[$key]['content']['channeltitle'] = $categoriesInfo[$node['parentid']]['title'];
				$nodeContent[$key]['content']['channelroute'] = $categoriesInfo[$node['parentid']]['routeid'];
				$cacheEvents[] = 'nodeChg_' . $node['parentid'];
			}
		}

		$lastTitles = $lastInfo = array();
		$lastIds = array();
		foreach ($lastNodes as $lastnode)
		{
			$lastInfo[$lastnode['nodeid']]['starter'] = $lastnode['starter'];
			if ($lastnode['starter'] == $lastnode['nodeid'])
			{
				$lastInfo[$lastnode['nodeid']]['title'] = $lastnode['title'];
				$lastInfo[$lastnode['nodeid']]['routeid'] = $lastnode['routeid'];

				$contributorIds[$lastnode['userid']] = $lastnode['userid'];
			}
			else
			{
				//We need another query
				$lastIds[$lastnode['starter']] = $lastnode['starter'];
			}
		}

		//Now get any lastcontent starter information we need
		if (!empty($lastIds))
		{
			$nodes = vB_Library::instance('node')->getNodes($lastIds);
			foreach ($nodeContent AS $index => $channel)
			{
				$nodeid = $lastInfo[$channel['lastcontentid']]['starter'];
				if (isset($nodes[$nodeid]))
				{
					$node =& $nodes[$nodeid];
					$lastInfo[$channel['lastcontentid']]['routeid'] = $node['routeid'];
					$lastInfo[$channel['lastcontentid']]['title'] = $node['title'];

					$contributorIds[$node['userid']] = $node['userid'];
				}
			}
		}

		$groupManagers = array();
		$contributors = array();
		if (!empty($options['contributors']))
		{
			//Get contributors
			$groups = vB::getDbAssertor()->getColumn('usergroup', 'usergroupid', array('systemgroupid' => array(
					vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID
				)),
				false,
				'systemgroupid'
			);

			$membersQry = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'nodeid' => $channelids,
				'groupid' => $groups
			));

			foreach ($membersQry AS $record)
			{
				if ($record['groupid'] == $groups[vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID])
				{
					$groupManagers[] = $record;
				}
				$contributorIds[$record['userid']] = $record['userid'];
				$cacheEvents[] = 'sgMemberChg_' . $record['userid'];
			}
		}

		// get avatar information for all relevant users
		$userApi = vB_Api::instanceInternal('user');
		$avatarInfo = $userApi->fetchAvatars($contributorIds);

		if (!empty($groupManagers))
		{
			foreach ($groupManagers AS $index => $contributor)
			{
				if (!isset($contributors[$contributor['nodeid']]))
				{
					$contributors[$contributor['nodeid']] = array();
				}
				$userInfo = $userApi->fetchUserinfo($contributor['userid']);
				$contributors[$contributor['nodeid']][$contributor['userid']] = $userInfo;
				$contributors[$contributor['nodeid']][$contributor['userid']]['avatar'] = $avatarInfo[$contributor['userid']];
			}
		}

		// Obtain keys for sg pages
		$pageKeyInfo = array();
		$routes = vB::getDbAssertor()->getRows('routenew', array('class' => 'vB5_Route_Channel', 'contentid' =>$channelids),false,'routeid');
		vB5_Route::preloadRoutes(array_keys($routes));
		foreach ($routes AS $record)
		{
			$route = vB5_Route_Channel::getRoute($record['routeid'], @unserialize($record['arguments']));
			if ($route AND ($pageKey = $route->getPageKey()))
			{
				$pageKeyInfo[$pageKey] = $record['contentid'];
			}
		}

		$viewingQry = vB::getDbAssertor()->getRows('session',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'pagekey' => array_keys($pageKeyInfo))
		);

		$viewing = array();

		foreach ($viewingQry AS $viewingUser)
		{
			if (!isset($viewing[$viewingUser['nodeid']]))
			{
				$viewing[$viewingUser['nodeid']] = 0;
			}
			$viewing[$viewingUser['nodeid']]++;
		}

		// get the members count
		$countRecords = vB::getDbAssertor()->assertQuery('vBForum:getChannelMembersCount', array(
			'nodeid' => $channelids,
			'groupid' => $groups
		));

		$membersCount = array();
		foreach ($countRecords AS $count)
		{
			$membersCount[$count['nodeid']] = $count;
		}

		foreach ($nodeContent AS $index => $channel)
		{
			$nodeid = $channel['nodeid'];
			if (!empty($options['contributors']))
			{
				$nodeContent[$index]['contributors'] = !empty($contributors[$nodeid]) ? $contributors[$nodeid] : 0;
				$nodeContent[$index]['contributorscount'] = !empty($contributors[$nodeid]) ? count($contributors[$nodeid]) : 0;
			}
			$nodeContent[$index]['members'] = !empty($membersCount[$nodeid]) ? $membersCount[$nodeid]['members'] : 0;
			$nodeContent[$index]['viewing'] = !empty($viewing[$nodeid]) ? $viewing[$nodeid] : 0 ;
			$nodeContent[$index]['lastposttitle'] = !empty($lastInfo[$channel['lastcontentid']]['title']) ? $lastInfo[$channel['lastcontentid']]['title'] : 0;
			$nodeContent[$index]['lastpostrouteid'] = !empty($lastInfo[$channel['lastcontentid']]['routeid']) ? $lastInfo[$channel['lastcontentid']]['routeid'] : 0;

			$nodeContent[$index]['owner_avatar'] = $avatarInfo[$nodeContent[$index]['userid']];
			$nodeContent[$index]['lastauthor_avatar'] = $avatarInfo[$nodeContent[$index]['lastauthorid']];
		}

		$total = $totalCount['totalcount'];
		if ($total > 0)
		{
			$pages = ceil($total / $perpage);
		}
		else
		{
			$pages = 1; //we don't want the UI to display Page 1 of 0
		}

		$pageInfo = array(
			'currentpage' => $page,
			'perpage' => $perpage,
			'prevurl' => '',
			'nexturl' => '',
			'totalpages' => $pages,
			'totalrecords' => $total,
			'sgparent' => $sgParent,
		);

		$result = array(
			'results' => $nodeContent,
			'totalcount' => count($nodeContent),
			'pageInfo' => $pageInfo,
		);
		vB_Cache::instance(vB_Cache::CACHE_FAST)->write($cacheKey, $result, 60, array_unique($cacheEvents));

		//we don't cache the pagination URLs as they may vary for the same content depending on the specified routeInfo (routeId, arguments, queryParameters)
		$paginationURLs = $this->buildPaginationURLs($page, $pages, $routeInfo);
		if ($paginationURLs)
		{
			$pageInfo = array_merge($pageInfo, $paginationURLs);
			$result['pageInfo'] = $pageInfo;
		}

		return $result;
	}

	/**
	 * Builds pagination previous and next URLs.
	 *
	 * @param	int		The current page number.
	 * @param	int		The total number of pages.
	 * @param	Array	The route information containing routeId, arguments and queryParameters.
	 * @return	Array	The pagination array containing prevurl and nexturl. Returns false if routeId is not specified or invalid or if there is only one page.
	 */
	protected function buildPaginationURLs($page = 1, $totalpages = 1, $routeInfo = array())
	{
		//if the caller did not pass routeId or there is only one page, then don't build the prev and next URLs
		if (isset($routeInfo['routeId']) AND intval($routeInfo['routeId']) > 0 AND ($page < $totalpages OR $page > 1))
		{
			$prevUrl = $nextUrl = '';
			$baseUrl = vB::getDatastore()->getOption('frontendurl');

			if ($page < $totalpages)
			{
				$routeInfo['arguments']['pagenum'] = $page + 1;
				$nextUrl = $baseUrl . vB5_Route::buildUrl($routeInfo['routeId'], $routeInfo['arguments'], $routeInfo['queryParameters']);
			}

			if ($page > 1)
			{
				$routeInfo['arguments']['pagenum'] = $page - 1;
				$prevUrl = $baseUrl . vB5_Route::buildUrl($routeInfo['routeId'], $routeInfo['arguments'], $routeInfo['queryParameters']);
			}

			return array(
				'prevurl' => $prevUrl,
				'nexturl' => $nextUrl
			);
		}

		return false;
	}

	/**
	 * Get the current user's permissions for own stuff
	 * (eg. Own groups, own discussions, own messages)
	 *
	 *	@param int	the nodeid to check
	 *	@return	array of permissions set to yes
	 */
	public function getSGOwnerPerms($nodeid)
	{
		$userContext = vB::getUserContext();
		$perms = array();

		$node = vB_Api::instanceInternal('node')->getNode($nodeid, true, false);
		if (!intval($nodeid) OR !$this->isSGNode($nodeid, $node))
		{
			return $perms;
		}

		// removed canmanageowngroups VBV-13160. If templates need this, we should be checking for canconfigchannel & canadminforums
		// on the current node like in vB_Library_Content::validate() update check.
		// Also see canmanageownchannels checked by node API for soft deleting posts for moderation.

		// removed caneditowngroups VBV-13160. Use see above note for replacement permissions.

		// keep this in sync with vB_Library_Content::validate() delete check.
		if ($userContext->getChannelPermission('forumpermissions2', 'candeletechannel', $node['nodeid']) OR
			$userContext->hasAdminPermission('canadminforums'))
		{
			$perms['candeletechannel'] = 1;
		}

		// removed canmanagediscussions &  canmanagemessages, VBV-13160

		return $perms;
	}

	/**
	 * returns the category list- direct children of the social group channel
	 *
	 * @return mixed	array of nodeid => title
	 */
	public function getCategories()
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$categories = $cache->read('vbSGChannels');
		if (!empty($categories))
		{
			return $categories;
		}
		$sgChannel = $this->getSGChannel();
		$categories = vB::getDbAssertor()->getRows('vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'parentid' => $sgChannel,
				'contenttypeid' => vB_Types::instance()->getContentTypeID('vBForum_Channel')
			),
			'title',
			'nodeid'
		);

		$return = array();
		$userContext = vB::getUserContext();
		$events = array();
		vB_Library::instance('node')->fetchClosureParent(array_keys($categories));
		foreach ($categories as $category)
		{
			if ($userContext->getChannelPermission( 'forumpermissions', 'canview', $category['nodeid'], false, $sgChannel))
			{
				$return[$category['nodeid']] = array(
					'title' => $category['title'],
					'htmltitle' => $category['htmltitle'],
					'routeid' => $category['routeid'],
					'content' => $category['content'],
				);
				$events[] = 'routeChg_' . $category['routeid'];
				$events[] = 'nodeChg_' . $category['content'];
			}
			vB_Library_Content::writeToCache(array($category), vB_Library_Content::CACHELEVEL_NODE);
		}
		$cache->write('vbSGChannels', $return, 1440, $events);
		return $return;
	}

	/**
	 * creates a new social group
	 *
	 * @param mixed	array which must include parentid, title. Should also have various options and a description.
	 *
	 * @return int nodeid of the created group/channel
	 */
	public function createSocialGroup($input)
	{
		if (empty($input['parentid']))
		{
			throw new vB_Exception_Api('invalid_sg_parent');
		}

		$sgParent = intval($input['parentid']);
		$catNode = vB_Api::instanceInternal('node')->getNode($sgParent);
		if (empty($catNode) OR $catNode['parentid'] != $this->getSGChannel())
		{
			throw new vB_Exception_Api('invalid_sg_parent');
		}

		// Check for the permissions
		$check = vB_Api::instanceInternal('content_channel')->canAddChannel($this->getSGChannel());
		if (!$check['can'] AND $check['exceeded'])
		{
			throw new vB_Exception_Api('you_can_only_create_x_groups_delete', array($check['exceeded']));
		}
		// Note that this->createChannel() will also check for create permissions, so leaving the sketchy check
		// above alone as a "limit check" only.

		// social group type, we allow post by default while creating social group
		$input['nodeoptions'] = 2;
		switch ($input['group_type'])
		{
			case 2:
				$input['nodeoptions'] |= vB_Api_Node::OPTION_NODE_INVITEONLY;
				break;
			case 1:
				break;
			default:
				$input['nodeoptions'] |= vB_Api_Node::OPTION_AUTOAPPROVE_MEMBERSHIP;
				break;
		}

		// This node option can come in from the createcontent controller as part of $input.
		// Because of the way vB_Library_Content::updateNodeOptions(), if we specify 'nodeoptions'
		// like above, we must specify the rest of the node options in the same format because all
		// of the name-specified bitfields (e.g. $input['moderate_topics'], $input['disablesmilies']
		// get ignored in that case
		// Minimal-change version:
		if (!empty($input['moderate_topics']))
		{
			$input['nodeoptions'] |= vB_Api_Node::OPTION_MODERATE_TOPICS;
		}
		// All node options version:
		/*
		$nodeOptions = vB_Library::instanceInternal('node')->getOptions();
		foreach ($nodeOptions AS $key => $bit)
		{
			if (!empty($input[$key]))
			{
				$input['nodeoptions'] |= $bit;
			}
		}
		*/

		return $this->createChannel(
			$input,
			$sgParent,
			vB_Page::getSGConversPageTemplate(),
			vB_Page::getSGChannelPageTemplate(),
			vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID
		);
	}

	/**
	 * creates a new category
	 *
	 *	@param	int
	 * @param mixed	array which must include title and optionally parentid
	 *
	 * @return int nodeid of the created category
	 */
	public function saveCategory($nodeId, $input)
	{
		$channelApi = vB_Api::instanceInternal('content_channel');

		$nodeId = (int) $nodeId;

		// force social group channel as parent id (categories cannot be nested)
		$input['parentid'] = $this->getSGChannel();
		$input['category'] = 1; // force channel to be a category
		$input['templates']['vB5_Route_Channel'] = vB_Page::getSGCategoryPageTemplate();
		$input['templates']['vB5_Route_Conversation'] = vB_Page::getSGCategoryConversPageTemplate();

		// TODO: this code is similar to vB_Api_Widget::saveChannel, add a library method with it?
		if ($nodeId > 0)
		{
			// this call won't update parentid
			$channelApi->update($nodeId, $input);
		}
		else
		{
			$nodeId = $channelApi->add($input);
		}

		return $nodeId;
	}

	public function changeCategory($groupid, $categoryid)
	{
		if (!$this->isSGChannel($groupid))
		{
			throw new vB_Exception_Api('channel_not_socialgroup', array($groupid));
		}

		$categories = $this->getCategories();
		if (!isset($categories[$categoryid]))
		{
			throw new vB_Exception_Api('invalid_sg_parent');
		}

		$nodeLib = vB_Library::instance('node');
		$channelLib = vB_Library::instance('content_channel');

		//if someone can update the social group channel, let them change which category it is in.
		if (!$channelLib->validate(array('parentid' => $categoryid), vB_Library_Content::ACTION_UPDATE, $groupid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$node = $nodeLib->getNode($groupid);

		//it isn't really an error if the parent is already the same
		//but we don't want to call moveNodes if it is, nothing to do
		if($catgoryid != $node['parentid'])
		{
			$nodeLib->moveNodes($groupid, $categoryid);
		}

		return array('success' => true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102017 $
|| #######################################################################
\*=========================================================================*/
