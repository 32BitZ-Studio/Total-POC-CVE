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
 * vB_Api_Blog
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Blog extends vB_Api
{
	/**
	 * @var object The database assertor object instance
	 */
	protected $assertor = null;

	/**
	 * @var object The blog library object instance
	 */
	protected $library;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
		$this->library = vB_Library::instance('blog');
	}

	/**
	 * Creates a blog channel
	 *
	 * @param  array Array of input
	 *
	 * @return array
	 */
	public function createBlog($input)
	{
		$this->canCreateBlog($this->getBlogChannel());

		// check that 'auto_subscribe_on_join' is set, in case this didn't come through the createcontent controller
		if (!isset($input['auto_subscribe_on_join']))
		{
			$input['auto_subscribe_on_join'] = 1;
		}

		return $this->createChannel(
			$input,
			$this->getBlogChannel(),
			vB_Page::getBlogConversPageTemplate(),
			vB_Page::getBlogChannelPageTemplate(),
			vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID
		);
	}

	/**
	 * Check validity of data passed in and create a blog or group channel
	 *
	 * @param array $input
	 * @param int $channelid
	 * @param int $channelConvTemplateid
	 * @param int $channelPgTemplateId
	 * @param int $ownerSystemGroupId
	 *
	 * @return int The nodeid of the new blog channel.
	 */
	protected function createChannel($input, $channelid, $channelConvTemplateid, $channelPgTemplateId, $ownerSystemGroupId)
	{
		// Check user is logged in
		$currentSession = vB::getCurrentSession();
		$userid = $currentSession->get('userid');
		$userid = intval($userid);
		if (!$channelid)
		{
			$channelid = $this->getBlogChannel();
		}

		if ($userid <= 0 || !vB::getUserContext()->getChannelPermission('createpermissions', 'vBForum_Channel', $channelid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		// Check input is valid
		$errors = array();

		$input['title'] = isset($input['title']) ? trim($input['title']) : '';
		$input['description'] = isset($input['description']) ? trim($input['description']) : '';
		$input['parentid'] = $channelid;

		if (empty($input['title']))
		{
			if (isset($this->sgChannel))
			{
				$errors[] = 'content_no_title';
			}
			else //For Blogs, blank title should default to <username>'s Blog
			{
				$userInfo = $currentSession->fetch_userinfo();
				$input['title'] = (string) new vB_Phrase('global', 'x_blog', $userInfo['username']);
			}
		}

		//blank title may have been auto-filled for Blog, so let's check for title again
		if (!empty($input['title']))
		{
			if (empty($input['urlident']))
			{
				$input['urlident'] = $this->toSeoFriendly($input['title']);
			}

			// verify prefixes do not collide
			$newPrefix = vB5_Route_Channel::createPrefix($channelid, $input['urlident'], true);
			if (vB5_Route::isPrefixUsed($newPrefix) !== FALSE)
			{
				$errors[] = (isset($this->sgChannel)) ? 'sg_title_exists' : 'blog_title_exists';
			}
		}

		if (!empty($errors))
		{
			$e = new vB_Exception_Api();
			foreach ($errors as $error)
			{
				$e->add_error($error);
			}

			throw $e;
		}

		$input = vB_Api::instanceInternal('content_channel')->cleanInput($input, $channelid);
		$nodeid = $this->library->createChannel($input, $channelid, $channelConvTemplateid, $channelPgTemplateId, $ownerSystemGroupId);

		// Because "subscribe" in blogs is equivalent to "join AND subscribe" of a group, and because there is no interface for a group owner to
		// separately subscribe to a blog they created, we must subscribe the owner to the newly created blog.
		// Since social group API inherits the blog API, we can't just do that in the library's createChannel() function after it creates the groupintopic
		// record (look for vB_User::setGroupInTopic(...))
		// So we check to see if the channel created is a blog (as opposed to a social group), and if so, create a subscription.
		if ($this->isBlogNode($nodeid))
		{
			vB_Api::instanceInternal('follow')->add($nodeid, vB_Api_Follow::FOLLOWTYPE_CHANNELS, $userid, true);
		}

		return $nodeid;
	}

	/**
	 * @uses fetch the id of the global Blog Channel
	 * @return int nodeid of actual Main Blog Channel
	 */
	public function getBlogChannel()
	{
		return $this->library->getBlogChannel();
	}

	/**
	 * Determines if the given node is a blog-related node (blog entry).
	 *
	 * @param  int  $nodeid
	 *
	 * @return bool
	 */
	public function isBlogNode($nodeId, $node = false)
	{
		$nodeId = (int) $nodeId;

		if ($nodeId < 0)
		{
			return false;
		}

		$blogChannelId = (int) $this->getBlogChannel();

		if (empty($node))
		{
			$node = vB_Library::instance('node')->getNode($nodeId, true, false);
		}

		if (empty($node['parents']))
		{
			$parents = vB_Library::instance('node')->getParents($nodeId);
			foreach ($parents as $parent)
			{
				if ($parent['nodeid'] == $blogChannelId)
				{
					return true;
				}
			}
			return false;
		}

		return in_array($blogChannelId, $node['parents']);
	}

	/**
	 * @uses Get info on every Blog Channel
	 *
	 * @param int Page number
	 * @param int Per page
	 * @param int The userid of the owner or author of the blog channels to fetch. If 0, blog channels for all users are fetched.
	 *
	 * @return mixed array containing the blog channel info we need
	 */
	public function getBlogInfo($from = 1, $perpage = 20, $authorid = 0)
	{
		$response = array();
		$nodeApi = vB_Api::instanceInternal('node');
		$blogParentChannel = $this->getBlogChannel();
		$channelContentType  = vB_Types::instance()->getContentTypeId('vBForum_Channel');

		//Get base data
		$options = array('channel' => $blogParentChannel, 'depth' => 1, 'type' => 'vBForum_Channel', 'nolimit' => 1);

		if (intval($authorid) > 0)
		{
			$options['authorid'] = $authorid;
		}

		$nodeContent = vB_Api::instanceInternal('search')->getInitialResults($options, $perpage, $from);
		//We need the nodeids to collect some data
		$lastids = array();
		$channelids = array();

		$pageKeyInfo = array();
		$remaining_channelids = array();

		foreach ($nodeContent['results'] AS $key => $node)
		{
			if ($node['lastcontentid'] > 0)
			{
				$lastids[] = $node['lastcontentid'];
			}
			$channelids[] = $node['nodeid'];
			$remaining_channelids[] = $node['nodeid'];
		}

		if (empty($channelids))
		{
			return array();
		}

		$lastNodes = vB_Api::instanceInternal('node')->getNodes($lastids);

		//Get contributors
		$contributorQry = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $channelids,
			'groupid' => vB_Api::instanceInternal('usergroup')->getModeratorGroupId()
		));
		$userApi = vB_Api::instanceInternal('user');
		$contributors = array();
		$contributorsAvatarToFetch = array();
		$contributorsInfo = array();
		foreach ($contributorQry as $contributor)
		{
			if (!isset($contributors[$contributor['nodeid']]))
			{
				$contributors[$contributor['nodeid']] = array();
			}
			$userInfo = $userApi->fetchUserinfo($contributor['userid'], array(vB_Api_User::USERINFO_AVATAR));
			$contributorsAvatarToFetch[] = $userInfo['userid'];
			$contributorsInfo[$userInfo['userid']] = $userInfo;
			$contributors[$contributor['nodeid']][$contributor['userid']] = $userInfo;
		}

		// Fetching and setting avatar url for contributors
		$avatarsurl = $userApi->fetchAvatars($contributorsAvatarToFetch, true, $contributorsInfo);
		foreach ($contributors as $nodeid => $nodeContributors)
		{
			foreach ($nodeContributors as $contributorid => $contributor)
			{
				if (isset($avatarsurl[$contributorid]))
				{
					$contributors[$nodeid][$contributorid]['avatar'] = $avatarsurl[$contributorid];
				}
			}
		}

		if (!empty($remaining_channelids))
		{
			$routes = vB::getDbAssertor()->assertQuery('routenew', array('class' => 'vB5_Route_Channel', 'contentid' =>$remaining_channelids));
			foreach ($routes as $record)
			{
				$route = vB5_Route_Channel::getRoute($record['routeid'], @unserialize($record['arguments']));

				if ($route AND ($pageKey = $route->getPageKey()))
				{
					$pageKeyInfo[$pageKey] = $record['contentid'];
				}
			}
		}
		// ... now obtain visits
		$viewingQry = vB::getDbAssertor()->getRows('session',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'pagekey' => array_keys($pageKeyInfo))
		);
		$viewing = array();
		foreach ($viewingQry as $viewingUser)
		{
			$nodeId = $pageKeyInfo[$viewingUser['pagekey']];
			if (!isset($viewing[$nodeId]))
			{
				$viewing[$nodeId] = 0;
			}
			$viewing[$nodeId]++;
		}

		foreach ($nodeContent['results'] AS $index => $channel)
		{
			$nodeid = $channel['nodeid'];
			$nodeContent['results'][$index]['contributors'] = (!empty($contributors[$nodeid]) ? $contributors[$nodeid] : array());
			$nodeContent['results'][$index]['viewing'] = (!empty($viewing[$nodeid]) ? $viewing[$nodeid] : 0);
			if (!empty($lastNodes[$channel['lastcontentid']]))
			{
				$nodeContent['results'][$index]['lastposttitle'] = $lastNodes[$channel['lastcontentid']]['title'];
				$nodeContent['results'][$index]['lastpost'] = $lastNodes[$channel['lastcontentid']];
			}
		}

		return $nodeContent;
	}

	/**
	 * Returns a list of channel owner permissions and their values
	 *
	 * @param  int   Channel Node ID
	 *
	 * @return array List of permissions and their values:
	 *               canmanageusers (value from moderatorpermissions:canaddowners)
	 *               canmoderate (value from moderatorpermissions:canmoderateposts)
	 *               canconfig (value from forumpermissions2:canconfigchannel)
	 *               canmanagechannel (value from forumpermissions2:candeletechannel)
	 *               canstats true
	 */
	public function getChannelAdminPerms($nodeid)
	{
		$userContext = vB::getUserContext();
		if ($userContext->fetchUserId() == 0)
		{
			return array('canmanageusers' => 0, 'canmoderate' => 0, 'canconfig' => 0, 'canstats' => 0);
		}

		return array(
			'canmanageusers'   => $userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $nodeid),
			'canmoderate'      => $userContext->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid),
			'canconfig'        => $userContext->getChannelPermission('forumpermissions2', 'canconfigchannel', $nodeid),
			'canmanagechannel' => $userContext->getChannelPermission('forumpermissions2', 'candeletechannel', $nodeid),
			'canstats'         => ($userContext->isAdministrator() OR $userContext->isSuperMod() OR $this->isChannelModerator($nodeid)),
		);
	}

	/**
	 * Returns the userid of the channel owner
	 *
	 * @param  int Channel Node ID
	 *
	 * @return int Channel owner user ID
	 */
	public function fetchOwner($nodeid)
	{
		$contributors = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', array(
				'nodeid' => $nodeid,
				'groupid' => array(vB_Api::instanceInternal('usergroup')->getOwnerGroupId())
			)
		);

		if ($contributors->valid())
		{
			$owner = $contributors->current();
			return $owner['userid'];
		}

		return false;
	}

	/**
	 * Returns the userids of the channel contributors (moderators)
	 *
	 * @param  int   Channel Node ID
	 * @param  int   (optional) Max number of userids to return
	 *
	 * @return array Array of channel contributor user IDs
	 */
	public function fetchContributors($nodeid, $count = false)
	{
		$contributors = vB::getDbAssertor()->getRows('vBForum:groupintopic', array(
				'nodeid' => $nodeid,
				'groupid' => vB_Api::instanceInternal('usergroup')->getModeratorGroupId(),
				vB_dB_Query::PARAM_LIMIT => $count
			),
			false,
			'userid'
		);

		return empty ($contributors) ? array() : array_keys($contributors);
	}

	/**
	 * Fetches information about members (subscribers) for a blog.
	 *
	 * For actual node subscription information
	 * @see vB_Api_Follow::fetchNodeSubscribers()
	 *
	 * @param	int $nodeid the nodeid
	 * @param	int $pageno page for which we want data
	 * @param	int	$perpage items per page
	 * @param bool $thumb whether to get the thumbnail avatar
	 *
	 * @return	mixed	array with
	 * 	'count'=> total subscriber count
	 * 	'pagecount' => total number of pages
	 * 	'groupid' => id for the channel member group
	 * 	'members'=> array of users:
	 * 	* avatarUrl
	 * 	* username
	 * 	* userid
	 *
	 */
	public function fetchSubscribers($nodeid, $pageno = 1, $perpage = 20, $thumb = false)
	{
		// NOTE: This function has a lot of overlap with fetchMembers()

		$nodeid = (int) $nodeid;
		$pageno = (int) $pageno;
		$perpage = (int) $perpage;

		if ($nodeid < 1 OR $pageno < 1 OR $perpage < 1)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$userContext = vB::getUserContext();

		if (!$userContext->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$userApi = vB_Api::instanceInternal('user');
		$assertor = vB::getDbAssertor();

		$memberGroup = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID);
		$memberCount = $assertor->getRow('vBForum:groupintopicCount', array('groupid' => $memberGroup['usergroupid'], 'nodeid' => intval($nodeid)));

		$results = array(
			'count' => $memberCount['count'],
			'pagecount' => ceil($memberCount['count'] / $perpage),
			'groupid' => $memberGroup['usergroupid'],
			'members' => array()
		);
		$offset = (intval($pageno) -1) * intval($perpage);

		$members = $assertor->assertQuery('vBForum:groupintopicPage',
			array(
				'groupid' => $memberGroup['usergroupid'],
				'nodeid' => intval($nodeid),
				vB_dB_Query::PARAM_LIMITSTART => $offset,
				vB_dB_Query::PARAM_LIMIT => intval($perpage))
		);
		foreach ($members AS $member)
		{
			$avatarUrl = $userApi->fetchAvatar($member['userid'], $thumb, $member);
			if (empty($avatarUrl))
			{
				$member['avatarUrl'] = 0;
			}
			else
			{
				$member['avatarUrl'] = $avatarUrl['avatarpath'];
			}

			// remove unneeded information -- 'groupids' was added to the query for use in fetchMembers()
			unset($member['groupids']);

			$results['members'][] = $member;
		}

		return $results;
	}

	/**
	 * Handles subscription in special channels for the current user.
	 * This is used basically for social groups subscription handling the join/subscribe logical but we are
	 * implementing here in case requirements change and join/subscribe gets into blogs too.
	 *
	 * @param	int		The channel id we are subscribing to
	 *
	 * @param	bool	Flag indicating if subscription went well.
	 */
	public function subscribeChannel($channelId)
	{
		if (!intval($channelId))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		$userId = vB::getUserContext()->fetchUserId();
		if (empty($userId))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$nodeInfo = vB_Api::instanceInternal('node')->getNode($channelId);

		// validate that we have joined this
		$result = vB_Api::instanceInternal('user')->getGroupInTopic(vB::getUserContext()->fetchUserId(), $channelId);
		$result = array_pop($result);

		// validate the record
		if (!empty($result) AND ($result['nodeid'] == $channelId))
		{
			$response = vB_Api::instanceInternal('follow')->add($channelId, vB_Api_Follow::FOLLOWTYPE_CHANNELS);
			return $response;
		}
		else
		{
			throw new vB_Exception_Api('invalid_special_channel_subscribe_request');
		}
	}

	/**
	 * Handles leave in special channels for the current or specified user.
	 * This is used basically for social groups handling the join/subscribe logical but we are
	 * implementing here in case requirements change and join/subscribe gets into blogs too.
	 *
	 * @param	int		$channelid		The channel id we are leaving
	 * @param	int		$leavingUser	Optional, userid of the user leaving the channel.
	 *										If not provided, current user will leave the channel.
	 *
	 * @param	bool	Flag indicating if subscription went well.
	 */
	public function leaveChannel($channelId, $leavingUser = 0)
	{
		$currentUser = vB::getUserContext()->fetchUserId();
		if (intval($leavingUser) > 0)
		{
			$userId = intval($leavingUser);
			// Only the channel owner or the user himself can remove a user
			if (($currentUser != $userId) AND ($currentUser != $this->fetchOwner($channelId)))
			{
				throw new vB_Exception_Api('no_permission_remove_channel_user');
			}
		}
		else
		{
			$userId = vB::getUserContext()->fetchUserId();
		}

		// channel moderators & owners cannot leave their own channel
		if ($this->isChannelModerator($channelId, $userId))
		{
			// if someone else is trying to remove this user, the error message is slightly different
			if ((intval($leavingUser) > 0) AND (intval($leavingUser) != $currentUser))
			{
				throw new vB_Exception_Api('no_permission_moderator_leave_channel');
			}
			else
			{
				throw new vB_Exception_Api('no_leave_channel_permission');
			}
		}

		// unfollow first...
		// @TODO change this to use removeFollowing if unsubscribing will use the same logic as regular channels
		// we are only removing the subscribediscussion record here...
		vB_Api::instanceInternal('follow')->delete($channelId, vB_Api_Follow::FOLLOWTYPE_CHANNELS, $userId);
		$memberGroup = vB_Api::instanceInternal('usergroup')->getMemberGroupId();

		if (!$memberGroup)
		{
			throw new vB_Exception_Api('invalid_membergroup_id');
		}

		$result = vB_Api::instanceInternal('user')->unsetGroupInTopic($userId, $channelId, $memberGroup);

		// check if we have a pending request to remove...
		$existingCheck = vB::getDbAssertor()->getRows('vBForum:getNodePendingRequest', array('userid' => array($userId),
			'nodeid' => array($channelId), 'request' => array(vB_Api_Node::REQUEST_GRANT_SUBSCRIBER, vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER)));

		if (!empty($existingCheck) AND is_array($existingCheck))
		{
			$nodeIds = array();
			foreach ($existingCheck AS $rec)
			{
				$nodeIds[] = $rec['nodeid'];
			}

			vB::getDbAssertor()->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $nodeIds));
			vB::getDbAssertor()->assertQuery('vBForum:privatemessage', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $nodeIds));
			vB::getDbAssertor()->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $nodeIds));
			vB::getDbAssertor()->assertQuery('vBForum:text', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $nodeIds));
		}

		return $result;
	}

	/**
	 * Handles removing a channel member
	 *
	 * @param	int		$channelid		The channel id of that $userId is leaving
	 * @param	int		$userId			Userid of the user leaving the channel.
	 *
	 * @param	bool					Flag indicating that the user was removed successfully
	 */
	public function removeChannelMember($channelId, $userId)
	{
		if (!intval($channelId))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}
		if (!(intval($userId) > 0))
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}

		// if the user is a channel owner or moderator, following with throw an exception.
		return $this->leaveChannel($channelId, $userId);
	}

	/**
	 * Handles removing a channel moderator
	 *
	 * @param	int		$channelid		The channel id of that $userId is leaving
	 * @param	int		$userId			Userid of the user leaving the channel.
	 *
	 * @param	bool					Flag indicating the moderator was removed successfully
	 */
	public function removeChannelModerator($channelId, $userId)
	{
		if (!intval($channelId))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}
		if (!(intval($userId) > 0))
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}

		// only the channel owner can add or remove moderators
		$currentUser = vB::getUserContext()->fetchUserId();
		if ($currentUser != $this->fetchOwner($channelId))
		{
			throw new vB_Exception_Api('invalid_permissions');
		}

		// check for member/moderator records.
		$memberGroupId = vB_Api::instanceInternal('usergroup')->getMemberGroupId();
		$moderatorGroupId = vB_Api::instanceInternal('usergroup')->getModeratorGroupId();
		$gitQry = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', array(
				'userid' => $userId,
				'nodeid' => $channelId,
				'groupid' => array($memberGroupId, $moderatorGroupId)
			)
		);

		// If the soon to be ex-moderator does not have a membership, we add one, but only
		// if they were actually a moderator (as opposed to pending)
		$needsMembership = false;
		if ($gitQry->valid())
		{
			foreach ($gitQry AS $gitRow)
			{
				if ($gitRow['groupid'] == $moderatorGroupId)
				{
					$needsMembership = true;
				}
				else if ($gitRow['groupid'] == $memberGroupId)
				{
					$needsMembership = false;
					break;
				}
			}
		}


		// unset group in topic, which also removes pending requests to that user
		$result = vB_Api::instanceInternal('user')->unsetGroupInTopic($userId, $channelId, $moderatorGroupId);

		// add membership & subscription as needed
		if ($needsMembership)
		{
			$isMember = vB_User::setGroupInTopic($userId, $channelId, $memberGroupId);

			// if autosubscribe, add subscription
			$node = vB_Api::instanceInternal('node')->getNode($channelId);
			if ( (($node['nodeoptions'] & vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN) > 0) AND $isMember)
			{
				vB_Api::instanceInternal('follow')->add($channelId, vB_Api_Follow::FOLLOWTYPE_CHANNELS, $userId, true);
			}
		}

		return $result;
	}

	/**
	 * Cancels a channel transfer request
	 *
	 * @param	int	$channelid
	 * @param	int	$userId
	 *
	 * @param	bool
	 */
	public function cancelChannelTransfer($channelId, $userId)
	{
		$channelId = (int) $channelId;
		$userId = (int) $userId;

		if ($channelId < 1)
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		if ($userId < 1)
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}

		// check permissions for cancelling a transfer request
		$usercontext = vB::getUserContext();
		if (!$usercontext->getChannelPermission('moderatorpermissions', 'canaddowners', $channelId))
		{
			throw new vB_Exception_Api('no_permission');
		}

		//deny the pending request
		$pending = vB::getDbAssertor()->assertQuery('vBForum:fetchPendingChannelRequestUser', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				'msgtype' => 'request',
				'aboutid' => $channelId,
				'about' => array(
					vB_Api_Node::REQUEST_TAKE_OWNER,
					vB_Api_Node::REQUEST_SG_TAKE_OWNER
				),
				'userid' => $userId,
			)
		);

		if ($pending)
		{
			$messageLib = vB_Library::instance('content_privatemessage');
			foreach($pending AS $p)
			{
				$messageLib->denyRequest($p['nodeid'], $userId);
			}
		}

		return true;
	}

	/**
	 * Indicates if the given user or current user is owner or mod from given channel.
	 * Owner can't leave the channel ditto for mods (managers or contributors).
	 *
	 * @param	int		$channelId		The channel id we are checking.
	 * @param	int		$checkUser			Optional, the user id we're checking if we're not checking the current user
	 *
	 * @param	bool	Flag indicating if user is owner/mod
	 */
	public function isChannelModerator($channelId, $checkUser = 0)
	{
		if (intval($checkUser) > 0 )
		{
			$userId = intval($checkUser);
		}
		else
		{
			$userId = vB::getUserContext()->fetchUserId();
		}
		$groupids = vB_Api::instanceInternal('usergroup')->getMultipleGroupIds(array(
			vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
			vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID
		));

		$channelMembers = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', array(
			'nodeid' => $channelId,
			'groupid' => $groupids
		));

		$ismod = false;
		foreach ($channelMembers AS $record)
		{
			if ($userId == $record['userid'])
			{
				$ismod = true;
			}
		}

		return $ismod;
	}

	/**
	 * Indicates if the current user is member of a given channelid
	 *
	 * @param	int		The channel id we are checking.
	 *
	 * @return	int		Values of the member status.
	 * 					0 = no member
	 * 					1 = member
	 * 					2 = request pending
	 */
	public function isChannelMember($channelId)
	{
		if (!intval($channelId))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		$userId = vB::getUserContext()->fetchUserId();
		if (empty($userId))
		{
			throw new vB_Exception_Api('invalid_current_userid', array($userId));
		}

		$result = vB_Api::instanceInternal('user')->getGroupInTopic(vB::getUserContext()->fetchUserId(), $channelId);

		$memberStatus = 0;
		// try to check if we have a pending request...
		if (empty($result))
		{
			$pending = vB::getDbAssertor()->getRow('vBForum:getNodePendingRequest', array(
				'nodeid' => $channelId, 'userid' => $userId, 'request' => array(vB_Api_Node::REQUEST_SG_GRANT_MEMBER, vB_Api_Node::REQUEST_GRANT_MEMBER)
			));
			if (!empty($pending))
			{
				$memberStatus = 2;
			}
		}
		else
		{
			$memberStatus = 1;
		}

		return $memberStatus;
	}

	/**
	 * Returns whether current user can comment in the blog or not
	 *
	 * @param	array	Either a single blog post or an array of elements containing blog posts info.The info for each blog post must have:
	 *					- nodeid
	 *					- parentid
	 *					- nodeoptions
	 *
	 * @return	array	- Returns an array with nodeid as key and value for "user can comment"?
	 *					0 : No (Commenting is disabled for the blog post or the blog channel)
	 *					-1: No (User is not logged in and Guests have no permission to comment
	 *					-2: No (User is logged in but is not subscribed to the blog post - permission to comment is set for subscribers only)
	 *					1 : Yes
	 */
	public function userCanComment($blogPosts)
	{
		if (empty($blogPosts))
		{
			return array();
		}

		if (isset($blogPosts['parentid']))
		{
			// a single post
			$blogPosts = array($blogPosts);
		}

		$result = array();
		$channelInfo = array();
		foreach($blogPosts AS $key => $post)
		{
			//this can come from the outside, so let's do some extra checking to
			//avoid complete garbage.
			if(!is_array($post))
			{
				throw new vB_Exception_Api('invalid_data_w_x_y_z', array($post, '$blogPosts[' . $key . ']', __CLASS__, __FUNCTION__));
			}

			$entry_allow_comments = (isset($post['nodeoptions']) ? ($post['nodeoptions'] & vB_Api_Node::OPTION_ALLOW_POST) : 0);
			if (empty($entry_allow_comments))
			{
				//comments are disabled on the blog entry level
				$result[$post['nodeid']] = 0;
			}
			else if (isset($post['canreply']) AND !$post['canreply'])
			{
				// user cannot reply to this post.
				$result[$post['nodeid']] = 0;
			}
			else if (!empty($post['parentid']) AND ($channelId = intval($post['parentid'])))
			{
				$channelInfo[$channelId][] = $post['nodeid'];
			}
		}

		if (!empty($channelInfo))
		{
			$userId = vB::getUserContext()->fetchUserId();

			$channels = vB_Library::instance('node')->getNodes(array_keys($channelInfo));

			if (!empty($channels))
			{
				foreach ($channels AS $channel)
				{
					// If comments are off, don't bother checking the rest.
					// added latter to match comment control panel display behavior - see conversation_footer template
					// The comment box still doesn't match the button behavior for owners and admins.
					if (($channel['nodeoptions'] & vB_Api_Node::OPTION_ALLOW_POST) == 0)
					{
						$canComment = 0;
					}
					else
					{
						switch ($channel['commentperms'])
						{
							//everyone can post
							case 2:
								$canComment = 1;
							break;
							// registered or subscribed
							case 1:
								// if they're not logged in, then they can't comment
								if (empty($userId))
								{
									$canComment = -1;
								}
								else
								{
									$canComment = 1;
								}
							break;
							//user must be subscribed to the blog
							case 0:
							default:
								// if they're not logged in, then they can't comment
								if (empty($userId))
								{
									$canComment = -1;
								}
								else if ($this->isChannelMember($channelId) == 1)
								{
									// user is subscribed
									$canComment = 1;
								}
								else
								{
									// user is logged in but is not a member of the blog
									$canComment = -2;
								}
							break;
						}
					}

					// Add results based on channel info
					foreach($channelInfo[$channel['nodeid']] AS $postId)
					{
						$result[$postId] = $canComment;
					}
				}
			}
		}

		return $result;
	}

	/**
	 * Returns the widget instances that are used for blog sidebar.
	 * This method should be used only for owner configuration of the blog, not rendering
	 *
	 * @param  int Channel ID
	 *
	 * @return array An array of widget instances, keyed by widget instance ID
	 *               <pre>
	 *               array(
	 *                   widget instance ID => array(
	 *                       title
	 *                       widgetid
	 *                       widgetinstanceid
	 *                       hidden (int flag)
	 *                   )
	 *               )
	 *               </pre>
	 */
	public function getBlogSidebarModules($channelId = 0)
	{
		$channelId = intval($channelId);

		$widgetApi = vB_Api::instance('widget');

		// We assume there's only one container in blog pagetemplate. If this is no longer the case, we may need to implement GUID for widgetinstances
		$blogTemplate = vB_Page::getBlogChannelPageTemplate();

		$modules = vB::getDbAssertor()->getRows('getBlogSidebarModules', array('blogPageTemplate' => $blogTemplate));

		$results = $parentConfig = $sortAgain = array();
		foreach($modules AS $module)
		{
			$title = $module['title'];

			//Temporarily removing the Blog Categories module as it is not implemented yet (VBV-4247)
			//@TODO: Remove this when this module gets implemented.
			//@TODO: It would be great if we have a way to globally disable any module and not display it anywhere to avoid this kind of fix.
			if ($module['guid'] == 'vbulletin-widget_blogcategories-4eb423cfd6dea7.34930850')
			{
				continue;
			}
			//END

			if (isset($module['adminconfig']) AND !empty($module['adminconfig']))
			{
				// search for custom title
				$adminConfig = @unserialize($module['adminconfig']);
				if (is_array($adminConfig))
				{
					foreach($adminConfig AS $key => $val)
					{
						if (stripos($key, 'title') !== false)
						{
							$title = $val;
							break;
						}
					}
				}
			}

			if (!isset($parentConfig[$module['containerinstanceid']]))
			{
				$parentConfig[$module['containerinstanceid']] = $widgetApi->fetchConfig($module['containerinstanceid'], 0, $channelId);
				if (isset($parentConfig[$module['containerinstanceid']]['display_order']))
				{
					$sortAgain[] = $module['containerinstanceid'];
				}
			}
			if (isset($parentConfig[$module['containerinstanceid']]['display_modules']) AND !empty($parentConfig[$module['containerinstanceid']]['display_modules']))
			{
				$hidden = in_array($module['widgetinstanceid'], $parentConfig[$module['containerinstanceid']]['display_modules']) ? 0 : 1;
			}
			else
			{
				$hidden = 0;
			}

			$results[$module['widgetinstanceid']] = array(
				'title' => $title,
				'widgetid' => $module['widgetid'],
				'widgetinstanceid' => $module['widgetinstanceid'],
				'hidden' => $hidden
			);
		}

		if (!empty($sortAgain))
		{
			$newOrder = array();
			foreach($sortAgain AS $parent)
			{
				if (is_array($parentConfig[$parent]['display_order']))
				{
					foreach($parentConfig[$parent]['display_order'] AS $widgetInstanceId)
					{
						$newOrder[$widgetInstanceId] = $results[$widgetInstanceId];
						unset($results[$widgetInstanceId]);
					}
				}

				// append remaining items
				$newOrder += $results;
			}

			return $newOrder;
		}
		else
		{
			return $results;
		}
	}

	/**
	 * Saves channel configuration for blog sidebar
	 *
	 * @param int               $blogId
	 * @param array             $modules An array in which each element contains:
	 *                          - widgetinstanceid (int)
	 *                          - hide (bool)
	 * @throws vB_Exception_Api no_permission
	 */
	public function saveBlogSidebarModules($blogId, $modules)
	{
		if (empty($blogId) OR empty($modules))
		{
			return;
		}

		// check the user is owner
		$userid = vB::getCurrentSession()->get('userid');
		if ($userid != $this->fetchOwner($blogId))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$config = array(
			'display_order' => array(),
			'display_modules' => array()
		);

		foreach($modules AS $module)
		{
			$config['display_order'][] = $module['widgetinstanceid'];
			if (!$module['hide'])
			{
				$config['display_modules'][] = $module['widgetinstanceid'];
			}
		}

		// get parent (container widget instance)
		$parent = vB::getDbAssertor()->getField('widgetinstance', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('containerinstanceid'),
			vB_dB_Query::CONDITIONS_KEY => array(
				'widgetinstanceid' => $config['display_order']
			)
		));

		vB_Api::instance('widget')->saveChannelConfig($parent, $blogId, $config);
	}

	/**
	 * Gets the number of members for the given blog channel
	 *
	 * @param  int              nodeid
	 *
	 * @throws vB_Exception_Api invalid_node_id If it is not a blog channel
	 *
 	 * @return int              number of members
	 */
	public function getMembersCount($nodeid)
	{
		$node = vB_Api::instanceInternal('node')->getNode($nodeid, true, false);
		if (!intval($nodeid) OR !$this->isBlogNode($nodeid, $node))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		return $this->doMembersCount($nodeid);
	}

	/**
	 * Returns the number of members for the channel (blog or group)
	 *
	 * @param  int Node ID for the channel
	 *
	 * @return int Number of members
	 */
	protected function doMembersCount($nodeid)
	{
		$db = vB::getDbAssertor();

		$groups = $db->getColumn(
			'usergroup',
			'usergroupid',
			array(
				'systemgroupid' => array(
					vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID
				)
			),
			false,
			'systemgroupid'
		);

		// get the members count -- since nodeid is not an array this will return a single record
		$countRecord = $db->getRow('vBForum:getChannelMembersCount', array(
			'nodeid' => array($nodeid),
			'groupid' => $groups
		));

		if($countRecord)
		{
			return $countRecord['members'];
		}
		else
		{
			//probably not needed, but let's make sure.
			return 0;
		}
	}

	/**
	 * Lists channel members
	 *
	 * This is used for groups.
	 *
	 * @param  int nodeid
	 * @param  int pageno       Page number to fetch
	 * @param  int perpage      Number of members to list per page
	 * @param  bool thumb       Whether to return the thumbnail version of the avatar
	 *
	 * @throws vB_Exception_Api invalid_data
	 * @throws vB_Exception_Api no_permission
	 *
	 * @return array
	 *	int count     -- total count of members
	 *	array members -- list of userid => Array
	 *		int userid
	 *		string username
	 *		string avatarUrl -- deprecated, use avatarpath
	 *		string avatarpath -- the user's avatar url path.  Thumbnail path if requested
	 *		int groupid -- the groupid from the channel member usergroup
	 *	int pagecount -- total number of pages
	 */
	public function fetchMembers($nodeid, $pageno = 1, $perpage = 20, $thumb = false, $includeOwnersAndMods = false)
	{
		// NOTE: This function has a lot of overlap with fetchSubscribers()

		$nodeid = (int) $nodeid;
		$pageno = (int) $pageno;
		$perpage = (int) $perpage;

		if ($nodeid < 1 OR $pageno < 1 OR $perpage < 1)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		//we don't use this data, but we need to validate that the user can load the node.
	 	$node = vB_Api::instanceInternal('node')->getNodeContent($nodeid);

		$assertor = vB::getDbAssertor();
		$pageno = max($pageno, 1);

		if ($includeOwnersAndMods)
		{
			// Need to return owners and moderators too, since they are also members of the social group.
			$groupids = vB_Api::instanceInternal('usergroup')->getMultipleGroupIds(array(
				vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
				vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
				vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID,
			));
		}
		else
		{
			$groupids = vB_Api::instanceInternal('usergroup')->getMultipleGroupIds(array(
				vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
			));
		}

		$memberQry = $assertor->assertQuery('vBForum:groupintopicPage', array(
			vB_dB_Query::PARAM_LIMIT => $perpage,
			vB_dB_Query::PARAM_LIMITSTART => $perpage * ($pageno - 1),
			'nodeid' => $nodeid,
			'groupid' => $groupids
		));

		$sortFunc = function($a, $b)
		{
			static $order = null;

			if ($order === null)
			{
				$order = vB_Api::instanceInternal('usergroup')->getMultipleGroupIds(array(
					vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
					vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
				));
			}

			$apos = array_search($a, $order);
			$bpos = array_search($b, $order);

			return $apos < $bpos ? -1 : ($apos > $bpos ? 1 : 0);
		};

		$members = array();
		foreach ($memberQry as $member)
		{
			// Users can have multiple usergroups in 'groupintopic'. Store the
			// "highest" of these in the groupid element (owner > moderator > member)
			$ids = explode(',', $member['groupids']);
			// We could sort in the GROUP_CONCAT in the query, but I don't think we
			// can rely on a particular order of the usergroupids in the database
			// In other words, there might be cases where they aren't 9, 10, and 11.
			// Upgrades from vB4, for example. So let's sort here.
			usort($ids, $sortFunc);

			$members[$member['userid']] = array(
				'groupid' => reset($ids),
			);
		}

		if (empty($members))
		{
			return array(
				'count' => 0,
				'members' => array(),
				'pagecount' => 1,
			);
		}

		$userApi = vB_Api::instanceInternal('user');

		$userQry = $assertor->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'userid' => array_keys($members)
		));

		foreach ($userQry AS $user)
		{
			$avatarUrl = $userApi->fetchAvatar($user['userid'], $thumb, $user);
			if (empty($avatarUrl))
			{
				$user['avatarUrl'] = 0;
			}
			else
			{
				$user['avatarUrl'] = $avatarUrl['avatarpath'];
			}

			$members[$user['userid']]['userid'] = $user['userid'];
			$members[$user['userid']]['username'] = $user['username'];
			$members[$user['userid']]['avatarUrl'] = $user['avatarUrl'];
			$members[$user['userid']]['avatarpath'] = $user['avatarUrl'];
		}

		$count = $assertor->getRow('vBForum:groupintopicCount', array(
			'groupid' => $groupids,
			'nodeid' => $nodeid,
		));

		$count = $count['count'];
		$pagecount = ceil($count / $perpage);

		return array(
			'count'     => $count,
			'members'   => $members,
			'pagecount' => $pagecount,
		);
	}

	/**
	 * Checks if the user can create a new Blog
	 *
	 * @param  int              Parentid of the blog parent
	 *
	 * @throws vB_Exception_Api invalid_blog_parent
	 * @throws vB_Exception_Api you_can_only_create_x_blogs
	 *
	 * @return bool
	 */
	public function canCreateBlog($parentid)
	{
		if (empty($parentid))
		{
			throw new vB_Exception_Api('invalid_blog_parent');
		}

		$blogNode = vB_Api::instanceInternal('node')->getNode(intval($parentid));

		if (empty($blogNode) OR $blogNode['nodeid'] != $this->getBlogChannel())
		{
			throw new vB_Exception_Api('invalid_blog_parent');
		}

		// Check for the permissions
		$check = vB_Api::instanceInternal('content_channel')->canAddChannel($blogNode['nodeid']);

		if (!$check['can'] AND $check['exceeded'])
		{
			throw new vB_Exception_Api('you_can_only_create_x_blogs', array($check['exceeded']));
		}

		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101586 $
|| #######################################################################
\*=========================================================================*/
