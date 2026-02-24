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
 * vB_Api_Node
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Node extends vB_Api
{

	/** @TODO: this is duplicated info which is already declared in querydef. We should read it from there.*/
	protected $contentAPIs = array();

	/**
	 * @var 	array 	 Collection of nodeids with content library related.
	 */
	protected $contentLibraries = array();

	/**
	 *
	 * @var vB_Library_Node
	 */
	protected $library;

	/**
	 * @var	array	Channel statistics populated by fetchChannelNodeTree and accessed by getChannelStatistics.
	 */
	protected $channelStatistics = false;

	const FILTER_SOURCEALL = 'source_all';
	const FILTER_SOURCEUSER = 'source_user';
	const FILTER_SOURCEVM = 'source_vm';

	const FILTER_SORTMOSTRECENT = 'sort_recent';
	const FILTER_SORTPOPULAR = 'sort_popular';
	const FILTER_SORTFEATURED = 'sort_featured';
	const FILTER_SORTOLDEST = 'sort_oldest';

	const FILTER_SHOWALL = 'show_all';
	const FILTER_TIME = 'date';
	const FILTER_SOURCE = 'filter_source';
	const FILTER_SORT = 'sort';
	const FILTER_ORDER = 'order';
	const FILTER_SHOW = 'filter_show';
	const FILTER_FOLLOW = 'filter_follow';
	const FILTER_DEPTH= 'filter_depth';

	// When adding new channel requests, be sure to add it to the $channelRequests array in vB_Library_Content_Privatemessage

	// requests for blogs
	const REQUEST_TAKE_OWNER = 'owner_to';// ask the recipient to assume ownership;
	const REQUEST_TAKE_MODERATOR = 'moderator_to';// ask the recipient to assume moderation;
	const REQUEST_TAKE_MEMBER = 'member_to';// ask the recipient to become a member;
	// @TODO for inviting subscriber functionality
	const REQUEST_TAKE_SUBSCRIBER = 'subscriber_to';// ask the recipient to become a subscriber;
	const REQUEST_GRANT_OWNER = 'owner_from';// ask the recipient to grant ownership;
	const REQUEST_GRANT_MODERATOR = 'moderator';// ask the recipient to grant moderation;
	const REQUEST_GRANT_MEMBER = 'member';// ask the recipient to grant membership;
	const REQUEST_GRANT_SUBSCRIBER = 'subscriber';// ask the recipient to grant subscribription, used for forum-channels;

	// requests for social groups
	const REQUEST_SG_TAKE_OWNER = 'sg_owner_to';// ask the recipient to assume ownership;
	const REQUEST_SG_TAKE_MODERATOR = 'sg_moderator_to';// ask the recipient to assume moderation;
	const REQUEST_SG_TAKE_MEMBER = 'sg_member_to';// ask the recipient to become a member;
	// @TODO for inviting subscriber functionality
	const REQUEST_SG_TAKE_SUBSCRIBER = 'sg_subscriber_to';// ask the recipient to become a subscriber;
	const REQUEST_SG_GRANT_OWNER = 'sg_owner_from';// ask the recipient to grant ownership;
	const REQUEST_SG_GRANT_MODERATOR = 'sg_moderator';// ask the recipient to grant moderation;
	const REQUEST_SG_GRANT_MEMBER = 'sg_member';// ask the recipient to grant membership;
	const REQUEST_SG_GRANT_SUBSCRIBER = 'sg_subscriber';// ask the recipient to grant subscription;

	const OPTION_ALLOW_POST = 2;
	const OPTION_MODERATE_COMMENTS = 4;
	const OPTION_AUTOAPPROVE_MEMBERSHIP = 8;
	const OPTION_NODE_INVITEONLY = 16;
	const OPTION_NODE_PARSELINKS = 32;
	const OPTION_NODE_DISABLE_SMILIES = 64;
	const OPTION_AUTOAPPROVE_SUBSCRIPTION = 128;
	const OPTION_MODERATE_TOPICS = 256;
	const OPTION_AUTOSUBSCRIBE_ON_JOIN = 512;		// mainly used for blogs, but binds membership & subscription together (membership approval/removal also adds/removes subscription)
	const OPTION_NODE_DISABLE_BBCODE = 1024;		// disable bbcode parsing. Used for static pages (CMS)
	const OPTION_NODE_HIDE_TITLE = 2048;			// CMS
	const OPTION_NODE_HIDE_AUTHOR = 4096;			// CMS
	const OPTION_NODE_HIDE_PUBLISHDATE = 8192;		// CMS
	const OPTION_NODE_DISPLAY_FULL_IN_CATEGORY = 16384;	// CMS
	const OPTION_NODE_DISPLAY_PAGEVIEWS = 32768;		// CMS
	const OPTION_NODE_HIDE_COMMENT_COUNT = 65536;		// CMS

	const DATE_RANGE_DAILY = 'daily';
	const DATE_RANGE_MONTHLY = 'monthly';

	//This should be kept consistent with content library $allCanview. Anything there should be here,
	// although not necessarily the reverse.
	protected $previewFields = array('nodeid' => 'nodeid', 'title' => 'title', 'publishdate' => 'publishdate',
		'showpublished' => 'showpublished', 'showapproved' => 'showapproved', 'routeid' => 'routeid',
		'contenttypeid' => 'contenttypeid', 'publishdate' => 'publishdate', 'unpublishdate' => 'unpublishdate',
		'description' => 'description',	'htmltitle' => 'htmltitle', 'parentid' => 'parentid',
		'urlident' => 'urlident', 'displayorder' => 'displayorder', 'created' => 'created',
		'taglist' => 'taglist', 'showopen' => 'showopen', 'nodeoptions' => 'nodeoptions',
		'public_preview' => 'public_preview', 'channelid' => 'channelid', 'channelroute' => 'channelroute',
		'channeltitle' => 'channeltitle', 'starterroute' => 'starterroute', 'startertitle' => 'startertitle',
		'views' => 'views',	'disable_bbcode' => 'disable_bbcode', 'hide_title' => 'hide_title',
		'hide_author' => 'hide_author', 'hide_publishdate' => 'hide_publishdate',
		'display_fullincategory' => 'display_fullincategory', 'display_pageviews' => 'display_pageviews',
		'channeltype' => 'channeltype', 'edit_reason' =>  'edit_reason', 'edit_userid' =>  'edit_userid', 'edit_username' =>  'edit_username',
		'edit_dateline' =>  'edit_dateline', 'hashistory' =>  'hashistory',  'starternodeoptions' =>  'starternodeoptions',
		'channelnodeoptions' =>  'channelnodeoptions', 'contenttypeclass' => 'contenttypeclass',
		);

	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('node');
		$this->pmContenttypeid = vB_Types::instance()->getContentTypeId('vBForum_PrivateMessage');
	}

	/**
	 * opens a node for posting
	 *
	 * @param	mixed	integer or array of integers
	 * @return	mixed	Either array 'errors' => error string or array of id's.
	 */
	public function openNode($nodeid)
	{
		$userContext = vB::getUserContext();
		if($userContext->isModerator())
		{
			$this->inlinemodAuthCheck();
		}


		//we need to handle a single nodeid or an array of nodeids
		if (!is_array($nodeid))
		{
			$nodeids = array($nodeid);
		}
		else
		{
			$nodeids = $nodeid;
		}
		//First check permissions of course.
		foreach ($nodeids as $nodeid)
		{
			//this can be approved through moderator permissions, or because the node is the current user's and they have forumpermission canopenclose
			if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canopenclose', $nodeid))
			{
				$node = $this->library->getNode($nodeid);

				if(($node['userid'] != vB::getCurrentSession()->get('userid')) OR
					!vB::getUserContext()->getChannelPermission('forumpermissions', 'canopenclose', $nodeid))
				{
					throw new vB_Exception_Api('no_permission');
				}
			}
		}

		return $this->library->openNode($nodeids);
	}

	/**
	 * Closes a node for posting. Closed nodes can still be viewed but nobody can reply to one.
	 *
	 * 	@param	mixed	integer or array of integers
	 *
	 *	@return	mixed	Either array 'errors' => error string or array of id's.
	 */
	public function closeNode($nodeid)
	{
		$userContext = vB::getUserContext();
		if($userContext->isModerator())
		{
			$this->inlinemodAuthCheck();
		}

		//we need to handle a single nodeid or an array of nodeids
		if (!is_array($nodeid))
		{
			$nodeids = array($nodeid);
		}
		else
		{
			$nodeids = $nodeid;
		}

		//First check permissions of course.
		foreach ($nodeids as $nodeid)
		{
			//this can be approved through moderator permissions, or because the node is the current user's and they have forumpermission canopenclose
			if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canopenclose', $nodeid))
			{
				$node = $this->library->getNode($nodeid);

				if(($node['userid'] != vB::getCurrentSession()->get('userid')) OR
					!vB::getUserContext()->getChannelPermission('forumpermissions', 'canopenclose', $nodeid))
				{
					throw new vB_Exception_Api('no_permission');
				}
			}
		}

		return $this->library->closeNode($nodeids);
	}

	/**
	 * Permanently/Temporarily deletes a set of nodes
	 *	@param	array	The nodeids of the records to be deleted
	 *	@param	bool	hard/soft delete
	 *	@param	string	the reason for soft delete (not used for hard delete)
	 *	@param	bool	Log the deletes in moderator log
	 *  @param	bool	Report node content to spam service
	 *
	 *	@return	array nodeids that were deleted
	 */
	public function deleteNodes($nodeids, $hard = true, $reason = '', $modlog = true, $reportspam = false)
	{
		if (empty($nodeids))
		{
			return false;
		}
		//If it's a protected channel, don't allow removal.
		$existing = vB_Library::instance('node')->getNodes($nodeids);
		// need to see if we require authentication
		$currentUserId = vB::getCurrentSession()->get('userid');
		$need_auth = false;
		$moderateInfo = vB::getUserContext()->getCanModerate();
		$allowToDelete = array();
		foreach ($existing as $node)
		{
			// this is a Visitor Message
			if (!empty($node['setfor']) AND ($node['setfor'] == $currentUserId))
			{
				$canModerateOwn = vB::getUserContext()->hasPermission('visitormessagepermissions', 'canmanageownprofile');
				if ($canModerateOwn)
				{
					$allowToDelete[$node['nodeid']] = $node['nodeid'];
					continue;
				}
			}
			else
			{
				$canModerateOwn = vB::getUserContext()->getChannelPermission('forumpermissions2', 'canmanageownchannels', $node['nodeid']);
			}

			// check if this is the owner of a blog that needs to moderate the comments
			if (!empty($moderateInfo['can']) OR ($canModerateOwn))
			{
				// let's get the channel node
				$channelid = vB_Library::instance('node')->getChannelId($node);
				if ($channelid == $node['nodeid'])
				{
					$channel = $node;
				}
				else
				{
					$channel = vB_Library::instance('node')->getNodeBare($channelid);
				}

				// this channel was created by the current user so we don't need the auth check
				if ( (in_array($channelid, $moderateInfo['can']) OR $canModerateOwn) AND ($channel['userid'] == $currentUserId))
				{
					$allowToDelete[$node['nodeid']] = $node['nodeid'];
					continue;
				}
			}

			if ($node['userid'] != $currentUserId)
			{
				$need_auth = true;
				break;
			}
		}

		$userContext = vB::getUserContext();
		// VBV-12184 Only moderators should get the inline mod auth prompt
		if (($need_auth OR $reportspam) AND $userContext->isModerator())
		{
			$this->inlinemodAuthCheck();
		}

		$deleteNodeIds = array();
		$vmChannel = $this->fetchVMChannel();
		$contenttype_Channel = vB_Types::instance()->getContentTypeId('vBForum_Channel');
		foreach ($existing as $node)
		{
			//Check for protected- O.K. if it's not a channel.
			if ($node['protected'] AND ($node['contenttypeid'] == $contenttype_Channel))
			{
				throw new vB_Exception_Api('invalid_request');
			}


			// note that canremoveposts gives them ONLY physical-delete permissions, not soft delete.
			$canDeleteAsMod =
				(
					($userContext->getChannelPermission('moderatorpermissions', 'canremoveposts', $node['nodeid']) AND $hard)
					OR
					($userContext->getChannelPermission('moderatorpermissions', 'candeleteposts', $node['nodeid']) AND !$hard)
				);
			$canSoftDeleteOwn =
				(
					($node['userid'] == $currentUserId)
					AND !$hard
					AND (
							(($node['starter'] == $node['nodeid']) AND
								$userContext->getChannelPermission('forumpermissions', 'candeletethread', $node['nodeid']))
							OR
							(($node['starter'] != $node['nodeid']) AND
								$userContext->getChannelPermission('forumpermissions', 'candeletepost', $node['nodeid']))
					)
				);
			$canSoftDeleteOthers =
				(
					($node['userid'] != $currentUserId)
					AND !$hard
					AND $userContext->getChannelPermission('forumpermissions2', 'candeleteothers', $node['nodeid'])

				);

			// if they're not allowed to delete this node let's throw an exception in their face
			if (
				!(
					array_key_exists($node['nodeid'], $allowToDelete)
					OR $canDeleteAsMod OR $canSoftDeleteOwn	OR $canSoftDeleteOthers
				)
			)
			{
				throw new vB_Exception_Api('no_permission');
			}

			if ($node['parentid'] == $vmChannel AND $node['setfor'] == $currentUserId)
			{
				$vm_user = vB_User::fetchUserinfo($node['setfor']);
				if (!vB::getUserContext($vm_user['userid'])->hasPermission('genericpermissions', 'canviewmembers'))
				{
					throw new vB_Exception_Api('no_permission');
				}
			}

			array_push($deleteNodeIds, $node['nodeid']);
		}

		if (empty($deleteNodeIds))
		{
			return array();
		}

		return $this->library->deleteNodes($deleteNodeIds, $hard, $reason, $modlog, $reportspam);
	}


	/**
	 * Delete nodes as spam
	 *
	 * @param array	$nodeids The nodeids of the records to be deleted
	 * @param array $userids Selected userids who are being applied punitive action to
	 * @param bool $hard hard/soft delete
	 * @param string $reason
	 * @param bool $deleteother Whether to delete other posts and threads started by the affected users
	 * @param bool $banusers Whether to ban the affected users
	 * @param int $banusergroupid Which banned usergroup to move the users to
	 * @param string $period Ban period
	 * @param string $banreason Ban reason
	 */
	public function deleteNodesAsSpam(
		$nodeids,
		$userids = array(),
		$hard = true,
		$reason = "",
		$deleteother = false,
		$banusers = false,
		$banusergroupid = 0,
		$period = 'PERMANENT',
		$banreason = '',
		$report = false
	)
	{
		$this->inlinemodAuthCheck();
		// Permission check
		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		$usercontext = &vB::getUserContext();

		if ($banusers AND !$usercontext->hasPermission('moderatorpermissions', 'canbanusers'))
		{
			$forumHome = vB_Library::instance('content_channel')->getForumHomeChannel();
			throw new vB_Exception_Api('nopermission_loggedin',
				$loginuser['username'],
				vB_Template_Runtime::fetchStyleVar('right'),
				vB::getCurrentSession()->get('sessionurl'),
				$loginuser['securitytoken'],
				vB5_Route::buildUrl($forumHome['routeid'] . '|fullurl')
			);
		}

		foreach ((array)$nodeids as $k => $nodeid)
		{
			if (!$usercontext->getChannelPermission('moderatorpermissions', 'canremoveposts', $nodeid))
			{
				unset($nodeids[$k]);
			}
		}

		if (empty($nodeids))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$checkuserids = $this->fetchUsersFromNodeids($nodeids);
		$userids = array_intersect((array)$userids, array_keys($checkuserids));

		if ($deleteother AND !empty($userids))
		{
			$search_api = vB_Api::instanceInternal('search');
			$search_json = json_encode(array(
				'authorid'		=> $userids,
				'ignore_cache' => true,
				'exclude_type' => array(
					'vBForum_Channel',
					'vBForum_PrivateMessage',
					'vBForum_Report',
					'vBForum_Infraction',
				)
			));

			$result = $search_api->getSearchResult($search_json);

			$othernodeids = array();
			do
			{
				$othernodes = $search_api->getMoreNodes($result['resultId']);

				if ($othernodeids == array_values($othernodes['nodeIds']))
				{
					break;
				}
				$othernodeids = array_values($othernodes['nodeIds']);

				if (!empty($othernodeids))
				{
					$this->deleteNodes($othernodeids, $hard, $reason, true, $report);
				}
			} while (!empty($othernodeids));
		}
		else
		{
			$this->deleteNodes($nodeids, $hard, $reason, true, $report);
		}

		if ($banusers AND !empty($userids))
		{
			$user_api = vB_Api::instanceInternal('user');
			//get a $banusergroupid if none is provided
			if (empty($banusergroupid))
			{
				$bannedusergroups = vB_Api::instanceInternal('usergroup')->fetchBannedUsergroups();
				$banusergroupid = key($bannedusergroups);
			}
			$user_api->banUsers($userids, $banusergroupid, $period, $banreason);
		}

		return $nodeids;
	}

	/**
	 * undeletes a set of nodes
	 * @param	array	The nodeids of the records to be deleted
	 *
	 * @return	array nodeids that were deleted
	 */
	public function undeleteNodes($nodeids)
	{
		if (empty($nodeids))
		{
			return false;
		}

		$assertor = vB::getDbAssertor();
		//If it's a protected channel, don't allow removal.
		$existing = vB_Library::instance('node')->getNodes($nodeids);
		// need to see if we require authentication
		$currentUserid = vB::getCurrentSession()->get('userid');
		$userContext = vB::getUserContext();
		//If any of the nodes are channels we need to rebuild
		$needRebuild = false;
		foreach ($existing as $node)
		{
			if ($node['userid'] != $currentUserid)
			{
				$this->inlinemodAuthCheck();
			}

			if ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'))
			{
				$needRebuild = true;
			}

			if (!$userContext->getChannelPermission('moderatorpermissions', 'candeleteposts', $node['nodeid']))
			{
				//one check for channels
				if (($node['starter'] == 0) AND $userContext->getChannelPermission('forumpermissions2', 'canmanageownchannels', $node['nodeid']))
				{

					$starter = vB_Api::instanceInternal('node')->getNode($node['starter']);
					$channel = vB_Api::instanceInternal('node')->getNode($starter['parentid']);

					if ($channel['userid'] != $currentUserid)
					{
						throw new vB_Exception_Api('no_delete_permissions');
					}
				}
				else
				{
					throw new vB_Exception_Api('no_delete_permissions');
				}
			}
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		return $this->library->undeleteNodes($nodeids, $needRebuild);
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
		$userContext = vB::getUserContext();

		if($userContext->isModerator())
		{
			$this->inlinemodAuthCheck();
		}

		$to_parent = $this->assertNodeidStr($to_parent);

		//this depends fairly heavily on the fact that we cache calls to getNodes.
		//since we'll call it repeatedly both here and in the library class for the same
		//set of nodes.
		$isTopicMerge = $this->moveIsTopicMerge($nodeids, $to_parent);

		//If the current user has can moderator canmove on the current nodes, or if the user can create in
		//the new channel and is the owner of the moved nodes and has forum canmove, then they can move
		if (
			!$userContext->getChannelPermission('forumpermissions', 'canmove', $to_parent) AND
			!$userContext->getChannelPermission('moderatorpermissions', 'canmassmove', $to_parent) AND
			(!$isTopicMerge OR !$userContext->getChannelPermission('moderatorpermissions', 'canmanagethreads', $to_parent))
		)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$currentUserid = vB::getCurrentSession()->get('userid');

		$nodes = $this->library->getNodes($nodeids);
		foreach ($nodes AS $node)
		{
			$hasPermission = (
				$userContext->getChannelPermission('moderatorpermissions', 'canmassmove', $node['nodeid']) OR
				(
					($currentUserid == $node['userid']) AND
					$userContext->getChannelPermission('forumpermissions', 'canmove', $node['nodeid'], false, $node['parentid'])
				) OR
				($isTopicMerge AND $userContext->getChannelPermission('moderatorpermissions', 'canmanagethreads', $to_parent))
			);

			if (!$hasPermission)
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		return $this->library->moveNodes($nodeids, $to_parent, $makeTopic, $newtitle, $modlog, $leaveRedirectData);
	}


	private function moveIsTopicMerge($nodeids, $to_parent)
	{
		$checkNodes = $this->getNodes(array_merge((array)$nodeids, (array)$to_parent));
		// If all the nodes to be moved are content nodes and are currently in the same
		// channel, then we are only merging posts/topics and need to check different permissions.
		// To detemine this, we iterate through all the nodes to be moved and get all the "starter"
		// nodeids. We then iterate through all the starters and check if they all have the same
		// parentid, which is the channel they are in.
		$checkStarterIds = array();
		foreach ($checkNodes AS $checkNode)
		{
			if (empty($checkNode['starter']))
			{
				// we can skip this check because one of the nodes is a channel
				return false;
				break;
			}
			else
			{
				$checkStarterIds[] = $checkNode['starter'];
			}
		}

		$checkStarters = $this->getNodes($checkStarterIds);
		$starterParents = array();

		foreach ($checkStarters AS $checkStarter)
		{
			$starterParents[$checkStarter['parentid']] = $checkStarter['parentid'];
		}

		if (count($starterParents) === 1)
		{
			// the parent node of all the starters is the same, so we are
			// only moving topics / posts around inside the same channel,
			// this is likely a topic merge request and we can check a separate
			// permission below
			return true;
		}

		return false;
	}

	/**
	 * DEPRECATED Move multiple posts to a new topic or to a new channel.  Use moveNodes function.
	 *
	 * @param $nodeids
	 * @param string|int $to_parent Parent node id. If to_parent is a string, it should be a route path to the node
	 * @param string $newtitle If parent is a channel, the oldest post will be promoted to a Thread with the new title.
	 * @return array Moved node ids
	 * @deprecated
	 */
	public function movePosts($nodeids, $to_parent, $newtitle = '')
	{
		//You should just call the moveNodes method
		return $this->moveNodes($nodeids, $to_parent, true, $newtitle);
	}

	/**
	 * Clone Nodes and their children deeply into a new parent Node.
	 *
	 * @param array $nodeids Source nodeIDs
	 * @param string|int $to_parent Parent node id. If to_parent is a string, it should be a route path to the node
	 * @param string $newtitle If parent is a channel, the oldest post will be promoted to a Thread with the new title.
	 * @return array of origional nodeids as keys, cloned nodeids as values
	 */
	public function cloneNodes($nodeids, $to_parent, $newtitle = '')
	{
		$userContext = vB::getUserContext();
		if($userContext->isModerator())
		{
			$this->inlinemodAuthCheck();
		}

		$to_parent = $this->assertNodeidStr($to_parent);

		// check permissions
		// * if the user has the moderator permission 'canmassmove' on the source and target
		// nodes, they can do the move/copy.
		// * if this node belongs to the user and they have 'canmove' on the source node and
		// they have create permission on the target node, they can do the move/copy.
		$canMassMoveAtTarget = $userContext->getChannelPermission('moderatorpermissions', 'canmassmove', $to_parent);
		$createPermissionsAtTarget = $userContext->getCanCreate($to_parent);
		foreach ($nodeids AS $nodeid)
		{
			if (!$canMassMoveAtTarget OR !$userContext->getChannelPermission('moderatorpermissions', 'canmassmove', $nodeid))
			{
				$node = $this->library->getNode($nodeid);

				$contentTypeClass = vB_Types::instance()->getContentTypeClasses($node['contenttypeid']);
				$contentTypeClass = strtolower($contentTypeClass[$node['contenttypeid']]);

				$canCreateAtTarget = !empty($createPermissionsAtTarget[$contentTypeClass]);

				if(
					$node['userid'] != vB::getCurrentSession()->get('userid') OR
					!$canCreateAtTarget OR
					!$userContext->getChannelPermission('forumpermissions', 'canmove', $nodeid)
				)
				{
					throw new vB_Exception_Api('no_permission');
				}
			}
		}

		return $this->library->cloneNodes($nodeids, $to_parent, $newtitle);
	}

	/**
	 * Convert node path or id string to node id.
	 *
	 * @param string|int $nodestring Node String. If $nodestring is a string, it should be a route path to the node
	 * @return int Node ID
	 */
	protected function assertNodeidStr($nodestring)
	{
		return $this->library->assertNodeidStr($nodestring);
	}

	/**
	 * Merge several topics into a target topic
	 *
	 * @param array $nodeids Source topic node IDs
	 * @param int $targetnodeid Target topic node ID
	 *
	 * @return array
	 */
	public function mergeTopics($nodeids, $targetnodeid, array $leaveRedirectData = array())
	{
		$this->inlinemodAuthCheck();

		// check that the user has permission
		$nodesToCheck = $nodeids;
		$nodesToCheck[] = $targetnodeid;
		foreach ($nodesToCheck AS $key => $nodeid)
		{
			// this is here just in case for some reason, a nodeid is 0. Shouldn't happen, but
			// I don't want getChannelPermission to go bonkers from it.
			if (empty($nodeid))
			{
				unset($nodesToCheck[$key]);
				continue;
			}

			if ( !vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmanagethreads', $nodeid) )
			{
				// perhaps we could generate a list of unmergeable nodes and return a warning instead, but
				// I don't think there's a real use case where a moderator can manage only *some* of the
				// nodes they're trying to merge. I think that would require multiple channels being involved, and
				// we don't have a UI for that so I can't test it. As such I'm just going to throw an exception if
				// *any* of the nodes fail the check.
				throw new vB_Exception_Api('no_permission');
			}
		}

		$mergedNodes = array();
		$sourceNodes = array();

		if (count($nodeids) < 2)
		{
			throw new vB_Exception_Api('not_much_would_be_accomplished_by_merging');
		}

		if (!in_array($targetnodeid, $nodeids))
		{
			throw new vB_Exception_Api('invalid_target');
		}

		$userContext = vB::getUserContext();

		$nodes = vB::getDbAssertor()->getRows('vBForum:node',
			array('nodeid' => $nodeids),
			array(
				'field' => array('publishdate'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			)
		);

		$loginfo = array();
		$targetnode = $this->getNode($targetnodeid);

		foreach ($nodes as $node)
		{
			if (intval($node['inlist']) AND !intval($node['protected'])
				AND
				(
					$userContext->getChannelPermission('forumpermissions', 'canview', $node['nodeid'], false, $node['parentid'])
				)
				AND $node['nodeid'] == $node['starter'] // Node must be a topic
			)
			{
				$mergedNodes[] = $node['nodeid'];

				if ($node['nodeid'] != $targetnodeid)
				{
					$sourceNodes[] = $node['nodeid'];

					$extra = array(
						'targetnodeid'	=> $targetnode['nodeid'],
						'targettitle'	=> $targetnode['title'],
					);

					$loginfo[] = array(
						'nodeid'		=> $node['nodeid'],
						'nodetitle'		=> $node['title'],
						'nodeusername'	=> $node['authorname'],
						'nodeuserid'	=> $node['userid'],
						'action'		=> $extra,
					);
				}
			}
		}

		if (count($mergedNodes) < 2)
		{
			throw new vB_Exception_Api('not_much_would_be_accomplished_by_merging');
		}

		if ($mergedNodes == $sourceNodes)
		{
			// Something wrong with target node
			throw new vB_Exception_Api('invalid_target');
		}

		$this->moveNodes($sourceNodes, $targetnodeid, false, false, false, $leaveRedirectData); // Dont log the individual moves

		// We need to promote the replies of the sourcenodes to the replies of the targetnode instead of being comments of the sourcenodes.
		foreach ($sourceNodes as $sourcenodeid)
		{
			$sourcereplies = vB::getDbAssertor()->getRows('vBForum:node',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'parentid' => $sourcenodeid,
				),
				array(
					'field' => array('publishdate'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				)
			);

			$replyNodes = array();
			foreach ($sourcereplies as $replies)
			{
				$replyNodes[] = $replies['nodeid'];
			}

			if ($replyNodes)
			{
				// Move the replies to the targetnode
				$this->moveNodes($replyNodes, $targetnodeid, false, false, false);
			}
		}

		// If source node is a poll, we need to delete it
		// Here all source nodes' children have been promoted so they won't be deleted
		foreach ($nodes AS $node)
		{
			if ($node['nodeid'] != $targetnodeid AND $node['contenttypeid'] == vB_Types::instance()->getContentTypeId('vBForum_Poll'))
			{
				$this->library->deleteNodes(array($node['nodeid']));
			}
		}

		vB_Library_Admin::logModeratorAction($loginfo, 'node_merged_by_x');

		$clearCacheNodes = array_unique(array_merge($mergedNodes, $sourceNodes, array($targetnodeid)));
		$this->library->clearChildCache($clearCacheNodes);
		$this->clearCacheEvents($clearCacheNodes);

		return array($mergedNodes, $sourceNodes, $targetnodeid);
	}

	/**
	 * Sets the publishdate and (optionally) the unpublish date of a node
	 * @param	integer	The node id
	 * @param	integer	The timestamp for publish date
	 * @param	integer	The timestamp for unpublish date if applicable
	 *
	 * @return	boolean
	 */
	public function setPublishDate($nodeid, $datefrom, $dateto = null)
	{
		if (!intval($nodeid) OR !intval($datefrom))
		{
			throw new Exception('invalid_node_id');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
		{
			throw new Exception('no_publish_permissions');
		}

		return $this->library->setPublishDate($nodeid, $datefrom, $dateto);
	}

	/**
	 * Sets the unpublish date
	 * @param	integer	The node id
	 * @param	integer	The timestamp for unpublish
	 *
	 * @return	boolean
	 */
	public function setUnPublishDate($nodeid, $dateto = false)
	{
		if (!intval($nodeid))
		{
			throw new Exception('invalid_node_id');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
		{
			throw new Exception('no_publish_permissions');
		}

		return $this->library->setUnPublishDate($nodeid, $dateto);
	}

	/**
	 * sets a node to not published
	 * @param	integer	The node id
	 *
	 * @return	boolean
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

		return $this->library->setUnPublished($nodeid);
	}

	/**
	 * sets a list of nodes to be featured
	 * @param	array	The node ids
	 * @param	boot	set or unset the featured flag
	 *
	 * @return	array nodeids that have permission to be featured
	 */
	public function  setFeatured($nodeids, $set = true)
	{
		$this->inlinemodAuthCheck();

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$featureIds = array();
		foreach ($nodeids as $nodeid)
		{
			if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'cansetfeatured', $nodeid))
			{
				continue;
			}
			$featureIds[] = $nodeid;
		}
		//If this user doesn't have the featured permission and they are trying to set it,
		//throw an exception
		if (empty($featureIds))
		{
			throw new Exception('no_featured_permissions');
		}

		return $this->library->setFeatured($featureIds, $set);
	}

	/**
	 * sets a node list to be not featured
	 * @param	array	The node ids
	 *
	 * @return	array nodeids that have permission to be featured
	 */
	public function  setUnFeatured($nodeids)
	{
		return $this->setFeatured($nodeids, false);
	}


	/**
	 * clears the unpublishdate flag.
	 * @param	integer	The node id
	 *
	 * @return	boolean
	 */
	public function  clearUnpublishDate($nodeid)
	{
		if (!intval($nodeid))
		{
			throw new Exception('invalid_node_id');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
		{
			throw new Exception('no_publish_permissions');
		}

		return $this->library->clearUnpublishDate($nodeid);
	}

	/**
	 * gets one node.
	 * @param	integer The node id
	 * @param	boolean Whether to include list of parents
	 * @param	boolean Whether to include joinable content
	 *
	 * @return Array.  A node record, optionally including attachment and ancestry.
	 */
	public function getNode($nodeid, $withParents = false, $withJoinableContent = false)
	{
		$node = $this->library->getNode($nodeid, $withParents, $withJoinableContent);

		//check permissions.
		$approved = $this->validateNodeList(array($nodeid => $node));

		if (!empty($approved['errors']))
		{
			throw new vB_Exception_Api('invalid_request');
		}
		else if (empty($approved) OR empty($approved[$nodeid]))
		{
			throw new vB_Exception_Api('no_permission');
		}
		else
		{
			if (!vB::getUserContext()->getChannelPermission('moderatorpermission', 'canviewips', $nodeid))
			{
				$approved[$nodeid]['ipaddress'] = '';
			}
			return $approved[$nodeid];
		}
	}

	/**
	 * Gets the node info for a list of nodes
	 *	@param	array $nodeList -- array of nodeids
	 *	@param	bool	$withJoinableContent -- Include joinable content
	 *
	 * 	@return array of node records
	 */
	public function getNodes($nodeList, $withJoinableContent = false)
	{
		if (empty($nodeList))
		{
			return array();
		}

		$nodes = $this->library->getNodes($nodeList, $withJoinableContent);
		$nodes = $this->validateNodeList($nodes);

		foreach ($nodes AS $key => $node)
		{
			if (!vB::getUserContext()->getChannelPermission('moderatorpermission', 'canviewips', $node['nodeid'], false, $node['parentid']))
			{
				$nodes[$key]['ipaddress'] = '';
			}
		}
		return $nodes;
	}

	/**
	 * Gets the attachment information for a node. Which may be empty.
	 * @param mixed  	integer or array of integers
	 * @return mixed	either false or an array of attachments with the following fields:
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
	function getNodeAttachments($nodeids)
	{
		if (empty($nodeids))
		{
			return array();
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$userContext = vB::getUserContext();

		$getnodeids = array();
		$perms = array();
		foreach ($nodeids AS $nodeid)
		{
			$perms[$nodeid] = array(
				'cangetattachment' => $userContext->getChannelPermission('forumpermissions', 'cangetattachment', $nodeid),
				'cangetimgattachment' => $userContext->getChannelPermission('forumpermissions2', 'cangetimgattachment', $nodeid),
			);

			if ($perms[$nodeid]['cangetattachment'] OR $perms[$nodeid]['cangetimgattachment'])
			{
				$getnodeids[] = $nodeid;
			}
		}

		if (empty($getnodeids))
		{
			return array();
		}

		$attachments = array();
		$rawAttach = $this->library->fetchNodeAttachments($getnodeids);

		foreach ($rawAttach AS $attach)
		{
			$isImg = (!empty($attach['extension']) AND in_array(strtolower($attach['extension']), array('png', 'bmp', 'jpeg', 'jpg', 'jpe', 'gif')));
			if (
				($isImg AND $perms[$attach['parentid']]['cangetimgattachment'])
				OR
				(!$isImg AND $perms[$attach['parentid']]['cangetattachment'])
			)
			{
				$attachments[$attach['nodeid']] = $attach;
			}
		}

		return $attachments;
	}

	/**
	 * Gets the "public" attachment information for a node. Which may be empty.
	 * @param int|int[]  	$nodeids	nodeid or array of nodeids
	 * @return array	Array(
	 *						{nodeid1} => array(
	 *							{attachmentid1} => array(attachment information),
	 *							{attachmentid2} => array(attachment information)
	 *						),
	 *						{nodeid2} => array(
	 *							{attachmentid3} => array(attachment information),
	 *							{attachmentid4} => array(attachment information)
	 *						),
	 *					)
	 *					Where attachment information contains
	 *						- nodeid
	 *						- parentid
	 *						- filedataid
	 *						- filename
	 *						- filesize
	 *						- settings
	 *						- counter
	 *						- dateline
	 *						- resize_dateline
	 *						- extension
	 *						- userid
	 *						- visible
	 */
	function getNodeAttachmentsPublicInfo($nodeids)
	{
		if (empty($nodeids))
		{
			return array();
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$getnodeids = array();
		$perms = array();
		foreach ($nodeids AS $nodeid)
		{
			$node = $this->library->getNodeBare($nodeid);
			$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
			if (!$contentLib->validate($node, vB_Library_Content::ACTION_VIEW, $node['nodeid'], array($node['nodeid'] => $node)))
			{
				continue;
			}

			$getnodeids[] = $nodeid;

			/*
				We don't care about attachment permissions. This is used for getting enough attachment data
				to create the attachment link for a user who DOES NOT have enough permission to view an image outright.
			$perms[$nodeid] = array(
				'cangetattachment' => vB::getUserContext()->getChannelPermission('forumpermissions', 'cangetattachment', $nodeid),
				'cangetimgattachment' => vB::getUserContext()->getChannelPermission('forumpermissions2', 'cangetimgattachment', $nodeid),
			);
			*/
		}

		if (empty($getnodeids))
		{
			return array();
		}

		$rawAttach = $this->library->fetchNodeAttachments($getnodeids);
		$attachments = $this->filterPublicAttachmentInfo($rawAttach);

		return $attachments;
	}

	/**
	 * Gets the "public" attachment information for a single attachment. If the user cannot view this attachment, it
	 * will be empty. Depending on the cangetattachment  or cangetimgattachment permissions, the returned data will be
	 * consumed to create an anchor, an image, or unparsed bbcode.
	 *
	 *
	 * @param int|int[]  	$attachmentid	nodeid or array of nodeids
	 * @return array	Array(
	 *						{attachmentid1} => array(attachment information)
	 *					)
	 *					Where attachment information contains
	 *						- nodeid
	 *						- parentid
	 *						- filedataid
	 *						- filename
	 *						- filesize
	 *						- settings
	 *						- counter
	 *						- dateline
	 *						- resize_dateline
	 *						- extension
	 *						- userid
	 *						- visible
	 */
	function getAttachmentPublicInfo($attachmentid)
	{
		$attachmentid = intval($attachmentid);
		if (empty($attachmentid))
		{
			return array();
		}

		/*
			We don't care about attachment permissions. This is used for getting enough attachment data
			to create the attachment link for a user who DOES NOT have enough permission to view an image outright.
		$perms[$nodeid] = array(
			'cangetattachment' => vB::getUserContext()->getChannelPermission('forumpermissions', 'cangetattachment', $nodeid),
			'cangetimgattachment' => vB::getUserContext()->getChannelPermission('forumpermissions2', 'cangetimgattachment', $nodeid),
		);
		*/
		$node = $this->library->getNodeBare($attachmentid);
		$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
		if (!$contentLib->validate($node, vB_Library_Content::ACTION_VIEW, $node['nodeid'], array($node['nodeid'] => $node)))
		{
			return array();
		}

		if (empty($node['parentid']))
		{
			return array();
		}

		// Make sure we can also view the parent node that the attachment is under. This is probably overkill..
		$parentNode =  $this->library->getNodeBare($node['parentid']);
		$contentLib = vB_Library_Content::getContentLib($parentNode['contenttypeid']);
		if (!$contentLib->validate($parentNode, vB_Library_Content::ACTION_VIEW, $parentNode['nodeid'], array($parentNode['nodeid'] => $parentNode)))
		{
			return array();
		}

		/*
			We do not yet have queries and methods to access a *single* attachment. I think the closest we have at the moment is the content_attach::fetchImage()
			API function, but that's not quite what we want either. It's rather late in the sprint to be making big refactors, and furthermore, there're
			performance implications of just fetching single attachments at a time.
			For now, let's use existing methods to fetch the parent's attachments, which will be memory cached (for quoted content, this might allow us to skip a
			DB fetch if the quoted node	was on the same page & already rendered in this page load session), and pull out our "single" attachment from the parent list.
		 */



		$rawAttach = array();
		$rawAttaches = $this->library->fetchNodeAttachments(array($parentNode['nodeid']));
		foreach ($rawAttaches AS $attach)
		{
			if ($attach['nodeid'] == $attachmentid)
			{
				$rawAttach = $attach;
				break;
			}
		}

		if (empty($rawAttach))
		{
			return array();
		}

		$attachments = $this->filterPublicAttachmentInfo(array($rawAttach));

		if (isset($attachments[$parentNode['nodeid']][$attachmentid]))
		{
			return array($attachmentid => $attachments[$parentNode['nodeid']][$attachmentid]);
		}
		else
		{
			return array();
		}
	}

	private function filterPublicAttachmentInfo($rawAttachArray)
	{
		$attachments = array();
		$publicFields = array(
			"nodeid",
			"contenttypeid",
			"parentid",
			"filedataid",
			"filename",
			"filesize",
			"settings",
			"resize_filesize",
			"hasthumbnail",
			"counter",
			"dateline",
			"resize_dateline",
			"extension",
			"userid",
			"visible",
		);
		foreach ($rawAttachArray AS $attach)
		{
			foreach ($publicFields AS $fieldname)
			{
				if (isset($attach[$fieldname]))
				{
					$attachments[$attach['parentid']][$attach['nodeid']][$fieldname] = $attach[$fieldname];
				}
			}
		}

		return $attachments;
	}

	/**
	 *	lists the nodes that should be displayed on a specific page including content detail.
	 *	@param	integer	The node id of the parent where we are listing
	 *	@param	integer	page number to return
	 *	@param	integer	items per page
	 *	@param	integer	depth- 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 *	@param	mixed	if desired, will only return specific content types.
	 *	@param	mixed	'sort', or 'exclude' recognized..
	 *							Options flags:
	 *							showVm => appends visitor message node info.
	 *							Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	 *  						withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	 *
	 * 	@return	mixed	array of id's
	 */
	public function listNodeContent($parentid, $page = 1, $perpage = 20, $depth = 0, $contenttypeid = null, $options = false)
	{
		return $this->listNodeFullContent($parentid, $page, $perpage, $depth, $contenttypeid, $options);
	}

	/**
	 *	lists the nodes that should be displayed on a specific page including content detail.
	 *	@param	integer	The node id of the parent where we are listing
	 *	@param	integer	page number to return
	 *	@param	integer	items per page
	 *	@param	integer	depth- 0 means no stopping, otherwise 1= direct child, 2= grandchild, etc
	 *	@param	mixed	if desired, will only return specific content types.
	 *	@param	mixed	'sort', or 'exclude' recognized.
	 *							Options flags:
	 *							showVm => appends visitor message node info.
	 *							Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	 *						withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	 *
	 *	@return	mixed	array of id's
	 */
	public function listNodeFullContent($parentid, $page = 1, $perpage = 20, $depth = 0, $contenttypeid = null, $options = false)
	{
		//First get the node list
		$nodeList = $this->library->listNodes($parentid, $page, $perpage, $depth, $contenttypeid, $options);
		$nodeList = $this->library->addFullContentInfo($nodeList, $options);
		$nodeList = $this->validateNodeList($nodeList);
		$this->library->removePrivateDataFromNodeList($nodeList);

		return $nodeList;
	}

	/**
	 * Lists the "total count" that can be expected from a listNodeFullContent() call with infinite $perpage param.
	 * Used for pagination purposes. Call it with the same parameters you called listNodeFullContent() with.
	 * @See vB_Api_Node::listNodeFullContent()  for function param info
	 *
	 * @return array("totalCount" => integer)
	 */
	public function listNodeFullContentCount($parentid, $page = 1, $perpage = 20, $depth = 0, $contenttypeid = null, $options = false)
	{
		// the search in listNodesInternal() should be cached, so doing this right after calling listNodeFullContent()
		// should be pretty OK.


		$searchResult = $this->library->listNodesInternal($parentid, $page, $perpage, $depth, $contenttypeid, $options);

		/*
		The counts could get out of sync with listNodeFullContent() if any of these calls that are in listNodeFullContent()
		*removes* something from the node list from listNodes(). In that case, we'd need to figure out a way to do the same
		filtering operation cheaply here... if that's even possible.
		//First get the node list
		$nodeList = $this->library->addFullContentInfo($nodeList, $options);
		$nodeList = $this->validateNodeList($nodeList);
		$this->library->removePrivateDataFromNodeList($nodeList);
		*/

		return array(
			'totalCount' => $searchResult['totalRecords'],
		);
	}

	/**
	 *	Gets the content info for a list of nodes
	 *	@param	mixed	array of node ids
	 *	@param 	mixed	array of options.
	 *						Options flags:
	 *							showVm => appends visitor message node info.
	 *							Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	 *  						withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	 *
	 * 	@return	mixed	array of content records
	 */
	public function getContentforNodes($nodeList, $options = false)
	{
		if (empty($nodeList))
		{
			return array();
		}
		$content = $this->library->getContentforNodes($nodeList, $options);
		$content = $this->validateNodeList($content);

		$this->library->removePrivateDataFromNodeList($content);
		return $content;
	}

	/**
	 *	Gets the content info for a list of nodes
	 *	@param array array of node ids
	 *	@param 	mixed	array of options.
	 *						Options flags:
	 *							showVm => appends visitor message node info.
	 *							Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	 *						withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	 *
	 *	@return array array of content records -- preserves the original keys
	 */
	public function getFullContentforNodes($nodeList)
	{
		if (empty($nodeList))
		{
			return array();
		}

		$content = $this->library->getFullContentforNodes($nodeList);
		$content = $this->validateNodeList($content);
		foreach ($content AS $key => $node)
		{
			if (!$node['content']['moderatorperms']['canviewips'])
			{
				$content[$key]['ipaddress'] = '';
				$content[$key]['content']['ipaddress'] = '';
			}
		}
		return $content;
	}

	/**
	 *	Given a list of nodes, removes those the user can't see.
	 *
	 *	@param array $nodes -- list of node arrays
	 *
	 *	@return	array the array passed minus any $nodes that fail the test
	 */
	protected function validateNodeList($nodes)
	{
		//@todo.  Let's look into how this works.
		$userid = vB::getCurrentSession()->get('userid');
		$pmIds = array();
		$nodeMap = array();
		$canViewIps = vB::getUserContext()->hasPermission('moderatorpermissions', 'canviewips');
		//First check permissions
		foreach ($nodes as $key => $node)
		{
			//If they are the author they can see it.
			if ($node['userid'] == $userid)
			{
				continue;
			}
			//if it's a private message, the user can only see if they have a record in sentto or are the originator.
			else if ($node['contenttypeid'] == $this->pmContenttypeid)
			{
				$pmIds[] = $node['nodeid'];
				$nodeMap[$node['nodeid']] = $key;
			}
			else if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $node['nodeid'], false, $node['parentid']))
			{
				if ($node['public_preview'])
				{
					$this->getPreviewOnly($nodes[$key]);
				}
				else
				{
					unset($nodes[$key]);
				}
			}
			else if (!vb::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $node['nodeid']))
			{
				if ($node['public_preview'])
				{
					$this->getPreviewOnly($nodes[$key]);
				}
				else
				{
					//The user can't see content. We hide the content and the "last" data
					unset($nodes[$key]['content']);
					$nodes[$key]['content'] = $node;
					$nodes[$key]['lastcontent'] = $node['publishdate'];
					$nodes[$key]['lastcontentid'] = $node['nodeid'];
					$nodes[$key]['lastcontentauthor'] = $node['authorname'];
					$nodes[$key]['lastauthorid'] = $node['userid'];
					unset($nodes[$key]['photo']);
					unset($nodes[$key]['attach']);
				}
			}
			if (!$canViewIps)
			{
				unset($nodes[$key]['ipaddress']);
			}
		}

		if (!empty($pmIds))
		{
			//The user can see it if there's a record in sentto
			$sentQry = vB::getDbAssertor()->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			 'nodeid' => $pmIds, 'userid' => $userid));
			$cansee = array();
			foreach ($sentQry as $sentto)
			{
				$cansee[] = $sentto['nodeid'];
			}

			$pmIds = array_diff($pmIds, $cansee);

			foreach ($pmIds as $nodeid)
			{
				$index = $nodeMap[$nodeid];

				if ($index !== false)
				{
					unset($nodes[$index]);
				}
			}
		}

		return $nodes;
	}

	/**
	* This gets a content record based on nodeid. Useful from ajax.
	*
	*	@param	int
	*	@param	int	optional
	*	@param	bool optional. 	Options flags:
	*							showVm => appends visitor message node info.
	*							Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	*  							withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	*
	*	@return array.  An array of node record arrays as $nodeid => $node
	*
	*/
	public function getNodeContent($nodeid, $contenttypeid = false, $options = array())
	{
		return $this->getNodeFullContent($nodeid, $contenttypeid, $options);
	}


	/**
	 *	This gets a content record based on nodeid including channel and starter information.
	 *
	 *	@param	int $nodeid
	 *	@param	bool	$contenttypeid optional, defaults to false
	 *	@param	array optional	Options flags:
	 *		showVm => appends visitor message node info.
	 *				Such as isVisitorMessage flag indicating if node is visitor message and vm_userInfo from the user the visitor message was posted for.
	 *	withParent => appends information from the parent. This info will append the 'parentConversation' info if the node is a comment.
	 *
	 *	@return array node list ($nodeid=>node record) will only have one item
	 *
	 */
	public function getNodeFullContent($nodeid, $contenttypeid = false, $options = array())
	{
		if (!is_numeric($nodeid))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$nodeid = intval($nodeid);
		$result = $this->library->getNodeFullContent($nodeid, $contenttypeid, $options);

		//Can happen with a damaged node
		if (empty($result) OR empty($result[$nodeid]) OR empty($result[$nodeid]['nodeid']))
		{
			return array();
		}

		foreach ($result AS $key => $node)
		{
			$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
			if (!$contentLib->validate($node, vB_Library_Content::ACTION_VIEW, $node['nodeid'], array($node['nodeid'] => $node)))
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		$this->library->removePrivateDataFromNodeList($result);

		return $result;
	}

	/**
	 *	This gets a content record based on nodeid including channel and starter information.
	 *
	 *	@param	int $quoteid '12345' for vB4 id (which will be translated).  'n12345' for a vB nodeid
	 *	@return mixed
	 *
	 */
	public function getQuoteFullContent($quoteId)
	{
		if (!is_array($quoteId))
		{
			$quoteId = array($quoteId);
		}

		$nodeIds = $postIds = $translatedIds = array();
		foreach ($quoteId AS $id)
		{
			if (preg_match('#^n(\d+)$#', $id, $matches))
			{
				// it's a node id
				$nodeIds[] = $matches[1];
			}
			else
			{
				// it's a postid from vB4, we need to translate
				$postIds[] = $id;
			}
		}

		if (!empty($postIds))
		{
			// check cache first
			$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
			$cacheKey = 'vB4_QuoteIds';
			$cached = $cache->read($cacheKey);

			if ($cached)
			{
				foreach($postIds AS $key => $oldId)
				{
					if (isset($cached[$oldId]))
					{
						$translatedIds[$cached[$oldId]] = $oldId;
						unset($postIds[$key]);
					}
				}
			}
			else
			{
				$cached = array();
			}

			// do we still need to translate?
			if (!empty($postIds))
			{
				$nodes = vB::getDbAssertor()->assertQuery('vBForum:fetchLegacyPostIds', array(
					'oldids' => $postIds,
					'postContentTypeId' => vB_Types::instance()->getContentTypeID('vBForum_Post'),
				));

				if ($nodes)
				{
					foreach($nodes as $node)
					{
						$translatedIds[$node['nodeid']] = $node['oldid'];
						$cached[$node['oldid']] = $node['nodeid'];
					}

					$cache->write($cacheKey, $cached, 14400);
				}
			}
		}

		// use the the ids originally requested as keys
		$result = array();
		foreach (array_unique($nodeIds + array_keys($translatedIds)) as $nodeId)
		{
			$info = $this->getNodeFullContent($nodeId);
			$info = $info[$nodeId];

			if (in_array($nodeId, $nodeIds))
			{
				$result["n$nodeId"] =& $info;
			}

			if (isset($translatedIds[$nodeId]))
			{
				$result[$translatedIds[$nodeId]] =& $info;
			}
		}

		return $result;
	}

	/**
	 *	Validates permission and sets a node to published status
	 *
	 *	@param	mixed	nodeid- integer or array of integers
	 *
	 */
	public function publish($nodes)
	{
		if (!is_array($nodes))
		{
			$nodes = array($nodes);
		}

		$timeNow = vB::getRequest()->getTimeNow();
		foreach ($nodes as $nodeid)
		{
			if (vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid) OR
			vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
			{
				$this->setPublishDate($nodeid, $timeNow);
			}
		}
	}

	/**
	 * Validates permission and sets a node to unpublished status
	 *
	 *	@param	mixed	nodeid- integer or array of integers
	 *
	 */
	public function unPublish($nodes, $permanent = false)
	{
		if (!is_array($nodes))
		{
			$nodes = array($nodes);
		}

		$approved = array();

		foreach ($nodes as $nodeid)
		{
			if (vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid, false) OR
				vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $nodeid))
			{
				$approved[] = $nodeid;
			}

		}


		if ($permanent)
		{
			$publishdate = -1;
		}
		else
		{
			$publishdate = 0;
		}
		$approvedNodes = vB_Library::instance('node')->getNodes($approved);
		$parents = $starters = array();
		$events = array();
		foreach ($approvedNodes as $approvedNode)
		{
			if (empty($approvedNode['starter']) OR !empty($starters[$approvedNode['starter']]))
			{
				continue;
			}
			$starters[$approvedNode['starter']] = 1;
			$events[] = "nodeChg_" . $approvedNode['starter'];
		}

		if (!empty($starters))
		{
			$starterNodes = vB_Library::instance('node')->getNodes(array_keys($starters));
			foreach ($starterNodes as $starterNode)
			{
				if (empty($starterNode['parentid']) OR !empty($parents[$starterNode['parentid']]))
				{
					continue;
				}
				$parents[$starterNode['parentid']] = 1;
				$events[] = "nodeChg_" . $starterNode['parentid'];
			}
		}
		vB_Cache::allCacheEvent($events);
		foreach ($approved as $nodeid)
		{
			$this->library->setUnPublished($nodeid);
		}
		vB_Library::instance('search')->purgeCacheForCurrentUser();
	}

	/**
	 * Adds one or more attachments
	 *
	 * 	@param 	int
	 *	@param mixed	array of attachment info
	 *
	 *	@return	int		an attachid
	 *
	 */
	public function addAttachment($nodeid, $data)
	{
		/* data must include a filedataid, and possibly
		   any combination of visible,counter,posthash,filename,caption, reportthreadid, settings
		*/
		if (empty($nodeid) OR empty($data['filedataid']))
		{
			throw new Exception('incorrect_attach_data');
		}
		//we need the current node data.
		$node = $this->getNode($nodeid);

		if (empty($node))
		{
			throw new Exception('incorrect_attach_data');
		}

		$maxattachments = vB::getUserContext()->getChannelLimitPermission('forumpermissions', 'maxattachments', $nodeid);

		//check the permission.
		$canAdd = false;
		if (($node['userid'] == vB::getCurrentSession()->get('userid')) AND vB::getUserContext()->getChannelPermission('forumpermissions', 'canpostattachment', $nodeid))
		{
			$canAdd = true;
		}

		if (!$canAdd AND vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateattachments', $nodeid))
		{
			$canAdd = true;
		}

		if (!$canAdd)
		{
			throw new Exception('no_permission');
		}

		if (isset($node['attachments'])AND ($maxattachments > 0) AND count($node['attachments']) >= $maxattachments)
		{
			throw new Exception('max_attachments_reached');
		}

		$attachApi = vB_Api::InstanceInternal('content_attach');
		$data['parentid'] = $nodeid;
		$attachid = $attachApi->add($data);

		//updating the refcount in filedata happens in attach library's add() now.

		return is_array($attachid) ? $attachid[0] : $attachid;
	}

	/**
	 * delete one or more attachments
	 *
	 * 	@param 	int
	 *	@param 	mixed	an attachment id, or an array of either attach id's, or an array of filedataids
	 *	@param	bool	whether to delete all attachments for this node
	 *
	 *
	 */
	public function removeAttachment($nodeid, $data, $all = false)
	{
		/* data must include a filedataid, and possibly
		   any combination of visible,counter,posthash,filename,caption, reportthreadid, settings
		*/
		if (empty($nodeid))
		{
			throw new Exception('incorrect_attach_data');
		}

		//check the permissions.
		$node = vB_Library::instance('node')->getNodeBare($nodeid);
		if (empty($node))
		{
			throw new Exception('incorrect_attach_data');
		}

		if (!($node['userid'] == vB::getCurrentSession()->get('userid')) OR
			!vB::getUserContext()->getChannelPermission('forumpermissions', 'canpostattachment', $nodeid))
		{
			if (! vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateattachments', $nodeid))
			{
				throw new Exception('no_permission');
			}
		}

		//If we got here we have permission.
		//If all is, we delete all attachments for this node.
		if ($all)
		{
			$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $nodeid));

			// todo: shouldn't this decrement filedata.refcounts for records associated with the attachment records deleted here?
			return  vB::getDbAssertor()->assertQuery('vBForum:attach', $params);
		}

		if (isset($data['attachnodeid']))
		{
			return  vB::getDbAssertor()->assertQuery('vBForum:attach', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $data['attachnodeid'],
			));
		}

		if (isset($data['filedataid']))
		{
			$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array());
			if (is_array($data['filedataid']))
			{
				foreach($data['filedataid'] AS $id)
				{
					$params[vB_dB_Query::CONDITIONS_KEY][] = array('filedataid' => $id,
						'nodeid' => $nodeid);
				}
			}
			else
			{
				$params[vB_dB_Query::CONDITIONS_KEY] = array('nodeid' => $nodeid,
				'filedataid' => $data['filedataid']);
			}

			// since this doesn't go through the attach API or LIB, refcount change has to be taken care of here.
			vB::getDbAssertor()->assertQuery('updateFiledataRefCount',
				array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'countChange' => -1, 'filedataid' => $data['filedataid']));

			return  vB::getDbAssertor()->assertQuery('vBForum:attach', $params);
		}

		//if we got here we don't have enough data
		throw new Exception('incorrect_attach_data');
	}

	/**
	 * 	returns id of the Albums Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchAlbumChannel()
	{
		return $this->library->fetchAlbumChannel();
	}

	/**
	 * 	returns id of the Private Message Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchPMChannel()
	{
		return $this->library->fetchPMChannel();
	}

	/**
	 * 	returns id of the Vistor Message Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchVMChannel()
	{
		return $this->library->fetchVMChannel();
	}

	/**
	 * 	returns id of the Report Channel
	 *
	 *	@return	integer		array including
	 */
	public function fetchReportChannel()
	{
		return $this->library->fetchReportChannel();
	}

	/**
	 * Returns the nodeid of the root forum channel
	 *
	 * @return	integer	The nodeid for the root forum channel
	 */
	public function fetchForumChannel()
	{
		return $this->library->fetchForumChannel();
	}

	/**
	 * Returns the nodeid of the infraction channel
	 *
	 * @return	integer	The nodeid for the infraction channel
	 */
	public function fetchInfractionChannel()
	{
		return $this->library->fetchInfractionChannel();
	}

	/**
	 * Returns the nodeid of the articles channel
	 *
	 * @return	integer	The nodeid for the articles channel
	 */
	public function fetchArticleChannel()
	{
		return $this->library->fetchArticleChannel();
	}

	/**
	 * This returns a list of a user's albums
	 * @param int $userid
	 * @param int $page
	 * @param int $perPage
	 * @param array $options
	 *
	 * @return array node list of albums
   */
	public function listAlbums($userid = false, $page = 1, $perpage = 100, $options= array())
	{
		if (!$userid)
		{
			if (empty($_REQUEST['userid']))
			{
				$userid = vB::getUserContext()->fetchUserId();
			}
			else
			{
				$userid = $_REQUEST['userid'];
			}
		}
		$albumChannel = $this->fetchAlbumChannel();
		$contenttypeid = vB_Types::instance()->getContentTypeId('vBForum_Gallery');
		$nodeList = $this->library->listNodes($albumChannel, $page, $perpage, 0, $contenttypeid,
			array('includeProtected' => 1, 'userid' => $userid));

		$nodeList = $this->library->addFullContentInfo($nodeList, $options);
		$this->library->removePrivateDataFromNodeList($nodeList);
		return $nodeList;
	}


	/**
	 * 	returns array of all node content for a user's activity
	 *
	 *	@param	mixed	array- can include userid, sento, date flag, count, page, and  content type.
	 *
	 *	@return	integer		array including
	 */
	public function fetchActivity($params)
	{
		$rootid = (int) vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);

		$userdata = vB::getUserContext()->getReadChannels();
		//It's possible we have a permission record for the current node.
		if (empty($userdata['canRead']) OR !in_array($rootid, $userdata['canRead']))
		{
			throw new Exception('no_read_permission');
		}
		$exclude = $userdata['cantRead'];

		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD);

		/** Time filter */
		if (!empty($params[self::FILTER_TIME]))
		{
			$data[self::FILTER_TIME] = $params[self::FILTER_TIME];
		}

		if (!empty($params['contenttypeid']))
		{
			$data['contenttypeid'] = intval($params['contenttypeid']);
		}

		if (!empty($params['contenttypeid']))
		{
			$data['contenttypeid'] = intval($params['contenttypeid']);
		}

		if (!empty($params[self::FILTER_SOURCE]))
		{
			$data[self::FILTER_SOURCE] = $params[self::FILTER_SOURCE];
		}

		//We must have userid
		if (!empty($params['userid']))
		{
			$data['userid'] = intval($params['userid']);
		}
		else
		{
			$userinfo = vB::getCurrentSession()->fetch_userinfo();
			$data['userid'] = $userinfo['userid'];
		}

		if (!empty($params['perpage']))
		{
			$data[vB_dB_Query::PARAM_LIMIT] = intval($params['perpage']);
		}

		if (!empty($params['page']))
		{
			$data[vB_dB_Query::PARAM_LIMITPAGE] = intval($params['page']);
		}

		$results = vB::getDbAssertor()->assertQuery('vBForum:getActivity',
			$data);

		if (!$results->valid())
		{
			return array();
		}

		$nodeids = array();
		foreach ($results as $result)
		{
			$nodeids[] = $result['nodeid'];
		}
		$results = $this->getFullContentforNodes($nodeids);
		return $results;
	}

	/**
	 * This returns all the albums in a channel. Those can be photogalleries or text with attachments.
	 *
	 *	@param		int
	 *
	 *	@mixed		array of node records. Each node includes the node content and userinfo, and attachment records.
	 */
	public function getAlbums($nodeid)
	{

		if (empty($nodeid))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$nodes =  $this->library->getAlbums($nodeid);
		$this->library->removePrivateDataFromNodeList($nodes);
		return $nodes;
	}

	/**
	 * Sets or unsets the sticky field
	 * @param array $nodeids
	 * @param boolean $stick - set or unset the sticky field
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	function setSticky($nodeids, $stick = true)
	{
		$this->inlinemodAuthCheck();

		if (empty($nodeids))
		{
			return false;
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$loginfo = array();
		$stickyNodeIds = array();
		$events = array();

		foreach ($nodeids as $nodeid)
		{
			if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmanagethreads', $nodeid))
			{
				continue;
			}

			$node = $this->getNode($nodeid);

			$loginfo[] = array(
				'nodeid'		=> $node['nodeid'],
				'nodetitle'		=> $node['title'],
				'nodeusername'	=> $node['authorname'],
				'nodeuserid'	=> $node['userid']
			);

			array_push($stickyNodeIds, $nodeid);
			array_push($events, 'nodeChg_' . $nodeid);
		}

		if (empty($stickyNodeIds))
		{
			return false;
		}


		$result = vB::getDbAssertor()->update('vBForum:node', array('sticky' => $stick), array(array('field' => 'nodeid', 'value' => $stickyNodeIds, 'operator' => vB_dB_Query::OPERATOR_EQ)));

		vB_Cache::allCacheEvent($events);
		// we need to purge the cache so it is immediately shown
		vB_Library::instance('search')->purgeCacheForCurrentUser();

		vB_Library_Admin::logModeratorAction($loginfo, ($stick ? 'node_stuck_by_x' : 'node_unstuck_by_x'));

		return $stickyNodeIds;
	}

	/**
	 * Unsets sticky field
	 * @param array $nodeids
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	function unsetSticky($nodeids)
	{
		return $this->setSticky($nodeids, false);
	}

	/**
	 * Sets or unsets the approved field
	 * @param array $nodeids
	 * @param boolean $approved - set or unset the approved field
	 * @throws vB_Exception_Api
	 * @return array - the nodeids that have the permission to be changed
	 */
	public function setApproved($nodeids, $approved = true)
	{
		$nodeids = vB::getCleaner()->clean($nodeids,  is_array($nodeids) ? vB_Cleaner::TYPE_ARRAY_UINT : vB_Cleaner::TYPE_UINT);

		if (empty($nodeids))
		{
			return false;
		}
		$currentUserid = vB::getCurrentSession()->get('userid');

		if (empty($currentUserid))
		{
			return false;
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$existing = vB_Library::instance('node')->getNodes($nodeids);

		if (empty($existing))
		{
			return false;
		}

		// need to see if we require authentication
		$userContext = vB::getUserContext();
		$approveNodeIds = array();
		//allow unapproving of VMs by the recipient that has canmanageownprofile
		$need_auth = false;
		$moderateInfo = vB::getUserContext()->getCanModerate();
		$timeNow = vB::getRequest()->getTimeNow();
		$result = false;
		foreach ($existing as $node)
		{
			//Two possibilities. It might be unapproved, in which case we need moderate permissions. Or it might be unpublished,
			// in which case we need canpublish.
			// TODO: why is setApproved() used to publish nodes?? Something does not look correct here.

			//if (($node['publishdate'] < $timeNow) OR ($node['unpublishdate'] > 0))
			if (!$this->library->isPublished($node))
			{
				$this->inlinemodAuthCheck();

				if ($userContext->getChannelPermission('forumpermissions2', 'canpublish', $node['nodeid']))
				{
					$this->setPublishDate($node['nodeid'], $timeNow);
					$result = true;
				}
			}
			$currentApproved = (intval($node['approved']) > 0);

			if ($approved != $currentApproved)
			{
				//do we need to call setApproved? Not if we just have
				//$approve = 1;
				// todo: limit usage of this perm check to blogs/groups only?
				$canModerateOwn = $userContext->getChannelPermission('forumpermissions2', 'canmanageownchannels', $node['nodeid']);

				// check if this is the owner of a blog that needs to moderate the comments
				if (!empty($moderateInfo['can']) OR ($canModerateOwn))
				{
					// let's get the channel node
					$channelid = vB_Library::instance('node')->getChannelId($node);

					if ($channelid == $node['nodeid'])
					{
						$channel = $node;
					}
					else
					{
						$channel = vB_Library::instance('node')->getNodeBare($channelid);
					}

					// this channel was created by the current user so we don't need the auth check
					if ((in_array($channelid, $moderateInfo['can'])) OR ($canModerateOwn AND ($channel['userid'] == $currentUserid)))
					{
						$approveNodeIds[] = $node['nodeid'];
						continue;
					}
				}

				// don't check permissions if the user is the recipient of the VM
				if (!empty($node['setfor']) AND ($node['setfor'] == $currentUserid) AND $userContext->hasPermission('visitormessagepermissions', 'canmanageownprofile'))
				{
					$approveNodeIds[] = $node['nodeid'];
				}
				else
				{
					$this->inlinemodAuthCheck();

					/*
						Leaving above inlinemodAuthCheck() in place to maintain old behavior.

						canmanagethreads isn't supposed to provide approve/unapprove perms, only stick/unstick, move, copy,
						merge, & feature/unfeature. canmoderateposts channel permission & moderator permission allow
						approve/unapprove actions, but that's implicitly checked above via checking moderateInfo['can']
						(unless user is a supermod, in which case various "view" permissions provide moderation permissions,
						for some reason)
					 */
					/*
					if ($userContext->getChannelPermission('moderatorpermissions', 'canmanagethreads', $node['nodeid']))
					{
						$approveNodeIds[] = $node['nodeid'];
					}
					*/
				}
			}
		}

		if (empty($approveNodeIds))
		{
			return $result;
		}

		return $this->library->setApproved($approveNodeIds, $approved);
	}


	/**
	 * Approves a post. Since the publish date might be affected user will need moderate and
	 * publish posts permissions.
	 *
	 * @param	int|array	Int Nodeid (or an array of int nodeids) for the node(s) we are approving.
	 * @param	int		Boolean used to set or unset the approved value
	 * @param	array	Optional array to update the node fields. Accepted fields are: title, rawtext, reason
	 *
	 * @return	bool	Flag to indicate if approving went succesfully done (true/false).
	 */
	public function setApprovedPost($nodeid, $approved = false, $data = array())
	{
		$nodeid = vB::getCleaner()->clean($nodeid,  is_array($nodeid) ? vB_Cleaner::TYPE_ARRAY_UINT : vB_Cleaner::TYPE_UINT);

		$ret = $this->setApproved($nodeid, $approved);
		if (empty($data) OR (empty($data['title']) AND empty($data['text'])))
		{
			return $ret;
		}

		if (!intval($nodeid))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}


		//actually -- if we do the update like we are supposed to then it will nuke some data
		//not passed.  This is a problem for pretty much all of the edit forms that don't
		//display a full post control and we need to fix that globally.  However this didn't used
		//to work and fixing it causes more problems (the approve post overlay in the message center
		//will update the title/text/reaons, but the tags disappear).
		return $ret;

		//hack -- this function is supposed to take an array of nodeids as well as a single
		//nodeid, but the reality is that the rest of this function simply doesn't work on
		//a list.  However there isn't time now to track down all the callers and ensure
		//they aren't calling a list and/or fix things so that the work with a list
		//properly.  And its unlike that we are passing data without it being a single
		//node so let's just skip processing this if we have a list.
		$nodeupdateid = $nodeid;
		if(is_array($nodeid))
		{
			if(count($nodeid) == 1)
			{
				$nodeupdateid = reset($nodeid);
			}
			else
			{
				return $ret;
			}
		}

		// let's check that node really exists
		$node = $this->getNode($nodeupdateid);

		if (empty($this->contentAPIs[$node['nodeid']]))
		{
			$this->contentAPIs[$node['nodeid']] =
				vB_Api::instanceInternal('Content_' . vB_Types::instance()->getContentTypeClass($node['contenttypeid']));
		}

		$data = array_intersect_key($data, array_flip(array('title', 'rawtext', 'reason')));

		$this->contentAPIs[$node['nodeid']]->update($nodeupdateid, $data);
		return $ret;
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
	 * This creates a request for access to a channel
	 *
	 *	@param		int		$channelid		the nodeid of the channel to which access is requested.
	 *	@param		string	$requestType	the type of request. See vB_Api_Node::REQUEST_<> constants
	 *	@param		mixed	$recipient		the userid/username of the member who will get the request
	 *	@param		string	$recipientname	(Optional) the username of the member who will get the request
	 *
	 *	@return		mixed	If it is 1 or true, then it means that the follow request was successful.
	 *							If it is integer and greater than 1, then the request is pending.
	 */
	public function requestChannel($channelid, $requestType, $recipient = 0, $recipientname = null)
	{
		$context = vB::getUserContext();
		if (
			!$context->getChannelPermission('forumpermissions', 'canjoin', $channelid) OR
			!$context->getChannelPermission('forumpermissions', 'canview', $channelid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$canAddOwners = $context->getChannelPermission('moderatorpermissions', 'canaddowners', $channelid);
		return $this->library->requestChannel($channelid, $requestType, $recipient, $recipientname, $canAddOwners);
	}

	/**
	 * Approves a channel request.
	 * @param	int $messageId
	 */
	public function approveChannelRequest($messageId)
	{
		$userInfo =  vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];
		$username = $userInfo['username'];

		$assertor = vB::getDbAssertor();

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$sentto = $assertor->getRow('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $messageId, 'userid' => $userid));

		if (!$sentto OR !empty($sentto['errors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$messageApi = vB_Api::instanceInternal('content_privatemessage');
		$message = $messageApi->getContent($messageId);
		$message = $message[$messageId];

		if (($message['msgtype'] != 'request' ) OR empty($message['aboutid']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		// if a user joins a channel as owner/moderator/member, check if they should automatically be subscribed
		$autoSubscribeMember = false;
		$node = $this->getNode($message['aboutid']);
		if ( ($node['nodeoptions'] & vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN) > 0)
		{
			$autoSubscribeMember = true;
		}

		switch ($message['about'])
		{
			case self::REQUEST_TAKE_MODERATOR:
			case self::REQUEST_SG_TAKE_MODERATOR:
				//Can we grant the transfer?
				$userContext = vB::getUserContext($message['userid']);
				if (!$userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $message['aboutid'] ))
				{
					throw new vB_Exception_API('no_permission');
				}
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID);
				$usergroupid = $usergroupInfo['usergroupid'];
				$permUserid = $userid;
				break;

			case self::REQUEST_TAKE_MEMBER:
			case self::REQUEST_SG_TAKE_MEMBER:
				$userContext = vB::getUserContext($message['userid']);
				if (!$userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $message['aboutid'] ))
				{
					throw new vB_Exception_API('no_permission');
				}
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID);
				$usergroupid = $usergroupInfo['usergroupid'];
				$permUserid = $userid;
				break;

			case self::REQUEST_TAKE_OWNER:
			case self::REQUEST_SG_TAKE_OWNER:
				//Can we grant the transfer?
				$userContext = vB::getUserContext($message['userid']);
				if (!$userContext->getChannelPermission('moderatorpermissions', 'canaddowners', $message['aboutid'] ))
				{
					throw new vB_Exception_API('no_permission');
				}
				//We can't use the user api, because that checks the permissions.

				//let's get the current channels in which the user already is set for that group.
				//Then remove any for which they already are set.
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID);

				$groupInTopic = vB_Api::instanceInternal('user')->getGroupInTopic($userid, $message['aboutid']);
				$groupInTopic = array_column($groupInTopic, 'groupid');
				if ($groupInTopic AND in_array($usergroupInfo['usergroupid'], $groupInTopic))
				{
					//This user already has this right
					return true;
					break;
				}
				//There is only one owner at a time, so we delete the current user;
				$result = $assertor->assertQuery('vBForum:groupintopic', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'nodeid' => $message['aboutid'], 'groupid' => $usergroupInfo['usergroupid']));

				//and do the inserts
				$result = $assertor->assertQuery('vBForum:groupintopic', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'userid' => $userid, 'nodeid' => $message['aboutid'], 'groupid' => $usergroupInfo['usergroupid']));

				// add subscription for new owner if autosubcribe is enabled
				if ( $autoSubscribeMember )
				{
					vB_Api::instanceInternal('follow')->add($message['aboutid'], vB_Api_Follow::FOLLOWTYPE_CHANNELS, $userid, true);
				}

				// Add membership for the old owner. Note the lack of auto-subscription check because an old owner
				// should already have a subscription if channel is auto-subscribe.
				$oldOwner = $node['userid'];
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID);
				vB_User::setGroupInTopic($oldOwner, $message['aboutid'], $usergroupInfo['usergroupid']);

				//replace the old owner in the node table as well
				$assertor->update('vBForum:node', array('userid' => $userid, 'authorname' => $username), array('nodeid' => $message['aboutid']));
				$myUserContext = vB::getUserContext();
				vB_Cache::allCacheEvent("userPerms_$userid");
				vB_Cache::allCacheEvent('nodeChg_' . $message['aboutid']);

				$myUserContext->clearChannelPermissions();
				$myUserContext->reloadGroupInTopic();
				$senderUserContext = vB::getUserContext($message['userid']);
				$senderUserContext->clearChannelPermissions();
				$senderUserContext->reloadGroupInTopic();
				return true;
				break;

			case self::REQUEST_GRANT_OWNER:
			case self::REQUEST_SG_GRANT_OWNER:
				// these requests don't exist yet.
				throw new vB_Exception_API('invalid_action');
				// when these requests are implemented, be careful about what $permUserid below should be.
				// I think this request goes to the owner, so $permUserid has to be the sender of the message,
				// meaning we have to grab the node where nodeid = $message['nodeid'], & grab its author
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID);
				$usergroupid = $usergroupInfo['usergroupid'];
				$permUserid = $message['userid'];
				break;
			case self::REQUEST_GRANT_MODERATOR:
			case self::REQUEST_SG_GRANT_MODERATOR:
				// these requests don't exist yet.
				throw new vB_Exception_API('invalid_action');
				// when these requests are implemented, be careful about what $permUserid below should be.
				// I think this request goes to the owner, so $permUserid has to be the author of the message,
				// meaning we have to grab the node where nodeid = $message['nodeid'], & grab its author
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID);
				$usergroupid = $usergroupInfo['usergroupid'];
				$permUserid = $message['userid'];
				break;
			case self::REQUEST_GRANT_MEMBER:
			case self::REQUEST_SG_GRANT_MEMBER:
				$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID);
				$usergroupid = $usergroupInfo['usergroupid'];
				$permUserid = $message['userid'];
				break;
			default:
				throw new vB_Exception_API('invalid_data');
		} // switch

		$result = vB_User::setGroupInTopic($permUserid, $message['aboutid'], $usergroupid);

		// If automatic subscription is enabled for the channel (e.g. blogs by default) and if groupintopic is set
		// make the user follow the channel.
		if ( ($result === true) AND $autoSubscribeMember )
		{
			// The 4th param, $auto_subscribe = true, is required since an auto-subscribe probably doesn't come
			// with an existing subscriber request, only a join request.
			vB_Api::instanceInternal('follow')->add($message['aboutid'], vB_Api_Follow::FOLLOWTYPE_CHANNELS, $permUserid, true);
		}

		// I'm fairly certain that the below is incorrect. The (old) OWNER would receive the request, so $userid = $message['userid']..
		// It should probably compaer $userid with $permUserid, given that $permUserid is corrected (see above case statement)
		//last item- if we just granted owner to a new member we should remove anyone else & add the old owner as a regular member
		if (($message['userid'] != $userid) AND in_array($message['about'], array(self::REQUEST_GRANT_OWNER, self::REQUEST_SG_GRANT_OWNER)))
		{
			$result = $assertor->assertQuery('vBForum:groupintopic', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'nodeid', 'value'=> $message['aboutid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'groupid', 'value'=> $usergroupid, 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'userid', 'value'=> $message['userid'], 'operator' => vB_dB_Query::OPERATOR_NE))
				));

			// TODO: if this is ever corrected/implemented, be sure to add the old owner as a member of the channel

			//reset the recipient's permissions.
			$myUserContext = vB::getUserContext();
			vB_Cache::allCacheEvent("userPerms_$userid" );
			$myUserContext->clearChannelPermissions();
			$myUserContext->reloadGroupInTopic();
		}
		vB_Api::instanceInternal('user')->clearChannelPerms($userid);
		return true;
	}



	/**
	 * Set the node options
	 *
	 * @param int $nodeid
	 * @param	array|int $options- can be an integer or an array
	 * @return int|string 1 or an error message.
	 */
	public function setNodeOptions($nodeid, $options = false)
	{
		if (empty($nodeid) OR !intval($nodeid) OR ($options === false))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canconfigchannel', $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->setNodeOptions($nodeid, $options);
	}


	/**
	 * Set the node special permissions
	 *
	 * @param int $nodeid
	 * @param	array with 'viewperms' and/or 'commentperms'
	 * @return int|string 1 or an error message.
	 */
	public function setNodePerms($nodeid, $perms = array())
	{
		if (empty($nodeid) OR !intval($nodeid) OR
			(!isset($perms['viewperms']) AND !isset($perms['commentperms'])))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		//If this is a gallery and the owner is setting to private, it's O.K.
		if (isset($perms['viewperms']) AND !isset($perms['commentperms']))
		{
			$node = $this->library->getNodeBare($nodeid);

			if (($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Gallery') ) AND
				($node['parentid'] == self::fetchAlbumChannel()) AND ($node['userid'] == vB::getCurrentSession()->get('userid')))
			{
				$canChange = true;
			}
		}

		if (empty($canChange) AND !vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canaddowners', $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$updates = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $nodeid);
		$node = $this->getNode($nodeid);

		if (isset($perms['viewperms']) AND is_numeric($perms['viewperms']) AND in_array($perms['viewperms'], array(0,1,2)))
		{
			$updates['viewperms'] = $perms['viewperms'];
		}
		else
		{
			$updates['viewperms'] = $node['viewperms'];
		}


		if (isset($perms['commentperms']) AND is_numeric($perms['commentperms']) AND in_array($perms['commentperms'], array(0,1,2)))
		{
			$updates['commentperms'] = $perms['commentperms'];
		}
		else
		{
			$updates['commentperms'] = $node['commentperms'];
		}
		$result = vB::getDbAssertor()->assertQuery('vBForum:updateNodePerms', $updates);
		$this->clearCacheEvents($nodeid);
		$this->library->clearChildCache($nodeid);
		return $result;
	}

	/**
	 * Validates whether nodes can be merged and returns the merging info. If nodes cannot be merged, an error is returned.
	 * @param array $nodeIds
	 * @return array
	 */
	protected function validateMergePosts($nodeIds)
	{
		$nodes = $this->getContentForNodes($nodeIds);

		$response = array();
		$response['contenttypeclass'] = 'Text';

		$contentTypes = array();

		// check content type constraints
		foreach ($nodes AS $node)
		{
			$contentTypeClass = $node['contenttypeclass'];
			$contentTypes[$contentTypeClass] = isset($contentTypes[$contentTypeClass]) ? ($contentTypes[$contentTypeClass] + 1) : 1;

			// currently we cannot merge multiple links or videos
			if ($contentTypes[$contentTypeClass] > 1 AND !in_array($contentTypeClass, array('Text', 'Gallery')))
			{
				return array('error' => 'merge_invalid_contenttypes_multiple');
			}

			// meanwhile, gather the info from it...
			if ($contentTypeClass != 'Text')
			{
				$response['contenttypeclass'] = $contentTypeClass;
			}

			$response['destnodes'][$node['nodeid']] = $node;
			$response['destauthors'][$node['content']['userid']] = $node['content']['authorname'];
			// The mergeContentInfo method is checking view permissions to the $response
			$response['nodeid'] = $node['nodeid'];

			vB_Library::instance('content_' . $contentTypeClass)->mergeContentInfo($response, $node['content']);
		}

		if (count($contentTypes) > 1)
		{
			// we are merging different contenttypes.
			// If there are two, one must be Text.
			if (count($contentTypes) > 2 || !array_key_exists('Text', $contentTypes))
			{
				return array('error' => 'merge_invalid_contenttypes');
			}
		}

		// we are good to continue...
		asort($response['destauthors']);

		return $response;
	}

	/**
	 * Validates whether nodes can be merged and returns merging info.
	 * @param mixed $nodeIds
	 * @return array
	 */
	public function getMergePostsInfo($nodeIds)
	{
		if (empty($nodeIds))
		{
			throw new vB_Exception_Api('please_select_at_least_one_post');
		}
		else if (is_string($nodeIds))
		{
			$nodeIds = explode(',', $nodeIds);
		}

		$response = $this->validateMergePosts($nodeIds);

		if (isset($response['error']))
		{
			throw new vB_Exception_Api($response['error']);
		}
		else
		{
			return $response;
		}
	}

	/**
	 * Performs the actual merging, using edited input from UI.
	 * @param type $data - Contains pairs (value, name) from edit form in addition to the following fields:
	 *						* mergePosts - posts to be merged
	 *						* destnodeid - target post
	 *						* destauthorid - author to be used
	 *						* contenttype - target contenttype
	 */
	public function mergePosts($input)
	{
		$this->inlinemodAuthCheck();
		$cleaner = vB::getCleaner();
		$data = array();

		foreach ($input as $i)
		{
			$name = $cleaner->clean($i['name'], vB_Cleaner::TYPE_NOHTML);
			//mostly the data is either integer or string, although the possibility exists of a
			//'url_image'
			switch($name)
			{
				case 'nodeid':
				case 'url_nopreview':
				case 'nodeuserid':
				case 'filedataid':
				case 'destauthorid':
				case 'destnodeid':
					$value = $cleaner->clean($i['value'],vB_Cleaner::TYPE_UINT );
					break;
				case 'title':
				case 'text':
				case 'reason':
					$value = $cleaner->clean($i['value'],vB_Cleaner::TYPE_STR);
					break;
				case 'url_title':
				case 'authorname':
				case 'url':
				case 'url_image':
				case 'url_meta':
					$value = $cleaner->clean($i['value'],vB_Cleaner::TYPE_NOHTML );
					break;
				case 'mergePosts':
					if (!is_array($i['value']))
					{
						$i['value'] = explode(',', $i['value']) ;
					}
					$value = $cleaner->clean($i['value'],vB_Cleaner::TYPE_ARRAY_UINT);
					break;
				case 'filedataid[]' :
					//The filedata records are passed as
					//input[xx][name]	filedataid[]
					//input[xx][value]	<integer>
					$value = $cleaner->clean($i['value'],vB_Cleaner::TYPE_UINT );

					if (!isset($data['filedataid']))
					{
						$data['filedataid'] = array();
					}

					if (!isset($data['filedataid'][$value]))
					{
						$data['filedataid'][$value] = '';
					}
					break;

				default:
					//The title records are passed as
					//input[xx][name]	title_<filedataid>
					//input[xx][value]	<title>
					if (empty($name))
					{
						break;
					}

					if (substr($name, 0, 6) == 'title_')
					{
						$filedataid = substr($name, 6);
						$filedataid = $cleaner->clean($filedataid,vB_Cleaner::TYPE_UINT );

						if ($filedataid)
						{
							if (!isset($data['filedataid']))
							{
								$data['filedataid'] = array();
							}
							$data['filedataid'][$filedataid] = $cleaner->clean($i['value'],vB_Cleaner::TYPE_NOHTML );
						}
					}
					else if (preg_match('#^videoitems\[([\d]+)#', $name, $matches))
					{
						if (!isset($data['videoitems']))
						{
							$data['videoitems'] = array();
						}
						$videoitems[] = array(
							'videoitemid' => intval($matches[1]),
							'url' => $i['value'],
						);
					}
					else if (preg_match('^videoitems\[new^', $name, $matches))
					{
						if (!isset($data['videoitems']))
						{
							$data['videoitems'] = array();
						}
						foreach ($matches as $video)
						{
							$data['videoitems'][] = array('url' => $video['url']);
						}
					}
					break;
			}

			if (isset($data[$name]))
			{
				if (!is_array($data[$name]))
				{
					$data[$name] = array($data[$name]);
				}

				$data[$name][] = $value;
			}
			else
			{
				$data[$name] = $value;
			}
		}

		if (empty($data['mergePosts']))
		{
			throw new vB_Exception_Api('please_select_at_least_one_post');
		}

		// check that the user has permission
		$nodesToCheck = $data['mergePosts'];
		$nodesToCheck[] = $data['destnodeid'];
		foreach ($nodesToCheck AS $key => $nodeid)
		{
			// this is here just in case for some reason, a nodeid is 0. Shouldn't happen, but
			// I don't want getChannelPermission to go bonkers from it.
			if (empty($nodeid))
			{
				unset($nodesToCheck[$key]);
				continue;
			}

			if ( !vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmanagethreads', $nodeid) )
			{
				// perhaps we could generate a list of unmergeable nodes and return a warning instead, but
				// I don't think there's a real use case where a moderator can manage only *some* of the
				// nodes they're trying to merge. I think that would require multiple channels being involved, and
				// we don't have a UI for that so I can't test it. As such I'm just going to throw an exception if
				// *any* of the nodes fail the check.
				throw new vB_Exception_Api('no_permission');
			}
		}

		// validate that selected nodes can be merged
		$mergeInfo = $this->validateMergePosts($data['mergePosts']);

		if (isset($mergeInfo['error']))
		{
			throw new vB_Exception_Api($mergeInfo['error']);
		}

		// validate form fields
		if (empty($data['destnodeid']) || !array_key_exists($data['destnodeid'], $mergeInfo['destnodes']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (empty($data['destauthorid']) || !array_key_exists($data['destauthorid'], $mergeInfo['destauthors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$destnode = $this->library->getNodeFullContent($data['destnodeid']);
		$destnode = array_pop($destnode);

		if ($destnode['starter'] != $destnode['nodeid'] AND $destnode['starter'] != $destnode['parentid'])
		{
			if (isset($data['tags']))
			{
				unset($data['tags']);
			}
		}

		$type = vB_Types::instance()->getContentTypeClass($destnode['contenttypeid']);
		$response = vB_Library::instance("content_{$type}")->mergeContent($data);

		if ($response)
		{
			$sources = array_diff($data['mergePosts'], array($data['destnodeid']));

			$origDestnode = $destnode;

			if (!empty($destnode['rawtext']))
			{
				$origRawText = $destnode['rawtext'];
			}
			else if (!empty($destnode['content']['rawtext']))
			{
				$origRawText = $destnode['content']['rawtext'];
			}
			else
			{
				$origRawText = '';
			}
			$destnode = $this->getNode($data['destnodeid']);

			if (!empty($destnode['rawtext']))
			{
				$rawText = $destnode['rawtext'];
			}
			else if (!empty($destnode['content']['rawtext']))
			{
				$rawText = $destnode['content']['rawtext'];
			}
			else
			{
				$rawText = '';
			}
			$destnode = $this->getNode($data['destnodeid']);

			$loginfo = array(
				'nodeid'       => $destnode['nodeid'],
				'nodetitle'    => $destnode['title'],
				'nodeusername' => $destnode['authorname'],
				'nodeuserid'   => $destnode['userid'],
			);

			// move children to target node
			$children = vB::getDbAssertor()->assertQuery('vBForum:closure', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'parent' => $sources,
				'depth' => 1,
			));

			$childrenIds = array();
			foreach ($children AS $child)
			{
				$childrenIds[] = $child['child'];
			}

			if (!empty($childrenIds))
			{
				$this->moveNodes($childrenIds, $data['destnodeid'], false, false, false);
			}

			// remove merged nodes
			$this->deleteNodes($sources, true, null, false); //  Dont log the deletes

			$loginfo['action'] = array('merged_nodes' => implode(',' , $sources));
			$vboptions = vB::getDatastore()->getValue('options');
			if (
				(
					vB_Api::instanceInternal('user')->hasPermissions('genericoptions', 'showeditedby')
						AND
					$destnode['publishdate'] > 0
						AND
					$destnode['publishdate'] < (vB::getRequest()->getTimeNow() - ($vboptions['noeditedbytime'] * 60))
				)
					OR
				!empty($data['reason'])
			)
			{

				$userinfo = vB::getCurrentSession()->fetch_userinfo();
				if ($vboptions['postedithistory'])
				{
					$record = vB::getDbAssertor()->getRow('vBForum:postedithistory',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							'original' => 1,
							'nodeid'   => $destnode['nodeid']
					));
					// insert original post on first edit
					if (empty($record))
					{
						vB::getDbAssertor()->assertQuery('vBForum:postedithistory', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
							'nodeid'   => $origDestnode['nodeid'],
							'userid'   => $origDestnode['userid'],
							'username' => $origDestnode['authorname'],
							'dateline' => $origDestnode['publishdate'],
							'pagetext' => $origRawText,
							'original' => 1,
						));
					}
					// insert the new version
					vB::getDbAssertor()->assertQuery('vBForum:postedithistory', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
						'nodeid'   => $destnode['nodeid'],
						'userid'   => $userinfo['userid'],
						'username' => $userinfo['username'],
						'dateline' => vB::getRequest()->getTimeNow(),
						'reason'   => isset($data['reason']) ? vB_String::htmlSpecialCharsUni($data['reason']) : '',
						'pagetext' => $rawText
					));
				}

				vB::getDbAssertor()->assertQuery('editlog_replacerecord', array(
					'nodeid'     => $destnode['nodeid'],
					'userid'     => $userinfo['userid'],
					'username'   => $userinfo['username'],
					'timenow'    => vB::getRequest()->getTimeNow(),
					'reason'     => isset($data['reason']) ? vB_String::htmlSpecialCharsUni($data['reason']) : '',
					'hashistory' => intval($vboptions['postedithistory'])
				));
			}

			vB_Library_Admin::logModeratorAction($loginfo, 'node_merged_by_x');

			return true;
		}

	}

	/**
	 * gets the node option bitfields
	 *
	 * 	@return	array 	associative array of bitfield name => value
	 */
	public function getOptions()
	{
		return $this->library->getOptions();
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
	public function listPendingPosts($options = array())
	{

		return $this->library->listPendingPosts(vB::getCurrentSession()->get('userid'), $options);
	}

	/**
	 * Function wrapper for listPendingPosts but used for current user.
	 *
	 */
	public function listPendingPostsForCurrentUser($options = array())
	{
		$userId = vB::getCurrentSession()->get('userid');

		if (!$userId)
		{
			return array();
		}
		return $this->library->listPendingPostsForCurrentUser($options);
	}


	/**
	 * Clears the cache events from a given list of nodes.
	 * Useful to keep search results updated due node changes.
	 *
	 * @param	array		List of node ids to clear cached results.
	 *
	 * @return
	 */
	public function clearCacheEvents($nodeIds)
	{
		return $this->library->clearCacheEvents($nodeIds);
	}
	/**
	* Marks a node as read using the appropriate method.
	*
	* @param int $nodeid The ID of node being marked
	*
	* @return	array	Returns an array of nodes that were marked as read
	*/
	public function markRead($nodeid)
	{
		return $this->library->markRead($nodeid);
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
		return $this->library->markReadMultiple($nodeids);
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
		return $this->library->markUnreadMultiple($nodeids);
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
		return $this->library->markChannelsRead($nodeid);
	}

	/**
	 * Fetches the moderator logs for a node
	 * @param int $nodeid
	 * @return array $logs list of log records
	 */
	public function fetchModLogs($nodeid)
	{
		if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'caneditthreads', $nodeid))
		{
			$node = $this->getNode($nodeid);
			if ($node['userid'] != vB::getCurrentSession()->get('userid'))
			{
				throw new vB_Exception_Api('no_permission');
			}
			// do not throw an error if the author requests logs, just don't show them to it.
			else
			{
				return array();
			}
		}

		$logs = array();
		$log_res = vB::getDbAssertor()->assertQuery('getModLogs', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $nodeid));

		foreach ($log_res as $log)
		{
			$phrase_name = vB_Library_Admin::GetModlogAction($log['type']);
			$phrase = vB_Api::instanceInternal('phrase')->fetch($phrase_name);
			if (!isset($phrase[$phrase_name]))
			{
				continue;
			}
			$phrase = $phrase[$phrase_name];
			$log['action'] = vsprintf($phrase, $log['username']);
			$logs[] = $log;
		}
		return $logs;
	}

	/**
	 * Manages a deleted node regarding options being passed.
	 *
	 * @param 	int 	Nodeid.
	 * @param 	array 	Options for the node managing.
	 * 					keys -- deletetype, reason, iconid, prefixid, topictitle, option_open, option_sticky, option_visible
	 *
	 * @return 	array 	Whether manage action succeeded or not.
	 *					keys -- success
	 *
	 */
	public function manageDeletedNode($nodeid, $params)
	{
		$currentnode = vB_Api::instanceInternal('node')->getNode($nodeid);
		if (empty($currentnode))
		{
			throw new vB_Exception_Api('invalid_target');
		}

		if ($currentnode['userid'] != vB::getCurrentSession()->get('userid'))
		{
			$this->inlinemodAuthCheck();
			if (!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateposts', $nodeid))
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		// hard deleting the node. There is no point doing anything else beyond this
		if (!empty($params['deletetype']) AND $params['deletetype'] == 3)
		{
			$this->deleteNodes($nodeid, true, empty($params['reason']) ? '' : $params['reason']);
			return array('success' => true);
		}


		$is_topic = ($currentnode['starter'] == $currentnode['nodeid']);
		$is_reply = ($currentnode['starter'] == $currentnode['parentid']);

		$nodeFields = array();

		if (!empty($params['reason']))
		{
			$nodeFields['deletereason'] = $params['reason'];
		}

		if ($is_topic AND $params['post_icon'] != $currentnode['iconid'])
		{
			$nodeFields['iconid'] = $params['post_icon'];
		}

		if($is_topic AND $params['prefixid'] != $currentnode['prefixid'])
		{
			$nodeFields['prefixid'] = $params['prefixid'];
		}

		if ($is_topic AND !empty($params['topictitle']) AND $params['topictitle'] != $currentnode['title'])
		{
			$nodeFields['title'] = $params['topictitle'];
		}
		//updating the node if needed
		if (!empty($nodeFields))
		{
			$nodeFields['parentid'] = $currentnode['parentid'];
			vB_Api_Content::getContentApi($currentnode['contenttypeid'])->update($nodeid, $nodeFields);
		}

		// adding moderation note happens in downstream functions as of r69182 (VBV-4955 part 3)

		// undelete
		if (!empty($params['deletetype']) AND $params['deletetype'] == 2)
		{
			$this->undeleteNodes($nodeid);
		}

		if (isset($params['deletetype']) AND ($params['deletetype'] == 0 OR $params['deletetype'] == 2))
		{
			if ($is_topic)
			{
				if (!empty($params['option_open']) AND !$currentnode['open'])
				{
					$this->openNode($nodeid);
				}
				elseif (empty($params['option_open']) AND $currentnode['open'])
				{
					$this->closeNode($nodeid);
				}

				if (!empty($params['option_sticky']) AND !$currentnode['sticky'])
				{
					$this->setSticky($nodeid, true);
				}
				elseif (empty($params['option_sticky']) AND $currentnode['sticky'])
				{
					$this->setSticky($nodeid, false);
				}

				if (!empty($params['option_visible']) AND !$currentnode['approved'])
				{
					$this->setApproved($nodeid, true);
				}
				elseif (empty($params['option_visible']) AND $currentnode['approved'])
				{
					$this->setApproved($nodeid, false);
				}
			}

			return array('success' => true);
		}

		//delete attachments
		if (!empty($params['deletetype']) AND $params['deletetype'] == 1 AND empty($params['keep_attachments']))
		{
			$attachments = $this->getNodeAttachments($nodeid);
			if (!empty($attachments))
			{
				$this->deleteNodes(array_keys($attachments), true, empty($params['reason']) ? '' : $params['reason']);
			}
		}

		return array('success' => true);
	}

	/**
	 * Check whether current logged-in user is "authenticated" for moderation actions.
	 * If the user is a moderator but not "authenticated", this will throw an exception.
	 * If the user is not a moderator, this won't throw the exception!
	 *
	 * @throws vB_Exception_Api inlinemodauth_required if we need user to login again
	 */
	protected function inlinemodAuthCheck()
	{
		$session = vB::getCurrentSession();

		if (!$session->validateCpsession())
		{
			throw new vB_Exception_Api('inlinemodauth_required');
		}
	}

	/**
	 * Checks if ip should be shown
	 *
	 * @return	bool	If the ip of the poster should be posted or not
	 */
	public function showIp($nodeid)
	{
		$logip = vB::getDatastore()->getOption('logip');
		if ($logip == 2)
		{
			return true;
		}
		else if ($logip == 1 AND vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canviewips', $nodeid))
		{
			return true;
		}

		return false;
	}

	public function getHostName($ip)
	{
		return @gethostbyaddr($ip);
	}

	/**
	 * Fetch users from given nodeids
	 * @param array $nodeids Node IDs
	 * @return array User IDs and names.
	 */
	public function fetchUsersFromNodeids($nodeids)
	{
		if(!is_array($nodeids))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeids, 'nodeids', __CLASS__, __FUNCTION__));
		}

		foreach ($nodeids AS &$nodeid)
		{
			$nodeid = intval($nodeid);
		}
		$nodes = $this->getNodes($nodeids);

		$userids = array();
		foreach ($nodes as $node)
		{
			if ($node['inlist'] == 1 AND !in_array($node['userid'], $userids))
			{
				$userids[$node['userid']] = $node['authorname'];
			}
		}

		return $userids;
	}


	/**
	 * Fetch node tree structure of the specified parent id as the root. Root is excluded from the tree structure.
	 * If parentid is not specified or less than 1, it is automatically set to the top-most level special category "Forum"
	 *
	 * @param integer $parentid
	 * @param integer $depth
	 * @param integer $pagenum -- unused
	 * @param integer $perpage -- unused
	 *
	 * @return array The node tree (need to fill out expected structure).
	 * 		 May also contain 'warnings' => String[] of warnings to be displayed in debug mode.
	 */
	public function fetchChannelNodeTree($parentid = 0, $depth = 3, $pagenum = 1, $perpage = 20)
	{
		$parentid = (int) $parentid;
		$depth = (int) $depth;
		$pagenum = (int) $pagenum;
		$perpage = (int) $perpage;

		/*
		 	This is a very expensive function. Therefore we should cache at three levels.
		 	First- if asked at root, we cache a copy of the for this user without the "last" data.
		 	Then we have a copy of the structure for this user but with no "last".
			Then we have a copy of the entire structure.
			These all have a lifetime of one day, with appropriate events.
		*/
		$userid = vB::getCurrentSession()->get('userid');

		//If we are not passed a parent, we default to main forum.
		if ($parentid < 1)
		{
			$topChannels = vB_Api::instanceInternal('content_channel')->fetchTopLevelChannelIds();
 			$parentid = $topChannels['forum'];
		}
		//See if we have a cached version
		$userTree = $this->getUserChannels($userid);

		/*
		 *	Note, be careful about using $complete after the addChannelTotals() & assembleTree() calls below.
		 *	Right out of addChannelLastData(), it's user-agnostic, but it's passed by reference into the two
		 *	functions, and the functions make user-dependent modifications to the array.
		 *	Specifically, assembleTree() might blank out some 'lastcontent' subarrays, while addChannelTotals()
		 *	adds the user-dependent sums "topics" and "posts" to nearly all the channel subarrays. Each might
		 *	make further modifications in the future as the code changes.
		 */
		$complete = $this->addChannelLastData();
		// Add channel totals for the forum channel.
		// This assumes that we don't really care about totals outside of the "forum" (e.x. articles, blogs, groups, special channels)
		$channelTotalsResult = $this->addChannelTotals($complete, $userTree, $parentid);
		$tree = $this->assembleTree($userTree, $complete, $parentid, $depth, $userid);
		$tree['root'] = $parentid;

		// Populate channel statistics. Previously done by calculateChannelStatistics(), and used by getChannelStatistics()
		$this->channelStatistics[$parentid] = array(
			'topics' => $complete[$parentid]['total_topics'],
			'posts' => $complete[$parentid]['total_posts'],
		);

		if (!empty($channelTotalsResult['warnings']))
		{
			if (empty($tree['warnings']))
			{
				$tree['warnings'] = $channelTotalsResult['warnings'];
			}
			else
			{
				$tree['warnings'] = array_merge($channelTotalsResult['warnings'], $tree['warnings']);
			}
		}

		return $tree;
	}

	/**
	 * Fetches a list of channels that guests can access. Basically a public access for getUserChannels()
	 *	but only for userid 0.
	 */
	public function getGuestChannels()
	{
		return $this->getUserChannels(0);
	}

	/**
	 * Returns a list of channels that the current user can access.
	 *
	 * This is a wrapper for getUserChannels, which shouldn't be public
	 * because then anyone could figure out the channel access
	 * permissions of any user.
	 *
	 * @return	array	List of channels that the current user can access.
	 */
	public function getCurrentUserChannels()
	{
		$userid = vB::getCurrentSession()->get('userid');

		return $this->getUserChannels($userid);
	}

	protected function getUserChannels($userid)
	{
		$rawTree = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read("vB_ChannelTreeRaw_$userid");

		if ($rawTree === false)
		{
			$rawTree = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read("vB_ChannelTree_Total");

			if (empty($rawTree))
			{
				$rawTree = $this->getChannelTree();
			}

			//We need to do three things here- filter out nodes this user can't see at all, and flag those where they can only see their own.
			$channelPerms = vB::getUserContext($userid)->getAllChannelAccess();
			//this needs to be filtered recursively.
			foreach($rawTree AS $index => $channel)
			{
				if (isset($channelPerms['selfonly'][$channel['nodeid']]) OR isset($channelPerms['starteronly'][$channel['nodeid']]))
				{
					$rawTree[$index]['noDetail'] = true;
					$rawTree[$index]['readtime'] = 0;
				}
				else if (
					!isset($channelPerms['canview'][$channel['nodeid']]) AND
					!isset($channelPerms['canalwaysview'][$channel['nodeid']]) AND
					!isset($channelPerms['canmoderate'][$channel['nodeid']])
				)
				{
					unset($rawTree[$index]);
				}
				else
				{
					$rawTree[$index]['readtime'] = 0;
				}
			}

			vB_Cache::instance(vB_Cache::CACHE_LARGE)->write("vB_ChannelTreeRaw_$userid", $rawTree, 1440,
				array('vB_ChannelStructure_chg', 'perms_changed', "userPerms_$userid"));
		}

		return $rawTree;
	}

	/** This takes the total tree and adds 'last' data to it */
	protected function addChannelLastData()
	{
		$cacheKey = 'vB_ChTreeWithLast';
		$cacheLife = vB::getDatastore()->getOption('channeltreelife');

		if (!isset($cacheLife))
		{
			$cacheLife = 1;
		}

		if ( $cacheLife > 0 )
		{
			$channels = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($cacheKey);
			if (!empty($channels))
			{
				return $channels;
			}
		}
		$channels = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read("vB_ChannelTree_Total");

		if (empty($channels))
		{
			$channels = $this->getChannelTree();
		}
		$nodes = $this->library->getNodes(array_keys($channels));
		$lastNodes = array();
		//Let's put avatars in the array so the template doesn't need to fetch them.
		$authors = array();
		foreach ($nodes AS $node)
		{
			if (!empty($channels[$node['nodeid']]))
			{
				$channels[$node['nodeid']]['textcount'] = $node['textcount'];
				$channels[$node['nodeid']]['totalcount'] = $node['totalcount'];

				// 'noDetail' is a construct added to the "userTree", and not the complete channel tree.
				// See getUserChannels() where it's added to the tree that's saved with the key vB_ChannelTreeRaw_$userid,
				// not vB_ChTreeWithLast or vB_ChannelTree_Total
				$channels[$node['nodeid']]['viewing'] = 0; //@TODO: is the number of 'viewing' users implemented in api?

				$channels[$node['nodeid']]['lastcontent'] = array(
					'nodeid' => $node['lastcontentid'],
					'authorname' => $node['lastcontentauthor'],
					'userid' => $node['lastauthorid'],
					'starter' => array(),
					'created' => $node['lastcontent']
				);
				$authors[$node['lastauthorid']] = $node['lastauthorid'];
				$lastNodes[] = $node['lastcontentid'];
				// Couple issues with this
				// First, 'topics' should contain the immediate topics (textcount) + all subchannels' topics
				// Second, 'topics' is always user-dependent. If the user cannot view the channel (and subchannels),
				// it should technically say 0.
				// Third, this is done by addChannelTotals()
				//$channels[$node['nodeid']]['topics'] = $node['textcount'];
			}

		}

		//we preload the user information. That way the
		$avatars = vB_Api::instanceInternal('user')->fetchAvatars($authors, true);

		//Now we need to build the 'starter' array. since the node has the same route as its starter.
		$lastNodes =  $this->library->getNodes($lastNodes);
		//getNodes returns the array with nodeid as the key, which is useful here.
		$starters = array();
		foreach($lastNodes AS $lastNode)
		{
			if ($lastNode['starter'] != $lastNode['nodeid'])
			{
				$starters[] = $lastNode['starter'];
			}
		}

		if (!empty($starters))
		{
			$starters = $this->library->getNodes($starters);
			foreach($lastNodes AS $index => $lastNode)
			{
				if (isset($starters[$lastNode['starter']]))
				{
					$lastNodes[$index] = $starters[$lastNode['starter']];
				}
			}
		}
		//now we can populate the starters sub-array, add avatars,
		//and do the totals. We couldn't until we know we have the table fully populated.
		foreach ($channels AS $nodeid => $channel)
		{
			if (empty($channel['noDetail']))
			{
				if (!empty($channel['lastcontent']['nodeid']) AND isset($lastNodes[$channel['lastcontent']['nodeid']])
					AND ($lastNodes[$channel['lastcontent']['nodeid']]['parentid'] == $nodeid))
				{
					$lastnode = $lastNodes[$channel['lastcontent']['nodeid']];
					$channels[$nodeid]['lastcontent']['starter'] = array('nodeid' => $lastnode['nodeid'],
						'routeid' => $lastnode['routeid'],
						'title' => $lastnode['title'], 'channelid' => $lastnode['parentid']);
					$channels[$nodeid]['lastcontent']['title'] = $lastnode['title'];

					if ($channel['lastcontent']['userid'] AND !empty($avatars[$channel['lastcontent']['userid']]))
					{
						$channels[$nodeid]['avatar'] = $avatars[$channel['lastcontent']['userid']];
					}
					else
					{
						$channels[$nodeid]['avatar'] = array();
					}
				}
			}
		}

		if ($cacheLife > 0 )
		{
			vB_Cache::instance(vB_Cache::CACHE_LARGE)->write($cacheKey, $channels, $cacheLife, array('vB_ChannelStructure_chg'));
		}

		return $channels;
	}

	/**
	 *	@param array	$userTree		The channel tree that's dependent on the user. Only channels visible to the current
	 *									user will be present.
	 *	@param array	$channels		The COMPLETE, user-agnostic channel tree, as constructed by addChannelLastData(). Note
	 *									that this function will modify this array to add user-dependent information 'topics' &
	 *									'posts, and potentially blank out some 'lastcontent' arrays, so any callers should be
	 *									aware of this and pre-emptively make a copy of the array before calling this function if
	 *									this array needs to stay user-independent.
	 *	@param int		$rootid 		The root channel
	 *	@param int $depth
	 *	@param int $userid
	 *
	 *	@return array
	 *		'channels' => list of the child channel data. May be empty if there are no children, or if user lacks view permissions.
	 */
	protected function assembleTree(&$userTree, &$channels, $rootid, $depth, $userid)
	{
		$result = array('channels' => array());
		if (empty($userTree) OR !is_array($userTree) OR !isset($userTree[$rootid]))
		{
			return $result;
		}

		if (intval($userid))
		{
			$readData = vB::getDbAssertor()->assertQuery('noderead', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'userid' => $userid,
				'nodeid'  => array_keys($userTree)
			));

			if (!empty($readData))
			{
				foreach($readData AS $noderead)
				{
					$userTree[$noderead['nodeid']]['readtime'] = $noderead['readtime'];
				}
			}
		}

		foreach ($userTree AS $key => $node)
		{
			if (!empty($node['noDetail']))
			{
				$channels[$node['nodeid']]['lastcontent'] = array ();
			}
		}

		//Now the final assembly
		$root = $userTree[$rootid];
		$startsAt = $root['depth'];

		if (empty($root['children']))
		{
			return $result;
		}

		// totals are now added to $channels before this function is called. Look for addChannelTotals()

		foreach($root['children'] AS $childid)
		{
			if (!empty($userTree[$childid]) AND !empty($channels[$childid]['displayorder']))
			{
				$result['channels'][$childid] = $channels[$childid];

				if (
					!empty($result['channels'][$childid]) AND
					!empty($result['channels'][$childid]['starter']) AND
					($result['channels'][$childid]['starter']['channelid'] != $childid)
				)
				{
					$result['channels'][$childid]['lastcontent']['posts'] =  $channels[$childid]['textcount'];
				}

				// If parent channel was marked read at a latter time, then assume that the subchannels were read at that time.
				$inheritReadTime = (
					isset($root['readtime']) AND
					(
						!isset($result['channels'][$childid]['readtime']) OR
						$root['readtime'] > $result['channels'][$childid]['readtime']
					)
				);
				if ($inheritReadTime)
				{
					$result['channels'][$childid]['readtime'] = $root['readtime'];
				}

				$this->addFinalBranches($result['channels'][$childid], $channels, $userTree, $startsAt + $depth, $userid);
			}
		}

		return $result;
	}

	protected function addFinalBranches(&$trunk, &$tree, &$userTree, $maxDepth, $userid)
	{
		static $oldestNew;

		if (!isset($oldestNew))
		{
			$oldestNew = vB::getRequest()->getTimeNow() - (vB::getDatastore()->getOption('markinglimit') * 86400);
		}

		if (isset($userTree[$trunk['nodeid']]['readtime']))
		{
			// Readtime might have been set from the parent channel's readtime.
			// If a parent channel was marked "read" later than the current trunk,
			// use the later readtime and do not overwrite.
			if (
				!isset($trunk['readtime']) OR
				$userTree[$trunk['nodeid']]['readtime'] > $trunk['readtime']
			)
			{
				$trunk['readtime'] = $userTree[$trunk['nodeid']]['readtime'];
			}
		}
		// topics & posts are set directly to the complete channels array in addChannelTotals()
		//$trunk['topics'] = $userTree[$trunk['nodeid']]['topics'];
		//$trunk['posts'] = $userTree[$trunk['nodeid']]['posts'];

		if (!empty($trunk['children']) AND ($trunk['depth'] <= $maxDepth))
		{
			$lastContent = array();
			foreach ($trunk['children'] AS $subchannel)
			{
				if (isset($userTree[$subchannel]) AND ($trunk['nodeid'] !== $subchannel) AND ($tree[$subchannel]['displayorder'] > 0))
				{
					if (!isset($trunk['subchannels']))
					{
						$trunk['subchannels'] = array();
					}
					$trunk['subchannels'][$subchannel] = $tree[$subchannel];
					// If parent channel was marked read at a latter time, then assume that the subchannels were read at that time.
					$inheritReadTime = (
						isset($trunk['readtime']) AND
						(
							!isset($trunk['subchannels'][$subchannel]['readtime']) OR
							$trunk['readtime'] > $trunk['subchannels'][$subchannel]['readtime']
						)
					);
					if ($inheritReadTime)
					{
						$trunk['subchannels'][$subchannel]['readtime'] = $trunk['readtime'];
					}

					$this->addFinalBranches($trunk['subchannels'][$subchannel], $tree, $userTree, $maxDepth, $userid);

					if (!empty($trunk['subchannels'][$subchannel]['lastcontent'])  AND
						!empty($trunk['subchannels'][$subchannel]['lastcontent']['created']) AND
							(empty($lastContent) OR ($lastContent['created'] < $tree[$subchannel]['lastcontent']['created'])) )
					{
						$lastContent = $trunk['subchannels'][$subchannel]['lastcontent'];
					}
				}
			}

			if (!empty($lastContent) AND
				(empty($trunk['lastcontent']) OR empty($trunk['lastcontent']['created']) OR empty($trunk['lastcontent']['starter'])
					OR ($lastContent['created'] > $trunk['lastcontent']['created'])))
			{
				$trunk['lastcontent'] = $lastContent;
			}
		}

		if (!intval($userid))
		{
			// I have no idea why guests get special treatment, but this was how it was. I just moved this out of another
			// if condition while making changes for VBV-14562.
			$trunk['is_new'] = 1;
		}
		elseif (!empty($trunk['lastcontent']) AND (!isset($trunk['readtime']) OR $trunk['lastcontent']['created'] > $trunk['readtime']))
		{
			// If lastcontent was cleared by assembleTree or genuinely doesn't exist,
			// it makes no sense to set is_new. So only set is_new if lastcontent is there,
			// AND the created vs readtime actually makes it new. VBV-14562
			$trunk['is_new'] = 1;
		}
		else
		{
			$trunk['is_new'] = 0;
		}

		// rss info
		$type = vB_Api_External::TYPE_RSS2;
		$rssinfo = vB_Library::instance('external')->getExternalDataForChannels(array($trunk['nodeid']), $type);
		$trunk['rss_enabled'] = $rssinfo[$trunk['nodeid']][$type . '_enabled'];
		$trunk['rss_route'] = $rssinfo[$trunk['nodeid']][$type . '_route'];

		//This isn't needed any more.
		unset($trunk['children']);
	}

	/**
	 * This function builds the basic channel tree. This is global, without reference to depth or user permissions.
	 *
	 * @return array of with nodeid => array of node information including ancestry, etc.
	 */
	protected function getChannelTree()
	{
		$channelList = array();
		//First let's get all the channels
		$rawChannels = vB::getDbAssertor()->getRows('vBForum:getChannelTree', array());
		/* We are sorted by parentid, and the normal simple case will be that the node tree is clean and (since children
		can't be created until their parents exist, the child nodes come after their parents. So in that case we simply scan the
		table once.

		 BUT...
		there are two possible problem cases. First, somehow we got an orphan record. We have to recover from that case.
		Second, somebody moved a channel to a node created after it, therefore a higher nodeid. In that case we will have to
		scan the array twice. So.. we'll keep a "rescan" flag- if we skipped anything, we rescan. */

		$rescan = true;
		//First we need to insert the root node.
		foreach($rawChannels AS $index => $channel)
		{
			if ($channel['parentid'] == 0)
			{
				$channel['children'] = array();
				$channel['depth'] = 0;
				$channel['parents'] = array($channel['nodeid']);
				$channelList[$channel['nodeid']] = $channel;
				unset($rawChannels[$index]);
				break;
			}
		}

		while ($rescan AND !empty($rawChannels))
		{
			$rescan = false;
			foreach($rawChannels AS $index => $rawChannel)
			{
				if (isset($channelList[$rawChannel['parentid']]))
				{
					$channel = $rawChannel;
					$rescan = true;
					$channel['children'] = array();
					$channel['parents'] = array($channel['nodeid']);
					foreach($channelList[$channel['parentid']]['parents'] AS $parentid)
					{
						$channel['parents'][] = $parentid;
					}
					$channel['depth'] = $channelList[$channel['parentid']]['depth'] + 1;
					$channelList[$channel['parentid']]['children'][$channel['nodeid']] = $channel['nodeid'];
					$channel['parent'] = $channel['parentid'];
					$channelList[$channel['nodeid']] = $channel;
					unset($rawChannels[$index]);
				}
			}
		}
		vB_Cache::instance(vB_Cache::CACHE_LARGE)->write('vB_ChannelTree_Total', $channelList, 1440, array('vB_ChannelStructure_chg'));
		return $channelList;
	}

	/**
	 * This starts at the bottom and sums the totalcount and textcount fields to topics and posts in the userChannels.
	 *
	 * @param array	$channels		array of all channel records
	 * @param array	$userChannels	array of channel records for the current user only
	 * @param int	$channelid		Id of the channel we are currently processing.
	 *
	 * @return	Array	May contain 'warnings' => String[] of warning(s)
	 */
	protected function addChannelTotals(&$channels, &$userChannels, $channelid)
	{
		$returnArray = array();
		/* This is a complex task. The user should see only totals that they could view. A
		 * parent channel may have both subchannels and direct totals.
		 * We call this recursively to get the totals, which we add to $userChannels.
		 */

		/*
		 * textcount is the count of the direct children. I.e. immediate topics in a channel.
		 * totalcount is textcount + all descendants' textcount. I.e. total posts.
		 * We can't just use totalcount and call it a day because there might be
		 * descendant channels that the user cannot view.
		 *
		 * So starting at the very bottom,
		 *	if user can view this channel:
		 * 		immediate_topics = this_channel.textcount;
		 *		immediate_posts = this_channel.totalcount - SUM(direct_children_channel.totalcount);
		 * 	if user cannot view this channel:
		 *		immediate_topics = 0; // user cannot view this channel, but this says nothing about descendants
		 *		immediate_posts = 0;
		 *
		 * 	this_channel.topics = immediate_topics + SUM(direct_children_channel.topics)
		 *	this_channel.posts = immediate_posts + SUM(direct_children_channel.posts)
		 */
		$sum_children_totalcount = 0;
		$sum_visible_topics = 0;
		$sum_visible_posts = 0;

		/*
		 * Now, the statistics module is a different beast altogether. We need to ignore view permissions for the module,
		 * so we'll have to basically do the above, but just ignore the view check.
		 *
		 */
		$sum_total_topics = 0;
		$sum_total_posts = 0;

		if (!empty($channels[$channelid]['children']))
		{
			foreach($channels[$channelid]['children'] AS $childid)
			{
				// We want to do this recursively. But the current channel's INvisibility doesn't
				// guarantee a descendant channel's INvisibility (for ex. a parent could
				// have all channel perms set to no, but its child channel could have all
				// perms set to yes), so we must call addChannelTotals() outside of any
				// "visibility checks".
				$returnArray += $this->addChannelTotals($channels, $userChannels, $childid);

				$throwException = (
					(	!isset($channels[$childid]['topics']) OR
						!isset($channels[$childid]['posts']) OR
						!isset($channels[$childid]['total_topics']) OR
						!isset($channels[$childid]['total_posts'])
					) AND $this->inDebugMode()
				);
				if ($throwException)
				{
					// We can't handle these errors at all at the moment, but we do want to know if this
					// somehow happens during development.
					// I haven't seen this happen, but it could if the complete channel tree $channels has a broken
					// hierarchy/order.
					if (!isset($returnArray['warnings']))
					{
						$returnArray['warnings'] = array();
					}
					$msg = 'Unexpected error, missing total_topics & total_posts for child channels. If you do not want to see this exception, turn debug mode off.';
					$returnArray['warnings']['missing totals warning'] =  $msg; // don't show multiples of this warning for different channels.
				//	throw new vB_Exception_Api('Unexpected error, missing total_topics & total_posts for child channels. If you do not want to see this exception, turn debug mode off.');
				}
				$sum_visible_topics += $channels[$childid]['topics'];
				$sum_visible_posts += $channels[$childid]['posts'];

				// User-independent
				$sum_children_totalcount += $channels[$childid]['totalcount'];
				$sum_total_topics += $channels[$childid]['total_topics'];
				$sum_total_posts += $channels[$childid]['total_posts'];
			}
		}

		$immediate_topics = 0;
		$immediate_posts = 0;
		// Check isset to avoid showing a warning --
		// We should probably be checking if $channelid is valid somewhere upstream,
		// but I don't have time to address that right now. This preserves current
		// behavior while avoiding outputting the warning
		if (isset($channels[$channelid]))
		{
			// topics that are immediately under this channel
			$immediate_topics = $channels[$channelid]['textcount'];
			// posts includes topics & replies to topics that are immediately under this channel
			$immediate_posts = $channels[$channelid]['totalcount'] - $sum_children_totalcount;
		}

		if ($immediate_posts < 0)
		{
			if ($this->inDebugMode())
			{
				// Again, we can't handle these errors properly at the moment.
				// This happens frequently post-upgrade due to VBV-14784.
				// To work around this, rebuild the topic & forum info in adminCP.
				$msg = 'Unexpected error, post count is negative!
If you do not want to see this exception, turn debug mode off.
This issue is usually fixed by running AdminCP > Maintenance > General Update Tools > "Rebuild Topic Information", followed by "Rebuild Forum Information", then clearing the system cache (order matters).
Please see VBV-14784 for more details. If a specific action has triggered this exception (ex. deleting a node), please create a JIRA with the details.';
				if (!isset($returnArray['warnings']))
				{
					$returnArray['warnings'] = array();
				}
				$returnArray['warnings']['negative postcount warning'] = $msg;	// don't show multiples of this warning for different channels.
				//throw new vB_Exception_Api($msg);
			}
			$immediate_posts = 0;
		}

		// The 'topics' & 'posts' counts are user-dependent, and should include ALL descendant topics & posts that the user can see.
		if (isset($userChannels[$channelid]))
		{
			$channels[$channelid]['topics'] = $immediate_topics + $sum_visible_topics;
			$channels[$channelid]['posts'] = $immediate_posts + $sum_visible_posts;
		}
		else
		{
			// If this channel is invisible to the user, exclude the topics & posts immediately under this channel.
			// However, subchannels might be visible and have topics & posts, so include those.
			$channels[$channelid]['topics'] = $sum_visible_topics;
			$channels[$channelid]['posts'] = $sum_visible_posts;
		}

		// For site statistics module. User-independent
		$channels[$channelid]['total_topics'] = $immediate_topics + $sum_total_topics;
		$channels[$channelid]['total_posts'] = $immediate_posts + $sum_total_posts;


		return $returnArray;
	}


	public function fetchChannelDetails($nodes, $nodesOnly = array())
	{
		$userContext = vB::getUserContext();
		//We want some detail on the lastcontent record
		$lastIds = array();
		$channels = array();
		foreach ($nodes AS $node)
		{
			// VBV-14562, do not set is_new if lastcontent doesn't exist or was cleared due to view permissions.
			// THIS DOESN'T TAKEN INTO ACCOUNT WHEN PARENT CHANNELS ARE READ. However, out of scope for this JIRA.
			// See the JIRA & diff for this commit for details.
			$is_new = (
				!empty($node['lastcontent']) AND
				(!isset($node['readtime']) OR $node['lastcontent'] > $node['readtime'])
			);
			//There might be some channels for which this user can't see content.
			$channels[$node['nodeid']] = array(
				'nodeid' 		=> $node['nodeid'],
				'routeid' 		=> $node['routeid'],
				'title'			=> $node['title'],
				'description'	=> $node['description'],
				'parentid' 		=> $node['parentid'],
				'textcount'		=> $node['textcount'],
				'totalcount'	=> $node['totalcount'],
				'viewing'		=> 0, //@TODO: is the number of 'viewing' users implemented in api?
				'readtime' 		=> isset($node['readtime']) ? $node['readtime'] : null,
				'is_new'		=> $is_new,
				'category' 	    => $node['content']['category'],
				'displayorder'  => $node['displayorder'],
				'parents'  		=> $node['parents'],
				'subchannels' 	=> array(),
			);

			if (
				array_key_exists($node['nodeid'], $nodesOnly)
				OR (
					($node['lastcontentid'] > 0) AND
					(!$userContext->getChannelPermission('forumpermissions', 'canview', $node['lastcontentid']) OR
					 !$userContext->getChannelPermission('forumpermissions', 'canviewthreads', $node['lastcontentid']) OR
					 !$userContext->getChannelPermission('forumpermissions', 'canviewothers', $node['lastcontentid']))
				)
			)
			{
				$channels[$node['nodeid']]['lastcontent'] = array(
					'nodeid'	=> 0,
					'title'		=> '',
					'authorname'=> '',
					'userid'	=> '',
					'starter'	=> array(),
				);

			}
			else
			{
				if (($node['lastcontentid'] > 0) AND !array_key_exists($node['lastcontentid'], $lastIds))
				{
					$lastIds[$node['lastcontentid']] = $node['lastcontentid'];
				}

				$channels[$node['nodeid']]['lastcontent'] = array(
					'nodeid'	=> $node['lastcontentid'],
					'title'		=> '',
					'authorname'=> $node['lastcontentauthor'],
					'userid'	=> $node['lastauthorid'],
					'starter'	=> array(),
				);
			}
			if (!empty($node['readtime']))
			{
				$channels[$node['nodeid']]['readtime'] = $node['readtime'];
			}
		}

		unset($nodes);
		//first we get the lastcontent record.
		$nodes = $this->getNodes($lastIds);

		// Check if we have any prefixes
		$phrasevars = array();
		foreach ($nodes as $node)
		{
			if (!empty($node['prefixid']))
			{
				$phrasevars[] = 'prefix_' .  $node['prefixid'] . '_title_plain';
				$phrasevars[] = 'prefix_' .  $node['prefixid'] . '_title_rich';
			}
		}
		$phrases = array();
		if ($phrasevars)
		{
			$phrases = vB_Api::instanceInternal('phrase')->fetch($phrasevars);
		}

		$lastIds = array();
		foreach ($channels AS $key => $channel)
		{
			$nodeid = $channel['lastcontent']['nodeid'];
			if ($nodeid AND isset($nodes[$nodeid]))
			{
				$node =& $nodes[$nodeid];
				$channels[$key]['lastcontent']['title'] = $node['title'];
				$channels[$key]['lastcontent']['created'] = $node['created'];
				$channels[$key]['lastcontent']['parentid'] = $node['parentid'];
				//if this is a starter we have all the information we need.
				$channels[$key]['lastcontent']['starter']['nodeid'] = $node['starter'];

				if ($node['starter'] == $node['nodeid'])
				{
					$channels[$key]['lastcontent']['starter']['routeid'] = $node['routeid'];
					$channels[$key]['lastcontent']['starter']['title'] = $node['title'];
				}
				else
				{
					//We need another query
					$lastIds[$node['starter']] = $node['starter'];
				}

				if (!empty($node['prefixid']))
				{
					$channels[$key]['lastcontent']['starter']['prefixid'] = $node['prefixid'];
					if (!empty($phrases['prefix_' .  $node['prefixid'] . '_title_plain']))
					{
						$node['prefix_plain'] = $phrases['prefix_' .  $node['prefixid'] . '_title_plain'];
					}
					if (!empty($phrases['prefix_' .  $node['prefixid'] . '_title_rich']))
					{
						$node['prefix_rich'] = $phrases['prefix_' .  $node['prefixid'] . '_title_rich'];
					}
				}

				if (!empty($node['prefix_rich']))
				{
					$channels[$key]['lastcontent']['starter']['prefix_rich'] = $node['prefix_rich'];
				}

				if (!empty($node['prefix_plain']))
				{
					$channels[$key]['lastcontent']['starter']['prefix_plain'] = $node['prefix_plain'];
				}
			}
		}

		//Now get any lastcontent starter information we need
		if (!empty ($lastIds))
		{
			$nodes = $this->getNodes($lastIds);
			foreach ($channels AS $channelId => $channel)
			{
				if ($channels[$channelId]['lastcontent']['starter'])
				{
					$nodeid = $channels[$channelId]['lastcontent']['starter']['nodeid'];
					if ($nodeid AND isset($nodes[$nodeid]))
					{
						$node =& $nodes[$nodeid];
						$channels[$channelId]['lastcontent']['starter']['routeid'] = $node['routeid'];
						$channels[$channelId]['lastcontent']['starter']['title'] = $node['title'];
					}
				}
			}
		}

		return $channels;
	}

	/**
	 * Returns the node read time for the current user and the given nodeid
	 *
	 * @param	int	Node id
	 *
	 * @return	int	Read time for the node
	 */
	public function getNodeReadTime($nodeid)
	{
		$nodeid = (int) $nodeid;

		$user = vB::getCurrentSession()->fetch_userinfo();

		$nodeRead = vB::getDbAssertor()->getRow('noderead', array(
			'userid' => $user['userid'],
			'nodeid' => $nodeid,
		));

		return $nodeRead['readtime'];
	}

	/**
	 * Returns the first immediate child node of the given node that was created
	 * after the given timestamp
	 *
	 * @param	int	Parent Node ID
	 * @param	int	Time stamp
	 *
	 * @return	int	Node ID
	 */
	public function getFirstChildAfterTime($parentNodeId, $timeStamp)
	{
		$parentNodeId = (int) $parentNodeId;
		$timeStamp = (int) $timeStamp;

		while(true)
		{
			$newReplies = vB::getDbAssertor()->getRows('vBForum:getRepliesAfterCutoff', array(
				'starter' => $parentNodeId,
				'cutoff' => $timeStamp,
			));

			if (empty($newReplies))
			{
				// topic has no more replies
				break;
			}

			foreach ($newReplies AS $newReply)
			{
				if (vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $newReply['nodeid']))
				{
					return $newReply['nodeid'];
				}
				$timeStamp = $newReply['publishdate'];
			}
		}

		return false;
	}


	/**
	 * Insert/Update nodeview for nodeid
	 * @param	int		$nodeid		nodeid for which we should increment the view count
	 * @return 	mixed				return true upon completion, or an error message
	 */
	public function incrementNodeview($nodeid)
	{
		$nodeid = intval($nodeid);

		// no permissions to check for. Any views (including guests') should count.

		// counting views should only be for starters
		$node = vB_Library::instance('node')->getNodeBare($nodeid);
		if ($node['starter'] != $node['nodeid'])
		{
			return array('error' => 'Nodeid is not a starter');
		}

		vB::getDbAssertor()->assertQuery('vBForum:updateNodeview', array('nodeid' =>  $nodeid));
		return true;
	}

	/**
	 * Fetch nodeview count(s) for nodeid(s), used by mergeNodeviewsForTopics() below
	 * @param	array	$nodeids		array of nodeid(s) for which we're grabbing the count(s)
	 * @return 	array					array with keys $nodeids & corresponding counts for the values
	 *										array(<nodeid1> => <view count of nodeid1>, <nodeid2> => <view count of nodeid2>...)
	 */
	protected function getNodeviews($nodeids)
	{
		return $this->library->getNodeviews($nodeids);
	}

	/**
	 * Merges the nodeviews into the topics array, used by the display_Topics template
	 *
	 * @param  array $topicsArray	search results array with nodeids for keys, and each element having a 'content' array
	 *
	 * @return array array with keys $nodeids & corresponding counts for the values
	 *               array(<nodeid1> => <view count of nodeid1>, <nodeid2> => <view count of nodeid2>...)
	 */
	public function mergeNodeviewsForTopics($topicsArray)
	{
		if(!is_array($topicsArray))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($topicsArray, 'topicsArray', __CLASS__, __FUNCTION__));
		}

		//nothing to do
		if(!$topicsArray)
		{
			return array();
		}

		// assuming that topicsArray will always have nodeids for keys. Otherwise we'd have to walk through the array twice.
		$nodeids = array_keys($topicsArray);
		$nodeViews = $this->library->getNodeviews($nodeids);

		foreach ($topicsArray AS $nodeid => &$nodeData)
		{
			$nodeData['content']['views'] = $nodeViews[$nodeid];
		}

		return $topicsArray;
	}

	/**
	 * Merges "posted" info into the topics array, used by the display_Topics template.
	 * This adds the "content.posted" element to the node record. The value is the number of
	 * times the current user has posted in the topic (replies and comments); zero if none.
	 *
	 * @param  array  Nodes
	 *
	 * @return array  Same array of nodes, with the "posted" element added to the "content" sub-array
	 */
	public function mergePostedStatusForTopics($nodes)
	{
		$user = vB::getCurrentSession()->fetch_userinfo();
		$userid = $user['userid'];

		return $this->library->mergePostedStatusForTopics($nodes, $userid);
	}

	/**
	 * Return only the safe data for a node for which previewonly is set
	 *
	 * @param  mixed Existing node data
	 *
	 * @return mixed Cleaned node data
	 */
	public function getPreviewOnly($node)
	{

		$result = array();

		foreach ($this->previewFields as $fieldname)
		{
			if (isset($node[$fieldname]))
			{
				$result[$fieldname] = $node[$fieldname];
			}
		}
		return $result;
	}

	/**
	 * Return the specified node's createpermissions for editing for the current user
	 *
	 *	@param array	existing node data array including nodeid, starter, channelid, contenttypeid
	 *
	 *	@return array	key 'createpermissions':
	 *						boolean false if they cannot edit the node
	 *						an array with keys contenttypes => integer 1 if they can create the specified
	 *							contenttype, 0 if they cannot
	 */
	public function getCreatepermissionsForEdit($node)
	{
		// This function is only meant to be called from the createcontent controller's actionLoadEditor()
		// It's not meant to be very versatile.
		if (
			!is_array($node) OR
			empty($node['nodeid']) OR
			empty($node['starter']) OR
			empty($node['channelid']) OR
			empty($node['contenttypeid'])
		)
		{
			return array('createpermissions' => false);
		}

		// if the user can't edit this node, then we're out.
		if (!vB_Library_Content::getContentLib($node['contenttypeid'])->getCanEdit($node))
		{
			return array('createpermissions' => false);
		}

		/*
		 *	If we got to this point, the user can edit this node. However, to save any edits to the node, we need
		 *	to know if we can basically re-create this node. In other words, we need to know if we can create a
		 *	reply to this node's parent.
		 */
		 $createpermissions = vB::getUserContext()->getCanCreate($node['parentid']);
		 /*
		  * Now, this bit is to handle the case where the createpermissions has changed between the post's creation
		  *	and edit time. Since content lib's validate() only cares about edit permissions for ACTION_UPDATE (which
		  *	getCanEdit() should very closely mimic, if not outright replace in a refactor marathon in the future),
		  *	the user technically can update the post even if they can't create an analogous one anymore. I think the
		  * best solution for this conflict is to grab the contenttype of the existing post, and set createpermission
		  * for that so the front-end will load the editor for that type. Again, this affects front-end behavior only.
		  */
		// TODO: make a legitimate map function that we can use everywhere for this. Is 'contenttypeclass' always set?
		// May need to map from {contenttypeid} -> {type string specified in bitfields}
		$type = 'vbforum_' . strtolower($node['contenttypeclass']);
		$createpermissions[$type] = 1;
		return array('createpermissions' => $createpermissions);
	}

	/**
	 * Return whether the user can delete the node or not. Used by createcontent controller
	 *
	 * @param array	$node		Existing node data array including nodeid, starter, channelid, contenttypeid
	 * @param boolean	$specific	(OPTIONAL) Whether to specifically check for hard delete or soft delete. By default
	 *									it is false, meaning it will check whether user can soft OR hard delete the node
	 * @param boolean	$hard		(OPTIONAL) Only used if $specific is true. Whether it's checking if user can hard
	 *									delete (true) or soft delete (false)
	 *
	 * @return array	key 'candelete':
	 *	boolean true if they can delete the node
	 */
	public function getCanDeleteForEdit($node, $specific = false, $hard = false)
	{
		// This function is only meant to be called from the createcontent controller's actionLoadEditor()
		// It's not meant to be very versatile.
		if (!is_array($node)
			OR empty($node['nodeid']) OR empty($node['starter'])
			OR empty($node['channelid']) OR empty($node['userid'])
			OR empty($node['contenttypeid'])
		)
		{
			return array('candelete' => false);
		}

		// Let's grab some params that getCanDelete() requires if we want to use the $hard param.
		$userContext = vB::getUserContext();
		$starter = vB_Library::instance('node')->getNodeBare($node['starter']);
		$channelid = $starter['parentid'];
		$channelPerms = vB::getUserContext()->fetchPermsForChannels(array($channelid));
		$thisChannelPerms = $channelPerms[$channelid];
		$thisChannelPerms['global'] = $channelPerms['global'];

		$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);

		if ($specific)
		{
			$canDelete = $contentLib->getCanDelete($node, $userContext, $thisChannelPerms, $hard);
		}
		else
		{
			$canDelete = (
				$contentLib->getCanDelete($node, $userContext, $thisChannelPerms, false)
				OR $contentLib->getCanDelete($node, $userContext, $thisChannelPerms, true)
			);
		}

		return array("candelete" => $canDelete);
	}

	/**
	 * Returns channel statistics-- number of topics / posts.
	 *
	 * This function depends on fetchChannelNodeTree, which populates channelStatistics.
	 *
	 * @param	int	Parent node id
	 *
	 * @return	array	Channel statistics.
	 */
	public function getChannelStatistics($parentid)
	{
		if (empty($this->channelStatistics) OR empty($this->channelStatistics[$parentid]))
		{
			// The same parameters are sent to fetchChannelNodeTree as when displaying
			// the main listing of forums on the home page.
			$this->fetchChannelNodeTree($parentid, 3);
		}

		return $this->channelStatistics[$parentid];
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104244 $
|| #######################################################################
\*=========================================================================*/
