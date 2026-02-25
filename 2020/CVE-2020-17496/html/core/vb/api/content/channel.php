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
 * vB_Api_Content_Channel
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: channel.php 102709 2019-08-29 16:53:27Z jinsoojo.ib $
 * @access public
 */
class vB_Api_Content_Channel extends vB_Api_Content
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Channel';

	//The table for the type-specific data.
	protected $tablename = 'channel';

	//We need the primary key field name.
	protected $primarykey = 'nodeid';

	private $topLevelChannels = array();

	/**
	 * Normal constructor- protected to prevent direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Channel');
		$this->previewField[] = 'options';
		$this->previewField[] = 'styleid';
		$this->previewField[] = 'filedataid';
		$this->previewField[] = 'category';
	}

	/**
	 * Adds a new channel.
	 *
	 * @param  mixed   Array of field => value pairs which define the record.
	 * @param  array   Array of options for the content being created.
	 * 	skipTransaction,
	 * 	skipFloodCheck,
	 * 	floodchecktime,
	 * 	skipDupCheck,
	 * 	skipNotification
	 * 	nodeonly: Boolean indicating whether extra info for channel should be created
	 * 		(page, routes, etc). Used for importing channels
	 *
	 * @return integer the new nodeid
	 */
	public function add($data, $options = array())
	{
		// prevent adding top level channels
		if (!empty($data['parentid']))
		{
			$channel = $this->fetchChannelById($data['parentid']);
			if ($channel['guid'] == vB_Channel::MAIN_CHANNEL)
			{
				throw new vB_Exception_Api('cant_add_channel_to_root');
			}
		}
		else
		{
			// The library has some code to "support" adding channels without a parentid (VBV-833)
			// but that complicates (icon) permission checks and ATM it defaults the parent to the "Special"
			// channel which is probably a mistake. The current UI no longer allows skipping the parent when
			// creating channels in AdminCP, so I'm going to no longer support it in the API, and eventually
			// remove the library code.
			throw new vB_Exception_Api('invalid_data');
		}

		if (!isset($data['displayorder']))
		{
			$data['displayorder'] = 1;
		}

		if (isset($data['filedataid']))
		{
			$this->validateIcon($data['parentid'], array('filedataid' => $data['filedataid']));
		}

		return parent::add($data, $options);
	}


	/**
	 * Returns a channel record based on its node id
	 *
	 * @param  int   Node ID
	 * @param  array Options array, understands:
	 *               'moderatorperms'
	 *
	 * @return array Channel information
	 */
	public function fetchChannelById($nodeid, $options = array())
	{
		$nodeid = intval($nodeid);
		$nodes = $this->getContent($nodeid, $options);
		$data = array();

		if (!$this->library->validate($data, vB_Library_Content::ACTION_VIEW, $nodeid, array($nodes)))
		{
			throw new vB_Exception_Api('no_permission');
		}

		if (!empty($options['moderatorperms']))
		{
			foreach ($nodes AS $nodeid => $node)
			{
				//Now the moderator-type permissions
				$nodes[$nodeid]['moderatorperms'] = vB::getUserContext()->getModeratorPerms($node);
				if (!empty($nodes[$nodeid]['moderatorperms']))
				{
					foreach ($nodes[$nodeid]['moderatorperms'] AS $perm)
					{
						if ($perm > 0)
						{
							$nodes[$nodeid]['canmoderate'] = true;
							break;
						}
					}
				}
			}

			if ($this->library->getCanModerate($nodes[$nodeid]))
			{
				$nodes[$nodeid]['moderatorperms']['canmoderateposts'] = 1;
			}
		}


		return $nodes[$nodeid];
	}

	/**
	 * Returns a channel record based on its node guid
	 *
	 * @param  string Channel GUID
	 *
	 * @return array  Channel information
	 */
	public function fetchChannelByGUID($guid)
	{
		return vB_Library::instance('content_channel')->fetchChannelByGUID($guid);
	}

	/**
	 * Returns a channel id based on its node guid
	 *
	 * @param  string Channel GUID
	 *
	 * @return int    Channel id
	 */
	public function fetchChannelIdByGUID($guid)
	{
		return vB_Library::instance('content_channel')->fetchChannelIdByGUID($guid);
	}

	/**
	 * Returns an array with bbcode options for the node.
	 *
	 * @param  int   $nodeId
	 *
	 * @return array Array of Bbcodee options from the datastore
	 */
	public function getBbcodeOptions($nodeId)
	{
		$record = $this->assertor->getRow('vBForum:channel', array(
			vB_dB_Query::TYPE_KEY	=> vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $nodeId)
		));

		$result = array();

		$options = vB::getDatastore()->getValue('bf_misc_forumoptions');
		foreach($options AS $optionName => $optionVal)
		{
			$result[$optionName] = (bool)($record['options'] & $optionVal);
		}

		return $result;
	}

	/**
	 * Get a blog icon
	 *
	 * @param  int    The channel or nodeid
	 * @param  string Thumbnail version/size requested (SIZE_* constanst in vB_Api_Filedata)
	 *
	 * @return mixed  the raw content of the image.
	 */
	function fetchChannelIcon($nodeid, $type = vB_Api_Filedata::SIZE_FULL)
	{
		if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $nodeid))
		{
			return $this->getDefaultChannelIcon($nodeid);
		}

		$channel = $this->assertor->getRow('vBForum:channel', array('nodeid' => $nodeid));
		if(!$channel)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeid, 'nodeid', __CLASS__, __FUNCTION__));
		}

		if ($channel['filedataid'])
		{
			$params = array('filedataid' => $channel['filedataid'], 'type' => $type);
			$record = vB::getDbAssertor()->getRow('vBForum:getFiledataContent', $params);

			if (!empty($record))
			{
				return vB_Image::instance()->loadFileData($record, $type, true);
			}
		}
		//If we don't have a valid custom icon, return the default.
		return $this->getDefaultChannelIcon($nodeid);
	}

	/**
	 * Returns the default channel icon for the passed channel node ID
	 *
	 * @param  int   Channel Node ID
	 *
	 * @return array The array of icon information.
	 */
	private function getDefaultChannelIcon($nodeid)
	{
		$is_sg = vB_Api::instanceInternal('socialgroup')->isSGChannel($nodeid);
		$is_blog = $def_icon = false;
		if (!empty($is_sg))
		{
			$def_icon = "default_sg_large.png";
		}
		else
		{
			$is_blog = vB_Api::instanceInternal('blog')->isBlogNode($nodeid);
			if (!empty($is_blog))
			{
				$def_icon = "default_blog_large.png";
			}
		}
		if (!empty($def_icon))
		{
			return array(
					'filesize' => filesize(DIR . "/images/default/$def_icon"),
					'dateline' => vB::getRequest()->getTimeNow(),
					'headers' => vB_Library::instance('content_attach')->getAttachmentHeaders('png'),
					'filename' => $def_icon,
					'extension' => 'png',
					'filedataid' => 0,
					'is_default' => 1,
					'filedata' => file_get_contents(DIR . "/images/default/$def_icon")
				);
		}
		else
		{
			$cleargif = DIR . '/clear.gif';
			$clearinfo = pathinfo($cleargif);
			return array(
					'filesize' => filesize($cleargif),
					'dateline' => vB::getRequest()->getTimeNow(),
					'headers' => vB_Library::instance('content_attach')->getAttachmentHeaders($clearinfo['extension']),
					'filename' => $clearinfo['basename'],
					'extension' => $clearinfo['extension'],
					'is_default' => 2,
					'filedataid' => 0,
					'filedata' => file_get_contents($cleargif)
			);

		}
	}

	/**
	 * Returs the contributors for a channel
	 *
	 * @param  int   Channel Node ID
	 *
	 * @return array List of channel contributors/authors.
	 */
	public function getContributors($nodeId)
	{
		$db = vB::getDbAssertor();

		$users = array();

		// fetch relevant usergroups
		$systemgroups = array();
		$usergroups = $db->assertQuery('vBForum:usergroup', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'systemgroupid' => array(
				vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID,
				vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
				vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID
			)
		));
		foreach ($usergroups as $usergroup)
		{
			$systemgroups[$usergroup['systemgroupid']] = $usergroup['usergroupid'];
		}
		$userids = array();
		// fetch active contributors
		$active = $db->assertQuery('vBForum:fetchActiveChannelContributors', array('nodeid' => $nodeId));
		if ($active AND $active->valid())
		{
			foreach($active AS $a)
			{
				switch ($a['systemgroupid'])
				{
					case vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID:
						$role = 'owner';
						break;
					case vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID:
						$role = 'moderator';
						break;
					case vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID:
						$role = 'member';
						break;
					default:
						continue 2;
				}

				$userids[$a['userid']] = $a['userid'];

				$result['active'][$role][] = array(
					'usergroupid' => $a['usergroupid'],
					'userid' => $a['userid']
				);
			}
		}

		// fetch pending contributors
		$pending = $db->assertQuery('vBForum:fetchPendingChannelContributors', array('nodeid' => $nodeId));

		if ($pending AND $pending->valid())
		{
			foreach($pending AS $p)
			{
				switch ($p['about'])
				{
					case vB_Api_Node::REQUEST_TAKE_OWNER:
					case vB_Api_Node::REQUEST_SG_TAKE_OWNER:
						$role = 'owner';
						$usergroupid = $systemgroups[vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID];
						break;
					case vB_Api_Node::REQUEST_TAKE_MODERATOR:
					case vB_Api_Node::REQUEST_SG_TAKE_MODERATOR:
						$role = 'moderator';
						$usergroupid = $systemgroups[vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID];
						break;
					default:
						continue 2;
				}

				$userids[$p['recipientid']] = $p['recipientid'];

				$result['pending'][$role][] = array(
					'usergroupid' => $usergroupid,
					'userid' => $p['recipientid'],
				);
			}
		}

		if (!empty($userids))
		{
			$usernames = vB_Library::instance('user')->fetchUserNames($userids);
			foreach ($result as $status => $roles)
			{
				foreach ($roles as $role => $users)
				{
					foreach ($users as $index => $user)
					{
						if (!empty($usernames[$user['userid']]))
						{
							$result[$status][$role][$index]['username'] = $usernames[$user['userid']];
						}
					}
				}
			}
		}

		return $result;
	}

	/**
	 * Converts a channel from a forum to a category or vice versa.
	 *
	 * @param  bool $makeCategory If true it will convert the channel to a category, if false to a forum.
	 * @param  int  $nodeId Channel Node ID.
	 *
	 * @return bool
	 */
	public function switchForumCategory($makeCategory, $nodeId)
	{
		$this->checkHasAdminPermission('canadminforums');

		//Only continue if we are switching.
		$channel = $this->library->getContent($nodeId);

		if ((bool)$channel[$nodeId]['category'] == (bool)$makeCategory)
		{
			return true;
		}

		// can't convert a top level channel
		if (in_array($nodeId, $this->fetchTopLevelChannelIds()))
		{
			throw new vB_Exception_Api('cannot_convert_channel');
		}

		return $this->library->switchForumCategory($makeCategory, $nodeId);
	}

	/**
	 * Fetches the top level Channels/Categories
	 *
	 * @return array Array of channel information
	 */
	public function fetchTopLevelChannelIds()
	{
		if(empty($this->topLevelChannels))
		{
			$topLevelChannels = array(
				'forum' => vB_Channel::DEFAULT_FORUM_PARENT,
				'blog' => vB_Channel::DEFAULT_BLOG_PARENT,
				'groups' => vB_Channel::DEFAULT_SOCIALGROUP_PARENT,
				'articles' => vB_Channel::DEFAULT_ARTICLE_PARENT,
				'special' => vB_Channel::DEFAULT_CHANNEL_PARENT,
			);

			$channels = array();
			$channels_res = vB::getDbAssertor()->assertQuery('vBForum:channel', array('guid' => $topLevelChannels));
			foreach ($channels_res as $channel)
			{
				$area = array_search($channel['guid'], $topLevelChannels);
				$channels[$area] = $channel['nodeid'];
			}
			$this->topLevelChannels = $channels;
		}

		return $this->topLevelChannels;
	}

	/**
	 * Fetches the top level Channel/Category for a node/nodes
	 *
	 * @param  int|array        $nodeids An integer Node ID or an array of int Node IDs.
	 *
	 * @throws vB_Exception_Api 'invalid_data'
	 *
	 * @return int|false        Returns false on failure or the top level channel node ID.
	 */
	public function getTopLevelChannel($nodeids)
	{
		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$toplevel = $this->fetchTopLevelChannelIds();
		$parent = false;
		foreach ($nodeids as $nodeid)
		{
			$parents = vB::getDbAssertor()->getRow(
				'vBForum:closure',
				array('child' => $nodeid, 'parent' => $toplevel),
				array('field' => 'depth', 'direction' => vB_dB_Query::SORT_DESC)
			);

			// the nodes belog to different top level channels
			if (!empty($parent) AND ($parents['parent'] != $parent))
			{
				throw new vB_Exception_Api('invalid_data');
			}

			$parent = empty($parents) ? false : $parents['parent'];
		}

		return $parent;
	}

	/**
	 * Tells whether or not the current user can add a new channel for the given node
	 *
	 * @param  int              Nodeid to check
	 *
	 * @throws vB_Exception_Api 'invalid_data_w_x_y_z', 'no_permission'
	 *
	 * @return array            Array containing checks information. It contains two keys or the standard error array:
	 *                          'can' -- to indicate if user can or can not add channel to the node.
	 *                          'exceeded' -- value indicating if user already reached the max channels allowed at node level.
	 */
	public function canAddChannel($nodeid)
	{
		if (!is_numeric($nodeid) OR ($nodeid < 1))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeid, '$nodeid', __CLASS__, __FUNCTION__));
		}

		$usercontext = vB::getUserContext();

		if (!$usercontext->getChannelPermission('createpermissions', 'vbforum_channel', $nodeid)
			OR !$usercontext->getChannelPermission('forumpermissions', 'canjoin', $nodeid)
			OR !$usercontext->getChannelPermission('forumpermissions', 'canview', $nodeid)
			)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$queryParams = array('parent' => $nodeid, 'userid' => $usercontext->fetchUserId());
		$total = vB::getDbAssertor()->getRow('vBForum:getUserChannelsCount', $queryParams);
		$totalCount = $total['totalcount'];
		$maxchannels = $usercontext->getChannelLimits($nodeid, 'maxchannels');

		if(($maxchannels > 0) AND ($totalCount >= $maxchannels))
		{
			return array('can' => false, 'exceeded' => $maxchannels);
		}

		return array('can' => true, 'exceeded' => 0);
	}

	/**
	 * Checks the permissions to upload a channel icon
	 *
	 * @param  int   $nodeid
	 * @param  array $data
	 *
	 * @return true  Returns true if the icon is acceptible
	 */
	public function validateIcon($nodeid, $data)
	{
		if (empty($nodeid) OR !intval($nodeid))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canuploadchannelicon', $nodeid))
		{
			throw new vB_Exception_Api('can_not_use_channel_icon');
		}

		// special case, we're unsetting an icon, for which we only need to
		// check the canuploadchannelicon permission above.
		if (isset($data['filedataid']) AND empty($data['filedataid']))
		{
			return true;
		}

		// todo: if we're gonna trust the caller on data.filesize, this might be more
		// appropriate as a library function
		if (!empty($data['filedata']) AND !empty($data['filesize']))
		{
			$filedata = $data;
		}
		else if (!empty($data['filedataid']))
		{
			$filedata = vB_Api::instanceInternal('filedata')->fetchImageByFiledataid($data['filedataid']);
		}

		// TODO: fix this check?
		// Is the image animated? This is how it is checked in vB_Image_GD::fetchImageInfo
		// For some reason some animated GIFs are uploaded unanimated, I couldn't find the cause
		if ((strpos($filedata['filedata'], 'NETSCAPE2.0') !== false) AND
			!vB::getUserContext()->getChannelPermission('forumpermissions', 'cananimatedchannelicon', $nodeid))
		{
			throw new vB_Exception_Api('can_not_use_animated_channel_icon');
		}

		$imageLimit = vB::getUserContext()->getChannelLimits($nodeid, 'channeliconmaxsize');

		/*
			todo: the help text for channeliconmaxsize says
			"Note: Channel Image Icons are always limited to 200px by 200px."
			but it doesn't seem like we're enforcing that anywhere.
		 */

		if ($imageLimit > 0 AND $filedata['filesize'] > $imageLimit)
		{
			// the channel icon upload (blogs/groups) checks for this exception
			// and attempts to resize the icon so that it's within the size limits
			// in the uploadAttachment function in the attach library.
			throw new vB_Exception_Api(
				'upload_file_exceeds_limit',
				array(
					vb_number_format($filedata['filesize'], 1, true),
					vb_number_format($imageLimit, 1, true)
				)
			);
		}

		return true;
	}

	/**
	 * Updates the given channel
	 *
	 * @param  int  $nodeid
	 * @param  int  $data
	 *
	 * @return bool
	 */
	public function update($nodeid, $data)
	{
		// we might be setting filedataid = 0 to remove a previous icon
		if (isset($data['filedataid']))
		{
			$this->validateIcon($nodeid, array('filedataid' => $data['filedataid']));

			$oldChannelData = $this->fetchChannelById($nodeid);
		}

		$ret = parent::update($nodeid, $data);

		if (isset($data['filedataid']))
		{
			$assertor = vB::getDbAssertor();

			if (!empty($data['filedataid']))
			{
				$assertor->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $data['filedataid']));
			}

			if (!empty($oldChannelData))
			{
				$assertor->assertQuery('decrementFiledataRefcount', array('filedataid' => $oldChannelData['filedataid']));
			}
		}

		return $ret;
	}

	/**
	 * Cleans the input in the $data array, directly updating $data.
	 *
	 * @param mixed     Array of fieldname => data pairs, passed by reference.
	 * @param int|false Nodeid of the node being edited, false if creating new
	 */
	public function cleanInput($data, $nodeid = false)
	{
		$parentid = empty($data['parentid']) ? $nodeid : $data['parentid'];
		$userCanUseHtml = false;
		if (!empty($parentid))
		{
			$userCanUseHtml = vB::getUserContext()->getChannelPermission('forumpermissions2', 'canusehtml', $parentid);
		}
		// We're only allowing html in titles and descriptions for channels.
		// htmltitle not included because if it was provided, it should still not have html in it anyway.
		$htmlFields = array('title', 'description');
		$htmlData = array();
		$cleaner = vB::getCleaner();

		if ($userCanUseHtml)
		{
			foreach ($htmlFields as $fieldname)
			{
				if (isset($data[$fieldname]))
				{
					$htmlData[$fieldname] = $cleaner->clean($data[$fieldname], vB_Cleaner::TYPE_STR);
				}
			}
		}

		$data = parent::cleanInput($data, $nodeid);

		// Let vB_Api_Content cleanInput do it's thing, then just replace the html fields if they were set.
		foreach ($htmlData AS $fieldname => $value)
		{
			$data[$fieldname] = $value;
		}

		return $data;
	}


	/**
	 * Determines if the current user can moderate the passed node
	 *
	 * @param int|array Node ID or array of Node IDs.
	 */
	public function getCanModerate($node)
	{
		if (is_array($node))
		{
			return $this->library->getCanModerate($node);
		}
		else if (intval($node))
		{
			return $this->library->getCanModerate(null, null, null, $node);
		}

		return false;
	}

	/**
	 * Permanently deletes a node
	 *
	 * @param  integer The nodeid of the record to be deleted
	 *
	 * @return boolean
	 */
	public function delete($nodeid)
	{
		$nodecontent = $this->getContent($nodeid);
		if (isset($nodecontent[$nodeid]))
		{
			$nodecontent = $nodecontent[$nodeid];
		}
		else
		{
			throw new vB_Exception_Api('invalid_node_id');
		}

		// Note: The library delete has a check to prevent top level channels from being deleted, but
		// that excludes channels like the root channel, or the special, privatemessage or vm channels.
		$guids = vB_Channel::getProtectedChannelGuids();
		if (in_array($nodecontent['guid'], array_values($guids)))
		{
			throw new vB_Exception_Api('can_not_remove_default_channel');
		}

		// the reason there is no permission check in this function is because the parent (vB_Api_Content) performs the checks
		return parent::delete($nodeid);
	}

	/**
	 * Returns array of data indicating user's view permissions for the report & infraction channels.
	 * Used by template widget_privatemessage_navigation
	 *
	 * @return Array
	 *				- Array		'result'
	 *						- bool 	'can_view_reports'		True if user can view the report channel
	 *						- bool	'can_view_infractions'	True if user can view the infraction channel
	 *				Ex:
	 *				array('result' => array('can_view_reports' => true, 'can_view_infractions' => false))
	 */
	public function canViewReportsAndInfractions()
	{
		$reportChannelid = $this->fetchChannelIdByGUID(vB_Channel::REPORT_CHANNEL);
		$infractionChannelid = $this->fetchChannelIdByGUID(vB_Channel::INFRACTION_CHANNEL);

		// We need some dummy variable since the first param is passed by reference, even though we don't use it.
		$data = array();
		$canViewReports = $this->library->validate($data, vB_Library_Content::ACTION_VIEW, $reportChannelid);
		$data = array();	// ATM this isn't even used for ACTION_VIEW and its contents are not changed, but just in case that changes in the future...
		$canViewInfractions = $this->library->validate($data, vB_Library_Content::ACTION_VIEW, $infractionChannelid);


		$return = array(
			'result' => array(
				'can_view_reports' => $canViewReports,
				'can_view_infractions' => $canViewInfractions,
			),
		);

		return $return;
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102709 $
|| #######################################################################
\*=========================================================================*/
