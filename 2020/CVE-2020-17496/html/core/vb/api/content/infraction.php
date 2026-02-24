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
 * vB_Api_Content_Infraction
 *
 * @package vBApi
 * @author David Grove
 * @copyright Copyright (c) 2013
 * @version $Id: infraction.php 99787 2018-10-25 00:13:06Z ksours $
 * @access public
 */
class vB_Api_Content_Infraction extends vB_Api_Content_Text
{
	protected $contenttype = 'vBForum_Infraction';
	protected $tablename = array('infraction', 'text');
	protected $infractionChannel = null;
	protected $assertor = null;

	/**
	 * Constructor, no direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Infraction');
		$this->infractionChannel = $this->nodeApi->fetchInfractionChannel();
		$this->assertor = vB::getDbAssertor();
	}

	/*
		Overview of functions in this class:

		add
		update
		delete
		reverseInfraction
		reverseNodeInfraction

		getInfraction
		getNodeInfraction
		getUserInfractions
		getAutomaticBanList
		getInfractionLevels

		canInfractNode
		canInfractUser
		canViewInfraction
		canViewNodeInfraction
		canViewUserInfractions
		canReverseInfraction
		canGiveCustomInfraction
		canViewAdminNote

		buildUserInfractions
		saveInfractionGroup
		deleteInfractionGroup
		checkInfractionGroupChange
		buildInfractionGroupIds
	*/

	/**
	 * Adds a new infraction node
	 *
	 * @param  mixed $data Array of field => value pairs which define the record.
	 * @param  array Array of options for the content being created
	 *               Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *               - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *               - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return mixed array of infraction data.
	 */
	public function add($data, $options = array())
	{
		if (empty($data['infracteduserid']))
		{
			throw new vB_Exception_Api('invalid_userid');
		}

		if (isset($data['infractednodeid']) AND $data['infractednodeid'] > 0 AND !$this->canInfractNode($data['infractednodeid']))
		{
			throw new vB_Exception_Api('no_permission');
		}

		if (empty($data['infractednodeid']) AND !$this->canInfractUser($data['infracteduserid']))
		{
			throw new vB_Exception_Api('no_permission');
		}

		if (empty($data['infractionlevelid']) AND !$this->canGiveCustomInfraction())
		{
			throw new vB_Exception_Api('no_permission');
		}

		//cleanInput wants a parentid
		$data['parentid'] = $this->nodeApi->fetchInfractionChannel();
		$data = $this->cleanInput($data);
		$this->cleanOptions($options);

		$wysiwyg = true;
		if(isset($options['wysiwyg']))
		{
			$wysiwyg = (bool) $options['wysiwyg'];
		}

		return $this->library->add($data, $options, $wysiwyg);
	}

	/**
	 * Cannot update an infraction
	 *
	 * @throws vB_Exception_Api
	 *
	 * @param  $nodeid
	 * @param  $data
	 *
	 * @return void
	 */
	public function update($nodeid, $data)
	{
		throw new vB_Exception_Api('action_not_available');
	}

	/**
	 * Deletes an infraction. Currently the only UI for this is in the Admin CP
	 *
	 * @param  $nodeid Node ID to be deleted
	 *
	 * @return void
	 */
	public function delete($nodeid)
	{
		$this->checkHasAdminPermission('canadminusers');

		if (!$this->canReverseInfraction())
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->delete($nodeid);
	}

	/**
	 * Reverse an infraction
	 *
	 * @param  int    The infraction nodeid
	 * @param  string Reason for the reversal
	 *
	 * @return int    The number of rows that were affected
	 */
	public function reverseInfraction($nodeid, $reason)
	{
		if (!$this->canReverseInfraction())
		{
			throw new vB_Exception_Api('no_permission');
		}

		$nodeid = (int) $nodeid;
		$reason = vB_String::htmlSpecialCharsUni($reason);

		if ($nodeid < 1)
		{
			throw new vB_Exception_Api('invalid_node');
		}

		return $this->library->reverseInfraction($nodeid, $reason);
	}

	/**
	 * Reverses the infraction associated with the given node
	 *
	 * @param  int    Node ID of the node that received the infraction
	 * @param  string Reason for the reversal
	 * @param  array  Node record, if you have it (for the node that received the infraction)
	 *
	 * @return int    The number of rows that were affected
	 */
	public function reverseNodeInfraction($nodeid, $reason, array $node = null)
	{
		// no need to clean input because we're calling another api method

		$infractionNode = $this->getNodeInfraction($nodeid, $node);
		if ($infractionNode AND !empty($infractionNode['nodeid']))
		{
			return $this->reverseInfraction($infractionNode['nodeid'], $reason);
		}

		return false;
	}

	/**
	 * Returns an infraction node based on its nodeid
	 *
	 * @param  int           Node ID
	 *
	 * @return (array|false) Array of infraction info, or false if there is no infraction or you don't have permission to view the infraction
	 */
	public function getInfraction($nodeid)
	{
		$nodeid = (int) $nodeid;

		$infraction = $this->library->getInfraction($nodeid);

		if (!$infraction)
		{
			return false;
		}

		if (!$this->canViewInfraction($nodeid, $infraction))
		{
			return false;
		}

		return $infraction;
	}

	/**
	 * Returns the infraction node for the given node (if it has an infraction)
	 *
	 * @param  int           Node ID
	 * @param  array         Node record, if you have it
	 *
	 * @return (array|false) Array of infraction info, or false if there is no infraction or you don't have permission to view the infraction
	 */
	public function getNodeInfraction($nodeid, array $node = null)
	{
		$nodeid = (int) $nodeid;

		if (!$this->canViewNodeInfraction($nodeid, $node))
		{
			return false;
		}

		return $this->library->getNodeInfraction($nodeid);
	}

	/**
	 * Returns the infraction nodes for infractions that the given user has received.
	 *
	 * @param  int           User ID
	 * @param  int           Offset to start returning records from
	 * @param  int           Limit - the max number of records to return
	 *
	 * @return (array|false) Array of infraction info, or false if there are no infractions or you don't have permission to view the infractions
	 */
	public function getUserInfractions($userid, $offset = 0, $limit = 20)
	{
		$userid = (int) $userid;

		if (!$this->canViewUserInfractions($userid))
		{
			return false;
		}

		return $this->library->getUserInfractions($userid, $offset, $limit);
	}

	/**
	 * Returns the usernames of those users that participated in an infraction conversation.
	 *
	 * @param  array   node IDs
	 *
	 * @return (array) Array of usernames, userid is the key
	 */
	public function getParticipants($nodeids)
	{
		if (empty($nodeids))
		{
			return array();
		}

		foreach ($nodeids as $key => $nodeid)
		{
			if (!$this->canViewInfraction($nodeid))
			{
				unset ($nodeids[$key]);
			}
		}
		return $this->library->getParticipants($nodeids);
	}

	/**
	 * Returns a certain type of infractions
	 *
	 * @param string  $type
	 * @param boolean $replied_by_me - if true, only infractions that the user commented on
	 *                type = 'user' => infractions given to a user
	 *                type = 'post' => infractions given to a post by a user
	 */
	public function getInfractionsByType($type = '', $replied_by_me = false)
	{

		if (!vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction'))
		{
			return array();
		}

		return $this->library->getInfractionsByType($type, $replied_by_me);
	}

	/**
	 * Returns a list of automatic bans or an empty array if there are none.
	 *
	 * @return (array|false) Array of automatic bans or false if the user does not have permission to see them.
	 */
	public function getAutomaticBanList()
	{
		if (
			!vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction')
			AND
			!vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
			AND
			!vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
		)
		{
			return false;
		}

		return $this->library->getAutomaticBanList();
	}

	/**
	 * Returns an array of information for the infraction levels that are currently set up
	 *
	 * @return array Infraction levels
	 */
	public function getInfractionLevels()
	{
		if (!vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction'))
		{
			throw new vB_Exception_Api('no_permission');
		}
		return $this->library->getInfractionLevels();
	}

	/**
	 * Gets the infraction groups
	 *
	 * @return array infraction groups with infractiongroupid as key >
	 */
	public function getInfractionGroups()
	{
		if (!vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction'))
		{
			throw new vB_Exception_Api('no_permission');
		}
		return $this->library->getInfractionGroups();
	}

	/**
	 * Determines if the logged-in user can infract the (author of) the given node
	 *
	 * @param  int   Node ID
	 * @param  array Node record, if you have it
	 *
	 * @return bool  The node (user) can be infracted by current user (or not)
	 */
	public function canInfractNode($nodeid, array $node = null)
	{
		$nodeid = (int) $nodeid;

		return $this->library->canInfractNode($nodeid, $node);
	}

	/**
	 * Determines if the logged-in user can infract the given user
	 *
	 * @param  int  User ID
	 *
	 * @return bool The user can be infracted by current user (or not)
	 */
	public function canInfractUser($userid)
	{
		$userid = (int) $userid;

		return $this->library->canInfractUser($userid);
	}

	/**
	 * Determines if the logged-in user can view the given infraction node
	 *
	 * @param  int   Node ID
	 * @param  array Infraction node record, if you have it
	 *
	 * @return bool  The current user can view the infraction (or not)
	 */
	public function canViewInfraction($nodeid, array $infraction = null)
	{
		$nodeid = (int) $nodeid;
		$userId = vB::getCurrentSession()->get('userid');

		if ($infraction === null)
		{
			$infraction = $this->library->getInfraction($nodeid);
		}

		if (!$infraction)
		{
			return false;
		}

		return (
			// is the user who received this infraction
			$userId == $infraction['infracteduserid']
			// has the 'canseeinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction')
			// has the 'canreverseinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
			// has the 'cangiveinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
		);
	}

	/**
	 * Determines if the logged-in user can view any infractions on the given node
	 *
	 * @param  int   Node ID
	 * @param  array Node record, if you have it
	 *
	 * @return bool  The current user can view any infractions on this node (or not)
	 */
	public function canViewNodeInfraction($nodeid, array $node = null)
	{
		$nodeid = (int) $nodeid;

		return $this->library->canViewNodeInfraction($nodeid, $node);
	}

	/**
	 * Determines if the logged-in user can view the infractions for the given user
	 *
	 * @return bool The current user can view the given user's infractions (or not)
	 */
	public function canViewUserInfractions($userid)
	{
		$userid = (int) $userid;
		$currentUserId = vB::getCurrentSession()->get('userid');

		return (
			// is the user who received the infractions
			$userid == $currentUserId
			// has the 'canseeinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction')
			// has the 'canreverseinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
			// has the 'cangiveinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
		);
	}

	/**
	 * Determines if the logged-in user can reverse an infraction
	 *
	 * @return bool The current user can reverse an infraction (or not)
	 */
	public function canReverseInfraction()
	{
		return (
			// has the 'canreverseinfraction' permission
			vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
		);
	}

	/**
	 * Determines if the logged-in user can give custom (arbitrary value) infractions
	 *
	 * @return bool The current user can give a custom infraction (or not)
	 */
	public function canGiveCustomInfraction()
	{
		// To give an arbitrary infraction, you must also have permission
		// to give infractions in general
		return (
			// has the 'cangiveinfraction' permission
			vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
			// has the 'cangivearbinfraction' permission
			AND vB::getUserContext()->hasPermission('genericpermissions', 'cangivearbinfraction')
		);
	}

	/**
	 * Determines if the logged-in user can view admin notes
	 *
	 * @return bool The current user can view admin notes (or not)
	 */
	public function canViewAdminNote()
	{
		// To view the admin note, you must have permission to give or to reverse infractions
		// (not merely permission to view the infraction)
		return (
			// has the 'cangiveinfraction' permission
			vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
			// has the 'canreverseinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
		);
	}

	/**
	 * Builds user infractions
	 *
	 * @param array
	 * @param array
	 * @param array
	 */
	public function buildUserInfractions($points, $infractions, $warnings)
	{
		$this->checkHasAdminPermission('canadminusers');

		$warningsql = array();
		$infractionsql = array();
		$ipointssql = array();
		$querysql = array();
		$userids = array();

		$updates = array();

		foreach($warnings AS $userid => $warning)
		{
			if (!isset($updates[$userid]))
			{
				$updates[$userid] = array('warnings' => 0,
				'infractions' => 0,
				'points' => 0);
			}
			$updates[$userid]['warnings'] += $warning;
		}

		foreach($infractions AS $userid => $infraction)
		{
			if (!isset($updates[$userid]))
			{
				$updates[$userid] = array('warnings' =>array(),
				'infractions' => array(),
				'points' => array());
			}

			$updates[$userid]['infractions'] += $infraction;
		}

		foreach($points AS $userid => $point)
		{
			if (!isset($updates[$userid]))
			{
				$updates[$userid] = array('warnings' =>array(),
				'infractions' => array(),
				'points' => array());
			}

			$updates[$userid]['points'][] = $point;
		}

		foreach ($updates AS $userid => $update)
		{
			if (
				!empty($update['warnings'])
				OR
				!empty($update['infractions'])
				OR
				!empty($update['points'])
			)
			{
				$data = array_merge(
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'userid' => $userid,
					),
					$update
				);

				$this->assertor->assertQuery('userInfractions', $data);
			}
		}
	}

	/**
	 * Adds or updates an infraction group
	 *
	 * @param  int  $pointlevel
	 * @param  int  $usergroupid
	 * @param  int  $orusergroupid
	 * @param  bool $override
	 * @param  int  $infractiongroupid - optional
	 *
	 * @return int  The infraction group ID.
	 */
	public function saveInfractionGroup($pointlevel, $usergroupid, $orusergroupid, $override, $infractiongroupid = false)
	{
		$this->checkHasAdminPermission('canadminusers');

		if (empty($pointlevel))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$conditions = array(
			array(
				'field' => 'usergroupid',
				'value' => $pointlevel,
				'operator' => vB_dB_Query::OPERATOR_EQ,
			)
		);

		if ($usergroupid != -1)
		{
			$conditions[] = array(
				'field' => 'pointlevel',
				'value' => array(-1, $usergroupid),
				'operator' => vB_dB_Query::OPERATOR_EQ,
			);
		}

		if ($infractiongroupid)
		{
			$conditions[] = array(
				'field' => 'infractiongroupid',
				'value' => $infractiongroupid,
				'operator' => vB_dB_Query::OPERATOR_NE,
			);
		}

		if ($this->assertor->getRow('infractiongroup', array(vB_dB_Query::CONDITIONS_KEY => $conditions)))
		{
			throw new vB_Exception_Api('invalid_infraction_usergroup');
		}

		if (empty($vbulletin->GPC['infractiongroupid']))
		{
			$infractiongroupid = $this->assertor->insert('infractiongroup', array('pointlevel' => '0'));
		}

		$this->assertor->update('infractiongroup',
			array(
				'pointlevel' => $pointlevel,
				'usergroupid' => $usergroupid,
				'orusergroupid' => $orusergroupid,
				'override' => intval($override),
			),
			array(
				array(
					'field' => 'infractiongroupid',
					'value' => $infractiongroupid,
					'operator' => vB_dB_Query::OPERATOR_EQ,
				)
			)
		);

		$this->checkInfractionGroupChange(
			$orusergroupid,
			$pointlevel,
			$usergroupid
		);

		return $infractiongroupid;
	}

	/**
	 * Deletes an infraction group
	 *
	 * @param int The infraction group id
	 */
	public function deleteInfractionGroup($infractiongroupid)
	{
		$this->checkHasAdminPermission('canadminusers');

		$infractiongroupid = (int) $infractiongroupid;

		$group = vB::getDbAssertor()->getRow('infractiongroup', array(
			'infractiongroupid' => $infractiongroupid
		));

		if ($group)
		{
			vB::getDbAssertor()->delete('infractiongroup', array(
				'infractiongroupid' => $infractiongroupid
			));

			$this->checkInfractionGroupChange(
				$group['orusergroupid'],
				$group['pointlevel'],
				$group['usergroupid']
			);
		}
	}

	/**
	 * Recalculates the members of an infraction group based on changes to it.
	 * Specifying the (required) override group ID allows removal of users from the group.
	 * Specifying the point level and applicable group allows addition of users to the group.
	 *
	 * @param int Usergroup ID users are placed in
	 * @param int Point level when this infraction group kicks in
	 * @param int User group that this infraction group applies to
	 */
	protected function checkInfractionGroupChange($override_groupid, $point_level = null, $applies_groupid = -1)
	{
		$this->checkHasAdminPermission('canadminusers');

		$params = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'override_groupid' => $override_groupid,
		);

		if ($point_level !== null)
		{
			$params['point_level'] = $point_level;
			if ($applies_groupid != -1)
			{
				$params['applies_groupid'] = $applies_groupid;
			}
		}

		$users = array();
		$userResult = vB::getDbAssertor()->assertQuery('fetchUsersInfractionGroups', $params);

		foreach ($userResult AS $user)
		{
			$users[] = $user['userid'];
		}

		if ($users)
		{
			$this->buildInfractionGroupIds($users);
		}
	}

	/**
	 * Builds infraction groups for users. Also called from the cron script
	 *
	 * @param array User IDs to build
	 */
	public function buildInfractionGroupIds(array $userids)
	{
		$this->checkHasAdminPermission('canadminusers');

		$this->library->buildInfractionGroupIds($userids);
	}

	/**
	 * returns a string (if int is passed) or array of strings with nodeids as keys (when an array is passed) with quoted strings in bbcode format.
	 * return empty string for the nodes that the current user has no permission viewing
	 *
	 * @param  mixed  int or array of ints
	 *
	 * @return string or array of strings with nodeids as keys
	 */

	public function getQuotes($nodeids)
	{
		if (is_array($nodeids))
		{
			$quotes = array();
			foreach ($nodeids AS $nodeid)
			{
				if ($this->canViewNodeInfraction($nodeid))
				{
					$quotes[$nodeid] = $this->library->getQuotes($nodeid);
				}
				else
				{
					$quotes[$nodeid] = '';
				}
			}
		}
		elseif (is_numeric($nodeids))
		{
			$nodeids = intval($nodeids);
			$quotes = '';
			if ($this->canViewNodeInfraction($nodeids))
			{
				$quotes = $this->library->getQuotes($nodeids);
			}
		}
		else
		{
			$quotes = '';
		}
		return $quotes;
	}


	/**
	 * Returns the Infraction channel ID
	 *
	 * @return int Infraction channel ID
	 */
	public function getChannelId()
	{
		return vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::INFRACTION_CHANNEL);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
