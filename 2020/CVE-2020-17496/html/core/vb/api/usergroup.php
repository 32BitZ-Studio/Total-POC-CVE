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
 * vB_Api_UserGroup
 *
 * @package vBApi
 * @access public
 */
class vB_Api_UserGroup extends vB_Api
{
	const UNREGISTERED_SYSGROUPID = 1;
	const REGISTERED_SYSGROUPID = 2;
	const AWAITINGEMAIL_SYSGROUPID = 3;
	const AWAITINGMODERATION_SYSGROUPID = 4;
	const ADMINISTRATOR = 6;
	const SUPER_MODERATOR = 5;
	const MODERATOR = 7;	// Taken from mysql-schema file that defines 7 as moderators group's systemgroupid
	const BANNED = 8;

	// these are used for blogs
	const CHANNEL_OWNER_SYSGROUPID = 9;
	const CHANNEL_MODERATOR_SYSGROUPID = 10;
	const CHANNEL_MEMBER_SYSGROUPID = 11;

	// @TODO we already removed usages of this in the system but still some references in upgrader.
	// Need to figure it out what to do on those upgrade steps (a28 a29).
	const SG_OWNER_SYSGROUPID = 12;
	const SG_MODERATOR_SYSGROUPID = 13;
	const SG_MEMBER_SYSGROUPID = 14;

	//For articles
	const CMS_AUTHOR_SYSGROUPID = 15;
	const CMS_EDITOR_SYSGROUPID = 16;

	protected $usergroupcache = array();
	protected $privateGroups= array();
	protected function __construct()
	{
		parent::__construct();
		$this->usergroupcache = vB::getDatastore()->getValue('usergroupcache');
		if (!is_array($this->usergroupcache))
		{
			$this->usergroupcache = array();
		}
		$this->privateGroups = array(self::CHANNEL_OWNER_SYSGROUPID, self::CHANNEL_MODERATOR_SYSGROUPID, self::CHANNEL_MEMBER_SYSGROUPID);
	}

	/**
	 * Returns a list of all user groups.
	 *
	 * Returns extra fields if the user has canadminpermissions
	 *
	 * @return	array -- array of groups each with the fields:
	 *	* canoverride
	 *	* closetag
	 *	* description
	 *	* ispublicgroup
	 *	* opentag
	 *	* systemgroupid
	 *	* title
	 *	* usergroupid
	 *	* usertitle
	 *
	 * 	(Admin only)
	 *	* adminpermissions
	 *	* albummaxpics
	 *	* albummaxsize
	 *	* albumpermissions
	 *	* albumpicmaxheight
	 *	* albumpicmaxwidth
	 *	* attachlimit
	 *	* avatarmaxheight
	 *	* avatarmaxsize
	 *	* avatarmaxwidth
	 *	* calendarpermissions
	 *	* createpermissions
	 *	* forumpermissions
	 *	* forumpermissions2
	 *	* genericoptions
	 *	* genericpermissions
	 *	* genericpermissions2
	 *	* groupiconmaxsize
	 *	* maximumsocialgroups
	 *	* passwordhistory
	 *	* passwordexpires
	 *	* pmpermissions
	 *	* pmquota
	 *	* pmsendmax
	 *	* pmthrottlequantity
	 *	* sigmaxchars
	 *	* sigmaximages
	 *	* sigmaxlines
	 *	* sigmaxrawchars
	 *	* sigmaxsizebbcode
	 *	* signaturepermissions
	 *	* sigpicmaxheight
	 *	* sigpicmaxsize
	 *	* sigpicmaxwidth
	 *	* socialgrouppermissions
	 *	* usercsspermissions
	 *	* visitormessagepermissions
	 *	* wolpermissions
	 */
	public function fetchUsergroupList($flushcache = false)
	{
		//this should really call the library function of the same name
		//(which returns all group fields) but right now its heavily tied
		//into the rest of the class (some places use this function to
		//clear $this->usergroupcache generically so that the functions
		//they do use will respond correctly).
		//
		//it's not clear that keeping a local copy of the datastore
		//value really improves anything, but until we clean that up
		//we should keep this separate.
		if ($flushcache)
		{
			$this->usergroupcache = vB::getDatastore()->getValue('usergroupcache');
		}

		$nameList = array();
		foreach ($this->usergroupcache AS $key => $group)
		{
			$nameList[$group['title']] = $this->sanitizeUserGroup($group);
		}
		uksort($nameList, 'strcasecmp');

		return array_values($nameList);
	}

	/**
	 * Fetch the special groups. Used by permissions check. Each is a systemgroupid in the usergroups table
	 *
	 * 	@return	array -- usergroup ids
	 *
	 */
	public function fetchPrivateGroups()
	{
		return $this->privateGroups;
	}

	/**
	 * Fetch usergroup information by its ID
	 *
	 * Returns extra fields if the user has canadminpermissions
	 *
	 * @param int $usergroupid Usergroup ID
	 * @return array Usergroup information -- returns usergroup array
	 * @see fetchUsergroupList for fields
	 */
	public function fetchUsergroupByID($usergroupid)
	{
		if (isset($this->usergroupcache[$usergroupid]))
		{
			return $this->sanitizeUserGroup($this->usergroupcache[$usergroupid]);
		}
		else
		{
			throw new vb_Exception_Api('invalidid', array('usergroupid'));
		}
	}

	private function sanitizeUserGroup($groupinfo)
	{

		if(!$this->hasAdminPermission('canadminusers'))
		{
			$userFields = array(
				'canoverride' => 1,
				'closetag' => 1,
				'description' => 1,
				'ispublicgroup' => 1,
				'opentag' => 1,
				'systemgroupid' => 1,
				'title' => 1,
				'usergroupid' => 1,
				'usertitle' => 1,
			);
			return array_intersect_key($groupinfo, $userFields);
		}
		else
		{
			//includes user fields
			$adminFields = array(
				'canoverride' => 1,
				'closetag' => 1,
				'description' => 1,
				'ispublicgroup' => 1,
				'opentag' => 1,
				'systemgroupid' => 1,
				'title' => 1,
				'usergroupid' => 1,
				'usertitle' => 1,
				'adminpermissions' => 1,
	 			'albummaxpics' => 1,
	 			'albummaxsize' => 1,
				'albumpermissions' => 1,
	 			'albumpicmaxheight' => 1,
	 			'albumpicmaxwidth' => 1,
	 			'attachlimit' => 1,
	 			'avatarmaxheight' => 1,
	 			'avatarmaxsize' => 1,
	 			'avatarmaxwidth' => 1,
				'calendarpermissions' => 1,
				'forumpermissions' => 1,
				'forumpermissions2' => 1,
				'genericoptions' => 1,
				'genericpermissions' => 1,
				'genericpermissions2' => 1,
	 			'groupiconmaxsize' => 1,
	 			'maximumsocialgroups' => 1,
				'passwordhistory' => 1,
				'passwordexpires' => 1,
				'pmpermissions' => 1,
	 			'pmquota' => 1,
	 			'pmsendmax' => 1,
	 			'pmthrottlequantity' => 1,
	 			'sigmaxchars' => 1,
	 			'sigmaximages' => 1,
	 			'sigmaxlines' => 1,
	 			'sigmaxrawchars' => 1,
	 			'sigmaxsizebbcode' => 1,
				'signaturepermissions' => 1,
	 			'sigpicmaxheight' => 1,
	 			'sigpicmaxsize' => 1,
	 			'sigpicmaxwidth' => 1,
				'socialgrouppermissions' => 1,
				'usercsspermissions' => 1,
				'visitormessagepermissions' => 1,
				'wolpermissions' => 1,
			);

			//add custom permission fields from products.  This will duplicate some of the fields
			//above which belong to the "vbulletin" product, but that's not really a problem.
			$ugp = vB::getDatastore()->getValue('bf_ugp');
			foreach($ugp AS $key => $dummy)
			{
				$adminFields[$key] = 1;
			}

			return array_intersect_key($groupinfo, $adminFields);
		}
	}


	/**
	 * Fetch usergroup information by its SystemID
	 *
	 * @param int $systemgroupid
	 * @return array Usergroup information -- returns usergroup array
	 * @see fetchUsergroupList for fields
	 */
	public function fetchUsergroupBySystemID($systemgroupid)
	{
		foreach ($this->usergroupcache AS $usergroup)
		{
			if ($usergroup['systemgroupid'] == $systemgroupid)
			{
				return $this->sanitizeUserGroup($usergroup);
			}
		}

		//if we got here, the request is invalid
		throw new vb_Exception_Api('invalidid', array($systemgroupid));
	}

	/**
	 * Fetch default usergroup data for adding or editing new usergroup
	 *
	 * @param int $usergroupid If present, the data will be copied from this usergroup
	 * @return array Default usergroup data. It contains four sub-arrays:
	 *               'usergroup' - Basic usergroup information
	 *               'ugarr' - usergroups to be used for 'Create Forum Permissions Based off of Usergroup'
	 *               'ug_bitfield' - Usergroup bitfield
	 *               'groupinfo' - Usergroup permission information
	 */
	public function fetchDefaultData($usergroupid = 0)
	{
		$this->checkHasAdminPermission('canadminpermissions');
		$bf_ugp = vB::getDatastore()->getValue('bf_ugp');

		require_once(DIR . '/includes/class_bitfield_builder.php');
		$myobj =& vB_Bitfield_Builder::init();

		if ($usergroupid)
		{
			$usergroup = vB::getDbAssertor()->getRow('usergroup', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_TABLE,
				vB_dB_Query::CONDITIONS_KEY => array(
					'usergroupid' => $usergroupid
				)
			));

			$ug_bitfield = array();
			foreach($bf_ugp AS $permissiongroup => $fields)
			{
				$ug_bitfield["$permissiongroup"] = convert_bits_to_array($usergroup["$permissiongroup"], $fields);
			}
		}
		else
		{
			$ug_bitfield = array(
				'genericoptions' => array('showgroup' => 1, 'showeditedby' => 1, 'isnotbannedgroup' => 1),
				'forumpermissions' => array(
					'canview' => 1,
					'canviewothers' => 1,
					'cangetattachment' => 1,
					'cansearch' => 1,
					'canthreadrate' => 1,
					'canpostattachment' => 1,
					'canpostpoll' => 1,
					'canvote' => 1,
					'canviewthreads' => 1,
				),
				'forumpermissions2' => array('cangetimgattachment' => 1),
				'wolpermissions' => array('canwhosonline' => 1),
				'genericpermissions' => array(
					'canviewmembers' => 1,
					'cannegativerep' => 1,
					'canuserep' => 1,
					'cansearchft_nl' => 1,
				)
			);
			// set default numeric permissions
			$usergroup = array(
				'pmquota' => 0, 'pmsendmax' => 5, 'attachlimit' => 1000000,
				'avatarmaxwidth' => 200, 'avatarmaxheight' => 200, 'avatarmaxsize' => 20000,
				'sigmaxsizebbcode' => 7
			);
		}

		$permgroups = vB::getDbAssertor()->assertQuery('usergroup_fetchperms', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED));

		$ugarr = array();
		foreach ($permgroups as $group)
		{
			$ugarr["$group[usergroupid]"] = $group['title'];
		}

		foreach ((array)$myobj->data['ugp'] AS $grouptitle => $perms)
		{
			if ($grouptitle == 'createpermissions')
			{
				continue;
			}
			foreach ($perms AS $permtitle => $permvalue)
			{
				if (empty($permvalue['group']))
				{
					continue;
				}
				$groupinfo["$permvalue[group]"]["$permtitle"] = array(
					'phrase' => $permvalue['phrase'],
					'value' => $permvalue['value'],
					'parentgroup' => $grouptitle,
				);
				if ($permvalue['intperm'])
				{
					$groupinfo["$permvalue[group]"]["$permtitle"]['intperm'] = true;
				}
				if (!empty($myobj->data['layout']["$permvalue[group]"]['ignoregroups']))
				{
					$groupinfo["$permvalue[group]"]['ignoregroups'] = $myobj->data['layout']["$permvalue[group]"]['ignoregroups'];
				}
				if (!empty($permvalue['ignoregroups']))
				{
					$groupinfo["$permvalue[group]"]["$permtitle"]['ignoregroups'] = $permvalue['ignoregroups'];
				}
				if (!empty($permvalue['options']))
				{
					$groupinfo["$permvalue[group]"]["$permtitle"]['options'] = $permvalue['options'];
				}
			}
		}

		return array(
			'usergroup' => $usergroup,
			'ug_bitfield' => $ug_bitfield,
			'ugarr' => $ugarr,
			'groupinfo' => $groupinfo,
		);
	}

	/**
	 * Insert a new usergroup or update an existing usergroup
	 *
	 * @param array $usergroup Usergroup information to be inserted or updated
	 * @param int $ugid_base Usergroup ID. New inserted usergroup's forum permission will based on this usergroup.
	 * @param int $usergroupid when updating an existing usergroup, pass usergroup ID as this parameter
	 * @return int New or existing usergroup ID
	 */
	public function save($usergroup, $ugid_base = 0, $usergroupid = 0)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		$db = vB::getDbAssertor();
		$datastore = vB::getDatastore();

		$bf_ugp = $datastore->getValue('bf_ugp');
		$bf_ugp_adminpermissions = $datastore->getValue('bf_ugp_adminpermissions');
		$bf_ugp_genericpermissions = $datastore->getValue('bf_ugp_genericpermissions');
		$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');
		$bf_misc_useroptions = $datastore->getValue('bf_misc_useroptions');
		$usergroupcache = $datastore->getValue('usergroupcache');
		$bf_misc_prefixoptions = $datastore->getValue('bf_misc_prefixoptions');

		// create bitfield values
		require_once(DIR . '/includes/functions_misc.php');
		foreach($bf_ugp AS $permissiongroup => $fields)
		{
			if ($permissiongroup == 'createpermissions' OR $permissiongroup == 'forumpermissions2')
			{
				continue;
			}
			$usergroup["$permissiongroup"] = convert_array_to_bits($usergroup["$permissiongroup"], $fields, 1);
		}

		if (!empty($usergroupid))
		{
			//if this is an update and we don't have a title passed assume we
			//just want to keep what we have.
			if (isset($usergroup['title']) AND trim($usergroup['title']) == '')
			{
				throw new vB_Exception_Api('usergroup_title_required');
			}

			// update
			if (!($usergroup['adminpermissions'] & $bf_ugp_adminpermissions['cancontrolpanel']))
			{
				// check that not removing last admin group
				$checkadmin = $db->getField('usergroup_checkadmin', array(
					'cancontrolpanel' => $bf_ugp_adminpermissions['cancontrolpanel'],
					'usergroupid' => $usergroupid,
				));

				if ($usergroupid == 6)
				{
					// stop them turning no control panel for usergroup 6, seems the most sensible thing
					throw new vB_Exception_Api('invalid_usergroup_specified');
				}
				if (!$checkadmin)
				{
					throw new vB_Exception_Api('cant_delete_last_admin_group');
				}
			}

			$data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array('usergroupid' => $usergroupid)
			);
			$data = array_merge($data, $usergroup);
			$db->assertQuery('usergroup', $data);

			if (!($usergroup['genericpermissions'] & $bf_ugp_genericpermissions['caninvisible']))
			{
				if (!($usergroup['genericoptions'] & $bf_ugp_genericoptions['allowmembergroups']))
				{
					// make the users in this group visible
					$db->assertQuery('usergroup_makeuservisible', array(
						'invisible' => $bf_misc_useroptions['invisible'],
						'usergroupid' => $usergroupid,
					));
				}
				else
				{
					// find all groups allowed to be invisible - don't change people with those as secondary groups
					$db->assertQuery('updateInvisible', array(
						'caninvisible' => $bf_ugp_genericpermissions['caninvisible'],
						'invisible' => $bf_misc_useroptions['invisible'],
						'usergroupid' => $usergroupid,
					));
				}
			}

			if ($usergroup['adminpermissions'] & $bf_ugp_adminpermissions['cancontrolpanel'])
			{
				$ausers = $db->assertQuery('usergroup_fetchausers', array(
					'usergroupid' => $usergroupid,
				));
				foreach ($ausers as $auser)
				{
					$userids[] = $auser['userid'];
				}

				if (!empty($userids))
				{
					foreach ($userids AS $userid)
					{
						$admindm = new vB_DataManager_Admin(ERRTYPE_SILENT);
						$admindm->set('userid', $userid);
						$admindm->save();
						unset($admindm);
					}
				}
			}
			else if ($usergroupcache["{$usergroupid}"]['adminpermissions'] & $bf_ugp_adminpermissions['cancontrolpanel'])
			{
				// lets find admin usergroupids
				$ausergroupids = array();
				$usergroupcache["{$usergroupid}"]['adminpermissions'] = $usergroup['adminpermissions'];
				foreach ($usergroupcache AS $ausergroupid => $ausergroup)
				{
					if ($ausergroup['adminpermissions'] & $bf_ugp_adminpermissions['cancontrolpanel'])
					{
						$ausergroupids[] = $ausergroupid;
					}
				}

				$ausers = $db->assertQuery('fetchAdminusersFromUsergroup', array(
					'ausergroupids' => $ausergroupids,
					'usergroupid' => $usergroupid,
				));

				foreach ($ausers as $auser)
				{
					$userids[] = $auser['userid'];
				}

				if (!empty($userids))
				{
					foreach ($userids AS $userid)
					{
						$info = array('userid' => $userid);

						$admindm = new vB_DataManager_Admin(ERRTYPE_SILENT);
						$admindm->set_existing($info);
						$admindm->delete();
						unset($admindm);
					}
				}
			}

			vB_Cache::instance()->event('perms_changed');
			vB::getUserContext()->clearChannelPermissions($usergroupid);
		}
		else
		{
			//if this is an insert then we really need a title
			if (!isset($usergroup['title']) OR trim($usergroup['title']) == '')
			{
				throw new vB_Exception_Api('usergroup_title_required');
			}

			// insert
			/*insert query*/
			$newugid = $db->insert('usergroup', $usergroup);

			if ($ugid_base <= 0)
			{
				// use usergroup registered as default
				foreach($usergroupcache AS $ausergroup)
				{
					if ($ausergroup['systemgroupid'] == self::REGISTERED_SYSGROUPID)
					{
						$ugid_base = $ausergroup['usergroupid'];
					}
				}
			}

			if ($ugid_base > 0)
			{
				$fperms = $db->assertQuery('vBForum:forumpermission', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'usergroupid' => $ugid_base,
				));
				foreach ($fperms as $fperm)
				{
					unset($fperm['forumpermissionid']);
					$fperm['usergroupid'] = $newugid;
					/*insert query*/
					$data = array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					);
					$data += $fperm;
					$db->assertQuery('vBForum:forumpermission', $data);
				}

				$cperms = $db->assertQuery('vBForum:calendarpermission', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'usergroupid' => $ugid_base,
				));
				foreach ($cperms as $cperm)
				{
					unset($cperm['calendarpermissionid']);
					$cperm['usergroupid'] = $newugid;
					/*insert query*/
					$data = array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					);
					$data += $cperm;
					$db->assertQuery('vBForum:calendarpermission', $data);
				}

				$perms = $db->assertQuery('vBForum:permission', array('groupid' => $ugid_base));
				foreach ($perms as $perm)
				{
					unset($perm['permissionid']);
					$perm['groupid'] = $newugid;
					$db->insert('vBForum:permission', $perm);
				}

				vB::getUserContext()->clearChannelPermissions();
			}

			$db->assertQuery('usergroup_insertprefixpermission', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				'newugid' => $newugid,
				'deny_by_default' => $bf_misc_prefixoptions['deny_by_default'],
			));

			$db->assertQuery('usergroup_inserteventhighlightpermission', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				'newugid' => $newugid,
			));
		}

		$markups = $db->getRows('usergroup_fetchmarkups', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
		));
		$usergroupmarkup = array();
		foreach ($markups as $markup)
		{
			$usergroupmarkup["{$markup['usergroupid']}"]['opentag'] = $markup['opentag'];
			$usergroupmarkup["{$markup['usergroupid']}"]['closetag'] = $markup['closetag'];
		}

		vB_Library::instance('usergroup')->buildDatastore();
		vB::getUserContext()->rebuildGroupAccess();

		require_once(DIR . '/includes/functions_databuild.php');
		build_birthdays();

		/*
			We need to update the in-memory values that have just been modified since they were created in the constructor.
			While there's probably no bugs that out-of-date class vars yet in normal usage, there are definitely
			unit test bugs, as a bunch of usergroup changes can happen in the same session w/o class reconstruction.

			Incidentally, fetchusergroupList(true) resets the 2 vars I'm aware of atm, but this below might need to change
			to independently reset all values...
		 */
		$this->fetchUsergroupList(true);

		// could be changing sig perms -- this is unscientific, but empty the sig cache
		$db->assertQuery('truncateTable', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD, 'table' => 'sigparsed'));

		if ($newugid)
		{
			return $newugid;
		}
		else
		{
			return $usergroupid;
		}

	}

	/**
	 * Delete an usergroup
	 *
	 * @param int $usergroupid Usergroup ID to be deleted
	 * @return array -- standard success array
	 */
	public function delete($usergroupid)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		$db = vB::getDbAssertor();
		// update users who are in this usergroup to be in the registered usergroup
		$db->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'usergroupid' => 2,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'displaygroupid' => 0,
			vB_dB_Query::CONDITIONS_KEY => array(
				'displaygroupid' => $usergroupid
			),
		));
		$db->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'infractiongroupid' => 0,
			vB_dB_Query::CONDITIONS_KEY => array(
				'infractiongroupid' => $usergroupid
			),
		));
		$db->assertQuery('useractivation', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'usergroupid' => 2,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:subscription', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'nusergroupid' => -1,
			vB_dB_Query::CONDITIONS_KEY => array(
				'nusergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:subscriptionlog', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'pusergroupid' => -1,
			vB_dB_Query::CONDITIONS_KEY => array(
				'pusergroupid' => $usergroupid
			),
		));

		// now get on with deleting stuff...
		$db->assertQuery('usergroup', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:forumpermission', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:permission', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array(
						'groupid' => $usergroupid
				),
		));

		vB_Library::instance('userrank')->deleteForUsergroup($usergroupid);

		$db->assertQuery('vBForum:usergrouprequest', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('userpromotion', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('deleteUserPromotion', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'usergroupid' => $usergroupid
		));
		$db->assertQuery('vBForum:imagecategorypermission', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:attachmentpermission', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:prefixpermission', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('vBForum:eventhighlightpermission', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));

		$db->assertQuery('vBforum:usergroupleader', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));

		$db->assertQuery('infractiongroup', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('infractiongroup', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'orusergroupid' => $usergroupid
			),
		));

		$db->assertQuery('infractionban', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupid' => $usergroupid
			),
		));
		$db->assertQuery('infractionban', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'banusergroupid' => $usergroupid
			),
		));

		vB_Library::instance('usergroup')->buildDatastore();

		require_once(DIR . '/includes/adminfunctions.php');
		build_attachment_permissions();

		// remove this group from users who have this group as a membergroup
		$updateusers = array();
		$casesql = '';

		$users = $db->getRows('usergroup_fetchmemberstoremove', array(
			'usergroupid' => $usergroupid,
		));
		if (count($users))
		{
			$db->assertQuery('updateMemberForDeletedUsergroup', array(
				'users' => $users,
				'usergroupid' => $usergroupid,
			));
		}

		vB::getUserContext()->rebuildGroupAccess();
		return array('success' => true);
	}

	/**
	 * Remove usergroup leader from an usergroup
	 *
	 * @param  $usergroupleaderid Leader's user ID to be removed
	 * @return array -- standard success array
	 */
	public function removeLeader($usergroupleaderid)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		vB::getDbAssertor()->assertQuery('vBForum:usergroupleader', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'usergroupleaderid' => $usergroupleaderid
			),
		));
 		return array('success' => true);
	}

	/**
	 * Add a leader for an usergroup
	 *
	 * @param int $usergroupid
	 * @param int $userid
	 * @return int New usergroupleader ID
	 */
	public function addLeader($usergroupid, $userid)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		require_once(DIR . '/includes/adminfunctions.php');

		$usergroupid = intval($usergroupid);
		$userid = intval($userid);
		if (
			$usergroup = vB::getDbAssertor()->getRow('usergroup', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'usergroupid', 'value' => $usergroupid, 'operator' => 'EQ'),
					array('field' => 'ispublicgroup', 'value' => 1, 'operator' => 'EQ'),
					array('field' => 'usergroupid', 'value' => 7, 'operator' => 'GT'),
				)
			))
		)
		{
			if (
				$user = vB::getDbAssertor()->getRow('user', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'userid' => $userid,
				))
			)
			{
				if (is_unalterable_user($user['userid']))
				{
					throw new vB_Exception_Api('user_is_protected_from_alteration_by_undeletableusers_var');
				}

				if (
					$preexists = vB::getDbAssertor()->getRow('user', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'usergroupid', 'value' => $usergroupid, 'operator' => vB_dB_Query::OPERATOR_EQ),
							array('field' => 'userid', 'value' => $user['userid'], 'operator' => vB_dB_Query::OPERATOR_EQ)
						)
					))
				)
				{
					throw new vB_Exception_Api('invalid_usergroup_leader_specified');
				}

				// update leader's member groups if necessary
				if (strpos(",$user[membergroupids],", "," . $usergroupid . ",") === false AND $user['usergroupid'] != $usergroupid)
				{
					if (empty($user['membergroupids']))
					{
						$membergroups = $usergroupid;
					}
					else
					{
						$membergroups = "$user[membergroupids]," . $usergroupid;
					}

					$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
					$userdm->set_existing($user);
					$userdm->set('membergroupids', $membergroups);
					$userdm->save();
					unset($userdm);
				}

				// insert into usergroupleader table
				/*insert query*/
				return vB::getDbAssertor()->assertQuery('vBForum:usergroupleader', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'userid' => $user['userid'],
					'usergroupid' => $usergroupid,
				));

			}
			else
			{
				throw new vB_Exception_Api('invalid_user_specified');
			}
		}
		else
		{
			throw new vB_Exception_Api('cant_add_usergroup_leader');
		}

	}

	/**
	 * Fetch a list of usergroup promotions
	 *
	 * @param int $usergroupid Fetch promotions for only this usergroup
	 * @return array Promotions information
	 */
	public function fetchPromotions($usergroupid = 0)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		$promotions = array();
		$getpromos = vB::getDbAssertor()->assertQuery('fetchPromotions', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'usergroupid' => intval($usergroupid)
		));
		foreach ($getpromos as $promotion)
		{
			$promotions["$promotion[usergroupid]"][] = $promotion;
		}

		return $promotions;

	}

	/**
	 * Insert a new usergroup promotion or update an existing one
	 *
	 * @param array $promotion Promotion information with fields:
	 *  * usergroupid
	 *  * reputation
	 *  * date
	 *  * posts
	 * 	* strategy
	 * 	* type
	 * 	* reputationtype
	 * 	* joinusergroupid
	 * @param int $usergroupid
	 * @param int $userpromotionid Existing Usergroup promotion ID to be updated
	 * @return int new or existing userpromotion ID
	 */
	public function savePromotion($promotion, $usergroupid, $userpromotionid = 0)
	{
		$cleaner = vB::getCleaner();
		$promotion = $cleaner->clean($promotion, vB_Cleaner::TYPE_ARRAY);
		$usergroupid = $cleaner->clean($usergroupid, vB_Cleaner::TYPE_INT);
		$userpromotionid = $cleaner->clean($userpromotionid, vB_Cleaner::TYPE_INT);

		$this->checkHasAdminPermission('canadminpermissions');

		$usergroupid = intval($usergroupid);
		$userpromotionid = intval($userpromotionid);

		if (!isset($promotion['joinusergroupid']) OR $promotion['joinusergroupid'] == -1)
		{
			throw new vB_Exception_Api('invalid_usergroup_specified');
		}

		if (!empty($promotion['reputationtype']) AND $promotion['strategy'] <= 16)
		{
			$promotion['strategy'] += 8;
		}
		unset($promotion['reputationtype']);

		// update
		if (!empty($userpromotionid))
		{
			if ($usergroupid == $promotion['joinusergroupid'])
			{
				throw new vB_Exception_Api('promotion_join_same_group');
			}
			$data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array(
					'userpromotionid' => $userpromotionid,
				)
			);
			$data += $promotion;
			vB::getDbAssertor()->assertQuery('userpromotion', $data);

			return $userpromotionid;
		}
		// insert
		else
		{
			$usergroupid = $promotion['usergroupid'];
			if ($usergroupid == $promotion['joinusergroupid'])
			{
				throw new vB_Exception_Api('promotion_join_same_group');
			}
			/*insert query*/
			$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT);
			$data += $promotion;
			$promotion_id = vB::getDbAssertor()->assertQuery('userpromotion', $data);
			return $promotion_id;
		}
	}

	/**
	 * Delete an usergroup promotion
	 *
	 * @param  $userpromotionid
	 * @return void
	 */
	public function deletePromotion($userpromotionid)
	{
		$this->checkHasAdminPermission('canadminpermissions');

		vB::getDbAssertor()->assertQuery('userpromotion', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				'userpromotionid' => intval($userpromotionid)
			),
		));
	}

	/**
	 * Fetch a list of usergroup join requests
	 * @param int $usergroupid Usergroup ID. If 0, this method will return a list of usergroups
	 *                         which have join requests.
	 *
	 * @return array If $usergroupid is 0, it will return a list of usergroups which have join requests.
	 *               If $usergroupid is not 0, it will return an array of join requests.
	 *               If the return is an empty array, it means no join requests for all usergroups (usergroupid = 0)
	 *                  or for the specified usergroup ($usergroupid != 0)
	 */
	public function fetchJoinRequests($usergroupid = 0)
	{
		if (!$usergroupid)
		{
			$this->checkHasAdminPermission('canadminpermissions');
		}

		// first query groups that have join requests
		$getusergroups = vB::getDbAssertor()->getRows('usergroup_fetchwithjoinrequests', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED));
		if (count($getusergroups) == 0)
		{
			// there are no join requests
			return array();
		}

		$usergroupcache = vB::getDatastore()->getValue('usergroupcache');

		// if we got this far we know that we have at least one group with some requests in it
		$usergroups = array();
		$badgroups = array();

		foreach ($getusergroups as $getusergroup)
		{
			$ugid =& $getusergroup['usergroupid'];

			if (isset($usergroupcache["$ugid"]))
			{
				$usergroupcache["$ugid"]['joinrequests'] = $getusergroup['requests'];
				if ($usergroupcache["$ugid"]['ispublicgroup'])
				{
					$goodgroups["$ugid"]['title'] = $usergroupcache["$ugid"]['title'];
					$goodgroups["$ugid"]['joinrequests'] = $usergroupcache["$ugid"]['joinrequests'];
				}
			}
			else
			{
				$badgroups[] = $getusergroup['usergroupid'];
			}
		}
		unset($getusergroup);

		// if there are any invalid requests, zap them now
		if (!empty($badgroups))
		{
			$badgroups = implode(', ', $badgroups);
			vB::getDbAssertor()->assertQuery('vBForum:usergrouprequest', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array(
					'usergroupid' => $badgroups
				),
			));
		}

		// now if we are being asked to display a particular usergroup, do so.
		if ($usergroupid)
		{
			// check this is a valid usergroup
			if (!is_array($usergroupcache["{$usergroupid}"]))
			{
				throw new vB_Exception_Api('invalid_usergroup_specified');
			}

			// check that this usergroup has some join requests
			if ($usergroupcache["{$usergroupid}"]['joinrequests'])
			{

				// everything seems okay, so make a total record for this usergroup
				$usergroup =& $usergroupcache["{$usergroupid}"];

				// query the requests for this usergroup
				$requests = vB::getDbAssertor()->getRows('usergroup_fetchjoinrequests', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'usergroupid' => $usergroupid,
				));

				return (array)$requests;
			}
			else
			{
				return array();
			}

		}
		else
		{
			return $goodgroups;
		}
	}

	/**
	 * Update user's display group
	 *
	 * @param  $userid User ID
	 * @param  $usergroupid Usergroup ID to be used as display group
	 * @return array -- standard success array
	 */
	public function updateDisplayGroup($userid, $usergroupid)
	{
		//this whole function should probably be in the user API.  It's currently unused
		//so it's not entirely clear what permissions it should have.  The admin
		//canadminusers is sufficient, but we may also want to open this up to allow
		//users to change their own display group -- but that may have its own permissions
		//associated with it.  For now, lock it down.
		$this->checkHasAdminPermission('canadminusers');

		$userinfo = vB_Api::instanceInternal('user')->fetchUserinfo($userid);

		$membergroups = fetch_membergroupids_array($userinfo);
		$permissions = $userinfo['permissions'];
		$bf_ugp_genericpermissions = vB::getDatastore()->getValue('bf_ugp_genericpermissions');

		if ($usergroupid == 0)
		{
			throw new vB_Exception_Api('invalidid', array('usergroupid'));
		}

		if (!in_array($usergroupid, $membergroups))
		{
			throw new vB_Exception_Api('notmemberofdisplaygroup');
		}
		else
		{
			$display_usergroup = $this->usergroupcache["{$usergroupid}"];

			//I'm  not sure why we require canoverride to set the display group... this is *not* required
			//by the the admincp user interface which uses a different method of saving.
			if ($usergroupid == $userinfo['usergroupid'] OR $display_usergroup['canoverride'])
			{
				$userinfo['displaygroupid'] = $usergroupid;

				// init user data manager
				$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
				$userdata->set_existing($userinfo);

				$userdata->set('displaygroupid', $usergroupid);

				if (!$userinfo['customtitle'])
				{
					$userdata->set_usertitle(
						$userinfo['customtitle'] ? $userinfo['usertitle'] : '',
						false,
						$display_usergroup,
						($permissions['genericpermissions'] & $bf_ugp_genericpermissions['canusecustomtitle']) ? true : false,
						($permissions['genericpermissions'] & $bf_ugp_genericpermissions['cancontrolpanel']) ? true : false
					);
				}

				$userdata->save();
			}
			else
			{
				throw new vB_Exception_Api('usergroup_invaliddisplaygroup');
			}
		}

		return array('success' => true);
	}

	/**
	 * Fetch a list of banned usergroups
	 */
	public function fetchBannedUsergroups()
	{
		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		$usercontext = &vB::getUserContext($loginuser['userid']);

		if (!$usercontext->hasAdminPermission('cancontrolpanel') AND !$usercontext->getChannelPermission('moderatorpermissions', 'canbanusers', 1))
		{
			$forumHome = vB_Library::instance('content_channel')->getForumHomeChannel();

			$args = array($loginuser['username']);
			$args[] = vB_Template_Runtime::fetchStyleVar('right');
			$args[] = $loginuser['securitytoken'];
			$args[] = vB5_Route::buildUrl($forumHome['routeid'] . '|fullurl');

			throw new vB_Exception_Api('nopermission_loggedin', $args);
		}

		$bf_ugp_genericoptions = vB::getDatastore()->getValue('bf_ugp_genericoptions');

		$bannedusergroups = array();
		foreach ($this->usergroupcache AS $usergroup)
		{
			if (!($usergroup['genericoptions'] & $bf_ugp_genericoptions['isnotbannedgroup']))
			{
				$bannedusergroups[$usergroup['usergroupid']] = $usergroup;
			}
		}

		return $bannedusergroups;
	}

	/**
	 * Returns the usergroupid for moderator group
	 *
	 * @return false|int
	 */
	public function getModeratorGroupId()
	{
		try
		{
			$group = $this->fetchUsergroupBySystemID(self::CHANNEL_MODERATOR_SYSGROUPID);
			return $group['usergroupid'];
		}
		catch(vB_Exception_Api $e)
		{
			return false;
		}
	}

	/**
	 * Returns the usergroupid for owner group
	 *
	 * @return false|int
	 */
	public function getOwnerGroupId()
	{
		try
		{
			$group = $this->fetchUsergroupBySystemID(self::CHANNEL_OWNER_SYSGROUPID);
			return $group['usergroupid'];
		}
		catch(vB_Exception_Api $e)
		{
			return false;
		}
	}

	/**
	 * Returns the usergroupid for member group
	 *
	 * @return false|int
	 */
	public function getMemberGroupId()
	{
		try
		{
			$group = $this->fetchUsergroupBySystemID(self::CHANNEL_MEMBER_SYSGROUPID);
			return $group['usergroupid'];
		}
		catch(vB_Exception_Api $e)
		{
			return false;
		}
	}

	/**
	 * Returns the usergroupids for multiple specified SYSGROUPID constants
	 *
	 * @param array $groups -- int, the systemIDs to look up the db ids from
	 * @return array -- usergroup ids -- NOTE: The usergroups in the return
	 *                  array are in the same order as in the input array.
	 *                  Some callers depend on this behavior.
	 */
	public function getMultipleGroupIds($groups)
	{
		if (empty($groups))
		{
			return array();
		}

		$invertGroups = array_fill_keys($groups, false);
		foreach ($this->usergroupcache AS $usergroup)
		{
			if(isset($invertGroups[$usergroup['systemgroupid']]))
			{
				$invertGroups[$usergroup['systemgroupid']] = $usergroup['usergroupid'];
			}
		}

		return array_values(array_filter($invertGroups));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
