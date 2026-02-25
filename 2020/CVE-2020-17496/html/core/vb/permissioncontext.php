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

class vB_PermissionContext
{
	use vB_Trait_NoSerialize;

	protected $primary_group_id;
	protected $secondary_group_ids;
	protected $infraction_group_ids;
	/**
	 *
	 * @var vB_Datastore
	 */
	protected $datastore;
	protected $group_ids = null;
	protected $permissions = null;
	protected $forumPerms = false;

	/**Once we've checked permissions let's retain that data. **/
	protected $perms = array();
	protected $attachmentPermissions = array();

	public function __construct($datastore, $primary_group_id, $secondary_group_ids = array(), $infraction_group_ids = array())
	{
		$this->datastore = $datastore;

		// If $primary_group_id is 0, we assume that it's guest usergroup
		if (!$primary_group_id)
		{
			$primary_group_id = 1;
		}
		$this->primary_group_id = $primary_group_id;
		$this->secondary_group_ids = $secondary_group_ids;
		$this->infraction_group_ids = $infraction_group_ids;

		$this->group_ids = $this->getUserGroups();
		$this->buildBasicPermissions();
	}

	public function getPermission($group)
	{
		return $this->permissions[$group];
	}

	/**
	 * This returns an array with the access for each usergroup passed.
	 *
	 *	@param array|integer $usergroups -- usergroup ids
	 *
	 * 	@return	array on element for each usergroup with the following arrays (each is the
	 * 		array of nodeids the user has the appropriate permissons for)
	 * 			canview
	 * 			canalwaysview
	 *			canaccess
	 *			selfonly
	 *			starteronly
	 *			canseedelnotice
	 *			canpublish
	 */
	public function getAllChannelAccess($usergroups)
	{
		if (!is_array($usergroups))
		{
			$usergroups = array($usergroups);
		}
		$result = array();
		$can = array();
		$cannot = array();
		$canview = array();

		$keys = array();
		foreach($usergroups AS $usergroup)
		{
			$keys[] = 'vBUgChannelAccessG' . $usergroup;
		}
		$this->datastore->preload($keys);

		foreach($usergroups AS $usergroup)
		{
			$access = $this->datastore->getValue('vBUgChannelAccessG' . $usergroup);
			if (!$access)
			{
				$access =  array(
					'canview'       =>		array(),
					'canalwaysview'	=>		array(),
					'canaccess'     =>		array(),
					'selfonly'      =>		array(),
					'starteronly'   =>		array(),
					'canseedelnotice' => 	array(),
					'canpublish' 	=>		array(),
				);
			}
			$result[$usergroup] = $access;
		}
		return $result;
	}

	/**
	 * This rebuilds the array of channel access by group
	 *
	 * This also sets the datastore keys vBUgChannelPermissionsFrom and vBUgChannelAccess
	 *
	 *  sets datastore values for each group, each datatore entity is an array of channel ids where a user
	 *  in that group has that access
	 * 	-- canview
	 * 	-- canaccess
	 * 	-- selfonly
	 * 	-- starteronly
	 *	-- canseedelnotice
	 *	-- canpublish
	 *	-- canmoderate
	 */
	public function rebuildGroupAccess()
	{
		$bf_ugp = $this->datastore->getValue('bf_ugp_forumpermissions');
		$bf_ugp_f2 = $this->datastore->getValue('bf_ugp_forumpermissions2');
		$bf_mod = $this->datastore->getValue('bf_misc_moderatorpermissions');
		$bf_forum = $this->datastore->getValue('bf_misc_forumoptions');

		//First we need all the channels.
		$channelQry = vB::getDbAssertor()->assertQuery('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'contenttypeid' => vB_Types::instance()->getContentTypeID('vBForum_Channel')
		));
		$channels = array();
		$channelPerms = array();
		foreach ($channelQry AS $channel)
		{
			$channels[$channel['nodeid']] = array('parentid' => $channel['parentid']);
		}

		//Let's build a permissionsfrom array of $usergroup => array($nodeid => $node the permissions are from)
		$permFrom = array();
		$usergroupcache = $this->datastore->getValue('usergroupcache');

		$groupsSeen = array();
		if (is_array($usergroupcache))
		{
			foreach (array_keys($usergroupcache) AS $groupid)
			{
				$permFrom[$groupid] = $channels;

				$groupsSeen[$groupid] = true;
				$channelPerms[$groupid] = array();
			}
		}

		$permQry = vB::getDbAssertor()->assertQuery('vBForum:permission', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
		foreach ($permQry AS $permissionRec)
		{
			if (array_key_exists($permissionRec['nodeid'], $channels))
			{
				$permFrom[$permissionRec['groupid']][$permissionRec['nodeid']]['fromid'] = $channels[$permissionRec['nodeid']];
				$channelPerms[$permissionRec['groupid']][$permissionRec['nodeid']] = array(
					'moderatorpermissions' => $permissionRec['moderatorpermissions'],
					'forumpermissions' => $permissionRec['forumpermissions'],
					'forumpermissions2' => $permissionRec['forumpermissions2'],
				);
			}
		}

		foreach ($permFrom AS $groupid => $from)
		{
			unset($groupsSeen[$groupid]);
			$access = array(
				'canview'       =>		array(),
				'canalwaysview'	=>		array(),
				'canaccess'     =>		array(),
				'selfonly'      =>		array(),
				'starteronly'   =>		array(),
				'canseedelnotice' => 	array(),
				'canpublish' 	=>      array(),
				'canmoderate' =>      array(),
			);

			//the reference here is important, we're doing this for speed so
			//we can avoid repeatedly looking up the $group subarray inside the
			//second loop.
			$permFromGroup = &$permFrom[$groupid];
			$channelPermsGroup = &$channelPerms[$groupid];

			foreach ($from AS $nodeid => $perms)
			{
				if (isset($channelPermsGroup[$nodeid]))
				{
					$fromId = $nodeid;
				}
				else
				{
					//We look up the tree above. We should never get to node 1 without finding permissions, but if so this
					//usergroup has no access
					$fromId = 0;
					$parentid = $perms['parentid'];
					while ($parentid > 0)
					{
						if (isset($channelPermsGroup[$parentid]))
						{
							$fromId = $parentid;
							break;
						}
						else if (empty($permFromGroup[$parentid]['parentid']))
						{
							break;
						}
						else
						{
							$parentid = $permFromGroup[$parentid]['parentid'];
						}
					}
				}

				if (!empty($fromId))
				{
					$permFrom[$groupid][$nodeid]['fromid'] = $fromId;
					$fromChannelPerms = &$channelPermsGroup[$fromId];

					if ($groupid > 1 AND ($bf_ugp['canseedelnotice'] & $fromChannelPerms['forumpermissions']) > 0)
					{
						$access['canseedelnotice'][$nodeid] = $nodeid;
					}

					if ($groupid > 1 AND ($bf_ugp_f2['canpublish'] & $fromChannelPerms['forumpermissions2']) > 0)
					{
						$access['canpublish'][$nodeid] = $nodeid;
					}

					//Can we moderate?
					if ($groupid > 1 AND (bool) ($bf_mod['canmoderateposts'] & $fromChannelPerms['moderatorpermissions']))
					{
						$access['canmoderate'][$nodeid] = $nodeid;
					}
					else if ( (bool) ($bf_ugp_f2['canalwaysview'] & $fromChannelPerms['forumpermissions2']) )
					{
						$access['canalwaysview'][$nodeid] = $nodeid;
						$access['canview'][$nodeid] = $nodeid;
					}
					else if ((bool) ($bf_ugp['canview'] & $fromChannelPerms['forumpermissions']))
					{
						if (
							(($bf_ugp['canviewothers'] & $fromChannelPerms['forumpermissions']) > 0) AND
							(($bf_ugp['canviewthreads'] & $fromChannelPerms['forumpermissions']) > 0)
						)
						{
							$access['canview'][$nodeid] = $nodeid;
						}
						else if (($bf_ugp['canviewothers'] & $fromChannelPerms['forumpermissions']) > 0)
						{
							$access['starteronly'][$nodeid] = $nodeid;
						}
						else
						{
							$access['selfonly'][$nodeid] = $nodeid;
						}
					}
				}
			}

			$this->datastore->build('vBUgChannelAccessG' . $groupid, serialize($access), 1, false);
		}

		//if we don't have anything for a user group in $permsFrom make sure we store the default
		foreach($groupsSeen AS $group => $dummy)
		{
			$access = array(
				'canview'       =>		array(),
				'canalwaysview'	=>		array(),
				'canaccess'     =>		array(),
				'selfonly'      =>		array(),
				'starteronly'   =>		array(),
				'canseedelnotice' => 	array(),
				'canpublish' 	=>      array(),
				'canmoderate' =>      array(),
			);
			$this->datastore->build('vBUgChannelAccessG' . $groupid, serialize($access), 1, false);
		}

		//we don't need parent info any more, so let's get rid of it to save space.
		foreach ($permFrom AS $groupid => $from)
		{
			foreach ($from AS $nodeid => $perms)
			{
				if (isset($permFrom[$groupid][$nodeid]['fromid']))
				{
					$permFrom[$groupid][$nodeid] = $permFrom[$groupid][$nodeid]['fromid'];
				}
				else
				{
					$permFrom[$groupid][$nodeid] = false;
				}
			}
		}

		//delete any entries for groups that don't exist
		$keys = $this->datastore->getKeys();
		foreach ($keys AS $key)
		{
			$matches = array();
			if (preg_match('#^vBUgChannelAccessG(\d+)$#', $key, $matches))
			{
				$groupid = $matches[1];
				if (!isset($usergroupcache[$groupid]))
				{
					$this->datastore->delete($key);
				}
			}
		}

		$this->datastore->build('vBUgChannelPermissionsFrom', serialize($permFrom), 1);
	}

	/**
	 * Returns array of moderator permissions
	 *
	 * @param int	usergroupid
	 * @param int	nodeid
	 *
	 * @return array	array of $key => integer
	 */
	public function getModeratorPermissions($usergroupid, $channelid)
	{
		$bf_ugp = $this->datastore->getValue('bf_misc_moderatorpermissions');

		if (!isset($this->channelPermissions[$usergroupid]))
		{
			$this->loadChannelPermissions($usergroupid);
			$this->validateInfractionPermissions($usergroupid, $channelid);
		}

		$permissionsFrom = $this->datastore->getValue('vBUgChannelPermissionsFrom');

		if (empty($permissionsFrom[$usergroupid]))
		{
			return array();
		}
		$perms = array();

		if (!array_key_exists($channelid, $this->channelPermissions[$usergroupid]))
		{
			//Let's see if there is a permissionsfrom entry
			if (empty($permissionsFrom[$usergroupid][$channelid]))
			{
				return array();
			}
			$channelid = $permissionsFrom[$usergroupid][$channelid];
		}

		if (isset($this->channelPermissions[$usergroupid][$channelid]['moderatorpermissions']))
		{
			foreach ($bf_ugp AS $permName => $bitmask)
			{
				$perms[$permName] = $bitmask & $this->channelPermissions[$usergroupid][$channelid]['moderatorpermissions'];
			}
		}
		else
		{
			foreach ($bf_ugp AS $permName => $bitmask)
			{
				$perms[$permName] = 0;
			}
		}

		return $perms;
	}

	/**
	 * Returns permissions array. This is used for unit testing
	 *
	 * @param bool $get_bitmap
	 * @param bool $get_limit
	 * @return array
	 */
	public function getPermissions($get_bitmap = TRUE, $get_limit = TRUE)
	{
		$result = array();

		foreach ($this->permissions as $key=>$value)
		{
			if ($this->isLimitPermission($key))
			{
				if ($get_limit)
				{
					$result[$key] = $value;
				}
			}
			else
			{
				if ($get_bitmap)
				{
					$result[$key] = $value;
				}
			}
		}

		return $result;
	}

	public function isLimitPermission($permission)
	{
		$intperms = $this->datastore->getValue('bf_misc_intperms');
		return array_key_exists($permission, $intperms);
	}

	/**
	 * Return an array with usergroups that can provide permissions
	 * Extracted from includes/functions.php::cache_permissions
	 * @return array
	 */
	public function getUserGroups()
	{
		$usergroupcache = $this->datastore->getValue('usergroupcache');
		$bf_ugp_genericoptions = $this->datastore->getValue('bf_ugp_genericoptions');

		if (empty($this->secondary_group_ids) OR !($usergroupcache[$this->primary_group_id]['genericoptions'] & $bf_ugp_genericoptions['allowmembergroups']))
		{
			return array($this->primary_group_id);
		}
		else
		{
			return array_unique(array_merge(array($this->primary_group_id), (array)$this->secondary_group_ids));
		}
	}

	/**
	 * Sets the permissions attribute with basic permissions
	 * Adapted from includes/functions.php::cache_permissions
	 */
	protected function buildBasicPermissions()
	{
		//If we have infraction group let's get the overriding perm usergroup
		$assertor = vB::getDbAssertor();
		$groupIds = array();
		if (!empty($this->infraction_group_ids))
		{
			foreach ($this->infraction_group_ids as $group)
			{
				// user.infractiongroupid links to infractiongroup.orusergroupid.
				// See vB_Library_Content_Infraction->fetchInfractionGroups() & buildInfractionGroupIds()
				$groupInfo = $assertor->getRow('infractiongroup', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'orusergroupid' => $group ));

				if (!empty($groupInfo))
				{
					$groupIds[] = $groupInfo['orusergroupid'];
				}
			}

			$this->infraction_group_ids = array_unique($groupIds);
		}

		$usergroupcache = $this->datastore->getValue('usergroupcache');
		$bf_ugp = $this->datastore->getValue('bf_ugp');
		$bf_misc_intperms = $this->datastore->getValue('bf_misc_intperms');

		if (count($this->group_ids) == 1)
		{
			$permissions = $usergroupcache[$this->group_ids[0]];
		}
		else
		{
			// initialise fields to 0
			foreach ($bf_ugp AS $dbfield => $permfields)
			{
				$permissions["$dbfield"] = 0;
			}

			// return the merged array of all user's membergroup permissions
			foreach ($this->group_ids AS $usergroupid)
			{
				foreach ($bf_ugp AS $dbfield => $permfields)
				{
					//Some permissions- initially the create permissions- are only available at the channel level.
					if (isset($usergroupcache["$usergroupid"]["$dbfield"]))
					{
						$permissions["$dbfield"] |= $usergroupcache["$usergroupid"]["$dbfield"];
					}
				}
				foreach ($bf_misc_intperms AS $dbfield => $precedence)
				{
					// put in some logic to handle $precedence
					if (!isset($intperms["$dbfield"]))
					{
						$intperms["$dbfield"] = $usergroupcache["$usergroupid"]["$dbfield"];
					}
					else if (!$precedence)
					{
						if ($usergroupcache["$usergroupid"]["$dbfield"] > $intperms["$dbfield"])
						{
							$intperms["$dbfield"] = $usergroupcache["$usergroupid"]["$dbfield"];
						}
					}
					else if ($usergroupcache["$usergroupid"]["$dbfield"] == 0 OR (isset($intperms["$dbfield"]) AND $intperms["$dbfield"] == 0))
					{
						// Set value to 0 as it overrides all
						$intperms["$dbfield"] = 0;
					}
					else if ($usergroupcache["$usergroupid"]["$dbfield"] > $intperms["$dbfield"])
					{
						$intperms["$dbfield"] = $usergroupcache["$usergroupid"]["$dbfield"];
					}
				}
			}
			$permissions = array_merge($permissions, $intperms);
		}

		if (!empty($this->infraction_group_ids))
		{
			foreach ($this->infraction_group_ids AS $usergroupid)
			{
				foreach ($bf_ugp AS $dbfield => $permfields)
				{
					if (isset($usergroupcache["$usergroupid"]["$dbfield"]))
					{
						$permissions["$dbfield"] &= $usergroupcache["$usergroupid"]["$dbfield"];
					}
				}
				foreach ($bf_misc_intperms AS $dbfield => $precedence)
				{
					if (!$precedence)
					{
						if ($usergroupcache["$usergroupid"]["$dbfield"] < $permissions["$dbfield"])
						{
							$permissions["$dbfield"] = $usergroupcache["$usergroupid"]["$dbfield"];
						}
					}
					else if ($usergroupcache["$usergroupid"]["$dbfield"] < $permissions["$dbfield"] AND $usergroupcache["$usergroupid"]["$dbfield"] != 0)
					{
						$permissions["$dbfield"] = $usergroupcache["$usergroupid"]["$dbfield"];
					}
				}
			}
		}

		$this->permissions = & $permissions;
	}

	/**
	 * Does this group have the requested system permissions
	 *
	 * @param string $group Permission group the permission is in
	 * @param string $permission Name of permission
	 * @return boolean
	 */
	public function hasPermission($group, $permission)
	{
		if (!$this->isLimitPermission($permission))
		{
			$bf_ugp = $this->datastore->getValue('bf_ugp_' . $group);
			if (isset($this->permissions[$group]) AND isset($bf_ugp[$permission]))
			{
				return (bool) ($this->permissions[$group] & $bf_ugp[$permission]);
			}
			else
			{
				return false;
			}
		}
		else
		{
			// todo: throw an exception?
			return false;
		}
	}

	public function getLimit($permission)
	{
		if ($this->isLimitPermission($permission))
		{
			return $this->permissions[$permission];
		}
		else
		{
			// this is not an intperm, throw an exception?
			return -1;
		}
	}


	/**
	 * Returns the available permissions
	 *
	 * @return array
	 */
	public function getForumPerms()
	{
		if ($this->forumPerms === false)
		{
			$this->forumPerms = $this->datastore->getValue('bf_ugp');
		}
		return $this->forumPerms;
	}

	/**
	 * Returns a list of forums this usergroup can view.
	 *
	 *	@param	integer	the usergroup id
	 *
	 *	@return 	array		an array of 'canRead' and 'cantRead', each an array
	 */
	public function getForumAccess($usergroupid)
	{
		//canview is defined as 1
		$canview = 1;
		//see if we already have a record
		if (isset($this->perms[$usergroupid]) && $this->perms[$usergroupid])
		{
			return $this->perms[$usergroupid];
		}

		$hashkey = 'vb_readperms';
		//See if we have a cached value
		$perms = vB_Cache::instance()->read($hashkey);
		if (isset($perms[$usergroupid]))
		{
			$this->perms = $perms;
			return $perms[$usergroupid];
		}

		//we need to build the permissions. First let's do the CMS.
		$perms = $this->buildPerms();
		return $perms[$usergroupid];
	}

	/**
	 * Build and caches the permissions array
	 */
	protected function buildPerms()
	{
		//we need to build the permissions.
		//Most of the time the user will have access to the root. If that's the case
		// then we can ignore all the other read access values.
		$perms = array();
		//let's get a list of all the groups and their CMS access
		$assertor = vB::getDbAssertor();
		$groupquery = $assertor->assertQuery('usergroup', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));

		$sections = array();
		$parents = array();

		if ($groupquery AND $groupquery->valid())
		{
			$groupinfo = $groupquery->current();
			while($groupquery->valid())
			{
				$perms[$groupinfo['usergroupid']] = array(
					'canRead' => array(),
					'cantRead' => array(),
					'selfOnly' => array(),
					'starterOnly' => array(),
					'canModerate' => array(),
					'cantModerate' => array(),
				);
				$groupinfo = $groupquery->next();
			}
		}

		$bf_ugp = $this->datastore->getValue('bf_ugp_forumpermissions');
		$bf_ugp_f2 = $this->datastore->getValue('bf_ugp_forumpermissions2');
		$bf_mod = $this->datastore->getValue('bf_misc_moderatorpermissions');

		//Now get the permissions.
		$permquery = $assertor->assertQuery('vBForum:permission', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));

		if ($permquery AND $permquery->valid())
		{
			$permission = $permquery->current();
			while($permquery->valid())
			{
				if ((($permission['forumpermissions'] & $bf_ugp['canview']) AND
					($permission['forumpermissions'] & $bf_ugp['canviewthreads']) AND
					($permission['forumpermissions'] & $bf_ugp['canviewothers']))
					OR ($permission['forumpermissions2'] & $bf_ugp_f2['canalwaysview'])
					)
				{
					$perms[$permission['groupid']]['canRead'][] = $permission['nodeid'];
				}
				else if (($permission['forumpermissions'] & $bf_ugp['canview']) AND
					($permission['forumpermissions'] & $bf_ugp['canviewothers']))
				{
					$perms[$permission['groupid']]['starterOnly'][] = $permission['nodeid'];
				}
				else if (($permission['forumpermissions'] & $bf_ugp['canview']) AND
					($permission['forumpermissions'] & $bf_ugp['canviewthreads']))
				{
					$perms[$permission['groupid']]['selfOnly'][] = $permission['nodeid'];
				}
				else
				{
					$perms[$permission['groupid']]['cantRead'][] = $permission['nodeid'];
				}

				if ($permission['moderatorpermissions'] & $bf_mod['canmoderateposts'])
				{
					$perms[$permission['groupid']]['canModerate'][] = $permission['nodeid'];
				}
				else
				{
					$perms[$permission['groupid']]['cantModerate'][] = $permission['nodeid'];
				}
				$permission = $permquery->next();
			}
		}

		$this->perms = $perms;

		$hashkey = 'vb_readperms';
		vB_Cache::instance()->write($hashkey, $perms, 1440, 'perms_changed');
		return $perms;
	}

	/**
	 * This checks to see if a specific permission has been set for a specific usergroup in a channel
	 *
	 *	@param	int	$usergroupid
	 * 	@param	int	$channelid
	 *
	 */
	public function getChannelPermSet($usergroupid, $channelid)
	{
		//make sure permissions are set
		if (!isset($this->channelPermissions[$usergroupid]))
		{
			$this->loadChannelPermissions($usergroupid);
			$this->validateInfractionPermissions($usergroupid, $channelid);
		}
		return array_key_exists($channelid, $this->channelPermissions[$usergroupid]);
	}

	/**
	 * Does the actual bitmap check for a single usergroup in a channel, after we have all the data loaded
	 *
	 * @param integer	the usergroup id
	 * @param string	the name of the permission group
	 * @param string	the name of the permission
	 * @param int		the channel to check. Note that we may inherit from a parent.
	 *
	 * @return	boolean
	 */
	public function getChannelPerm($usergroupid, $permissiongroup, $permission, $channelid)
	{
		if ($permissiongroup == 'moderatorpermissions')
		{
			$bf_ugp = $this->datastore->getValue('bf_misc_' . $permissiongroup);
		}
		else
		{
			$bf_ugp = $this->datastore->getValue('bf_ugp_' . $permissiongroup);
		}

		if (!isset($this->channelPermissions[$usergroupid]))
		{
			$this->loadChannelPermissions($usergroupid);
			$this->validateInfractionPermissions($usergroupid, $channelid);
		}

		$permissionsFrom = $this->datastore->getValue('vBUgChannelPermissionsFrom');

		// We might have gotten an integer;
		if (is_numeric($permission))
		{
			$permission = strtolower(vB_Types::instance()->getContentTypePackage($permission) .
				'_' . vB_Types::instance()->getContentTypeClass($permission) );
		}
		else
		{
			$permission = strtolower($permission);
		}

		if (
			!isset($this->channelPermissions[$usergroupid][$channelid]) AND
			isset($permissionsFrom[$usergroupid]) AND
			isset($permissionsFrom[$usergroupid][$channelid])
		)
		{
			$channelid = $permissionsFrom[$usergroupid][$channelid];
		}

		if (isset($bf_ugp[$permission])
			AND isset($this->channelPermissions[$usergroupid][$channelid]))
		{
			switch($permissiongroup)
			{
				case 'forumpermissions':
					return $bf_ugp[$permission] & $this->channelPermissions[$usergroupid][$channelid]['forumpermissions'];
					break;
				case 'forumpermissions2':
					return $bf_ugp[$permission] & $this->channelPermissions[$usergroupid][$channelid]['forumpermissions2'];
					break;
				case 'createpermissions':
					//We might have gotten an integer;
					if (is_numeric($permission))
					{
						$permission = strtolower(vB_Types::instance()->getContentTypePackage($permission) . '_' .
							vB_Types::instance()->getContentTypeClass($permission) );
					}
					else
					{
						$permission = strtolower($permission);
					}

					return $bf_ugp[$permission] & $this->channelPermissions[$usergroupid][$channelid]['createpermissions'];
					break;
				case 'moderatorpermissions':
					if ($usergroupid == 1) // Unregistered Group
					{
						return false;
					}
					return $bf_ugp[$permission] & intval($this->channelPermissions[$usergroupid][$channelid]['moderatorpermissions']);
					break;
				default:
					return false;
			} // switch
		}
		else
		{
			$permFields = vB_ChannelPermission::fetchPermFields();
			if (isset($permFields[$permission])
				AND ($permFields[$permission] != vB_ChannelPermission::TYPE_BITMAP)
				AND isset($this->channelPermissions[$usergroupid][$channelid]))
			{
				return $this->channelPermissions[$usergroupid][$channelid][$permission];
			}
			return false;
		}
	}

	/**
	 * Clears all existing permissions. Needed primarily in test.
	 *
	 * @param	int	$usergroupid (optional)
	 */
	public function clearChannelPermissions($usergroupid = false)
	{
		if ($usergroupid)
		{
			unset($this->channelPermissions[$usergroupid]);
			unset($this->perms[$usergroupid]);
		}
		else
		{
			$this->channelPermissions = false;
			$this->buildPerms();
		}

		$this->buildBasicPermissions();

		if ($usergroupid)
		{
			$this->loadChannelPermissions($usergroupid);
		}
	}

	/**
	 * This loads a permission group from the database and caches the results
	 *
	 * @param 	int		$usergroupid
	 */
	public function loadChannelPermissions($usergroupid)
	{
		$hashkey = 'channelperms_' . $usergroupid;
		$writelock = true;

		$this->channelPermissions[$usergroupid] = vB_Cache::instance()->read($hashkey, $writelock, false);

		//See if we got a result.
		if ($this->channelPermissions[$usergroupid] === false)
		{
			$permissions = vB::getDbAssertor()->getRows('vBForum:permission', array('groupid' => $usergroupid), false, 'nodeid');

			if (empty($permissions) OR !empty($permissions['errors']))
			{
				$this->channelPermissions[$usergroupid] = array();
			}
			else
			{
				$this->channelPermissions[$usergroupid] = $permissions;
			}
			vB_Cache::instance()->write($hashkey, $this->channelPermissions[$usergroupid], 1440, 'perms_changed');
		}
	}

	protected function validateInfractionPermissions($usergroupid, $channelid)
	{
		/** Check infraction groups */
		if (!empty($this->infraction_group_ids))
		{
			/** Temp array for infraction perms */
			$iPerms = array("permissionid" => $this->channelPermissions[$usergroupid][$channelid]["permissionid"], "nodeid" => $this->channelPermissions[$usergroupid][$channelid]["nodeid"], "groupid" => $this->channelPermissions[$usergroupid][$channelid]["groupid"]);
			foreach ($this->infraction_group_ids as $usergroup)
			{
				if (!isset($this->channelPermissions[$usergroup]) )
				{
					$this->loadChannelPermissions($usergroup);
				}
				foreach ($this->channelPermissions[$usergroup][$channelid] as $permGroup => $permVal)
				{
					if (!in_array($permGroup, array('nodeid', 'permissionid', 'groupid')))
					{
						if (!in_array($permGroup, array('forumpermissions', 'forumpermissions2', 'moderatorpermissions', 'createpermissions')))
						{
							$iPerms[$permGroup] = (isset($iPerms[$permGroup]))
								? min($iPerms[$permGroup], $permVal)
								: min($this->channelPermissions[$usergroupid][$channelid][$permGroup], $permVal);
						}
						else
						{
							$iPerms[$permGroup] = (isset($iPerms[$permGroup]))
								? ($iPerms[$permGroup] & $permVal)
								: $permVal;
						}
					}
				}
			}
			$this->channelPermissions[$usergroupid][$channelid] = $iPerms;
		}
	}

	/**
	 * Gets any admin usergroups. This is defined as one that can administer permissions
	 *
	 * @return	array -- user groupids
	 */
	public static function getAdminUsergroups($all = true)
	{
		$datastore = vB::getDatastore();
		$usergroupcache = $datastore->getValue('usergroupcache');
		$bf_ugp = $datastore->getValue('bf_ugp');
		$adminMask = $bf_ugp['adminpermissions']['cancontrolpanel'];

		$group = 0;
		$groups = array();
		if (is_array($usergroupcache))
		{
			foreach($usergroupcache AS $usergroup)
			{
				if ($usergroup['adminpermissions'] & $adminMask)
				{
					if ($all)
					{
						$groups[] = $usergroup['usergroupid'];
					}
					else
					{
						$group = ($group ? $group : $usergroup['usergroupid']);
					}
				}
			}
		}

		return ($all ? $groups : $group);
	}

	/**
	 * Gets an admin user. This is defined as one that can administer the admincp
	 *
	 * return	false|integer		a userid with admin permissions, false if not found
	 */
	public static function getAdminUser()
	{
		//First see if we have somebody configured as superadmin.
		$config = vB::getConfig();
		if (!empty($config['SpecialUsers']['superadmins']))
		{
			$superAdmins = explode(",", $config['SpecialUsers']['superadmins']);

			//check the db to ensure that any admins users in the config file actually exist
			$superAdmins = vB::getDbAssertor()->getColumn('user', 'userid', array('userid' => $superAdmins));

			if (!empty($superAdmins))
			{
				return (int) current($superAdmins);
			}
		}

		//See if we have somebody with an admin user as primary usergroup
		$usergroups = self::getAdminUsergroups();

		if (empty($usergroups))
		{
			return false;
		}

		$user = vB::getDbAssertor()->getRow('user', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => 'userid', 'usergroupid' => $usergroups));

		if (!empty($user))
		{
			return $user['userid'];
		}

		// VBV-11898 - Nothing prevents a user from having an admin group as a secondary group, but with a primary
		// group that doesn't allow member groups. So we should check that the returned user's primary group does allow it.
		$datastore = vB::getDatastore();
		$usergroupcache = $datastore->getValue('usergroupcache');
		$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');
		$allowsmembergroups = array();
		foreach ($usergroupcache AS $groupid => $groupdata)
		{
			if ($groupdata['genericoptions'] & $bf_ugp_genericoptions['allowmembergroups'])
			{
				$allowsmembergroups[] = $groupid;
			}
		}

		//Last chance- see if we have somebody who has one of the admin groups as a secondary id. This is potentially very expensive.
		//so it's a real last resort.
		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(array('field' => 'membergroupids', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES)));
		$assertor = vB::getDbAssertor();
		foreach($usergroups AS $usergroup)
		{
			$data[vB_dB_Query::CONDITIONS_KEY][0]['value'] = $usergroup;
			$test = $assertor->assertQuery('user', $data);
			//There's a dangerous condition we need to check. Let's say a site has more than eleven usergroups, and usergroup 2 has the admin permission. We need to
			//may have gotten usergroup 12 or 20.
			if ($test->valid())
			{
				foreach($test as $user)
				{
					$memberGroups = explode(',', $user['membergroupids']);
					if (in_array($usergroup,$memberGroups) AND in_array($user['usergroupid'], $allowsmembergroups))
					{
						return $user['userid'];
					}
				}
			}
		}
		//out of things to try;
		return false;
	}

	/**
	 * Get the attachment limits for an extension and usergroupid. If that usergroup does not have permission
	 *	or the extension is not in the list of allowed extensions, return false.
	 *	Note: This is only constrained to the attachmenttype and attachmentpermission tables. The create permissions
	 *	for all attachments are handled in the channels.
	 *	TODO: Make this part of the channel permissions
	 *
	 *	@param int $group Permission group the permission is in
	 *	@param string $permission Name of permission
	 *
	 *	@return	boolean|array	false if not enabled for the usergroupid. array of limits if its enabled.
	 */
	public function getAttachmentPermissions($usergroupid, $extension)
	{
		$extension = vB_String::vBStrToLower($extension);
		if (!isset($this->attachmentPermissions[$extension]))
		{
			$extensionPerms = array();
			$allAttachperms = vB::getDbAssertor()->getRows('vBForum:fetchAttachPermsByExtension', array('extension' => $extension));

			if (empty($allAttachperms))
			{
				$this->attachmentPermissions[$extension] = false;
			}
			else
			{
				foreach($allAttachperms AS $attachPerms)
				{
					if (!isset($extensionPerms['default']))
					{
						// First set the defaults set in the attachmenttype table
						$defaultPerms = array();
						$defaultPerms['height'] = !empty($attachPerms['default_height']) ? $attachPerms['default_height'] : 0;
						$defaultPerms['width'] = !empty($attachPerms['default_width']) ? $attachPerms['default_width'] : 0;
						$defaultPerms['size'] = !empty($attachPerms['default_size']) ? $attachPerms['default_size'] : 0;
						$extensionPerms['default'] = $defaultPerms;
					}

					if (!empty($attachPerms['usergroupid']))
					{
						// Now set individual permissions for the usergroups.
						if (empty($attachPerms['custom_permissions']))
						{
							// The usergroup doesn't have permission to use this extension
							$extensionPerms[$attachPerms['usergroupid']] = false;
						}
						else
						{
							// The usergroup has permission to use this extension.
							$customPerms = array();
							$customPerms['height'] = ($attachPerms['custom_height'] !== null) ? $attachPerms['custom_height'] : $extensionPerms['default']['height'];
							$customPerms['width'] = ($attachPerms['custom_width'] !== null) ? $attachPerms['custom_width'] : $extensionPerms['default']['width'];
							$customPerms['size'] = ($attachPerms['custom_size'] !== null) ? $attachPerms['custom_size'] : $extensionPerms['default']['size'];
							$extensionPerms[$attachPerms['usergroupid']] = $customPerms;
							unset($customPerms);
						}
					}
				}

				$this->attachmentPermissions[$extension] = $extensionPerms;
			}
		}

		if (isset($this->attachmentPermissions[$extension]) AND !empty($this->attachmentPermissions[$extension]))
		{
			if (isset($this->attachmentPermissions[$extension][$usergroupid]))
			{
				// We have custom permissions, use those. Could be false if this usergroup has no permissions for this extension.
				return $this->attachmentPermissions[$extension][$usergroupid];
			}
			else
			{
				// Use the defaults. Custom permissions not set, so it's allowed.
				return $this->attachmentPermissions[$extension]['default'];
			}
		}

		// This extension is not allowed.
		return false;
	}

	/**
	 * Clear out the attachment permissions.
	 */
	public function clearAttachmentPermissions()
	{
		$this->attachmentPermissions = array();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
