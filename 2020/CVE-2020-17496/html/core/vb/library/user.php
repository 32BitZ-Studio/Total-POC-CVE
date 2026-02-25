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
 * vB_Library_User
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_User extends vB_Library
{
	const PASSWORD_RESET_ATTEMPTS = 10;
	const PASSWORD_RESET_LOCK_MINUTES = 10;

	/**
	 * Check whether a user is banned.
	 *
	 * @param integer $userid User ID.
	 * @return bool Whether the user is banned.
	 */
	public function isBanned($userid)
	{
		$usercontext = vB::getUserContext($userid);
		return !$usercontext->hasPermission('genericoptions', 'isnotbannedgroup');
	}

	/**
	 * Check whether a user is banned and returns info such as reason and liftdate if possible.
	 *
	 * @param	int	$userid
	 *
	 * @retun	array -- ban liftdate and reason or false is user is not banned.
	 */
	public function fetchBannedInfo($userid)
	{
		$userid = intval($userid);
		if (!$userid)
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		// looking up cache for the node
		$hashKey = 'vbUserBanned_'. $userid;
		$banned = $cache->read($hashKey);

		if (!empty($banned))
		{
			return $banned;
		}

		if ($this->isBanned($userid))
		{
			$info = array('isbanned' => 1);
			$banRecord = vB::getDbAssertor()->getRow('vBForum:userban', array('userid' => $userid));

			if ($banRecord AND empty($banRecord['errors']))
			{
				$info['liftdate'] = $banRecord['liftdate'];
				$info['reason'] = $banRecord['reason'];
				$info['admin'] = $this->fetchUserName($banRecord['adminid']);
			}
			else if (!vB::getUserContext()->hasPermission('genericoptions', 'isnotbannedgroup'))
			{
				$info['bannedGroup'] = true;
				$info['admin'] = vB_Phrase::fetchSinglePhrase('administrator');
			}
		}
		else
		{
			$info = array('isbanned' => 0);
		}

		$cache->write($hashKey, $info, 1440, 'userChg_' . $userid);
		return $info;
	}

	/**
	 * Fetches the username for a userid
	 *
	 * @param integer $ User ID
	 * @return string
	 */
	public function fetchUserName($userid)
	{
		$userInfo = $this->fetchUserinfo($userid);

		if (empty($userInfo) OR empty($userInfo['userid']))
		{
			return false;
		}

		return $userInfo['username'];
	}

	/**
	 * Fetches the user names for the given user ids
	 * @param array $userIds
	 * @return array $usernames -- format array($userid => $username)
	 */
	public function fetchUserNames($userIds)
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$usernames = array();
		$remainingIds = array();
		foreach ($userIds as $userid)
		{
			$user = $cache->read('vbUserInfo_' . $userid);
			if (!empty($user))
			{
				$usernames[$userid] = $user['username'];
			}
			else
			{
				$remainingIds[] = $userid;
			}
		}
		if (!empty($remainingIds))
		{
			$usernames += vB::getDbAssertor()->getColumn('user', 'username', array('userid' => $remainingIds), false, 'userid');
		}
		return $usernames;
	}

	/**
	 * Fetches an array containing info for the specified user, or false if user is not found
	 * @param integer $userid
	 * @param integer $languageid -- If set to 0, it will use user-set languageid (if exists) or default languageid.
	 * @param boolean $nocache -- If true, the method won't use user cache but fetch information from DB.
	 * @param	boolean $lastactivity -- unused
	 * @return array The information for the requested user
	 */
	public function fetchUserWithPerms($userid, $languageid = 0, $nocache = false, $lastactivity = false)
	{
		//Try cached data.
		$fastCache = vB_Cache::instance(vB_Cache::CACHE_FAST);

		$userCacheKey = "vb_UserWPerms_$userid" . '_' . $languageid;
		$infoKey = "vb_UserInfo_$userid" . '_' . $languageid;
		$cached = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($userCacheKey);

		// This already uses FAST cache, do not encapsulate in LARGE
		$userInfo = $this->fetchUserinfo($userid, array(), $languageid);
		//This includes usergroups, groupintopic, moderator, and basic userinformation. Each should be cached in fastcache.
		if (($cached !== false) AND ($cached['groups'] !== false))
		{
			$usergroups = $cached['groups'];
			$groupintopic = $cached['git'];
			$moderators = $cached['moderators'];
		}
		else
		{
			// unsetting secondary groups depending on allowmembergroups UG option is done in
			// vB_User::fetchUserinfo()

			//Let's see if we have the raw data.
			$groupintopic = $this->getGroupInTopic($userid);
			$primary_group_id = $userInfo['usergroupid'];
			$display_group_id = $userInfo['displaygroupid'];
			$secondary_group_ids = (!empty($userInfo['membergroupids'])) ? explode(',', str_replace(' ', '', $userInfo['membergroupids'])) : array();
			$infraction_group_ids = (!empty($userInfo['infractiongroupids'])) ? explode(',', str_replace(' ', '', $userInfo['infractiongroupids'])) : array();

			$usergroups = array(
				'groupid' => $primary_group_id,
				'displaygroupid' => $display_group_id,
				'secondary' => $secondary_group_ids,
				'infraction' => $infraction_group_ids
			);

			$moderators = $this->fetchModerator($userid);

			vB_Cache::instance(vB_Cache::CACHE_LARGE)->write(
				$userCacheKey,
				array(
					'groups' => $usergroups,
					'git' => $groupintopic,
					'moderators' => $moderators
				),
				1440,
				array("userPerms_$userid", "userChg_$userid")
			);
		}

		$fastCache->write($infoKey, $userInfo, 5, "userChg_$userid");

		$this->groupInTopic[$userid] = $groupintopic;
		return $userInfo;
	}

	/**
	 * Delete a user
	 *
	 * @param integer   $userid              The ID of user to be deleted
	 * @param bool      $transfer_groups     Whether to transfer the Groups and Blogs owned by the user to $transferee
	 * @param integer   $transferee          ID of user that will receive the groups & blogs owned by deleted user.
	 */
	public function delete($userid, $transfer_groups = true, $transferee = null)
	{
		require_once(DIR . '/includes/adminfunctions.php');

		// check user is not set in the $undeletable users string
		if (is_unalterable_user($userid))
		{
			throw new vB_Exception_Api('user_is_protected_from_alteration_by_undeletableusers_var');
		}
		else
		{
			$info = vB_User::fetchUserinfo($userid);
			if (!$info)
			{
				throw new vB_Exception_Api('invalid_user_specified');
			}

 			$events = array();
			if ($transfer_groups AND $transferee)
			{
				// This is untested outside of admin calling the API::delete().
				$this->transferOwnership($userid, $transferee);
			}
			else
			{
				// TODO: We need to skip perm checks for this so *all* user data gets caught in the net when
				// the delete is triggered from a cron and doesn't run under an admin session.

				// Replicate the check in the content_channel API, but don't throw an exception, just ignore it.
				$guids = vB_Channel::getProtectedChannelGuids();
				// checking keys is cheaper in a loop.
				$guids = array_flip(array_values($guids));

				// Grab all social groups (but not categories)
				// TODO: figure out what should happen with categories
				$channelContentType = vB_Types::instance()->getContentTypeId('vBForum_Channel');
				$socialGroupChannel = vB_Library::instance('node')->getSGChannel();
				$nodeidsforuser = array();
				$debugGuids = array();
				$assertor = vB::getDbAssertor();
				$groups = $assertor->getRows('vBForum:getUserChannels',
					array(
						'userid' => $userid,
						'channeltypeid' => $channelContentType,
						'parentchannelid' => $socialGroupChannel,
					)
				);
				foreach ($groups AS $__row)
				{
					// This should never happen unless the main social group channel somehow became a non-category due to
					// some bug AND somehow this user got ownership of the channel.
					// But it's simple to check for so let's do it and terrible things will happen if we delete it so let's
					// check.
					if ($__row['nodeid'] != $socialGroupChannel AND !isset($guids[$__row['guid']]))
					{
						$nodeidsforuser[] = $__row['nodeid'];
						$events[] = 'nodeChg_' . $__row['nodeid'];
					}
				}


				$blogChannel = vB_Library::instance('blog')->getBlogChannel();
				$blogs = $assertor->getRows('vBForum:getUserChannels',
					array(
						'userid' => $userid,
						'channeltypeid' => $channelContentType,
						'parentchannelid' => $blogChannel,
					)
				);
				foreach ($blogs AS $__row)
				{
					// Similar to the group channel check, see note above.
					if ($__row['nodeid'] != $blogChannel AND !isset($guids[$__row['guid']]))
					{
						$nodeidsforuser[] = $__row['nodeid'];
						$events[] = 'nodeChg_' . $__row['nodeid'];
					}
				}

				// We need to skip permission checks when we're nuking the user from orbit.
				// For one thing, this might be running on another user (or guest)'s session via
				// privacy-consent remove user cron, for another thing, even if the user themselves
				// aren't allowed channel permissions to remove these channels, we should remove them
				// since we're getting rid of the user who owns the channels.
				$channelLib = vB_Library::instance('content_channel');
				foreach ($nodeidsforuser AS $nodeid)
				{
					$channelLib->delete($nodeid);
				}
			}

			$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
			$userdm->set_existing($info);
			$userdm->delete();

			if ($userdm->has_errors(false))
			{
				throw $userdm->get_exception();
			}

			vB_User::clearUsersCache($userid);
			$events[] = 'userChg_' . $userid;
			vB_Cache::allCacheEvent($events);

			return true;
		}
	}


	/**
	 *	Returns a report on "personal information" for a user
	 *
	 *	This is the personally identifiable information for
	 *	privacy laws.  Currently this follows our best understanding
	 *	of the EU law, but eventually this may end up being a superset
	 *	of all simpilar laws.
	 *
	 *	@param $userid
	 *	@return array
	 *	--string username
	 *	--string email
	 *	--string icq
	 *	--string aim
	 *	--string yahoo
	 *	--string msn
	 *	--string skype
	 *	--string google
	 *	--string usertitle
	 *	--int lastvisit
	 *	--int lastactivity
	 *	--int lastpost
	 *	--int posts
	 *	--string reputation
	 *	--int reputationlevelid
	 *	--string timezoneoffset
	 *	--string ipaddress
	 *	--int pmtotal
	 *	--string fbuserid
	 *	--int fbjoindate
	 *	--string fbname
	 *	--int infractions
	 *	--int warnings
	 *	--string reputationlevelphrase
	 *	--string startofweekphrase
	 *	--string language
	 *	--string birthday
	 *	--array(string) devicetokens
	 *	--array customFields
	 *		--array {categoryname} -- multiple arrays of categoryname => field
	 *			-- array {fieldphrase} -- mutple array of fieldphrase => field details
	 *				--mixed val
	 *				--int hidden
	 */
	public function getPersonalData($userid)
	{
		$data = vB_User::fetchUserinfo($userid);
		$personalData = array();

		$userfields = array(
			'username',
			'email',
			'icq',
			'aim',
			'yahoo',
			'msn',
			'skype',
			'google',
			'usertitle',
			'lastvisit',
			'lastactivity',
			'lastpost',
			'posts',
			'reputation',
			'reputationlevelid',
			'timezoneoffset',
			'ipaddress',
			'pmtotal',
			'fbuserid',
			'fbjoindate',
			'fbname',
			'infractions',
			'warnings',
		);

		foreach($userfields AS $field)
		{
			$personalData[$field] = $data[$field];
		}

		//let's avoid forcing the caller to put this together since, for example the templates
		//cause this to clutter up.
		$personalData['reputationlevelphrase'] = 'reputation' . $personalData['reputationlevelid'];

		// Ensure startofweek is within the valid range, default to Sunday.
		// In vB4, startofweek could be -1 which meant to use the startofweek value
		// from the calendar they were viewing. In vB5 we don't have customizable
		// calendars showing different holidays, instead we have one calendar showing
		// events so that is no longer applicable at this time.
		$startofweek = $data['startofweek'];
		if ($startofweek < 1 OR $startofweek > 7)
		{
			$startofweek = 1;
		}
		$personalData['startofweekphrase'] = $this->getDayOfWeekPhrases()[$startofweek];

		//if we don't have a matching language, leave blank.  This is the case when it's set to
		//"use board default".
		$personalData['language'] = '';
		$languages = vB::getDatastore()->getValue('languagecache');
		if (isset($languages[$data['languageid']]))
		{
			$personalData['language'] = $languages[$data['languageid']]['title'];
		}

		//use the search form because it's in YYYY-MM-DD format.  This is the closest thing we have to
		//universally recognized format.  Only skip the '0000-00-00' we add when we don't have a value.
		//if we need to format it according to user formats we'll need to figure out how we want to do that
		$personalData['birthday'] = ($data['birthday'] ? $data['birthday_search'] : '');

		$db = vB::getDbAssertor();
		$personalData['devicetokens'] = $db->getColumn('vBForum:apiclient_devicetoken', 'devicetoken', array('userid' => $userid));

		// todo: external login ids
		$personalData['externallogin'] = vB_Library::instance("externallogin")->getPersonalData($userid);

		$personalData['customFields'] = $this->getAllCustomFields($userid, true);

		return $personalData;
	}

	public function getDayOfWeekPhrases()
	{
		return array(
			1 => 'sunday',
			2 => 'monday',
			3 => 'tuesday',
			4 => 'wednesday',
			5 => 'thursday',
			6 => 'friday',
			7 => 'saturday'
		);
	}

	public function getRawCustomFields($userid)
	{
		//see if we have a cached userfield
		$fields = vB_Cache::instance(vB_Cache::CACHE_FAST)->read("userFields_$userid");

		if ($fields == false)
		{
			$assertor = vB::getDbAssertor();
			$fields = $assertor->getRow('vBForum:userfield',  array('userid' => $userid));
			vB_Cache::instance(vB_Cache::CACHE_FAST)->write("userFields_$userid", $fields, 1440, "userData_$userid");
		}

		return $fields;
	}

	public function getCustomFields($userid, $showHidden)
	{
		$customFields = array();
		$fields = $this->getRawCustomFields($userid);

		if (!empty($fields))
		{
			$fieldsInfo = $this->getProfileFieldInfoFromDatastore();
			$customFields = $this->getProfileFieldsInternal($fieldsInfo, $showHidden, $fields);
		}

		return $customFields;
	}

	//This is specifically for the profile export (for various privacy law issues)
	//
	//the public version uses the data store which excludes some older fields that
	//were set for areas that existed in previous versions of vb.  This was
	//removed from the system some time ago, but some of these fields may linger
	//We really want to make sure that we don't have undisclosed user data
	//hiding in dark corners.
	//
	//We really shouldn't use this function anywhere else.  Generally speaking if
	//admins want these field to be used elsewhere they should update them and set
	//the area to profile (which happens automatically). We should probably
	//find a way to clean up this data in old sites.
	private function getAllCustomFields($userid, $showHidden)
	{
		$customFields = array();
		$fields = $this->getRawCustomFields($userid);

		if (!empty($fields))
		{
			$fieldsInfo = $this->getProfileFieldInfo();
			$customFields = $this->getProfileFieldsInternal($fieldsInfo, $showHidden, $fields);
		}

		return $customFields;
	}

	private function getProfileFieldInfoFromDatastore()
	{
		$datastore = vB::getDatastore();

		//we should *really* clean up the datastore save to
		//1) not store three arrays.
		//2) unserialize the data values on save instead of on load
		//But that's beyond the current time availability.
		$fieldsInfo = $datastore->getValue('profilefield');
		if (is_array($fieldsInfo) AND array_key_exists('all', $fieldsInfo))
		{
			$fieldsInfo = $fieldsInfo['all'];
		}
		else
		{
			$fieldsInfo = array();
		}

		foreach($fieldsInfo AS $key => $field)
		{
			if($field['data'])
			{
				$fieldsInfo[$key]['data'] = unserialize($field['data']);
			}
		}

		return $fieldsInfo;
	}

	private function getProfileFieldInfo()
	{
		$assertor = vB::getDbAssertor();

		// Get profile fields information
		$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
		$fieldsInfo = $cache->read('vBProfileFields');
		if (empty($fieldsInfo))
		{
			$fieldsInfo = $assertor->getRows('vBForum:profilefield', array(
				vB_dB_Query::COLUMNS_KEY => array('profilefieldid', 'hidden', 'data', 'profilefieldcategoryid', 'type', 'showonpost')
			));

			foreach($fieldsInfo AS $key => $field)
			{
				if($field['data'])
				{
					$fieldsInfo[$key]['data'] = unserialize($field['data']);
				}
			}

			$cache->write('vBProfileFields', $fieldsInfo, 1440, array('vBProfileFieldsChg'));
		}


		return $fieldsInfo;
	}

	public function getProfileFieldsFromUserInfoArray($userInfoArray, $showHidden)
	{
		$fieldsInfo = $this->getProfileFieldInfoFromDatastore();

		$result = array();
		foreach($userInfoArray AS $userid => $userInfo)
		{
			$result[$userid] = $this->getProfileFieldsInternal($fieldsInfo, $showHidden, $userInfo);
		}

		return $result;
	}

	private function getProfileFieldsInternal($fieldsInfo, $showHidden, $fieldValues)
	{
		$result = array();

		foreach ($fieldsInfo AS $customField)
		{
			if (($customField['hidden'] == 0) OR $showHidden)
			{
				if ($customField['profilefieldcategoryid'])
				{
					$catNameString = 'category' . $customField['profilefieldcategoryid'] . '_title';
				}
				else
				{
					$catNameString = 'default';
				}

				$fieldName = 'field' . $customField['profilefieldid'];
				$fieldNameString =  $fieldName . '_title';

				$customFields[$catNameString][$fieldNameString] = array(
					'val' => $this->getCustomFieldValue($customField, $fieldValues[$fieldName]),
					'hidden' => $customField['hidden'],
					'showonpost' => $customField['showonpost'],
				);
			}
		}

		return $customFields;
	}

	private function getCustomFieldValue($customField, $value)
	{
		$type = $customField['type'];
		if($type == 'select_multiple' OR $type == 'checkbox')
		{
			$selected = intval($value);

			$value = array();
			foreach ($customField['data'] AS $key => $val)
			{
				if ($selected & pow(2, $key))
				{
					$value[] = $val;
				}
			}
			$value = implode(', ', $value);
		}
		return $value;
	}

	/**
	 * This returns a user's additional permissions from the groupintopic table
	 *
	 *	@param	int $userid
	 *	@param	int	$nodeid -- nodeid
	 *
	 *	@return	array -- Array of  array('nodeid' => nodeid, 'groupid' => groupid);
	 */
	public function getGroupInTopic($userid , $nodeid = false, $forceReload = false)
	{
		if (!isset($this->groupInTopic[$userid]) OR $forceReload)
		{
			// Only call getUserContext if we already have it, as we don't need all of the queries that it does
			if (vB::isUserContextSet($userid) AND !$forceReload)
			{
				$groupInTopic = vB::getUserContext($userid)->fetchGroupInTopic();
				$perms = array();
				foreach ($groupInTopic AS $_nodeid => $groups)
				{
					foreach($groups AS $group)
					{
						$perms[] = array('nodeid' => $_nodeid, 'groupid' => $group);
					}
				}
			}
			else
			{
				$params = array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'userid' => $userid
				);
				$permQry = vB::getDbAssertor()->assertQuery('vBForum:groupintopic', $params);
				$perms = array();
				foreach ($permQry AS $permission)
				{
					$perms[] = array('nodeid' => $permission['nodeid'], 'groupid' => $permission['groupid']);
				}
			}
			$this->groupInTopic[$userid] = $perms;
		}

		if ($nodeid)
		{
			$results = array();
			foreach ($this->groupInTopic[$userid] AS $perm)
			{
				if ($perm['nodeid'] == $nodeid)
				{
					$results[] = $perm;
				}
			}
			return $results;
		}

		return $this->groupInTopic[$userid];
	}


	/**
	 * Fetches an array containing all the moderator permission informationd
	 *
	 * @param integer $userid
	 * @param array of $moderator records for user
	 *
	 * @return array	the permission array
	 */
	public function fetchModerator($userid, $moderators = false)
	{
		$parentnodeids = array();
		$moderatorPerms = array();

		if ($moderators === false)
		{
			$moderators = vB::getDbAssertor()->assertQuery('vBForum:moderator', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'userid' => $userid));
			if (!$moderators->valid())
			{
				return array();
			}
		}

		if (empty($moderators))
		{
			return array();
		}

		foreach ($moderators AS $modPerm)
		{
			if (isset($modPerm['nodeid']))
			{
				if ($modPerm['nodeid'] >= 1)
				{
					$parentnodeids[] = $modPerm['nodeid'];
				}

				$moderatorPerms[$modPerm['nodeid']] = $modPerm;
			}
		}

		if (!empty($parentnodeids))
		{
			foreach ($parentnodeids as $parentnodeid)
			{
				if ($parentnodeid < 1)
				{
					continue;
				}

				$closurerecords = vB::getDbAssertor()->assertQuery('vBForum:getDescendantChannelNodeIds', array(
					'parentnodeid' => $parentnodeid, 'channelType' => vB_Types::instance()->getContentTypeID('vBForum_Channel')
				));
				foreach ($closurerecords as $closurerecord)
				{
					$childnodeid = $closurerecord['child'];
					if (!isset($moderatorPerms[$childnodeid]) AND isset($moderatorPerms[$parentnodeid]))
					{
						// descendant channels inherit moderator permissions from parent channels
						// so we copy the parent channel's permissions and change the nodeid in it
						$moderatorPerms[$childnodeid] = $moderatorPerms[$parentnodeid];
						$moderatorPerms[$childnodeid]['nodeid'] = $childnodeid;
					}
				}
			}
		}

		return $moderatorPerms;
	}

	/**
	 * Fetches an array containing info for the specified user, or false if user is not found
	 *
	 * Values for Option parameter:
	 * avatar - Get avatar
	 * location - Process user's online location
	 * admin - Join the administrator table to get various admin options
	 * signpic - Join the sigpic table to get the userid just to check if we have a picture
	 * isfriend - Is the logged in User a friend of this person?
	 * Therefore: array('avatar', 'location') means 'Get avatar' and 'Process online location'
	 *
	 * @param integer $userid
	 * @param array $option --(see description)
	 * @param integer $languageid -- If set to 0, it will use user-set languageid (if exists) or default languageid
	 * @param boolean $nocache -- If true, the method won't use user cache but fetch information from DB.
	 *
	 * @return array The information for the requested user
	 */
	public function fetchUserinfo($userid = false, $option = array(), $languageid = false, $nocache = false)
	{
		if ($languageid === false)
		{
			$session = vB::getCurrentSession();
			if ($session)
			{
				$languageid = vB::getCurrentSession()->get('languageid');
			}
		}

		$result = vB_User::fetchUserinfo($userid, $option, $languageid, $nocache);

		if (empty($result) OR !isset($result['userid']))
		{
			return false;
		}

		if (!empty($result['lang_options']))
		{
			//convert bitfields to arrays for external clients.
			$bitfields = vB::getDatastore()->getValue('bf_misc_languageoptions');
			$lang_options = $result['lang_options'];
			$result['lang_options'] = array();
			foreach ($bitfields as $key => $value)
			{
				$result['lang_options'][$key] = (bool) ($lang_options & $value);
			}
		}
		$userContext = vB::getUserContext($userid);

		//use the default style instead of the user style in some cases
		//1) The user style isn't set (value 0)
		//2) Style choosing isn't allowed and the user is not an admin
		if ($session = vB::getCurrentSession())
		{
			$sessionstyleid = $session->get('styleid');
			if ($sessionstyleid)
			{
				$result['styleid'] = $sessionstyleid;
			}
		}

		// adding some extra info
		if ($userid)
		{
			$result['is_admin'] = $userContext->isAdministrator();
			$result['is_supermod'] = (vB_UserContext::USERLEVEL_SUPERMODERATOR == $userContext->getUserLevel() ? true : false);
			$result['is_moderator'] = ($userContext->getUserLevel() >= vB_UserContext::USERLEVEL_MODERATOR);
			$result['can_use_sitebuilder'] = $userContext->hasAdminPermission('canusesitebuilder');
			$result['can_admin_ads'] = $userContext->hasAdminPermission('canadminads');
			$result['is_globally_ignored'] = $userContext->isGloballyIgnored();
		}

		$vboptions = vB::getDatastore()->getValue('options');
		$canChangeStyle =  ($vboptions['allowchangestyles'] == 1 OR $userContext->hasAdminPermission('cancontrolpanel'));

		if ( ($result['styleid'] == 0) OR !$canChangeStyle)
		{
			$result['styleid'] = $vboptions['styleid'];
		}

		//get the online status
		$this->fetchOnlineStatus($result);
		return $result;
	}

	/**
	 * Gets the usergroup information. Returns the secondary groups even if allowmembergroups usergroup option is set to No.
	 *
	 * @param	int		userid
	 *
	 * @return array with
	 * 	* groupid integer primary group id
	 * 	* displaygroupid integer display group id
	 * 	* secondary array list of secondary user groups
	 * 	* infraction array list of infraction groups.
	 *
	 * @throws vB_Exception_Api invalid_user_specified
	 */
	public function fetchUserGroups($userid)
	{
		/*
		 * Anything that calls this should take care of discarding the secondary groups
		 * based on the allowmembergroups option as appropriate. For example refer to
		 * usercontext's reloadUserPerms().
		 * Do not change this function to check for the option. AdminCP's user.php relies on this function
		 * to get the secondary groups when vB_User::fetchUserinfo() doesn't return the membergroups
		 * when the option is set to "No."
		 */

		$session = vB::getCurrentSession();
		if ($session)
		{
			$languageid = $session->get('languageid');
			$cached = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read("vb_UserWPerms_$userid" . '_' . $languageid);

			//This includes usergroups, groupintopic, moderator, and basic userinformation. Each should be cached in fastcache.
			if (($cached !== false) AND ($cached['groups'] !== false))
			{
				return $cached['groups'];
			}
		}

		//Now- we can't use fetchUserinfo here. It would put us in a loop.
		$userInfo = vB::getDbAssertor()->getRow('user',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('usergroupid', 'displaygroupid', 'membergroupids', 'infractiongroupids'),
				'userid' => $userid
			)
		);

		if (!$userInfo)
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}
		$primary_group_id = $userInfo['usergroupid'];
		$display_group_id = $userInfo['displaygroupid'];
		$secondary_group_ids = (!empty($userInfo['membergroupids'])) ? explode(',', str_replace(' ', '', $userInfo['membergroupids'])) : array();
		$infraction_group_ids = (!empty($userInfo['infractiongroupids'])) ? explode(',', str_replace(' ', '', $userInfo['infractiongroupids'])) : array();

		return array(
			'groupid' => $primary_group_id,
			'displaygroupid' => $display_group_id,
			'secondary' => $secondary_group_ids,
			'infraction' => $infraction_group_ids
		);
	}

	/**
	 *	Adds groups to a user
	 *
	 *	Will not add a group if it matches the user's primary group is set to that group
	 *	Will add groups even if allowmembergroups is set to "no".  There will be cases where
	 *	we want to track secondary group changes even if we aren't doing anything with them
	 *
	 *	Does not validate that the usergroupids are valid
	 *
	 *	@param integer $userid
	 *	@param array $groups list of integer ids for usergroups to add
	 *
	 *	@return none
	 */
	public function addSecondaryUserGroups($userid, $groups)
	{
		$usergroups = $this->fetchUserGroups($userid);
		$membergroups = $usergroups['secondary'];

		//PHP 5.3 doesn't like combining empty arrays.
		$membergroupmap = array();
		if ($usergroups['secondary'])
		{
			$membergroupmap = array_combine($usergroups['secondary'], $usergroups['secondary']);
		}

		$change = false;
		foreach($groups AS $group)
		{
			if ($group != $usergroups['groupid'] AND !isset($membergroupmap[$group]))
			{
				$change = true;
				$membergroups[] = $group;
			}
		}
		sort($membergroups);
		vB::getDbAssertor()->update('user', array('membergroupids' => implode(',', $membergroups)), array('userid' => $userid));

		if ($change)
		{
			$this->clearUserInfo(array($userid));
		}
	}

	/**
	 *	Remove groups from a user
	 *
	 *	Will not affect the user's primary group
	 *	Will unset (set to 0) the display groupid if its being removed
	 *	Will remove groups even if allowmembergroups is set to "no".  There will be cases where
	 *	we want to track secondary group changes even if we aren't doing anything with them
	 *
	 *	@param integer $userid
	 *	@param array $groups list of integer ids for usergroups to remove
	 *
	 *	@return none
	 */
	public function removeSecondaryUserGroups($userid, $groups)
	{
		$usergroups = $this->fetchUserGroups($userid);

		//Now- we can't use fetchUserinfo here. It would put us in a loop.
		$userInfo = vB::getDbAssertor()->getRow('user',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('usergroupid', 'displaygroupid', 'membergroupids', 'infractiongroupids'),
				'userid' => $userid
			)
		);

		//PHP 5.3 doesn't like combining empty arrays.
		$membergroups = array();
		if ($usergroups['secondary'])
		{
			$membergroups = array_combine($usergroups['secondary'], $usergroups['secondary']);
		}

		$change = false;
		foreach ($groups AS $group)
		{
			if (isset($membergroups[$group]))
			{
				$change = true;
				unset($membergroups[$group]);
			}
		}

		sort($membergroups);
		$updates['membergroupids'] = implode(',', $membergroups);

		//if the display group is not one of the user's groups, set it to 0
		$displaygroupid = $usergroups['displaygroupid'];
		if ($displaygroupid AND ($usergroups['groupid'] != $displaygroupid) AND !in_array($displaygroupid, $membergroups))
		{
			$updates['displaygroupid'] = 0;
		}

		vB::getDbAssertor()->update('user', $updates, array('userid' => $userid));

		if ($change)
		{
			$this->clearUserInfo(array($userid));
		}
	}

	/**
	 * @param	array	$useractivation		Record to check. Must have 'reset_locked_since'
	 */
	public function checkPasswordResetLock($useractivation)
	{
		$attemptsLimit = self::PASSWORD_RESET_ATTEMPTS;
		$lockDurationMinutes = self::PASSWORD_RESET_LOCK_MINUTES;
		$lockDurationSeconds = $lockDurationMinutes * 60;

		// data validation. Meant for devs/unit testing really, if these values aren't present than some code changed
		// unintentionally.
		if (!isset($useractivation['reset_locked_since']) OR !is_numeric($useractivation['reset_locked_since']))
		{
			throw new vB_Exception_Api('incorrect_data');
		}

		if (empty($attemptsLimit) OR empty($lockDurationSeconds))
		{
			throw new vB_Exception_Api('incorrect_data');
		}

		$timeNow = vB::getRequest()->getTimeNow();
		$locked = ($timeNow <= ($useractivation['reset_locked_since'] + $lockDurationSeconds));
		$lostPWLink = vB5_Route::buildUrl('lostpw|fullurl');
		$exceptionArgs = array($lockDurationMinutes, $lostPWLink);
		/*
			If they try to reset their password or generate a new reset activationid before the end
			of their timeout, throw an exception
		 */
		if ($locked)
		{
			throw new vB_Exception_Api('reset_password_lockout', $exceptionArgs);
		}

		// Caller must check if this activation record is invalid before using it.
		// We don't do that here as this is used by both new activationid generation &
		// password reset validation.
	}


	public function sendPasswordEmail($userid, $email)
	{
		if (!$email)
		{
			throw new vB_Exception_Api('invalidemail', array(vB5_Route::buildUrl('contact-us|fullurl')));
		}

		$vboptions = vB::getDatastore()->getValue('options');

		$users = vB::getDbAssertor()->select('user', array('email' => $email), array('userid', 'username', 'email', 'languageid'));

		$count = 0;
		foreach ($users AS $user)
		{
			$count++;
			if ($userid AND $userid != $user['userid'])
			{
				continue;
			}
			$user['username'] = unhtmlspecialchars($user['username']);

			// buildUserActivationId() will throw an exception downstream if an existing activation record is locked.
			$user['activationid'] = $this->buildUserActivationId($user['userid'], 2, 1);

			$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
				'lostpw',
				array(
					$user['username'],
					$vboptions['bbtitle'],
					$vboptions['frontendurl'],
					vB5_Route::buildUrl('reset-password|fullurl', array(), array('userid' => $user['userid'], 'activationid' => $user['activationid'])),
				),
				array($vboptions['bbtitle']),
				$user['languageid']
			);
			vB_Mail::vbmail($user['email'], $maildata['subject'], $maildata['message'], true);
		}

		if ($count)
		{
			return true;
		}
		else
		{
			throw new vB_Exception_Api('invalidemail', array(vB5_Route::buildUrl('contact-us|fullurl')));
		}
	}

	/**
	 *	Send the activation email to the user
	 *
	 *	@param int $userid
	 *	@param bool $checkmoderation -- Depeneding on configuration options, once activated a
	 *		user may be put in the awaiting moderation user group instead of the registered user's group.
	 *		If this is false we'll always force a switch back to the registered user's group.
	 *		This is primarily for admin actions where we still need to validate the email but by
	 *		sending the activation we're implicitly moderating the account.
	 */
	public function sendActivateEmail($userid, $checkmoderation = true)
	{
		$userinfo = vB_User::fetchUserinfo($userid);

		if (empty($userinfo))
		{
			throw new vB_Exception_Api('invaliduserid');
		}

		if ($userinfo['usergroupid'] != 3)
		{
			// Already activated
			throw new vB_Exception_Api('activate_wrongusergroup');
		}

		$vboptions = vB::getDatastore()->getValue('options');

		$coppauser = false;
		if ($vboptions['usecoppa'] == 1)
		{
			if (!empty($userinfo['birthdaysearch']))
			{
				$birthday = $userinfo['birthdaysearch'];
			}
			else
			{
				//we want YYYY-MM-DD for the coppa check but normally we store MM-DD-YYYY
				$birthday = $userinfo['birthday'];
				if (strlen($birthday) >= 6 AND $birthday[2] == '-' AND $birthday[5] == '-')
				{
					$birthday = substr($birthday, 6) . '-' . substr($birthday, 0, 2) . '-' . substr($birthday, 3, 2);
				}
			}

			if ($this->needsCoppa($birthday))
			{
				$coppauser = true;
			}
		}

		$username = trim(unhtmlspecialchars($userinfo['username']));

		$db = vB::getDbAssertor();

		// Try to get existing activateid from useractivation table
		$useractivation = $db->getRow('useractivation', array(
			'userid' => $userinfo['userid'],
		));

		if ($useractivation)
		{
			$activateid = fetch_random_string(40);
			$db->update('useractivation',
				array(
					'dateline' => vB::getRequest()->getTimeNow(),
					'activationid' => $activateid,
				),
				array(
					'userid' => $userinfo['userid'],
					'type' => 0,
				)
			);
		}
		else
		{
			$newgroup = 2;
			if ($checkmoderation AND ($vboptions['moderatenewmembers'] OR $coppauser))
			{
				$newgroup = 4;
			}

			$activateid = $this->buildUserActivationId($userinfo['userid'], $newgroup, 0);
		}

		$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
			'activateaccount',
			array(
				$username,
				$vboptions['bbtitle'],
				$vboptions['frontendurl'],
				$userinfo['userid'],
				$activateid,
				$vboptions['webmasteremail'],
			),
			array($username),
			$userinfo['languageid']
		);
		vB_Mail::vbmail($userinfo['email'], $maildata['subject'], $maildata['message'], true);
	}

	/**
	 * (Re)Generates an Activation ID for a user
	 *
	 * @param	integer	User's ID
	 * @param	integer	The group to move the user to when they are activated
	 * @param	integer	0 for Normal Activation, 1 for Forgotten Password
	 * @param	boolean	Whether this is an email change or not
	 *
	 * @return	string	The Activation ID
	 *
	 */
	private function buildUserActivationId($userid, $usergroupid, $type, $emailchange = 0)
	{
		if ($usergroupid == 3 OR $usergroupid == 0)
		{
			// stop them getting stuck in email confirmation group forever :)
			$usergroupid = 2;
		}

		/*
			preserve lockout
		 */
		if (!empty($type)) // Forgotten password
		{
			$existing = vB::getDbAssertor()->getRow('useractivation', array(
				'userid' => $userid,
				'type' => $type,
			));
			if (!empty($existing) AND !empty($existing['reset_locked_since']))
			{
				// If we're currently locked, throw an exception and force agent to
				// wait until lockout is over. Note that if the lockout is over,
				// the 'user_replaceuseractivation' query will reset the lockout.
				vB_Library::instance('user')->checkPasswordResetLock($existing);
			}
		}


		vB::getDbAssertor()->assertQuery('useractivation', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'userid' => $userid,
			'type' => $type,
		));

		$activateid = fetch_random_string(40);
		/*insert query*/
		vB::getDbAssertor()->assertQuery('user_replaceuseractivation', array(
			'userid' => $userid,
			'timenow' => vB::getRequest()->getTimeNow(),
			'activateid' => $activateid,
			'type' => $type,
			'usergroupid' => $usergroupid,
			'emailchange' => intval($emailchange),
		));

		if ($userinfo = vB_User::fetchUserinfo($userid))
		{
			$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
			$userdata->set_existing($userinfo);
			$userdata->set_bitfield('options', 'noactivationmails', 0);
			$userdata->save();
		}

		return $activateid;
	}

	/**
	 * This checks whether a user needs COPPA approval based on birthdate. Responds to Ajax call
	 *
	 * @param array $dateInfo array of month/day/year.
	 * @return int 0 - no COPPA needed, 1- Approve but require adult validation, 2- Deny
	 */
	public function needsCoppa($dateInfo)
	{
		$options = vB::getDatastore()->getValue('options');

		if ((bool) $options['usecoppa'])
		{
			$birthdate = false;
			// date can come as a unix timestamp, or an array, or 'YYYY-MM-DD', or 'MM-DD-YYYY' which is much more likely.
			if (is_array($dateInfo))
			{
				$cleaner = vB::getCleaner();
				$dateInfo = $cleaner->cleanArray($dateInfo, array(
					'day' => vB_Cleaner::TYPE_UINT,
					'month' => vB_Cleaner::TYPE_UINT,
					'year' => vB_Cleaner::TYPE_UINT)
				);
				$birthdate = mktime(0, 0, 0, $dateInfo['month'], $dateInfo['day'], $dateInfo['year']);
			}
			//the string formats we are interesting are 10 characters long.  So are many unix timestamps.
			//strtotime *will* happily take numeric results (specifically document is the YYYYMMDD which works
			//fine) but will produce bizarre results -- 2004130 results in 05-09-2004 and there is no explanation
			//as to why that happens.  The strings we expect to process should never pass is_numeric.
			else if (strlen($dateInfo) == 10 AND !is_numeric($dateInfo))
			{
				//strtotime has weird ideas about the delimiter.  It assume that - has day first (Euro style) and
				//that / has month first.  Unles its YYYY-MM-DD in which case it doesn't care which delimiter is
				//used.  Our dates are most like in MM-DD-YYYY which will cause all kinds of problems if we don't
				//fix the delimiter.
				$dateInfo = str_replace('-', '/', $dateInfo);
				$birthdate = strtotime($dateInfo);
			}
			else if (is_numeric($dateInfo))
			{
				//truncate the time when we get a time stamp.  Otherwise if
				//somebody has an actually time we'll compare it against midnight
				//below.  If somebody is just turning 13 today and their birthdate
				//value contains it a time it will be automatically later than
				//midnight on their birthday but as far as we (and the law) are
				//concerned they are 13 as of midnight regardless of when they were
				//born on that day or whatever other time value might have crept in.
				$birthdate = strtotime(date("Y-m-d", intval($dateInfo)));
			}

			//if we can't get a valid birthdate, assume that we needCoppa
			//note that and invalid date string will result is a false return from strtotime
			if ($birthdate === false)
			{
				return $options['usecoppa'];
			}

			$request = vB::getRequest();

			if (empty($request))
			{
				// mainly happens in test- should never happen in production.
				$cutoff = strtotime(date("Y-m-d", time()) . '- 13 years');
			}
			else
			{
				$cutoff = strtotime(date("Y-m-d", $request->getTimeNow()) . '- 13 years');
			}
			if ($birthdate > $cutoff)
			{
				return $options['usecoppa'];
			}
		}

		return 0;
	}

	/**
	 * This preloads information for a list of userids, so it will be available for userContext and other data loading
	 *
	 * @param array $userids
	 */
	public function preloadUserInfo($userids)
	{
		if (empty($userids) OR !is_array($userids))
		{
			//no harm here. Just nothing to do.
			return;
		}
		$userids = array_unique($userids);

		//first we can remove anything that already has been loaded.
		$fastCache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$languageid = vB::getCurrentSession()->get('languageid');
		$cacheKeys = array();
		foreach ($userids AS $key => $userid)
		{
			//If we already have userinfo in cache we'll have the others
			$infoKey = "vb_UserInfo_$userid" . '_' . $languageid;

			if ($fastCache->read($infoKey))
			{
				unset($userids[$key]);
				continue;
			}
			//See if we have a cached version we can use.
			$cacheKeys[$userid] = "vb_UserWPerms_$userid" . '_' . $languageid;
		}

		//Now let's see what we can get from large cache
		if (!empty($cacheKeys))
		{
			$cached = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($cacheKeys);
			$needLast = array();
			foreach($cacheKeys AS $userid => $cacheKey)
			{
				if (!empty($cached[$cacheKey]))
				{
					$needLast[] = $userid;
				}
			}

			if (!empty($needLast))
			{
				$lastData = array();
				$lastActivityQuery = vB::getDbAssertor()->assertQuery('user', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::COLUMNS_KEY => array('userid', 'lastactivity'),
					vB_dB_Query::CONDITIONS_KEY => array('userid' => $needLast)
				));

				foreach($lastActivityQuery AS $lastRecord)
				{
					$lastData[$lastRecord['userid']] = $lastRecord['lastactivity'];
				}

				foreach($cacheKeys AS $userid => $cacheKey)
				{
					if (!empty($cached[$cacheKey]))
					{
						/* VBV-10856: fetchUserWithPerms() expects true/false as its third parameter.
						   $lastData[$userid] was being passed to it below, which triggered a PHP notice
						   (Undefined offset) if it wasnt set. I have altered it to send true/false instead. */
						$this->fetchUserWithPerms($userid, $languageid, isset($lastData[$userid]));
						unset($cacheKeys[$userid]);
					}
				}
			}

		}

		//Now let's see what's left
		if (!empty($cacheKeys))
		{
			$assertor = vB::getDbAssertor();
			//First get userinfo. We cannot use a table query since we also need signature
			$userQry = $assertor->assertQuery('fetchUserinfo', array('userid' => array_keys($cacheKeys)));

			if (!$userQry->valid())
			{
				return;
			}

			foreach($userQry AS $userInfo)
			{
				$userid = $userInfo['userid'];
				$this->fetchOnlineStatus($userInfo);
				$primary_group_id = $userInfo['usergroupid'];
				$secondary_group_ids = (!empty($userInfo['membergroupids'])) ? explode(',', str_replace(' ', '', $userInfo['membergroupids'])) : array();
				$infraction_group_ids = (!empty($userInfo['infractiongroupids'])) ? explode(',', str_replace(' ', '', $userInfo['infractiongroupids'])) : array();
				$usergroups = array('groupid' => $primary_group_id, 'secondary' => $secondary_group_ids, 'infraction' => $infraction_group_ids);
				$fastCache->write("vb_UserInfo_$userid" . '_' . $languageid, $userInfo, 5, "userChg_$userid");
			}
		}
	}

	/**
 	 * Fetches the online states for the user, taking into account the browsing
	 * user's viewing permissions. Also modifies the user to include [buddymark]
	 * and [invisiblemark]
	 *
	 * @param	array	Array of userinfo to fetch online status for
	 * @param	boolean	True if you want to set $user[onlinestatus] with template results
	 *
	 * @return	integer	0 = offline, 1 = online, 2 = online but invisible (if permissions allow)
	 */
	public function fetchOnlineStatus(&$user)
	{
		$currentUser = array();

		$session = vB::getCurrentSession();
		if (empty($session))
		{
			$currentUserId = 0;
		}
		else
		{
			$currentUserId = $session->get('userid');
			//need to be very careful about calling fetch_userinfo here as there is
			//a potential infinite loop.  We really need to improve how we generate
			//the current user info because it has all kinds of circular dependancies.
			if (!empty($currentUserId))
			{
				if($currentUserId == $user['userid'])
				{
					$currentUser = $user;
				}
				else
				{
					$currentUser = $session->fetch_userinfo();
				}
			}
		}

		$buddylist = array();

		// get variables used by this function
		$list = trim($currentUser['buddylist'] ?? '');
		if ($list)
		{
			$buddylist = preg_split('/\s+/', $list, -1, PREG_SPLIT_NO_EMPTY);
		}

		// is the user on bbuser's buddylist?
		if (in_array($user['userid'], $buddylist))
		{
			$user['buddymark'] = '+';
		}
		else
		{
			$user['buddymark'] = '';
		}

		// set the invisible mark to nothing by default
		$onlinestatus = 0;
		$user['invisiblemark'] = '';
		$user['online'] = 'offline';

		// now decide if we can see the user or not
		$datecut = vB::getRequest()->getTimeNow() - vB::getDatastore()->getOption('cookietimeout');
		if ($user['lastactivity'] > $datecut AND $user['lastvisit'] != $user['lastactivity'])
		{
			$bf_misc_useroptions = vB::getDatastore()->getValue('bf_misc_useroptions');
			if ($user['options'] & $bf_misc_useroptions['invisible'])
			{
				$userContext = vB::getUserContext();
				if (
					$currentUserId == $user['userid'] OR
					($userContext AND $userContext->hasPermission('genericpermissions','canseehidden'))
				)
				{
					// user is online and invisible BUT bbuser can see them
					$user['invisiblemark'] = '*';
					$user['online'] = 'invisible';
					$onlinestatus = 2;
				}
			}
			else
			{
				// user is online and visible
				$onlinestatus = 1;
				$user['online'] = 'online';
			}
		}

		return $onlinestatus;
	}


	/**
	 * This method clears remembered channel permission
	 *
	 * @param	int	$userid
	 */
	public function clearChannelPerms($userid)
	{
		unset($this->groupInTopic[$userid]);
	}

	public function updateEmailFloodTime()
	{
		$usercontext = vB::getCurrentSession()->fetch_userinfo();
		if ($usercontext['userid'])
		{
			vB::getDbAssertor()->update('user', array("emailstamp" => vB::getRequest()->getTimeNow()), array("userid" => $usercontext['userid']));
			vB_Cache::instance(vB_CACHE::CACHE_LARGE)->event(array('userChg_' . $usercontext['userid']));
		}
		else
		{
			// Guest. Update the field for its session
			vB::getCurrentSession()->set('emailstamp', vB::getRequest()->getTimeNow());
			vB::getCurrentSession()->save();
		}
	}

	private function scanFile($filename)
	{
		$check = vB_Library::instance('filescan')->scanFile($filename);
		if (empty($check))
		{
			if (is_uploaded_file($filename))
			{
				@unlink($filename);
			}
			// todo: the current phrase indicates that the file was deleted, but we will only delete the file
			// iff the file was an uploaded file. Add a new phrase to separate the cases?
			throw new vB_Exception_Api('filescan_fail_uploaded_file');
		}
	}

	public function uploadAvatar($filename, $crop = array(), $userid = false, $adminoverride = false)
	{
		$this->scanFile($filename);

		$imageHandler = vB_Image::instance();

		$attachLib = vB_Library::instance('content_attach');

		$isImage = $imageHandler->fileLocationIsImage($filename);
		if ($isImage)
		{
			$attachLib->checkConfigImageResizeLimitsForFile($filename);

			$newImageData = $imageHandler->loadImage($filename);
			// Once we hit above, we do not care about the old file regardless of if it's "safe" or "dangerous".
			if (file_exists($filename))
			{
				// Remove old file. Image Handler intentionally DOES NOT write to the old file in case the caller
				// needs to access it.
				@unlink($filename);
				unset($filename);
			}
			if (empty($newImageData))
			{
				// throw useful exception here.
				throw new vB_Exception_Api('dangerous_image_rejected');
			}

			// use re-written image from this point on.
			$filename = $newImageData['tmp_name'];
			$fileInfo = $imageHandler->fetchImageInfo($filename);
		}
		else
		{
			// throw something useful here.
			throw new vB_Exception_Api('not_an_image');
		}

		if (!$fileInfo)
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		if ($userid === false)
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		$usercontext = vB::getUserContext($userid);
		$pathinfo = empty($crop['org_file_info']) ? pathinfo($filename) : $crop['org_file_info'];

		$dimensions = array();

		$dimensions['src_width'] = $fileInfo[0];
		$dimensions['src_height'] = $fileInfo[1];

		// set default crop size
		if (empty($crop['width']) AND empty($crop['height']))
		{
			$crop['width'] = $dimensions['src_width'];
			$crop['height'] = $dimensions['src_height'];
		}

		// cropped image can't be larger than the original image
		$crop['width'] = min($crop['width'], $dimensions['src_width']);
		$crop['height'] = min($crop['height'], $dimensions['src_height']);

		// the crop area should be square
		$crop['width'] = $crop['height'] = min($crop['width'], $crop['height']);

		// get max dimensions
		if (vB::getUserContext()->hasAdminPermission('canadminusers') AND $adminoverride)
		{
			$maxwidth = $dimensions['src_width'];
			$maxheight = $dimensions['src_height'];
		}
		else
		{
			$maxwidth = $usercontext->getLimit('avatarmaxwidth');
			$maxheight = $usercontext->getLimit('avatarmaxheight');
		}

		// if the crop happened on an image that was resized down in the browser due
		// to small screen/viewport size, then we want to increase the selection
		// coordinates to match the original image size so that the final avatar
		// uses the original image resolution (up to what the max avatar size allows)
		if (!empty($crop['resized_width']) AND $crop['resized_width'] < $dimensions['src_width'])
		{
			$resize_ratio = $dimensions['src_height'] / $crop['resized_height'];
			$crop['resized_width'] = floor($crop['resized_width'] * $resize_ratio);
			$crop['resized_height'] = floor($crop['resized_height'] * $resize_ratio);
			$crop['x1'] = floor($crop['x1'] * $resize_ratio);
			$crop['x2'] = floor($crop['x2'] * $resize_ratio);
			$crop['y1'] = floor($crop['y1'] * $resize_ratio);
			$crop['y2'] = floor($crop['y2'] * $resize_ratio);
			$crop['width'] = floor($crop['width'] * $resize_ratio);
			$crop['height'] = floor($crop['height'] * $resize_ratio);
		}

		$dimensions['x1'] = empty($crop['x1']) ? 0 : $crop['x1'];
		$dimensions['y1'] = empty($crop['y1']) ? 0 : $crop['y1'];
		$dimensions['width'] = empty($crop['width']) ? $maxwidth : $crop['width'];
		$dimensions['height'] = empty($crop['height']) ? $maxheight : $crop['height'];

		$isCropped = ($dimensions['src_width'] > $dimensions['width'] OR $dimensions['src_height'] > $dimensions['height']);

		$ext = strtolower($fileInfo[2]);

		$dimensions['extension'] = empty($ext) ? $pathinfo['extension'] : $ext;
		$dimensions['filename'] = $filename;
		$dimensions['filedata'] = file_get_contents($filename);

		// Check max height and max weight from the usergroup's permissions
		$needsResize = ($maxwidth < $fileInfo[0] OR $maxheight < $fileInfo[1]);
		$forceResize = false;

		// force a resize if the uploaded file has the right dimensions but the file size exceeds the limits
		if (!$isCropped AND !$needsResize AND strlen($dimensions['filedata']) > $usercontext->getLimit('avatarmaxsize'))
		{
			$new_dimensions = $imageHandler->bestResize($dimensions['src_width'], $dimensions['src_height']);
			$crop['width'] = $new_dimensions['width'];
			$crop['height'] = $new_dimensions['height'];

			$forceResize = true;
		}

		$extension_map = $imageHandler->getExtensionMap();

		if ($forceResize OR $needsResize)
		{
			$fileArray_cropped = $imageHandler->cropImg(
				$dimensions,
				min(empty($crop['width']) ? $maxwidth : $crop['width'], $maxwidth),
				min(empty($crop['height']) ? $maxheight : $crop['height'], $maxheight),
				$forceResize
			);

			//want to get the thumbnail based on the cropped image
			$fh = fopen($filename, 'w');
			fwrite($fh, $fileArray_cropped['filedata']);
			fclose($fh);

			$fileArray_thumb = $imageHandler->fetchThumbnail($pathinfo['basename'], $filename);
			$filearray = array(
					'size' => $fileArray_cropped['filesize'],
					'filename' => $filename,
					'name' => $pathinfo['filename'],
					'location' => $pathinfo['dirname'],
					'type' => 'image/' . $extension_map[strtolower($dimensions['extension'])],
					'filesize' => $fileArray_cropped['filesize'],
					'height' => $fileArray_cropped['height'],
					'width' => $fileArray_cropped['width'],
					'filedata_thumb' => $fileArray_thumb['filedata'],
					'filesize_thumb' => $fileArray_thumb['filesize'],
					'height_thumb' => $fileArray_thumb['height'],
					'width_thumb' => $fileArray_thumb['width'],
					'extension' => $imageHandler->getExtensionFromFileheaders($filename),
					'filedata' => $fileArray_cropped['filedata']
			);
		}
		else
		{
			$fileArray_thumb = $imageHandler->fetchThumbnail($pathinfo['basename'], $filename);
			$filearray = array(
					'size' => strlen($dimensions['filedata']),
					'filename' => $filename,
					'name' => $pathinfo['filename'],
					'location' => $pathinfo['dirname'],
					'type' => 'image/' . $extension_map[strtolower($dimensions['extension'])],
					'filesize' => strlen($dimensions['filedata']),
					'height' => $fileInfo[1],
					'width' => $fileInfo[0],
					'filedata_thumb' => $fileArray_thumb['filedata'],
					'filesize_thumb' => $fileArray_thumb['filesize'],
					'height_thumb' => $fileArray_thumb['source_height'],
					'width_thumb' => $fileArray_thumb['source_width'],
					'extension' => $imageHandler->getExtensionFromFileheaders($filename),
					'filedata' => $dimensions['filedata']
			);
		}

		$api = vB_Api::instanceInternal('user');
		$result = $this->updateAvatar($userid, false, $filearray, true);

		if (empty($result['errors']))
		{
			if (vB::getUserContext()->hasAdminPermission('canadminusers') AND $adminoverride AND !$usercontext->hasPermission('genericpermissions', 'canuseavatar'))
			{
				$userinfo = fetch_userinfo($userid);
				$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
				$userdata->set_existing($userinfo);
				$userdata->set_bitfield('adminoptions', 'adminavatar', 1);
				$userdata->save();
			}

			return $api->fetchAvatar($userid);
		}
		else
		{
			return $result;
		}
	}

	/**
	 * Update avatar
	 *
	 * @param integer $userid User ID whose avatar is going to be updated
	 * @param integer $avatarid Predefined avatar ID. -1 means to remove avatar
	 *				from the user. 0 means use custom avatar defined in $avatardata
	 * @param array $data Avatar data. It should be an array contains
	 *			  the following items: 'filename', 'width', 'height', 'filedata', 'location'
	 */
	private function updateAvatar($userid, $avatarid, $data = array(), $cropped = false)
	{
		if(empty($data['extension']))
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		$userContext = vB::getUserContext();
		$currentUserId = $userContext->fetchUserId();
		$userid = intval($userid);

		if ($userid <= 0 AND $currentUserId)
		{
			$userid = $currentUserId;
		}

		$useavatar = (($avatarid == -1) ? 0 : 1);
		$bf_ugp_genericpermissions = vB::getDatastore()->getValue('bf_ugp_genericpermissions');

		$userinfo = vB_User::fetchUserinfo(intval($userid));
		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}
		// init user datamanager
		$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
		$userdata->set_existing($userinfo);

		if ($useavatar)
		{
			if (!$avatarid)
			{
				$userpic = new vB_DataManager_Userpic(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
				// user's group doesn't have permission to use custom avatars so set override

				if (!$userContext->hasPermission('genericpermissions', 'canuseavatar'))
				{
					// init user datamanager
					$userdata->set_bitfield('adminoptions', 'adminavatar', 1);
				}
				$userpic->set('userid', $userinfo['userid']);
				$userpic->set('dateline', vB::getRequest()->getTimeNow());
				$userpic->set('width', $data['width']);
				$userpic->set('height', $data['height']);
				$userpic->set('extension', $data['extension']);

				if (vB::getDatastore()->getOption('usefileavatar'))
				{
					$avatarpath = vB::getDatastore()->getOption('avatarpath');
					$prev_dir = getcwd();
					chdir(DIR);

					$oldavatarfilename = "avatar{$userid}_{$userinfo['avatarrevision']}.{$data['extension']}";
					$avatarrevision = $userinfo['avatarrevision'] + 1;
					$avatarfilename = "avatar{$userid}_{$avatarrevision}.{$data['extension']}";
					@unlink($avatarpath . '/' . $oldavatarfilename);
					@unlink($avatarpath . '/thumbs/' . $oldavatarfilename);

					$avatarres = @fopen("$avatarpath/$avatarfilename", 'wb');
					$userpic->set('filename', $avatarfilename);
					fwrite($avatarres, $data['filedata']);
					@fclose($avatarres);
					if (!empty($data['filedata_thumb']))
					{
						$thumbres = @fopen("$avatarpath/thumbs/$avatarfilename", 'wb');
						fwrite($thumbres, $data['filedata_thumb']);
						@fclose($thumbres);
						$userpic->set('width_thumb', $data['width_thumb']);
						$userpic->set('height_thumb', $data['height_thumb']);
					}
					chdir($prev_dir);
					$userpic->set('filesize', $data['filesize']);
					$userdata->set('avatarrevision', $userinfo['avatarrevision'] + 1);
				}
				else
				{
					$avatarfilename = "avatar{$userid}_{$userinfo['avatarrevision']}.{$data['extension']}";
					$userpic->setr('filedata', $data['filedata']);
					$userpic->set('filename', $avatarfilename);

					$imageHandler = vB_Image::instance();
					if(!$cropped)
					{
						$thumb = $imageHandler->fetchThumbNail($data['name'], $data['location']);
					}
					if(!$cropped)
					{
						$userpic->set('filedata_thumb', $thumb['filedata']);
						$userpic->set('width_thumb', $thumb['width']);
						$userpic->set('height_thumb', $thumb['height']);
					}
					else {
						$userpic->set('filedata_thumb', $data['filedata_thumb']);
						$userpic->set('width_thumb', $data['width_thumb']);
						$userpic->set('height_thumb', $data['height_thumb']);
					}
				}

				$userpic->save();
			}
			else
			{
				// predefined avatar
				$userpic = new vB_DataManager_Userpic_Avatar(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
				$userpic->condition = array('userid'  => $userinfo['userid']);
				$userpic->delete();

				if ($userpic->has_errors(false))
				{
					throw $userpic->get_exception();
				}
			}
		}
		else
		{
			// not using an avatar
			$avatarid = 0;
			$userpic = new vB_DataManager_Userpic_Avatar(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
			$userpic->condition = array('userid'  => $userinfo['userid']);
			$userpic->delete();

			if ($userpic->has_errors(false))
			{
				throw $userpic->get_exception();
			}
		}

		$userdata->set('avatarid', $avatarid);
		if (!$userdata->save())
		{
			throw $userpic->get_exception();
		}

		unset($this->avatarsCache['avatar'][$userid]);
		unset($this->avatarsCache['thumb'][$userid]);

		return true;
	}


	/**
	 * Transfers all ownerships (blogs and groups) from given user to another one.
	 *
	 * 	@param 		int 	Userid to transfer ownerships from.
	 * 	@param 		int 	Userid to transfer ownerships to.
	 *
	 * 	@return 	bool 	Indicates if transfer where properly done, throws exception if needed.
	 */
	public function transferOwnership($fromuser, $touser)
	{
		$fromuser = intval($fromuser);
		$touser = intval($touser);
		if (!$touser OR !$fromuser)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$usergroupInfo = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID);
		$update = vB::getDbAssertor()->update('vBForum:groupintopic', array('userid' => $touser), array('userid' => $fromuser, 'groupid' => $usergroupInfo['usergroupid']));

		// update cache if needed
		if (is_numeric($update) AND ($update > 0))
		{
			$events = array();
			foreach (array($fromuser, $touser) AS $uid)
			{
				vB::getUserContext($uid)->clearChannelPermissions();
				$events[] = 'userPerms_' . $uid;
			}

			vB_Cache::allCacheEvent($events);
		}

		return true;
	}

	/**
	 * Generates a totally random string
	 *
	 * Intended to populate the user secret field.  Exposed as a function
	 * because the installer doesn't use the normal user save code and will
	 * need access.
	 *
	 * @return	string	Generated String
	 */
	public function generateUserSecret()
	{
		$length = 30;
		$secret = '';
		for ($i = 0; $i < $length; $i++) {
			$secret .= chr(vbrand(33, 126));
		}
		return $secret;
	}


	/**
	 *	Update the post count for a list of users.
	 *
	 *	The simple case is one user and one post, but if we
	 *	do a large operation -- for example undeleting a topic -- we can cause a number of posts to be
	 *	"counted" for a number of users (and have more than one "new" post per user).  We batch
	 *	the call for all affected users because it allows us to avoid
	 *
	 *	We also update the lastpost information for the user (conditionally).  These are linked
	 *	primary to save queries to the database because they tend to change together rather
	 *	than because the are conceptually the same thing.
	 *
	 *	@param array of $userid => $info array with the following fields
	 *	* posts -- the number of new posts for the user
	 *	* lastposttime -- the publish time of the most recent "activated" post.  This will
	 *		become the user's last post IF it's more recent than the one we have on record
	 *	* lastpostid -- the id of the last post
	 *
	 *	@return none
	 */
	public function incrementPostCountForUsers($userInfo)
	{
		$assertor = vB::getDbAssertor();
		$events = array();
		foreach($userInfo AS $userid => $info)
		{
			$assertor->assertQuery('vBForum:incrementUserPostCount', array(
				'userid' => $userid,
				'lastposttime' => $info['lastposttime'],
				'lastnodeid' => $info['lastpostid'],
				'count' => $info['posts']
			));

			$events[] = 'usrChg_' . $userid;
		}

		//efficiency hack.  If we have only one user and its the current user we
		//can skip loading the user's information because we should already (more
		//or less) have it.
		//This probably the most common case we will encounter.
		if (count($userInfo) == 1)
		{
			$currentuser = vB::getCurrentSession()->fetch_userinfo();
			$user = reset($userInfo);
			$userid = key($userInfo);

			if ($userid == $currentuser['userid'])
			{
				//the post count won't reflect the changes in this function but our calculations
				//based on post count should.  Fix the user array.
				$currentuser['posts'] += $user['posts'];
				$this->updatePostCountInfoCurrentUser($currentuser);
			}
			else
			{
				$this->updatePostCountInfo(array_keys($userInfo));
			}
		}
		else
		{
				$this->updatePostCountInfo(array_keys($userInfo));
		}

		vB_Cache::allCacheEvent($events);
	}

	/**
	 *	Update the post count for a list of users.
	 *
	 *	The simple case is one user and one post, but if we
	 *	do a large operation -- for example deleting a topic -- we can cause a number of posts to be
	 *	"uncounted" for a number of users (and have more than one "new" post per user).  We batch
	 *	the call for all affected users because it allows us to avoid
	 *
	 *	@param array of $userid => $info array with the following fields.  This is structured this
	 *		way to be consistant with the data for incrementPostCountForUsers
	 *	* posts -- the number of removed posts for the user
	 *
	 *	@return none
	 */
	public function decrementPostCountForUsers($userInfo)
	{
		$assertor = vB::getDbAssertor();
		$events = array();
		foreach($userInfo AS $userid => $info)
		{
			$assertor->assertQuery('vBForum:decrementUserPostCount', array(
				'userid' => $userid,
				'count' => $info['posts']
			));

			$events[] = 'usrChg_' . $userid;
		}

		//efficiency hack.  If we have only one user and its the current user we
		//can skip loading the user's information because we should already (more
		//or less) have it.
		//This probably the most common case we will encounter.
		//This is almost but not quite identical to the increment code (mind the change in sign)
		//But trying to isolate it to its own function is more trouble than its worth
		if (count($userInfo) == 1)
		{
			$currentuser = vB::getCurrentSession()->fetch_userinfo();
			$user = reset($userInfo);
			$userid = key($userInfo);

			if ($userid == $currentuser['userid'])
			{
				//the post count won't reflect the changes in this function but our calculations
				//based on post count should.  Fix the user array.
				$currentuser['posts'] -= $user['posts'];
				$this->updatePostCountInfoCurrentUser($currentuser);
			}
			else
			{
				$this->updatePostCountInfo(array_keys($userInfo));
			}
		}
		else
		{
				$this->updatePostCountInfo(array_keys($userInfo));
		}

		vB_Cache::allCacheEvent($events);
	}

	/**
	 *	Update the user post count dependant info for the users identified.
	 *
	 * 	Note that the user cache should be cleared after calling this function
	 * 	but it does not do so (to avoid clearing the cache repeatedly).  If
	 * 	this is needed to be made public a new public version should be created
	 * 	that calls this function and then clears the cash
	 *
	 *	Note also that this function will only update the ranks if there are ranks
	 *	defined.  This is intended to avoid querying user data that we don't need
	 *	if we can't match any ranks -- not everybody uses this feature.  However it
	 *	also means that if we create ranks and delete them all then then this
	 *	function will not clear the rank data.  There is a maintanince tool to
	 *	update this data that should be run whenever the rank structure is changed
	 *	that will fix this problem.
	 *
	 * 	@param $users an array of user ids
	 * 	@return none
	 */
	private function updatePostCountInfo($users)
	{
		//if this is empty, we'll likely get an DB error.  Shouldn't happen but its good to check.
		if (empty($users))
		{
			return;
		}

		$ranklib = vB_Library::instance('userrank');
		$haveRanks = $ranklib->haveRanks();

		$db = vB::getDbAssertor();
		$userinfo = $db->select(
			'user',
			array('userid' => $users),
			false,
			array('customtitle', 'usertitle', 'userid', 'posts', 'usergroupid', 'displaygroupid', 'membergroupids')
		);

		foreach($userinfo AS $info)
		{
			if (!$haveRanks)
			{
				$rankHtml = $ranklib->getRankHtml($info);
				$db->update('vBForum:usertextfield', array('rank' => $rankHtml), array('userid' => $info['userid']));
			}

			$this->updateLadderUserTitle($info);
		}
	}

	/**
	 *	Updates the post count dependant info for the current user.
	 *
	 *	This is going to be the common case.  We could use updatePostCountInfo for this, but we
	 *	already have all of the information we need for the user here so we can save
	 *	a query.
	 *
	 *	@param $currentUser The current user array.  We have to pass this in because the cached
	 *		value is likely to be outdated when get here and the caller may need to alter it before
	 *		we use it.  This prevents an unnecesary cache clear/reload.
	 */
	private function updatePostCountInfoCurrentUser($currentUser)
	{
		$ranklib = vB_Library::instance('userrank');
		if ($ranklib->haveRanks())
		{
			$db = vB::getDbAssertor();
			$rankHtml = $ranklib->getRankHtml($currentUser);
			$db->update('vBForum:usertextfield', array('rank' => $rankHtml), array('userid' => $currentUser['userid']));
		}
		$this->updateLadderUserTitle($currentUser);
	}

	private function updateLadderUserTitle($userInfo)
	{
		//if the user has a custom title, then continue to use that
		if ($userInfo['customtitle'])
		{
			return;
		}

		$usergroups = vB::getDatastore()->getValue('usergroupcache');

		$usergroupid = ($userInfo['displaygroupid'] ? $userInfo['displaygroupid'] : $userInfo['usergroupid']);
		$usergroup = $usergroups[$usergroupid];

		//if the title is set via usergroup, continue to use that
		if ($usergroup['usertitle'])
		{
			return;
		}

		//otherwise let's get the ladder title
		//(these are probably candidate for a datastore entry)
		$db = vB::getDbAssertor();

		$gettitle = $db->getRow('usertitle',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'minposts', 'value' => intval($userInfo['posts']), 'operator' => 'LTE')
				),
			),
			array(
				'field' => array('minposts'),
				'direction' => array(vB_dB_Query::SORT_DESC),
			)
		);

		if ($gettitle['title'] != $userInfo['usertitle'])
		{
			$db->update('user', array('usertitle' => $gettitle['title']), array('userid' => $userInfo['userid']));
		}
	}

	/**
	 * Clear user cached info for given userids.
	 * There's currently cached info in several places  (vB_Session, vB_User and vB_Cache implementations)
	 * this makes sure they all properly cleared.
	 *
	 *	@param 	array 	List of users to clear cache.
	 *
	 *	@param 	bool 	Cache was cleared or not.
	 **/
	public function clearUserInfo($userids)
	{
		if (empty($userids) OR !is_array($userids))
		{
			return false;
		}

		$events = array();
		$userids = array_unique($userids);

		$session = vB::getCurrentSession();
		$currentuser = $session->get('userid');
		$updatecurrent = false;
		foreach ($userids AS $userid)
		{
			// update current user?
			if ($currentuser == $userid)
			{
				$updatecurrent = true;
			}

			vB_User::clearUsersCache($userid);
			$events[] = 'userChg_' . $userid;
		}

		vB_Cache::allCacheEvent($events);

		if ($updatecurrent)
		{
			$session->clearUserInfo();
		}

		return true;
	}

	//These are IP related rather than strictly user related.  However IP
	//addresses are closely related to users and we don't have enough warrant
	//a completely new library class.  So for the moment we'll put them here.
	//However if we expand this section in the future it would be worth
	//revisting that decision.
	/**
	 * Return if the privacy consent is required for given IP address
	 *
	 * @param string $ipaddress
	 *
	 * @return int
	 *	-- 0 unknown
	 *	-- 1 Privacy Consent Required
	 *	-- 2 Privacy Consent Not Required
	 */
	public function getPrivacyConsentRequired($ipaddress)
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('ipaddressinfo', array('ipaddress' => $ipaddress));

		if ($row)
		{
			return $row['eustatus'];
		}

		//the geoip service is slow enough that we have a potential race condition in many cases.
		//which causes an insert after the call to fail. This means that in this case the calls that would
		//formerly fail will get an 'unknown' status.  But the alternative is to hammer the geoip service
		//and it's unlikely that in the known cases the result is likely to be important.
		$time = vB::getRequest()->getTimeNow();
		$db->insertIgnore('ipaddressinfo', array('ipaddress' => $ipaddress, 'eustatus' => 0, 'created' => $time));

		$options = vB::getDatastore()->getValue('options');

		$data = array();
		$data['urlLoader'] = vB::getUrlLoader(true);
		$data['key'] = $options['geoip_service_key'];

		//if we don't have an IP provider, then treat as unknown.
		if (!$options['geoip_provider'] OR $options['geoip_provider'] == 'none')
		{
			return 0;
		}

		try
		{
			$class = vB::getVbClassName($options['geoip_provider'], 'Utility_Geoip', 'vB_Utility_Geoip');
			$geoip = new $class($data);
			$isEu = $geoip->isEu($ipaddress);
			$euStatus = ($isEu ? 1 : 2);
		}
		catch(Exception $e)
		{
			//status could not be determined.
			$euStatus = 0;
		}
		catch(Error $e)
		{
			//status could not be determined.
			$euStatus = 0;
		}

		$db->update('ipaddressinfo', array('eustatus' => $euStatus, 'created' => $time), array('ipaddress' => $ipaddress));

		return $euStatus;
	}

	/**
	 *	Delete the old IP cache data
	 */
	public function cleanIpInfo()
	{
		$db = vB::getDbAssertor();
		$time = vB::getRequest()->getTimeNow();

		$cutoff = $time - (45 * 24 * 60 * 60);
		$db->delete('ipaddressinfo', array(array('field' => 'created', 'value' => $cutoff, 'operator' =>  vB_dB_Query::OPERATOR_LT)));
	}

	/**
	 * Updates guest privacy consent
	 *
	 * This saves a new record for each consent "event", even if the IP address is the
	 * same, because we have no way of knowing if it's the same person or not. If a
	 * saved consent "event" for a given time and IP address needs to be retrieved,
	 * this will give us the greatest likelihood of finding it.
	 *
	 * @param bool True if consenting, false otherwise
	 */
	public function updateGuestPrivacyConsent($consent)
	{
		$userid = vB::getCurrentSession()->get('userid');

		if ($userid > 0)
		{
			throw new vB_Exception_Api('invalid_request');
		}

		$request = vB::getRequest();

		$ipaddress = $request->getIpAddress();
		$created = $request->getTimeNow();
		$consent = (int) ((bool)$consent);

		return vB::getDbAssertor()->insert('privacyconsent', array(
			'ipaddress' => $ipaddress,
			'created' => $created,
			'consent' => $consent,
		));
	}

	/**
	 * Returns the values for the user-related phrase shortcodes, for use in emails.
	 * These correspond to the recipient user.
	 *
	 * @param string Recipient's email address
	 * @param int Recipient's User ID (if email address is empty, it can use user id instead)
	 * @return array Array of replacement values
	 */
	public function getEmailReplacementValues($email, $userid = 0)
	{
		$email = (string) $email;

		$return = array(
			'{musername}' => '[username]',
			'{username}' => '[username]',
			'{userid}' => '[userid]',
		);

		$condition = array();

		if (!empty($email))
		{
			$condition['email'] = $email;
		}
		else if (!empty($userid))
		{
			$condition['userid'] = $userid;
		}

		if (!empty($condition))
		{
			$row = vB::getDbAssertor()->getRow('user', $condition);
			if ($row)
			{
				$return['{musername}'] = vB_User::fetchMusername($row);
				$return['{username}'] = $row['username'];
				$return['{userid}'] = $row['userid'];
			}
		}

		return $return;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103869 $
|| #######################################################################
\*=========================================================================*/
