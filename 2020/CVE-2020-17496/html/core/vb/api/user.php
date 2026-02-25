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
 * vB_Api_User
 *
 * @package vBApi
 * @access public
 */
class vB_Api_User extends vB_Api
{
	const USERINFO_AVATAR = 'avatar'; // Get avatar
	const USERINFO_ADMIN = 'admin'; // Join the administrator table to get various admin options
	const USERINFO_SIGNPIC = 'signpic'; // Join the sigpic table to get the userid just to check if we have a picture
	const USERINFO_ISFRIEND = 'isfriend'; // Is the logged in User a friend of this person?

	const DEFAULT_AVATAR_PATH_REGULAR = 'images/default/default_avatar_medium.png';
	const DEFAULT_AVATAR_PATH_THUMB = 'images/default/default_avatar_thumb.png';
	const DEFAULT_AVATAR_PATH_LARGE = 'images/default/default_avatar_large.png';

	protected $disableWhiteList = array(
		'fetchCurrentUserinfo',
		'fetchProfileInfo',
		'fetchUserinfo',
		'fetchUserSettings',
		'getPrivacyConsentRequired',
		'hasPermissions',
		'login',
		'login2',
		'loginSpecificUser',
		'setPrivacyConsent',
		'updateGuestPrivacyConsent',
	);
	protected $disableFalseReturnOnly = array('fetchAvatar');

	protected $users = array();

	protected $groupInTopic = array();
	protected $moderatorsOf = array();
	protected $membersOf = array();
	protected $permissionContext = array();
	protected $referrals = array();
	protected $avatarsCache = array();
	protected $avatarUserCache = array();
	// usertitle
	protected $usertitleCache = array();


	// user privacy options
	protected $privacyOptions = array(
		'showContactInfo' => 'contact_info',
		'showAvatar' => 'profile_picture',
		'showActivities' => 'activities',
		'showVM' => 'visitor_messages',
		'showSubscriptions' => 'following',
		'showSubscribers' => 'followers',
		'showPhotos' => 'photos',
		'showVideos' => 'videos',
		'showGroups' => 'group_memberships',
	);

	protected $library;

	/**
	 * An array of userids to batch-fetch avatar information for.
	 * @var array Userids
	 */
	protected $pendingAvatarUserids = array();

	/**
	 * Array of userids that have already been used to batch-fetch avatar information
	 * @var array Userids
	 */
	protected $loadedAvatarUserids = array();

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('user');
	}

	/**
	 * This gets the information needed for a user's profile. Only public information unless this is an admin or the user.
	 *
	 * @param int $userid -- uses the current logged in user if not given.  Error if the user is a guest.
	 * @return array -- the profile information.
	 */
	public function fetchProfileInfo($userid = false)
	{
		$options = vB::getDatastore()->getValue('options');
		$currentUserId = vB::getCurrentSession()->get('userid');

		if (empty($userid))
		{
			$userid = $currentUserId;
		}
		else
		{
			$userid = intval($userid);
		}

		if (($userid < 1))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, 'userid', __CLASS__, __FUNCTION__));
		}

		$userContext = vB::getUserContext();
		$requestedUserContext = vB::getUserContext($userid);

		$hashKey = 'vBProfileUser_' . $userid;

		$fastCache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$userInfo = $fastCache->read($hashKey);

		if (empty($userInfo))
		{
			$userInfo = vB_User::fetchUserinfo($userid,
				array(
					vB_Api_User::USERINFO_AVATAR,
					vB_Api_User::USERINFO_SIGNPIC,
				)
			);

			//strip the private fields here before we cache.
			$userInfo = $this->stripPrivateUserFields($userInfo);


			//
			// Fields for the user's profile pages
			//

			// Show hidden fields only if the user views his own profile or if it has the permission to see them
			$showHidden = (($currentUserId == $userid) OR $userContext->hasPermission('genericpermissions', 'canseehiddencustomfields'));
			$customFields = $this->library->getCustomFields($userid, $showHidden);

			$userInfo['customFields'] = $customFields;

			//
			// Check whether user has permission to use friends list (follow users)
			//
			$userInfo['canusefriends'] = $requestedUserContext->hasPermission('genericpermissions2', 'canusefriends');
			$userInfo['canviewmembers'] = $requestedUserContext->hasPermission('genericpermissions', 'canviewmembers');

			$assertor = vB::getDbAssertor();

			//
			// User counts
			//
			$followApi = vB_Api::instanceInternal('follow');
			if ($currentUserId == $userid OR $userInfo['canusefriends'])
			{
				$follows = $followApi->getFollowing($userid);
				$userInfo['followsCount'] = $follows['paginationInfo']['totalcount'];
			}
			$followers = $followApi->getFollowers($userid);
			$userInfo['followersCount'] = $followers['paginationInfo']['totalcount'];

			$userInfo['socialGroupsCount'] = 10;

			if (isset($this->referrals[$userid]))
			{
				$referrals = $this->referrals[$userid];
			}
			else
			{
				$referrals = $assertor->getRow('vBForum:getReferralsCount', array('userid' => $userid));
				$this->referrals[$userid] = $referrals;
			}

			$userInfo['birthdayTimestamp'] = 0;
			$userInfo['referralsCount'] = $referrals['referrals'];

			if ($userInfo['birthday_search'])
			{
				list($year, $month, $day) = explode("-", $userInfo['birthday_search']);
				$userInfo['birthdayTimestamp'] = mktime(0, 0, 0, $month, $day, $year);
				$userInfo['age'] = (date("md") < $month . $day ? date("Y") - $year - 1 : date("Y") - $year);
			}

			/**
			 * Get vms info
			 */
			$vms = $assertor->getRows('vBForum:node',
				array('setfor' => $userid),
				array('field' => 'publishdate', 'direction' => vB_dB_Query::SORT_DESC)
			);
			vB_Library_Content::writeToCache($vms, vB_Library_Content::CACHELEVEL_NODE);
			$userInfo['vmCount'] = count($vms);
			$userInfo['vmMostRecent'] = ($userInfo['vmCount']) ? $vms[0]['publishdate'] : 0;

			/**
			 * Let's get posts per day
			 */
			$timeIn = (vB::getRequest()->getTimeNow() - $userInfo['joindate']) / (24 * 60 * 60);
			if (($timeIn >= 1) AND ($userInfo['posts'] > 0))
			{
				$userInfo['postPerDay'] = vb_number_format(($userInfo['posts'] / $timeIn), 2);
			}
			else
			{
				$userInfo['postPerDay'] = $userInfo['posts'];
			}

			$fastCache->write($hashKey, $userInfo, 1440, 'userChg_' . $userid);
		}

		//strip the user fields after we cache.  Otherwise infromation is determined by the
		//permissions of whoever triggered the cache write and not the current user.
		//this isn't a huge problem since the fast cache current only really works with local memory
		//but if we ever fix using memcache for that ...
		//Note that this will rerun stripPrivateUserFields called above, but that's harmless
		//and trying to replicate the rest of the behavior of this function was causing needless
		//duplication of logic.
		$this->sanitizeUserInfo($userInfo, $currentUserId);

		if(($userInfo['userid'] != $currentUserId) AND !$this->hasAdminPermission('canadminusers'))
		{
			$userInfo = $this->blankUserOnlyFields($userInfo);
		}

		// add current user flags
		// if user is the profile owner..
		$userInfo['showAvatar'] = 1;
		if ($currentUserId == $userid)
		{
			if ($userContext->hasPermission('genericpermissions', 'canuseavatar'))
			{
				$userInfo['canuseavatar'] = 1;
				$userInfo['avatarmaxwidth'] = $userContext->getLimit('avatarmaxwidth');
				$userInfo['avatarmaxheight'] = $userContext->getLimit('avatarmaxheight');
				$userInfo['avatarmaxsize'] = ($userContext->getLimit('avatarmaxsize') / 1024);
			}
			else
			{
				$userInfo['canuseavatar'] = 0;
			}

			//Are there any default avatars this user could assign?
			$avatars = vB_Api::instanceInternal('profile')->getDefaultAvatars();
			$userInfo['defaultAvatarCount'] = count($avatars);
			if (($userInfo['defaultAvatarCount']) OR ($userInfo['canuseavatar'] > 0))
			{
				$userInfo['showAvatarOptions'] = 1;
			}
			else
			{
				$userInfo['showAvatarOptions'] = 0;
			}
		}
		else
		{
			$userInfo['canuseavatar'] = $userInfo['showAvatarOptions'] = 0;

			//Check the privacy settings and see if this user has hidden his
			if ($userInfo['privacy_options'] AND $requestedUserContext->hasPermission('usercsspermissions', 'caneditprivacy'))
			{
				switch ($userInfo['privacy_options']['profile_picture'])
				{
					case 1:
						//visible only if the current user is a subscriber.
						if (($currentUserId == 0) OR (vB_Api::instanceInternal('follow')->isFollowingUser($userid) != vB_Api_Follow::FOLLOWING_YES))
						{
							$userInfo['showAvatar'] = 0;
						}
						break;
					case 2:
						//visible only if the current user is a registered user.
						if ($currentUserId == 0)
						{
							$userInfo['showAvatar'] = 0;
						}
						break;
				} // switch
			}
		}

		$this->setCurrentUserFlags($userInfo);
		// Add online status
		$this->library->fetchOnlineStatus($userInfo);
		return $userInfo;
	}

	/**
	 * Set current user flags to display or not certain user items.
	 */
	protected function setCurrentUserFlags(&$userInfo)
	{
		$currentUserId = vB::getCurrentSession()->get('userid');
		$profileUserContext = vB::getUserContext($userInfo['userid']);
		$isModerator = vB::getUserContext()->isModerator();
		$followApi = vB_Api::instanceInternal('follow');

		$canViewAll = (($userInfo['userid'] == $currentUserId) OR $isModerator OR
			!$profileUserContext->hasPermission('usercsspermissions', 'caneditprivacy'));

		foreach ($this->privacyOptions AS $key => $opt)
		{
			//default to viewing everything
			$userInfo[$key] = 1;
			if (!$canViewAll AND isset($userInfo['privacy_options'][$opt]))
			{
				switch ($userInfo['privacy_options'][$opt])
				{
					case 1:
						if (($currentUserId == 0) OR $followApi->isFollowingUser($userInfo['userid']) != vB_Api_Follow::FOLLOWING_YES)
						{
							$userInfo[$key] = 0;
						}
						break;
					case 2:
						if ($currentUserId == 0)
						{
							$userInfo[$key] = 0;
						}
						break;
				}
			}
		}
	}

	/**
	 * Fetches the needed info for user settings
	 */
	public function fetchUserSettings($userid = false)
	{
		$currentUserId = vB::getCurrentSession()->get('userid');
		if (empty($userid))
		{
			$userid = $currentUserId;
		}
		else
		{
			$userid = intval($userid);
		}

		if (($userid < 1))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, 'userid', __CLASS__, __FUNCTION__));
		}

		$userInfo = vB_User::fetchUserinfo($userid,
			array(
				vB_Api_User::USERINFO_AVATAR,
				vB_Api_User::USERINFO_SIGNPIC,
			)
		);

		$userInfo = $this->sanitizeUserInfo($userInfo, $currentUserId);

		/**
		 * * Fields for the user's profile pages
		 */
		$fields = $this->library->getRawCustomFields($userid);

		// CustomFields for user settings
		$settingsCustomFields = array();
		// Types of userfields that have data array
		$fieldsWithData = array('radio', 'checkbox', 'select', 'select_multiple');

		// Web is not a customField we are grabbing this from user.homepage record -- however it acts like a custom field
		$settingsCustomFields[0]['fields']['-1'] = array(
			'text' => 'usersetting_web',
			'field' => 'homepage',
			'value' => $userInfo['homepage'],
			'type' => 'text',
			'editable' => true
		);

		$assertor = vB::getDbAssertor();
		$fieldsInfo = $assertor->getRows('vBForum:fetchCustomProfileFields', array('hidden' => array(0,1)));
		foreach ($fieldsInfo as $customField)
		{
			// Setting the category in which the profile field belongs to
			if (!isset($settingsCustomFields[$customField['profilefieldcategoryid']]))
			{
				$catNameString = ($customField['profilefieldcategoryid']) ? (string) new vB_Phrase('cprofilefield', 'category' . $customField['profilefieldcategoryid'] . '_title') : '';
				$catDescString = ($customField['profilefieldcategoryid']) ? (string) new vB_Phrase('cprofilefield', 'category' . $customField['profilefieldcategoryid'] . '_desc') : '';
				$settingsCustomFields[$customField['profilefieldcategoryid']] = array(
					'name' => $catNameString,
					'desc'  => $catDescString,
					'fields' => array(),
				);
			}

			$value = $fields['field'.$customField['profilefieldid']];
			// Adding general field information
			$settingsCustomFields[$customField['profilefieldcategoryid']]['fields'][$customField['profilefieldid']] = array(
				'text' => 'field' . $customField['profilefieldid'],
				'field' => 'field' . $customField['profilefieldid'],
				'value' => $value,
				'type' => $customField['type'],
				'hidden' => $customField['hidden'],
				'id' => $customField['profilefieldid'],
				'def' => $customField['def'],
				'maxlength' => $customField['maxlength'],
				//allow editing when otherwise we wouldn't for blank "registration only" fields
				'editable' => ($customField['editable'] == 1 OR ($customField['editable'] == 2 AND empty($value))),
			);

			// For specific field types (defined in $fieldsWithData) adding the data array and setting if that option is selected
			if (in_array($customField['type'], $fieldsWithData))
			{
				$multi = ($customField['type'] == 'select_multiple' OR $customField['type'] == 'checkbox');

				$selectedtype = '';
				if ($multi)
				{
					$selectedtype = ($customField['type'] == 'select_multiple' ?  'selected="selected"' : 'checked="checked"');
					$selectedbits = intval($fields['field' . $customField['profilefieldid']]);
				}

				$tmpData = unserialize($customField['data']);
				foreach ($tmpData as $key => $value)
				{
					$selected = '';
					if ($multi AND ($selectedbits & pow(2, $key)))
					{
						$selected = $selectedtype;
					}

					$settingsCustomFields[$customField['profilefieldcategoryid']]['fields'][$customField['profilefieldid']]['data'][$key+1] = array(
						'value' => $value,
						'selected' => $selected,
					);
				}
			}
		}

		$userInfo['settings_customFields'] = $settingsCustomFields;

		$queryData = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'userid' => $userid);
		$tempData = array();

		/**
		 * Let's get day month and year from birthday
		 *
		 */
		if ($userInfo['birthday_search'] != '0000-00-00')
		{
			$elements = explode('-', $userInfo['birthday_search']);
		}
		else
		{
			$elements = array('', '', '');
		}

		list($userInfo['bd_year'], $userInfo['bd_month'], $userInfo['bd_day']) = $elements;

		/**
		 * we know available providers, so let's see if user has one
		 */
		$userInfo['im_providers'] = array('aim', 'google', 'skype', 'yahoo', 'icq');
		$userInfo['has_im'] = false;
		foreach ($userInfo['im_providers'] as $provider)
		{
			if (!empty($userInfo[$provider]))
			{
				$userInfo['has_im'] = true;
			}
		}

		/**
		 * @TODO remove when templates support perm checks
		 */
		$userInfo['canusecustomtitle'] = vB::getUserContext()->hasPermission('genericpermissions', 'canusecustomtitle');

		/**
		 * @TODO timezone options
		 */
		$userInfo['timezones'] = array(
			'-12'  => 'timezone_gmt_minus_1200',
			'-11'  => 'timezone_gmt_minus_1100',
			'-10'  => 'timezone_gmt_minus_1000',
			'-9.5' => 'timezone_gmt_minus_0930',
			'-9'   => 'timezone_gmt_minus_0900',
			'-8'   => 'timezone_gmt_minus_0800',
			'-7'   => 'timezone_gmt_minus_0700',
			'-6'   => 'timezone_gmt_minus_0600',
			'-5'   => 'timezone_gmt_minus_0500',
			'-4.5' => 'timezone_gmt_minus_0430',
			'-4'   => 'timezone_gmt_minus_0400',
			'-3.5' => 'timezone_gmt_minus_0330',
			'-3'   => 'timezone_gmt_minus_0300',
			'-2'   => 'timezone_gmt_minus_0200',
			'-1'   => 'timezone_gmt_minus_0100',
			'0'	=> 'timezone_gmt_plus_0000',
			'1'	=> 'timezone_gmt_plus_0100',
			'2'	=> 'timezone_gmt_plus_0200',
			'3'	=> 'timezone_gmt_plus_0300',
			'3.5'  => 'timezone_gmt_plus_0330',
			'4'	=> 'timezone_gmt_plus_0400',
			'4.5'  => 'timezone_gmt_plus_0430',
			'5'	=> 'timezone_gmt_plus_0500',
			'5.5'  => 'timezone_gmt_plus_0530',
			'5.75' => 'timezone_gmt_plus_0545',
			'6'	=> 'timezone_gmt_plus_0600',
			'6.5'  => 'timezone_gmt_plus_0630',
			'7'	=> 'timezone_gmt_plus_0700',
			'8'	=> 'timezone_gmt_plus_0800',
			'8.5' => 'timezone_gmt_plus_0830',
			'8.75' => 'timezone_gmt_plus_0845',
			'9'	=> 'timezone_gmt_plus_0900',
			'9.5'  => 'timezone_gmt_plus_0930',
			'10'   => 'timezone_gmt_plus_1000',
			'10.5' => 'timezone_gmt_plus_1030',
			'11'   => 'timezone_gmt_plus_1100',
			'12'   => 'timezone_gmt_plus_1200'
		);

		$profileApi = vB_Api::instanceInternal('profile');
		/**
		 * style options
		 */
		$styles = $profileApi->getStyles();
		if (count($styles) > 1)
		{
			$userInfo['styles']['count'] = count($styles);
			foreach ($styles as $style)
			{
				if ($style['depth'] > 1)
				{
					$identation = '';
					for($x = 1; $x < $style['depth']; $x++)
					{
						$identation .= '--';
					}
					$style['title'] = $identation . $style['title'];
				}

				$userInfo['styles']['options'][] = $style;
			}
		}

		/**
		 * fetch language options
		 */
		$languages = $profileApi->getLanguages($userInfo['languageid']);
		if (count($languages) > 1)
		{
			$userInfo['languages']['count'] = count($languages);
			$userInfo['languages']['options'] = $languages;
		}
		$userOptions = vB::getDatastore()->getValue('bf_misc_useroptions');
		foreach ($userOptions as $option => $value)
		{
			$userInfo["$option"] = ($userInfo['options'] & $value) ? true : false;
		}

		/**
		 * User max posts
		 */
		foreach (array(-1, 5, 10, 20, 30, 40) as $maxPostOption)
		{
			if ($maxPostOption == $userInfo['maxposts'])
			{
				$userInfo['maxposts_options'][$maxPostOption]['selected'] = true;
			}
			else
			{
				$userInfo['maxposts_options'][$maxPostOption]['selected'] = false;
			}
		}

		/**
		 * DST options
		 */
		$selectdst = 0;
		if ($userInfo['dstauto'])
		{
			$selectdst = 2;
		}
		else if ($userInfo['dstonoff'])
		{
			$selectdst = 1;
		}

		$userInfo['dst_options'] = array(
			2 => array('phrase' => 'automatically_detect_dst_settings', 'selected' => ($selectdst == 2)),
			1 => array('phrase' => 'dst_corrections_always_on', 'selected' => ($selectdst == 1)),
			0 => array('phrase' => 'dst_corrections_always_off', 'selected' => ($selectdst == 0))
		);

		/**
		 * SoW options
		 */
		foreach ($this->library->getDayOfWeekPhrases() AS $idx => $day)
		{
			$userInfo['sow_options'][$idx] = array('day' => $day, 'selected' => ($userInfo['startofweek'] == $idx));
		}
		$options = vB::getDatastore()->getValue('options');
		//user maxresults for the autocomplete display for the moment
		$userInfo['minuserlength'] = ($options['minuserlength']) ? $options['minuserlength'] : 1;
		$userInfo['maxresults'] = ($options['maxresults']) ? $options['maxresults'] : 20;

		//if facebook connect is enabled
		$userInfo['facebookactive'] = (bool)$options['facebookactive'];

		//user signature
		$userInfo['allow_signatures'] = ((bool)$options['allow_signatures']) & vB::getUserContext()->hasPermission('genericpermissions', 'canusesignature');
		//user ignorelist
		$usernames = $this->library->fetchUserNames(explode(' ', $userInfo['ignorelist']));
		$userInfo['ignorelist'] = implode(',', $usernames);

		//profile options
		 $userInfo['profile_options']['options'] = array();
		foreach (array('everyone', 'followers', 'members') AS $phrase)
		{
			$userInfo['profile_options']['options'][] = $phrase;
		}

		//notifications settings
		$notificationOptions = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');
		$optVals = array();
		foreach ($notificationOptions as $key => $option)
		{
			$optVals[$key] = ($option & $userInfo['notification_options']) ? 'true' : 'false';
		}
		$userInfo['notification_options'] = array('options' => $userInfo['notification_options'], 'values' => $optVals);

		//email notification setting
		$emailOptions = array(
			'0' => array('phrase' => 'usersetting_emailnotification_none'),
			'1' => array('phrase' => 'usersetting_emailnotification_on'),
			'2' => array('phrase' => 'usersetting_emailnotification_daily'),
			'3' => array('phrase' => 'usersetting_emailnotification_weekly'),
		);
		foreach ($emailOptions AS $key => $emailOption)
		{
			if ($userInfo['emailnotification'] == $key)
			{
				$emailOptions[$key]['selected'] = 1;
			}
		}
		$userInfo['email_notifications'] = $emailOptions;

		//Permission for hiding reputation level
		$userInfo['canhiderep'] = vB::getUserContext()->hasPermission('genericpermissions', 'canhiderep');

		// Permission for invisible mode
		$userInfo['caninvisible'] = vB::getUserContext()->hasPermission('genericpermissions', 'caninvisible');

		/**
		 * advanced editor interface
		 */
		$editorOptions = array(
			'0' => array('phrase' => 'basic_editor_simple_text_box'),
			'1' => array('phrase' => 'standard_editor_extra_formatting'),
			'2' => array('phrase' => 'enhanced_interface_wysiwyg')
		);
		foreach ($editorOptions as $key => $val)
		{
			if ($key == $userInfo['showvbcode'])
			{
				$editorOptions[$key]['selected'] = true;
			}
		}

		/**
		 *	MFA Information
		 */

		//we want to be a little cagey about MFA status for security reasons.  Only disclose the
		//information if the user if this is user in question requesting it or an appropriate admin
		$userInfo['showMFATab'] = false;
		if ($userid == $currentUserId OR $this->hasAdminPermission('canadminusers'))
		{
			$thisUserContext = vB::getUserContext($userid);
			$isAdmin = $thisUserContext->isAdministrator();
			$isMod = $thisUserContext->isModerator();
			$config = vB::getConfig();
			if(!empty($config['Security']['mfa_enabled']))
			{
				//for now we only use MFA for cpsessions so if this isn't a moderator
				//MFA is irrelevant.
			 	if($isAdmin OR $isMod)
				{
					//this is true if
					//a) The requester is somebody allowed to know it
					//b) MFA is enabled
					//c) The user queried is an admin or a mod
					$userInfo['showMFATab'] = true;
				}
			}
			// let's also stick in the isAdmin / isMod data here.
			// ATM this is used in the usersettings_privacy template to display a warning for
			// privacy consent withdrawal for admins.
			$userInfo['is_admin'] = $isAdmin;
			//$userInfo['is_mod'] = $isMod; // not used yet.
		}

		$userInfo['editor_options'] = $editorOptions;
		return $userInfo;
	}

	/**
	* Fetches an array containing info for the specified user, or false if user is not found
	*
	* Values for Option parameter:
	* avatar - Get avatar
	* admin - Join the administrator table to get various admin options
	* signpic - Join the sigpic table to get the userid just to check if we have a picture
	* isfriend - Is the logged in User a friend of this person?
	* Therefore: array('avatar', 'location') means 'Get avatar' and 'Process online location'
	*
	 * @param integer $ User ID
	 * @param array $ Fetch Option (see description)
	 * @param integer $ Language ID. If set to 0, it will use user-set languageid (if exists) or default languageid
	 * @param boolean $ If true, the method won't use user cache but fetch information from DB.
	* @return array The information for the requested user
	*/
	public function fetchUserinfo($userid = false, $option = array(), $languageid = false, $nocache = false)
	{
		$currentUserId = vB::getCurrentSession()->get('userid');
		$userid = intval($userid);

		if ($userid <= 0 AND $currentUserId)
		{
			$userid = $currentUserId;
		}

		if ($languageid === false)
		{
			$languageid = vB::getCurrentSession()->get('languageid');
		}

		//If we just want avatar info, we can proceed.
		if (($userid != $currentUserId) AND ($option != array(vB_Api_User::USERINFO_AVATAR)))
		{
			if(!$this->hasAdminPermission('canadminusers'))
			{
				return $this->fetchProfileInfo($userid);
			}
		}

		$userInfo = $this->library->fetchUserinfo($userid, $option, $languageid, $nocache);

		if ($userInfo)
		{
			$userInfo = $this->sanitizeUserInfo($userInfo, $currentUserId);
		}

		return $userInfo;
	}

	/**
	 * Fetches an array containing info for the current user
	 *
	 * @return array The information for the requested user. Userinfo record plus language information
	 */
	public function fetchCurrentUserinfo()
	{
		$session = vB::getCurrentSession();

		//if this is called if there's an error during initialization, and we have nothing yet
		if (empty($session))
		{
			return array();
		}

		$userInfo = $session->fetch_userinfo();
		$vboptions = vB::getDatastore()->getValue('options');

		$languageid = $session->get('languageid');
		if (!$languageid)
		{
			$languageid = $vboptions['languageid'];

			if (!empty($userInfo['languageid']) AND $userInfo['languageid'] != $languageid)
			{
				$languageid = $userInfo['languageid'];
			}

			$session->set('languageid', $languageid);
			$session->loadLanguage();
			$userInfo = $session->fetch_userinfo();
		}

		// Templates can use this flag to display/skip pmchat specific stuff.
		$check = vB_Api::instanceInternal('pmchat')->canUsePMChat();
		$userInfo['canUsePMChat'] = (bool) $check['canuse'];

		return $this->sanitizeUserInfo($userInfo, $session->get('userid'));
	}

	/**
	 * Fetches the username for a userid, or false if user is not found
	 *
	 * @param integer $ User ID
	 * @return string
	 */
	public function fetchUserName($userid)
	{
		if (!intval($userid))
		{
			return false;
		}

		return $this->library->fetchUserName($userid);
	}

	/**
	 * fetches the proper username markup and title
	 *
	 * @param array $user User info array
	 * @param string $displaygroupfield Name of the field representing displaygroupid in the User info array
	 * @param string $usernamefield Name of the field representing username in the User info array
	 * @return string Username with markup and title
	 */
	public function fetchMusername($user, $displaygroupfield = 'displaygroupid', $usernamefield = 'username')
	{
		vB_User::fetchMusername($user, $displaygroupfield, $usernamefield);

		return $user['musername'];
	}

	/**
	 * Fetch user by its username
	 *
	 * @param string $username Username
	 * @param array $option Fetch Option (see description of fetchUserinfo())
	 * @return array The information for the requested user
	 */
	public function fetchByUsername($username, $option = array())
	{
		$userid = vB::getDbAssertor()->getField('user', array(
			'username' => $username,
			vB_dB_Query::COLUMNS_KEY => array('userid'),
		));

		if (!$userid)
		{
			return false;
		}
		else
		{
			//if this was added we might need a cache refresh.
			$result = $this->fetchUserinfo($userid, $option);

			//not entirely sure what this is for.  It's problematic in a lot of ways.  The correct
			//solution is to clear the cache for whatever is causing an incorrect result to appear
			//from the first call.  Due to the wierd fetchProfileInfo hack in fetchUserinfo we can't
			//just call that with the cache clear either.  It's not clear that due to that hack
			//that the function will return precisely the same information if we hit this case.
			//However cleaning all this up is beyond the scope of the current effort.
			if (empty($result))
			{
				//we know the information is there. We got a userid force so we need to force a refresh.
				$currentUserId = vB::getCurrentSession()->get('userid');
				$result = vB_User::fetchUserinfo($userid, $option, vB::getCurrentSession()->get('languageid'), true);
				$result = $this->sanitizeUserInfo($result, $currentUserId);
			}
			return $result;
		}
	}

	/**
	 * Fetch user by its email
	 *
	 * @param string $email Email
	 * @param array $option Fetch Option (see description of fetchUserinfo())
	 * @return array The information for the requested user
	 */
	public function fetchByEmail($email, $option = array())
	{
		$userid = vB::getDbAssertor()->getField('user', array(
			'email' => $email,
			vB_dB_Query::COLUMNS_KEY => array('userid'),
		));

		if (!$userid)
		{
			return false;
		}
		else
		{
			return $this->fetchUserinfo($userid, $option);
		}
	}

	/**
	 * Fetch a list of user based on the provided criteria
	 *
	 * Will only return a user if their primary user group has the
	 * viewable on the memberslist option set.
	 *
	 * @param array $criteria
	 * 	values for criteria:
	 * 	int $pagenumber the page to start from
	 * 	int $perpage number of members to display on a page
	 * 	string $sortfield the foeld to sort by
	 * 	string $sortorder the sort order (asc/desc)
	 * 	string $startswith the first letter(s) the username should match
	 *
	 * @return array
	 * 		members - the list of members that match the criteria
	 * 		pagingInfo - pagination information
	 */
	public function memberList($criteria = array())
	{
		if (!vB::getUserContext()->hasPermission('genericpermissions', 'canviewmembers'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$default = array(
			'pagenumber' => 1,
			'perpage' => 25,
			'sortfield' => 'username',
			'sortorder' => 'ASC',
		);

		if (!is_array($criteria))
		{
			$criteria = $default;
		}

		$criteria = $criteria + $default;
		$pagingInfo = array(
			'currentpage' => $criteria['pagenumber'],
			'perpage' => $criteria['perpage'],
		);

		$data = array(
			vB_dB_Query::PARAM_LIMITPAGE => $criteria['pagenumber'],
			vB_dB_Query::PARAM_LIMIT => $criteria['perpage'],
			'sortfield' => $criteria['sortfield'],
			'sortorder' => $criteria['sortorder'],
		);

		$condition = array();
		if (!empty($criteria['startswith']))
		{
			$data['startswith'] = $criteria['startswith'];
			$condition = array(
				array('field' => 'username', 'value' => $criteria['startswith'], 'operator' => vB_dB_Query::OPERATOR_BEGINS)
			);
		}
		if (!empty($criteria['username']))
		{
			$data['username'] = $criteria['username'];
			$condition = array(
				array('field' => 'username', 'value' => $criteria['username'], 'operator' => vB_dB_Query::OPERATOR_BEGINS)
			);
		}

		$usergroupids = vB_Library::instance('usergroup')->getMemberlistGroups();
		$condition['usergroupid'] = $usergroupids;
		$data['usergroupid'] = $usergroupids;

		$db = vB::getDbAssertor();

		$members = array();
		$members_list = $db->assertQuery('fetchMemberList', $data);
		foreach ($members_list AS $member)
		{
			vB_User::expandOptions($member);
			$member['reputationimg'] = vB_Library::instance('reputation')->fetchReputationImageInfo($member);
			$members[$member['userid']] = $member;
		}

		if (!empty($criteria['startswith']) AND $criteria['startswith'] == '#')
		{
			$pagingInfo['records'] = $db->getField('usersCountStartsWithNumber', array('usergroupid' => $usergroupids));
		}
		else
		{
			$pagingInfo['records'] = $db->getField('user', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
				vB_dB_Query::CONDITIONS_KEY => $condition,
			));
		}
		$pagingInfo['totalpages'] = ceil($pagingInfo['records'] / $pagingInfo['perpage']);

		$avatars = $this->fetchAvatars(array_keys($members), false);
		foreach ($avatars AS $userid => $avatar)
		{
			$members[$userid]['avatarpath'] = $avatar['avatarpath'];
		}

		return array('members' => $members, 'pagingInfo' => $pagingInfo);
	}

	/**
	 * Find user
	 *
	 * @param array $user An array of common conditions for user search
	 * @param array $profile An array of user profile field conditions for user search
	 * @param string $orderby Order by
	 * @param string $direction Order direction
	 * @param integer $limitstart Limit start
	 * @param integer $limitnumber Limit number
	 * @return bool |array False if no user found. Otherwise it returns users array as result.
	 *		 The array also contains a field that stores total found user count.
	 */
	public function find($user, $profile, $orderby, $direction, $limitstart = 0, $limitnumber = 25)
	{
		$this->checkHasAdminPermission('canadminusers');
		require_once(DIR . '/includes/class_core.php');
		require_once(DIR . '/includes/adminfunctions_user.php');
		require_once(DIR . '/includes/adminfunctions_profilefield.php');

		$db = vB::getDbAssertor();

		$conditions = $this->fetchUserSearchCondition($user, $profile);
		$countusers = $db->getField('userFindCount', array(
			'filters' => $conditions['filters'],
			'exceptions' => $conditions['exceptions'],
			'unions' => (isset($conditions['unions'])? $conditions['unions'] : array()),
		));

		$users = $db->getRows('userFind', array(
			'filters' => $conditions['filters'],
			'exceptions' => $conditions['exceptions'],
			'unions' => (isset($conditions['unions'])? $conditions['unions'] : array()),
			'orderby' => $orderby,
			'direction' => $direction,
			'limitstart' => $limitstart,
			vB_dB_Query::PARAM_LIMIT => $limitnumber,
		));

		if ($countusers == 0)
		{
			// no users found!
			return false;
		}
		else
		{
			return array(
				'users' => $users,
				'count' => $countusers,
			);
		}
	}

	/**
	 * This returns a user's additional permissions from the groupintopic table
	 *
	 *	@param int $userid
	 *	@param int $nodeid -- optional
	 *	@param boolean $forceReload -- optional defaults to false
	 *
	 *	@return	array -- Array of  array('nodeid' => nodeid, 'groupid' => groupid);
	 */
	public function getGroupInTopic($userid = false, $nodeid = false, $forceReload = false)
	{
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		$currentUserId = $userInfo['userid'];
		//we need a single int for userid;
		if (!$userid)
		{
			$userid = $currentUserId;
		}
		else if (!is_numeric($userid) OR !intval($userid))
		{
			throw new vB_Exception_Api('invalid_request');
		}
		else
		{
			$userid = intval($userid);
		}

		//check permissions
		if (($userid != $currentUserId) AND
			!vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canaddowners', $nodeid ))
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->getGroupInTopic($userid, $nodeid, $forceReload);
	}

	/**
	 * Returns a list of channels where this user is moderator
	 *
	 * @param	int $userid
	 * @return array -- nodeids
	 */
	public function getModeratorsOf($userid = false)
	{
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		$currentUserId = $userInfo['userid'];
		//we need a single int for userid;
		if (!$userid)
		{
			$userid = $currentUserId;
		}
		else if (!is_numeric($userid) OR !intval($userid))
		{
			throw new vB_Exception_Api('invalid_request');
		}
		else
		{
			$userid = intval($userid);
		}

		//check permissions
		if (($userid != $currentUserId) AND
			!vB::getUserContext()->hasAdminPermission('canadminpermissions'))
		{
			//this requires admin canadminpermissions or that it be for the current user.
			throw new vB_Exception_Api('no_permission');
		}

		if (!isset($this->moderatorsOf[$userid]))
		{
			$this->computeMembersOf($userid);
		}
		return $this->moderatorsOf[$userid];

	}

	/**
	 * Returns a list of channels where this user is moderator
	 *
	 * @param	int $userid
	 * @return array -- nodeids
	 */
	public function getMembersOf($userid = false)
	{
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		$currentUserId = $userInfo['userid'];
		//we need a single int for userid;
		if (!$userid)
		{
			$userid = $currentUserId;
		}
		else if (!is_numeric($userid) OR !intval($userid))
		{
			throw new vB_Exception_Api('invalid_request');
		}
		else
		{
			$userid = intval($userid);
		}

		//check permissions
		if (($userid != $currentUserId) AND
			!vB::getUserContext()->hasAdminPermission('canadminpermissions'))
		{
			//this requires admin canadminpermissions or that it be for the current user.
			throw new vB_Exception_Api('no_permission');
		}

		if (!isset($this->membersOf[$userid]))
		{
			$this->computeMembersOf($userid);
		}
		return $this->membersOf[$userid];
	}

	/**
	 * This is a wrapper for userContext getCanCreate- it returns the content types a user can create
	 *
	 *	@param	int $nodeid
	 *	@return array -- types the user can create in that node
	 */
	public function getCanCreate($nodeid)
	{
		if (empty($nodeid))
		{
			return false;
		}
		return vB::getUserContext()->getCanCreate($nodeid);
	}

	/**
	 * Analyzes what groups this user belongs to in specific channels. Stores in member variables
	 *
	 * @param	int $userid
	 */
	protected function computeMembersOf($userid)
	{
		$hashKey = "vB_MembersOf_$userid";
		$cached = vB_Cache::instance(vB_Cache::CACHE_STD)->read($hashKey);
		if ($cached !== false)
		{
			$this->membersOf[$userid] = $cached['membersOf'];
			$this->moderatorsOf[$userid] = $cached['moderatorsOf'];;
			return;
		}
		$this->membersOf[$userid] = $this->moderatorsOf[$userid] = array();

		$groupInTopic = $this->library->getGroupInTopic($userid);

		if (empty($this->permissionContext))
		{
			$this->permissionContext = new vB_PermissionContext(vB::getDatastore(), 2, null, null);
		}

		//scan the groups and set the array

		foreach ($groupInTopic as $permission)
		{
			$groupid = $permission['groupid'];
			$nodeid = false;

			if ($this->permissionContext->getChannelPermSet($groupid, $permission['nodeid']))
			{
				$nodeid = $permission['nodeid'];
			}
			else
			{
				$parentage = vB_Library::instance('node') -> fetchClosureParent($permission['nodeid']);
				foreach ($parentage as $parent)
				{
					if ($this->permissionContext->getChannelPermSet($groupid, $parent['parent']))
					{
						$nodeid = $parent['parent'];
						break;
					}
				}
			}

			//If we got a node with permissions we need to check what they are.
			if ($nodeid)
			{
				if (!in_array($permission['nodeid'], $this->membersOf[$userid]) AND
					$this->permissionContext->getChannelPerm($groupid, 'createpermissions', 'vbforum_privatemessage', $nodeid) > 0)
				{
					$this->membersOf[$userid][] =  $permission['nodeid'] ;
				}
				if (!in_array($permission['nodeid'], $this->moderatorsOf[$userid]) AND
					$this->permissionContext->getChannelPerm($groupid, 'moderatorpermissions', 'canmoderateposts', $nodeid) > 0)
				{
					$this->moderatorsOf[$userid][] =  $permission['nodeid'] ;
				}
			}
		}
		$cacheData = array('membersOf' => $this->membersOf[$userid], 'moderatorsOf' => $this->moderatorsOf[$userid]);
		vB_Cache::instance(vB_Cache::CACHE_STD)->write($hashKey, $cacheData, 1440, "userPerms_$userid");
	}

	/**
	 * This grants a user additional permissions in a specific channel, by adding to the groupintopic table
	 *
	 * @param	int $userid
	 * @param	array|int $nodeids
	 * @param	int $usergroupid
	 *
	 * @return	bool
	 */
	public function setGroupInTopic($userid, $nodeids, $usergroupid)
	{
		//check the data.
		if (!is_numeric($userid) OR !is_numeric($usergroupid))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		else
		{
			$nodeids = array_unique($nodeids);
		}

		$usercontext = vB::getUserContext();
		//check permissions
		foreach ($nodeids AS $nodeid)
		{
			if (!$usercontext->getChannelPermission('moderatorpermissions', 'canaddowners', $nodeid ))
			{
				throw new vB_Exception_Api('no_permission');
			}

		}

		//class vB_User does the actual work. Here we just want to clean the data.
		return vB_User::setGroupInTopic($userid, $nodeids, $usergroupid);
	}


	/**
	 * This removes additional permissions a user was given in a specific channel, by removing from the groupintopic table
	 *
	 *	@param	int		$userid		user for whom we are unsetting GIT records
	 *	@param	array|int	$nodeids	(integer or array of integers) nodeid(s) of the GIT record(s) to unset
	 * 	@param	int		$usergroupid	usergroupid of the GIT record to unset
	 *
	 *	@return	bool
	 */
	public function unsetGroupInTopic($userid, $nodeids, $usergroupid)
	{
		//check the data.
		if (!is_numeric($userid) OR !is_numeric($usergroupid))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		else
		{
			$nodeids = array_unique($nodeids);
		}

		//check permissions
		$usercontext = vB::getUserContext();
		//this requires moderatorpermissions->canmoderatetags
		foreach ($nodeids as $nodeid)
		{
			if (
				(!$usercontext->getChannelPermission('moderatorpermissions', 'canaddowners', $nodeid )) AND
				!($userid == $usercontext->fetchUserId())
			)
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		//and do the deletes
		foreach ($nodeids as $nodeid)
		{
			vB::getDbAssertor()->assertQuery(
				'vBForum:groupintopic', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'userid'  => $userid,
					'nodeid'  => $nodeid,
					'groupid' => $usergroupid)
			);

			//deny any pending request
			$pending = vB::getDbAssertor()->assertQuery('vBForum:fetchPendingChannelRequestUser', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'msgtype' => 'request',
					'aboutid' => $nodeid,
					'about' => array(
											vB_Api_Node::REQUEST_TAKE_MODERATOR,
											vB_Api_Node::REQUEST_TAKE_OWNER,
											vB_Api_Node::REQUEST_SG_TAKE_MODERATOR,
											vB_Api_Node::REQUEST_SG_TAKE_OWNER
										),
					'userid' => $userid
				)
			);
			if ($pending)
			{
				$messageLib = vB_Library::instance('content_privatemessage');
				foreach($pending as $p)
				{
					$messageLib->denyRequest($p['nodeid'], $userid);
				}
			}
		}
		vB_Cache::allCacheEvent(array("userPerms_$userid", "followChg_$userid", "sgMemberChg_$userid"));
		vB_Api::instanceInternal('user')->clearChannelPerms($userid);
		vB::getUserContext($userid)->reloadGroupInTopic();
		vB::getUserContext()->clearChannelPermissions();
		//if we got here all is well.
		return true;
	}


	/**
	 * This method clears remembered channel permission
	 *
	 * @param int The userid to be cleared
	 */
	public function clearChannelPerms($userid)
	{
		if (isset($this->membersOf[$userid]))
		{
			unset($this->membersOf[$userid]);
			unset($this->moderatorsOf[$userid]);
		}

		$this->library->clearChannelPerms($userid);
	}

	/**
	 * Registers userids that we will later be fetching avatars for. If we
	 * register the userids here, they can be fetched in batches.
	 *
	 * @param array Array if integer user IDs for the users whose avatars we will be fetching later.
	 */
	public function registerNeedAvatarForUsers($userids)
	{
		foreach ($userids AS $userid)
		{
			if (empty($this->loadedAvatarUserids[$userid]))
			{
				$this->pendingAvatarUserids[$userid] = $userid;
			}
		}
	}

	/**
	 * Fetches the URL for a User's Avatar
	 *
	 * @param integer $ The User ID
	 * @param boolean $ Whether to get the Thumbnailed avatar or not
	 * @return array Information regarding the avatar
	 */
	public function fetchAvatar($userid, $thumb = false, $userinfo = array())
	{
		// fetchAvatars wants an array of userinfos
		if (!empty($userinfo))
		{
			$userinfo = array($userinfo['userid'] => $userinfo);
		}
		else
		{
			$userinfo = array();
		}
		$result = $this->fetchAvatars(array($userid), $thumb, $userinfo);

		if (!empty($result[$userid]))
		{
			$avatarurl = $result[$userid];
		}
		$userContext = vB::getUserContext($userid);
		$profileInfo = vB_User::fetchUserinfo($userid);

		if (// no avatar defined for this user
			empty($avatarurl)
			//TODO: Decide how we will handle the showavatars user option. We should add to the wireframe or remove the bitfield
			/*OR // user doesn't want to see avatars
			!$avatarinfo['showavatars']
			*/
			OR // user has a custom avatar but no permission to display it
			($avatarurl['hascustom'] AND !$userContext->hasPermission('genericpermissions', 'canuseavatar')
					AND !$userContext->isAdministrator() AND !$profileInfo['adminavatar'])
		)
		{
			return false;
		}

		return $avatarurl;
	}

	/**
	 * Fetch the Avatars for a userid array
	 *
	 * @param array The User IDs array
	 * @param boolean $ Whether to get the Thumbnailed avatar or not
	 * @param array	Array of userinfo, possibly already containing the avatar information
	 * @return array Information regarding the avatar
	 */
	public function fetchAvatars($userids = array(), $thumb = false, $userinfo = array())
	{
		$requestedUserids = $userids;

		// add userids that have been flagged as needing avatars via registerNeedAvatarForUsers()
		foreach ($this->pendingAvatarUserids AS $userid)
		{
			$userids[] = $userid;
			$this->loadedAvatarUserids[$userid] = $userid;
		}
		$this->pendingAvatarUserids = array();

		// cache avatar information from the passed userinfo array
		foreach ($userinfo AS $userid => $_userinfo)
		{
			if (!isset($this->avatarUserCache[$userid]) AND isset($_userinfo['hascustomavatar']))
			{
				$this->avatarUserCache[$userid] = array(
					'userid'         => $_userinfo['userid'],
					'avatarid'       => $_userinfo['avatarid'],
					'avatarpath'     => $_userinfo['avatarpath'],
					'avatarrevision' => $_userinfo['avatarrevision'],
					'dateline'       => $_userinfo['avatardateline'],
					'width'          => $_userinfo['avwidth'],
					'height'         => $_userinfo['avheight'],
					'height_thumb'   => $_userinfo['avheight_thumb'],
					'width_thumb'    => $_userinfo['avwidth_thumb'],
				);
			}
		}

		if(empty($userids))
		{
			return array();
		}

		if (empty($thumb))
		{
			$typekey = 'avatar';
		}
		elseif ($thumb === 'profile')
		{
			$typekey = 'profile';
			$thumb = false;
		}
		else
		{
			$typekey = 'thumb';
		}

		$cachedKeys = array();
		if (isset($this->avatarsCache[$typekey]))
		{
			$cachedKeys = array_keys($this->avatarsCache[$typekey]);
		}

		$notCachedKeys = array_diff($userids, $cachedKeys);
		$notCached = array_combine($notCachedKeys, $notCachedKeys);

		// load any non-cached avatars into $this->avatarsCache, either
		// from $this->avatarUserCache or by querying the database
		if(!empty($notCached))
		{
			$options = vB::getDatastore()->getValue('options');
			$avatars = array();

			foreach($notCached AS $userid)
			{
				if (isset($this->avatarUserCache[$userid]))
				{
					$avatars[$userid] = $this->avatarUserCache[$userid];
					unset($notCached[$userid]); // key and value of $notCached are both the userid
				}
			}

			if (!empty($notCached))
			{
				$avatarsinfo = vB::getDbAssertor()->assertQuery('vbForum:fetchAvatarsForUsers', array('userid' => $notCached));
				foreach ($avatarsinfo AS $user)
				{
					$this->avatarUserCache[$user['userid']] = $user;
					$avatars[$user['userid']] = $user;
				}
			}

			$avatarpaths = array();
			foreach ($avatars AS $user)
			{
				$userid = $user['userid'];
				$this->avatarsCache[$typekey][$userid]['avatarurl'] = array();
				if (!empty($user['avatarid']))
				{
					if(!isset($avatarpaths[$user['avatarid']]))
					{
						$avatarpath = $user['avatarpath'];
						//If this is an absolute path we must trim the DIR portion
						if (substr($avatarpath, 0, strlen(DIR)) == DIR)
						{
							$avatarpath = substr($avatarpath, strlen(DIR) + 1);
						}

						$avatarpaths[$user['avatarid']] = array('hascustom' => 0, 'avatarpath' => $avatarpath);
					}
					$this->avatarsCache[$typekey][$userid]['avatarurl'] = $avatarpaths[$user['avatarid']];
				}
				else
				{
					$this->avatarsCache['avatar'][$userid]['avatarurl'] = array('hascustom' => 1);
					$this->avatarsCache['thumb'][$userid]['avatarurl'] = array('hascustom' => 1);
					$this->avatarsCache['profile'][$userid]['avatarurl'] = array('hascustom' => 1);

					$defaultAvatarPath = vB_Api_User::DEFAULT_AVATAR_PATH_REGULAR;
					$defaultAvatarThumbPath = vB_Api_User::DEFAULT_AVATAR_PATH_THUMB;
					$defaultAvatarProfilePath = vB_Api_User::DEFAULT_AVATAR_PATH_LARGE;

					//the user did not select any avatars
					if ((!$user['avatarrevision'] AND !$user['dateline']) OR ($options['usefileavatar'] AND !$user['filename']))
					{
						$this->avatarsCache['avatar'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarPath;
						$this->avatarsCache['avatar'][$userid]['avatarurl']['hascustom'] = 0;
						$this->avatarsCache['thumb'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarThumbPath;
						$this->avatarsCache['thumb'][$userid]['avatarurl']['hascustom'] = 0;
						$this->avatarsCache['profile'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarProfilePath;
						$this->avatarsCache['profile'][$userid]['avatarurl']['hascustom'] = 0;
					}
					else
					{
						if ($options['usefileavatar'])
						{
							$avatarpathoption = (substr($options['avatarpath'],0,2) == './') ? substr($options['avatarpath'],2) : $options['avatarpath'];
							$userAvatar = $avatarpathoption . "/{$user['filename']}";
							$userThumb = $avatarpathoption . "/thumbs/{$user['filename']}";
							if(file_exists(DIR . "/" . $userAvatar) AND file_exists(DIR . "/" . $userThumb))
							{
								$this->avatarsCache['avatar'][$userid]['avatarurl']['avatarpath'] = $userAvatar;
								$this->avatarsCache['thumb'][$userid]['avatarurl']['avatarpath'] = $userThumb;
								$this->avatarsCache['profile'][$userid]['avatarurl']['avatarpath'] = $userAvatar;
							}
							else
							{
								$this->avatarsCache['avatar'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarPath;
								$this->avatarsCache['avatar'][$userid]['avatarurl']['hascustom'] = 0;
								$this->avatarsCache['thumb'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarThumbPath;
								$this->avatarsCache['thumb'][$userid]['avatarurl']['hascustom'] = 0;
								$this->avatarsCache['profile'][$userid]['avatarurl']['avatarpath'] = $defaultAvatarProfilePath;
								$this->avatarsCache['profile'][$userid]['avatarurl']['hascustom'] = 0;
							}
						}
						else
						{
							$add_session = (class_exists('vB5_Cookie') AND vB5_Cookie::isEnabled()) ? '' : vB::getCurrentSession()->get('sessionurl');
							$this->avatarsCache['avatar'][$userid]['avatarurl']['avatarpath'] = "image.php?" . $add_session . "userid=$userid";
							$this->avatarsCache['thumb'][$userid]['avatarurl']['avatarpath'] = "image.php?" . $add_session . "userid=$userid&thumb=1";
							$this->avatarsCache['profile'][$userid]['avatarurl']['avatarpath'] = "image.php?" . $add_session . "userid=$userid&profile=1";

							if (!empty($user['dateline']))
							{
								$this->avatarsCache['profile'][$userid]['avatarurl']['avatarpath'] .= '&dateline=' . $user['dateline'];
								$this->avatarsCache['thumb'][$userid]['avatarurl']['avatarpath'] .= '&dateline=' . $user['dateline'];
								$this->avatarsCache['avatar'][$userid]['avatarurl']['avatarpath'] .= '&dateline=' . $user['dateline'];
							}
						}
					}
					/* This code was used in vB3 & 4 to passback the avatar image sizes for use in the templates
					As far as I can tell, no vB5 templates make use of this, so I have commented it out for now */
//					if ($thumb)
//					{
//						if (isset($user['width_thumb']) AND isset($user['height_thumb']))
//						{
//							$avatarurl[] = " width=\"$user[width_thumb]\" height=\"$user[height_thumb]\" ";
//						}
//					}
//					else
//					{
//						if (isset($user['width']) AND isset($user['height']))
//						{
//							$avatarurl[] = " width=\"$user[width]\" height=\"$user[height]\" ";
//						}
//					}

				}
			}
		}

		// prepare return value

		if (empty($requestedUserids))
		{
			return array();
		}

		// We usually hit this for guests
		$defaults = array(
			'avatar' => array(
				'avatarpath' => vB_Api_User::DEFAULT_AVATAR_PATH_REGULAR,
				'hascustom' => 0,
			),
			'thumb' => array(
				'avatarpath' => vB_Api_User::DEFAULT_AVATAR_PATH_THUMB,
				'hascustom' => 0,
			),
			'profile' => array(
				'avatarpath' => vB_Api_User::DEFAULT_AVATAR_PATH_LARGE,
				'hascustom' => 0,
			),
		);

		$return = array();
		foreach ($requestedUserids AS $requestedUserid)
		{
			if (!empty($this->avatarsCache[$typekey][$requestedUserid]))
			{
				$return[$requestedUserid] = $this->avatarsCache[$typekey][$requestedUserid]['avatarurl'];
			}
			else
			{
				$return[$requestedUserid] = $defaults[$typekey];

			}
		}

		return $return;
	}

	/**
	 * Fetches the Profile Fields that needs to be displayed in Registration From
	 *
	 * @param array $userinfo User information as fields' current value
	 * @return array Profile fields
	 */
	public function fetchProfileFieldsForRegistration($userinfo = array())
	{
		$profilefields = vB::getDbAssertor()->getRows('user_fetchprofilefieldsforregistration');
		$this->_processProfileFields($profilefields, $userinfo);
		return $profilefields;
	}

	/**
	 * Process Profile Fields for templates
	 *
	 * @param array $profilefields (ref) Profile fields (database records array) to be processed.
	 * @param array $currentvalues Current values of the profile fields
	 * @return void
	 */
	protected function _processProfileFields(&$profilefields, $currentvalues)
	{

		$phraseapi = vB_Api::instanceInternal('phrase');

		$customfields_other = array();
		$customfields_profile = array();
		$customfields_option = array();

		foreach ($profilefields as $field)
		{
			$field['fieldname'] = "field$field[profilefieldid]";
			$field['optionalname'] = $field['fieldname'] . '_opt';

			$titleanddescription = $phraseapi->fetch(array($field['fieldname'] . '_title', $field['fieldname'] . '_desc'));

			$field['title'] = $titleanddescription[$field['fieldname'] . '_title'];
			$field['description'] = $titleanddescription[$field['fieldname'] . '_desc'];

			$field['foundfield'] = 0;

			$field['currentvalue'] = '';
			if ($currentvalues)
			{
				$field['currentvalue'] = $currentvalues['userfield'][$field['fieldname']];
			}

			if ($field['type'] == 'select')
			{
				$field['data'] = unserialize($field['data']);

				$field['bits'] = array();
				foreach ($field['data'] as $key => $val)
				{
					$key++;
					$field['bits'][$key]['val'] = $val;
					$field['bits'][$key]['selected'] = false;
					if (isset($field['currentvalue']))
					{
						if (trim($val) == $field['currentvalue'])
						{
							$field['bits'][$key]['selected'] = true;
							$field['foundfield'] = 1;
						}
					}
					else if ($field['def'] AND $key == 1)
					{
						$field['bits'][$key]['selected'] = true;
						$field['foundfield'] = 1;
					}
				}

				// No empty option
				if (!$field['foundfield'])
				{
					$field['selected'] = true;
				}
				else
				{
					$field['selected'] = false;
				}

			}
			elseif ($field['type'] == 'select_multiple')
			{
				$field['data'] = unserialize($field['data']);
				if ($field['height'] == 0)
				{
					$field['height'] = count($field['data']);
				}

				$field['bits'] = array();
				foreach ($field['data'] as $key => $val)
				{
					$key++;
					$field['bits'][$key]['val'] = $val;
					$field['bits'][$key]['selected'] = false;
					if ($field['currentvalue'] & pow(2, $key - 1))
					{
						$field['bits'][$key]['selected'] = true;
					}
					else
					{
						$field['bits'][$key]['selected'] = false;
					}
				}
			}
			elseif ($field['type'] == 'checkbox')
			{
				$field['data'] = unserialize($field['data']);

				$field['bits'] = array();
				foreach ($field['data'] as $key => $val)
				{
					$key++;
					$field['bits'][$key]['val'] = $val;
					$field['bits'][$key]['selected'] = false;
					if ($field['currentvalue'] & pow(2, $key - 1))
					{
						$field['bits'][$key]['selected'] = true;
					}
					else
					{
						$field['bits'][$key]['selected'] = false;
					}
				}
			}
			elseif ($field['type'] == 'radio')
			{
				$field['data'] = unserialize($field['data']);

				$field['bits'] = array();
				foreach ($field['data'] as $key => $val)
				{
					$key++;
					$field['bits'][$key]['val'] = $val;
					$field['bits'][$key]['checked'] = false;
					if (!$field['currentvalue'] AND $key == 1 AND $field['def'] == 1)
					{
						$field['bits'][$key]['checked'] = true;
					}
					else if (trim($val) == $field['currentvalue'])
					{
						$field['bits'][$key]['checked'] = 'checked="checked"';
						$field['foundfield'] = 1;
					}
				}
			}


			if ($field['required'] == 2)
			{
				// not required to be filled in but still show
				$customfields_other[] = $field;
			}
			else // required to be filled in
			{
				if ($field['form'])
				{
					$customfields_option[] = $field;
				}
				else
				{
					$customfields_profile[] = $field;
				}
			}

		}

		$profilefields = array(
			'other' => $customfields_other,
			'option' => $customfields_option,
			'profile' => $customfields_profile,
		);
	}

	/**
	 * Delete a user
	 *
	 * @param integer 	int 	 	The ID of user to be deleted
	 * @param bool 		boolean 	Whether to transfer the Groups and Blogs owned by the user to current logged-in admininstrator
	 */
	public function delete($userid, $transfer_groups = true)
	{
		$this->checkHasAdminPermission('canadminusers');

		// Admin userid to transfer groups & blogs to.
		if ($transfer_groups)
		{
			$adminuserid = vB::getCurrentSession()->fetch_userinfo_value('userid');
		}
		else
		{
			$adminuserid = null;
		}

		return $this->library->delete($userid, $transfer_groups, $adminuserid);
	}

	/**
	 * Shortcut to saving only email and password if user only has permission to modify password and email
	 *
	 * Saves the email and password for the current logged in user.
	 *
	 * @param array $extra Generic flags or data to affect processing.
	 *	*email -- email to set
	 *	*newpass -- new password to set
	 *	*password -- existing password to verify (we verify passwords before changing email/password)
	 *
	 * @return integer New or updated userid.
	 */
	private function saveEmailPassword($extra)
	{
		$context = vB::getUserContext();
		$userid = $context->fetchUserId();
		if (!$userid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		// Password & email
		if (!empty($extra['newpass']) OR !empty($extra['email']))
		{
			if (!$extra['password'])
			{
				throw new vB_Exception_Api('enter_current_password');
			}

			$loginlib = vB_Library::instance('login');

			$userinfo = vB_User::fetchUserinfo($userid);
			$login = array_intersect_key($userinfo, array_flip(array('userid', 'token', 'scheme')));
			$auth = $loginlib->verifyPasswordFromInfo($login, array(array('password' => $extra['password'], 'encoding' => 'text')));

			if (!$auth['auth'])
			{
				throw new vB_Exception_Api('badpassword', vB5_Route::buildUrl('lostpw|fullurl'));
			}

			$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
			$userdata->set_existing($userinfo);

			if (!empty($extra['newpass']))
			{
				$loginlib->setPassword($userinfo['userid'], $extra['newpass'],
					array('passwordhistorylength' => $context->getUsergroupLimit('passwordhistory'))
				);

				//the secret really isn't related to the password, but we want to change it
				//periodically and for now "every time the user changes their password"
				//works (we previously used the password salt so that's when it got changed
				//prior to the refactor).
				$userdata->set('secret', vB_Library::instance('user')->generateUserSecret());
			}

			//save the email if set
			if (!empty($extra['email']))
			{
				$userdata->set('email', $extra['email']);
			}

			if ($userdata->has_errors(false))
			{
				throw $userdata->get_exception();
			}
			$userdata->save();

			// clear user info cached
			$this->library->clearUserInfo(array($userid));
			vB_Cache::instance(vB_Cache::CACHE_FAST)->event('userChg_' . $userid);
			vB_Cache::instance(vB_Cache::CACHE_LARGE)->event('userChg_' . $userid);
		}

		return vB::getUserContext()->fetchUserId();
	}

	/**
	 * Insert or Update an user
	 *
	 * @param integer $userid Userid to be updated. Set to 0 if you want to insert a new user.
	 * @param string $password Password for the user. Empty means no change.  May be overriden by the $extra array
	 * @param array $user Basic user information such as email or home page
	 * 	* username
	 * 	* email
	 * 	* usertitle
	 * 	* birthday
	 * 	* usergroupid (will get no_permissions exception without administrate user permissions)
	 * 	* membergroupids (will get no_permissions exception without administrate user permissions)
	 *  * privacyconsent   int  -1|0|1 meaning Privacy-Consent Withdrawn|Unknown|Given respectively.
	 *	* list not complete
	 * @param array $options vB options for the user
	 * @param array $adminoptions Admin Override Options for the user
	 * @param array $userfield User's User Profile Field data
	 * @param array $notificationOptions
	 * @param array $hvinput Human Verify input data. @see vB_Api_Hv::verifyToken()
	 * @param array $extra Generic flags or data to affect processing.
	 *	* email
	 *	* newpass
	 *	* password
	 *	* acnt_settings => 1 if we are editing the user as a normal user (suppresses
	 *		adminoverride if the user is an admin.  This is really misnamed and only treats
	 *		the request as from a normal user even if the user is an admin.
	 *	* fbautoregister => true if we are using the FB quick registration.  This skips some checks
	 *		such as the HV *if* we actually have a facebook account
	 * @return integer New or updated userid.
	 */
	public function save(
		$userid,
		$password,
		$user,
		$options,
		$adminoptions,
		$userfield,
		$notificationOptions = array(),
		$hvinput = array(),
		$extra = array()
	)
	{
		$db = vB::getDbAssertor();
		$datastore = vB::getDatastore();
		$userContext = vB::getUserContext();
		$request = vB::getRequest();

		$vboptions = $datastore->getValue('options');
		$currentUserId = $userContext->fetchUserId();
		$userid = intval($userid);
		$coppauser = false;

		//set up some booleans to control behavior.  This is done to simply/document the later code
		$newuser = (!$userid);
		$canadminusers = $this->hasAdminPermission('canadminusers');
		$adminoverride = ($canadminusers AND empty($extra['acnt_settings']) AND empty($extra['acnt_settings']));
		$changingCurrentUser = ($userid == $currentUserId);

		$targetUserIsAdmin = false;
		if (!$newuser)
		{
			$targetUserContext = vB::getUserContext($userid);
			$targetUserIsAdmin = $targetUserContext->isAdministrator();
			if (isset($user['privacyconsent']) AND $user['privacyconsent'] == -1 AND $targetUserIsAdmin)
			{
				throw new vB_Exception_Api('privacyconsent_admincannotwithdraw');
			}
		}
		else
		{
			$fblib = vB_Library::instance('facebook');

			//if this is an override scenario then the FB user is the admin user and we don't want to
			//process as a facebook signup -- we don't know if the end user is an FB user and we won't link
			//the accounts.
			$isfacebooksignup = (!$adminoverride AND $fblib->isFacebookEnabled() AND $fblib->userIsLoggedIn());

			//we'll be in "autoregister" mode if a) facebook is on, b) we're configured to do it, c) we request it
			//the front end.  The front end shouldn't request it if it isn't configured but we don't trust the front end.
			$fbautoregister = ($isfacebooksignup AND $vboptions['facebookautoregister'] AND !empty($extra['fbautoregister']));

			if($fbautoregister)
			{
				//we might want a check like this for the normal facebook sign in:
				//If the fb user already has a FB account don't allow them to create an new one
				//In auto register mode we *have* to connect to an FB account or this isn't going to work
				if($fblib->getVbUseridFromFbUserid())
				{
					throw new vB_Exception_Api('facebook_user_already_connected');
				}

				//we don't require a password with FB autoregister (and, in fact, actively avoid it).
				//Ideally we'd set the password hash to something invalid like '*' which would prevent
				//a login via password entirely.  However, a bunch of logic below aggressively vaidates
				//the existence of a password and figuring out how to skip all that is more effort than
				//it's worth right now.  Instead will randomly generate a long, secure password and then
				//not tell anybody about it.
				if(!$password)
				{
					$random = new vB_Utility_Random();
					$password = $random->alphanumeric(32);
				}
			}
		}

		// Not sure why we do this at all.  The caller should handle this appropriately.
		// We shouldn't set $userid = $currentUserId if $userid == 0 here
		// Cause we may need to allow logged-in user to register again
		if ($userid < 0 AND $currentUserId)
		{
			$userid = $currentUserId;
		}

		//we'll need this all over the place if this isn't a new user.
		$userinfo = array(); // Also passed into checkEmail() (though not used) for new user, so we need to set it.
		if (!$newuser)
		{
			$userinfo = vB_User::fetchUserinfo($userid);
		}

		//something of a hack, but we don't want the DST autocorrect to fail because of general permission
		//or validation checks failures
		$onlyChangeDst = (isset($options['dstonoff']) AND count($options) == 1 AND !$extra AND
			!$password AND !$user AND !$userfield AND !$adminoptions AND !$notificationOptions);

		//check some permissions.  If we can admin users we can skip all of these checks.  Some checks
		//only apply to some cases, such as registering a newuser.  We also check various fields
		//in some cases and not others.
		if (!$canadminusers)
		{
			if ($newuser)
			{
				// Check if registration is allowed
				if (!$vboptions['allowregistration'])
				{
					throw new vB_Exception_Api('noregister');
				}

				// Check Multiple Registrations Per User
				if ($currentUserId AND !$vboptions['allowmultiregs'])
				{
					$currentUser = vB::getCurrentSession()->fetch_userinfo();
					throw new vB_Exception_Api('signing_up_but_currently_logged_in_msg', array($currentUser['username'],
						$vboptions['frontendurl'] . '/auth/logout?logouthash=' . $currentUser['logouthash']));
				}

				// If it's a new registration, we need to verify the HV
				// VBV-9386: HV is disabled when accessing through the VB_API in vb4.
				// There is also a comment saying that it should be enabled once it goes live???
				if (!$fbautoregister AND (!defined('VB_API') OR VB_API !== true))
				{
					vB_Api::instanceInternal('hv')->verifyToken($hvinput, 'register');
				}

				// Verify Stop Forum Spam
				$nospam = vB_StopForumSpam::instance();
				if (!$nospam->checkRegistration($user['username'], $request->getIpAddress(), $user['email']))
				{
					throw new vB_Exception_Api('noregister');
				}
			}

			//existing user
			else
			{
				//attempting to update somebody else's profile -- only admins can do this
				if (!$changingCurrentUser)
				{
					throw new vB_Exception_Api('no_permission');
				}

				if (!$userContext->hasPermission('genericpermissions', 'canmodifyprofile'))
				{

					//if we are only chaning the DST on/off pass this through the permission check
					if (!$onlyChangeDst)
					{
						//this is wierd.
						//1) We need to check that we aren't trying to do anything else
						//2) Should check that there is something in $extra to save.  Otherwise
						//	it succees while doing nothing
						//3) should throw "no permission" if we aren't just saving the email
						//4) saving DST and updating password without permission is technically
						//	valid (but not actually going to happen) and currently will quietly
						//	change the password without doing anything else
						//Declining to fix as part of DST bug because of potential regression.

						/*
							Adding onto this weirdness... Privacy Consent changes shouldn't be blocked by canmodifyprofile.
							Normally this will be set as any other user field via user DM, but in this case, we want to
							still allow them to provide consent.
						 */
						$update = array();
						$this->setEuStatus($vboptions, $request, $newuser, $changingCurrentUser, $adminoverride, $userinfo, $user);

						if(isset($user['eustatus']))
						{
							$update['eustatus'] = $user['eustatus'];
						}

						$privacycacheclear = false;
						if (is_array($user) AND array_key_exists('privacyconsent', $user))
						{
							$user['privacyconsent'] = intval($user['privacyconsent']);
							// Disallow withdrawal if admin disabled account removal, unless this is the admin.
							// Also do not allow setting privacyconsent back to "unknown". Once we have it, we have it.
							if ($user['privacyconsent'] == 0 OR
								$user['privacyconsent'] == -1 AND !$vboptions['enable_account_removal'] AND !$adminoverride
							)
							{
								unset($user['privacyconsent']);
								// do nothing.
							}
							else
							{
								if (!isset($userinfo['privacyconsent']) OR $userinfo['privacyconsent'] != $user['privacyconsent'])
								{
									$update['privacyconsent'] = $user['privacyconsent'];
									$update['privacyconsentupdated'] = vB::getRequest()->getTimeNow();
									$privacycacheclear = true;
								}
							}
						}

						if(count($update))
						{
							$db->update('user', $update, array("userid" => $userid));

							// These events may be issued via saveEmailPassword() as well if
							// email or password was updated, but let's make sure.
							if($privacycacheclear)
							{
								//we can do this before of after the update, it's not going to ma
								vB_Cache::instance()->event('userPrivacyChg_' . $userid);
							}
							$this->library->clearUserInfo(array($userid));
						}

						return $this->saveEmailPassword($extra);
					}
				}

				if (isset($user['privacy_options']) AND !$userContext->hasPermission('usercsspermissions', 'caneditprivacy'))
				{
					// User doesn't have permission to update privacy
					throw new vB_Exception_Api('no_permission');
				}

				if (isset($options['invisible']) AND !empty($options['invisible']) AND !$userContext->hasPermission('genericpermissions', 'caninvisible'))
				{
					// User doesn't have permission to go invisible
					throw new vB_Exception_Api('no_permission');
				}
			}

			//handle some fields that users should not be able to set (the admin can do what he wants)
			if (isset($user['usergroupid']))
			{
				throw new vB_Exception_Api('no_permission');
			}

			if(isset($user['membergroupids']))
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		/*
		 * Some checks for all cases.
		 */

		//don't allow changes to an unalterable user unless the user themselves requests it.  We might want to lock down what the
		//user can edit in this case.
		require_once(DIR . '/includes/adminfunctions.php');
		if (!$changingCurrentUser AND is_unalterable_user($userid))
		{
			throw new vB_Exception_Api('user_is_protected_from_alteration_by_undeletableusers_var');
		}

		$olduser = array();
		if ($userid != 0)
		{
			// Get old user information
			$olduser = $db->getRow('user_fetchforupdating', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				'userid'              => $userid,
			));

			if (!$olduser)
			{
				throw new vB_Exception_Api('invalid_user_specified');
			}
		}

		// if birthday is required -- but don't trigger the error if this is an exiting user and we are only
		// updating the DST value.  This isn't the cleanest thing, but we need the DST autocorrect to work
		// regardless of most permission/validation issues.
		if (($newuser OR !$onlyChangeDst) AND $vboptions['reqbirthday'] AND empty($olduser['birthday']) AND empty($user['birthday']))
		{
			if (count($userfield))
			{
				throw new vB_Exception_Api('birthdayfield');
			}
			else
			{
				throw new vB_Exception_Api('birthdayfield_nonprofile_tab');
			}
		}


		/*
		 *	If we are changing the password or email from the account setting we need to validate the users
		 *	existing password.
		 */

		//we allow stuff for the account profile page to be passed separately in the $extra array.
		//we shouldn't but cleaning that up is a larger task.
		if (!empty($extra['acnt_settings']))
		{
			if (!empty($extra['email']))
			{
				$user['email'] = $extra['email'];
			}

			//new password to set
			if (!empty($extra['newpass']))
			{
				$password = $extra['newpass'];
			}

			//the user's existing password -- needed to verify to set certain sensative fields.
			if (!empty($extra['password']))
			{
				$user['password'] = $extra['password'];
			}
		}

		$this->checkEmail($newuser, $user, $userinfo);

		//we never want to save a blank email.  If the email isn't set and it
		//passed the check function its because we don't want to change the
		//existing email.
		if(empty($user['email']))
		{
			unset($user['email']);
		}

		//if we are setting the password or the email we may need to check the user's existing
		//password as an extra precaution.
		// * If this is an existing user
		// * If we are changing the password or email
		// * If we are not overriding as an admin

		if (!$newuser AND (!empty($password) OR !empty($user['email'])) AND !$adminoverride)
		{
			$loginlib = vB_Library::instance('login');
			if (!$user['password'])
			{
				throw new vB_Exception_Api('enter_current_password');
			}

			$login = array_intersect_key($userinfo, array_flip(array('userid', 'token', 'scheme')));
			$auth = $loginlib->verifyPasswordFromInfo($login, array(array('password' => $user['password'], 'encoding' => 'text')));

			if (!$auth['auth'])
			{
				throw new vB_Exception_Api('badpassword', vB5_Route::buildUrl('lostpw|fullurl'));
			}
		}
		//this is the user's existing password which we don't need now that we've verified it.
		//attempting to set it to the DM, which we do below for all user fields causes problems.
		unset($user['password']);

		//if this is a newuser we need to have a password -- even if this is an admin creating the user
		if ($newuser AND empty($password))
		{
			throw new vB_Exception_Api('invalid_password_specified');
		}

		/*
		 *	If we got this far, we basically have permission to update the user in the way we requested.
		 */
		$bf_misc_useroptions = $datastore->getValue('bf_misc_useroptions');
		$bf_misc_adminoptions = $datastore->getValue('bf_misc_adminoptions');
		$bf_misc_notificationoptions = $datastore->getValue('bf_misc_usernotificationoptions');
		$usergroupcache = $datastore->getValue('usergroupcache');

		if($adminoverride)
		{
			if(!isset($user['ipaddress']))
			{
				if($newuser)
				{
					$user['ipaddress'] = "0.0.0.0";
				}
				else
				{
					$user['ipaddress'] = $userinfo['ipaddress'];
				}
			}
		}
		else
		{
			if($newuser || $changingCurrentUser)
			{
				$user['ipaddress'] = $request->getIpAddress();
			}
			else
			{
				$user['ipaddress'] = $userinfo['ipaddress'];
			}
		}

		if (!$newuser)
		{
			// Only run this for existing users. We don't want to run this for new
			// users since it will set all the bits to 0, and since they're now set,
			// set_registration_defaults() in the user datamanager won't overwrite
			// them with the defaults.
			$olduser = array_merge($olduser, convert_bits_to_array($olduser['options'], $bf_misc_useroptions));
			$olduser = array_merge($olduser, convert_bits_to_array($olduser['adminoptions'], $bf_misc_adminoptions));
			$olduser = array_merge($olduser, convert_bits_to_array($olduser['notification_options'], $bf_misc_notificationoptions));
		}

		// get threaded mode options
		if (isset($olduser['threadedmode']) AND ($olduser['threadedmode'] == 1 OR $olduser['threadedmode'] == 2))
		{
			$threaddisplaymode = $olduser['threadedmode'];
		}
		else
		{
			if (isset($olduser['postorder']) AND $olduser['postorder'] == 0)
			{
				$threaddisplaymode = 0;
			}
			else
			{
				$threaddisplaymode = 3;
			}
		}
		$olduser['threadedmode'] = $threaddisplaymode;

		// init data manager
		$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);

		// Let's handle this at API level, ignore list is causing problems in the data manager
		//handle ignorelist
		if (isset($user['ignorelist']))
		{
			//this will not work for new users.  (Never has correctly).  To fix we'll need to
			//call it *after* the user is saved and give it the proper userid.  Given what a mess
			//the function currently is and how nasty it's going to be to unwind (and the fact that
			//we currently have nothing that attempts to create a new user with a preformed ignore list)
			//we're going to punt
			$user['ignorelist'] = $this->updateIgnorelist($userid, explode(',', $user['ignorelist']));
			$userdata->set('ignorelist', $user['ignorelist']);
		}

		/*
		 * If this was called from the account settings or registration pages
		 * (not the Admin Control Panel) then we shouldn't be setting admin override.
		 * Should also make sure that the admin is logged in and its not just a case of someone
		 * telling the API that we're in the ACP
		 */
		if ($adminoverride)
		{
			$userdata->adminoverride = true;
		}

		$updateUGPCache = false;
		// set existing info if this is an update
		if (!$newuser)
		{
			// birthday
			if (!$adminoverride AND $user['birthday'] AND $olduser['birthday'] AND ($user['birthday'] != $olduser['birthday']) AND $vboptions['reqbirthday'])
			{
				throw new vB_Exception_Api('has_no_permission_change_birthday');
			}

			// update buddy list
			$user['buddylist'] = array();
			foreach(explode(' ', $userinfo['buddylist']) as $buddy)
			{
				//I'm not sure if this is right -- we may not be saving the ignore list
				//and we aren't checking agaist the existing ignorelist if we aren't.
				//but it preserves prior behavior when the ignore list isn't set.
				if (empty($user['ignorelist']) OR in_array($buddy, $user['ignorelist']) === false)
				{
					$user['buddylist'][] = $buddy;
				}
			}

			// update usergroups cache if needed...
			$uInfoMUgpIds = explode(',', trim($userinfo['membergroupids']));
			$uInfoUgpId = trim($userinfo['usergroupid']);
			$uIGpIds =  explode(',', trim($userinfo['infractiongroupids']));

			$mUgpIds = isset($user['membergroupids']) ? $user['membergroupids'] : false;
			$ugpId = isset($user['usergroupid']) ? trim($user['usergroupid']) : false;
			$iGpIds = isset($user['infractiongroupids']) ? explode(',', trim($user['infractiongroupids'])) : false;

			if (($ugpId AND ($uInfoUgpId != $ugpId)) OR ($mUgpIds AND array_diff($uInfoMUgpIds, $mUgpIds)) OR ($iGpIds AND array_diff($iGpIds, $uIGpIds)))
			{
				$updateUGPCache = true;
			}

			$userdata->set_existing($userinfo);
		}
		else if (!$adminoverride AND $this->useCoppa())
		{
			if (empty($user['birthday']))
			{
				throw new vB_Exception_Api('under_thirteen_registration_denied');
			}

			if ($this->needsCoppa($user['birthday']))
			{
				if ($vboptions['usecoppa'] == 2)
				{
					throw new vB_Exception_Api('under_thirteen_registration_denied');
				}
				else
				{
					if (empty($user['parentemail']))
					{
						throw new vB_Exception_Api('coppa_rules_description', array(
							$vboptions['bbtitle'],
							vB5_Route::buildUrl('home|fullurl'),
							vB5_Route::buildUrl('coppa-form|fullurl'),
							$vboptions['webmasteremail']
						));
					}
					$userdata->set_info('coppauser', true);
					$userdata->set_info('coppapassword', $password);
					$options['coppauser'] = 1;
					$coppauser = true;
				}
			}
		}

		// user options
		foreach ($bf_misc_useroptions AS $key => $val)
		{
			if (isset($options["$key"]))
			{
				$userdata->set_bitfield('options', $key, $options["$key"]);
			}
			else if (isset($olduser["$key"]))
			{
				$userdata->set_bitfield('options', $key, $olduser["$key"]);
			}
		}

		foreach($adminoptions AS $key => $val)
		{
			$userdata->set_bitfield('adminoptions', $key, $val);
		}

		// notification options
		foreach ($notificationOptions AS $key => $val)
		{
			// @TODO related to VBV-92
			if ($olduser["$key"] != $val)
			{
				$userdata->set_bitfield('notification_options', $key, $val);
			}
			else if($olduser["$key"] == $val)
			{
				$userdata->set_bitfield('notification_options', $key, $olduser["$key"]);
			}
		}

		$displaygroupid = (array_key_exists('displaygroupid', $user) AND intval($user['displaygroupid'])) ? $user['displaygroupid'] : '';
		if (isset($user['usergroupid']) AND $user['usergroupid'])
		{
			$displaygroupid = $user['usergroupid'];
		}
		elseif (isset($olduser['usergroupid']) AND $olduser['usergroupid'])
		{
			$displaygroupid = $olduser['usergroupid'];
		}

		if (isset($user['usertitle']))
		{
			//this logic is getting insanely complicated due to trying to sort out the
			//correct approach based on context and permissions.  If we have $adminoverride
			//it's pretty simple because we want to set things based on the data passed.
			//However for a normal user we have some complicated use cases.
			//1) If we are resetting the title ($user['customtitle'] == 0) we want to do that
			//2) If we have a different title we want to set it as a user ($customtitle == 2)
			//3) If we haven't changed the title and we are resetting it, then we *don't* *want* *to*
			//		*change* *anything*.  Even if we are normally not allowed to set to that value.
			//		This allows admins to set titles to whatever they want without the user getting
			//		dinged because they saved their profile and it passed the title back unchanged.

			//if not given assume "user set" as the custom title
			$customtitle = (isset($user['customtitle']) ? $user['customtitle'] : 2);

			//if we aren't the admin then we need to make sure that check the right
			//permissions to allow the user to have a custom title.
			$canusecustom = $userContext->hasPermission('genericpermissions', 'canusecustomtitle');

			$savetitle = true;
			if(!$adminoverride)
			{
				if (!$canusecustom)
				{
					$customtitle = 0;
				}
				elseif ($customtitle == 1)
				{
					$customtitle = 2;
				}

				$titlechanged = (empty($olduser['usertitle']) OR $olduser['usertitle'] != $user['usertitle']);

				//we have a title and its changed OR we are resetting the title
				$savetitle = (($user['usertitle'] AND $titlechanged) OR (isset($user['customtitle']) AND $customtitle == 0));

				//we aren't resetting the title, it's changed and we aren't an admin.  Check the title length.
				//note that we should probably be checking $adminoverride instead of isAdmin (which is already implicit)
				//but that will enforce the limit on admins on the front end which might annoy them since they aren't
				//used to it.  (The overall rule is to treat admins as regular users when editing using normal user
				//UI (which doesn't pass the override flag).
				if (
					$customtitle != 0 AND
					$titlechanged AND
					(vB_String::vbStrlen($user['usertitle']) > $vboptions['ctMaxChars']) AND
					!$userContext->isAdministrator()
				)
				{
					throw new vB_Exception_Api('please_enter_user_title_with_at_least_x_characters', $vboptions['ctMaxChars']);
				}
			}

			if ($savetitle)
			{
				$usertitle = ($user['usertitle'] ? $user['usertitle'] : '');

				$userdata->set_usertitle(
					$usertitle,
					($customtitle == 0),
					$usergroupcache["$displaygroupid"],
					$adminoverride OR $canusecustom,
					$adminoverride AND ($customtitle == 1)
				);
			}

			//if we didn't save the title, don't attempt to change any of the values as
			//part of the default field setting
			unset($user['usertitle'], $user['customtitle']);
		}

		// privacy_options
		$privacyChanged = false;
		if (isset($user['privacy_options']) AND $user['privacy_options'])
		{
			foreach ($user['privacy_options'] AS $opt => $val)
			{
				if (!in_array($opt, $this->privacyOptions))
				{
					unset($user['privacy_options'][$opt]);
				}
			}

			// check if we need to update cached values...
			if ($olduser['privacy_options'])
			{
				$check = unserialize($olduser['privacy_options']);
				$diff = array_diff_assoc($user['privacy_options'], $check);
				if (!empty($diff))
				{
					$privacyChanged = true;
				}
			}

			$user['privacy_options'] = serialize($user['privacy_options']);
		}

		$this->setEuStatus($vboptions, $request, $newuser, $changingCurrentUser, $adminoverride, $userinfo, $user);

		// Privacy Consent. Only update updated time if the value changed. This is to prevent issues
		// in the future where if the user withdrew consent, then updates something in their
		// user settings without re-consenting, it doesn't keep "refreshing" the cooldown period.
		unset($user['privacyconsentupdated']);
		// Using array_key_exists instead of isset() to disallow null from bypassing below checks and sneaking
		// in as 0 (consent unknown) into user datamanager
		if (is_array($user) AND array_key_exists('privacyconsent', $user))
		{
			$user['privacyconsent'] = intval($user['privacyconsent']);
			// Disallow withdrawal if admin disabled account removal, unless this is the admin.
			// Also do not allow setting privacyconsent back to "unknown". Once we have it, we have it.
			if ($user['privacyconsent'] == 0 OR
				$user['privacyconsent'] == -1 AND !$vboptions['enable_account_removal'] AND !$adminoverride
			)
			{
				unset($user['privacyconsent']);
			}
			else
			{
				if (!isset($olduser['privacyconsent']) OR $olduser['privacyconsent'] != $user['privacyconsent'])
				{
					$user['privacyconsentupdated'] = $request->getTimeNow();
				}
			}
		}


		// Update from user fields
		foreach ($user AS $key => $val)
		{
			if (!$userid OR $olduser["$key"] != $val)
			{
				$userdata->set($key, $val);
			}
		}

		$membergroupids = false;
		if (isset($user['membergroupids']) AND is_array(($user['membergroupids'])))
		{
			$membergroupids =  $user['membergroupids'];
		}

		if($newuser)
		{
			//only set the usergroupid if we don't already have one -- if we do for a new user then
			//this is an admin creating a user and we should do what they say we should.
			if(!isset($user['usergroupid']))
			{
				//this preempts the logic in the datamanager that does roughly the same
				//thing.  The purpose is to allow us to tweak the logic to potentially
				//skip certain validation steps without having to pass a bunch of
				//information in to datamanager for its magic function to trigger.
				//We should probably remove this (and possibly the rest of that function)
				//out the DM to here since we should always be registering new users
				//through this function now, but I'm declining to do the work required
				//to ensure that it is safe right now.

				$verifyemail = $vboptions['verifyemail'];
				if($verifyemail AND $fbautoregister)
				{
					//if the email the user gives us matches the facebook email we can skip the
					//email verification step.  We'll treat it as if it was turned off entirely
					$fbinfo = $fblib->getFbUserInfo();
					if($fbinfo['email'] == $user['email'])
					{
						$verifyemail = false;
					}
				}

				if ($verifyemail)
				{
					$usergroupid = 3;
				}
				else if ($vboptions['moderatenewmembers'] OR $coppauser)
				{
					$usergroupid = 4;
				}
				else
				{
					$usergroupid = 2;
				}
				$userdata->set('usergroupid', $usergroupid);
			}

			//if configured and FB is enabled then set the fb usergroup.
			if($vboptions['facebookusergroupid'] AND $isfacebooksignup)
			{
				if (is_array($membergroupids))
				{
					$membergroupids[] = $vboptions['facebookusergroupid'];
				}
				else
				{
					$membergroupids = array($vboptions['facebookusergroupid']);
				}
			}

			// timezone
			if(empty($user['timezoneoffset']))
			{
				$userdata->set('timezoneoffset', $vboptions['timeoffset']);
			}
		}

		//actually set the usergroup array if we have one
		if(is_array($membergroupids))
		{
			$userdata->set('membergroupids', $membergroupids);
		}

		// custom profile fields
		if (!empty($userfield) AND is_array($userfield))
		{
			$scope ="admin";
			if(!$adminoverride)
			{
				if($newuser)
				{
					$scope = "register";
				}
				else
				{
					$scope = "normal";
				}
			}
			$userdata->set_userfields($userfield, true, $scope);
		}

		$userdata->set('buddylist', isset($user['buddylist']) ? $user['buddylist'] : array());


		//the secret really isn't related to the password, but we want to change it
		//periodically and for now "every time the user changes their password"
		//works (we previously used the password salt so that's when it got changed
		//prior to the refactor).
		if (!empty($password))
		{
			$userdata->set('secret', vB_Library::instance('user')->generateUserSecret());
		}

		// save data
		$newuserid = $userdata->save();
		if ($userdata->has_errors(false))
		{
			throw $userdata->get_exception();
		}

		//a bit of a hack.  If the DM save function runs an update of an existing user then
		//it returns true rather than the userid (despite what the comments say). However its
		//not clear how to handle that in the DM (which looks like it could be use to alter
		//multiple users wholesale, in which case we really don't have an ID.  Better to catch it here.
		if ($newuserid === true)
		{
			$newuserid = $userid;
		}

		//if we have a new password, then let's set it.
		if (!empty($password))
		{
			try
			{
				//lookup the history for the user we are editing, which is not necesarily the
				//user that we currently are.
				if ($changingCurrentUser)
				{
					$history = $userContext->getUsergroupLimit('passwordhistory');
				}
				//on an adminoverride the admin can do what he wants.  We'll skip the check entirely.
				else if ($adminoverride)
				{
					$history = 0;
				}
				//not sure if this can happen.  It probably shouldn't
				else
				{
					$history = vB::getUserContext($userid)->getUsergroupLimit('passwordhistory');
				}

				$loginlib = vB_Library::instance('login');
				$loginlib->setPassword($newuserid, $password,
					array('passwordhistorylength' => $history),
					array('passwordhistory' => $adminoverride)
				);
			}
			catch(Exception $e)
			{
				//if this is a new user, deleted it if we fail to set the intial password.
				if($newuser)
				{
					$db->delete('user', array('userid' => $newuserid));
				}
				throw $e;
			}
		}

		if ($updateUGPCache)
		{
			vB_Cache::instance(vB_Cache::CACHE_FAST)->event('perms_changed');
		}

		if ($privacyChanged)
		{
			vB_Cache::instance()->event('userPrivacyChg_' . $userid);
		}

		// clear user info cached
		$this->library->clearUserInfo(array($newuserid));

		// update session's languageid, VBV-11318
		if (isset($user['languageid']))
		{
			vB::getCurrentSession()->set('languageid', $user['languageid']);
		}

		$verifyEmail = false;
		if ($newuser)
		{
			if($vboptions['newuseremail'] != '')
			{
				// Prepare email data
				$customfields = '';
				if (!empty($userfield) AND is_array($userfield))
				{
					$customfields = $userdata->set_userfields($userfield, true, 'register');
				}

				//the $user array doesn't have the latest information since we saved the user
				//so let's load it here so we can send it to the email
				$newUserInfo = vB_User::fetchUserinfo($newuserid);
				$profileUrl = vB5_Route::buildUrl('profile|fullurl', $newUserInfo);
				$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
					'newuser',
					array(
						$newUserInfo['username'],
						$vboptions['bbtitle'],
						$profileUrl,
						$newUserInfo['email'],
						$newUserInfo['birthday'],
						$newUserInfo['ipaddress'],
						$customfields,
					),
					array($vboptions['bbtitle'])
				);

				// Send out the emails
				$newemails = explode(' ', $vboptions['newuseremail']);
				foreach ($newemails AS $toemail)
				{
					if (trim($toemail))
					{
						vB_Mail::vbmail($toemail, $maildata['subject'], $maildata['message'], false);
					}
				}
			}

			$usergroupid = $userdata->fetch_field('usergroupid');

			// Check if we need to send out activate email -- make sure to check the actual
			// usergroups for which emails to send since we may not do exactly what the
			// global configurations suggest due to special cases and we don't want to
			// keep replicating that logic.  If we wind up in the verification group we
			// send the email, otherwise we don't
			$verifyEmail = (!$adminoverride AND $usergroupid == 3);
			if ($verifyEmail)
			{
				$this->library->sendActivateEmail($newuserid);
			}

			// Check if we need to send out welcome email
			if ($usergroupid == 2 AND $vboptions['welcomemail'])
			{
				$newUserInfo = vB_User::fetchUserinfo($newuserid);
				// Send welcome mail
				$username = trim(unhtmlspecialchars($newUserInfo['username']));
				$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
					'welcomemail',
					array(
						$username,
						$vboptions['bbtitle'],
					),
					array($vboptions['bbtitle']),
					isset($newUserInfo['languageid']) ? $newUserInfo['languageid'] : $vboptions['languageid']
				);
				vB_Mail::vbmail($newUserInfo['email'], $maildata['subject'], $maildata['message'], true);
			}
		}


		// Check for monitored words in various pieces of user information and send notifications
		$currentuserid = vB::getCurrentSession()->get('userid');
		if (!$currentuserid)
		{
			$currentuserid = $newuserid;
		}

		// Check for monitored words in username
		$newUserInfo = vB_User::fetchUserinfo($newuserid);
		if ($newuser OR ($olduser['username']) != $newUserInfo['username'])
		{
			$newusername = unhtmlspecialchars($newUserInfo['username']);
			$this->library->monitorWords($newusername, 'user-name', null, $newuserid, true, $currentuserid);
		}

		// Check for monitored words in user fields
		if (!empty($userfield) AND is_array($userfield))
		{
			$this->library->monitorWords($userfield, 'user-fields', null, $newuserid, true, $currentuserid);
		}

		// Check for monitored words in user title
		if (!empty($usertitle))
		{
			$this->library->monitorWords($usertitle, 'user-title', null, $newuserid, true, $currentuserid);
		}


		vB::getHooks()->invoke('hookUserAfterSave', array(
			'adminoverride' => $adminoverride,
			'userid' => $newuserid,
			'newuser' => $newuser,
			'emailVerificationRequired' => $verifyEmail,
			'userIsModerated' => (!$adminoverride AND $newuser AND $vboptions['moderatenewmembers'])
		));

		return $newuserid;
	}

	private function setEuStatus($vboptions, $request, $newuser, $changingCurrentUser, $adminoverride, $userinfo, &$user)
	{
		if($vboptions['enable_privacy_registered'])
		{
			//we don't have a status (most likely we already know the answer and don't want to check again)
			if(!isset($user['eustatus']))
			{
				//we aren't the current user so we can't look this up from the IP Address
				if($adminoverride OR (!$newuser AND !$changingCurrentUser))
				{
					$user['eustatus'] = ($newuser ? 0 : $userinfo['eustatus']);
				}
				else
				{
					//if this is "unknown" because of a failed lookup we may be looking up
					//an additional time but the cache should stop that from overloading the
					//service.
					$user['eustatus'] = $this->library->getPrivacyConsentRequired($request->getIpAddress());
				}
			}
			else
			{
				//let's not change this once it's set unless it's an admin request.
				if(!$newuser AND $userinfo['eustatus'] AND !$adminoverride)
				{
					$user['eustatus'] = $userinfo['eustatus'];
				}
			}

			//if we are saving an euuser (or an unknown user) and we don't have Privacy consent, then
			//we need to have the consent flagged.

			//either we have consent given in the params or we have consent in the user record already
			$haveConsent = (!empty($user['privacyconsent']) OR (!$newuser AND $userinfo['privacyconsent'] == 1));
			if(!$adminoverride AND $user['eustatus'] != 2 AND !$haveConsent)
			{
				throw new vB_Exception_Api('privacyconsent_required');
			}
		}
		else if($newuser)
		{
			//if we aren't tracking this and it's a new user, we should set this to "unknown"
			$user['eustatus'] = 0;
		}
	}

	/**
	 * Checks if email is empty -- and throws an exception if that's a problem.
	 * New users always require a non-empty email address.
	 * Existing users may not blank out an existing email address.
	 * Existing users with an already empty email address are allowed to maintain
	 * it, although it's not recommended (legacy behavior support).
	 *
	 * This function does not validate the email. It only checks if the email is empty.
	 *
	 * @param	$newuser    Boolean if user is new one
	 * @param	$user       Incoming user data to check
	 * @param	$userinfo   Current user inforamation (if availiable)
	 *
	 * @throws	vB_Exception_Api('fieldmissing_email')
	 */
	private function checkEmail($newuser, $user, $userinfo)
	{
		//if we have a new user the email is always required.
		if($newuser)
		{
			if(empty($user['email']))
			{
				throw new vB_Exception_Api('fieldmissing_email');
			}
		}
		else
		{
			//otherwise if we have an email address for the existing user
			//and we have a value passed in, but that value is blank
			if (!empty($userinfo['email']) AND array_key_exists('email', $user) AND !$user['email'])
			{
				throw new vB_Exception_Api('fieldmissing_email');
			}

			//if we don't have a user email and the email is blank we want to assume that they didn't
			//change it and allow the save to happen. This is explicitly to prevent legacy cases where
			//there is no email to pass if other fields are being changed.

			//if the email field is not set in the new user data we assume that the caller of the API
			//is not changing the users email value.  Therefore we allow it to be "blank" in this case.
		}
	}

	public function sendActivateEmail($email)
	{
		$userinfo = $this->fetchByEmail($email);
		$vboptions = vB::getDatastore()->getValue('options');

		if (empty($userinfo))
		{
			throw new vB_Exception_Api('invalidemail', array('mailto:' . $vboptions['webmasteremail']));
		}

		$this->library->sendActivateEmail($userinfo['userid']);
	}

	/**
	 * Activate an user with an activate ID and Username
	 *
	 * @param string $username Username
	 * @param string $activateid Activate ID
	 *
	 * @throws vB_Exception_Api
	 * @return string User status after activation. Possible values:
	 *         1) moderateuser: user is put into moderate queue
	 *         2) emailchanged: user's email address has been updated successfully
	 *         3) registration_complete: user's registration is completed
	 */

	public function activateUserByUsername($username, $activateid)
	{
		$userinfo = $this->fetchByUsername($username);

		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalid_username');
		}

		return $this->activateUser($userinfo['userid'], $activateid);
	}

	/**
	 * Activate an user with an activate ID
	 *
	 * @param int $userid User ID
	 * @param string $activateid Activate ID
	 *
	 * @throws vB_Exception_Api
	 * @return string User status after activation. Possible values:
	 *		 1) moderateuser: user is put into moderate queue
	 *		 2) emailchanged: user's email address has been updated successfully
	 *		 3) registration_complete: user's registration is completed
	 */
	public function activateUser($userid, $activateid)
	{
		$dbassertor = vB::getDbAssertor();
		$userinfo = vB_User::fetchUserinfo($userid);
		$usercontext = vB::getUserContext($userid);
		$userid = intval($userid);
		$usergroupcache = vB::getDatastore()->getValue('usergroupcache');
		$vboptions = vB::getDatastore()->getValue('options');

		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalidid',
				array(vB_Phrase::fetchSinglePhrase('user'), vB5_Route::buildUrl('contact-us|fullurl')));
		}

		if ($userid == 0)
		{
			throw new vB_Exception_Api('invalidactivateid', array(
					vB5_Route::buildUrl('activateuser|fullurl'),
					vB5_Route::buildUrl('activateemail|fullurl'),
					vB5_Route::buildUrl('contact-us|fullurl')
			));
		}
		else if ($userinfo['usergroupid'] == 3)
		{
			// check valid activation id
			$user = $dbassertor->getRow('useractivation', array(
				'activationid' => $activateid,
				'userid' => $userid,
				'type' => 0
			));

			if (!$user OR $activateid != $user['activationid'])
			{
				// send email again
				throw new vB_Exception_Api('invalidactivateid', array(
						vB5_Route::buildUrl('activateuser|fullurl'),
						vB5_Route::buildUrl('activateemail|fullurl'),
						vB5_Route::buildUrl('contact-us|fullurl')
				));
			}

			// delete activationid
			$dbassertor->delete('useractivation', array('userid' => $userid, 'type' => 0));


			if (empty($user['usergroupid']))
			{
				$user['usergroupid'] = 2; // sanity check
			}

			// ### DO THE UG/TITLE UPDATE ###

			$getusergroupid = ($userinfo['displaygroupid'] != $userinfo['usergroupid']) ? $userinfo['displaygroupid'] : $user['usergroupid'];

			$user_usergroup =& $usergroupcache["$user[usergroupid]"];
			$display_usergroup =& $usergroupcache["$getusergroupid"];

			// init user data manager
			$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_STANDARD);
			$userdata->set_existing($userinfo);
			$userdata->set('usergroupid', $user['usergroupid']);
			$userdata->set_usertitle(
				!empty($user['customtitle']) ? $user['usertitle'] : '',
				false,
				$display_usergroup,
				($usercontext->hasPermission('genericpermissions', 'canusecustomtitle')) ? true : false,
				($usercontext->isAdministrator()) ? true : false
			);

			if ($userinfo['coppauser'] OR ($vboptions['moderatenewmembers'] AND !$userinfo['posts']))
			{
				// put user in moderated group
				$userdata->save();
				$result = array('moderateuser', $this->fetchUserName($userid), vB5_Route::buildUrl('home|fullurl'));;
			}
			else
			{
				// activate account
				$userdata->save();

				// rebuild stats so new user displays on forum home
				require_once(DIR . '/includes/functions_databuild.php');
				build_user_statistics();
				vB_Cache::instance(vB_Cache::CACHE_FAST)->event(array("userPerms_$userid", "userChg_$userid"));
				vB_Cache::instance(vB_Cache::CACHE_LARGE)->event(array("userPerms_$userid", "userChg_$userid"));

				$username = unhtmlspecialchars($userinfo['username']);
				if (!$user['emailchange'])
				{
					if ($vboptions['welcomemail'])
					{
						// Send welcome mail
						$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
							'welcomemail',
							array(
								$username,
								$vboptions['bbtitle'],
							),
							array($vboptions['bbtitle']),
							isset($user['languageid']) ? $user['languageid'] : vB::getDatastore()->getOption('languageid')
						);
						vB_Mail::vbmail($userinfo['email'], $maildata['subject'], $maildata['message'], true);
					}

					$userdata->send_welcomepm(null, $userid);
				}

				if ($user['emailchange'])
				{
					$result = 'emailchanged';
				}
				else
				{
					$result = array('registration_complete',
						vB_String::htmlSpecialCharsUni($username),
						vB5_Route::buildUrl('profile|fullurl', $userinfo),
						vB5_Route::buildUrl('settings|fullurl', array('tab' => 'account')),
						vB5_Route::buildUrl('settings|fullurl', array('tab' => 'account')),
						vB5_Route::buildUrl('home|fullurl')
					);
				}
			}

			vB::getHooks()->invoke('hookUserAfterActivation', array(
				'userid' => $userid,
				'newuser' => !$user['emailchange'],
				'userIsModerated' => ($user['usergroupid'] == 4)
			));

			return $result;
		}
		else
		{
			if ($userinfo['usergroupid'] == 4)
			{
				// In Moderation Queue
				return 'activate_moderation';
				vB_Cache::instance(vB_Cache::CACHE_FAST)->event(array("userPerms_$userid", "userChg_$userid"));
				vB_Cache::instance(vB_Cache::CACHE_LARGE)->event(array("userPerms_$userid", "userChg_$userid"));
			}
			else
			{
				// Already activated
				throw new vB_Exception_Api('activate_wrongusergroup');
			}
		}
	}


	//this function appears to only be called from the registration controller action and that
	//action doesn't appear to be used anywhere.  This is almost identical to killActivation
	//but not quite.
	public function deleteActivation($userid, $activateid)
	{
		$userid = intval($userid);

		$dbassertor = vB::getDbAssertor();

		$userinfo = vB_User::fetchUserinfo($userid);
		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalidid',
				array(vB_Phrase::fetchSinglePhrase('user'), vB5_Route::buildUrl('contact-us|fullurl')));
		}

		if ($userinfo['usergroupid'] == 3)
		{
			// check valid activation id
			$user = $dbassertor->getRow('useractivation', array(
				'activationid' => $activateid,
				'userid' => $userid,
				'type' => 0
			));

			if (!$user OR $activateid != $user['activationid'])
			{
				throw new vB_Exception_Api('invalidactivateid',
					array(
						vB5_Route::buildUrl('activateuser|fullurl'),
						vB5_Route::buildUrl('activateemail|fullurl'),
						vB5_Route::buildUrl('contact-us|fullurl')
					)
				);
			}

			return array('activate_deleterequest', $user['activationid'], $user['userid']);
		}
		else
		{
			throw new vB_Exception_Api('activate_wrongusergroup');
		}
	}

	/**
	 *
	 */
	public function killActivation($userid, $activateid)
	{
		$userid = intval($userid);
		$dbassertor = vB::getDbAssertor();

		$userinfo = vB_User::fetchUserinfo($userid);
		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalidid',
				array(vB_Phrase::fetchSinglePhrase('user'), vB5_Route::buildUrl('contact-us|fullurl')));
		}

		if ($userinfo['usergroupid'] == 3)
		{
			// check valid activation id
			$user = $dbassertor->getRow('useractivation', array(
				'activationid' => $activateid,
				'userid' => $userid,
				'type' => 0
			));

			if (!$user OR $activateid != $user['activationid'])
			{
				throw new vB_Exception_Api('invalidactivateid',
					array(
						vB5_Route::buildUrl('activateuser|fullurl'),
						vB5_Route::buildUrl('activateemail|fullurl'),
						vB5_Route::buildUrl('contact-us|fullurl')
					)
				);
			}

			$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
			$userdata->set_existing($userinfo);
			$userdata->set_bitfield('options', 'noactivationmails', 1);
			$userdata->save();

			$dbassertor->delete('useractivation', array('useractivationid' => intval($user['useractivationid'])));

			return array('activate_requestdeleted');
		}
		else
		{
			return array('activate_wrongusergroup');
		}
	}

	private function getFiledataIdsFromSignature($signature)
	{
		$img2Filedataids = array();
		if (preg_match_all('#\[(?<tag>attach|img2)=json\](?<jsondata>{(?:(?!}\[/\k<tag>\]).)*})\[/\k<tag>\]#i', $signature, $matches))
		{
			$vboptions = vB::getDatastore()->getValue('options');
			$frontendurl = $vboptions['frontendurl'];
			$ourUrl = parse_url($frontendurl);
			$ourUrl1 = trim($ourUrl['host'], "/") . "/" . trim($ourUrl['path'], "/") . "/core/filedata/fetch";
			$ourUrl2 = trim($ourUrl['host'], "/") . "/" . trim($ourUrl['path'], "/") . "/filedata/fetch";
			foreach($matches['jsondata'] AS $key => $__data)
			{
				$custom_config = json_decode($__data, true);

				if (empty($custom_config))
				{
					$custom_config = array();
				}

				if (!empty($custom_config['src']))
				{
					$urlData = parse_url($custom_config['src']);
					$checkUrl = trim($urlData['host'], "/") . "/" . trim($urlData['path'], "/");
					if ($checkUrl === $ourUrl1 OR $checkUrl === $ourUrl2)
					{
						parse_str($urlData['query'], $queryData);
						if (!empty($queryData['filedataid']) AND is_numeric($queryData['filedataid']))
						{
							$img2Filedataids[] = intval($queryData['filedataid']);
						}
					}

				}
			}
		}

		return $img2Filedataids;
	}

	/**
	 * Verifies and saves a signature for current logged in user. Returns the signature.
	 * @param string $signature
	 * @param array $filedataids
	 * @return string
	 */
	public function saveSignature($signature, $filedataids = array())
	{
		// This code is based on profile.php
		$options = vB::getDatastore()->getValue('options');

		// *********************** CHECKS **********************
		// *****************************************************

		$userid = vB::getCurrentSession()->get('userid');
		$userid = intval($userid);

		if ($userid <= 0)
		{
			throw new vB_Exception_Api('no_permission_logged_out');
		}

		$userContext = vB::getUserContext($userid);
		if (
			!$userContext->hasPermission('genericpermissions', 'canusesignature')
				OR
			!$userContext->hasPermission('genericpermissions', 'canmodifyprofile')
		)
		{
			throw new vB_Exception_Api('no_permission_signatures');
		}

		if (!empty($filedataids))
		{
			if (!$userContext->hasPermission('signaturepermissions', 'cansigpic'))
			{
				throw new vB_Exception_Api('no_permission_images');
			}

			// Max number of images in the sig if imgs are allowed.
			if ($maxImages = $userContext->getLimit('sigmaximages'))
			{
				if (count($filedataids) > $maxImages)
				{
					throw new vB_Exception_Api('max_attachments_reached');
				}
			}
		}

		// Count the raw characters in the signature
		if (($maxRawChars = $userContext->getLimit('sigmaxrawchars')) AND vB_String::vbStrlen($signature) > $maxRawChars)
		{
			throw new vB_Exception_Api('sigtoolong_includingbbcode', array($maxRawChars));
		}

		// Image2 hack. Remove the tempid to force any img.bbcode-attachment into img2 bbcode.
		// This forces the Wysiwyg->HTML parser to convert these to img2 tags instead of attach tags, see vB_WysiwygHtmlParser::handleWysiwygAdvancedImageImg()
		// using the filedataid URL in an image2 tag in addition to setting filedata.publicview++/refcount++ allows the images to be visible by other users,
		// and any customizations on it is also rendered by the parser ala image2 bbcode handler.
		if (preg_match_all('#<img(?:(?!>).)*(?<tempidtag>data-tempid=(?<quot>\'|")temp_\\d+_\\d+_\\d+\\k<quot>)(?:(?!>).)*>#i', $signature, $matches))
		{
			$str_search = array();
			$str_replace = array();
			foreach($matches['tempidtag'] AS $key => $__data)
			{
				$str_search[$__data] = $__data;
				$str_replace[$__data] = '';
			}
			$signature = str_replace($str_search, $str_replace, $signature);
		}

		// *****************************************************
		//Convert signature to BBcode
		$bbcodeApi = vB_Api::instanceInternal('bbcode');
		$signature = $bbcodeApi->parseWysiwygHtmlToBbcode($signature);
		//removing consecutive spaces
		$signature = preg_replace('# +#', ' ', $signature);
		$hasBbcode = $bbcodeApi->hasBbcode($signature);
		if ($hasBbcode AND !$userContext->hasPermission('signaturepermissions', 'canbbcode'))
		{
			throw new vB_Exception_Api('bbcode_not_allowed');
		}

		// add # to color tags using hex if it's not there
		$signature = preg_replace('#\[color=(&quot;|"|\'|)([a-f0-9]{6})\\1]#i', '[color=\1#\2\1]', $signature);

		// Turn the text into bb code.
		if ($userContext->hasPermission('signaturepermissions', 'canbbcodelink'))
		{
			$signature = $bbcodeApi->convertUrlToBbcode($signature);
		}

		/*
			Let's pull out any filedataids we need to make public.

		 */
		$img2Filedataids = $this->getFiledataIdsFromSignature($signature);


		// Create the parser with the users sig permissions
		require_once(DIR . '/includes/class_sigparser.php');
		$sig_parser = new vB_SignatureParser(vB::get_registry(), $bbcodeApi->fetchTagList(), $userid);
		// Parse the signature
		$paresed = $sig_parser->parse($signature);
		if ($error_num = count($sig_parser->errors))
		{
			$e = new vB_Exception_Api();
			foreach ($sig_parser->errors AS $tag => $error_phrase)
			{
				if (is_array($error_phrase))
				{
					$phrase_name = key($error_phrase);
					$params = $error_phrase[$phrase_name];
					$e->add_error($phrase_name, $params);
				}
				else
				{
					$e->add_error($error_phrase, array($tag));
				}
			}

			throw $e;
		}

		unset($sig_parser);

		// Count the characters after stripping in the signature
		if (($maxChars = $userContext->getLimit('sigmaxchars')) AND (vB_String::vbStrlen(vB_String::stripBbcode($signature, false, false, false)) > $maxChars))
		{
			throw new vB_Exception_Api('sigtoolong_excludingbbcode', array($maxChars));
		}

		if (($maxLines = $userContext->getLimit('sigmaxlines')) > 0)
		{
			require_once(DIR . '/includes/class_sigparser_char.php');
			$char_counter = new vB_SignatureParser_CharCount(vB::get_registry(), $bbcodeApi->fetchTagList(), $userid);
			$line_count_text = $char_counter->parse(trim($signature));

			if ($options['softlinebreakchars'] > 0)
			{
				// implicitly wrap after X characters without a break
				//trim it to get rid of the trailing whitechars that are inserted by the replace
				$line_count_text = trim(preg_replace('#([^\r\n]{' . $options['softlinebreakchars'] . '})#', "\\1\n", $line_count_text));
			}

			// + 1, since 0 linebreaks still means 1 line
			$line_count = substr_count($line_count_text, "\n") + 1;

			if ($line_count > $maxLines)
			{
				throw new vB_Exception_Api('sigtoomanylines', array($maxLines));
			}
		}

		// *****************************************************

		// Check for monitored words in signature and send notifications
		$this->library->monitorWords($signature, 'user-signature', null, $userid);

		// Censored Words
		$signature = vB_String::fetchCensoredText($signature);

		// init user data manager
		$userinfo = vB_User::fetchUserinfo($userid);
		$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_STANDARD);
		$userdata->set_existing($userinfo);
		$userdata->set('signature', $signature);

		$db = vB::getDbAssertor();

		/*
			Image2 - Increment & publicize any new filedataids, decrement any old filedataids
		 */
		if (!empty($img2Filedataids))
		{
			$db->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $img2Filedataids));
		}
		$oldImg2Filedataids = $this->getFiledataIdsFromSignature($userinfo['signature']);
		if (!empty($oldImg2Filedataids))
		{
			$db->assertQuery('decrementFiledataRefcount', array('filedataid' => $oldImg2Filedataids));
		}

		$userdata->save();

		// I did not put this in the userdm as it only applies to saveSiganture
		// Clear autosave table of this items entry
		$db->delete('vBForum:autosavetext', array(
			'userid'   => $userid,
			'nodeid'   => 0,
			'parentid' => 0
		));

		// update userinfo
		$this->library->clearUserInfo(array($userid));

		return $bbcodeApi->parseSignature($userid, $signature, true);
	}

	/**
	 * Fetch a list of users who are awaiting moderate or Coppa
	 *
	 * @return array A list of users that are awaiting moderation
	 */
	public function fetchAwaitingModerate()
	{
		$this->checkHasAdminPermission('canadminusers');
		return vB::getDbAssertor()->getRows('user_fetchmoderate', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED));
	}

	/**
	 * Moderate users
	 *
	 * @param array $validate Validate information
	 * @param bool $send_validated Whether to send email to users who have been accepted
	 * @param bool $send_deleted Whether to send email to users who have been deleted
	 * @return bool True if user accounts validated successfully
	 */
	public function moderate($validate, $send_validated, $send_deleted)
	{
		$this->checkHasAdminPermission('canadminusers');

		if (empty($validate))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$evalemail_validated = array();
		$evalemail_deleted = array();
		$vboptions = vB::getDatastore()->getValue('options');
		$usergroupcache = vB::getDatastore()->getValue('usergroupcache');
		$bf_ugp_genericpermissions = vB::getDatastore()->getValue('bf_ugp_genericpermissions');

		require_once(DIR . '/includes/functions_misc.php');

		if ($vboptions['welcomepm'])
		{
			if ($fromuser = vB_User::fetchUserinfo($vboptions['welcomepm']))
			{
				cache_permissions($fromuser, false);
			}
		}

		foreach($validate AS $userid => $status)
		{
			$userid = intval($userid);
			$user = vB::getDbAssertor()->getRow('user', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'#filters' => array('userid' => $userid)
			));
			if (!$user)
			{
				// use was likely deleted
				continue;
			}
			$username = unhtmlspecialchars($user['username']);

			$chosenlanguage = iif($user['languageid'] < 1, intval($vboptions['languageid']), intval($user['languageid']));

			if ($status == 1)
			{
				// validated

				// init user data manager
				$displaygroupid = ($user['displaygroupid'] > 0 AND $user['displaygroupid'] != $user['usergroupid']) ? $user['displaygroupid'] : 2;

				$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_ARRAY_UNPROCESSED);
				$userdata->set_existing($user);
				$userdata->set('usergroupid', 2);
				$userdata->set_usertitle($user['customtitle'] ? $user['usertitle'] : '',
					false,
					$usergroupcache["$displaygroupid"],
					($usergroupcache['2']['genericpermissions'] &$bf_ugp_genericpermissions['canusecustomtitle']) ? true : false,
					false
				);
				$userdata->save();
				if ($userdata->has_errors(false))
				{
					throw $userdata->get_exception();
				}

				if ($send_validated)
				{
					if (!isset($evalemail_validated["$user[languageid]"]))
					{
						// note that we pass the "all languages" flag as true all the time because if the function does
						// caching internally and is not smart enough to check if the language requested the second time
						// was cached on the first pass -- so we make sure that we load and cache all language version
						// in case the second user has a different language from the first
						$route = vB5_Route::buildUrl('home|fullurl');
						$settings = vB5_Route::buildUrl('settings|fullurl');
						$evalemail_deleted["$user[languageid]"] = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
							'moderation_validated',
							array(
								$route,
								$username,
								$vboptions['bbtitle'],
								$settings,
							),
							array($vboptions['bbtitle']),
							$chosenlanguage
						);
					}
					vB_Mail::vbmail($user['email'], $evalemail_deleted["$user[languageid]"]['subject'], $evalemail_deleted["$user[languageid]"]['message'], true);
				}

				if ($vboptions['welcomepm'] AND $fromuser AND !$user['posts'])
				{
					$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_STANDARD);
					$userdata->send_welcomepm(null, $user['userid']);
				}
			}
			else if ($status == - 1)
			{
				// deleted

				if ($send_deleted)
				{
					if (!isset($evalemail_deleted["$user[languageid]"]))
					{
						// note that we pass the "all languages" flag as true all the time because if the function does
						// caching internally and is not smart enough to check if the language requested the second time
						// was cached on the first pass -- so we make sure that we load and cache all language version
						// in case the second user has a different language from the first
						$evalemail_deleted["$user[languageid]"] = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
							'moderation_deleted',
							array(
								$username,
								$vboptions['bbtitle'],
							),
							array($vboptions['bbtitle']),
							$chosenlanguage
						);
					}
					vB_Mail::vbmail($user['email'], $evalemail_deleted["$user[languageid]"]['subject'], $evalemail_deleted["$user[languageid]"]['message'], true);
				}

				$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
				$userdm->set_existing($user);
				$userdm->delete();
				unset($userdm);
			} // else, do nothing
		}
		// rebuild stats so new user displays on forum home
		require_once(DIR . '/includes/functions_databuild.php');
		build_user_statistics();

		return true;
	}

	/**
	 * Return a list of users for pruning or moving
	 *
	 * @param integer $usergroupid Usergroup where the users are in. -1 means all usergroups
	 * @param integer $daysprune Has not logged on for x days, 0 mean any
	 * @param integer $minposts Posts is less than, 0 means any
	 * @param array $joindate Join Date is Before. It's an array of 'month', 'day' and 'year'. Array means any
	 * @param string $order
	 * @return array Users to be pruned or moved
	 */
	public function fetchPruneUsers($usergroupid, $includeSecondary, $daysprune, $minposts, $joindate, $order)
	{
		$this->checkHasAdminPermission('canadminusers');

		$users = vB::getDbAssertor()->getRows('fetchPruneUsers', array(
			'usergroupid' => $usergroupid,
			'includesecondary' => $includeSecondary,
			'daysprune' => $daysprune,
			'minposts' => $minposts,
			'joindate' => $joindate,
			'order' => $order,
		));

		return $users;
	}

	/**
	 * Do prune/move users (step 1)
	 *
	 * @param array $userids UserID to be pruned or moved
	 * @param string $dowhat 'delete' or 'move'
	 * @param integer $movegroup Usergroup ID that the users are going to be moved
	 */
	public function prune($userids, $dowhat, $movegroup = 0)
	{
		$this->checkHasAdminPermission('canadminusers');

		if (empty($userids))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$vboptions = vB::getDatastore()->getValue('options');
		if ($dowhat == 'delete')
		{
			foreach ($userids AS $userid)
			{
				$this->delete($userid);
			}
		}
		else if ($dowhat == 'move')
		{
			$group = vB::getDbAssertor()->getRow('user_fetchusergroup', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'usergroupid' => $movegroup
				)
			);

			if (!$group)
			{
				throw new vB_Exception_Api('invalidid',
					array(vB_Phrase::fetchSinglePhrase('usergroup'), vB5_Route::buildUrl('contact-us|fullurl')));
			}

			vB::getDbAssertor()->assertQuery('user_updateusergroup', array(
				'usergroupid' => $movegroup,
				'userids' => $userids,
			));
		}
		else
		{
			throw new vB_Exception_Api('user_prune_missing_action');
		}

		return true;
	}

	/**
	 * Do prune/move users (step 2). Userids to be updated are stored in adminutil table.
	 *
	 * @param integer $startat Start at index.
	 * @return integer |bool Next startat value. True means all users have been updated.
	 */
	public function pruneUpdateposts($startat)
	{
		//function is currently unused and needs testing.
		$this->checkHasAdminPermission('canadminusers');

		$db = vB::getDbAssertor();

		require_once(DIR . '/includes/adminfunctions.php');
		$userids = fetch_adminutil_text('ids');
		if (!$userids) {
			$userids = '0';
		}
		$users = $db->getRows('user_fetch', array(
			'userids' => $userids,
			vB_dB_Query::PARAM_LIMITSTART => intval($startat),
		));

		if ($users)
		{
			foreach ($users as $user)
			{
				$db->update('vBForum:node', array('userid' => 0, 'authorname' => $user['username']),
					array('userid',  $user['userid']));
			}

			return ($startat + 50);
		}
		else
		{
			$db->assertQuery('user_deleteusertextfield', array('userids' => $userids));
			$db->getDbAssertor()->assertQuery('user_deleteuserfield', array('userids' => $userids));
			$db->getDbAssertor()->assertQuery('user_deleteuser', array('userids' => $userids));

			require_once(DIR . '/includes/functions_databuild.php');
			build_user_statistics();

			return true;
		}
	}

	/**
	 * Return user change history
	 *
	 * @param integer $userid
	 * @return array |bool User change history array. False means no change history.
	 */
	public function changeHistory($userid)
	{
		$this->checkHasAdminPermission('canadminusers');

		require_once(DIR . '/includes/class_userchangelog.php');
		require_once(DIR . '/includes/functions_misc.php');
		// initalize the $user storage
		$users = false;
		// create the vb_UserChangeLog instance and set the execute flag (we want to do the query, not just to build)
		$userchangelog = new vb_UserChangeLog(vB::get_registry());
		$userchangelog->set_execute(true);
		// get the user change list
		$userchange_list = $userchangelog->sql_select_by_userid($userid);

		if (!$userchange_list) {
			return false;
		}
		else
		{
			$usergroupcache = vB::getDatastore()->getValue('usergroupcache');
			// fetch the rows
			foreach ($userchange_list as $userchange) {
				// get/find some names, depend on the field and the content
				switch ($userchange['fieldname']) {
					// get usergroup names from the cache
					case 'usergroupid':
					case 'membergroupids': {
							foreach (array('oldvalue', 'newvalue') as $fname) {
							$str = '';
								if ($ids = explode(',', $userchange[$fname])) {
									foreach ($ids as $id) {
										if ($usergroupcache["$id"]['title']) {
											$str .= ($usergroupcache["$id"]['title']) . '<br/>';
									}
								}
							}
							$userchange["$fname"] = ($str ? $str : '-');
						}
						break;
					}
				}

				$userchanges[] = $userchange;
			}

			return $userchanges;
		}
	}

	/**
	 * Merge two users
	 *
	 * @param integer $sourceuserid
	 * @param integer $destuserid
	 */
	public function merge($sourceuserid, $destuserid)
	{
		$this->checkHasAdminPermission('canadminusers');
		$assertor = vB::getDbAssertor();

		$sourceinfo = $assertor->getRow('user_fetchwithtextfield', array('userid' => $sourceuserid));
		if (!$sourceinfo)
		{
			throw new vB_Exception_Api('invalid_source_username_specified');
		}

		$destinfo = $assertor->getRow('user_fetchwithtextfield', array('userid' => $destuserid));
		if (!$destinfo)
		{
			throw new vB_Exception_Api('invalid_destination_username_specified');
		}

		// Update Subscribed Events
		$assertor->assertQuery('userInsertSubscribeevent', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		/*
		REPLACE INTO
		*/
		// Merge relevant data in the user table
		// It is ok to have duplicate ids in the buddy/ignore lists
		$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
		$userdm->set_existing($destinfo);

		$options = vB::getDatastore()->getValue('options');
		$userdm->set('posts', $destinfo['posts'] + $sourceinfo['posts']);
		$userdm->set_ladder_usertitle_relative($sourceinfo['posts']);

		$userdm->set('lastvisit', max($sourceinfo['lastvisit'], $destinfo['lastvisit']));
		$userdm->set('lastactivity', max($sourceinfo['lastactivity'], $destinfo['lastactivity']));
		$userdm->set('lastpost', max($sourceinfo['lastpost'], $destinfo['lastpost']));
		$userdm->set('reputation', $destinfo['reputation'] + $sourceinfo['reputation'] - $options['reputationdefault']);
		$userdm->set('gmmoderatedcount', $destinfo['gmmoderatedcount'] + $sourceinfo['gmmoderatedcount']);

		//this is wrong, but it's not clear what the correct answer is at present due to VBV-14596 so let's skip
		//updating them for now.
//		$userdm->set('pmtotal', "pmtotal + $sourceinfo[pmtotal]", false);
//		$userdm->set('pmunread', "pmunread + $sourceinfo[pmunread]", false);

		if ($sourceinfo['joindate'] > 0)
		{
			// get the older join date, but only if we actually have a date
			$userdm->set('joindate', min($sourceinfo['joindate'], $destinfo['joindate']));
		}

		$userdm->set('ipoints', intval($destinfo['ipoints']) + intval($sourceinfo['ipoints']));
		$userdm->set('warnings', intval($destinfo['warnings']) + intval($sourceinfo['warnings']));
		$userdm->set('infractions', intval($destinfo['infractions']) + intval($sourceinfo['infractions']));

		$assertor->assertQuery('user_insertuserlist', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$assertor->assertQuery('user_updateuserlist', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$myfriendcount = $assertor->getField('user_fetchuserlistcount', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'userid' => $destinfo['userid'],
		));

		$userdm->set('friendcount', $myfriendcount);

		$userdm->save();
		unset($userdm);

		require_once(DIR . '/includes/functions_databuild.php');
		build_userlist($destinfo['userid']);

		// if the source user has infractions, then we need to update the infraction groups on the dest
		// easier to do it this way to make sure we get fresh info about the destination user
		if ($sourceinfo['ipoints'])
		{
			unset($usercache["$destinfo[userid]"]);
			$new_user = vB_User::fetchUserinfo($destinfo['userid']);

			$infractiongroups = array();
			$groups = $assertor->assertQuery('user_fetchinfractiongroup', array());
			foreach ($groups as $group)
			{
				$infractiongroups["$group[usergroupid]"]["$group[pointlevel]"][] = array(
					'orusergroupid' => $group['orusergroupid'],
					'override'	  => $group['override'],
				);
			}

			$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
			$userdm->set_existing($new_user);

			$infractioninfo = vB_Library::instance('Content_Infraction')->fetchInfractionGroups($infractiongroups, $new_user['userid'], $new_user['ipoints'], $new_user['usergroupid']);
			$userdm->set('infractiongroupids', $infractioninfo['infractiongroupids']);
			$userdm->set('infractiongroupid', $infractioninfo['infractiongroupid']);
			$userdm->save();
			unset($userdm);
		}
		// Update announcements
		$assertor->assertQuery('user_updateannouncement', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));
		// Update Read Announcements
		$assertor->assertQuery('userInsertAnnouncementread', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		// Update Deletion Log
		$assertor->assertQuery('user_updatedeletionlog', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
			'destusername' => $destinfo['username'],
		));

		// Update Edit Log
		$assertor->assertQuery('user_updateeditlog', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
			'destusername' => $destinfo['username'],
		));

		// Update Edit Log
		$assertor->assertQuery('user_updatepostedithistory', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
			'destusername' => $destinfo['username'],
		));

		// Update Poll Votes - find any poll where we both voted
		// we need to remove the source user's vote
		$polls = $assertor->assertQuery('usermerge_conflictedpolls', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$pollconflicts = array();
		foreach ($polls as $poll)
		{
			$pollconflicts[] = $poll['nodeid'];
		}

		if (!empty($pollconflicts))
		{
			//if both users have voted on the poll, delete the votes for the source user on that poll.
			//For single select polls we can't have both (and worse the DB will *allow* us to have both
			//if we aren't careful) and we prefer the destination user.
			//For multi select polls we could, in theory, merge the votes.  But each vote (with muliple options) is
			//presented as an atomic option (you can't, for example, vote for A and later vote for B) so it's a
			//bit weird to merge two sets of options like that.
			$assertor->delete('vBForum:pollvote', array('nodeid' => $pollconflicts, 'userid' => $sourceinfo['userid']));
		}

		$assertor->update('vBForum:pollvote', array('userid' => $destinfo['userid']),  array('userid' => $sourceinfo['userid']));

		// Polls that need to be rebuilt now
		foreach ($pollconflicts AS $nodeid)
		{
			vB_Library::instance('content_poll')->updatePollCache($nodeid);
		}

		if (!empty($pollconflicts))
		{
			//it feels like this should be part of updatePollCache above, but setting the last vote
			//sets it to now, which isn't the right answer.  Trying to improve updatePollCache is
			//beyond the scope of the current effort so we'll continue to do this by hand.  However
			//instead of pulling down a lot of data and doing individual queries we'll make it a single
			//query (though a complicated one with correlated subqueries).
			$assertor->assertQuery('usermerge_updatelastpollvote', array('nodeid' => $pollconflicts));
		}


		// Update User Notes
		$assertor->assertQuery('user_updateusernote', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$assertor->assertQuery('user_updateusernote2', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		// Update Reputation Details
		$assertor->assertQuery('user_updatereputation', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$assertor->assertQuery('user_updatereputation2', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		// Update infractions
		$assertor->assertQuery('user_updateinfraction', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$assertor->assertQuery('user_updateinfraction2', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		// Update tags
		require_once(DIR . '/includes/class_taggablecontent.php');
		vB_Taggable_Content_Item::merge_users($sourceinfo['userid'], $destinfo['userid']);

		// Clear Group Transfers
//		$assertor->assertQuery('user_updatesocialgroup', array(
//			'userid' => $sourceinfo['userid'],
//		));

		// Delete requests if the dest user already has them
		$assertor->assertQuery('userDeleteUsergrouprequest', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'sourceuserid' => $sourceinfo['userid'],
			'destusergroupid' => $destinfo['usergroupid'],
			'destmembergroupids' => $destinfo['membergroupids'],
		));
		// Convert remaining requests to dest user.
		$assertor->assertQuery('user_updateusergrouprequest', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		// Paid Subscriptions
		$assertor->assertQuery('user_updatepaymentinfo', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));
		// Move subscriptions over
		$assertor->assertQuery('user_updatesubscriptionlog', array(
			'sourceuserid' => $sourceinfo['userid'],
			'destuserid' => $destinfo['userid'],
		));

		$list = $remove = $update = array();
		// Combine active subscriptions
		$subs = $assertor->assertQuery('user_fetchsubscriptionlog', array(
			'userid' => $destinfo['userid'],
		));

		foreach ($subs as $sub)
		{
			$subscriptionid = $sub['subscriptionid'];
			$existing = $list[$subscriptionid];

			if ($existing)
			{
				if ($sub['expirydate'] > $existing['expirydate'])
				{
					$remove[] = $existing['subscriptionlogid'];
					unset($update[$existing['subscriptionlogid']]);
					$list[$subscriptionid] = $sub;
					$update[$sub['subscriptionlogid']] = $sub['expirydate'];
				}
				else
				{
					$remove[] = $sub['subscriptionlogid'];
				}
			}
			else
			{
				$list[$subscriptionid] = $sub;
			}
		}


		if (!empty($remove))
		{
			$assertor->assertQuery('user_deletesubscriptionlog', array(
				'ids' => $remove,
			));
		}

		foreach ($update AS $subscriptionlogid => $expirydate)
		{
			$assertor->assertQuery('user_updatesubscriptionlog2', array(
				'expirydate' => $expirydate,
				'subscriptionlogid' => $subscriptionlogid,
			));
		}

		//fix the names on any nodes that the user may be attached to.
		$assertor->assertQuery('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			vB_dB_Query::CONDITIONS_KEY => array('userid' => $sourceinfo['userid']),
			'authorname' => $destinfo['username'],
			'userid'     => $destinfo['userid'],
		));

		$assertor->assertQuery('vBForum:node',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			vB_dB_Query::CONDITIONS_KEY => array('lastauthorid' => $sourceinfo['userid']),
			'lastcontentauthor' => $destinfo['username'],
			'lastauthorid'     => $destinfo['userid'],
		));

		// Remove remnants of source user
		$userdm = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
		$userdm->set_existing($sourceinfo);
		$userdm->delete();
		unset($userdm);

		vB_User::clearUsersCache($sourceinfo['userid']);
		vB_User::clearUsersCache($destinfo['userid']);
		$events[] = 'userChg_' . $sourceinfo['userid'];
		$events[] = 'userChg_' . $destinfo['userid'];
		vB_Cache::allCacheEvent($events);

		return true;
	}


	/**
	 * Return if the privacy consent is required for the current session
	 *
	 * This is based on the IP address.  For security reasons we do not
	 * allow lookups for users other than the current session.
	 *
	 * @return array
	 *  --'required' int
	 *		-- 0 unknown
	 *		-- 1 Privacy Consent Required
	 *		-- 2 Privacy Consent Not Required
	 */
	public function getPrivacyConsentRequired()
	{
		$request = vB::getRequest();
		$ipaddress = $request->getIpAddress();

		return array('required' => $this->library->getPrivacyConsentRequired($ipaddress));
	}

	/**
	 * Search IP Addresses
	 *
	 * @param string $userid An userid. Find IP Addresses for user.
	 * @param integer $depth Depth to Search
	 * @return array 'regip' User's registration IP.
	 *			   'postips' IP addresses which the user has ever used to post
	 *			   'regipusers' Other users who used the same IP address to register
	 */
	public function searchIP($userid, $depth = 1)
	{
		try
		{
			$this->checkHasAdminPermission('canadminusers');
		}
		catch(vB_Exception_Api $e)
		{
			$userContext = vB::getUserContext();
			if(!$userContext->hasModeratorPermission('canviewips'))
			{
				throw $e;
			}
		}

		if (!$depth)
		{
			$depth = 1;
		}
		$userinfo = vB_User::fetchUserinfo(intval($userid));

		if (!$userinfo)
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}

		$retdata['regip'] = $userinfo['ipaddress'];
		$retdata['postips'] = $this->_searchUserIP($userid, 0, $depth);

		if ($userinfo['ipaddress'])
		{
			$retdata['regipusers'] = $this->_searchRegisterIP($userinfo['ipaddress'], $userid, $depth);
		}
		else
		{
			$retdata['regipusers'] = array();
		}

		return $retdata;
	}

	/**
	 * Search IP Addresses
	 *
	 * @param string $ipaddress An IP Address. Find Users by IP Address.
	 * @param integer $depth Search depth
	 * @return array 'postipusers' Users who used the IP address to post
	 *			   'regipusers' Users who used the IP address to register
	 */
	public function searchUsersByIP($ipaddress, $depth)
	{
		try
		{
			$this->checkHasAdminPermission('canadminusers');
		}
		catch(vB_Exception_Api $e)
		{
			$userContext = vB::getUserContext();
			if(!$userContext->hasModeratorPermission('canviewips'))
			{
				throw $e;
			}
		}

		if (!$depth)
		{
			$depth = 1;
		}

		$retdata['postipusers'] = $this->_searchIPUsage($ipaddress, 0, $depth);
		$retdata['regipusers'] = $this->_searchRegisterIP($ipaddress, 0, $depth);

		return $retdata;
	}

	/**
	 * Rewrite function construct_ip_register_table()
	 */
	protected function _searchRegisterIP($ipaddress, $prevuserid, $depth = 1)
	{
		$depth--;

		if (!$ipaddress)
		{
			return array();
		}

		$users = vB::getDbAssertor()->assertQuery('userSearchRegisterIP', array(
			'ipaddress' => $ipaddress,
			'prevuserid' => $prevuserid,
		));

		$retdata = array();
		foreach ($users as $user)
		{
			$retdata[$depth][] = $user;

			if ($depth > 0)
			{
				$retdata += $this->_searchRegisterIP($user['ipaddress'], $user['userid'], $depth);
			}
		}

		return $retdata;
	}

	/**
	 * Rewrite function construct_user_ip_table()
	 */
	protected function _searchUserIP($userid, $previpaddress, $depth = 2)
	{
		$depth--;

		$ips = vB::getDbAssertor()->assertQuery('user_searchpostip', array(
			'ipaddress' => $previpaddress,
			'userid' => $userid,
		));

		$retdata = array();
		foreach ($ips as $ip)
		{
			$retdata[$depth][] = $ip;

			if ($depth > 0)
			{
				$retdata += $this->_searchUserIP($userid, $ip['ipaddress'], $depth);
			}
		}

		return $retdata;
	}

	/**
	 * Rewrite function construct_ip_usage_table()
	 */
	protected function _searchIPUsage($ipaddress, $prevuserid, $depth = 1)
	{
		$depth--;

		if (!$ipaddress)
		{
			return array();
		}

		$users = vB::getDbAssertor()->assertQuery('userSearchIPUsage', array(
			'ipaddress' => $ipaddress,
			'prevuserid' => $prevuserid,
		));

		$retdata = array();
		foreach ($users as $user)
		{
			$retdata[$depth][] = $user;

			if ($depth > 0)
			{
				$retdata += $this->_searchIPUsage($user['ipaddress'], $user['userid'], $depth);
			}
		}

		return $retdata;
	}

	/**
	 * Return a report of referrers
	 *
	 * @param array $startdate Start Date of the report. an array of 'year', 'month', 'day', 'hour' and 'minute'
	 * @param array $enddate End Date of the report. an array of 'year', 'month', 'day', 'hour' and 'minute'
	 * @return array Referrers information
	 */
	public function fetchReferrers($startdate, $enddate)
	{
		$this->checkHasAdminPermission('canadminusers');

		require_once(DIR . '/includes/functions_misc.php');
		//checking for the month appears to be a proxy for "is the date set".
		//logic moved here from the method query where it doesn't belong
		$start = 0;
		if (!empty($startdate['month']))
		{
			$start = vbmktime_array($startdate);
		}

		$end = 0;
		if (!empty($enddate['month']))
		{
			$end = vbmktime_array($enddate);
		}

		$users = vB::getDbAssertor()->getRows('userReferrers', array(
			'startdate' => $start,
			'enddate' => $end,
		));

		return $users;
	}


	/**
	 * Check whether a user is banned.
	 *
	 * @param integer $userid User ID.
	 * @return bool Whether the user is banned.
	 */
	public function isBanned($userid)
	{
		$userid = intval($userid);
		$currentuserid = vB::getCurrentSession()->get('userid');

		if (!$userid)
		{
			$userid = $currentuserid;
		}

		if (($userid != $currentuserid) AND !$this->hasAdminPermission('canadminusers'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->isBanned($userid);
	}

	/**
	 * Check whether an email address is banned from the forums
	 *
	 * @param string $email The email address to check
	 * @return bool Whether the email is banned.
	 */
	public function isBannedEmail($email)
	{
		$vboptions = vB::getDatastore()->getValue('options');
 		$banemail = vB::getDatastore()->getValue('banemail');

		if ($vboptions['enablebanning'] AND $banemail !== null)
		{
			$bannedemails = preg_split('/\s+/', $banemail, - 1, PREG_SPLIT_NO_EMPTY);

			foreach ($bannedemails AS $bannedemail)
			{
				if (is_valid_email($bannedemail))
				{
					$regex = '^' . preg_quote($bannedemail, '#') . '$';
				}
				else
				{
					$regex = preg_quote($bannedemail, '#') . ($vboptions['aggressiveemailban'] ? '' : '$');
				}

				if (preg_match("#$regex#i", $email))
				{
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Gets the relationship of one user to another.
	 *
	 * The relationship level can be:
	 *
	 * 	3 - User 2 is a Friend of User 1 or is a Moderator
	 *  2 - User 2 is on User 1's contact list
	 *  1 - User 2 is a registered forum member
	 *  0 - User 2 is a guest or ignored user
	 *
	 * @param integer $user1 Id of user 1
	 * @param integer $user2 Id of user 2
	 * @return integer Relationship level
	 */
/*
 	//removed for VBV-16866.  Leaving commented in case we need to reference the logic later.
	public function fetchUserRelationship($user1, $user2)
	{
		static $privacy_cache = array();

		$user1 = intval($user1);
		$user2 = intval($user2);

		if (!$user2)
		{
			return 0;
		}

		if (isset($privacy_cache["$user1-$user2"]))
		{
			return $privacy_cache["$user1-$user2"];
		}

		//todo move this to a user context call and base on channels instead of moderators.
		if ($user1 == $user2 OR can_moderate(0, '', $user2)) {
			$privacy_cache["$user1-$user2"] = 3;
			return 3;
		}

		$contacts = vB::getDbAssertor()->assertQuery('user_fetchcontacts', array(
			'user1' => $user1,
			'user2' => $user2,
		));

		$return_value = 1;
		foreach ($contacts as $contact)
		{
			if ($contact['friend'] == 'yes')
			{
				$return_value = 3;
				break;
			}
			else if ($contact['type'] == 'ignore')
			{
				$return_value = 0;
				break;
			}
			else if ($contact['type'] == 'buddy')
			{
				// no break here, we neeed to make sure there is no other more definitive record
				$return_value = 2;
			}
		}

		$privacy_cache["$user1-$user2"] = $return_value;
		return $return_value;
	}
 */


	/**
	 *	Reset the current user's MFA secret
	 *
	 *	@param string $password -- the user's current password
	 *	@param string $mfa_authcode -- the authcode for the current secret, not required if the user
	 *		does not currently have an auth secret
	 */
	public function resetMfaSecret($password, $mfa_authcode=null)
	{
		$loginlib = vB_Library::instance('login');
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		//the verifyAuth function from this class recreates the session, which we don't
		//want to do here.  Copy some logic from there.
		$userInfo['username'] = vB_String::convertStringToCurrentCharset($userInfo['username']);
		$userInfo['email'] = vB_String::convertStringToCurrentCharset($userInfo['email']);
		$auth = $loginlib->verifyPasswordFromInfo($userInfo, array(array('password' => $password, 'encoding' => 'text')));
		if (!$auth['auth'])
		{
			throw new vB_Exception_Api('badpassword', vB5_Route::buildUrl('lostpw|fullurl'));
		}

		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $userInfo['userid']));
		if(!empty($mfa_user['enabled']))
		{
			$result = $loginlib->verifyMfa($mfa_user['secret'], $mfa_authcode, 'enabled');
			if (!$result)
			{
				throw new vB_Exception_Api('badmfa');
			}
		}

		$secret = $loginlib->resetMfaSecret($userInfo['userid']);
		return array('secret' => $secret);
	}

	/**
	 *	Enable the user's current MFA record after verify password and authcode
	 *
	 *	@param string $password -- the user's current password
	 *	@param string $mfa_authcode -- the authcode for the current secret, not required if the user
	 *		does not currently have an auth secret
	 */
	public function enableMfa($password, $mfa_authcode)
	{
		$loginlib = vB_Library::instance('login');
		$userInfo = vB::getCurrentSession()->fetch_userinfo();

		//the verifyAuth function from this class recreates the session, which we don't
		//want to do here.  Copy some logic from there.
		$userInfo['username'] = vB_String::convertStringToCurrentCharset($userInfo['username']);
		$userInfo['email'] = vB_String::convertStringToCurrentCharset($userInfo['email']);
		$auth = $loginlib->verifyPasswordFromInfo($userInfo, array(array('password' => $password, 'encoding' => 'text')));
		if (!$auth['auth'])
		{
			throw new vB_Exception_Api('badpassword', vB5_Route::buildUrl('lostpw|fullurl'));
		}

		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $userInfo['userid']));
		if(!$mfa_user)
		{
			throw new vB_Exception_Api('mfa_not_created');
		}

		$result = $loginlib->verifyMfa($mfa_user['secret'], $mfa_authcode, 'enabled');
		if (!$result)
		{
			throw new vB_Exception_Api('badmfa');
		}

		if(!$mfa_user['enabled'])
		{
			$loginlib->setMfaEnabled($userInfo['userid'], true);
		}

		return array('alreadyenabled' => (bool) $mfa_user['enabled']);
	}

	/**
	 *	Sets the users MFA record to enabled or disabled
	 *
	 *	Requires canadminusers permission
	 *	@param int $userid
	 *	@param bool $enabled
	 *	@return array ('success' => true)
	 */
	public function setMfaEnabled($userid, $enabled)
	{
		$this->checkHasAdminPermission('canadminusers');
		$loginlib = vB_Library::instance('login');
		$loginlib->setMfaEnabled($userid, $enabled);
		return array ('success' => true);
	}

	/**
	 *	Gets whether or not the user has an enabled MFA record
	 *
	 *	Requires canadminusers permission
	 *	@param int $userid
	 * 	@return array
	 * 		-- bool enabled
	 */
	public function isMfaEnabled($userid)
	{
		$this->checkHasAdminPermission('canadminusers');
		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $userid));
		return array('enabled' => !empty($mfa_user['enabled']));
	}

	/**
	 * Indicates if the current user needs to provide an MFA code for login.
	 *
	 * Note that it's not entirely pointless to request this for a logged
	 * in user as we can still require a login for a cpsession even after
	 * a user is logged in.
	 *
	 * @param string $logintype  -- either '', 'cplogin', 'modcplogin', 'mfareset'
	 * 	mfareset is a psuedo login where we reauthorize the login in order to
	 * 	change the mfa code.
	 * @return array
	 * 	-- bool enabled -- true if MFA auth is needed, false if not
	 */
	public function needMFA($logintype)
	{
		$config = vB::getConfig();

		//avoid repeating logic for common groupings
		$validlogintype = in_array($logintype, array('', 'cplogin', 'modcplogin', 'mfareset'));
		$cplogin = in_array($logintype, array('cplogin', 'modcplogin'));

		//we currently only require MFA for cplogins or the mfa reset
		if (empty($config['Security']['mfa_enabled']) OR $logintype == '' OR !$validlogintype)
		{
			return array('enabled' => false);
		}

		if ($cplogin)
		{
			//default mfa_force_cp to true
			if (!isset($config['Security']['mfa_force_cp']) OR $config['Security']['mfa_force_cp'])
			{
				return array('enabled' => true);
			}
		}

		//for now show the field for guests.  We *might* need it for the user and
		//if they are logged out we can't tell.  It might be better to set it up so that
		//we trap a "badmfa" error and show the UI only in that case.  But that's more
		//effort and can be done later.
		$currentUserId = vB::getCurrentSession()->get('userid');
		if (!$currentUserId)
		{
			//if we are requesting a cp login we need to allow entry
			//a mfareset login should always have a user and if somehow that's not the
			//case better to not show the MFA field.
			return array('enabled' => $cplogin);
		}

		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $currentUserId, vB_dB_Query::COLUMNS_KEY => array('enabled', 'secret')));

		return array('enabled' => !empty($mfa_user['enabled']));
	}


	/**
	 * Login a user
	 *
	 * @param string $username
	 * @param string $password
	 * @param string $md5password
	 * @param string $md5passwordutf
	 * @param string $logintype
	 *
	 * @return array
	 *	'userid' => int the id of the vbulletin user logged in
	 *	'password' => string "remeber me token".  A value that can be used to create a new
	 *		session without the user explicitly logging in
	 *	'lastvisit'
	 *	'lastactivity'
	 *	'sessionhash' => the session value used to authenticate the user on subsequent page loads
	 *	'cpsessionhash' => value needed to access the admincp.  Defines being logged in "as an admin"
	 *
	 *	@deprecated use login2
	 */
	public function login($username, $password = null, $md5password = null, $md5password_utf = null, $logintype = null)
	{
		$passwords = array(
			'password' => $password,
			'md5password' => $md5password,
			'md5password_utf' => $md5password_utf,
		);

		return $this->login2($username, $passwords, array(), $logintype);
	}


	/**
	 * Login a user
	 *
	 * @param string $username
	 * @param array $passwords -- contains at least one of
	 * 	* string password -- plain text password
	 * 	* string md5password -- md5 encoded password (legacy)
	 * 	* string md5password_utf -- md5 encoded password with utf replacements (legacy)
	 * @param array $extraAuthInfo -- information that might be required to authorize
	 * 	a user, such as numeric code for MFA
	 * @param string $logintype
	 *
	 * @return array
	 *	'userid' => int the id of the vbulletin user logged in
	 *	'password' => string "remeber me token".  A value that can be used to create a new
	 *		session without the user explicitly logging in
	 *	'lastvisit'
	 *	'lastactivity'
	 *	'sessionhash' => the session value used to authenticate the user on subsequent page loads
	 *	'cpsessionhash' => value needed to access the admincp.  Defines being logged in "as an admin"
	 */
	public function login2($username, $passwords, $extraAuthInfo, $logintype = '')
	{
		$username = vB_String::htmlSpecialCharsUni($username);

		$this->verifyCredentialExistanceError($username);
		$userInfo = vB_User::getUserInfoByCredential($username);

		if($userInfo == null)
		{
			$strikes = vB_User::verifyStrikeStatus($username);
			$this->verifyStrikeError($strikes);
			$this->processLoginError($username, $logintype, $strikes);
		}

		return $this->loginInternal($userInfo, $username, $passwords, $extraAuthInfo, $logintype);
	}

	/**
	 * Login a user for which we have the userid
	 *
	 * @param int $userid
	 * @param array $passwords -- contains at least one of
	 * 	* string password -- plain text password
	 * 	* string md5password -- md5 encoded password (legacy)
	 * 	* string md5password_utf -- md5 encoded password with utf replacements (legacy)
	 * @param array $extraAuthInfo -- information that might be required to authorize
	 * 	a user, such as numeric code for MFA
	 * @param string $logintype
	 *
	 * @return array
	 *	'userid' => int the id of the vbulletin user logged in
	 *	'password' => string "remeber me token".  A value that can be used to create a new
	 *		session without the user explicitly logging in
	 *	'lastvisit'
	 *	'lastactivity'
	 *	'sessionhash' => the session value used to authenticate the user on subsequent page loads
	 *	'cpsessionhash' => value needed to access the admincp.  Defines being logged in "as an admin"
	 */
	public function loginSpecificUser($userid, $passwords, $extraAuthInfo, $logintype = '')
	{
		$userid = (int) $userid;

		if(!$userid)
		{
			throw new vB_Exception_Api('invalid_userid');
		}

		$userInfo = vB_User::fetchUserInfo($userid);
		if(!$userInfo)
		{
			$strikes = vB_User::verifyStrikeStatus($userid);
			$this->verifyStrikeError($strikes);
			throw new vB_Exception_Api('invalid_userid');
		}

		return $this->loginInternal($userInfo, $userid, $passwords, $extraAuthInfo, $logintype);
	}

	private function loginInternal($userInfo, $username, $passwords, $extraAuthInfo, $logintype)
	{
		$strikes = vB_User::verifyStrikeStatus($userInfo['username']);
		$this->verifyStrikeError($strikes);

		$passwordInfo = array();

		if(!empty($passwords['password']))
		{
			$passwordInfo[] = array('password' => $passwords['password'], 'encoding' => 'text');
		}

		if(!empty($passwords['md5password']))
		{
			$passwordInfo[] = array('password' => $passwords['md5password'], 'encoding' => 'md5');
		}

		if(!empty($passwords['md5password_utf']))
		{
			$passwordInfo[] = array('password' => $passwords['md5password_utf'], 'encoding' => 'md5');
		}

		$auth = $this->verifyAuthentication($userInfo, $passwordInfo, $logintype);
		if (!$auth)
		{
			$this->processLoginError($username, $logintype, $strikes);
		}

		//this should either succeed or it should throw an error.
		$result = $this->verifyMfaAuthentication($userInfo['userid'], $logintype, $extraAuthInfo);
		if (!$result)
		{
			$this->processMfaError($username, $logintype, $strikes);
		}

		vB_User::execUnstrikeUser($username);
		$res = vB_User::processNewLogin($auth, $logintype);

		return $res;
	}



	/**
	 *	Log in via a third party provider.
	 *
	 * 	For now facebook is the only provider supported.  We do not support control panel logins via
	 * 	external providers.
	 *
	 *	@param string $provider.  Currently ignored, should be passed as 'facebook' since that is the only
	 *		provider recognized.
	 *
	 *	@param array $info.  The various information needed for the provider to log in.   One of
	 *		'token' or 'signedrequest' must be provided.  If both are then 'token' will be tried first.
	 *		* 'token' string the facebook access/oAuth token. (optional)
	 *		* 'signedrequest' string the facebook signedrequest.  this is a one use token that can be used
	 *			to retrieve the auth token. (optional)
	 *
	 *	@param int $userid.  If given we will only log in the requested userid. This prevents weirdness
	 *		where the front end has an FB token that does not belong to the user the front end thinks is
	 *		logged in (it's very difficult to figure out which user the token belongs to).
	 *
	 *	@return array.
	 *		'login' => array (should match the return from "login" function).  Only present if the login succeeded.
	 *			'userid' => int the id of the vbulletin user logged in
	 *			'password' => string "remeber me token" will always be blank for this method
	 *			'lastvisit'
	 *			'lastactivity'
	 *			'sessionhash' => the session value used to authenticate the user on subsequent page loads
	 *			'cpsessionhash' => will never be set for this function
	 */
	public function loginExternal($provider, $info, $userid = null)
	{
		$fblib = vB_Library::instance('facebook');
		$vbuserid = $fblib->createSessionForLogin($info);

		if($userid AND $vbuserid != $userid)
		{
			//clean up the session we just created -- probably doesn't matter
			//but it's good to be tidy.
			$fblib->clearSession();
			throw new vB_Exception_Api('error_external_wrong_vb_user', $provider);
		}

		if (!$vbuserid)
		{
			//shouldn't be here, should throw an exception if vbuserid isn't valid
			//this error isn't 100% correct but somes up the basic problem and we
			//don't really know what precisely happened.
			throw new vB_Exception_Api('error_external_no_vb_user', $provider);
		}

		$session = vB::getRequest()->createSessionForUser($vbuserid);
		$sessionUserInfo = $session->fetch_userinfo();

		//don't try to set "rememberme" for FB logins (the remember me token is called 'password' for legacy reasons.
		$auth = array(
			'userid'       => $vbuserid,
			'password'     => $provider,
			'lastvisit'    => $sessionUserInfo['lastvisit'],
			'lastactivity' => $sessionUserInfo['lastactivity']
		);

		// create new session -- this is probably 90% unnecesary both for us and for the
		// normal login, but that's how we used to do it and using it doesn't make things
		// any worse.
		$res = vB_User::processNewLogin($auth);
		return array('login' => $res);
	}

	/**
	 * Verify credential existance error
	 * @param $username
	 * @throws Exception
	 * @throws vB_Exception_Api
	 */
	private function verifyCredentialExistanceError($username)
	{
		if (!$username)
		{
			$vboptions = vB::getDatastore()->getValue('options');
			if ($vboptions['logintype'] == 0) // email
			{
				throw new vB_Exception_Api('badlogin_logintypeemail', vB5_Route::buildUrl('lostpw'));
			}
			else if ($vboptions['logintype'] == 1) // username
			{
				throw new vB_Exception_Api('badlogin_logintypeusername', vB5_Route::buildUrl('lostpw'));
			}
			else // 2 ==  both
			{
				throw new vB_Exception_Api('badlogin_logintypeboth', vB5_Route::buildUrl('lostpw'));
			}
		}
	}

	/**
	 * Verifies strike errors.
	 * @param $strikes
	 * @throws Exception
	 * @throws vB_Exception_Api
	 */
	private function verifyStrikeError($strikes)
	{
		if ($strikes === false)
		{
			throw new vB_Exception_Api('strikes', vB5_Route::buildUrl('lostpw'));
		}
	}


	/**
	 * Processes login error.
	 * @param $credential
	 * @param $logintype
	 * @param $strikes
	 * @throws Exception
	 * @throws vB_Exception_Api
	 */
	private function processLoginError($credential, $logintype, $strikes)
	{
		$vboptions = vB::getDatastore()->getValue('options');

		vB_User::execStrikeUser($credential);
		if ($logintype === 'cplogin')
		{
			// log this error if attempting to access the control panel
			require_once(DIR . '/includes/functions_log_error.php');
			log_vbulletin_error($credential, 'security');
		}

		$suffix = '';
		if ($vboptions['logintype'] == 0) // email
		{
			$suffix = 'logintypeemail';
		}
		else if ($vboptions['logintype'] == 1) // username
		{
			$suffix = 'logintypeusername';
		}
		else // 2 ==  both
		{
			$suffix = 'logintypeboth';
		}

		if ($vboptions['usestrikesystem'])
		{
			throw new vB_Exception_Api('badlogin_strikes_' . $suffix, array(vB5_Route::buildUrl('lostpw|fullurl'), $strikes + 1));
		}
		else
		{
			throw new vB_Exception_Api('badlogin_' . $suffix, vB5_Route::buildUrl('lostpw|fullurl'));
		}
	}


	/**
	 * Processes login error.
	 * @param $credential
	 * @param $logintype
	 * @param $strikes
	 * @throws Exception
	 * @throws vB_Exception_Api
	 */
	private function processMfaError($credential, $logintype, $strikes)
	{
		$vboptions = vB::getDatastore()->getValue('options');

		vB_User::execStrikeUser($credential);
		if ($logintype === 'cplogin')
		{
			// log this error if attempting to access the control panel
			require_once(DIR . '/includes/functions_log_error.php');
			log_vbulletin_error($credential, 'security');
		}

		if ($vboptions['usestrikesystem'])
		{
			throw new vB_Exception_Api('badmfa_strikes', array($strikes + 1));
		}
		else
		{
			throw new vB_Exception_Api('badmfa');
		}
	}


	/**
	 * Port of function verify_authentication()
	 *
	 * @param  $userInfo Recieves an array with username and email
	 * @param  $passwords @see vB_Library_Login::verifyPasswordFromInfo $passwords parameter
	 * @return array|bool false if auth failed. User info array if auth successfully.
	 * 	userid -- id of the user newly logged in
	 *	password -- remember me token
	 *	lastvisit -- the newly logged in user's last visit,
	 *	lastactivity -- the newly logged in user's last activity
	 */
	private function verifyAuthentication($userInfo, $passwords, $logintype = '')
	{
		$userInfo['username'] = vB_String::convertStringToCurrentCharset($userInfo['username']);
		$userInfo['email'] = vB_String::convertStringToCurrentCharset($userInfo['email']);

		$loginlib = vB_Library::instance('login');
		$auth = $loginlib->verifyPasswordFromInfo($userInfo, $passwords);
		if (!$auth['auth'])
		{
			return false;
		}

		// We check the logintype here and disallow non-admin/mods from continuing so that
		// we do NOT create/switch the user-session.
		if ($userInfo['userid'] > 0 AND ($logintype == 'cplogin' OR $logintype == 'modcplogin'))
		{
			$usercontext = vB::getUserContext($userInfo['userid']);
			$allowed = ($usercontext->isAdministrator() OR $usercontext->isModerator());
			if (!$allowed)
			{
				throw new vB_Exception_Api('badlogin_notadminmod');
			}
		}

		$session = vB::getRequest()->createSessionForUser($userInfo['userid']);
		$sessionUserInfo = $session->fetch_userinfo();

		$return_value = array(
			'userid'		=> $userInfo['userid'],
			'password'		=> $auth['remembermetoken'],
			'lastvisit'		=> $sessionUserInfo['lastvisit'],
			'lastactivity'	=> $sessionUserInfo['lastactivity']
		);

		return $return_value;
	}

	/**
	 *	Verify that the MFA information passes.
	 *
	 *	Either throws an exception or returns true.  Is always callable,
	 *	will check to ensure that the MFA check is require before
	 *	doing the validation (validation is considered passed if the
	 *	check is not required)
	 *
	 *	@param string $logintype -- either cplogin, modcplogin, or blank (regular login)
	 *	@param array $mfaAuth -- auth info for MFA with fields:
	 *		*
	 *		*
	 *	@return bool -- if the auth succeeded
	 */
	private function verifyMfaAuthentication($userid, $logintype, $mfaAuth)
	{
		$config = vB::getConfig();

		if (empty($config['Security']))
		{
			return true;
		}

		$mfaConfig = $config['Security'];

		$cpsession = ($logintype == 'cplogin' OR $logintype == 'modcplogin');

		//for the moment we only check the MFA for cp logins
		if(empty($mfaConfig['mfa_enabled']) OR !$cpsession)
		{
			return true;
		}

		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $userid));

		//if we don't have a record or the record is not enabled.
		if (!$mfa_user OR !$mfa_user['enabled'])
		{
			//default mfa_force_cp to true
			$forced = (!isset($mfaConfig['mfa_force_cp']) OR $mfaConfig['mfa_force_cp']);
			return !$forced;
		}

		$loginlib = vB_Library::instance('login');
		$result = $loginlib->verifyMfa($mfa_user['secret'], $mfaAuth['mfa_authcode'], 'enabled');
		if (!$result)
		{
			return false;
		}

		return true;
	}

	/**
	 * Logout user
	 *
	 * @param $logouthash Logout hash
	 * @return bool
	 */
	public function logout($logouthash = null)
	{
		// keeping this just because of datamanager constants
		require_once(DIR . '/includes/functions_login.php');
		// process facebook logout first if applicable

		vB_Library::instance('facebook')->clearSession();
		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		//Need to find a better way to deal with this than magic constants
		if(!(defined('VB_API') AND VB_API === true) OR (defined('VB_API_VERSION_CURRENT') AND VB_API_VERSION_CURRENT >= VB5_API_VERSION_START))
		{
			if ($userinfo['userid'] != 0 AND !vB_User::verifySecurityToken($logouthash, $userinfo['securitytoken_raw']))
			{
				throw new vB_Exception_Api('logout_error', array($userinfo['securitytoken']));
			}
		}

		return vB_User::processLogout();
	}

	/**
	 * Email user a password reset email
	 *
	 * @param integer $userid User ID
	 * @param string $email Email address
	 * @param array $hvinput Human Verify input data. @see vB_Api_Hv::verifyToken()
	 * @return bool
	 */
	public function emailPassword($userid, $email, $hvinput = array())
	{
		vB_Api::instanceInternal('hv')->verifyToken($hvinput, 'lostpw');
		vB_Library::instance('user')->sendPasswordEmail($userid, $email);
	}

	/**
	 * Set a new password for a user. Used by "forgot password" function.
	 *
	 * @param	integer  $userid
	 * @param	string   $activationid  Activation ID
	 * @param	string   $newpassword
	 *
	 * @return string[]  keys 'password_reset' & 'setnewpw_message', values
	 */
	public function setNewPassword($userid, $activationid, $newpassword)
	{
		$currentUserId = vB::getCurrentSession()->get('userid');
		if (!empty($currentUserId))
		{
			$userinfo = $this->fetchUserinfo($currentUserId);
			throw new vB_Exception_Api('changing_password_but_currently_logged_in_msg', array($userinfo['username'], $userinfo['logouthash']));
		}

		$useractivation = array();
		$userinfo = vB_User::fetchUserinfo($userid);
		$vboptions = vB::getDatastore()->getValue('options');

		if (isset($userinfo['userid']))
		{
			$useractivation = vB::getDbAssertor()->getRow('user_useractivation', array('userid' => $userinfo['userid']));
		}

		if (empty($useractivation))
		{
			// TODO: Should hitting a non-existent activation generate a reset email/record & increment the counter?
			// Need to be careful here, and may require updating the now deprecated resetPassword() (& anything else that might mess with useractivation records)

			throw new vB_Exception_Api('resetbadid', vB5_Route::buildUrl('lostpw|fullurl'));
		}

		// Need to brake brute force attempts.
		$this->processPasswordResetLockout($userinfo, $useractivation, $activationid);

 		// Is it older than 24 hours ?
 		if ($useractivation['dateline'] < (vB::getRequest()->getTimeNow() - 86400))
		{
			// Note, we're intentionally NOT resetting reset_attempts here, meaning if they happened to
			// fail 9 times yesterday, and fail again today with a new activationid, they're locked out.
			// This also means a bot or user can't just re-request a new activationid to bypass the lockout.
			// However, by throwing an exception here, it means that spamming an expired activation record
			// does not increment reset_attempts.

			//fullurl shouldn't be necesary here, but it looks like the lostpw route doesn't quite handle things without it
			throw new vB_Exception_Api('resetexpired', vB5_Route::buildUrl('lostpw|fullurl'));
		}

 		// Wrong act id ?
 		if ($useractivation['activationid'] != $activationid)
		{
			//fullurl shouldn't be necesary here, but it looks like the lostpw route doesn't quite handle things without it
			throw new vB_Exception_Api('resetbadid', vB5_Route::buildUrl('lostpw|fullurl'));
		}

		/*
			If they got to this point, they are either very lucky, and/or have the correct userid & activationid combination, which
			implies that they have access to the email associated with this user account.

			They have free reign of this account.
		 */

		$userContext = vB::getUserContext($userid);
		$expires = $userContext->getUsergroupLimit('passwordexpires');
		$overridePasswordHistory = ($expires === 0);
		$loginLib = vB_Library::instance('login');
		$loginLib->setPassword(
			$userid,
			$newpassword,
			array('passwordhistorylength' => $userContext->getUsergroupLimit('passwordhistory')),
			array('passwordhistory' => $overridePasswordHistory) // bypass if expiry = 0. Per password history desc, password history has no effect is expires == 0.
		);
		// If we got here without loginLIB throwing exceptions, password has been reset.

		// Delete old activation id
		vB::getDbAssertor()->assertQuery('user_deleteactivationid', array('userid' => $userid));


		$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
			'setnewpw',
			array(
				$userinfo['username'],
				$vboptions['frontendurl'],
				$vboptions['bbtitle'],
			),
			array($vboptions['bbtitle']),
			$userinfo['languageid']
		);
		vB_Mail::vbmail($userinfo['email'], $maildata['subject'], $maildata['message'], true);

		/*
			We could potentially pass in $userinfo['languageid'] to the fetch() call below,
			but if the current page is on a different encoding than the requested language,
			this might have weird character corruption issues.
		 */
		$response = vB_Api::instanceInternal('phrase')->fetch(array('password_reset', 'setnewpw_message'));

		return $response;
	}

	protected function processPasswordResetLockout($userinfo, $useractivation, $activationid)
	{
		/*
			If the particular activation record has had more than $attemptsLimit attempts, throw an exception and
			prevent it from being used for $lockDurationMinutes minutes, even if they have the correct activationid.

			When the lock is placed, the counter resets. This is the only way the counter resets, even if the 24
			expiry passes. This is intentional so that someone cannot bypass the lockout by just requesting a new
			activationid, and because we don't have a cron to check the expiry, but rather have a hard block on it
			@ the caller, trying to clear the counter after expiry is an added complexity that IMO is just not needed.

			This could allow a quick enough bot to perma-lock someone from resetting a password via this route,
			but they might as well be DDoSing at that point.
		 */

		// data validation. Meant for devs/unit testing really, if these values aren't present than some code changed
		// unintentionally.
		if (!isset($useractivation['reset_attempts']) OR !isset($useractivation['reset_locked_since']) OR !isset($useractivation['activationid']))
		{
			throw new vB_Exception_Api('incorrect_data');
		}

		$attemptsLimit = vB_Library_User::PASSWORD_RESET_ATTEMPTS;
		$lockDurationMinutes = vB_Library_User::PASSWORD_RESET_LOCK_MINUTES;
		$lostPWLink = vB5_Route::buildUrl('lostpw|fullurl');
		$exceptionArgs = array($lockDurationMinutes, $lostPWLink);

		/*
			If the lock is in place (checkPasswordResetLock()) or
			the placement of the lock invalidated the activationid,
			throw an exception.
		 */
		if (!empty($useractivation['reset_locked_since']))
		{
			// They need to generate a new id.
			throw new vB_Exception_Api('reset_password_lockout', $exceptionArgs);
		}
		// Currently this call is not needed as if checkPasswordResetLock() would have thrown an exception,
		// above will always throw an exception before we get here.
		// However I'm leaving it here in case of any refactor changes something about how the lock is checked.
		$this->library->checkPasswordResetLock($useractivation);

		/*
			If they have the right id, do not trigger a lockout.
			Note that the correct id does NOT allow them to bypass the lockout, see above.
		 */
 		if ($useractivation['activationid'] == $activationid)
		{
			// They pass. Caller will remove the useractivation record, so we don't have to
			// reset anything here.

			return true;
		}

		/*
			Increment the reset_attempts counter.
			Check it against the limit & do lockout if necessary
		*/
		$doLockout = (++$useractivation['reset_attempts'] >= $attemptsLimit);
		if ($doLockout)
		{
			$timeNow = vB::getRequest()->getTimeNow();
			//$useractivation['reset_attempts'] = 0;
			$useractivation['reset_locked_since'] = $timeNow;
		}

		vB::getDbAssertor()->update(
			'useractivation',
			array(
				'reset_attempts'     => $useractivation['reset_attempts'],
				'reset_locked_since' => $useractivation['reset_locked_since']
			),	// values
			array('useractivationid' => $useractivation['useractivationid']) // condition
		);

		if ($doLockout)
		{
			/*
				Warn the user when the lockout is started.
			 */
			$vboptions = vB::getDatastore()->getValue('options');
			$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
				'reset_password_lockout',
				array(
					$userinfo['username'], //1
					$attemptsLimit, 		//2
					$lockDurationMinutes, 	//3
					$lostPWLink,	//4
					vB5_Route::buildUrl('settings|fullurl', array('tab' => 'account')),	//5
					$vboptions['bbtitle'],	//6
				),
				array($vboptions['bbtitle']),
				$userinfo['languageid']
			);
			vB_Mail::vbmail($userinfo['email'], $maildata['subject'], $maildata['message'], true);

			throw new vB_Exception_Api('reset_password_lockout', $exceptionArgs);
		}
	}

	/**
	 * This checks whether a user needs COPPA approval based on birthdate. Responds to Ajax call
	 *
	 * @param array $dateInfo -- array of month/day/year.
	 * @return int
	 *   0 - no COPPA needed,
	 *   1 - Approve but require adult validation,
	 *   2 - Deny
	 */
	public function needsCoppa($dateInfo)
	{
		return $this->library->needsCoppa($dateInfo);
	}


	/**
	 * This checks whether the site uses COPPA review
	 *
	 *	@return	bool
	 */
	public function useCoppa()
	{
		$options = vB::getDatastore()->getValue('options');
		return (bool) $options['usecoppa'];
	}

	/**
	 * This checks whether the a username is available and valid
	 *
	 * @param username $
	 * @return	bool
	 */
	public function checkUsername($candidate)
	{
		$cleaner = vB::get_cleaner();
		$candidate = $cleaner->clean($candidate, vB_Cleaner::TYPE_STR);
		$options = vB::getDatastore()->getValue('options');

		if (empty($candidate))
		{
			throw new vB_Exception_Api('invalid_username_specified');
		}

		// We shouldn't use vB_String::vbStrlen() as it will count &xxx; as one character.
		$usernameLen = iconv_strlen($candidate, vB_String::getCharset());
		if ($usernameLen < $options['minuserlength'])
		{
			throw new vB_Exception_Api('invalid_username_specified_minlength_x', array($options['minuserlength']));
		}

		if ($usernameLen > $options['maxuserlength'])
		{
			throw new vB_Exception_Api('invalid_username_specified_maxlength_x', array($options['maxuserlength']));
		}

		if (!empty($options['usernameregex']))
		{
			// check for regex compliance
			if (!preg_match('#' . str_replace('#', '\#', $options['usernameregex']) . '#siU', $candidate))
			{
				throw new vB_Exception_Api('usernametaken', array(
					vB_String::htmlSpecialCharsUni($candidate),
					vB5_Route::buildUrl('lostpw|fullurl')
				));
			}
		}

		if (!empty($options['illegalusernames']))
		{
			// check for illegal username
			$usernames = preg_split('/[ \r\n\t]+/', $options['illegalusernames'], -1, PREG_SPLIT_NO_EMPTY);
			foreach ($usernames AS $val)
			{
				if (strpos(strtolower($candidate), strtolower($val)) !== false)
				{
					// wierd error to show, but hey...
					throw new vB_Exception_Api('usernametaken', array(
						vB_String::htmlSpecialCharsUni($candidate),
						vB5_Route::buildUrl('lostpw|fullurl')
					));
				}
			}
		}

		$candidate = trim(preg_replace('#[ \r\n\t]+#si', ' ', vB_String::stripBlankAscii($candidate, ' ')));
		$check = vB::getDbAssertor()->getRow('user', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'username' => $candidate));

		if (isset($check['errors']))
		{
			throw new vB_Exception_Api($check['errors'][0][0]);
		}
		else if (!empty($check))
		{
			throw new vB_Exception_Api('usernametaken', array(
				vB_String::htmlSpecialCharsUni($candidate),
				vB5_Route::buildUrl('lostpw|fullurl')
			));
		}

		return true;
	}

	public function currentUserHasAdminPermission($adminPermission)
	{
		$session = vB::getCurrentSession();
		$userInfo = $session->fetch_userinfo();
		$currentUserId = (int) $userInfo['userid'];

		//if we have a guest user for this check, it's likely that the
		//session timed out so let's return an inlinemodauth_required message.
		//if we are logged in we can check if the user is allowed to
		//have an auth session.
		if (!$session->validateCpsession() OR $currentUserId < 1)
		{
			throw new vB_Exception_Api('inlinemodauth_required');
		}

		return vB::getUserContext()->hasAdminPermission($adminPermission);
	}

	/**
	 * Returns suggested usernames for the username autocomplete popup menu.
	 *
	 * @param  string Text to search for, must be at least 3 chars long.
	 * @param  string Sort field, default 'username'
	 * @param  string Sort order, default 'ASC'
	 * @param  int    [Not used, always starts from 0] Offset to start searching from, default 0
	 * @param  int    Max number of suggestions to return, default 15, max 15
	 *
	 * @return array  Array containing one element "suggestions" which is an array.
	 *                Each element is an array containing:
	 *                    'title' => username without html entities
	 *                    'value' => username
	 *                    'id' => userid
	 */
	public function getAutocomplete($searchStr, $orderby = 'username', $direction = 'ASC', $limitstart = 0, $limitnumber = 15)
	{
		$cleaner = vB::getCleaner();

		$searchStr   = $cleaner->clean($searchStr,   vB_Cleaner::TYPE_STR);
		$orderby     = $cleaner->clean($orderby,     vB_Cleaner::TYPE_NOHTML);
		$direction   = $cleaner->clean($direction,   vB_Cleaner::TYPE_NOHTML);
		$limitstart  = $cleaner->clean($limitstart,  vB_Cleaner::TYPE_UINT);
		$limitnumber = $cleaner->clean($limitnumber, vB_Cleaner::TYPE_UINT);

		if (strlen($searchStr) < 3)
		{
			return array('suggestions' => array());
		}

		if ($limitnumber > 15)
		{
			$limitnumber = 15;
		}

		// always force $limitstart to be 0
		// I'm doing this because previously limitstart wasn't being respected
		// and I don't want to introduce a new problem by enabling it now.
		// if we actually need to use it, we just need to remove this line.
		$limitstart = 0;

		$direction = (strtoupper($direction) === 'DESC') ? 'DESC' : 'ASC';

		$query = vB::getDbAssertor()->assertQuery(
			'user',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array(
						'field' => 'username',
						'value' => "$searchStr",
						'operator' => vB_dB_Query::OPERATOR_BEGINS
					)
				),
				vB_dB_Query::FIELDS_KEY => array('username', 'userid'),
				vB_dB_Query::PARAM_LIMITSTART => $limitstart,
				vB_dB_Query::PARAM_LIMIT => $limitnumber,

			),
			array(
				'field' => $orderby,
				'direction' => $direction,
			)
		);

		$matching_users = array();

		if ($query AND $query->valid())
		{
			foreach ($query AS $user)
			{
				$matching_users[] = array(
					'title' => vB_String::unHtmlSpecialChars($user['username']),
					'value' => $user['username'],
					'id'    => $user['userid'],
				);
			}
		}

		return array('suggestions' => $matching_users);
	}

	/**
	 * This sets a user to use one of the default avatars.
	 *
	 * @param int $avatarid
	 *
	 * @result	array	the new avatar info array of custom => bool, 0=> avatarurl (string)
	 */
	public function setDefaultAvatar($avatarid)
	{
		// you can only do this for yourself.
		$userContext = vB::getUserContext();
		$userid = $userContext->fetchUserId();
		// just ignore for not logged in
		if ($userid < 1)
		{
			return;
		}
		// make sure this is a valid id.
		$assertor = vB::getDbAssertor();
		$avatarData = $assertor->getRows('avatar', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'avatarid' => $avatarid));

		if (!$avatarData OR !empty($avatarData['errors']) OR $avatarData[0]['imagecategoryid'] <> 3)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$result = $this->save($userid, null, array('avatarid' => $avatarid), array(), array(), array(), array());

		if ($result)
		{
			$assertor->assertQuery('customavatar', 	array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'userid' => $userid));
		}

		return $this->fetchAvatar($userid);
	}

	/**
	 *	Convert the search array to the assertor conditions.
	 *
	 *	Refactored from adminfunctions_user.php fetch_user_search_sql
	 */
	protected function fetchUserSearchCondition($user, $profile, $prefix = 'user')
	{
		if (!empty($prefix))
		{
			$prefix .= '.';
		}

		$conditions = array();

		$user['username'] = trim($user['username']);
		if ($user['username'])
		{
			$condition = array('field' => "{$prefix}username", 'value' => vB_String::htmlSpecialCharsUni($user['username']),
				'operator' => vB_dB_Query::OPERATOR_INCLUDES);

			if ($user['exact'])
			{
				$condition['operator'] =  vB_dB_Query::OPERATOR_EQ;
			}

			$conditions[] = $condition;
			unset($condition);
		}
		else if ($user['email'] AND $user['exact_email'])
		{
			// exact email match for VBV-15751
			$conditions[] = array('field' => "{$prefix}email", 'value' => $user['email'], 'operator' => vB_dB_Query::OPERATOR_EQ);
			unset ($user['email']); // don't try to do "includes" matching below.
		}
		else if ($user['username_or_email'])
		{
			$user['username_or_email'] = trim($user['username_or_email']);
			$op = vB_dB_Query::OPERATOR_INCLUDES;
			if ($user['exact'])
			{
				$op =  vB_dB_Query::OPERATOR_EQ;
			}
			$conditions[]  = array('field' => "{$prefix}username", 'value' => vB_String::htmlSpecialCharsUni($user['username_or_email']),
				'operator' => $op);
			$conditions[]  = array('field' => "{$prefix}email", 'value' => $user['username_or_email'],
				'operator' => $op);

			return array(
				'filters' => array(),
				'unions' => $conditions,
				'exceptions' => array('aim' => $user['aim'], 'membergroup' => $user['membergroup']),
			);
		}

		//handle the case where usergroup is an array or a singleton -- exclude the special value of -1
		$ids = false;
		if (is_array($user['usergroupid']))
		{
			$ids = array_map('intval', $user['usergroupid']);
		}
		else if ($user['usergroupid'] != -1 AND $user['usergroupid'])
		{
			$ids = intval($user['usergroupid']);
		}

		//if we have something, set the condition
		if ($ids)
		{
			$conditions[] = array('field' => "{$prefix}usergroupid", 'value' => $ids, 'operator' => vB_dB_Query::OPERATOR_EQ);
		}

		if (isset($user['coppauser']))
		{
			$user_option_fields = vB::getDatastore()->getValue('bf_misc_useroptions');
			if ($user['coppauser'] == 1)
			{
				$conditions[] = array('field' => "{$prefix}options", 'value' => $user_option_fields['coppauser'],
					'operator' => vB_dB_Query::OPERATOR_AND);
			}
			else if ($user['coppauser'] == 0)
			{
				$conditions[] = array('field' => "{$prefix}options", 'value' => $user_option_fields['coppauser'],
					'operator' => vB_dB_Query::OPERATOR_NAND);
			}
		}

		if (isset($user['facebook']))
		{
			if ($user['facebook'] == 1)
			{
				$conditions[] = array('field' => "{$prefix}fbuserid", 'value' => '',
					'operator' => vB_dB_Query::OPERATOR_NE);
			}
			else if ($user['facebook'] == 0)
			{
				$conditions[] = array('field' => "{$prefix}fbuserid", 'value' => '',
					'operator' => vB_dB_Query::OPERATOR_EQ);
			}
		}

		/*
			Privacy field searches requiring special mapping
		 */

		// At the moment, this is labeled "requires consent" in the adminCP user search form.
		// So "either" (-1) should skip setting a condition on this field, "yes" (1) should
		// search for eustatus != 2, and "no" (0) should search for eustatus == 2
		if (isset($user['eustatus_check']))
		{
			// Note, this form field is intentionally named differently than the table field
			// ("eustatus_check" vs "eustatus") to indicate that the "integer" values of the
			// form field does not map directly to the column. I.e. form 1 => eustatus IN (0, 1) / eustatus <> 2
			// form 0 => eustatus = 2
			// This is different behavior than privacyconsent below where a int value 1 maps directly
			// and only the "any" string value is treated specially.
			switch ($user['eustatus_check'])
			{
				case 1:
					// requires consent
					$conditions[] = array(
						'field' => "{$prefix}eustatus",
						'value' => '2',
						'operator' => vB_dB_Query::OPERATOR_NE,
					);
					break;
				case 0:
					// does not require consent
					$conditions[] = array(
						'field' => "{$prefix}eustatus",
						'value' => '2',
						'operator' => vB_dB_Query::OPERATOR_EQ,
					);
					break;
				case -1:
				default:
					// searcher doesn't care
					break;
			}
			unset($user['eustatus_check']);
		}

		// Consent status in the adminCP user search for has the options of  "provided",
		// "withdrawn", "unknown" and "any". Note that "unknown" and "any" are different!
		if (isset($user['privacyconsent']))
		{
			if ($user['privacyconsent'] === 'any')
			{
				// searcher doesn't care
			}
			else if ($user['privacyconsent'] == 1)
			{
				// provided consent
				$conditions[] = array(
					'field' => "{$prefix}privacyconsent",
					'value' => '1',
					'operator' => vB_dB_Query::OPERATOR_EQ,
				);
			}
			else if ($user['privacyconsent'] == -1)
			{
				// withdrew consent
				$conditions[] = array(
					'field' => "{$prefix}privacyconsent",
					'value' => '-1',
					'operator' => vB_dB_Query::OPERATOR_EQ,
				);
			}
			else if ($user['privacyconsent'] == 0)
			{
				// explicit search for user has neither provided nor withdrew consent (aka "unknown")
				$conditions[] = array(
					'field' => "{$prefix}privacyconsent",
					'value' => '0',
					'operator' => vB_dB_Query::OPERATOR_EQ,
				);
			}
			unset($user['privacyconsent']);
		}
		// privacyconsentupdatedafter & privacyconsentupdatedbefore are handled below via
		// the generic timestamp converting & search condition mapping

		//different table.
		if ($user['signature'])
		{
			$conditions[] = array('field' => 'usertextfield.signature', 'value' => $user['signature'],
				'operator' => vB_dB_Query::OPERATOR_INCLUDES);
		}

		//this is special, I'm not sure why...
		//actual filter added below with the standard filters
		if ($user['lastactivityafter'])
		{
			if (strval($user['lastactivityafter']) == strval(intval($user['lastactivityafter'])))
			{
				$user['lastactivityafter'] = intval($user['lastactivityafter']);
			}
			else
			{
				$user['lastactivityafter'] = strtotime($user['lastactivityafter']);
			}
		}

		//note that previously the date => timestamp conversion was done on the mysql side
		//with UNIX_TIMESTAMP.  In order to avoid trying to encode as an operation into the
		//DB Assertor, we'll move this to the client side.
		$dateFields = array(
			'joindateafter',
			'joindatebefore',
			'lastactivitybefore',
			'lastpostafter',
			'lastpostbefore',
			'privacyconsentupdatedafter',
			'privacyconsentupdatedbefore',
		);
		foreach ($dateFields as $field)
		{
			//strtotime is strange function, but anything valid for UNIX_TIMESTAMP should be okay here.
			if ($user[$field])
			{
				$user[$field] = strtotime($user[$field]);
			}
		}

		//standard fields
		// This is for fields that check if the given value is included in the text of a given field
		// (field like "%value%") in sql terms.  This replaces a bunch of nearly identical
		// if statements
		$fields = array (
			vB_dB_Query::OPERATOR_INCLUDES => array(
				'email', 'parentemail', 'homepage', 'icq', 'yahoo', 'msn', 'skype', 'usertitle', 'usertitle', 'ipaddress'
			),
			vB_dB_Query::OPERATOR_GT => array(
				'birthdayafter' => 'birthday_search',
				'lastactivityafter' => 'lastactivity',
				'joindateafter' => 'joindate',
				'lastpostafter' => 'lastpost',
				'privacyconsentupdatedafter' => 'privacyconsentupdated',
			),
			vB_dB_Query::OPERATOR_GTE => array(
				'postslower' => 'posts',
				'infractionslower' => 'infractions',
				'warningslower' => 'warnings',
				'pointslower' => 'ipoints',
				'reputationlower' => 'reputation',
				'useridlower' => 'userid',
			),
			vB_dB_Query::OPERATOR_LT => array(
				'birthdaybefore' => 'birthday_search',
				'lastactivitybefore' => 'lastactivity',
				'joindatebefore' => 'joindate',
				'lastpostbefore' => 'lastpost',
				'privacyconsentupdatedbefore' => 'privacyconsentupdated',

				'postsupper' => 'posts',
				'infractionsupper' => 'infractions',
				'warningsupper' => 'warnings',
				'pointsupper' => 'ipoints',
				'reputationupper' => 'reputation',
				'useridupper' => 'userid',
			),
		);

		foreach ($fields as $operator => $fieldList)
		{
			foreach ($fieldList as $key => $field)
			{
				if (is_numeric($key))
				{
					$key = $field;
				}

				if ($user[$key])
				{
					$conditions[] = array('field' => "{$prefix}$field", 'value' => $user[$key], 'operator' => $operator);
				}
			}
		}

		$profilefields = vB::getDbAssertor()->assertQuery('vBForum:fetchprofilefields');
		foreach ($profilefields as $profilefield)
		{
			$conditions = array_merge($conditions, $this->getProfileFieldConditions($profilefield, $profile));
		}

		return array('filters' => $conditions, 'exceptions' => array('aim' => $user['aim'], 'membergroup' => $user['membergroup']));
	}

	/**
	 * 	Get the profile information so the presentation can render it
	 *	@param 		int		userid
	 *	@return	array | false sigature information or false if there is an error or the user doesn't
	 *		have a sigature.  If the user is not permitted to have a signature, then they will
	 *		be treated as not having one even if it doesn't exist.
	 *		signature
	 *		permissions
	 *			dohtml
	 *			dobbcode
	 *			dobbimagecode
	 * 			dosmilies
	 *		sigpic
	 *		sigpicrevision
	 *		sigpicdateline
	 */
	public function fetchSignature($userid)
	{
		if (empty($userid))
		{
			return false;
		}
		$sigUserContext = vB::getUserContext($userid);
		$options = vB::getDatastore()->getValue('options');

		if (!$sigUserContext->hasPermission('genericpermissions', 'canusesignature') OR
			!(bool)$options['allow_signatures'])
		{
			return false;
		}
		$userInfo = vB_User::fetchUserinfo($userid);

		if(empty($userInfo['signature']))
		{
			return false;
		}

		$signature = array();
		$signature['raw'] = trim($userInfo['signature']);
		$signature['permissions'] = array(
			'dohtml' => $sigUserContext->hasPermission('signaturepermissions', 'allowhtml'),
			'dobbcode' => $sigUserContext->hasPermission('signaturepermissions', 'canbbcode'),
			'dobbimagecode' => $sigUserContext->hasPermission('signaturepermissions', 'allowimg'),
			'dosmilies' => $sigUserContext->hasPermission('signaturepermissions', 'allowsmilies'),
		);

		if (
			isset($userInfo['sigpic']) AND
			!empty($userInfo['sigpic']) AND
			$sigUserContext->hasPermission('signaturepermissions', 'cansigpic')
		)
		{
			$signature['sigpic'] = $userInfo['sigpic'];
			$signature['sigpicrevision'] = $userInfo['sigpicrevision'];
			$signature['sigpicdateline'] = $userInfo['sigpicdateline'];
		}
		//make sure that keys always exist.
		else
		{
			$signature['sigpic'] = null;
			$signature['sigpicrevision'] = null;
			$signature['sigpicdateline'] = null;
		}

		return $signature;
	}


	// ###################### Start checkprofilefield #######################
	protected function getProfileFieldConditions($profilefield, $profile)
	{
		$varname = "field$profilefield[profilefieldid]";
		$optionalvar = $varname . '_opt';

		if (isset($profile["$varname"]))
		{
			$value = $profile["$varname"];
		}
		else
		{
			$value = '';
		}

		if (isset($profile["$optionalvar"]))
		{
			$optvalue = $profile["$optionalvar"];
		}
		else
		{
			$optvalue = '';
		}

		if (empty($value) AND $optvalue === '')
		{
			return array();
		}

		if (($profilefield['type'] == 'input' OR $profilefield['type'] == 'textarea') AND $value !== '')
		{
			$conditions[] = array('field' => $varname, 'value' => vB_String::htmlSpecialCharsUni(trim($value)),
					'operator' => vB_dB_Query::OPERATOR_INCLUDES);
		}

		if ($profilefield['type'] == 'radio' OR $profilefield['type'] == 'select')
		{
			if ($value == 0 AND $optvalue === '')
			{
				// The select field was left blank!
				// and the optional field is also empty
				return array();
			}

			if ($profilefield['optional'] AND !empty($optvalue))
			{
				$conditions[] = array('field' => $varname, 'value' => htmlspecialchars_uni(trim($optvalue)),
					'operator' => vB_dB_Query::OPERATOR_INCLUDES);
			}
			else
			{
				$data = unserialize($profilefield['data']);
				foreach($data AS $key => $val)
				{
					if (($key + 1) == $value)
					{
						$conditions[] = array('field' => $varname, 'value' => htmlspecialchars_uni(trim($val)),
							'operator' => vB_dB_Query::OPERATOR_INCLUDES);
						break;
					}
				}
			}
		}

		if (($profilefield['type'] == 'checkbox' OR $profilefield['type'] == 'select_multiple') AND is_array($value))
		{
			foreach ($value AS $key => $val)
			{
				$conditions[] = array('field' => $varname, 'value' => pow(2, $val - 1), 'operator' => vB_dB_Query::OPERATOR_AND);
			}
		}
		return $conditions;
	}

	/**
	 * Fetch today's birthdays
	 * @return array birthday information
	 */
	public function fetchBirthdays()
	{
		$today = vbdate('Y-m-d', vB::getRequest()->getTimeNow(), false, false);
		$birthdaycache = vB::getDatastore()->getValue('birthdaycache');

		if (!is_array($birthdaycache)
			OR ($today != $birthdaycache['day1'] AND $today != $birthdaycache['day2'])
			OR !is_array($birthdaycache['users1'])
		)
		{
			// Need to update!
			require_once(DIR . '/includes/functions_databuild.php');
			$birthdaystore = build_birthdays();
		}
		else
		{
			$birthdaystore = $birthdaycache;
		}

		switch ($today)
		{
			case $birthdaystore['day1']:
				$birthdaysarray = $birthdaystore['users1'];
				break;

			case $birthdaystore['day2']:
				$birthdaysarray = $birthdaystore['users2'];
				break;

			default:
				$birthdaysarray = array();
		}
		// memory saving
		unset($birthdaystore);

		return $birthdaysarray;

	}

	/**
	 * Returns an array with the usernames for the user ids and optionally the profileUrl for the user
	 *
	 * @param array $userIds
	 * @param bool $profileUrl - if true include the profileUrl field in the returned array.
	 *
	 * @return array -- array($userid => array('username' => $username, 'profileUrl' => $profileUrl))
	 */
	public function fetchUsernames($userIds, $profileUrl = true)
	{
		$res = array();
		$usernames = vB_Library::instance('user')->fetchUserNames($userIds);
		foreach ($usernames AS $userid => $username)
		{
			$res[$userid]['username'] = $username;

			if ($profileUrl)
			{
				$res[$userid]['profileUrl'] = vB5_Route::buildUrl('profile', array('userid' => $userid, 'username' => $username));
			}

			$res[$userid]['userid'] = $userid;
		}
		return $res;
	}

	/**
	 * Updates the user ignore list
	 *
	 * @param int		$userid		Update ignorelist for this user.
	 * @param String[]	$userList	Usernames of ignored users.
	 */
	protected function updateIgnorelist($userid, $userList)
	{
		//we need a user record.  If we don't have one just... sulk away.
		//we should probably throw an error, but we really need to make sure
		//we won't call it this way first.
		if ($userid <= 0)
		{
			return array();
		}

		$userContext = vB::getUserContext();
		$currentUserId = $userContext->fetchUserId();
		$userid = intval($userid);
		$vboptions = vB::getDatastore()->getValue('options');

		if ($userid <= 0 AND $currentUserId)
		{
			$userid = $currentUserId;
		}

		//if it's not the current user, we need to be an admin
		if($currentUserId != $userid)
		{
			$this->checkHasAdminPermission('canadminusers');
		}

		$assertor = vB::getDbAssertor();

		// Get the list of previously ignored users
		$ignoredRes = $assertor->assertQuery('userlist', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'value' => $userid, 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'type', 'value' => 'ignore', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'friend', 'value' => 'denied', 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		));

		$ignoredDiff = array();
		foreach ($ignoredRes as $ignoredUser)
		{
			$ignoredDiff[$ignoredUser['relationid']] = $ignoredUser['relationid'];
		}

		//delete the existing ignored users
		$assertor->assertQuery('userlist', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'value' => $userid, 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'type', 'value' => 'ignore', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'friend', 'value' => 'denied', 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		));

		$ignored = array();
		if (!empty($userList))
		{
			$currentUserLvl = $userContext->getUserLevel();
			//get the ids from the userlist
			$users = $assertor->getRows('user', array('username' => $userList));

			// Update user list record
			foreach ($users as $user)
			{
				//ignore user itself
				if ($user['userid'] != $userid)
				{
					if (isset($ignoredDiff[$user['userid']]))
					{
						unset($ignoredDiff[$user['userid']]);
					}

					if (!$vboptions['ignoremods'] AND $currentUserLvl < vB::getUserContext($user['userid'])->getUserLevel())
					{
						throw new vB_Exception_Api('listignoreuser', array($user['username']));
					}

					$existing = $assertor->getRow('userlist', array(
						'userid' => $userid,
						'relationid' => $user['userid']
					));

					// update the record
					if ($existing AND !empty($existing) AND empty($existing['errors']))
					{
						$queryData = array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
							vB_dB_Query::CONDITIONS_KEY => array(
							'userid' => $userid,
							'relationid' => $user['userid']),
							'type' => 'ignore',
							'friend' => 'denied'
						);
					}
					else
					{
						$queryData = array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
							'userid' => $userid,
							'relationid' => $user['userid'],
							'type' => 'ignore',
							'friend' => 'denied'
						);
					}
					$response = $assertor->assertQuery('userlist', $queryData);
					$ignored[] = $user['userid'];
				}
			}

			$assertor->assertQuery('userlist', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'userid' => $ignoredDiff,
				'relationid' => $userid,
				'type' => 'follow',
				'friend' => 'pending'
			));
		}

		// return the ids ignored
		return $ignored;
	}

	/**
	 * Updates the user status
	 *
	 * @param int		UserID
	 * @param String	Status to set
	 *
	 * @return	String	Updated status from user.
	 */
	public function updateStatus($userid = false, $status)
	{
		$userContext = vB::getUserContext();
		$currentUserId = $userContext->fetchUserId();
		$userid = intval($userid);
		$vboptions = vB::getDatastore()->getValue('options');

		if (vB_String::vbStrlen($status) > $vboptions['statusMaxChars'])
		{
			throw new vB_Exception_Api('please_enter_user_status_with_at_most_x_characters', array($vboptions['statusMaxChars']));
		}

		if ($userid <= 0 AND $currentUserId)
		{
			$userid = $currentUserId;
		}

		// check user is logged
		if (!$userid OR !$currentUserId)
		{
			throw new vB_Exception_Api('invalid_userid');
		}

		// Check if current user canadminusers
		try
		{
			$this->checkHasAdminPermission('canadminusers');
		}
		catch (Exception $e)
		{
			// No. Then we need to do something here.
			if ($currentUserId != $userid)
			{
				// If current user isn't the same as passed $userid
				throw new vB_Exception_Api('no_permission');
			}
		}

		$userInfo = vB_User::fetchUserinfo($userid);
		$userdata = new vB_Datamanager_User();
		$userdata->set_existing($userInfo);
		$userdata->set('status', $status);
		$result = $userdata->save();

		if (!is_array($result))
		{
			$userInfo = vB_User::fetchUserinfo(0, array(), 0, true);

			// Check for monitored words in user status and send notifications
			$this->library->monitorWords($userInfo['status'], 'user-status', null, $userInfo['userid']);

			return $userInfo['status'];
		}
		else
		{
			return false;
		}
	}

	/**
	 * Ban users
	 *
	 * @param array $userids Userids to ban
	 * @param int $banusergroupid Which banned usergroup to move the users to
	 * @param string $period Ban period
	 * @param string $reason Ban reason
	 */
	public function banUsers($userids, $banusergroupid, $period, $reason = '')
	{
		$assertor = vB::getDbAssertor();
		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		$usercontext = &vB::getUserContext($loginuser['userid']);
		if (!$usercontext->hasAdminPermission('cancontrolpanel') AND !$usercontext->hasPermission('moderatorpermissions', 'canbanusers'))
		{
			$forumHome = vB_Library::instance('content_channel')->getForumHomeChannel();
			throw new vB_Exception_Api('nopermission_loggedin',
				array (
					$loginuser['username'],
					vB_Template_Runtime::fetchStyleVar('right'),
					$loginuser['securitytoken'],
					vB5_Route::buildUrl($forumHome['routeid'] . '|fullurl'),
				)
			);
		}

		if (!is_array($userids))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userids, 'userids', __CLASS__, __FUNCTION__));
		}

		foreach ($userids as &$userid)
		{
			$userid = intval($userid);
		}

		$bannedusergroups = vB_Api::instanceInternal('usergroup')->fetchBannedUsergroups();

		if (!in_array($banusergroupid, array_keys($bannedusergroups)))
		{
			throw new vB_Exception_Api('invalid_usergroup_specified');
		}

		// check that the number of days is valid
		if ($period != 'PERMANENT' AND !preg_match('#^(D|M|Y)_[1-9][0-9]?$#', $period))
		{
			throw new vB_Exception_Api('invalid_ban_period_specified');
		}

		if ($period == 'PERMANENT')
		{
			// make this ban permanent
			$liftdate = 0;
		}
		else
		{
			// get the unixtime for when this ban will be lifted
			require_once(DIR . '/includes/functions_banning.php');
			$liftdate = convert_date_to_timestamp($period);
		}

		$user_dms = array();

		$current_bans = $assertor->getRows('user_fetchcurrentbans', array(
			'userids' => $userids
		));
		foreach ($current_bans as $current_ban)
		{
			$userinfo = vB_User::fetchUserinfo($current_ban['userid']);
			$userid = $userinfo['userid'];

			if ($current_ban['bandate'])
			{
				// they already have a ban, check if the current one is being made permanent, continue if its not
				if ($liftdate AND $liftdate < $current_ban['liftdate'])
				{
					continue;
				}

				// there is already a record - just update this record
				$assertor->update('userban',
					array(
						'bandate' => vB::getRequest()->getTimeNow(),
						'liftdate' => $liftdate,
						'adminid' => $loginuser['userid'],
						'reason' => $reason,
					),
					array(
						'userid' => $userinfo['userid'],
					)
				);


			}
			else
			{
				// insert a record into the userban table
				/*insert query*/
				$assertor->insert('userban', array(
					'userid' => $userinfo['userid'],
					'usergroupid' => $userinfo['usergroupid'],
					'displaygroupid' => $userinfo['displaygroupid'],
					'customtitle' => $userinfo['customtitle'],
					'usertitle' => $userinfo['usertitle'],
					'adminid' => $loginuser['userid'],
					'bandate' => vB::getRequest()->getTimeNow(),
					'liftdate' => $liftdate,
					'reason' => $reason,
				));
			}

			// update the user record
			$user_dms[$userid] = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
			$user_dms[$userid]->set_existing($userinfo);
			$user_dms[$userid]->set('usergroupid', $banusergroupid);
			$user_dms[$userid]->set('displaygroupid', 0);
			$user_dms[$userid]->set('status', ''); // clear status, VBV-15853

			// update the user's title if they've specified a special user title for the banned group
			if ($bannedusergroups[$banusergroupid]['usertitle'] != '')
			{
				$user_dms[$userid]->set('usertitle', $bannedusergroups[$banusergroupid]['usertitle']);
				$user_dms[$userid]->set('customtitle', 0);
			}
			$user_dms[$userid]->pre_save();
		}

		foreach ($user_dms AS $userdm)
		{
			$userdm->save();
		}

		// and clear perms
		foreach ($userids AS $uid)
		{
			vB::getUserContext($uid)->clearChannelPermissions();
		}

		return true;
	}

	/**
	 * Returns global permission value or specific value for a nodeid for current user.
	 * @param string $group
	 * @param string $permission
	 * @param boolean $nodeid (optional)
	 * @return boolean|int
	 */
	public function hasPermissions($group, $permission, $nodeid = false)
	{
		if ($this->disabled)
		{
			// if disabled we do not have permission
			return false;
		}

		if ($group == 'adminpermissions')
		{
			//adminpermissions are always global.
			return vB::getUserContext()->hasAdminPermission($permission);
		}
		else if (empty($nodeid))
		{
			return vB::getUserContext()->hasPermission($group, $permission);
		}
		else
		{
			return vB::getUserContext()->getChannelPermission($group, $permission, $nodeid);
		}
	}

	/**
	 * Checks the various options as to whether the current user can physically remove a post

	 * @param integer $nodeid
	 *
	 * @return integer	0 or 1
	 */
	public function canRemovePost($nodeid)
	{
		if ($this->disabled)
		{
			// if disabled we do not have permission
			return 0;
		}

		$nodeid = vB::getCleaner()->clean($nodeid, vB_Cleaner::TYPE_INT);
		$userContext = vB::getUserContext();

		//if the user has global canremove, we're done
		if ($userContext->hasPermission('moderatorpermissions', 'canremoveposts') OR
			$userContext->getChannelPermission('moderatorpermissions', 'canremoveposts', $nodeid))
		{
			return 1;
		}

		//If this is is a visitor message, we check some other permissions.
		$node = vB_Library::instance('node')->getNodeBare($nodeid);
		if (($node['starter'] > 0) AND ($node['setfor'] > 0))
		{
			if ($userContext->hasPermission('moderatorpermissions2', 'canremovevisitormessages'))
			{
				return 1;
			}
			else if (($node['setfor'] == vB::getCurrentSession()->get('userid')) AND
				$userContext->hasPermission('visitormessagepermissions', 'candeleteownmessages'))
			{
				return 1;
			}
		}
		return 0;
	}


	/**
	 * Returns permission values of a group of nodes for current user.
	 * @param string $group
	 * @param string $permission
	 * @param array $nodeIds
	 * @return boolean|int
	 * @see vB_Api_User::hasPermissions
	 */
	public function havePermissions($group, $permission, $nodeIds = array())
	{
		if (empty($nodeIds))
		{
			return array();
		}

		$cleaner = vB::get_cleaner();
		$nodeIds = $cleaner->clean($nodeIds, vB_Cleaner::TYPE_ARRAY_INT);

		$result = array();

		foreach($nodeIds AS $nodeId)
		{
			$result[$nodeId] = $this->hasPermissions($group, $permission, $nodeId);
		}

		return $result;
	}

	/**
	 *	Invites members to a given node channel passing either an array of userids or usernames.
	 *
	 *	Will combine the list of username with the list of userids to get the list of
	 *	users to invite.
	 *
	 *	@param array 				$userids
	 *	@param array|string	$userNames
	 *	@param int 					$nodeId
	 *	@param string 			$requestType --	Either 'member_to' (blogs) or 'sg_member_to' (social groups)
	 *
	 *	@param array		List of the sucessfully invited members.
	 */

	public function inviteMembers($userIds, $userNames, $nodeId, $requestType)
	{
		$inviteMembers = array();
		// fetch userids...
		if (!is_array($userNames))
		{
			$userNames = array($userNames);
		}

		$users = array();
		if (is_array($userNames) AND !empty($userNames))
		{
			$users = vB::getDbAssertor()->assertQuery('user', array('username' => $userNames));
			if ($users AND !$users->valid())
			{
				$users = array();
			}
		}

		foreach ($users AS $user)
		{
			$inviteMembers[] = $user['userid'];
		}

		// and check that userids are valid...
		if (!is_array($userIds))
		{
			$userIds = array($userIds);
		}

		foreach ($userIds AS $pos => $id)
		{
			if (!intval($id))
			{
				unset($userIds[$pos]);
			}
		}

		$inviteMembers = array_unique(array_merge($inviteMembers, $userIds));
		if (empty($inviteMembers))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!intval($nodeId))
		{
			throw new vB_Exception_Api('invalid_node_id');
		}
		// let's check that node really exists
		$nodeApi = vB_Api::instanceInternal('node');
		$node = $nodeApi->getNode($nodeId);

		//and check that these invites don't already exist.

		$existingCheck =  vB::getDbAssertor()->assertQuery('vBForum:getExistingRequest', array(
			'userid' => $inviteMembers,
			'nodeid' => $nodeId,
			'request' => $requestType)
		);

		if ($existingCheck->valid())
		{
			foreach ($existingCheck AS $existing)
			{
				unset($inviteMembers[$existing['userid']]);
			}
		}
		$invited = array();
		foreach ($inviteMembers AS $member)
		{
			//requestChannel enforces permissions necesary
			$response = vB_Library::instance('node')->requestChannel($nodeId, $requestType, $member, null, true);
			if (!is_array($response))
			{
				$invited[] = $member;
			}
		}

		return $invited;
	}

	/**
	 *	Generates users mailing list for the given criteria.
	 *	Used for admincp - email sending and list generating.
	 *
	 * 	@param 	array 	$user 		An array of common conditions for user search
	 * 	@param 	array 	$profile 	An array of user profile field conditions for user search
	 * 	@param	array	$options 	Set of options such as activation info and pagination.
	 *
	 *	@return bool |array False if no user found. Otherwise it returns users array as result.
	 *		 The array also contains a field that stores total found user's e-mail count.
	 */
	public function generateMailingList($user, $profile, $options = array())
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminusers'))
		{
			throw new vB_Exception_Api('invalid_permissions');
		}

		$conditions = $this->fetchUserSearchCondition($user, $profile);
		$conditions['options'] = array('adminemail' => $user['adminemail']);

		if (!empty($options['activation']))
		{
			$conditions['activation'] = 1;
			$conditions[vB_dB_Query::PARAM_LIMITPAGE] = (intval($options[vB_dB_Query::PARAM_LIMITPAGE])) ? intval($options[vB_dB_Query::PARAM_LIMITPAGE]) : 0;
			$conditions[vB_dB_Query::PARAM_LIMIT] = (intval($options[vB_dB_Query::PARAM_LIMIT])) ? intval($options[vB_dB_Query::PARAM_LIMIT]) : 500;
		}

		$db = vB::getDbAssertor();

		$mailList = $db->getRows('fetchMailingList', $conditions);

		if (!empty($options['activation']))
		{
			$count = $db->getRow('fetchMailingListCount', $conditions);
			$count = $count['total'];
		}
		else
		{
			$count = count($mailList);
		}

		return array('list' => $mailList, 'totalcount' => $count);
	}

	/**
	 *	Fetch users and info from a given user criteria
	 *	Used for admincp - verticalresponse.
	 *
	 * 	@param 	array 	$user 		An array of common conditions for user search
	 * 	@param 	array 	$profile 	An array of user profile field conditions for user search
	 * 	@param	array	$options 	Set of options such as activation info and pagination.
	 *
	 *	@return array 	$result 	Result which includes the 'users' => userlist and the 'totalcount'.
	 */
	public function getUsersFromCriteria($user, $profile, $options = array())
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminusers'))
		{
			throw new vB_Exception_Api('invalid_permissions');
		}

		$conditions = $this->fetchUserSearchCondition($user, $profile);
		if (!empty($options[vB_dB_Query::PARAM_LIMITPAGE]) OR !empty($options[vB_dB_Query::PARAM_LIMIT]))
		{
			$conditions[vB_dB_Query::PARAM_LIMITPAGE] = (intval($options[vB_dB_Query::PARAM_LIMITPAGE])) ? intval($options[vB_dB_Query::PARAM_LIMITPAGE]) : 1;
			// default 50...
			$conditions[vB_dB_Query::PARAM_LIMIT] = (intval($options[vB_dB_Query::PARAM_LIMIT])) ? intval($options[vB_dB_Query::PARAM_LIMIT]) : 50;
		}

		$userList = vB::getDbAssertor()->getRows('fetchUsersFromCriteria', $conditions);
		return array('users' => $userList, 'totalcount' => count($userList));
	}

	/**
	 *	Fetch private messages statistics from all the users.
	 *	Used for admincp - usertools private message statistics
	 *	@TODO implement in class cache to user in some others places...
	 *
	 * 	@param	array	$options 	Set of options such as pagination, total pms filter.
	 *
	 *	@return array 	$result 	Private messages grouped by userid (including some userinfo and pm total count).
	 */
	public function fetchUsersPms($options = array())
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminusers'))
		{
			throw new vB_Exception_Api('invalid_permissions');
		}

		$params = array();
		if (!empty($options[vB_dB_Query::PARAM_LIMITPAGE]) OR !empty($options[vB_dB_Query::PARAM_LIMIT]))
		{
			$params[vB_dB_Query::PARAM_LIMITPAGE] = (intval($options[vB_dB_Query::PARAM_LIMITPAGE])) ? intval($options[vB_dB_Query::PARAM_LIMITPAGE]) : 1;
			// default 50...
			$params[vB_dB_Query::PARAM_LIMIT] = (intval($options[vB_dB_Query::PARAM_LIMIT])) ? intval($options[vB_dB_Query::PARAM_LIMIT]) : 50;
		}

		if (!empty($options['total']))
		{
			$params['total'] = intval($options['total']);
		}

		if (!empty($options['sortby']))
		{
			$params['sortby'] = array($options['sortby']);
		}

		if (!empty($options[vB_dB_Query::CONDITIONS_KEY]))
		{
			$params[vB_dB_Query::CONDITIONS_KEY] = $options[vB_dB_Query::CONDITIONS_KEY];
		}

		$pms = vB::getDbAssertor()->getRows('vBForum:getUsersPms', $params);
		return $pms;
	}

	/**
	 * This implements vB_PermissionContext::getAdminUser().
	 * return	int		User id from a user that can administer the admincp
	 */
	public function fetchAdminUser()
	{
		return vB_PermissionContext::getAdminUser();
	}

	/**
	 * This gets the current user profile fields from the database.
	 * @TODO improve this to be consistent with profilefield table. We should wrap that out when moving user profile fields add/updating to the API
	 *
	 * @return	array	The title of the existing user profile fields.
	 */
	public function fetchUserProfileFields()
	{
		$uFields = vB::getDbAssertor()->assertQuery('fetchUserFields');
		$fields = array();
		while($uFields AND $uFields->valid())
		{
			$field = $uFields->current();
			if ($field['Field'] != 'temp' AND $field['Field'] != 'userid')
			{
				$fields[] = $field['Field'];
			}

			$uFields->next();
		}

		return $fields;
	}

	/**
	 * Get the user title regarding the given posts.
	 *
	 * @param	int		Number of user posts.
	 *
	 * @return	string	User title.
	 */
	public function getUsertitleFromPosts($posts)
	{
		if (!is_numeric($posts))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (isset($this->usertitleCache[$posts]))
		{
			return $this->usertitleCache[$posts];
		}

		$title = vB::getDbAssertor()->getRow('usertitle', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'minposts', 'value' => $posts, 'operator' => 'LTE')
				)
			), array('field' => array('minposts'), 'direction' => array(vB_dB_Query::SORT_DESC))
		);

		$this->usertitleCache[$posts] = $title['title'];
		return $this->usertitleCache[$posts];
	}

	/**
	 * Mostly a getter for user privacy options.
	 *
	 * @return	array	Existing user privacy options.
	 */
	public function getPrivacyOptions()
	{
		return $this->privacyOptions;
	}

	/**
	 * This likes the channels below a parent node where a user can create starters based on groupintopic
	 * @param	int $parentNodeId -- the ancestor node id
	 *
	 * @return array array of integer, title- the nodeids
	 */
	public function getGitCanStart($parentNodeId)
	{
		$groupsCanContribute = vB::getUserContext()->getContributorGroups($parentNodeId);

		return vB::getDbAssertor()->getRows('vBForum:getGitCanStartThreads', array('parentnodeId' => $parentNodeId,
		'contributors' => $groupsCanContribute, 'userid' => vB::getCurrentSession()->get('userid')));

	}

	/**
	 * Tells whether the current user can create a blog entry. That can be their own permissions or GIT.
	 * @param int $nodeid	-- optional. If not passed will check the global blog channel.
	 * @return 1 if the user can create a entry in the given channel.  0 otherwise
	 */
	public function canCreateBlogEntry($nodeid = 0)
	{
		//This is called from the templates, so we return 0/1.  Templates have problems with true/false.
		if (empty($nodeid) AND vB::getUserContext()->hasPermission('forumpermissions', 'cancreateblog'))
		{
			return 1;
		}

		if (empty($nodeid))
		{
			$nodeid = vB_Library::instance('blog')->getBlogChannel();
		}
		$canStart = $this->getGitCanStart($nodeid);

		if (!empty($canStart))
		{
			return 1;
		}

		return 0;
	}

	/** Adjust GMT time back to user's time
	 * Use "gm" versions of date/time functions with this offset, not ones that rely on
	 * current server's system timezone.
	 *
	 * @param type $adjustForServer
	 * @param int  $userid             (Optional) If skipped, will use current user's offset.
	 *                                 If provided, will use that user's offset.
	 *
	 * @return integer
	 */
	public function fetchTimeOffset($adjustForServer = false, $userid = false, $ignoreDST = false)
	{
		if ($userid === false)
		{
			$userInfo = vB::getCurrentSession()->fetch_userinfo();
		}
		else
		{
			$userInfo = $this->library->fetchUserinfo($userid);
		}

		$hourdiff = null;
		if (is_array($userInfo) AND isset($userInfo['timezoneoffset']))
		{
			if ($ignoreDST)
			{
				return $userInfo['timezoneoffset'] * 3600;
			}

			$options = vB::getDatastore()->getValue('options');
			if (
				(isset($userInfo['dstonoff']) AND $userInfo['dstonoff']) OR
				(isset($userInfo['dstauto']) AND $userInfo['dstauto'] AND $options['dstonoff'])
			)
			{
				// DST is on, add an hour
				$userInfo['timezoneoffset']++;
				if ((substr($userInfo['timezoneoffset'], 0, 1) != '-') AND (substr($userInfo['timezoneoffset'], 0, 1) != '+'))
				{
					// recorrect so that it has a + sign, if necessary
					$userInfo['timezoneoffset'] = '+' . $userInfo['timezoneoffset'];
				}
			}

			if ($options['dstonoff'] AND $adjustForServer)
			{
				$userInfo['timezoneoffset']--;
			}
			$hourdiff = $userInfo['timezoneoffset'] * 3600;
		}

		return $hourdiff;
	}


	/**
	 * translate a year/month/day/hour/minute to a Unix timestamp.
	 *
	 * @param	array $dateInfo -- array of year, month, day, hour, minute, second. Year and month are required.
	 *
	 * @return integer -- Unix Timestamp, corrected for the user's time setting
	 */
	public function vBMktime($dateInfo)
	{
		// The date has already been corrected to .. date_default_timezone_get(),
		//	which could be the server setting but might not be.
		// The most reliable thing is to just get that offset.
		static $userOffset;

		if (empty($dateInfo['year']) OR empty($dateInfo['month']) OR ($dateInfo['month'] > 12))
		{
			return 0;
		}

		if (empty($dateInfo['day']) OR !intval($dateInfo['day']) OR (intval($dateInfo['day']) > 31) OR (intval($dateInfo['day']) < 1))
		{
			$dateInfo['day'] = 1;
		}
		// !isset() instead of empty(), because 00:00:00 is a real time (today's 12AM, previous day's "24:00:00")
		// Most 24 hour clocks go from 00:00 to 23:59 to get rid of the ambiguity of 24:00 which many consider to be the next day.
		if (!isset($dateInfo['hour']) OR !intval($dateInfo['hour']) OR (intval($dateInfo['hour']) >= 24) OR (intval($dateInfo['hour']) < 0))
		{
			// 12 might make sense if we were on a am/pm 12-h notation, but this function doesn't seem to allow that. So to me 0 makes more sense
			// as the default. Also technically mktime/gmmktime supports negative hours & hours greater than 23 (previous day, next day, respectively)
			//$dateInfo['hour'] = 12;
			$dateInfo['hour'] = 0;
		}

		if (empty($dateInfo['minute']) OR !intval($dateInfo['minute']) OR (intval($dateInfo['minute']) > 60) OR (intval($dateInfo['minute']) < 0))
		{
			$dateInfo['minute'] = 0;
		}

		if (empty($dateInfo['second']) OR !intval($dateInfo['second']) OR (intval($dateInfo['second']) > 60) OR (intval($dateInfo['second']) < 0))
		{
			 $dateInfo['second'] = 0;
		}

		$currentUserId = vB::getCurrentSession()->get('userid');
		if (!isset($userOffset[$currentUserId]))
		{
			$userOffset[$currentUserId] = $this->fetchTimeOffset();
		}

		$date = gmmktime($dateInfo['hour'], $dateInfo['minute'], $dateInfo['second'], $dateInfo['month'], $dateInfo['day'], $dateInfo['year']);
		/*
			For GMT => User time: Time + offset
			e.g. offset = -8 (PST), GMT -> PST: 7PM (GMT) + -8 (PST offset) = 11AM (PST)
			For User time => GMT: Time - offset
			e.g. offset = -5 (EST), EST -> GMT: 3PM (EST) - -5 (EST offset) = 8PM (GMT)
		 */
		return $date - $userOffset[$currentUserId];
	}

	/*
	 * Takes a readable time string and converts it to unixtimestamp (UTC)
	 *
	 * @param  string  $strTime  A well formated time string, e.g. "2016/12/31 11:59PM" "2017/01/01 12:00AM PST"
	 *
	 * @return  array('unixtimestamp' => int converted timestamp)
	 */
	public function userTimeStrToUnixtimestamp($strTime, $userid = false, $ignoreDST = true)
	{
		/*
			TODO: add unit tests for this & polltimeouts.
		 */

		/*
			Offset is strictly relative to GMT, NOT GMT + server time (as it was previously).
			strtotime() depends on system timezone. To skip dealing with any madness, we temporarily
			set the default timezone to UTC (in case $strTime actually has a timezone specified)
		 */
		$oldTz = date_default_timezone_get();
		date_default_timezone_set('UTC');

		$offset = $this->fetchTimeOffset(false, $userid, $ignoreDST);
		$timestamp = intval(strtotime(trim(strval($strTime)))) - $offset;

		// set it back in case some other downstream logic requires the old system time back.
		date_default_timezone_set($oldTz);


		return array('unixtimestamp' => $timestamp);
	}

	/*
	 * Takes a unixtimestamp and converts it into a readable date/time string for the current user.
	 * Basically inverts userTimeStrToUnixtimestamp().
	 *
	 * @param  string  $timestamp  Unixtimestamp ("unadjusted" for user's offset)
	 * @param  int     $userid     Optional userid, if not for current user.
	 * @param  string  $format     Optional output date format
	 *
	 * @return  array('datestr' => string converted datestring)
	 */
	public function unixtimestampToUserDateString($timestamp, $userid = false, $format = "Y-m-d H:i:s", $ignoreDST = true)
	{
		/*
			We basically pretend that the user is on GMT so that we can use gmdate() and
			forget about server timezone.
			For ex.
			2017-10-17 1:22PM PST = 1508271720
			2017-10-17 1:22PM GMT = 1508246520
			PST -> GMT = PST - 7 hours (aka + $offset).
			So if we want gmdate(timestamp) = 2017-10-17 1:22PM, we need to feed it the GMT time,
			which is + offset
		 */
		$offset = $this->fetchTimeOffset(false, $userid, $ignoreDST);
		$timestamp = $timestamp + $offset;

		$datestr = gmdate($format, $timestamp);


		return array('datestr' => $datestr);
	}

	private function sanitizeUserInfo($userInfo, $currentUserId)
	{
		$userInfo = $this->stripPrivateUserFields($userInfo);

		$noUserOnlyFields = (($userInfo['userid'] != $currentUserId) AND !$this->hasAdminPermission('canadminusers'));
		if($noUserOnlyFields)
		{
			$userInfo = $this->blankUserOnlyFields($userInfo);
		}

		//blank coppa only fields
		if ($noUserOnlyFields OR !$this->useCoppa() OR empty($userInfo['birthday']) OR !$this->needsCoppa($userInfo['birthday']))
		{
			$userInfo['coppauser'] = '';
			$userInfo['parentemail'] = '';
		}

		return $userInfo;
	}

	/**
	 * Strips fields that should *never* be returned by the API.  Full stop. Don't do it.
	 * not even if the user is a super special mega admin.
	 *
	 * @param $userInfo
	 * @return The user info array without the private fields.
	 */
	private function stripPrivateUserFields($userInfo)
	{
		$fields = array('token', 'scheme', 'secret', 'securitytoken_raw');

		foreach ($fields AS $field)
		{
			unset($userInfo[$field]);
		}

		return $userInfo;
	}

	/**
	 * Blank fields that only the user themselves should see.  We can also allow admins with the
	 * correct privs to see those too.  Note that this function doesn't actually check
	 * if the user should be able to see them, it just blanks them out.
	 *
	 * This doesn't actually remove the keys from the array in order to provide a consistant
	 * array format regardless of the user's permissions.
	 *
	 * @param $userInfo
	 * @return The user info array without the user fields set to ''
	 */
	private function blankUserOnlyFields($userInfo)
	{
		$fields = array(
			'coppauser', 'parentemail', 'passworddate', 'ipaddress', 'passworddate', 'email', 'referrerid',
			'ipoints', 'infractions', 'warnings', 'infractiongroupids', 'infractiongroupid', 'logouthash', 'securitytoken',
			'eustatus'
		);

		foreach ($fields AS $field)
		{
			$userInfo[$field] = '';
		}

		return $userInfo;
	}

	/**
	 * Updates guest privacy consent
	 *
	 * @param bool True if consenting, false otherwise
	 */
	public function updateGuestPrivacyConsent($consent)
	{
		$this->library->updateGuestPrivacyConsent($consent);

		return array(
			'success' => true,
		);
	}

	/**
	 * Set privacy consent and eu status for user
	 *
	 * @param int   User ID
	 * @param array Array containing one or both keys "eustatus" or "privacyconsent"
	 */
	public function setPrivacyConsent($userid, $data = array())
	{
		$userdata = array();

		if (isset($data['eustatus']))
		{
			$userdata['eustatus'] = $data['eustatus'];
		}
		if (isset($data['privacyconsent']))
		{
			$userdata['privacyconsent'] = $data['privacyconsent'];
		}

		return $this->save(
			$userid,
			null,
			$userdata,
			array(),
			array(),
			array(),
			array(),
			array(),
			array('acnt_settings' => 1)
		);
	}

	/**
	 *	Returns a report on "personal information" for a user
	 *
	 *	This is the personally identifiable information for
	 *	privacy laws.  Currently this follows our best understanding
	 *	of the EU law, but eventually this may end up being a superset
	 *	of all simpilar laws.
	 *
	 *	@param $userid (optional)
	 *	@return array of information. See the library function for full listing.
	 */
	public function getPersonalData($userid = 0)
	{
		$userid = (int) $userid;
		$currentUserId = vB::getCurrentSession()->get('userid');

		// if no userid passed, use current user
		if ($userid < 1)
		{
			$userid = $currentUserId;
		}

		// check for guest/invalid userid
		if ($userid < 1)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, 'userid', __CLASS__, __FUNCTION__));
		}

		// a user can view their own personal data, and an admin with
		// the proper permission can view others' personal data.
		if ($userid !== $currentUserId)
		{
			$this->checkHasAdminPermission('canadminusers');
		}

		// if we've gotten this far, this is a logged in user asking for their own personal
		// data or an admin with permission to admin users.
		return $this->library->getPersonalData($userid);
	}

	/**
	 * Verifies that a flash message passed through the URL is signed and valid
	 *
	 * @param string Phrase key
	 * @param string Timestamp for the securitytoken
	 * @param string The hash sha1(phrase + securitytoken)
	 *
	 * @return array Returns success=>true in the array if the message is valid.
	 */
	public function verifyFlashMessageSignature($phrase, $timestamp, $hash)
	{
		// The user API may not be the best home for this function, but
		// I choose to put it here for now since it's closely related
		// to user information (the securitytoken), and needs to have
		// access to user information before it is sanitized, namely the
		// raw security token.

		// For an overview of how the flashMessage system works, see:
		// vB5_Frontend_Controller::encodeFlashMessage()
		// vB5_Template::decodeFlashMessage()
		// vB_Api_User::verifyFlashMessageSignature()
		// displayFlashMessage() in global.js

		$success = false;

		$session = vB::getCurrentSession();
		$userinfo = $session->fetch_userinfo();
		$securitytoken_prev = $timestamp . '-' . sha1($timestamp . $userinfo['securitytoken_raw']);

		$testHash = substr(sha1($phrase . $securitytoken_prev), -10);

		if ($hash === $testHash)
		{
			$success = true;
		}

		return array(
			'success' => $success,
		);
	}

	/**
	 * Saves the content entry UI editor "state" where state is the show/hide state
	 * of the following 3 content entry UIs: ckeditor toolbar, attachements panel,
	 * and smilies panel.
	 *
	 * @param string Action -- 'add' (the panel is visible) or 'remove' (the panel is hidden)
	 * @param int The int bit value to add or remove from the editorstate. 1=toolbar, 2=attachments, 4=smilies
	 *
	 * @return array Array containing success and the current editor state
	 */
	public function saveEditorState($action, $value)
	{
		// 'add' or 'remove'
		$action = (string) $action;
		// 1=toolbar, 2=attachments, 4=smilies
		$value = (int) $value;

		$currentUserId = vB::getCurrentSession()->get('userid');

		// check for guest/invalid userid
		if ($currentUserId < 1)
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		// save it
		$assertor = vB::getDbAssertor();

		$params = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'editorstatevalue' => $value,
			'userid' => $currentUserId,
		);

		if ($action == 'add')
		{
			$assertor->assertQuery('vBforum:addUserEditorState', $params);
		}
		else
		{
			$assertor->assertQuery('vBforum:removeUserEditorState', $params);
		}

		$conditions = array('userid' => $currentUserId);
		$state = $assertor->getColumn('user', 'editorstate', $conditions);
		$state = reset($state);

		return array(
			'success' => true,
			'editorstate' => $state,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104066 $
|| #######################################################################
\*=========================================================================*/
