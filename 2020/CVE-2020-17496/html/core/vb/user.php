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

class vB_User
{
	use vB_Trait_NoSerialize;

	protected static $users = array();
	/**
	 * Processes logins into CP
	 * Adapted from functions_login.php::process_new_login
	 * THIS METHOD DOES NOT SET ANY COOKIES, SO IT CANNOT REPLACE DIRECTLY THE LEGACY FUNCTION
	 *
	 * @static
	 * @param array $auth The userinfo returned by vB_User::verifyAuthentication()
	 * @param string $logintype Currently 'cplogin' only or empty
	 * @param string $cssprefs AdminCP css preferences array
	 * @return array The info returned by vB_User::verifyAuthentication() with the addition of
	 * 	sessionhash -- hash identifying the new session
	 * 	cpsessionhash -- the hash for the cp session (only present if the user is an admin or a mod)
	 */
	public static function processNewLogin($auth, $logintype = '')
	{
		$assertor = vB::getDbAssertor();

		$result = array();

		if (
			($session = vB::getCurrentSession()) AND
			$session->isCreated() AND
			($session->get('userid') == 0)
		)
		{
			// if we just created a session on this page, there's no reason not to use it
			$newsession = $session;
			$newsession->set('userid', $auth['userid']);
		}
		else
		{
			$sessionClass = vB::getRequest()->getSessionClass();
			$newsession = call_user_func(array($sessionClass, 'getSession'), $auth['userid']);
		}
		$newsession->set('loggedin', 1);

		//I'm not sure if 'bypass' on the session actually does anything.
		if ($logintype == 'cplogin')
		{
			$newsession->set('bypass', 1);
		}
		else
		{
			$newsession->set('bypass', 0);
		}

		$newsession->fetch_userinfo();
		vB::setCurrentSession($newsession);
		$result['sessionhash'] = $newsession->get('dbsessionhash');

		$usercontext = vB::getUserContext();

		//create the session hash if requested. And appropriate for the user.
		//note that we use the cplogin type for the inline mod problem
		//so we'll except either cplogin or modpclogin for either
		//admin or moderator.
		if (
			($logintype == 'cplogin' OR $logintype == 'modcplogin') AND
		 	($usercontext->isAdministrator() OR $usercontext->isModerator())
		)
		{
			$cpsession = $newsession->fetchCpsessionHash();
			$result['cpsession'] = $cpsession;
		}

		if (defined('VB_API') AND VB_API === true)
		{
			$apiclient = $newsession->getApiClient();
			if ($apiclient['apiclientid'] AND $auth['userid'])
			{
				$assertor->update('apiclient',
					array(
						'userid' => intval($auth['userid']),
					),
					array(
						'apiclientid' => intval($apiclient['apiclientid'])
					)
				);

				// Also update the apiclient record in memory in case we still have processing
				// to do that requires updated data (e.g. saving device token immediately following
				// login)
				$newsession->refetchApiClientFromDB();
			}
		}

		$result = array_merge($result, $auth);

		vB::getHooks()->invoke('hookProcessNewLogin', array(
			'result' => &$result,
			'logintype' => $logintype,
			'cssprefs' => '',
			'userinfo' => $newsession->fetch_userinfo(),
		));

		return $result;
	}

	public static function setAdminCss($userid, $cssprefs)
	{
		$assertor = vB::getDbAssertor();
		$usercontext = vB::getUserContext();

		// admin control panel or upgrade script login
		if ($usercontext->hasAdminPermission('cancontrolpanel'))
		{
			if ($cssprefs != '')
			{
				$admininfo = $assertor->getRow('vBForum:administrator', array('userid' => $userid));
				if ($admininfo)
				{
					$admindm = new vB_DataManager_Admin(vB_DataManager_Constants::ERRTYPE_CP);
					$admindm->set_existing($admininfo);
					$admindm->set('cssprefs', $cssprefs);
					$admindm->save();
				}
			}
		}
	}

	/**
	 * Verifies a security token is valid
	 *
	 * @param	string	Security token from the REQUEST data
	 * @param	string	Security token used in the hash
	 *
	 * @return	boolean	True if the hash matches and is within the correct TTL
	 */
	public static function verifySecurityToken($request_token, $user_token)
	{
		global $vbulletin;

		if (!$request_token)
		{
			return false;
		}

		$parts = explode('-', $request_token);
		// $request_token can be 'guest' and not have 2 parts.
		// if it doesn't have the $time & $token parts, we can't really verify anything, so let's return false
		if (count($parts) < 2)
		{
			return false;
		}
		else
		{
			list($time, $token) = $parts;
		}

		if ($token !== sha1($time . $user_token))
		{
			return false;
		}

		// A token is only valid for 3 hours
		if ($time <= vB::getRequest()->getTimeNow() - 10800)
		{
			$vbulletin->GPC['securitytoken'] = 'timeout';
			return false;
		}

		return true;
	}

	/**
	 * Logs the current user out
	 *
	 * This function does not remove the session cookies
	 *
	 * @return info array:
	 *	sessionhash -- hash identifying the new session
	 *	apiaccesstoken -- the current api access token, if this is a request through MAPI
	 */
	public static function processLogout()
	{
		global $vbulletin;

		$assertor = vB::getDbAssertor();
		$session = vB::getCurrentSession();
		$userinfo = $session->fetch_userinfo();
		$timeNow = vB::getRequest()->getTimeNow();
		$options = vB::getDatastore()->getValue('options');

		if ($userinfo['userid'] AND $userinfo['userid'] != -1)
		{
			// init user data manager
			$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_SILENT);
			$userdata->set_existing($userinfo);
			$userdata->set('lastactivity', $timeNow - $options['cookietimeout']);
			$userdata->set('lastvisit', $timeNow);
			$userdata->save();

			if (!defined('VB_API'))
			{
				$assertor->delete('session', array('userid' => $userinfo['userid'], 'apiaccesstoken' => null));
				$assertor->delete('cpsession', array('userid' => $userinfo['userid']));
			}
		}

		$assertor->delete('session', array('sessionhash'=>$session->get('dbsessionhash')));

		// Remove accesstoken from apiclient table so that a new one will be generated
		if (defined('VB_API') AND VB_API === true AND $vbulletin->apiclient['apiclientid'])
		{
			$assertor->update(
				'apiclient',
				array('apiaccesstoken' => '', 'userid' => 0),
				array('apiclientid' => intval($vbulletin->apiclient['apiclientid']))
			);
			$vbulletin->apiclient['apiaccesstoken'] = '';
		}

		if ($vbulletin->session->created == true AND (!defined('VB_API') OR !VB_API))
		{
			// if we just created a session on this page, there's no reason not to use it
			$newsession = $vbulletin->session;
		}
		else
		{
			// API should always create a new session here to generate a new accesstoken
			$newsession = vB_Session::getNewSession(vB::getDbAssertor(), vB::getDatastore(), vB::getConfig(), '', 0, '', vB::getCurrentSession()->get('styleid'));
		}

		$newsession->set('userid', 0);
		$newsession->set('loggedin', 0);
		$vbulletin->session = & $newsession;

		$result = array();
		$result['sessionhash'] = $newsession->get('dbsessionhash');
		$result['apiaccesstoken'] = $newsession->get('apiaccesstoken');

		if (defined('VB_API') AND VB_API === true)
		{
			if ($_REQUEST['api_c'])
			{
				$assertor->update('apiclient',
					array(
						'apiaccesstoken' => $result['apiaccesstoken'],
						'userid' => 0,
					),
					array(
						'apiclientid' => intval($_REQUEST['api_c'])
					)
				);
			}
		}

		vB::getHooks()->invoke('hookProcessLogout', array(
			'result' => &$result,
			'userinfo' => $userinfo,
		));

		return $result;
	}

	/**
	 * Verifies that the user hasn't exceeded the strike total
	 * for attempted logins.  Based both on user name and IP address.
	 *
	 * @param string $username
	 */
	public static function verifyStrikeStatus($username = '')
	{
		$assertor = vB::getDbAssertor();
		$request = vB::getRequest();
		$options = vB::getDatastore()->getValue('options');

		$assertor->delete('vBForum:strikes', array(
			array(
				'field' => 'striketime',
				'value' => ($request->getTimeNow() - 3600),
				'operator' => vB_dB_Query::OPERATOR_LT
			)
		));

		if (!$options['usestrikesystem'])
		{
			return 0;
		}

		$ipFields = vB_Ip::getIpFields($request->getIpAddress());
		$strikes = $assertor->getRow('user_fetchstrikes', array(
			'ip_4' => vB_dB_Type_UInt::instance($ipFields['ip_4']),
			'ip_3' => vB_dB_Type_UInt::instance($ipFields['ip_3']),
			'ip_2' => vB_dB_Type_UInt::instance($ipFields['ip_2']),
			'ip_1' => vB_dB_Type_UInt::instance($ipFields['ip_1']),
		));

		if ($strikes['strikes'] >= 5 AND $strikes['lasttime'] > ($request->getTimeNow() - 900))
		{
			//they've got it wrong 5 times or greater for any username at the moment
			//the user is still not giving up so lets keep increasing this marker
			self::execStrikeUser($username);

			return false;
		}

		return $strikes['strikes'];
	}

	public static function execStrikeUser($username = '')
	{
		// todo: remove this global variable
		global $strikes;

		$assertor = vB::getDbAssertor();
		$request = vB::getRequest();
		$options = vB::getDatastore()->getValue('options');

		if (!$options['usestrikesystem'])
		{
			return 0;
		}

		$strikeip = $request->getIpAddress();
		$ipFields = vB_Ip::getIpFields($strikeip);

		if (!empty($username))
		{
			$strikes_user = $assertor->getRow('vBForum:strikes', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
							'ip_4' => vB_dB_Type_UInt::instance($ipFields['ip_4']),
							'ip_3' => vB_dB_Type_UInt::instance($ipFields['ip_3']),
							'ip_2' => vB_dB_Type_UInt::instance($ipFields['ip_2']),
							'ip_1' => vB_dB_Type_UInt::instance($ipFields['ip_1']),
							'username' => vB_String::htmlSpecialCharsUni($username)
					));

			if ($strikes_user['count'] == 4)  // We're about to add the 5th Strike for a user
			{
				if ($user = $assertor->getRow('user', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'username', 'value' => $username, 'operator' => vB_dB_Query::OPERATOR_EQ),
							array('field' => 'usergroupid', 'value' => 3, 'operator' => vB_dB_Query::OPERATOR_NE),
						)
				)))
				{
					$ip = $request->getIpAddress();

					$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
						'accountlocked',
						array(
							$user['username'],
							$options['bbtitle'],
							$ip,
						),
						array($options['bbtitle']),
						$user['languageid']
					);
					vB_Mail::vbmail($user['email'], $maildata['subject'], $maildata['message'], true);
				}
			}
		}

		/* insert query */
		$assertor->insert('vBForum:strikes', array(
			'striketime' => $request->getTimeNow(),
			'strikeip' => $strikeip,
			'ip_4' => vB_dB_Type_UInt::instance($ipFields['ip_4']),
			'ip_3' => vB_dB_Type_UInt::instance($ipFields['ip_3']),
			'ip_2' => vB_dB_Type_UInt::instance($ipFields['ip_2']),
			'ip_1' => vB_dB_Type_UInt::instance($ipFields['ip_1']),
			'username' => vB_String::htmlSpecialCharsUni($username)
		));
		$strikes++;

		// Legacy Hook 'login_strikes' Removed //
	}

	public static function execUnstrikeUser($username)
	{
		$ipFields = vB_Ip::getIpFields(vB::getRequest()->getIpAddress());
		vB::getDbAssertor()->delete('vBForum:strikes', array(
			'ip_4' => vB_dB_Type_UInt::instance($ipFields['ip_4']),
			'ip_3' => vB_dB_Type_UInt::instance($ipFields['ip_3']),
			'ip_2' => vB_dB_Type_UInt::instance($ipFields['ip_2']),
			'ip_1' => vB_dB_Type_UInt::instance($ipFields['ip_1']),
			'username' => vB_String::htmlSpecialCharsUni($username)
		));
	}

	/**
	* Fetches an array containing info for the specified user, or false if user is not found
	*
	* Values for Option parameter:
	* avatar - Get avatar
	* admin - Join the administrator table to get various admin options
	* signpic - Join the sigpic table to get the userid just to check if we have a picture
	* usercss - Get user's custom CSS
	* isfriend - Is the logged in User a friend of this person?
	* Therefore: array('avatar', 'location') means 'Get avatar' and 'Process online location'
	*
	* @param integer User ID
	* @param array Fetch Option (see description)
	* @param integer Language ID. If set to 0, it will use user-set languageid (if exists) or default languageid
	* @param boolean If true, the method won't use user cache but fetch information from DB.
	*
	* @return array The information for the requested user
	*/
	public static function fetchUserinfo($userid = 0, $option = array(), $languageid = false, $nocache = false)
	{
		$datastore = vB::getDatastore();

		sort($option);

		if (!empty($option))
		{
			$optionKey = implode('-', $option);
		}
		else
		{
			$optionKey = '#';
		}

		$session = vB::getCurrentSession();
		if ($session)
		{
			$currentUserId = $session->get('userid');
			if ($currentUserId AND !$userid)
			{
				$userid = $currentUserId;
			}
		}

		$userid = intval($userid);

		if (!$userid AND $session)
		{
			// return guest user info
			$guestInfo = $session->fetch_userinfo();

			//we can be a guest in an "admin" context if we are trying to log into the control panels.
			if (in_array(vB_Api_User::USERINFO_ADMIN, $option) AND empty($guestInfo['cssprefs']))
			{
				$vboptions = $datastore->getValue('options');
				$guestInfo['cssprefs'] = $vboptions['cpstylefolder'];
			}

			return $guestInfo;
		}

		if ($languageid === false)
		{
			if (!empty($session))
			{
				$languageid = $session->get('languageid');
			}
			else
			{
				$languageid = vB::getDatastore()->getOption('languageid');
			}
		}

		if ($nocache AND isset(self::$users["$userid"][$optionKey]))
		{
			// clear the cache if we are looking at ourself and need to add one of the JOINS to our information.
			unset(self::$users["$userid"][$optionKey]);
		}

		// return the cached result if it exists
		if (isset(self::$users[$userid][$optionKey]))
		{
			return self::$users[$userid][$optionKey];
		}

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$hashKey = 'vb_UserInfo_' . $userid;
		if (!empty($languageid))
		{
			$hashKey .= '_' . $languageid;
		}
		if (!empty($option))
		{
			$hashKey .= '_' . md5(serialize($option));
		}

		if (!$nocache)
		{
			$user = $cache->read($hashKey);
		}

		if (empty($user))
		{
			$user = vB::getDbAssertor()->getRow('fetchUserinfo', array(
				'userid'     => $userid,
				'option'     => $option,
				'languageid' => $languageid,
			));

			if (empty($user))
			{
				return false;
			}

			if (!is_numeric($user['timezoneoffset']))
			{
				$user['timezoneoffset'] = 0;
			}

			// Ensure we output a valid value for startofweek
			if ($user['startofweek'] < 1 OR $user['startofweek'] > 7)
			{
				// In vB4, this defaulted to -1 meaning to use the startofweek
				// that was set for the calendar they were viewing. That concept
				// doesn't translate to vB5, so we'll default to Sunday.
				$user['startofweek'] = 1;
			}

			if (in_array(vB_Api_User::USERINFO_ADMIN, $option) AND empty($user['cssprefs']))
			{
				$vboptions = $datastore->getValue('options');
				$user['cssprefs'] = $vboptions['cpstylefolder'];
			}
		}

		$cache->write($hashKey, $user, 1440, 'userChg_' . $userid);
		$user['languageid'] = (!empty($languageid) ? $languageid : $user['languageid']);

		// decipher 'options' bitfield
		vB_User::expandOptions($user);

		// make a username variable that is safe to pass through URL links
		$user['urlusername'] = urlencode(unhtmlspecialchars($user['username']));

		self::fetchMusername($user);

		// get the user's real styleid (not the cookie value)
		$user['realstyleid'] = $user['styleid'];

		$request = vB::getRequest();

		if ($request)
		{
			$timenow = vB::getRequest()->getTimeNow();
		}
		else
		{
			$timenow = time();
		}

		//should only happen during upgrades from before we had the secret field.
		if(!isset($user['secret']))
		{
			$user['secret'] = '';
		}

		$user['securitytoken_raw'] = sha1($user['userid'] . sha1($user['secret']) . sha1(vB_Request_Web::$COOKIE_SALT));
		$user['securitytoken'] = $timenow . '-' . sha1($timenow . $user['securitytoken_raw']);

		$user['logouthash'] =& $user['securitytoken'];

		// privacy_options
		if (isset($user['privacy_options']) AND $user['privacy_options'])
		{
			$user['privacy_options'] = unserialize($user['privacy_options']);
		}

		// VBV-11898 - Ignore secondary usergroups if allowmembergroups is set to "No." If any page requires the full membergroupids
		// regardless of the usergroup option (ex. adminCP user profile), they should call vB_Library_User->fetchUserGroups()
		$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');
		$usergroupCache = $datastore->getValue('usergroupcache');
		if (!($usergroupCache[$user['usergroupid']]['genericoptions'] & $bf_ugp_genericoptions['allowmembergroups']))
		{
			$user['membergroupids'] = '';
		}

		//the interval in seconds to add to a time in the user's timezone to get to the server timezone
		$user['servertimediff'] = self::calcUsertimeDiff($user);
		self::cacheUserLocal($userid, $optionKey, $user);

		return $user;
	}

	public static function expandOptions(&$user)
	{
		$datastore = vB::getDatastore();
		$bf_misc_useroptions = $datastore->getValue('bf_misc_useroptions');
		$bf_misc_adminoptions = $datastore->getValue('bf_misc_adminoptions');

		if (!empty($bf_misc_useroptions) AND isset($user['options']))
		{
			//should we also do this with adminoptions?  The code I pulled this from doesn't.
			$user['options'] = intval($user['options']);

			foreach ($bf_misc_useroptions AS $optionname => $optionval)
			{
				$user[$optionname] = ($user['options'] & $optionval ? 1 : 0);
			}
		}

		if (!empty($bf_misc_adminoptions) AND isset($user['adminoptions']))
		{
			foreach($bf_misc_adminoptions AS $optionname => $optionval)
			{
				$user[$optionname] = ($user['adminoptions'] & $optionval ? 1 : 0);
			}
		}

	}

	private static function cacheUserLocal($userid, $optionKey, $user)
	{
		if (!isset(self::$users[$userid]))
		{
			self::$users[$userid] = array();
		}
		self::$users[$userid][$optionKey] = $user;
	}

	public static function calcUsertimeDiff($userinfo)
	{
		$tzoffset = (int) $userinfo['timezoneoffset'];
		if ($userinfo['dstonoff'])
		{
			// DST is on, add an hour
			$tzoffset++;
		}

		return date('Z', vB::getRequest()->getTimeNow()) - ($tzoffset * 3600);
	}

	/**
	 * fetches the proper username markup and title
	 *
	 * @param array $user (ref) User info array
	 * @param string $displaygroupfield Name of the field representing displaygroupid in the User info array
	 * @param string $usernamefield Name of the field representing username in the User info array
	 *
	 * @return string Username with markup and title
	 */
	public static function fetchMusername(&$user, $displaygroupfield = 'displaygroupid', $usernamefield = 'username')
	{
		if (!empty($user['musername']))
		{
			// function already been called
			return $user['musername'];
		}

		$username = $user[$usernamefield];

		$datastore = vB::getDatastore();
		$usergroupcache = $datastore->getValue('usergroupcache');
		$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');

		if (!empty($user['infractiongroupid']) AND $usergroupcache["$user[usergroupid]"]['genericoptions'] & $bf_ugp_genericoptions['isnotbannedgroup'])
		{
			$displaygroupfield = 'infractiongroupid';
		}

		if (isset($user[$displaygroupfield], $usergroupcache[$user[$displaygroupfield]]) AND $user[$displaygroupfield] > 0)
		{
			// use $displaygroupid
			$displaygroupid = $user[$displaygroupfield];
		}
		else if (isset($usergroupcache[$user['usergroupid']]) AND $user['usergroupid'] > 0)
		{
			// use primary usergroupid
			$displaygroupid = $user['usergroupid'];
		}
		else
		{
			// use guest usergroup
			$displaygroupid = 1;
		}

		$user['musername'] = $usergroupcache["$displaygroupid"]['opentag'] . $username . $usergroupcache["$displaygroupid"]['closetag'];
		$user['displaygrouptitle'] = $usergroupcache["$displaygroupid"]['title'];
		$user['displayusertitle'] = $usergroupcache["$displaygroupid"]['usertitle'];

		if ($displaygroupfield == 'infractiongroupid' AND $usertitle = $usergroupcache[$user[$displaygroupfield]]['usertitle'])
		{
			$user['usertitle'] = $usertitle;
		}
		else if (isset($user['customtitle']) AND $user['customtitle'] == 2)
		{
			$user['usertitle'] = function_exists('htmlspecialchars_uni') ? htmlspecialchars_uni($user['usertitle']) : htmlspecialchars($user['usertitle']);
		}

		return $user['musername'];
	}

	/**
	 * This grants a user additional permissions in a specific channel, by adding to the groupintopic table
	 *
	 *	@param	int
	 *	@param	mixed	integer or array of integers
	 * 	@param	int
	 *
	 *	@return	bool
	 */
	public static function setGroupInTopic($userid, $nodeids, $usergroupid)
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

		//We don't do a permission check. It's essential that the api's do that before calling here.

		//let's get the current channels in which the user already is set for that group.
		//Then remove any for which they already are set.
		$assertor = vB::getDbAssertor();
		$existing = $assertor->assertQuery('vBForum:groupintopic', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'userid' => $userid, 'groupid' => $usergroupid));
		foreach ($existing as $permission)
		{
			$index = array_search($permission['nodeid'] , $nodeids);

			if ($index !== false)
			{
				unset($nodeids[$index]);
			}
		}

		//and do the inserts
		foreach ($nodeids as $nodeid)
		{
			$assertor->assertQuery('vBForum:groupintopic', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid' => $userid, 'nodeid' => $nodeid, 'groupid' => $usergroupid));
		}

		vB_Cache::allCacheEvent(array("userPerms_$userid", "userChg_$userid", "followChg_$userid", "sgMemberChg_$userid"));
		vB_Api::instanceInternal('user')->clearChannelPerms($userid);
		vB::getUserContext($userid)->reloadGroupInTopic();
		vB::getUserContext()->clearChannelPermissions();

		//if we got here all is well.
		return true;
	}

	/**
	 * Clears user cached information.
	 */
	public static function clearUsersCache($userid)
	{
		$userid = intval($userid);
		self::$users[$userid] = null;
		vB_Cache::instance(vB_Cache::CACHE_FAST)->event('userChg_' . $userid);
	}

	/**
	 * Obtains user info depending on the login credentials method.
	 * @param $credential
	 * @return mixed
	 */
	public static function getUserInfoByCredential($credential)
	{
		$assertor = vB::getDbAssertor();
		$vboptions = vB::getDatastore()->getValue('options');
		$loginType = intval($vboptions['logintype']);

		$columnsToObtain = array('email', 'username', 'userid', 'token', 'scheme');
		switch($loginType)
		{
			case 0:
				$data = $assertor->getRows('user', array(
					vB_dB_Query::COLUMNS_KEY => $columnsToObtain,
					vB_dB_Query::PARAM_LIMIT => 1,
					'email' => $credential
				));
				break;
			case 1:
				$data = $assertor->getRows('user', array(
					vB_dB_Query::COLUMNS_KEY => $columnsToObtain,
					vB_dB_Query::PARAM_LIMIT => 1,
					'username' => $credential
				));
				break;
			case 2:

				$data = $assertor->getRows('user', array(
					vB_dB_Query::COLUMNS_KEY => $columnsToObtain,
					vB_dB_Query::PARAM_LIMIT => 1,
					'username' => $credential
				));

				if($data == null || count($data) == 0)
				{
					$data = $assertor->getRows('user', array(
						vB_dB_Query::COLUMNS_KEY => $columnsToObtain,
						vB_dB_Query::PARAM_LIMIT => 1,
						'email' => $credential
					));
				}
				break;
		}

		if(is_array($data) && !empty($data))
		{
			$userData = $data[0];
		}
		else
		{
			$userData = null;
		}

		return $userData;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103552 $
|| #######################################################################
\*=========================================================================*/
