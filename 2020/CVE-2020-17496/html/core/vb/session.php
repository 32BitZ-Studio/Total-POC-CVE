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
* Class to handle sessions
*
* Creates, updates, and validates sessions; retrieves user info of browsing user
*
* @package	vBulletin
* @version	$Revision: 103869 $
* @date		$Date: 2020-01-15 16:35:29 -0800 (Wed, 15 Jan 2020) $
*/
abstract class vB_Session
{
	use vB_Trait_NoSerialize;

	/**
	 *
	 * @var vB_dB_Assertor
	 */
	protected $dBAssertor = null;

	/**
	 *
	 * @var vB_Datastore
	 */
	protected $datastore = null;

	/**
	 * @var array
	 */
	protected $config;

	/**
	* The individual session variables. Equivalent to $session from the past.
	*
	* @var	array
	*/
	protected $vars = array();

	//arbitrary data to be stored as part of the session
	protected $data = array();
	protected $cookietimeout ;
	protected $rememberMeToken = '';

	/**
	* A list of variables in the $vars member that are in the database. Includes their types.
	*
	* @var	array
	*/
	protected $db_fields = array(
		'sessionhash'   => vB_Cleaner::TYPE_STR,
		'userid'        => vB_Cleaner::TYPE_INT,
		'host'          => vB_Cleaner::TYPE_STR,
		'idhash'        => vB_Cleaner::TYPE_STR,
		'lastactivity'  => vB_Cleaner::TYPE_INT,
		'location'      => vB_Cleaner::TYPE_STR,
		'styleid'       => vB_Cleaner::TYPE_INT,
		'languageid'    => vB_Cleaner::TYPE_INT,
		'loggedin'      => vB_Cleaner::TYPE_INT,
		'inforum'       => vB_Cleaner::TYPE_INT,
		'inthread'      => vB_Cleaner::TYPE_INT,
		'incalendar'    => vB_Cleaner::TYPE_INT,
		'badlocation'   => vB_Cleaner::TYPE_INT,
		'useragent'     => vB_Cleaner::TYPE_STR,
		'bypass'        => vB_Cleaner::TYPE_INT,
		'profileupdate' => vB_Cleaner::TYPE_INT,
		'apiclientid'   => vB_Cleaner::TYPE_INT,
		'apiaccesstoken'=> vB_Cleaner::TYPE_STR,
		'emailstamp'    => vB_Cleaner::TYPE_INT,
	);

	/**
	* An array of changes. Used to prevent superfluous updates from being made.
	*
	* @var	array
	*/
	protected $changes = array();
	/**
	* Whether the session was created or existed previously
	*
	* @var	bool
	*/
	// todo: this is a public attribute to avoid breaking some references that even set this value.
	// Replace with getter and check if we can avoid setting this outside the class constructor.
	public $created = false;

	/**
	* Information about the user that this session belongs to.
	*
	* @var	array
	*/
	protected $userinfo = null;

	/*
	 *This should *never* change during a session
	 *@var string
	 */
	protected $sessionIdHash = null;

	/**
	 * cpsessionhash is a special session hash for admins and moderators
	 *
	 * @var string
	 */
	protected $cpsessionHash = '';

	// This functions are used to fill in the skeleton of the constructor using template method pattern
	/**
	 * Sets the attribute sessionIdHash
	 */
	protected function createSessionIdHash()
	{
		// API session idhash won't have User Agent compiled.
		$this->sessionIdHash = md5($this->fetch_substr_ip(vB::getRequest()->getAltIp()));
	}

	protected function loadExistingSession($sessionhash, $restoreSessionInfo)
	{
		$gotsession = false;

		// try to fetch stored session first and save it in $this->vars
		if ($this->fetchStoredSession($sessionhash, $restoreSessionInfo))
		{
			$gotsession = true;
			$this->created = false;

			// found a session - get the userinfo
			if (!empty($this->vars['userid']))
			{
				$useroptions = array();
				if (defined('IN_CONTROL_PANEL'))
				{
					$useroptions[] = vB_Api_User::USERINFO_ADMIN;
					$userinfo = vB_Library::instance('user')->fetchUserinfo(
						$this->vars['userid'],
						$useroptions,
						(!empty($languageid) ? $languageid : $this->vars['languageid'])
					);
				}
				else if (!empty($this->data['userinfo']))
				{
					$userinfo = &$this->data['userinfo'];
				}
				else
				{
					$userinfo = vB_Library::instance('user')->fetchUserWithPerms(
						$this->vars['userid'],
						(!empty($languageid) ? $languageid : $this->vars['languageid'])
					);
				}
				$this->userinfo =& $userinfo;

			}
		}

		if ($gotsession == false OR empty($this->vars['userid']))
		{
			// try to use remember me
			$useroptions = array();
			if (defined('IN_CONTROL_PANEL'))
			{
				$useroptions[] = 'admin';
			}


			/*
				vB_Session_Api note:
				VBV-12249: API session will always pass in "true" for this, as to preserve
				the behavior of always trying to fetch old session info from the information
				found in the apiclient table. If we got this far, that means they passed
				vB_Session_Api::validateApiSession(), so this should be safe.
			*/
			if (!empty($restoreSessionInfo['remembermetoken']))
			{
				if ($restoreSessionInfo['remembermetoken'] == 'facebook')
				{
					$result = $this->rememberFacebook($restoreSessionInfo, $useroptions);
				}
				else
				{
					$result = $this->rememberSession($restoreSessionInfo, $useroptions);
				}

				$gotsession = $result['auth'];
				$this->rememberMeToken = $result['remembermetoken'];
			}
		}

		// Need to sort out what this does and why.  We should *not* be skipping things by passing
		// nonsensical combinations of data.
		//
		// It appears to attempt, for guests, to find a session that matches your ID hash, and grabs that
		// instead of creating a new guest session.  However its not clear when we would have a guest that
		// matches the IDHash but did not find a session for the session hash above, and don't want
		// to create a new session.
		//
		// at this point, we're a guest, so lets try to *find* a session
		// you can prevent this check from being run by passing in a userid with no password (aka remember me token)
		if ($gotsession == false AND empty($restoreSessionInfo['userid']))
		{
			try
			{
				$session = $this->dBAssertor->getRow('session',
					array(
						'userid' => 0,
						'host' => vB::getRequest()->getSessionHost(),
						'idhash' => $this->getSessionIdHash(),
					)
				);
			}
			catch (Exception $e)
			{}
			if (!empty($session))
			{
				$gotsession = true;

				$this->vars =& $session;
				$this->created = false;
			}
		}


		//if we got user info, check to make sure the EU status is correct.
		if($gotsession AND $this->userinfo AND $this->userinfo['userid'] > 0)
		{
			$datastore = vB::getDatastore();
			//let's only check this if we don't have a cached value rather
			//than add a query to every user info request in some instances.
			$options = $datastore->getValue('options');
			if($options['enable_privacy_registered'])
			{
				//if we don't know the user's status, we need to look it up because
				//it could be a user that we haven't updated the status for yet.
				//it's possible that this because we can't determine it, in which case
				//we'll rely on the local ip caching to avoid spamming the geoip service
				//But if it's because we haven't look it up yet we need to know the
				//answer because it affects what info we show to the user.
				if($this->userinfo['eustatus'] == 0)
				{
					$request = vB::getRequest();
					$ipaddress = $request->getIpAddress();
					$consent = vB_Library::instance('user')->getPrivacyConsentRequired($ipaddress);

					if($consent != 0)
					{
						$this->userinfo['eustatus'] = $consent;
						$db = vB::getDbAssertor();

						//we can't call the save function here, it's just not going to work
						//we *need* to get the user load logic out of session, the dependency
						//chain is a nightmare.  But that's going to involve a lot of changes.
						$db->update('user', array('eustatus' => $consent), array('userid' => $this->userinfo['userid']));
					}
				}
			}

		}

		return $gotsession;
	}

	// called from loadExistingSession
	// check vB_Session_Api for different behavior
	protected function fetchStoredSession($sessionhash, $restoreSessionInfo = array())
	{
		$this->cookietimeout = $this->datastore->getOption('cookietimeout');
		if ($sessionhash)
		{
			$request = vB::getRequest();
			$sessionHostSubstr = $this->fetch_substr_ip($request->getSessionHost());
			$sessionRecord = $this->dBAssertor->getRow('session',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array(
						array(
							'field' => 'sessionhash',
							'value'	=> $sessionhash,
							'operator' => vB_dB_Query::OPERATOR_EQ
						),
						array(
							'field' => 'lastactivity',
							'value' => ($request->getTimeNow() - $this->cookietimeout),
							'operator' => vB_dB_Query::OPERATOR_GT
						),
					)
				)
			);

			if ($sessionRecord AND ($sessionRecord['idhash'] === $this->getSessionIdHash()))
			{
				$this->vars = $sessionRecord;
			}
			else if(
				!empty($restoreSessionInfo['tryagain_apiclient']) AND
				!empty($sessionRecord['apiaccesstoken'])
			)
			{
				/*
					Mobile clients can have agent mismatches between
					requests. For example, on the android app, a showthread
					api.php call may show "Android" as the useragent, then
					something else entirely for the subsequent filedata/fetch
					calls for attachment images in that thread show "Dalvik/..."
					as the agent.
					In that case, let's check if there's an apiclient associated
					with this sessionhash, just compare session.ip with requester's
					ip.
					Note that there is not an uptodate ip record on the apiclient table,
					only the session table. `apiclient`.`initialipaddress` is set once
					per init, not updated per request.
				 */
				$apiclientRecord = $this->dBAssertor->getRow('apiclient',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						vB_dB_Query::CONDITIONS_KEY => array(
							array(
								'field' => 'apiaccesstoken',
								'value'	=> $sessionRecord['apiaccesstoken'],
								'operator' => vB_dB_Query::OPERATOR_EQ
							),
						)
					)
				);
				if (!empty($apiclientRecord['apiclientid']))
				{
					// This check is exactly the same as below, but coded like this to preserve
					// the previous behavior (as much as possible) of not setting $this->vars
					// if idhash check failed.
					if ($this->fetch_substr_ip($sessionRecord['host']) == $sessionHostSubstr)
					{
						$this->vars = $sessionRecord;
						return true;
					}
				}
			}

			return ($this->vars AND $this->fetch_substr_ip($this->vars['host']) == $sessionHostSubstr);
		}
		else
		{
			return false;
		}
	}

	/**
	 *	Attempt to create a new session for the user without asking for a new login
	 *
	 * 	This uses various cookie information to revalidate a user without asking for a new
	 * 	login.  This is triggered wh
	 *
	 *  @param array $restoreSessionInfo -- restore array that was passed to the constructor (and is documented there)
	 *  @param array $useroptions -- User options to pass to fetchUserinfo
	 */
	protected function rememberSession($restoreSessionInfo, $useroptions)
	{
		if (!empty($restoreSessionInfo['userid']))
		{
			$userinfo = $this->fetchUserForRemember($restoreSessionInfo['userid'], $useroptions);
			$result = vB_Library::instance('login')->verifyRememberMeFromInfo($userinfo, $restoreSessionInfo['remembermetoken']);
			if ($result['auth'])
			{
				// combination is valid
				if (!empty($this->vars['sessionhash']))
				{
					$this->dBAssertor->delete('session', array('sessionhash'=>$this->vars['sessionhash']), TRUE);
				}

				$this->vars = $this->fetch_session($userinfo['userid']);
				$this->created = true;
				$this->userinfo =& $userinfo;

				return $result;
			}
		}

		return array ('auth' => false, 'remembermetoken' => '');
	}

	/**
	 *	Attempt to create a new session for the user from facebook
	 *
	 * 	This uses various cookie information to revalidate a user without asking for a new
	 * 	login.  This is triggered wh
	 *
	 *  @param array $restoreSessionInfo -- restore array that was passed to the constructor (and is documented there)
	 *  @param array $useroptions -- User options to pass to fetchUserinfo
	 */
	protected function rememberFacebook($restoreSessionInfo, $useroptions)
	{
		$failure = array ('auth' => false, 'remembermetoken' => '');

		$fblib = vB_Library::instance('facebook');
		if(!$fblib->isFacebookEnabled())
		{
			return $failure;
		}

		if (empty($restoreSessionInfo['userid']) OR empty($restoreSessionInfo['fb_signed_request']))
		{
			return $failure;
		}

		$userinfo = $this->fetchUserForRemember($restoreSessionInfo['userid'], $useroptions);

		//if this fails for some reason just carry on as guest.
		try
		{
			$vbuserid = $fblib->createSessionForLogin(array('signedrequest' => $restoreSessionInfo['fb_signed_request']));
		}
		catch (Exception $e)
		{
			return $failure;
		}

		//make sure we have the right user
		if($vbuserid != $restoreSessionInfo['userid'])
		{
			return $failure;
		}

		// combination is valid
		if (!empty($this->vars['sessionhash']))
		{
			$this->dBAssertor->delete('session', array('sessionhash' => $this->vars['sessionhash']), true);
		}

		$this->vars = $this->fetch_session($userinfo['userid']);
		$this->created = true;
		$this->userinfo =& $userinfo;

		return array ('auth' => true, 'remembermetoken' => 'facebook');
	}

	/**
	 *	Get the user info based on the useroptions
	 *
	 *	@return array user info array
	 */
	protected function fetchUserForRemember($userid, $useroptions)
	{
		// Not entire sure what this is about, but it shouldn't be this complicated.
		$languageid = (empty($this->vars['languageid']) ? 0 : $this->vars['languageid']);
		if (empty($useroptions))
		{
			$userinfo = vB_Library::instance('user')->fetchUserWithPerms($userid, $languageid);
		}
		else
		{
			$userinfo = vB_Library::instance('user')->fetchUserinfo($userid, $useroptions, $languageid);
		}
		return $userinfo;
	}



	/**
	* Constructor. Attempts to grab a session that matches parameters, but will create one if it can't.
	*
	*	@param vB_DB_Assertor $dBAssertor
	*	@param vB_Datastore $datastore
	*	@param array $config -- vBulletin config array
	*
	* @param	string		Previously specified sessionhash
	*	@param array $restoreSessionInfo -- Information to handle "remember me" logic.
	*		* remembermetoken -- Token value for "remember me".  Stored in the "password" cookie for legacy reasons.  There are
	*			so special values to indicate that we should reauthentic via a method other than the internal vB remember me
	*			system.
	*		* userid -- user we are remembering
	*		* fbsr_{appid} (optional) -- Only valid if facebook is enabled, and only used if "remembermetoken" is "facebook".
	* @param	integer		Style ID for this session
	* @param	integer		Language ID for this session
	*/
	protected function __construct(&$dBAssertor, &$datastore, &$config, $sessionhash = '', $restoreSessionInfo = array(), $styleid = 0, $languageid = 0)
	{
		$this->dBAssertor = & $dBAssertor;
		$this->datastore = & $datastore;
		$this->config = & $config;
		$request = vB::getRequest();

		if(isset($restoreSessionInfo['userid']))
		{
			$restoreSessionInfo['userid'] = intval($restoreSessionInfo['userid']);
		}
		$styleid = intval($styleid);
		$languageid = intval($languageid);

		$this->createSessionIdHash();

		if (!$this->loadExistingSession($sessionhash, $restoreSessionInfo))
		{
			// well, nothing worked, time to create a new session
			$this->vars = $this->fetch_session(0);
			$this->created = true;
		}

		$this->vars['dbsessionhash'] = $this->vars['sessionhash'];

		$this->set('styleid', $styleid);
		$this->set('languageid', $languageid);
		if ($this->created == false)
		{
			$this->set('useragent', $request->getUserAgent());
			$this->set('lastactivity', $request->getTimeNow());
			if (!defined('LOCATION_BYPASS'))
			{
				$this->set('location', WOLPATH);
			}
			$this->set('bypass', SESSION_BYPASS);
		}
	}

	/**
	 * Returns a new session of the type specified by defined constants
	 *
	 * @global array $VB_API_PARAMS_TO_VERIFY - Defined in api.php
	 * @global array $VB_API_REQUESTS - Defined in api.php
	 * @param vB_dB_Assertor $dBAssertor
	 * @param vB_Datastore $datastore
	 * @param array $config
	 * @param string $sessionhash
	 * @param int $userid
	 * @param string $password
	 * @param int $styleid
	 * @param int $languageid
	 * @return vB_Session
	 */
	// this is used by legacy code, not vb5 API
	public static function getNewSession(&$dBAssertor, &$datastore, &$config, $sessionhash = '', $userid = 0, $password = '', $styleid = 0, $languageid = 0)
	{
		if (defined('SKIP_SESSIONCREATE') AND SKIP_SESSIONCREATE)
		{
			$session = new vB_Session_Skip($dBAssertor, $datastore, $config, $styleid, $languageid);
		}
		else if (defined('VB_API') AND VB_API)
		{
			global $VB_API_PARAMS_TO_VERIFY, $VB_API_REQUESTS;
			$session = new vB_Session_Api($dBAssertor, $datastore, $config, $sessionhash, $VB_API_PARAMS_TO_VERIFY, $VB_API_REQUESTS);
		}
		else
		{
			$restoreSessionInfo = array('userid' => $userid, 'remembermetoken' => $password);
			$session = new vB_Session_Web($dBAssertor, $datastore, $config, $sessionhash, $restoreSessionInfo, $styleid, $languageid);
		}

		return $session;
	}

	/**
	 * Returns the sessionIdHash
	 * @return string
	 */
	public function getSessionIdHash()
	{
		return $this->sessionIdHash;
	}

	/**
	* Saves the session into the database by inserting it or updating an existing one.
	*/
	public function save()
	{
		$cleaned = array();
		foreach ($this->db_fields AS $fieldname => $cleantype)
		{
			switch ($cleantype)
			{
				case vB_Cleaner::TYPE_INT:
					$clean = isset($this->vars["$fieldname"]) ? intval($this->vars["$fieldname"]) : 0;
					break;
				case vB_Cleaner::TYPE_STR:
				default:
					// will be escaped by assertor
					$clean = isset($this->vars["$fieldname"]) ? $this->vars["$fieldname"] : '';
			}
			$cleaned["$fieldname"] = $clean;
		}

		// since the sessionhash can be blanked out, lets make sure we pull from "dbsessionhash"
		$cleaned['sessionhash'] = $this->vars['dbsessionhash'];

		if ($this->created == true)
		{
			$this->dBAssertor->insertIgnore('session', $cleaned);
		}
		else
		{
			// update query

			unset($this->changes['sessionhash']); // the sessionhash is not updateable
			$update = array();
			foreach ($cleaned AS $key => $value)
			{
				if (!empty($this->changes["$key"]))
				{
					$update[$key] = $value;
				}
			}

			if (sizeof($update) > 0)
			{
				// note that $cleaned['sessionhash'] has been escaped as necessary above!
				$this->dBAssertor->update('session', $update, array('sessionhash' => $cleaned['sessionhash']));
			}
		}
	}

	/**
	 *	Deletes the session from the session store.
	 *
	 *	Deletes records matching the session's sessionhash.  If there is an apiaccesstoken then
	 *	sessions matching that are also deleted.
	 *
	 *	Will have no effect and no error if the session doesn't exist.
	 *
	 *	Sets the session to "not created", but does not otherwise affect the session object.
	 */
	public function delete()
	{
		//refactored from vB_User login code.  This is more general logic and should be part of the session obect
		$db = vB::getDbAssertor();

		//delete by sessionhash
		$db->delete('session', array('sessionhash' => $this->get('dbsessionhash')));

		//if we have an apiaccess token, nuke sessions matching that too
		if(vB::getCurrentSession()->get('apiaccesstoken'))
		{
			vB::getDbAssertor()->delete('session', array('apiaccesstoken' => vB::getCurrentSession()->get('apiaccesstoken')));
		}
		$this->created = false;
	}

	/**
	 * Sets a session variable and updates the change list.
	 * @param	string	Name of session variable to update
	 * @param	mixed	Value to update it with
	 */
	public function set($key, $value)
	{
		if (!isset($this->vars[$key]) OR $this->vars[$key] != $value)
		{
			$this->vars[$key] = $value;
			$this->changes[$key] = true;
		}
	}


	public function setChannelPerms($key, $perms)
	{
		if (empty($this->data['channelPerms']))
		{
			$this->data['channelPerms'] = array('userid' => $this->vars['userid'], $key => $perms);
		}
		else
		{
			if (empty($this->data['channelPerms'][$key]) OR ($this->data['channelPerms'][$key] != $perms))
			{
				$this->data['channelPerms'][$key] = $perms;
			}
		}
	}

	public function getChannelPerms($key)
	{
		if (isset($this->data['channelPerms']) AND isset($this->data['channelPerms'][$key]))
		{
			return $this->data['channelPerms'][$key];
		}
	}


	public function clearChannelPerms()
	{
		unset ($this->data['channelPerms']);
	}


	public function getRememberMeToken()
	{
		return $this->rememberMeToken;
	}

	/**
	 * Gets a session variable.
	 *
 	 * @param	string - Name of session variable
	 * @return	mixed - Value of the key, NULL if not found
	 */
	public function get($key)
	{
		if (isset($this->vars[$key]))
		{
			return $this->vars[$key];
		}
		return NULL;
	}

	/**
	 * Returns whether the session was created
	 * @return bool
	 */
	public function isCreated()
	{
		return $this->created;
	}

	// this is used by templates class
	/**
	 * Returns an array with all session vars
	 * @return array
	 */
	public function getAllVars()
	{
		return $this->vars;
	}

	public function setSessionVars($userId)
	{
		$this->vars = $this->fetch_session($userId);
	}

	/**
	 * Fetches a valid sessionhash value, not necessarily the one tied to this session.
	 * @return	string	32-character sessionhash
	 */
	public function fetch_sessionhash()
	{
		return md5(uniqid(microtime(), true));
	}

	/**
	 * Returns the IP address with the specified number of octets removed
	 * @param	string	IP address
	 * @return	string	truncated IP address
	 */
	protected function fetch_substr_ip($ip)
	{
		$options = $this->datastore->getValue('options');
		$ipUtil = new vB_Utility_Ip();
		return $ipUtil->ipSubstring($ip, 4 - $options['ipcheck']);
	}

	/**
	* Fetches a default session. Used when creating a new session.
	*
	* @param	integer	User ID the session should be for
	*
	* @return	array	Array of session variables
	*/
	protected function fetch_session($userid = 0)
	{
		$sessionhash = $this->fetch_sessionhash();

		$request = vB::getRequest();

		$session = array(
			'sessionhash'   => $sessionhash,
			'dbsessionhash' => $sessionhash,
			'userid'        => intval($userid),
			'host'          => (empty($request) ? '' : $request->getSessionHost()),
			'idhash'        => $this->getSessionIdHash(),
			'lastactivity'  => (empty($request) ? '' : $request->getTimeNow()),
			'location'      => (defined('LOCATION_BYPASS') OR !defined('WOLPATH')) ? '' : WOLPATH, //defined('LOCATION_BYPASS') ? '' : WOLPATH,
			'styleid'       => 0,
			'languageid'    => 0,
			'loggedin'      => intval($userid) ? 1 : 0,
			'inforum'       => 0,
			'inthread'      => 0,
			'incalendar'    => 0,
			'badlocation'   => 0,
			'profileupdate' => 0,
			'useragent'     => (empty($request) ? '' : $request->getUserAgent()),
			'bypass'        => (defined('SESSION_BYPASS')) ? SESSION_BYPASS : false //SESSION_BYPASS
		);

		return $session;
	}

	/**
	 * Called after setting phrasegroups, adds new phrases to userinfo
	 */
	public function loadPhraseGroups()
	{
		$options = $this->datastore->getValue('options');
		$phraseinfo = vB_Language::getPhraseInfo((!empty($this->vars['languageid']) ? $this->vars['languageid'] : intval($options['languageid'])));

		if (!empty($phraseinfo))
		{
			foreach($phraseinfo AS $_arrykey => $_arryval)
			{
				$this->userinfo[$_arrykey] = $_arryval;
			}
			unset($phraseinfo);
		}
		else
		{
			// can't phrase this since we can't find the language
			trigger_error('The requested language does not exist, reset via tools.php.', E_USER_ERROR);
		}
	}

	/**
	 * Loads basic language information
	 */
	public function loadLanguage()
	{
		$allLanguages = vB::getDatastore()->getValue('languagecache');
		if (is_array($allLanguages) AND !array_key_exists($this->vars['languageid'], $allLanguages))
		{
			if (!empty($this->userinfo['languageid']) AND array_key_exists($this->userinfo['languageid'], $allLanguages))
			{
				$this->vars['languageid'] = $this->userinfo['languageid'];
			}
			else if (vB::getDatastore()->getOption('languageid'))
			{
				$this->vars['languageid'] = vB::getDatastore()->getOption('languageid');
			}
			//This as far as I know only happens if something has gone sideways during an upgrade.
			//This at least allows admincp and tools.php to restore the proper language
			else
			{
				$this->vars['languageid'] = 1;
			}
		}

		$language = vB_Language::getPhraseInfo($this->vars['languageid']);

		if(isset($language['lang_options']) AND !is_array($language['lang_options']))
		{
			//convert bitfields to arrays for external clients.
			$bitfields = vB::getDatastore()->getValue('bf_misc_languageoptions');
			if (is_array($bitfields))
			{
				$lang_options = $language['lang_options'];
				$language['lang_options'] = array();
				foreach ($bitfields AS $key => $value)
				{
					$language['lang_options'][$key] = (bool) ($lang_options & $value);
				}
			}
		}

		if (!empty($language))
		{
			if (!empty($this->userinfo))
			{
				foreach($language AS $_arrykey => $_arryval)
				{
					$this->userinfo[$_arrykey] = $_arryval;
				}

				$this->userinfo['languageid'] = $this->vars['languageid'];
			}
			else
			{
				foreach($language AS $_arrykey => $_arryval)
				{
					$this->vars[$_arrykey] = $_arryval;
				}
			}
		}
		else if (!defined('VB_UNITTEST'))
		{
			//this shouldn't happen and if it does we probably can't access the phrases
			//to render a phrased API exception anyway.
			throw new Exception('The requested language does not exist, reset via tools.php.');
		}
	}

	/**
	 * Returns appropriate user info for the owner of this session.
	 * @return	array	Array of user information.
	 */
	public function &fetch_userinfo()
	{
		if ($this->userinfo)
		{
			// we already calculated this
			// If languageid is changed by set(), we need to reload language too. The language cached in session cache isn't correct
			if (empty($this->userinfo['lang_options']) OR ($this->userinfo['languageid'] != $this->vars['languageid']))
			{
				$this->loadLanguage();
			}

			return $this->userinfo;
		}
		else if ($this->vars['userid'] AND !defined('SKIP_USERINFO'))
		{
			$this->loadUserInfo();
			return $this->userinfo;
		}
		else
		{
			$options = $this->datastore->getValue('options');
			$bf_misc_useroptions = $this->datastore->getValue('bf_misc_useroptions');

			// guest setup
			$this->userinfo = array(
				'userid'         => 0,
				'usergroupid'    => 1,
				'membergroupids' => '',
				'username'       => (!empty($_REQUEST['username']) ? vB_String::htmlSpecialCharsUni($_REQUEST['username']) : ''),
				'password'       => '',
				'email'          => '',
				'emailstamp'     => 0,
				'styleid'        => $this->vars['styleid'],
				'languageid'     => $this->vars['languageid'],
				'lastactivity'   => $this->vars['lastactivity'],
				'daysprune'      => 0,
				'timezoneoffset' => $options['timeoffset'],
				'dstonoff'       => $options['dstonoff'],
				'showsignatures' => 1,
				'showavatars'    => 1,
				'showimages'     => 1,
				'showusercss'    => 1,
				'dstauto'        => 0,
				'maxposts'       => -1,
				'startofweek'    => 1,
				'threadedmode'   => 0,
				'securitytoken'  => 'guest',
				'securitytoken_raw'  => 'guest',
				'lastvisit'      => null,
			);

			$this->userinfo['options'] =
				$bf_misc_useroptions['showsignatures'] |
				$bf_misc_useroptions['showavatars'] |
				$bf_misc_useroptions['showimages'] |
				$bf_misc_useroptions['dstauto'] |
				$bf_misc_useroptions['showusercss'];

			if (empty($this->userinfo['lang_options']))
			{
				$this->loadLanguage();
			}

			$this->userinfo['servertimediff'] = vB_User::calcUsertimeDiff($this->userinfo);

			if (!$this->userinfo['username'])
			{
				if (empty($globalPhrases) AND !empty($this->userinfo['phrasegroup_global']))
				{
					$globalPhrases =@ unserialize($this->userinfo['phrasegroup_global']);
				}

				$this->userinfo['username'] = $globalPhrases['guest'];
			}

			//this needs to be down here because calling it will cause a loop.
			//we'll break the loop on the second call because the this->userinfo
			//is already set.
			$eustatus = 0;
			if($options['enable_privacy_guest'] OR $options['enable_privacy_registered'] OR $options['block_eu_visitors'])
			{
				$request = vB::getRequest();
				$ipaddress = $request->getIpAddress();
				$eustatus = vB_Library::instance('user')->getPrivacyConsentRequired($ipaddress);
			}

			$this->userinfo['eustatus'] = $eustatus;

			//keep the guest user in sync with regular users
			vB_User::fetchMusername($this->userinfo);
		}

		return $this->userinfo;
	}


	/**
	 * Returns appropriate value from the user info array for the owner of this session.
	 *
	 * @return mix	value of user information.
	 */
	public function &fetch_userinfo_value($value)
	{
		$null = null;	// PHP will (can) complain if you return null by reference
		$userinfo = $this->fetch_userinfo();
		if (isset($userinfo[$value]))
		{
			return $userinfo[$value];
		}
		else
		{
			return $null;
		}
	}

	/**
	* Updates the last visit and last activity times for guests and registered users (differently).
	* Last visit is set to the last activity time (before it's updated) only when a certain
	* time has lapsed. Last activity is always set to the specified time.
	*
	* @param	integer	Time stamp for last visit time (guest only)
	* @param	integer	Time stamp for last activity time (guest only)
	* @return	array	Updated values for setting cookies (guest only)
	*/
	public function doLastVisitUpdate($lastvisit = 0, $lastactivity = 0)
	{
		$options = $this->datastore->getValue('options');
		$request = vB::getRequest();
		$timeNow = $request->getTimeNow();

		$cookies = array();

		// update last visit/activity stuff
		if ($this->vars['userid'] == 0)
		{
			// guest -- emulate last visit/activity for registered users by cookies
			if ($lastvisit)
			{
				// we've been here before
				$this->userinfo['lastactivity'] = ($lastactivity ? intval($lastactivity) : intval($lastvisit));

				// here's the emulation
				if ($timeNow - $this->userinfo['lastactivity'] > $options['cookietimeout'])
				{
					// update lastvisit
					$this->userinfo['lastvisit'] = $this->userinfo['lastactivity'];
					$cookies['lastvisit'] = $this->userinfo['lastactivity'];
				}
				else
				{
					// keep lastvisit value
					$this->userinfo['lastvisit'] = intval($lastvisit);
				}
			}
			else
			{
				// first visit!
				$this->userinfo['lastvisit'] = $timeNow;
				$cookies['lastvisit'] = $timeNow;
			}

			// lastactivity is always now
			$this->userinfo['lastactivity'] = $timeNow;
			$cookies['lastactivity'] = $timeNow;

			return $cookies;
		}
		else
		{
			// registered user
			if (!SESSION_BYPASS)
			{
				if ($timeNow - $this->userinfo['lastactivity'] > $options['cookietimeout'])
				{
					// see if session has 'expired' and if new post indicators need resetting
					$this->dBAssertor->shutdownQuery('updateLastVisit',
							array(
								'timenow' => $timeNow,
								'userid' => $this->userinfo['userid']
							),
							'lastvisit');

					$this->userinfo['lastvisit'] = $this->userinfo['lastactivity'];
				}
				else
				{
					// if this line is removed (say to be replaced by a cron job, you will need to change all of the 'online'
					// status indicators as they use $userinfo['lastactivity'] to determine if a user is online which relies
					// on this to be updated in real time.
					$this->dBAssertor->update('user', array('lastactivity'=>$timeNow), array('userid'=>$this->userinfo['userid']), 'lastvisit');
				}
			}

			// we don't need to set cookies for registered users
			return null;
		}
	}

	/**
	 * Create new cpsession for the user and insert it into database or fetch current existing one
	 *
	 * @param bool $renew Whether to renew cpsession hash (Create a new one and drop the old one)
	 *
	 * @throws vB_Exception
	 * @return string The new cpsession hash
	 *
	 */
	public function fetchCpsessionHash($renew = false)
	{
		if (!$this->created)
		{
			throw new vB_Exception_User('session_not_created');
		}

		if ($this->cpsessionHash)
		{
			if (!$renew)
			{
				return $this->cpsessionHash;
			}
			else
			{
				// Drop the old cp session record
				$this->dBAssertor->delete('cpsession', array('hash' => $this->cpsessionHash));
			}
		}

		$this->cpsessionHash = $this->fetch_sessionhash();
		$this->dBAssertor->insert('cpsession', array(
			'userid' => $this->vars['userid'],
			'hash' => $this->cpsessionHash,
			'dateline' => vB::getRequest()->getTimeNow()
		));

		return $this->cpsessionHash;
	}

	public function setCpsessionHash($cpsessionhash)
	{
		$this->cpsessionHash = $cpsessionhash;
	}

	/**
	 * Validate cpsession
	 *
	 * @param bool $updatetimeout Whether to update the table to reset the timeout
	 *
	 * @return bool
	 */
	public function validateCpsession($updatetimeout = true)
	{
		$vboptions = vB::getDatastore()->getValue('options');
		$timenow = vB::getRequest()->getTimeNow();
		$usercontext = vB::getUserContext();

		// Only moderators can use the mog login part of login.php, for cases that use inlinemod but
		// don't have this permission return true
		if (!$usercontext->isModerator() OR !$vboptions['enable_inlinemod_auth'])
		{
			return true;
		}

		if (empty($this->cpsessionHash))
		{
			return false;
		}
		else
		{
			$cpsession = vB::getDbAssertor()->getRow('cpsession', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $this->vars['userid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'hash', 'value' => $this->cpsessionHash, 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'dateline', 'value' => ($vboptions['timeoutcontrolpanel'] ? intval($timenow - $vboptions['cookietimeout']) : intval($timenow - 3600)), 'operator' => vB_dB_Query::OPERATOR_GT),
				)
			));

			if (!empty($cpsession))
			{
				if($updatetimeout)
				{
					vB::getDbAssertor()->update("cpsession", array('dateline' => $timenow), array('userid' => $this->vars['userid'], 'hash' => $this->cpsessionHash));
				}
				return true;
			}
		}

		return false;
	}

	/**
	 * Clear user cached info. Primarily needed for cleaning cache in memory.
	 *
	 */
	public function clearUserInfo()
	{
		if (empty($this->vars['userid']))
		{
			return true;
		}

		// and reload for current session
		$this->loadUserInfo(true);
	}

	/**
	 * Loads user info and stores it in session object property ($this->userinfo)
	 * for a given user regarding options being passed.
	 *
	 * 	@param 	Int 	Userid to load info
	 * 	@param 	Array 	Extra data passed to consider while loading user information.
	 *					'Options' => list of userinfo options (check vB_Api_User USERINFO_XXXX constants)
	 *					'Languageid' => id from the language to load info from.
	 * 	@param 	Bool 	Determines whether or not fetch cached information.
	 *
	 *
	 */
	protected function loadUserInfo($nocache = false)
	{
		if (defined('IN_CONTROL_PANEL'))
		{
			$this->userinfo = vB_Library::instance('user')->fetchUserinfo(
				$this->vars['userid'],
				array(vB_Api_User::USERINFO_ADMIN),
				$this->vars['languageid'],
				$nocache
			);
		}
		else
		{
			$this->userinfo = vB_Library::instance('user')->fetchUserWithPerms($this->vars['userid'], $this->vars['languageid'], $nocache);
		}

		$this->loadLanguage();
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103869 $
|| #######################################################################
\*=========================================================================*/
