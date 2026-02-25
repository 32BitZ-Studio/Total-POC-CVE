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
 * vB_Library_Facebook
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Facebook extends vB_Library
{
	//this should match the values in the javascript
	//and the api/collapsed facebook redirect response
	const FBVERSION = 'v3.3';

	protected static $sdk_failed = false;

	protected $facebookInitialized = false;
	protected $failureReason = "";
	protected $fb_session = null;
	protected $fb_session_tried = false;
	protected $fb_userinfo = array();

	protected $vb_userid = null;

	/**
	 * Constructor
	 *
	 */
	protected function __construct()
	{
		//this also works to intialize the first time
		$this->reinitialize();
	}

	/**
	 *	Reintialize the facebook application
	 *
	 *	If for some reason the FB status changes during a script run (for example you enable it in the vb option)
	 *	this will force an attempt to recheck its status.  Otherwise we will store the status based on the first
	 *	attempt.
	 *
	 *	If the intiailization fails, the reason can be determeined via vB_Library_Facebook::getInitializeFailureMessage();
	 *
	 *	@return boolean false if it failed, true if not
	 */
	public function reinitialize()
	{
		//if we tried before and couldn't load the SDK, don't try again.  We won't actually
		//load the SDK file the second time and this will cause a problem.
		if (self::$sdk_failed)
		{
			return false;
		}

		//reset our state
		$this->facebookInitialized = false;
		$this->failureReason = "";

		$options = vB::getDatastore()->getValue('options');
		if (!$options['facebookactive'])
		{
			$this->failureReason = "Facebook is not active";
			return false;
		}

		if (empty($options['facebookappid']) OR empty($options['facebooksecret']))
		{
			$this->failureReason = "Facebook is not configured";
			return false;
		}

		if (defined('SKIP_SESSIONCREATE'))
		{
			$this->failureReason = "Facebook is not available when session creation is skipped";
			return false;
		}

		try
		{
			require_once(DIR . '/libraries/facebook/autoload.php');
		}
		catch (Exception $e)
		{
			$this->failureReason = "Facebook SDK failed to initialize";
			$this->handleFacebookException($e);
			self::$sdk_failed = true;
			return false;
		}

		Facebook\FacebookSession::setDefaultApplication($options['facebookappid'], $options['facebooksecret']);
		$this->facebookInitialized = true;
		return true;
	}

	private function getSession()
	{
		//only try to find a session once even if we failed.
		if ($this->fb_session_tried)
		{
			return $this->fb_session;
		}

		if (!$this->fb_session)
		{
			$authtoken = $this->getAuthFromPHPSession();
			if ($authtoken)
			{
				$this->setSession($authtoken);
			}
		}

		if (!$this->fb_session)
		{
			//The javascript helper uses cookies internally.  We don't really want to be dealing
			//with cookies here, however unwinding this make require getting deeper into the
			//Facebook SDK than is prudent.
			$helper = new Facebook\FacebookJavaScriptLoginHelper();
			try
			{
				$this->fb_session = $helper->getSession();
				if ($this->fb_session)
				{
					$this->fb_session->validate();
					$this->storeInPHPSession($this->fb_session->getToken());
				}
			}
			catch(Facebook\FacebookAuthorizationException $e)
			{
				//deliberate fallthrough.  If we don't authorize we'll treat the
				//user as not logged in but we will assume that FB is enabled.
				//usually this means we have an expired token and the user will
				//need to log in again.
				$this->fb_session = null;
			}
		}

		$this->fb_session_tried = true;
		return $this->fb_session;
	}


	/**
	 *	Sets the session information from a signed request
	 *
	 *	This will "use up" the signed request by fetching the authtoken
	 *
	 *	@param string $sr -- the signed request token from facebook
	 *	@return bool
	 */
	private function setSessionFromSignedRequest($sr)
	{
		try
		{
			$requestObj = new Facebook\Entities\SignedRequest($sr);
			$this->fb_session = Facebook\FacebookSession::newSessionFromSignedRequest($requestObj);
			$this->fb_session->validate();
		}
		catch (Exception $e)
		{
			$this->fb_session = null;
			//$this->handleFacebookException($e);
			return false;
		}

		return true;
	}

	private function setSession($authToken)
	{
		try
		{
			$this->fb_session = new Facebook\FacebookSession($authToken);
			$this->fb_session->validate();
		}
		catch (Exception $e)
		{
			$this->fb_session = null;
			//$this->handleFacebookException($e);
			return false;
		}

		return true;
	}

	private function storeInPHPSession($authToken)
	{
		if (session_status() == PHP_SESSION_NONE)
		{
			session_start();
		}

		$_SESSION['facebookauthtoken'] = $authToken;
	}

	private function getAuthFromPHPSession()
	{
		if (session_status() == PHP_SESSION_NONE)
		{
			session_start();
		}
		return (isset($_SESSION['facebookauthtoken']) ? $_SESSION['facebookauthtoken'] : '');
	}


	/**
	 *	Is facebook enabled on this site.
	 *
	 *	@return bool true if the facebook system initialized properly, false otherwise
	 *		note that if we get an error this may be false even if facebook is configured
	 *		in the admincp.
	 */
	public function isFacebookEnabled()
	{
		return $this->facebookInitialized;
	}

	/**
	 *	Get the reason why facebook failed to initialize
	 *
	 *	@return string Reason why initialization failed
	 */
	public function getInitializeFailureMessage()
	{
		return $this->failureReason;
	}

	/**
	 *	Throws an exception if the a function needing the facebook system
	 *	is called without it being initialized.  The caller *should* call
	 *	isFacebookEnabled to ensure that this never happens.
	 *
	 *	@return none -- Either throws an exception or returns normally.
	 */
	private function checkInitialized()
	{
		if (!$this->facebookInitialized)
		{
			//todo update with a real API exception.
			throw new Exception($this->failureReason);
		}
	}

	/**
	 *	Associate a vb account with a facebook sesssion
	 *
	 *	@param array $info.  The various information needed for the provider to log in for facebook.  One of
	 *		'token' or 'signedrequest' must be provided.  If both are then 'token' will be tried first.
	 *		* 'token' string the facebook access/oAuth token. (optional)
	 *		* 'signedrequest' string the facebook signedrequest.  this is a one use token that can be used
	 *			to retrieve the auth token. (optional)
	 */
	public function createSessionForLogin($info)
	{
		$this->checkInitialized();
		$found = false;
		if (!empty($info['token']))
		{
			$found = $this->setSession($info['token']);
		}

		if (!$found AND !empty($info['signedrequest']))
		{
			$found = $this->setSessionFromSignedRequest($info['signedrequest']);
		}

		if (!$found)
		{
			throw new vB_Exception_Api('error_invalid_facebook_session');
		}

		//store this for later use, espcially the mobile app which will
		//expect us to have this after a failed FB login for potential linking.
		$this->storeInPHPSession($this->fb_session->getToken());

		$userinfo = $this->getFbUserInfo();
		$vbuserid = false;
		if (isset($userinfo['id']))
		{
			$vbuserid = vB::getDbAssertor()->getRow('user',
				array(
					'fbuserid' => $userinfo['id'],
					vB_dB_Query::COLUMNS_KEY => array('userid')
				)
			);
		}

		if ($vbuserid)
		{
			$vbuserid = $vbuserid['userid'];
		}
		else
		{
			throw new vB_Exception_Api('error_external_no_vb_user', 'Facebook');
		}
		return $vbuserid;
	}


	/**
	*	Clear all stored information for the current user from vB
  * This will not log the user out of either vB or Facebook (but is
  * is expected that this will be called as part of logging the user
	* out of the vBulletin)
	*
	*	Will do nothing if facebook is not initialized.
	*
	* @return none
	*/
	public function clearSession()
	{
		//let's not require the caller to check the init status of facebook
		//we'll just do nothing if its not enabled or working
		if (!$this->facebookInitialized)
		{
			return;
		}

		if ($this->getAuthFromPHPSession())
		{
			$this->storeInPHPSession('');
		}
	}

	/**
	 *	Disconnect the user's account from facebook
	 *
	 *	Unlike previous behavior *do not require that the user be logged in to facebook*
	 *	This causes a situation where if the user mucks with the association on the FB
	 *	end they can screw it up to the point where it doesn't work.  And they can't
	 *	just reassociate the account because they can't log in to disconnect.
	 *
	 *	@param int $userid the userid to be disconnected.
	 *
	 *	@return none
	 */
	public function disconnectUser($userid)
	{
		$this->checkInitialized();

		if ($userid)
		{
			vB::getDbAssertor()->update('user',
				array('fbuserid' => '', 'fbname' => '', 'fbjoindate' => ''),
				array('userid' => $userid)
			);

			//this is an extra update query, but its worth it to standardize the access to the user groups
			//also it will eventually be necesary since the we need to move the fb fields out of the user
			//table as part off expanding the notions of "3rd party logins/integrations".
			$fbusergroupid = vB::getDatastore()->getOption('facebookusergroupid');
			if ($fbusergroupid)
			{
				vB_Library::instance('user')->removeSecondaryUserGroups($userid, array($fbusergroupid));
			}
		}
	}

	/**
	 *	Connects the currently logged in user to the currently logged in Facebook user
	 *
	 *	Note that we don't allow connection of a non logged in account because
	 *	we need to validate the FB login.  Connecting somebody else's account
	 *	to a FB just doesn't make sense as an action.
	 *
	 *	@param string $accessToken.  The facebook access token to verify the FB login
	 *	@return none
	 */
	public function connectCurrentUser($accessToken=null)
	{
		$this->checkInitialized();

		$userid = vB::getCurrentSession()->get('userid');
		if (!$userid)
		{
			throw new vB_Exception_Api('error_cannot_connect_guest', 'Facebook');
		}

		//if we have an access token check it.
		if ($accessToken)
		{
			if (!$this->setSession($accessToken))
			{
				throw new vB_Exception_Api('error_invalid_facebook_session');
			}
		}
		//if we don't make sure that we have a stored session to use
		else if (!$this->userIsLoggedIn())
		{
			throw new vB_Exception_Api('error_invalid_facebook_session');
		}

		if ($this->getVbUseridFromFbUserid())
		{
			throw new vB_Exception_Api('error_already_connected', 'Facebook');
		}

		$this->fb_session = $this->fb_session->getLongLivedSession();
		if (!$this->fb_session)
		{
			throw new vB_Exception_Api('error_invalid_facebook_session');
		}

		$userinfo = $this->getFbUserInfo();
		vB::getDbAssertor()->update('user',
			array(
				'fbuserid' => $userinfo['id'],
				'fbname' => $userinfo['name'],
				'fbjoindate' => vB::getRequest()->getTimeNow(),
			),
			array('userid' => $userid)
		);

		//this is an extra update query, but its worth it to standardize the access to the user groups
		//also it will eventually be necesary since the we need to move the fb fields out of the user
		//table as part off expanding the notions of "3rd party logins/integrations".
		$fbusergroupid = vB::getDatastore()->getOption('facebookusergroupid');
		if ($fbusergroupid)
		{
			vB_Library::instance('user')->addSecondaryUserGroups($userid, array($fbusergroupid));
		}
	}

	/**
	 * Get the logged in user's profile url.
	 *
	 * @return string|false facebook profile url or false on failure
	 * 	(forex, there is no logged in FB user)
	 */
	public function getFbProfileUrl()
	{
		$fbuserid = $this->getLoggedInFbUserId();
    if ($fbuserid)
		{
			return "http://www.facebook.com/$fbuserid";
		}
		else
		{
			return false;
		}
	}

	/**
	 * Get the logged in user's profile picture url.
	 *
	 * @return string|false facebook profile picture url or false on failure
	 * 	(forex, there is no logged in FB user)
	 */
	public function getFbProfilePicUrl()
	{
		$fbuserid = $this->getLoggedInFbUserId();
    if ($fbuserid)
    {
      return "http://graph.facebook.com/" . self::FBVERSION . "/$fbuserid/picture";
    }
    else
    {
      return false;
    }

		return $picurl;
	}

	/**
	 * Checks if the current user is logged into facebook
	 *
	 * @param bool $ping Whether to ping Facebook (unused)
	 * @return bool
	 */
	public function userIsLoggedIn($ping = false)
	{
		if (!$this->facebookInitialized)
		{
			return false;
		}

		$session = $this->getSession();
		return (bool) $session;
	}

	/**
	 * Verifies that the current session auth token is still valid with facebook
	 * 	- performs a Facebook roundtrip
	 *
	 * @return bool, true if auth token is still valid
	 */
	public function isValidAuthToken()
	{
		$session = $this->getSession();
		if (!$this->fb_session)
		{
			return false;
		}

		return $this->fb_session->validate();
	}

	/**
	 * Checks for a currrently logged in user through facebook api
	 *
	 * @return mixed, fb userid if logged in, false otherwise
	 */
	public function getLoggedInFbUserId()
	{
		$info = $this->getFbUserInfo();
		return $info['id'];
	}

	/**
	 * Grabs logged in user info from faceboook if user is logged in
	 *
	 * @param bool, forces a roundtrip to the facebook server, ie. dont use cached info
	 *
	 * @return array, fb userinfo array if logged in, false otherwise,
	 * 		see the facebook '/me' docs for details
	 */
	public function getFbUserInfo($force_reload = false)
	{
		// check for cached versions of this, and return it if so
		if (!empty($this->fb_userinfo) AND !$force_reload)
		{
			return $this->fb_userinfo;
		}

		// make sure we have a fb session, otherwise we cant return any data
		if (empty($this->fb_session))
		{
			return false;
		}

		// attempt to grab userinfo from fb graph api, using FQL
		try
		{
			$fields = array(
				'name',
				'email',
				'id',
			);
			$user = $this->apiGet('/me', Facebook\GraphUser::className(), array('fields' => implode(',', $fields)));
			$this->fb_userinfo = $user->asArray();
		}
		catch (Exception $e)
		{
			$this->handleFacebookException($e);
			return false;
		}

		// now return the user info if we got any
		return $this->fb_userinfo;
	}

	/**
	 * Checks if current facebook user is associated with a vb user, and returns vb userid if so
	 *
	 * @param int, facebook userid to check in vb database, if not there well user current
	 * 		logged in user
	 * @return mixed, vb userid if one is associated, false if not
	 */
	public function getVbUseridFromFbUserid($fb_userid = false)
	{
		// if no fb userid was passed in, attempt to use current logged in fb user
		// but if no current fb user, there cannot be an associated vb account, so return false
		if (empty($fb_userid) AND !($fb_userid = $this->getLoggedInFbUserId()))
		{
			return false;
		}

		// check if vB userid is already cached in this object
		if ($fb_userid == $this->getLoggedInFbUserId() AND !empty($this->vb_userid))
		{
			return $this->vb_userid;
		}

		// otherwise we have to grab the vb userid from the database
		$user = vB::getDbAssertor()->getRow('user', array('fbuserid' => $fb_userid));
		$this->vb_userid = (!empty($user['userid']) ? $user['userid'] : false);

		return $this->vb_userid;
	}

	protected function apiGet($call, $type = 'Facebook\GraphObject', $data=null)
	{
		// Make a new request and execute it -- the version param is obscurely documented...
		// I've seen documentation that suggests putting the version in the call string like
		// you would calling the graph api directly.  But that... doesn't work.
		$request = new Facebook\FacebookRequest($this->fb_session, 'GET', $call, $data, self::FBVERSION);
  	$response = $request->execute();
  	$object = $response->getGraphObject($type);
		return $object;
	}

	protected function apiPost($call, $data, $type = 'Facebook\GraphObject')
	{
		$request = new Facebook\FacebookRequest($this->fb_session, 'POST', $call, $data, self::FBVERSION);
  	$response = $request->execute();
  	$object = $response->getGraphObject($type);
		return $object;
	}

	/**
	 * Handles facebook exceptions (expose the exception if in debug mode)
	 *
	 * @param	object	The facebook exception
	 */
	protected function handleFacebookException(Exception $e)
	{
		$config = vB::getConfig();
		if (isset($config['Misc']['debug']) AND $config['Misc']['debug'])
		{
			throw $e;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
