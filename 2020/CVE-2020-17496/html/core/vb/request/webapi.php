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

class vB_Request_WebApi extends vB_Request_Web
{
	public function __construct()
	{
		parent::__construct();

		$this->sessionClass = 'vB_Session_WebApi';
	}

	public function createSession()
	{
		$args =  func_get_args();
		call_user_func_array(array('parent', 'createSession'),$args);

		return array(
			'sessionhash' => $this->session->get('sessionhash'),
			'remembermetoken' => $this->session->getRememberMeToken()
		);
	}

	/**
	 *	Creates a session object and attach it to the request.  May reuse an existing session in the database.
	 *
	 *	@param string $sessionhash -- the token given to the client for session handling.  If the client has this token they
	 *		can use the session.
	 *	@param array $restoreSessionInfo -- Information to handle "remember me" logic.
	 *		* remembermetoken -- Token value for "remember me".  Stored in the "password" cookie for legacy reasons.  There are
	 *			so special values to indicate that we should reauthentic via a method other than the internal vB remember me
	 *			system.
	 *		* userid -- user we are remembering
	 *		* fbsr_{appid} (optional) -- Only valid if facebook is enabled, and only used if "remembermetoken" is "facebook".
	 *
	 *		@return array
	 *		* sessionhash -- the session hash for the session created.  This may be different from the passed sessionhash if that
	 *				session was expired or otherwise unusable.
	 *		* remembermetoken -- token for remembering the user.  This should only be set if the user requests it (or if the
	 *				there is already a token present but the token changed).  It is possible for this to change and if it
	 *				does and is not passed back to the client future attempts to "remember" the session (using the old value) will fail.
	 */
	public function createSessionNew($sessionhash, $restoreSessionInfo)
	{
		$session = vB_Session_WebApi::createSessionNew($sessionhash, $restoreSessionInfo);
		$this->setSession($session);

		return array(
			'sessionhash' => $this->session->get('sessionhash'),
			'remembermetoken' => $this->session->getRememberMeToken()
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
