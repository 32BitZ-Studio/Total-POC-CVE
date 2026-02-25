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
 * This class is used by collapsed interface and behaves exactly as a web session without cookies
 */
class vB_Session_WebApi extends vB_Session_Web
{

	public static function getSession($userId, $sessionHash = '', $dBAssertor = null, $datastore = null, $config = null)
	{
		$dBAssertor = ($dBAssertor) ? $dBAssertor : vB::getDbAssertor();
		$datastore = ($datastore) ? $datastore : vB::getDatastore();
		$config = ($config) ? $config : vB::getConfig();

		$restoreSessionInfo = array('userid' => $userId);
		$session = new vB_Session_WebApi($dBAssertor, $datastore, $config, $sessionHash, $restoreSessionInfo);
		$session->set('userid', $userId);
		$session->fetch_userinfo();
		return $session;
	}

	public static function createSession($sessionhash= '', $userid = 0, $password = '')
	{
		$assertor = vB::getDbAssertor();
		$datastore = vB::getDatastore();
		$config = vB::getConfig();

		$restoreSessionInfo = array('remembermetoken' => $password, 'userid' => $userid);
		$session = new vB_Session_WebApi($assertor, $datastore, $config, $sessionhash, $restoreSessionInfo);
		return $session;
	}

	/**
	 *	Create a session for this page load
	 *
	 *	Should only be called from the Request code.
	 *	Will use a reexisting session that matches the session hash
	 *
	 *	@param string $sessionhash -- the token given to the client for session handling.  If the client has this token they
	 *		can use the session.
	 *	@param array $restoreSessionInfo -- Information to handle "remember me" logic.
	 *		* remembermetoken -- Token value for "remember me".  Stored in the "password" cookie for legacy reasons.  There are
	 *			so special values to indicate that we should reauthentic via a method other than the internal vB remember me
	 *			system.
	 *		* userid -- user we are remembering
	 *		* fbsr_{appid} (optional) -- Only valid if facebook is enabled, and only used if "remembermetoken" is "facebook".
	 */
	public static function createSessionNew($sessionhash, $restoreSessionInfo = array())
	{
		$assertor = vB::getDbAssertor();
		$datastore = vB::getDatastore();
		$config = vB::getConfig();

		//this looks weird but its valid.  Will create the an instance of whatever session class this was called
		//on.  So vB_Session_Web::createSessionNew() will do the expected thing.
		$session = new vB_Session_WebApi($assertor, $datastore, $config, $sessionhash, $restoreSessionInfo);
		return $session;
	}

	protected function __construct(&$dBAssertor, &$datastore, &$config, $sessionhash = '', $restoreSessionInfo, $styleid = 0, $languageid = 0)
	{
		parent::__construct($dBAssertor, $datastore, $config, $sessionhash, $restoreSessionInfo, $styleid, $languageid);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
