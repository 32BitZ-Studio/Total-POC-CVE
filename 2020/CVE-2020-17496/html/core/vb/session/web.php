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

class vB_Session_Web extends vB_Session
{
	public static function getSession($userId, $sessionHash = '', $dBAssertor = null, $datastore = null, $config = null)
	{
		$dBAssertor = ($dBAssertor) ? $dBAssertor : vB::getDbAssertor();
		$datastore = ($datastore) ? $datastore : vB::getDatastore();
		$config = ($config) ? $config : vB::getConfig();

		$restoreSessionInfo = array('userid' => $userId);
		$session = new vB_Session_Web($dBAssertor, $datastore, $config, $sessionHash, $restoreSessionInfo);
		$session->set('userid', $userId);
		$session->fetch_userinfo();

		return $session;
	}

	protected function __construct(&$dBAssertor, &$datastore, &$config, $sessionhash = '', $restoreSessionInfo = array(), $styleid = 0, $languageid = 0)
	{
		parent::__construct($dBAssertor, $datastore, $config, $sessionhash, $restoreSessionInfo, $styleid, $languageid);
	}

	protected function createSessionIdHash()
	{
		$request = vB::getRequest();
		$this->sessionIdHash = md5($request->getUserAgent() . $this->fetch_substr_ip($request->getAltIp()));
	}

	/**
	 * Get the current url scheme- http or https
	 *
	 * @return string
	 */
	public function getVbUrlScheme()
	{
		return vB::getRequest()->getVbUrlScheme();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
