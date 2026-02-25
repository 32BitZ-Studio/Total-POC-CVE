<?php
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

// This class is used for install scripts
class vB_Session_Cli extends vB_Session
{
	public static function getSession($userId, $sessionHash = '', $dBAssertor = null, $datastore = null, $config = null)
	{
		$dBAssertor = ($dBAssertor) ? $dBAssertor : vB::getDbAssertor();
		$datastore = ($datastore) ? $datastore : vB::getDatastore();
		$config = ($config) ? $config : vB::getConfig();

		$session = new vB_Session_Cli($dBAssertor, $datastore, $config, $userId);
		return $session;
	}

	public function __construct(&$dBAssertor, &$datastore, &$config, $userid)
	{
		$restoreSessionInfo = array('userid' => $userid);
		parent::__construct($dBAssertor, $datastore, $config, '', $restoreSessionInfo);
		$this->set('userid', $userid);

		//If we are in unit test we need to force a load of userinfo.
		if (defined('VB_AREA') AND (VB_AREA == 'Unit Test') AND ($userid > 0))
		{
			$useroptions = array();
			if (defined('IN_CONTROL_PANEL'))
			{
				$useroptions[] = vB_Api_User::USERINFO_ADMIN;
			}
			$this->userinfo = vB_User::fetchUserinfo($this->vars['userid'], $useroptions, $this->vars['languageid'], true);
		}
		//needed for error message handling.
		$_SERVER['HTTP_HOST'] = 'commandline';
	}

	protected function loadExistingSession($sessionhash, $restoreSessionInfo)
	{
		// CLI doesn't need to use stored sessions
		return false;
	}

	/**
	 * Sets the attribute sessionIdHash
	 */
	protected function createSessionIdHash()
	{
		// API session idhash won't have User Agent compiled.
		$this->sessionIdHash = md5('session_' . $this->userinfo['userid'] . time());
	}

	public function save()
	{
		// CLI doesn't need to use stored sessions
		return false;
	}

	public function saveForTesting()
	{
		parent::save();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
