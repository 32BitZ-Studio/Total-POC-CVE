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

class vB_Request_Cli extends vB_Request
{
	public function __construct()
	{
		if (!$this->isCLI())
		{
			//we haven't remotely bootstrapped, so looking up phrases is going to be
			//dubious.  I don't think this check is likely enough to come up to
			//be worth the dance required to phrase it.
			echo "cannot use vB CLI scripts from the web";
			exit;
		}

		$this->sessionClass = 'vB_Session_Cli';

		$this->ipAddress = '127.0.0.1';
		$this->altIp = '127.0.0.1';
		$this->userAgent = 'PHP CLI';
		$this->sessionHost = '127.0.0.1';
		$this->referrer = 'PHP CLI';
		parent::__construct();
	}

	public function createSessionForUsername($username)
	{
		if (!$username)
		{
			return $this->createSessionForUser(0);
		}

		$db = vB::getDbAssertor();
		$userid = $db->getField('user', array('username' => $username, vB_dB_Query::COLUMNS_KEY => array('userid')));
		if ($userid)
		{
			return $this->createSessionForUser($userid);
		}
		else
		{
			//create guest session so that we have something for error handling
			$this->createSessionForUser(0);
			throw new vB_Exception_Api('invalid_username');
		}
	}

	private function isCLI()
	{
		if(!defined('STDIN') AND (substr(PHP_SAPI, 0, 3) == 'cgi'))
		{
			return empty($_SERVER['REQUEST_METHOD']);
		}

		return defined('STDIN');
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
