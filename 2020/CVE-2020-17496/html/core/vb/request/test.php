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

class vB_Request_Test extends vB_Request
{
	public function __construct($vars)
	{
		$serverVars = array('ipAddress', 'altIp', 'sessionHost', 'userAgent', 'referrer');
		foreach ($serverVars AS $serverVar)
		{
			if (!empty($vars[$serverVar]))
			{
				$this->$serverVar = $vars[$serverVar];
				unset($vars[$serverVar]);
			}
		}

		parent::__construct();

		foreach ($vars as $var=>$value)
		{
			$this->$var = $value;
		}
	}

	public function createSession($userid = 1)
	{
		//$this->session = vB_Session_Web::getSession(1);
		$this->session = new vB_Session_Cli(
		 	vB::getDbAssertor(),
		 	vB::getDatastore(),
			vB::getConfig(),
			$userid
		);
		vB::setCurrentSession($this->session);
		$this->timeNow = time();
	}

	/**
	 *	Allows setting the IP address for test purposes.
	 *
	 *	This should not be used by production code (nor should this entire class).
	 */
	public function setIpAddress($ipaddress)
	{
		$this->ipAddress = $ipaddress;
		$this->altIp = $ipaddress;
	}

	//note that the time functions are deliberately *not* availabe on the parent
	//class.  They should only be used in the unit tests where we know we have
	//a test request.

	/**
	 *	Set the request time for test purposes
	 *	@param $time -- the unix timestamp to set the time to
	 */
	public function setTimeNow($time)
	{
		$this->timeNow = $time;
	}

	/**
	 *	Change the request time for test purposes
	 *	@param $time -- the amount of time (in seconds) to add to the current value
	 *		negative values are okay.
	 */
	public function adjustTimeNow($time)
	{
		$this->timeNow += $time;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102399 $
|| #######################################################################
\*=========================================================================*/
