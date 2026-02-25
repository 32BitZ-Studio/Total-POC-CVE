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
 * vB_Library_Cron
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Cron extends vB_Library
{
	public function runById($cronid)
	{
		$nextitem = vB::getDbAssertor()->getRow('cron', array('cronid' => $cronid));
		$this->runCronInternal($nextitem);
	}

	public function runByVarname($varname)
	{
		$nextitem = vB::getDbAssertor()->getRow('cron', array('varname' => $varname));
		$this->runCronInternal($nextitem);
	}

	/**
	 * Run a cron by the cron record
	 *
	 * @param array $nextitem -- the cron record
	 * @return void
	 */
	private function runCronInternal($nextitem)
	{
		if ($nextitem)
		{
			ignore_user_abort(1);
			@set_time_limit(0);

			// Force custom scripts to use $vbulletin->db to follow function standards of only globaling $vbulletin
			// This will cause an error to be thrown when a script is run manually since it will silently fail when cron.php runs if $db-> is accessed

			require_once(DIR . '/includes/functions_cron.php');
			include(DIR . '/' . $nextitem['filename']);
		}
		else
		{
			throw new vB_Exception_Api('invalid_action_specified_gerror');
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
