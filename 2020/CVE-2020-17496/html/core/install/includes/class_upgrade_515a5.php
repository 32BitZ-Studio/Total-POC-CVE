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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_515a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '515a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.5 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.5 Alpha 4';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	/**
	 * Turn the user mention notification option on for new registrations by default
	 */
	public function step_1()
	{
		// Add 268435456 (general_usermention) to the default value for notification_options
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 2),
			"ALTER TABLE " . TABLE_PREFIX . "user
			CHANGE notification_options notification_options INT UNSIGNED NOT NULL DEFAULT '536870906'"
		);
	}

	/**
	 * Turn the user mention notification option on for all current users by default
	 */
	public function step_2()
	{
		// Turn 268435456 on (general_usermention) for all users
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 2, 2),
			"UPDATE " . TABLE_PREFIX . "user
			SET notification_options = (notification_options | 268435456)"
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
