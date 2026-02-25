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

class vB_Upgrade_523a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '523a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.3 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.3 Alpha 4';

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
	 * Change moderator id field from small int to int
	 */
	public function step_1()
	{
		if ($this->field_exists('moderator', 'moderatorid'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'moderator', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "moderator CHANGE moderatorid moderatorid INT(10) UNSIGNED NOT NULL AUTO_INCREMENT"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_2()
	{
		if ($this->field_exists('strikes', 'strikeip'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'strikes', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "strikes CHANGE strikeip strikeip VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_3()
	{
		if ($this->field_exists('adminlog', 'ipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'adminlog', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "adminlog CHANGE ipaddress ipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_4()
	{
		if ($this->field_exists('moderatorlog', 'ipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'moderatorlog', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "moderatorlog CHANGE ipaddress ipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_5()
	{
		if ($this->field_exists('user', 'ipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "user CHANGE ipaddress ipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
