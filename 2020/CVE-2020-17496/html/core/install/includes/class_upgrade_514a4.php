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

class vB_Upgrade_514a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '514a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.4 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.4 Alpha 3';

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
	 * VBV-13464 (VBV-3594)
	 * Update the bitfield value for email notifications in the default
	 * user registration settings.
	 */
	public function step_1()
	{
		// if 'subscribe_none' is set, then remove it and set 'emailnotification_none'
		// 512 was 'subscribe_none', is now 'autosubscribe'
		// 1024 was 'subscribe_nonotify', is now 'emailnotification_none'
		// subscribe_none used to be the default, and emailnotification_none is now the default

		$regoptions = vB::getDatastore()->getValue('bf_misc_regoptions');
		$existing = vB::getDbAssertor()->getRow('setting', array('varname' => 'defaultregoptions'));

		if ($existing['value'] & $regoptions['autosubscribe'])
		{
			// remove 'subscribe_none' (renamed to 'autosubscribe')
			$this->run_query(
				sprintf($this->phrase['vbphrase']['update_table_x'], TABLE_PREFIX . 'setting', 1, 2),
				"UPDATE " . TABLE_PREFIX . "setting
				SET value = value & ~" . intval($regoptions['autosubscribe']) . "
				WHERE varname = 'defaultregoptions'"
			);

			// add 'emailnotification_none'
			$this->run_query(
				sprintf($this->phrase['vbphrase']['update_table_x'], TABLE_PREFIX . 'setting', 2, 2),
				"UPDATE " . TABLE_PREFIX . "setting
				SET value = value | " . intval($regoptions['emailnotification_none']) . "
				WHERE varname = 'defaultregoptions'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * VBV-13449 (VBV-3594)
	 * Rename autosubscribe to emailnotification
	 */
	public function step_2()
	{
		if ($this->field_exists('user', 'autosubscribe') AND !$this->field_exists('user', 'emailnotification'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "user CHANGE autosubscribe emailnotification SMALLINT UNSIGNED NOT NULL DEFAULT '0'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * VBV-13451 (VBV-3594)
	 * Add (new) autosubscribe column
	 */
	public function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 1),
			'user',
			'autosubscribe',
			'smallint',
			self::FIELD_DEFAULTS
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
