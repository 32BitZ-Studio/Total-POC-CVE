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

class vB_Upgrade_524a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '524a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.4 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.4 Alpha 3';

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

	public function step_1()
	{
		$this->drop_table('subscribegroup');
	}

	// add missing css units
	public function step_2()
	{
		if ($this->field_exists('stylevardfn', 'units'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'stylevardfn', 1, 1),
				"
					ALTER TABLE " . TABLE_PREFIX . "stylevardfn
					MODIFY COLUMN units
						ENUM('','%','px','pt','em','rem','ch','ex','pc','in','cm','mm','vw','vh','vmin','vmax')
						NOT NULL DEFAULT ''
				"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Prep for step_4: Need to import the settings XML in case this install doesn't have the new option yet.
	 */
	public function step_3()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}


		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-settings.xml'));

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_1();
	}

	/*
	 * Copy current floodchecktime value into pm_floodchecktime. Run once only.
	 */
	public function step_4()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		vB_Upgrade::createAdminSession();
		$this->show_message($this->phrase['version']['524a4']['copying_floodchecktime']);
		$options = vB::get_datastore()->get_value('options');
		if (isset($options['floodchecktime']) AND isset($options['pm_floodchecktime']))
		{
			$this->set_option('pm_floodchecktime', 'pm', intval($options['floodchecktime']));
		}
	}

	public function step_5()
	{
		// Place holder to allow iRan() to work properly, as the last step gets recorded as step '0' in the upgrade log for CLI upgrade.
		$this->skip_message();
		return;
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
