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

class vB_Upgrade_514a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '514a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.4 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.4 Alpha 1';

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
	 * Update the Who's Online page to use the full width layout
	 */
	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'pagetemplate', 1, 1),
			"UPDATE " . TABLE_PREFIX . "pagetemplate
			SET screenlayoutid = 1
			WHERE guid = 'vbulletin-4ecbdac93721f3.19350821' AND screenlayoutid = 2"
		);
	}

	/**
	 * Add guid column to screenlayout
	 */
	public function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', 1, 6),
			'screenlayout',
			'guid',
			'varchar',
			array('length' => 150, 'null' => true, 'default' => null, 'attributes' => self::FIELD_DEFAULTS)
		);
	}

	/**
	 * Add unique index on screenlayout.guid
	 */
	public function step_3()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', 2, 6),
			'screenlayout',
			'guid',
			'guid',
			'unique'
		);
	}

	/**
	 * Add unique index on screenlayout.varname
	 */
	public function step_4()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', 3, 6),
			'screenlayout',
			'varname',
			'varname',
			'unique'
		);
	}

	/**
	 * Add standard GUIDs for the 3 default screenlayouts we've had up to now
	 */
	public function step_5()
	{
		$items = array(
			1 => 'vbulletin-screenlayout-full-ef8c99cab374d2.91030970',
			2 => 'vbulletin-screenlayout-wide-narrow-ef8c99cab374d2.91030971',
			4 => 'vbulletin-screenlayout-narrow-wide-ef8c99cab374d2.91030972',
		);

		$index = 4;
		foreach ($items AS $screenlayoutid => $guid)
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', $index, 6),
				"UPDATE " . TABLE_PREFIX . "screenlayout
				SET guid = '" . $this->db->escape_string($guid) . "'
				WHERE screenlayoutid = " . intval($screenlayoutid) . "
				"
			);
			++$index;
		}
	}

	/**
	 * Rename the screenlayout templates
	 *
	 * Note: the template names in the screenlayout records will be updated
	 * automatically in final upgrade.
	 */
	public function step_6()
	{
		$items = array(
			'screenlayout_1'       => 'screenlayout_display_full',
			'screenlayout_2'       => 'screenlayout_display_wide_narrow',
			'screenlayout_4'       => 'screenlayout_display_narrow_wide',
			'admin_screenlayout_1' => 'screenlayout_admin_full',
			'admin_screenlayout_2' => 'screenlayout_admin_wide_narrow',
			'admin_screenlayout_4' => 'screenlayout_admin_narrow_wide',
		);

		$index = 1;
		foreach ($items AS $oldTitle => $newTitle)
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'template', $index, 6),
				"UPDATE " . TABLE_PREFIX . "template
				SET title = '" . $this->db->escape_string($newTitle) . "'
				WHERE title = '" . $this->db->escape_string($oldTitle) . "'
				"
			);
			++$index;
		}

		$index = 1;
		foreach ($items AS $oldTitle => $newTitle)
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'templatehistory', $index, 6),
				"UPDATE " . TABLE_PREFIX . "templatehistory
				SET title = '" . $this->db->escape_string($newTitle) . "'
				WHERE title = '" . $this->db->escape_string($oldTitle) . "'
				"
			);
			++$index;
		}

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
