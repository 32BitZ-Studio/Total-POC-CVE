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

class vB_Upgrade_525a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '525a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.5 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.5 Alpha 2';

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

	/** Update default for user.options */
	public function step_1()
	{
		if ($this->field_exists('user', 'options'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "user CHANGE COLUMN `options` `options` INT UNSIGNED NOT NULL DEFAULT '167788559'
				"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add screenlayout.sectiondata
	 */
	public function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', 1, 1),
			'screenlayout',
			'sectiondata',
			'text',
			array('null' => false, 'default' => '')
		);
	}

	/**
	 * Add pagetemplate.screenlayoutsectiondata
	 */
	public function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'pagetemplate', 1, 1),
			'pagetemplate',
			'screenlayoutsectiondata',
			'text',
			array('null' => false, 'default' => '')
		);
	}

	/**
	 * Import default pagetemplate.screenlayoutsectiondata values if needed
	 */
	public function step_4()
	{
		$assertor = vB::getDbAssertor();

		$addSectionData = false;
		$guids = array(
			// all the default page templates that use the narrow-wide screenlayout
			'vbulletin-4ecbdac9372590.52063766', // User Profile Template
			'vbulletin-4ecbdac93742a5.43676026', // Private Messages Template (Message Center)
			'vbulletin-4ecbdac93742a5.43676027', // Subscription Template (User Profile => Subscriptions)
			'vbulletin-4ecbdac93742a5.43676029', // Visitor Message Display Template (User Profile => Click "See More" on a Visitor Message)
		);
		$pagetemplates = $assertor->assertQuery('pagetemplate', array(
			'guid' => $guids,
		));
		foreach ($pagetemplates AS $pagetemplate)
		{
			if (empty($pagetemplate['screenlayoutsectiondata']))
			{
				$addSectionData = true;
				break;
			}
		}

		if ($addSectionData)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-pagetemplates.xml'));

			$pageTemplateFile = DIR . '/install/vbulletin-pagetemplates.xml';
			if (!($xml = file_read($pageTemplateFile)))
			{
				$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pagetemplates.xml'), self::PHP_TRIGGER_ERROR, true);
				return;
			}

			$options = vB_Xml_Import::OPTION_OVERWRITECOLUMN;
			$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', $options);
			$xml_importer->setOverwriteColumn('screenlayoutsectiondata');
			$xml_importer->importFromFile($pageTemplateFile, $guids);
			$this->show_message($this->phrase['core']['import_done']);
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