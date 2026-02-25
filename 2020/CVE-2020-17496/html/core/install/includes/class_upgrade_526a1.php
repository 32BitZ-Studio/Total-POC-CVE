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

class vB_Upgrade_526a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '526a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.6 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.5';

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
	 * Import default pagetemplate.screenlayoutsectiondata values if needed
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();

		$addSectionData = false;
		$guids = array(
			// Some, but not all, of the default page templates that use the wide-narrow
			// screenlayout, specifically, the blog and group pages.
			'vbulletin-4ecbdac93742a5.43676030', // Individual Blog Page Template
			'vbulletin-sgroups93742a5.43676038', // Individual Group Page Template
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
