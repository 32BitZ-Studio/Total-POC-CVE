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

class vB_Upgrade_556a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '556a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION = '5.5.6 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.5';

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
	public $VERSION_COMPAT_ENDS = '';

	public function step_1()
	{
		// import vbulletin-settings.xml so "useemoji" exists for step 2
		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-settings.xml'));

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . '/install/includes/class_upgrade_final.php');
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase, $this->maxversion);
		$finalUpgrader->step_1();
	}

	public function step_2()
	{
		// See also vB_Upgrade_install::step_5
		$assertor = vB::getDbAssertor();
		$charsets = $assertor->getDbCharsets('text', 'rawtext');
		if ($charsets['effectiveCharset'] == 'utf8mb4')
		{
			$this->show_message($this->phrase['version']['556a1']['enabling_ckeditor_emoji_plugin']);

			vB_Upgrade::createAdminSession();
			// NOTE: set_option requires the option to already exist or else it won't set it.
			$this->set_option('useemoji', '', 1);
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
|| # CVS: $RCSfile$ - $Revision: 103823 $
|| ####################################################################
\*======================================================================*/
