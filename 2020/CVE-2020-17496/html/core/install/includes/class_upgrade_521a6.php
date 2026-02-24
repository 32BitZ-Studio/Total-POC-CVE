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

class vB_Upgrade_521a6 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '521a6';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.1 Alpha 6';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.1 Alpha 5';

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
		//this isn't 100% required because the system will init the admin session
		//for the first step as a side effect, but we should be specific about it
		//in case this changes.  It's also needed for the unit testing.
		vB_Upgrade::createAdminSession();
		$this->show_message($this->phrase['version']['521a6']['rebuild_usergroup_permissions']);
		vB::getUserContext()->rebuildGroupAccess();
	}

	/*
	 * Allow usermentions bbcode by default. Run once only.
	 */
	public function step_2()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}
		$this->show_message($this->phrase['version']['521a6']['enabling_usermention_bbcode']);

		$assertor = vB::getDbAssertor();
		$row = $assertor->getRow('setting', array('varname' => 'allowedbbcodes'));
		$row['value'] += vB_Api_Bbcode::ALLOW_BBCODE_USER;
		$assertor->update('setting',
			array(
				'value'     => $row['value'],
			),	// values
			array('varname' => $row['varname']) // condition
		);
	}



	public function step_3()
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
