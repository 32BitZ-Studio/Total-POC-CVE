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

class vB_Upgrade_554a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '554a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.4 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.4 Alpha 1';

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
		$this->show_message($this->phrase['version']['554a2']['update_imagetype']);
		$current = vB::getDatastore()->getOption('imagetype');

		if (empty($current))
		{
			vB::getDatastore()->setOption('imagetype', 'GD', true);
		}
	}

	public function step_2()
	{
		$this->show_message($this->phrase['version']['552a4']['updating_widgetinstance_adminconfig']);

		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:getWidgetInstanceAdminDetails', array());
		//this should already be changed to utf8.  If it isn't let's not change it to avoid
		//breaking the field -- especially the serialization.
		if (stripos($row['Collation'], 'utf8_') === 0)
		{
			$db->assertQuery('vBInstall:makeWidgetInstanceConfUtf8mb4');
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102693 $
|| ####################################################################
\*======================================================================*/
