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

class vB_Upgrade_550a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '550a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.0 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.6 Alpha 2';

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

	// Update orphan `reportnodeid` references for reports pointing to deleted nodes
	public function step_1()
	{
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'report', 1, 1));

		$db = vB::getDbAssertor();
		$db->assertQuery('vBInstall:updateOrphanReports');

		$this->long_next_step();
	}

	// Remove unused `text`.`reportnodeid`
	public function step_2()
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();

		if ($this->field_exists('text', 'reportnodeid'))
	{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'text', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "text
					DROP COLUMN reportnodeid"
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