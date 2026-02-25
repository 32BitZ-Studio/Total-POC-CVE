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

class vB_Upgrade_523a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '523a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.3 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.3 Alpha 2';

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


	public function step_1($data = null)
	{
		//would like to do it as a single update query but can't do a
		//limit with a multi-table update and can't use a subquery in an
		//update involving the table you are updating.  So we do it the
		//hard/slow way
		$db = vB::getDbAssertor();
		$result = $db->assertQuery('vBInstall:selectShowOpenMismatch', array('limit' => 500));
		$nodes = array();
		foreach($result AS $row)
		{
			$nodes[] = $row['nodeid'];
		}

		if (empty($data['startat']))
		{
			$data['startat'] = 0;
			$this->show_message($this->phrase['version']['523a3']['fix_showopen']);
		}

		if (count($nodes))
		{
			$db->update('vBForum:node', array('showopen' => 0), array('nodeid' => $nodes));

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], count($nodes)));
			return array('startat' => $data['startat'] + $result);
		}
		else
		{
			$this->show_message($this->phrase['core']['process_done']);
			return;
		}
	}

	public function step_2()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitAdcriteria');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'adcriteria', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitAdcriteria');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'adcriteria', 191));
		}
	}

	public function step_3()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitBbcode');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'bbcode', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitBbcode');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'bbcode', 191));
		}
	}

	public function step_4()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitFaq');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'faq', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitFaq');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'faq', 191));
		}
	}

	public function step_5()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitNoticecriteria');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'noticecriteria', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitNoticecriteria');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'noticecriteria', 191));
		}
	}

	public function step_6()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitNotificationevent');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'notificationevent', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitNotificationevent');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'notificationevent', 191));
		}
	}

	public function step_7()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitPhrase');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'phrase', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitPhrase');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'phrase', 191));
		}
	}

	public function step_8()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitStylevar');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'stylevar', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitStylevar');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'stylevar', 191));
		}
	}

	public function step_9()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitUserstylevar');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'userstylevar', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitUserstylevar');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'userstylevar', 191));
		}
	}

	public function step_10()
	{
		$db = vB::getDbAssertor();
		$row = $db->getRow('vBInstall:checkIndexLimitStylevardfn');
		if (!$row)
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'stylevardfn', 1, 1));
			$db->assertQuery('vBInstall:alterIndexLimitStylevardfn');
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['523a3']['data_too_long'], 'stylevardfn', 191));
		}
	}

	public function step_11()
	{
		$this->drop_table('profileblockprivacy');
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
