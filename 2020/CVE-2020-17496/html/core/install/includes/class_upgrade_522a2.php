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

class vB_Upgrade_522a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '522a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.2 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.2 Alpha 1';

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
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'channel', 1, 1));

		$forumoptionbits = vB::getDatastore()->getValue('bf_misc_forumoptions');
		$db = vB::getDbAssertor();

		//if its not a category it should allow threads
		$rows = $db->select('vBForum:channel',
			array(
				'category' => 0,
				array('field' => 'options', 'value' => $forumoptionbits['cancontainthreads'] , 'operator' => vB_dB_Query::OPERATOR_NAND)
			),
			array('nodeid', 'options')
		);

		foreach($rows AS $row)
		{
			$db->update('vBForum:channel',
				array('options' => $row['options'] | $forumoptionbits['cancontainthreads']),
				array('nodeid' => $row['nodeid'])
			);
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
