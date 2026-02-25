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

class vB_Upgrade_521a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '521a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.1 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.1 Alpha 1';

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
		$this->drop_table('reminder');
	}

	public function step_2()
	{
		$this->drop_table('pm');
	}

	public function step_3()
	{
		$this->drop_table('pmreceipt');
	}

	public function step_4()
	{
		$this->drop_table('pmtext');
	}

	public function step_5()
	{
		$this->drop_table('pmthrottle');
	}

	public function step_6()
	{
		$this->drop_table('nodevote');
		$this->long_next_step();
	}

	public function step_7()
	{
		$this->drop_table('searchcore');
		$this->long_next_step();
	}

	public function step_8()
	{
		$this->drop_table('searchcore_text');
		$this->long_next_step();
	}

	public function step_9()
	{
		$this->drop_table('searchgroup');
		$this->long_next_step();
	}

	public function step_10()
	{
		$this->drop_table('searchgroup_text');
	}

	public function step_11()
	{
		$this->skip_message();
	}

	public function step_12()
	{
		$this->skip_message();
	}

	public function step_13()
	{
		$this->skip_message();
	}

	public function step_14()
	{
		//just in case this still exists for some reason.  Step used to
		//created it after dropping
		$this->drop_table('access_temp');
	}

	public function step_15()
	{
		$this->skip_message();
	}

	public function step_16()
	{
		$this->skip_message();
	}

	public function step_17()
	{
		$this->skip_message();
	}

	public function step_18()
	{
		$this->skip_message();
	}

	public function step_19()
	{
		$this->skip_message();
	}

	public function step_20()
	{
		$this->drop_table('visitormessage');
	}

	public function step_21()
	{
		$this->drop_table('visitormessage_hash');
	}

	public function step_22()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'hook', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "hook MODIFY COLUMN template varchar(100) NOT NULL DEFAULT ''"
		);
	}

	/**
	 * Add useractivation.reset_attempts
	 */
	public function step_23()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'useractivation', 1, 2),
			'useractivation',
			'reset_attempts',
			'int',
			array('null' => false, 'default' => '0')
		);
	}

	/**
	 * Add useractivation.reset_locked_since
	 */
	public function step_24()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'useractivation', 2, 2),
			'useractivation',
			'reset_locked_since',
			'int',
			array('null' => false, 'default' => '0')
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
