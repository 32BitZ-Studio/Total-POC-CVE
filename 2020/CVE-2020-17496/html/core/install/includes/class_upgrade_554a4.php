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

class vB_Upgrade_554a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '554a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.4 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.4 Alpha 3';

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
		$this->drop_table('picturecomment');
	}

	public function step_2()
	{
		$this->drop_table('picturecomment_hash');
	}

	//several fields were set in a prior upgrade step, but not changed for new installs
	//we need to repeat this for sites installed in the interim.
	public function step_3()
	{
		$this->updateIPField('node', 'ipaddress');
	}

	public function step_4()
	{
		$this->updateIPField('session', 'host');
	}

	public function step_5()
	{
		$this->updateIPField('apiclient', 'initialipaddress');
	}

	public function step_6()
	{
		$this->updateIPField('apilog', 'ipaddress');
	}

	public function step_7()
	{
		$this->updateIPField('searchlog', 'ipaddress');
	}

	public function step_8()
	{
		$this->updateIPField('userchangelog', 'ipaddress');
	}

	public function step_9()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'userchangelog'));
		$db = vB::getDbAssertor();
		$db->assertQuery('vBInstall:updateUserchangeLogIp', array());
	}

	//Maybe this should be a protected function on the parent class.  However I'm hoping it
	//won't be a thing over multiple versions and I don't really want to clutter the parent
	//class with a function that's going to be of limited use. On the other hand I don't
	//want to case and paste a dozen versions of this.
	private function updateIPField($table, $field)
	{
		$this->alter_field(
			sprintf($this->phrase['core']['altering_x_table'], $table, 1, 1),
			$table,
			$field,
			'varchar',
			array(
				'length' => 45,
				'attributes' => self::FIELD_DEFAULTS
			)
		);
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102693 $
|| ####################################################################
\*======================================================================*/
