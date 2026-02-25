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

class vB_Upgrade_510a9 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a9';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 9';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 8';

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
	* Handle changes to the password history table.
	*/
	function step_1()
	{
		if (!$this->field_exists('passwordhistory', 'token'))
		{
			//the previous password history is invalid since we started changing the salts.
			//we've fixed that but the existing records are pretty much useless
			$db = vB::getDbAssertor();
			$db->delete('passwordhistory', vB_dB_Query::CONDITION_ALL);

			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 1, 4),
				'passwordhistory',
				'token',
				'varchar',
				array('length' => 255, 'default' => '',)
			);

			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 2, 4),
				'passwordhistory',
				'scheme',
				'varchar',
				array('length' => 100, 'default' => '',)
			);

			$this->drop_field(
				sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 3, 4),
				'passwordhistory',
				'password'
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_2()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 4, 4),
			"ALTER TABLE " . TABLE_PREFIX . "passwordhistory MODIFY passworddate INT NOT NULL DEFAULT '0'"
		);
	}

	function step_3()
	{
		if (!$this->field_exists('user', 'token'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 5),
				'user',
				'token',
				'varchar',
				array('length' => 255, 'default' => '',)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_4()
	{
		if (!$this->field_exists('user', 'scheme'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 2, 5),
				'user',
				'scheme',
				'varchar',
				array('length' => 100, 'default' => '',)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_5()
	{
		if (!$this->field_exists('user', 'secret'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 3, 5),
				'user',
				'secret',
				'varchar',
				array('length' => 100, 'default' => '',)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_6()
	{
		if ($this->field_exists('user', 'password'))
		{
			$this->show_message($this->phrase['version']['510a9']['updating_password_schemes']);
			$assertor = vB::getDbAssertor();
			$assertor->update('user', array('scheme' => 'legacy'), vB_dB_Query::CONDITION_ALL);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_7()
	{
		if ($this->field_exists('user', 'password'))
		{
			$this->show_message($this->phrase['version']['510a9']['updating_password_tokens']);
			$assertor = vB::getDbAssertor();
			$assertor->assertQuery('vBInstall:updatePasswordTokenAndSecret');
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_8()
	{
		if ($this->field_exists('user', 'password'))
		{
			$this->drop_field(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 4, 5),
				'user',
				'password'
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_9()
	{
		if ($this->field_exists('user', 'salt'))
		{
			$this->drop_field(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 5, 5),
				'user',
				'salt'
			);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
