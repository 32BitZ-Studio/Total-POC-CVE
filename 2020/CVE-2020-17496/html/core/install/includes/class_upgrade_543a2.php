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

class vB_Upgrade_543a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '543a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.3 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.3 Alpha 1';

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


	// Add ipaddressinfo table.
	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'ipaddressinfo'),
			"
				CREATE TABLE " . TABLE_PREFIX . "ipaddressinfo (
					`ipaddressinfoid` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
					`ipaddress` VARCHAR(45) NOT NULL DEFAULT '',
					`eustatus` TINYINT NOT NULL DEFAULT 0,
					`created` INT UNSIGNED NOT NULL,
					PRIMARY KEY (`ipaddressinfoid`),
					UNIQUE KEY (`ipaddress`),
					KEY (`created`)
				) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);

		$this->long_next_step();
	}


	// add `user`.`privacyconsent` column
	function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 2),
			'user',
			'privacyconsent',
			'tinyint',
			array('attributes' => 'SIGNED', 'null' => false, 'default' => '0')
		);
		$this->long_next_step();
	}

	// add `user`.`privacyconsentupdated` column
	function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 2, 2),
			'user',
			'privacyconsentupdated',
			'int',
			array('attributes' => 'UNSIGNED', 'null' => false, 'default' => '0')
		);
		$this->long_next_step();
	}

	// add `privacy_updated` index for `user` table
	function step_4()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'privacy_updated', TABLE_PREFIX . 'user'),
			'user',
			'privacy_updated',
			array('privacyconsent', 'privacyconsentupdated')
		);
	}

	public function step_5()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 1),
			'user',
			'eustatus',
			'TINYINT',
			array('null' => false, 'default' => '0')
		);
	}

	// add privacyconsent table
	public function step_6()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'privacyconsent'),
			"
				CREATE TABLE " . TABLE_PREFIX . "privacyconsent (
					privacyconsentid INT UNSIGNED NOT NULL AUTO_INCREMENT,
					ipaddress VARCHAR(45) NOT NULL DEFAULT '',
					created INT UNSIGNED NOT NULL DEFAULT '0',
					consent TINYINT UNSIGNED NOT NULL DEFAULT '0',
					PRIMARY KEY (privacyconsentid),
					KEY (ipaddress),
					KEY (created)
				) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}
	// add privacy consent withdrawn user delete cron
	public function step_7()
	{
		$this->add_cronjob(
			array(
				'varname'  => 'privacyconsentremoveuser',
				'nextrun'  => 0,
				'weekday'  => -1,
				'day'      => -1,
				'hour'     => -1,
				'minute'   => serialize(array(15)),
				'filename' => './includes/cron/privacyconsentremoveuser.php',
				'loglevel' => 1,
				'volatile' => 1,
				'product'  => 'vbulletin'
			)
		);
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
