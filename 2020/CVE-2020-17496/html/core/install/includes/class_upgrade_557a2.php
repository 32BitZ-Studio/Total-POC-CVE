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

class vB_Upgrade_557a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '557a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION = '5.5.7 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.7 Alpha 1';

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

	// create the eventhighlight table
	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'eventhighlight'),
			"
				CREATE TABLE " . TABLE_PREFIX . "eventhighlight (
					eventhighlightid INT UNSIGNED NOT NULL AUTO_INCREMENT,
					backgroundcolor VARCHAR(50) NOT NULL DEFAULT '',
					textcolor VARCHAR(50) NOT NULL DEFAULT '',
					displayorder INT UNSIGNED NOT NULL DEFAULT '0',
					denybydefault TINYINT UNSIGNED NOT NULL DEFAULT '1',
					PRIMARY KEY (eventhighlightid),
					INDEX displayorder (displayorder)
				) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}

	// create the eventhighlightpermission table
	public function step_2()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'eventhighlightpermission'),
			"
				CREATE TABLE " . TABLE_PREFIX . "eventhighlightpermission (
					eventhighlightid INT UNSIGNED NOT NULL DEFAULT '0',
					usergroupid INT UNSIGNED NOT NULL DEFAULT '0',
					UNIQUE INDEX eventhighlightid (eventhighlightid, usergroupid)
				) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}

	// add 'eventhighlightid' column to the event table
	public function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'event', 1, 1),
			'event',
			'eventhighlightid',
			'INT',
			array(
				'attributes' => 'UNSIGNED',
				'null'       => false,
				'default'    => '0',
				'extra'      => '',
			)
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| ####################################################################
\*======================================================================*/