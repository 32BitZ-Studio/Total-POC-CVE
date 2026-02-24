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

class vB_Upgrade_533a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '533a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.3 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.3 Alpha 2';

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

	// Add trending table.
	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'trending'),
			"
				CREATE TABLE " . TABLE_PREFIX . "trending (
					nodeid INT UNSIGNED NOT NULL PRIMARY KEY,
					weight INT UNSIGNED NOT NULL,
					KEY weight (weight)
				) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}

	public function step_2()
	{
		$this->add_cronjob(
			array(
				'varname'  => 'trending',
				'nextrun'  => 0,
				'weekday'  => -1,
				'day'      => -1,
				'hour'     => -1,
				'minute'   => serialize(array(50)),
				'filename' => './includes/cron/trending.php',
				'loglevel' => 1,
				'volatile' => 1,
				'product'  => 'vbulletin'
			)
		);
	}

	// Add fcmessage_offload table.
	public function step_3()
	{
		if (!$this->tableExists('fcmessage_offload'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'fcmessage_offload'),
				"
					CREATE TABLE " . TABLE_PREFIX . "fcmessage_offload (
						recipientids                VARCHAR(2048) NOT NULL DEFAULT '',
						message_data                VARCHAR(2048) NOT NULL DEFAULT '',
						hash                        CHAR(32) NOT NULL DEFAULT '',
						removeafter                 INT UNSIGNED NOT NULL DEFAULT '0',
						UNIQUE KEY guid  (hash)
					) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
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
