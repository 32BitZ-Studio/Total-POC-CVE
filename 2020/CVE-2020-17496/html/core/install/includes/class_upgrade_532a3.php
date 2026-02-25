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

class vB_Upgrade_532a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '532a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.2 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.2 Alpha 2';

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


	// Add apiclient_devicetoken table.
	public function step_1()
	{
		if (!$this->tableExists('apiclient_devicetoken'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'apiclient_devicetoken'),
				"
					CREATE TABLE " . TABLE_PREFIX . "apiclient_devicetoken (
						apiclientid INT UNSIGNED NOT NULL DEFAULT '0',
						userid INT UNSIGNED NOT NULL DEFAULT '0',
						devicetoken VARCHAR(191) NOT NULL DEFAULT '',
						PRIMARY KEY  (apiclientid),
						INDEX (userid)
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

	// Add fcmessage table.
	public function step_2()
	{
		if (!$this->tableExists('fcmessage'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'fcmessage'),
				"
					CREATE TABLE " . TABLE_PREFIX . "fcmessage (
						messageid                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
						message_data                VARCHAR(2048) NOT NULL DEFAULT '',
						message_hash                CHAR(32) NULL DEFAULT NULL,
						PRIMARY KEY (messageid),
						UNIQUE KEY message_hash (message_hash)
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

	// Add fcmessage_queue table.
	public function step_3()
	{
		if (!$this->tableExists('fcmessage_queue'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'fcmessage_queue'),
				"
					CREATE TABLE " . TABLE_PREFIX . "fcmessage_queue (
						recipient_apiclientid       INT UNSIGNED NOT NULL DEFAULT '0',
						messageid                   INT UNSIGNED NOT NULL DEFAULT '0',
						retryafter                  INT UNSIGNED NOT NULL DEFAULT '0',
						retryafterheader            INT UNSIGNED NOT NULL DEFAULT '0',
						retries						INT UNSIGNED NOT NULL DEFAULT '0',
						status                      ENUM('ready', 'processing') NOT NULL DEFAULT 'ready',
						UNIQUE KEY guid  (recipient_apiclientid, messageid),
						KEY id_status (messageid, status)
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

	// add fcmqueue cron
	public function step_4()
	{
		$this->add_cronjob(
			array(
				'varname'  => 'fcmqueue',
				'nextrun'  => 0,
				'weekday'  => -1,
				'day'      => -1,
				'hour'     => -1,
				'minute'   => 'a:2:{i:0;i:0;i:1;i:30;}',
				'filename' => './includes/cron/fcmqueue.php',
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
