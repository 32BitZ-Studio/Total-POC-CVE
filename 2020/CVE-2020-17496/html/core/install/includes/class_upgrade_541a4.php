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

class vB_Upgrade_541a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '541a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.1 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.1 Alpha 3';

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

	/*
		Steps 1-6:
		For alpha/beta testers, we have to resize the `additional_params` columns in userauth & sessionauth tables,
		relabel `loginlibrary_id` columns to `loginlibraryid`, and relabel the `loginlibraries` table to `loginlibrary`.
		Simplest thing to do is to just drop all the tables and recreate them at this point.
		This means they'll lose existing user links, but it'll only affect the first upgrade.
	 */
	public function step_1()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		$this->drop_table('sessionauth');
	}


	public function step_2()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		$this->drop_table('userauth');
	}

	public function step_3()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		// plural `loginlibraries` is intentional.
		// Before alpha 4, `loginlibrary` table was called `loginlibraries`, and
		// we're relabeling it from a3 -a4 along with some other table modifications
		// via just dropping the old table & readding the table with the new name.
		$this->drop_table('loginlibraries');
	}


	// Add userauth table.
	public function step_4()
	{
		if (!$this->tableExists('userauth'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'userauth'),
				"
					CREATE TABLE `" . TABLE_PREFIX . "userauth` (
						`userid`               INT UNSIGNED NOT NULL DEFAULT '0',
						`loginlibraryid`      INT UNSIGNED NOT NULL DEFAULT '0',
						`external_userid`      VARCHAR(191) NOT NULL DEFAULT '',
						`token`                VARCHAR(191) NOT NULL DEFAULT '',
						`token_secret`         VARCHAR(191) NOT NULL DEFAULT '',
						`additional_params`    VARCHAR(2048) NOT NULL DEFAULT '',

						PRIMARY KEY `user_platform_constraint`  (`userid`, `loginlibraryid`),
						UNIQUE KEY `platform_extuser_constraint`  (`loginlibraryid`, `external_userid`),
						KEY         `token_lookup`              (`userid`, `loginlibraryid`, `token`)
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

	// Add loginlibrary table.
	public function step_5()
	{
		if (!$this->tableExists('loginlibrary'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'loginlibrary'),
				"
					CREATE TABLE `" . TABLE_PREFIX . "loginlibrary` (
						`loginlibraryid`      INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
						`productid`            VARCHAR(25) NOT NULL,
						`class`                VARCHAR(64) NOT NULL,

						UNIQUE KEY (`productid`)
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

	// Add sessionauth table.
	public function step_6()
	{
		if (!$this->tableExists('sessionauth'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'sessionauth'),
				"
					CREATE TABLE `" . TABLE_PREFIX . "sessionauth` (
						`sessionhash`          CHAR(32) NOT NULL DEFAULT '',
						`loginlibraryid`      INT UNSIGNED NOT NULL DEFAULT '0',
						`token`                VARCHAR(191) NOT NULL DEFAULT '',
						`token_secret`         VARCHAR(191) NOT NULL DEFAULT '',
						`additional_params`    VARCHAR(2048) NOT NULL DEFAULT '',
						`expires`              INT UNSIGNED NOT NULL,

						PRIMARY KEY `session_platform_constraint`  (`sessionhash`, `loginlibraryid`),
						INDEX (`expires`)
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

	// Reinstall twitterlogin package to fix the externallogin settinggroup displayorder and to pick up
	// any other product XML changes in alpha/beta versions
	public function step_7()
	{
		// Moved to 541b1 step_1()
		$this->skip_message();

		$this->long_next_step();
	}

	public function step_8($data)
	{
		if(empty($data['startat']))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}

		$callback = function($startat, $nextid)
		{
			$types = vB_Types::instance();

			$channeltypeid = $types->getContentTypeID('vBForum_Channel');

			$db = vB::getDbAssertor();
			//the comment starter needs to run first because it depends on the fact that
			//replies aren't fixed yet
			$result = $db->assertQuery('vBInstall:fixReplyCommentStarter', array(
				'channeltypeid' => $channeltypeid,
				'nodetypeids' => $nodetypeids,
				'startat' => $startat,
				'nextid' => $nextid,
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat, $nextid), true);
		};

		$result = $this->updateByIdWalk($data,	20000, 'vBInstall:getMaxNodeid', 'vBForum:node', 'nodeid', $callback);
		return $result;
	}

	public function step_9()
	{
		$this->alter_field(
			sprintf($this->phrase['core']['altering_x_table'], 'permission', 1, 1),
			'permission',
			'edit_time',
			'float',
			self::FIELD_DEFAULTS
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
