<?php
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ©2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| #        www.vbulletin.com | www.vbulletin.com/license.html        # ||
|| #################################################################### ||
\*======================================================================*/

class vB_Upgrade_424b3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '424b3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '4.2.4 Beta 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '4.2.4 Beta 2';

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
	 * Change moderator id field from small int to int
	 *
	 * Step 1 Moved, it is now 5.2.3 Alpha 5, Step 1
	 * (Kept, but skipped, to avoid renumbering steps).
	 */
	public function step_1()
	{
		$this->skip_message();
	}

	/**
	 * Change [passwordhistory] passworddate field default for MySQL 5.7
	 */
	public function step_2()
	{
		if ($this->field_exists('passwordhistory', 'passworddate'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 1, 2),
				"ALTER TABLE " . TABLE_PREFIX . "passwordhistory CHANGE COLUMN passworddate passworddate DATE NOT NULL DEFAULT '1000-01-01'"
			);

			// There shouldn't be any to change, but lets play safe.
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'passwordhistory', 2, 2),
				"UPDATE " . TABLE_PREFIX . "passwordhistory SET passworddate = '1000-01-01' WHERE passworddate = '0000-00-00'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change [user] passworddate field default for MySQL 5.7
	 */
	public function step_3()
	{
		if ($this->field_exists('user', 'passworddate'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 4),
				"ALTER TABLE " . TABLE_PREFIX . "user CHANGE COLUMN passworddate passworddate DATE NOT NULL DEFAULT '1000-01-01'"
			);

			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 2, 4),
				"UPDATE " . TABLE_PREFIX . "user SET passworddate = '1000-01-01' WHERE passworddate = '0000-00-00'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Change [user] birthday_search field default for MySQL 5.7
	 */
	public function step_4()
	{
		if ($this->field_exists('user', 'birthday_search'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 3, 4),
				"ALTER TABLE " . TABLE_PREFIX . "user CHANGE COLUMN birthday_search birthday_search DATE NOT NULL DEFAULT '1000-01-01'"
			);

			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'user', 4, 4),
				"UPDATE " . TABLE_PREFIX . "user SET birthday_search = '1000-01-01' WHERE birthday_search = '0000-00-00'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	Step 5
	Delete old Panjo & Postrelease products.
	Not required as vB5 already deleted all the old products.
	*/
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org : $Revision: 101013 $
|| # $Date: 2019-03-15 10:31:08 -0700 (Fri, 15 Mar 2019) $
|| ####################################################################
\*======================================================================*/
