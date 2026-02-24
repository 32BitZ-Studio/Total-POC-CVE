<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

class vB_Upgrade_500a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '500a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.0 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.0 Alpha 2';

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

	function step_1()
	{
		$this->skip_message();
	}

	function step_2()
	{
		$this->skip_message();
	}

	function step_3()
	{
		$this->skip_message();
	}

	/***	adding relationship 'follow' to userlist table*/
	function step_4()
	{
		$this->run_query(sprintf($this->phrase['core']['altering_x_table'], 'userlist', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "userlist CHANGE type type ENUM('buddy', 'ignore', 'follow') NOT NULL DEFAULT 'buddy';");
	}

	/** Add the route for the profile pages**/
	function step_5()
	{
		$this->skip_message();
	}

	/***	Setting default adminConfig for activity stream widget */
	function step_6()
	{
		$this->run_query(
		sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'widgetinstance'),
		"
		UPDATE " . TABLE_PREFIX . "widgetinstance
			SET adminconfig = 'a:4:{s:11:\"filter_sort\";s:11:\"sort_recent\";s:11:\"filter_time\";s:8:\"time_all\";s:11:\"filter_show\";s:8:\"show_all\";s:20:\"filter_conversations\";s:1:\"1\";}'
			WHERE widgetid = (SELECT widgetid FROM " . TABLE_PREFIX . "widget WHERE title = 'Activity Stream') AND adminconfig = ''
			"
		);
	}

	/**
	 * Add default header navbar items for Blogs
	 */
	function step_7()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'),
			"
				UPDATE " . TABLE_PREFIX . "site
				SET headernavbar = 'a:1:{i:0;a:2:{s:5:\"title\";s:5:\"Blogs\";s:3:\"url\";s:1:\"#\";}}'
				WHERE
					siteid = 1
						AND
					headernavbar = ''
			"
		);
	}

	function step_8()
	{
		$this->skip_message();
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
