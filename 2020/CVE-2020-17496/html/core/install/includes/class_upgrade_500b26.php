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

class vB_Upgrade_500b26 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '500b26';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.0 Beta 26';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.0 Beta 25';

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
	
	// Fixing category field and removing conversation routes for root channels
	public function step_1()
	{
		//some upgrades may not have gotten this column from a step added to 500a1 after the release of that alpha version
		if (!$this->field_exists('channel', 'product'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'channel', 1, 1),
				'channel',
				'product',
				'VARCHAR',
				array(
					'length' => 25,
					'default' => 'vbulletin',
				)
			);
			$this->execute();
		}

		$this->show_message(sprintf($this->phrase['version']['500b26']['fixing_category_channels']));
		
		$channels = vB::getDbAssertor()->assertQuery('vBInstall:getRootChannels', array('rootGuids' => array(
			vB_Channel::MAIN_CHANNEL,
			vB_Channel::DEFAULT_FORUM_PARENT,
			vB_Channel::DEFAULT_BLOG_PARENT,
			vB_Channel::DEFAULT_SOCIALGROUP_PARENT,
			vB_Channel::DEFAULT_CHANNEL_PARENT,
		)));

		$library = vB_Library::instance('content_channel');
		foreach ($channels AS $channel)
		{
			if ($channel['category'] == 0 OR !empty($channel['routeid']))
			{
				// Since we are fixing some inconsistencies, we need to force this method to rebuild routes
				$library->switchForumCategory(true, $channel['nodeid'], true);
			}
		}
	}

	/**
	 * Add the nodehash table 
	 */
	public function step_2()
	{
		if (!$this->tableExists('nodehash'))
		{
			$this->run_query(
					sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'nodehash'),
					" 
					CREATE TABLE " . TABLE_PREFIX . "nodehash (
						userid INT UNSIGNED NOT NULL,
						nodeid INT UNSIGNED NOT NULL,
						dupehash char(32) NOT NULL,
						dateline INT UNSIGNED NOT NULL,
						KEY (userid, dupehash),
						KEY (dateline)
					) 
					ENGINE = " . $this->hightrafficengine,
					self::MYSQL_ERROR_TABLE_EXISTS
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
