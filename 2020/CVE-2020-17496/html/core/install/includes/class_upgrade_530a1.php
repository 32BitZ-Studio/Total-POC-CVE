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

class vB_Upgrade_530a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '530a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.0 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.7 Alpha 4';

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
	 * Add ishiddeninput column to widgetdefinition
	 */
	public function step_1()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'widgetdefinition', 1, 1),
			'widgetdefinition',
			'ishiddeninput',
			'tinyint',
			array('length' => 4, 'null' => false, 'default' => '0')
		);
	}

	public function step_2()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'userloginmfa'),
			"CREATE TABLE " . TABLE_PREFIX . "userloginmfa (
				userid INT UNSIGNED NOT NULL,
				enabled TINYINT NOT NULL,
				secret VARCHAR(255) NOT NULL,
				dateline INT NOT NULL,
				PRIMARY KEY (userid)
			) ENGINE = " . $this->hightrafficengine . "
			",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}

	public function step_3()
	{
		// hard coded in vbulletin-routes.xml
		$assertor = vB::getDbAssertor();
		$row = $assertor->getRow('routenew', array('name' => 'settings'));

		if (strpos($row['regex'], '|security') === false)
		{
			$regex = str_replace('|notifications', '|notifications|security', $row['regex']);
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
			$assertor->assertQuery('routenew',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array('routeid' => $row['routeid']),
					'regex' => $regex
				)
			);
		}
		else
		{
			// we're okay.
			$this->skip_message();
			return;
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
