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

class vB_Upgrade_531a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '531a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.1 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.1 Alpha 2';

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
	#############################################################
	Steps 1 to 4 replicate field changes made in vB3 & vB4
	to store IPv6 Addresses, they are replicated here to keep
	the	tables in sync when upgrading the database to vB5.
	#############################################################
	*/

	/**
	 * Replicates 4.2.5 Beta 2 Step 1
	 * Change host (ip address) field to varchar 45 for IPv6
	 */
	public function step_1()
	{
		if ($this->field_exists('session', 'host'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'session', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "session CHANGE host host VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Replicates 4.2.5 Beta 2 Step 3
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_2()
	{
		if ($this->field_exists('apiclient', 'initialipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'apiclient', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "apiclient CHANGE initialipaddress initialipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Replicates 4.2.5 Beta 2 Step 4
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_3()
	{
		if ($this->field_exists('apilog', 'ipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'apilog', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "apilog CHANGE ipaddress ipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Replicates 4.2.5 Beta 2 Step 5
	 * Change ip address field to varchar 45 for IPv6
	 */
	public function step_4()
	{
		if ($this->field_exists('searchlog', 'ipaddress'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'searchlog', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "searchlog CHANGE ipaddress ipaddress VARCHAR(45) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_5()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
		$assertor->assertQuery('routenew',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => 'vbulletin-4ecbdacd6aac05.50909987'),
				'regex' => 'node/(?P<nodeid>[0-9]+)(?:/contentpage(?P<contentpagenum>[0-9]+))?(?:/page(?P<pagenum>[0-9]+))?',
				'arguments' => 'a:3:{s:6:"nodeid";s:7:"$nodeid";s:7:"pagenum";s:8:"$pagenum";s:14:"contentpagenum";s:15:"$contentpagenum";}',
			)
		);
	}

	public function step_6()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));

		$route = $assertor->getRow('routenew', array('name' => 'settings'));
		if($route)
		{
			$assertor->assertQuery('routenew',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array('name' => 'settings'),
					'regex' => $route['prefix'] . '(/(?P<tab>profile|account|privacy|notifications|security|subscriptions))?',
				)
			);
		}
	}

	public function step_7()
	{
		//unescaping the data multiple times will be bad and there is no
		//good way to detect that.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		$assertor = vB::getDbAssertor();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'));

		// Get site's current navbar data
		$site = $assertor->getRow('vBForum:site', array('siteid' => 1));

		$headernavbar = @unserialize($site['headernavbar']);
		foreach ((array)$headernavbar AS $key => $currentitem)
		{
			$headernavbar[$key]['url'] = vB_String::unHtmlSpecialChars($headernavbar[$key]['url']);
			// We have the tab, check for subnavs of the tab
			foreach ((array)$currentitem['subnav'] AS $subkey => $currentsubitem)
			{
				$headernavbar[$key]['subnav'][$subkey]['url'] = vB_String::unHtmlSpecialChars($headernavbar[$key]['subnav'][$subkey]['url']);
			}
		}

		$assertor->update('vBForum:site',
			array(
				'headernavbar' => serialize($headernavbar),
			),
			array(
				'siteid' => 1,
			)
		);
	}

	public function step_8()
	{
		//unescaping the data multiple times will be bad and there is no
		//good way to detect that.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		$assertor = vB::getDbAssertor();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'));

		// Get site's current navbar data
		$site = $assertor->getRow('vBForum:site', array('siteid' => 1));

		$footernavbar = @unserialize($site['footernavbar']);
		foreach ((array)$footernavbar AS $key => $currentitem)
		{
			$footernavbar[$key]['url'] = vB_String::unHtmlSpecialChars($footernavbar[$key]['url']);
		}

		$assertor->update('vBForum:site',
			array(
				'footernavbar' => serialize($footernavbar),
			),
			array(
				'siteid' => 1,
			)
		);
	}

	public function step_9()
	{
		// Place holder to allow iRan() to work properly, as the last step gets recorded as step '0' in the upgrade log for CLI upgrade.
		$this->skip_message();
		return;
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
