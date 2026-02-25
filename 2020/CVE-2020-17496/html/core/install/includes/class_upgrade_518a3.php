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

class vB_Upgrade_518a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '518a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.8 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.8 Alpha 2';

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
	 * Turn the user mention notification option on for new registrations by default
	 */
	public function step_1()
	{
		// Add 268435456 (general_quote) to the default value for notification_options
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 1, 2),
			"ALTER TABLE " . TABLE_PREFIX . "user
			CHANGE notification_options notification_options INT UNSIGNED NOT NULL DEFAULT '1073741818'"
		);
	}

	/**
	 * Turn the quote notification option on for all current users by default
	 */
	public function step_2()
	{
		// Turn 536870912 on (general_quote) for all users
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'user', 2, 2),
			"UPDATE " . TABLE_PREFIX . "user
			SET notification_options = (notification_options | 536870912)"
		);
	}


	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'package', 1, 1));
		$db = vB::getDbAssertor();
		$package = $db->getRow('package', array('class' => 'vBCms'));
		if (!$package)
		{
			//we need this for the legacy but there is no longer a blog product.
			$result = $db->insert('package', array(
				'productid' => 'vbulletin',
				'class' => 'vBCms'
			));
		}
		else
		{
			if ($package['productid'] != 'vbulletin')
			{
				$db->update('package', array('productid' => 'vbulletin'), array('packageid' => $package['packageid']));
			}
		}
	}

	public function step_4()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', 1, 1));

		//legacy type information for the mobile API
		$db = vB::getDbAssertor();
		$contenttype = $db->getRow('vBForum:contenttype', array('class' => 'Article'));
		if(!$contenttype)
		{
			//we should have verified that this exits in step1
			$package = $db->getRow('package', array('class' => 'vBCms'));

			$db->insert('vBForum:contenttype', array(
				'class' => 'Article',
				'packageid' => $package['packageid'],
				'canplace' => '0',
				'cansearch' => '0',
				'cantag' => '1',
				'canattach' => '1',
				'isaggregator' => '0'
			));
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
