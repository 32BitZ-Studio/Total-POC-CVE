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

class vB_Upgrade_511a9 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '511a9';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.1 Alpha 9';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.1 Alpha 8';

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

	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'rssfeed', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "rssfeed MODIFY COLUMN nodeid INT UNSIGNED NOT NULL DEFAULT '0'"
		);
	}

	public function step_2()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'moderator', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "moderator MODIFY COLUMN nodeid INT NOT NULL DEFAULT '0'"
		);
	}

	/**
	 * Add the usergroup.forumpermissions2 column
	 */
	public function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'usergroup', 1, 1),
			'usergroup',
			'forumpermissions2',
			'int',
			self::FIELD_DEFAULTS
		);
	}

	/**
	 * Make sure the bitfields are up-to-date (for next step)
	 */
	public function step_4()
	{
		vB_Upgrade::createAdminSession();
		require_once(DIR . '/includes/class_bitfield_builder.php');
		vB_Bitfield_Builder::save();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'usergroup'));
	}

	/**
	 * Ensure that the new 'cangetimgattachment' setting matches the
	 * value of 'cangetattachment' for all usergroups (this was done
	 * for permission records in the 511a5 upgrade)
	 */
	public function step_5()
	{
		// Get the bitfields
		$forumpermissions = vB::getDatastore()->getValue('bf_ugp_forumpermissions');
		$forumpermissions2 = vB::getDatastore()->getValue('bf_ugp_forumpermissions2');

		// Set the new 'cangetimageattachment' permission.
		// Everyone who has the 'cangetattachment' permission gets this
		// new one when upgrading.
		$this->run_query(sprintf($this->phrase['vbphrase']['update_table'], 'usergroup'), "
			UPDATE " . TABLE_PREFIX . "usergroup
			SET forumpermissions2 = forumpermissions2 | " . intval($forumpermissions2['cangetimgattachment']) . "
			WHERE forumpermissions & " . intval($forumpermissions['cangetattachment']) . "
		");
	}

	public function step_6()
	{
		$db = vB::getDbAssertor();

		$this->show_message(sprintf($this->phrase['core']['update_table'], 'usergroup'));

		$groupinfo = $this->getDefaultGroupPerms();
		foreach($groupinfo AS $id => $perms)
		{
			//so the defaults in the bitfields are messed up for groups that aren't the
			//original eight that we've always had (not only do we not have them set we
			//can't rely on the usergroupid to be same across installs.
			//The added groups should already have the correct privs so skip them
			if($id > 8)
			{
				continue;
			}

			$db->update('usergroup', array('forumpermissions2' => $perms['forumpermissions2']), array('usergroupid' => $id));
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101486 $
|| #######################################################################
\*=========================================================================*/
