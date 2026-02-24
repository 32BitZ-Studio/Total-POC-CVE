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

class vB_Upgrade_511a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '511a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.1 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.1 Alpha 4';

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
	 * Make sure the bitfields are up-to-date (for next step)
	 */
	public function step_1()
	{
		vB_Upgrade::createAdminSession();
		require_once(DIR . '/includes/class_bitfield_builder.php');
		vB_Bitfield_Builder::save();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'permission'));
	}

	/**
	 * Ensure that the new 'cangetimgattachment' setting matches the
	 * value of 'cangetattachment' for all channels.
	 */
	public function step_2()
	{
		// Get the bitfields
		$forumpermissions = vB::getDatastore()->getValue('bf_ugp_forumpermissions');
		$forumpermissions2 = vB::getDatastore()->getValue('bf_ugp_forumpermissions2');

		// Set the new 'cangetimageattachment' permission.
		// Everyone who has the 'cangetattachment' permission gets this
		// new one when upgrading.
		$this->run_query(sprintf($this->phrase['vbphrase']['update_table'], 'permission'), "
			UPDATE " . TABLE_PREFIX . "permission
			SET forumpermissions2 = forumpermissions2 | " . intval($forumpermissions2['cangetimgattachment']) . "
			WHERE forumpermissions & " . intval($forumpermissions['cangetattachment']) . "
		");
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
