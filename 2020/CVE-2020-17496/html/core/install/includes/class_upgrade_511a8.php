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

class vB_Upgrade_511a8 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '511a8';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.1 Alpha 8';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.1 Alpha 7';

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
	 *	Set the bitfield forumpermissions.canattachmentcss (restored from vB4) for
	 *	admin & super moderator usergroups, only for upgrades from vB5
	 *	(this step was copied & modified from 511a5 step_1 & step_2)
	 */
	public function step_1()
	{
		// only run this once.
		$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '511a8', 'step' => 1));
		if ($log->valid())
		{
			$this->skip_message();
			return;
		}

		// Set the restored 'canattachmentcss' permission for vB5 to vB5.1.1 upgrades.
		// Since it occupies the same bitfield as in vB4, this shouldn't be done for upgrades from vB4
		// I'm making an assumption here that if this forum ran the 500a1 upgrade, then it upgraded
		// from vB4 (since a new vB5 install wouldn't have had to run the 500 upgrade steps). Of course,
		// the user could've manually ran the 500 steps for fun, but in that case they can manually set
		// the permissions :)
		$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '500a1'));
		if ($log->valid())
		{
			$this->skip_message();
			return;
		}

		// First make sure that the bitfields are up to date
		vB_Upgrade::createAdminSession();
		require_once(DIR . '/includes/class_bitfield_builder.php');
		$saveSuccess  = vB_Bitfield_Builder::save();

		// Get the bitfields
		$forumpermissions = vB::getDatastore()->getValue('bf_ugp_forumpermissions');

		// grab groups 5 & 6 (Administrators & Super Mods)
		$groupApi = vB_Api::instanceInternal('usergroup');
		$admins = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::ADMINISTRATOR);
		$admins = $admins['usergroupid'];
		$supermods = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::SUPER_MODERATOR);
		$supermods = $supermods['usergroupid'];

		// These groups should get the permission set by default.
		$this->run_query(sprintf($this->phrase['vbphrase']['update_table'], 'permission'), "
			UPDATE " . TABLE_PREFIX . "permission
			SET forumpermissions = (forumpermissions | " . intval($forumpermissions['canattachmentcss']) . ")
			WHERE groupid IN ($admins, $supermods)
		");
	}

	/*
	 *	Step 2: Currently unused, it's here because previous step uses a upgradelog check,
	 *		and we don't want it to be the last step to avoid confusion in case steps are
	 *		added or removed.
	 */
	public function step_2($data = NULL)
	{
		// There's a bug/intended-feature where the last step of a script is always recorded with step = 0.
		// ANY step that uses an upgradelog check to run only once either should NOT be the last step in
		// the script OR must remember to check for step = 0 instead of its real step and be careful about
		// maintenance when another step is added afterwards. To reduce maintenance, let's just keep an empty
		// step at the end.
		$this->skip_message();
		/*
						 __		   					 ___________  ________
					___./ /     _.---.				|		  	| \_   __/
					\__  (__..-`       \			|	^		|  /  /
					   \            O   |			|____		|_/	 /
						`..__.   ,=====/			|_______________/
						  `._/_.'_____/

		 * IF ANOTHER STEP IS ADDED, PLEASE REPLACE THIS ONE. HOWEVER, ADD A NOTE ON THAT STEP THAT
		 * IF THE STEP IS TO BE REMOVED, A BLANK ONE SHOULD BE INSERTED AGAIN.
		 */
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
