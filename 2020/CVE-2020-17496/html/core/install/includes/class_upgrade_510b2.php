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

class vB_Upgrade_510b2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510b2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Beta 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Beta 1';

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
	 *	Step 1:	Remove "canremoveposts" (physical delete) moderator permission from channel permissions
	 *		for CHANNEL_MODERATORS
	 */
	public function step_1($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		// we should only run this once. 
		$check = $assertor->assertQuery('vBInstall:upgradelog', array('script' => $this->SHORT_VERSION, 'step' => '1'));

		if ($check->valid())
		{
			$this->skip_message();
		}
		else
		{
			$this->show_message($this->phrase['version'][$this->SHORT_VERSION]['updating_channelmod_permissions']);
			
			vB_Upgrade::createAdminSession();
			$channelmods = vB_Api::instanceInternal('usergroup')->fetchUsergroupBySystemID(vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID);
			$assertor = vB::getDbAssertor();
			$assertor->assertQuery('vBInstall:unsetChannelModeratorPermissionCanremoveposts', 
				array('channel_moderators_usergroupid' => $channelmods['usergroupid'])
			);
		}
	}
	
	/*	
	 *	Step 2: Current unused, required here because step_1 uses a upgradelog check, and thus cannot be the
	 *		last step.
	 */
	public function step_2($data = NULL)
	{
		// There's a bug where the last step of a script is always recorded with step = 0. ANY step that uses an
		// upgradelog check to run only once CANNOT be the last step in the script. As such, this is just a filler.
		$this->skip_message();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
