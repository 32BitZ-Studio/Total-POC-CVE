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

class vB_Upgrade_5111a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '5111a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.11 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.10';

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

	public function step_1($data = array('startat' => 1))
	{
		$size = 1000;
		global $vbulletin;
		$this->show_message(sprintf($this->phrase['version']['5111a1']['updating_user_rank']));
		$startat = intval($data['startat']);
		//we create a blog channel per user. So get a list of blogposts since our last update
		$assertor = vB::getDbAssertor();

		$users = $assertor->assertQuery('vBAdmincp:getNextUsers', array('startat' => $startat, 'blocksize' => $size));

		if (!$users->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$lastUserid = 1;
		foreach ($users AS $user)
		{
			$userdm = new vB_Datamanager_User($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
			$userdm->set_existing($user);
			$userdm->save();
			unset($userdm);

			$lastUserid = $user['userid'];
		}

		$this->show_message(sprintf($this->phrase['core']['processed_records_x'], 1000));
		return array('startat' => $lastUserid);

	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
