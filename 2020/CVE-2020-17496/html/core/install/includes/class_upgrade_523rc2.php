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

class vB_Upgrade_523rc2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '523rc2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.3 Release Candidate 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.3 Release Candidate 1';

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
	 * Enable canusepmchat only for groups with pmquota > 0
	 */
	public function step_1()
	{
		/*
			This step effectively overrides 523a4.
		 */


		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}
		$this->show_message($this->phrase['version']['523rc2']['setting_ugp_canusepmchat']);



		/*
			Set up readable bitfield
		 */
		$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
		$pmpermissions = array();
		foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
		{
			if ($group['name'] == 'ugp')
			{
				foreach($group['group'] AS $bfgroup)
				{
					if (($bfgroup['name'] == 'pmpermissions'))
					{
						foreach ($bfgroup['bitfield'] AS $bitfield)
						{
							$pmpermissions[$bitfield['name']] = $bitfield['value'];
						}
					}
				}
			}
		}


		/*
			Grab all usergroups & pick out which ones should get canusepmchat set
		 */
		$assertor = vB::getDbAssertor();
		$allgroupids = array();
		$usergroupsToEnablePmchat = array();
		$usergroups = $assertor->assertQuery(
			'vBForum:usergroup',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('usergroupid', 'pmquota', 'pmpermissions'),
			)
		);
		if ($usergroups AND $usergroups->valid())
		{
			foreach ($usergroups AS $usergroup)
			{
				$allgroupids[] = $usergroup['usergroupid'];
				if ($usergroup['pmquota'] > 0)
				{
					$usergroupsToEnablePmchat[] = $usergroup['usergroupid'];
				}
			}
		}

		// first, just turn it off for everyone.
		vB::getDbAssertor()->assertQuery('vBInstall:unsetUsergroupPmpermissionsBit', array('bit' => $pmpermissions['canusepmchat'], 'groupids' => $allgroupids));

		// Now turn it on for only those who need it.
		if (!empty($usergroupsToEnablePmchat))
		{
			vB::getDbAssertor()->assertQuery('vBInstall:setUsergroupPmpermissionsBit', array('bit' => $pmpermissions['canusepmchat'], 'groupids' => $usergroupsToEnablePmchat));
		}

		// rebuild usergroup cache, reset global $vbulletin's array, & usergroup API instance's array.
		vB_Upgrade::createAdminSession();
		vB_Library::instance('usergroup')->buildDatastore();
		vB_Api::instanceInternal('usergroup')->fetchUsergroupList(true);
	}



	public function step_2()
	{
		// Place holder to allow iRan() to work properly in step_1(), as the last step gets recorded as step '0' in the upgrade log for CLI upgrade.
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
