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

class vB_Upgrade_541b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '541b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.1 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.1 Alpha 4';

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


	// Reinstall twitterlogin package step moved to 541b2.
	public function step_1()
	{
		$this->skip_message();
	}


	// Replace require_moderate with skip_moderate in 'defaultchannelpermissions'
	// See VBV-18294
	public function step_2()
	{
		$datastore = vB::getDatastore();
		$datastore->fetch('defaultchannelpermissions');
		$defaultchannelpermissions = vB::getDatastore()->getValue('defaultchannelpermissions');
		if (empty($defaultchannelpermissions))
		{
			// if this isn't created yet, then there's nothing to do.
			return $this->skip_message();
		}

		if (!is_array($defaultchannelpermissions))
		{
			$defaultchannelpermissions = vB_Utility_Unserialize::unserialize($defaultchannelpermissions);
		}

		$needsRebuild = false;
		foreach($defaultchannelpermissions AS $__nodekey => $__innerArr)
		{
			foreach ($__innerArr AS $__groupkey => $permissions)
			{
				if (isset($permissions['require_moderate']))
				{
					$needsRebuild = true;
					$defaultchannelpermissions[$__nodekey][$__groupkey]['skip_moderate'] = !($permissions['require_moderate']);
					unset($defaultchannelpermissions[$__nodekey][$__groupkey]['require_moderate']);
				}

			}
		}

		if ($needsRebuild)
		{
			// show message.
			$this->show_message($this->phrase['version']['541b1']['rebuilding_defaultchannelperms_datastore']);
			$datastore->build('defaultchannelpermissions', serialize($defaultchannelpermissions), 1);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
