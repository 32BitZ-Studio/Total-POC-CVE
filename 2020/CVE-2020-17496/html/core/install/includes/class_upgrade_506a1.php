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

class vB_Upgrade_506a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '506a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.6 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.5';

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
	
	/** We have four new admin permissions. We should set those for non-CLI users
	 *
	 */
	public function step_1($data = NULL)
	{
		//We don't want to run this except in the case that the original install was pre-5.1.0.
		$assertor = vB::getDbAssertor();
		$check = $assertor->assertQuery('vBInstall:upgradelog', array('script' => '505rc1'));
		
		if ($check->valid())
		{
			// we should only run this once. 
			$check = $assertor->assertQuery('vBInstall:upgradelog', array('script' => '506a1', 'step' => '1'));

			if ($check->valid())
			{
				$this->skip_message();
			}
			else
			{
				$this->show_message($this->phrase['version']['506a1']['updating_admin_permissions']);
				/*get the administrator permissions*/
				$parser = new vB_XML_Parser(false, DIR . '/includes/xml/bitfield_vbulletin.xml');
				$bitfields = $parser->parse();
				$adminperms = array();

				foreach ($bitfields['bitfielddefs']['group'] AS $topGroup)
				{
					if (($topGroup['name'] == 'ugp'))
					{
						foreach ($topGroup['group'] AS $group)
						{
							if ($group['name'] == 'adminpermissions')
							{
								foreach ($group['bitfield'] as $fielddef)
								{
									$adminperms[$fielddef['name']] = $fielddef['value'];
								}
								break;
							}
						}
					}
				}


				$changes = array(array('old' => 'canadminstyles', 'new' => 'canadmintemplates'), array('old' => 'canadminsettings', 'new' => 'canadminsettingsall'),
					array('old' => 'canadminimages', 'new' => 'cansetserverconfig'), array('old' => 'canadminusers', 'new' => 'cansetserverconfig'),
					array('old' => 'canadminthreads', 'new' => 'cansetserverconfig'), array('old' => 'canadminmaintain', 'new' => 'canuseallmaintenance'),
					array('old' => 'canadminsettings', 'new' => 'cansetserverconfig'));

				foreach ($changes as $change)
				{
 					if (!empty($adminperms[$change['old']]) AND !empty($adminperms[$change['new']]))
					{
						$assertor->assertQuery('vBInstall:updateAdminPerms', array('existing' => $adminperms[$change['old']], 'new' => $adminperms[$change['new']]));
					}
				}
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/*	
	 *	Step 2: Required here because step_1 uses a upgradelog check, and thus cannot be the
	 *		last step. See VBV-12130
	 */
	public function step_2($data = NULL)
	{
		$this->skip_message();
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
