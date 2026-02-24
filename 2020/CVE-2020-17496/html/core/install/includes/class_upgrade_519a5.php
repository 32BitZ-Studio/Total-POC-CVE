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

class vB_Upgrade_519a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '519a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.9 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.9 Alpha 4';

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

	/** We have one new admin permission. We should set that based on existing admin permissions. Anyone with canadmincron should get the new canadminrss
	 *
	 */
	public function step_1($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		// we should only run this once.
		$check = $assertor->assertQuery('vBInstall:upgradelog', array('script' => '519a5', 'step' => '1'));

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
			$assertor->assertQuery('vBInstall:updateAdminPerms', array('existing' => $adminperms['canadmincron'], 'new' => $adminperms['canadminrss']));
		}

	}

	/** This step is here to make the upgradelog check in step 1 work properly
	 *
	 */

	public function step_2()
	{
		$this->skip_message();
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
