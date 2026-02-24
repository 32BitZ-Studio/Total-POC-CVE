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

class vB_Upgrade_540a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '540a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.0 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.5 Alpha 4';

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
	 * Update the imgdir_spriteiconsvb stylevar
	 */
	public function step_1()
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();
		$updated = false;

		// Get imgdir_spriteiconsvb stylevar for all styles
		$stylevars = $assertor->getRows('stylevar', array('stylevarid' => 'imgdir_spriteiconsvb'));
		foreach ($stylevars AS $stylevar)
		{
			$unserialized = @unserialize($stylevar['value']);
			if ($unserialized AND is_array($unserialized))
			{
				// if it contains the previous default value, let's set it to blank
				// This stylevar is no longer used by the master/default style, but
				// we'll keep it around for custom styles that may use it.
				if ($unserialized['path'] == 'images/css')
				{
					$unserialized['path'] = '';
					$serialized = serialize($unserialized);
					$assertor->update('stylevar', array('value' => $serialized), array('stylevarid' => $stylevar['stylevarid'], 'styleid' => $stylevar['styleid']));
					$this->show_message(sprintf($this->phrase['version']['540a1']['updating_imgdir_spriteiconsvb_stylevar_in_styleid_x'], $stylevar['styleid']));
					$updated = true;
				}
			}
		}

		if (!$updated)
		{
			$this->skip_message();
		}
	}


	// Add admin message to warn about Groups channel permissions (VBV-17996)
	public function step_2()
	{
		$this->add_adminmessage(
			'after_upgrade_check_groups_channel_permissions',
			array(
				'dismissible' => 1,
				'execurl'     => 'forumpermission.php?do=modify',
				'method'      => 'get',
				'status'      => 'undone',
			)
		);
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
