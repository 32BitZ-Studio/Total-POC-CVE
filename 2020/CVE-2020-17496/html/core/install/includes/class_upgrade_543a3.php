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

class vB_Upgrade_543a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '543a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.3 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.3 Alpha 2';

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
	 * Add admin message to let them know there's a new (empty) privacy page VBV-18551
	 */
	public function step_1()
	{
		$this->add_adminmessage(
			'after_upgrade_check_privacy_policy_page',
			array(
				'dismissable' => 1,
				'script'      => '',
				'action'      => '',
				'execurl'     => '',
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