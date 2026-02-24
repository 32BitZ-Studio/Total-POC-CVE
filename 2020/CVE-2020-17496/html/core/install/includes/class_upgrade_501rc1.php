<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

class vB_Upgrade_501rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '501rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.1 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.1 Alpha 2';

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
	 * Remove invalid profile routes
	 *
	 */
	function step_1()
	{
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'routenew', 1, 1));

		// we changed class to vB5_Route_Content at some point in upgrade so let's get rid of them.
		vB::getDbAssertor()->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'class', 'value' => 'vB5_Route_Content', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'name', 'value' => array('profile', 'following', 'followers', 'groups', 'settings'), 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		));

		// we fix settings route class during the upgrade but we have a wrong regex for the duplicate.
		vB::getDbAssertor()->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'name', 'value' => 'settings', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'regex', 'value' => 'settings', 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
