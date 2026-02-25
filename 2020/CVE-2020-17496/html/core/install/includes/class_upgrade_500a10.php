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

class vB_Upgrade_500a10 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '500a10';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.0 Alpha 10';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.0 Alpha 9';

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
	 * Change settings routenew.name class
	 */
	function step_1()
	{
		$this->skip_message();
	}

	/**
	 * Change settings routenew.arguments
	 */
	function step_2()
	{
		$this->skip_message();
	}

	/**
	 * Change showpublished field to 1 for Albums and Private Messages
	 */
	function step_3()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . "node"),
			"UPDATE " . TABLE_PREFIX . "node
			SET showpublished = '1'
			WHERE showpublished = '0' AND
				contenttypeid = '23' AND
				title IN ('Albums', 'Private Messages')
			"
		);
	}

	/*** Add index on nodeid to the moderators table */
	function step_4()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'moderator', 1, 1),
			'moderator',
			'nodeid',
			'nodeid'
		);
	}


	/*** set the nodeid for moderators */
	function step_5()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'moderator'));
		vB::getDbAssertor()->assertQuery('vBInstall:setModeratorNodeid',
			array('forumTypeId' => vB_Types::instance()->getContentTypeID('vBForum_Forum')));
	}

	/*** Add index on nodeid to the moderatorlog table */
	function step_6()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'moderatorlog', 1, 1),
			'moderatorlog',
			'nodeid',
			'nodeid'
		);
	}


	/*** set the nodeid for moderatorlog */
	function step_7()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'moderatorlog'));
		vB::getDbAssertor()->assertQuery('vBInstall:setModeratorlogThreadid',
			array('threadTypeId' => vB_Types::instance()->getContentTypeID('vBForum_Thread')));
	}

	/*** Add index on nodeid to the access table */
	function step_8()
	{
		$this->skip_message();
	}


	/*** set the nodeid for access */
	function step_9()
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
