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

class vB_Upgrade_400b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '400b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '4.0.0 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '4.0.0 Alpha 6';

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
	* Step #1
	*
	*/
	function step_1()
	{
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'attachment', 1, 2),
			'attachment',
			'contenttypeid'
		);
	}

	/**
	* Step #2
	*
	*/
	function step_2()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'attachment', 2, 2),
			'attachment',
			'contenttypeid',
			array('contenttypeid', 'contentid', 'attachmentid')
		);
	}

	/**
	* Step #3
	*
	*/
	function step_3()
	{
		$row = $this->db->query_first("
			SELECT COUNT(*) AS count FROM " . TABLE_PREFIX . "notice WHERE title = 'default_guest_message'
		");

		if ($row['count'] == 0)
		{
			$this->show_message('Adding a notice');

			$data = array(
				'title' => 'default_guest_message',
				'text' => $this->phrase['install']['default_guest_message'],
				'displayorder' => 10,
				'active' => 1,
				'persistent' => 1,
				'dismissible' => 1,
				'criteria' => array('in_usergroup_x' => array('condition1' => 1)),
			);
			vB_Library::instance('notice')->save($data);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103168 $
|| #######################################################################
\*=========================================================================*/
