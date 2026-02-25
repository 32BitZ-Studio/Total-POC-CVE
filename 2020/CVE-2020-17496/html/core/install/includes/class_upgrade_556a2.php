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

class vB_Upgrade_556a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '556a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.6 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.6 Alpha 1';

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

	public function step_1()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'notice', 1, 1),
			'notice',
			'noticeoptions',
			'int',
			self::FIELD_DEFAULTS
		);
	}

	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
		$db = vB::getDbAssertor();

		$bitfields = vB::getDatastore()->getValue('bf_misc_announcementoptions');

		$options = 0;
		$options |= $bitfields['allowhtml'];

		$db->update('vBForum:notice', array('noticeoptions' => $options), array('noticeoptions' => 0));
	}

	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['version']['556a2']['rebuild_x_datastore'], 'noticecache'));
		vB_Library::instance('notice')->buildNoticeDatastore();
	}

	public function step_4()
	{
		$this->add_field(
			sprintf($this->phrase['vbphrase']['alter_table'], 'profilefield'),
			'profilefield',
			'showonpost',
			'smallint',
			self::FIELD_DEFAULTS
		);
	}

	public function step_5()
	{
		$this->show_message($this->phrase['version']['505a3']['update_profilefields_cache']);
		require_once(DIR . '/includes/adminfunctions_profilefield.php');
		build_profilefield_cache();
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103286 $
|| ####################################################################
\*======================================================================*/
