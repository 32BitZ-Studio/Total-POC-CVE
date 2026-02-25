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

class vB_Upgrade_542a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '542a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.2 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.2 Alpha 3';

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
		Pickup product XML changes in alpha 4 (moved from alpha 3)
	 */
	public function step_1()
	{
		// Packages are installed/upgraded as part of upgrade_final step_13
		$this->skip_message();
	}

	/*
	 *	Fix channel route REs so that they work with and without a prefix without modification.
	 */
	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));

		$db = vB::getDBAssertor();
		$set = $db->select('routenew', array('class' => 'vB5_Route_Channel'));
		foreach($set AS $row)
		{
			//we have a difference based on whether or nto the prefix is blank
			//(to account for the fact that we only have a slash before the page if
			//we have
			$expected = ($row['prefix'] === '' ? '(?:page(' : '(?:/page(');
			$newre = str_replace($expected, '(?:(?:/|^)page(', $row['regex']);
			$row = $db->update('routenew', array('regex' => $newre), array('routeid' => $row['routeid']));
		}
	}

	public function step_3()
	{
		$this->drop_table('bookmarksite');
	}

	public function step_4()
	{
		vB::getDatastore()->delete('bookmarksitecache');
		$this->show_message(sprintf($this->phrase['core']['remove_datastore_x'], 'bookmarksitecache'));
	}

	public function step_5()
	{
		$this->drop_table('indexqueue');
	}

	public function step_6()
	{
		$this->drop_table('discussionread');
	}

	public function step_7()
	{
		$this->drop_table('picturelegacy');
	}

	public function step_8()
	{
		$this->drop_table('podcast');
	}

	public function step_9()
	{
		$this->drop_table('podcastitem');
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
