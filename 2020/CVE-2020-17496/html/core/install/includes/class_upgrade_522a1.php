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

class vB_Upgrade_522a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '522a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.2 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.1';

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
		$assertor = vB::getDbAssertor();
		$assertor->delete('routenew', array('guid' => 'vbulletin-4ecbdacd6a6335.32656589'));
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'routenew', 1, 1));
		$this->long_next_step();
	}

	public function step_2()
	{
		$this->drop_table('post');
	}

	public function step_3()
	{
		$this->drop_table('posthash');
	}

	public function step_4()
	{
		$this->drop_table('postlog');
	}

	public function step_5()
	{
		$this->drop_table('postparsed');
		$this->long_next_step();
	}

	public function step_6()
	{
		$this->drop_table('thread');
	}

	public function step_7()
	{
		$this->drop_table('threadrate');
	}

	public function step_8()
	{
		$this->drop_table('threadread');
	}

	public function step_9()
	{
		$this->drop_table('threadredirect');
	}

	public function step_10()
	{
		$this->drop_table('threadviews');
	}

	public function step_11()
	{
		$this->drop_table('postrelease');
	}

	public function step_12()
	{
		$this->drop_table('skimlinks');
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
