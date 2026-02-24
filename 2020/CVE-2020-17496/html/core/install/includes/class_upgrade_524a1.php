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

class vB_Upgrade_524a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '524a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.4 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.3';

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
		$this->drop_table('forum');
	}

	public function step_2()
	{
		$this->drop_table('forumread');
	}

	public function step_3()
	{
		$this->drop_table('groupmessage');
	}

	public function step_4()
	{
		$this->drop_table('groupmessage_hash');
	}

	public function step_5()
	{
		$this->drop_table('groupread');
	}

	public function step_6()
	{
		$this->drop_table('navigation');
	}

	public function step_7()
	{
		$this->drop_table('plugin');
	}

	public function step_8()
	{
		$this->drop_table('route');
	}

	public function step_9()
	{
		$this->drop_table('socialgroup');
	}

	public function step_10()
	{
		$this->drop_table('socialgroupcategory');
	}

	public function step_11()
	{
		$this->drop_table('socialgroupicon');
	}

	public function step_12()
	{
		$this->drop_table('socialgroupmember');
	}

	public function step_13()
	{
		$this->drop_table('subscribeforum');
	}

	public function step_14()
	{
		$this->drop_table('subscribethread');
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
