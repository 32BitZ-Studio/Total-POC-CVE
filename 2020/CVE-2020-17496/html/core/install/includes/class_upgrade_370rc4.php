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

class vB_Upgrade_370rc4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '370rc4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '3.7.0 Release Candidate 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '3.7.0 Release Candidate 3';

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
	* special case: memberlist, modifyattachments, reputationbit
	* add missing sessionhash. Let later query add security tokens
	* special case for headinclude: the JS variable
	*
	*/
	function step_1()
	{
		//Any user styles that exist at this point are incompatible with vb5.  So this
		//would do nothing useful in the long run.  We don't even use the sessionhash
		//params in vB5. And we don't want to compile any old style templates
		//because that will likely fail
		$this->skip_message();
	}

	/**
	* Step #2 - add the security token to all forms
	*
	*/
	function step_2()
	{
		//Any user styles that exist at this point are incompatible with vb5.  So this
		//would do nothing useful in the long run.  And we don't want to compile any old style templates
		//because that will likely fail
		$this->skip_message();
	}

	/**
	* Step #3 - special case for headinclude: the JS variable
	*
	*/
	function step_3()
	{
		//This template will eventually be removed from the master style.  Any user
		//styles that exist at this point are incompatible with vb5.
		//This also will attempt to compile old style
		//template syntax, which is being removed from the system.
		$this->skip_message();
	}

	/**
	* Step #4 - special case for who's online: a form that should be get
	*
	*/
	function step_4()
	{
		//Any user styles that exist at this point are incompatible with vb5.  So this
		//would do nothing useful in the long run.  And we don't want to compile any old style templates
		//because that will likely fail
		$this->skip_message();
	}

	/**
	* Step #5
	*
	*/
	function step_5()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'setting', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "setting CHANGE datatype datatype ENUM('free', 'number', 'boolean', 'bitfield', 'username', 'integer', 'posint') NOT NULL DEFAULT 'free'"
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
