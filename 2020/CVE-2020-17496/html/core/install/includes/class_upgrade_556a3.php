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

class vB_Upgrade_556a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '556a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION = '5.5.6 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.6 Alpha 2';

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
	public $VERSION_COMPAT_ENDS = '';

	public function step_1()
	{
		//We previously treated a blank value for the cssfilelocation to 'clientscript/vbulletin_css'
		//This isn't really in line with how we deal with options in general and we want to put in
		//a real value at all times (and change it while we're at it).  This will also put things
		//more in line with how we handle the template file cache.
		$options = vB::getDatastore()->getValue('options');
		if(!$options['cssfilelocation'])
		{
			$db = vB::getDbAssertor();

			//Calling $this->set_option will potentially trigger a style rebuild as a side effect of
			//changing the file path.  We don't want to do that in an upgrade step as it can take a
			//while and will do it again when we import the master style (not to mention that we
			//don't actually need it because we won't be changing the actual path of a live directory).
			//
			//if storecssasfile is in use we need to preserve the old behavior to avoid breaking the site
			//if it's not, then we'll just update to the current default.
			$path = ($options['storecssasfile'] ? 'clientscript/vbulletin_css' : 'cache/css');
			$db->update('setting', array('value' => $path), array('varname' => 'cssfilelocation'));
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], TABLE_PREFIX . 'setting', 1, 1));
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_2()
	{
		$this->alter_field(
			sprintf($this->phrase['core']['altering_x_table'], 'smilie', 1, 1),
			'smilie',
			'smilietext',
			'VARCHAR',
			array('length' => 100, 'null' => false, 'default' => '')
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103406 $
|| ####################################################################
\*======================================================================*/
