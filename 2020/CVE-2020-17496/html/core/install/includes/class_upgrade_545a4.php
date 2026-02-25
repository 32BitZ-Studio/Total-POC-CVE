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

class vB_Upgrade_545a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '545a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.5 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.5 Alpha 3';

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
		// this corrects 541a4 step9 that due to a bug in alter_field (VBV-18813)
		// would set the column to allow NULL values.
		$this->alter_field(
			sprintf($this->phrase['core']['altering_x_table'], 'permission', 1, 1),
			'permission',
			'edit_time',
			'float',
			self::FIELD_DEFAULTS
		);
	}

	/**
	 * Handle customized values (in custom styles) for stylevars that have been renamed
	 */
	public function step_2()
	{
		$mapper = new vB_Stylevar_Mapper();

		// Map the entire stylevar value from old to new since this is only a rename
		// No need for mapping of any of the stylevar parts or any presets, since
		// we only renamed the stylevar and didn't change the data type.
		$mapper->addMapping('body_font', 'global_text_font');

		// Do the processing
		if ($mapper->load() AND $mapper->process())
		{
			$this->show_message($this->phrase['core']['mapping_customized_stylevars']);
			$mapper->processResults();
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Update inheritance for stylevars that inherit from a stylevar that was just renamed
	 */
	public function step_3()
	{
		$mapper = new vB_Stylevar_Mapper();
		$result = $mapper->updateInheritance('body_font', 'global_text_font');

		if ($result)
		{
			$this->show_message($this->phrase['core']['updating_customized_stylevar_inheritance']);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/