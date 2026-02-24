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

class vB_Upgrade_512a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '512a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.2 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.2 Alpha 1';

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
	 *	Steps 1 & 2 :
	 *		Add the style.guid & style.filedataid columns
	 */
	public function step_1()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'style', 1, 1),
			'style',
			'guid',
			'char',
			array('null' => true, 'length' => 150, 'default' => null, 'extra' => 'UNIQUE')
		);
	}

	public function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'style', 1, 1),
			'style',
			'filedataid',
			'int',
			self::FIELD_DEFAULTS
		);
	}

	public function step_3()
	{
		// Create textonly field
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'template', 1, 1),
			'template',
			'textonly',
			'smallint',
			self::FIELD_DEFAULTS
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
