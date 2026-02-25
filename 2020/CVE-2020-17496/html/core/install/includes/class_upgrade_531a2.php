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

class vB_Upgrade_531a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '531a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.1 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.1 Alpha 1';

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
	 * Add field for event date format
	 */
	public function step_1()
	{
		// this matches the code in sync_database to add this field
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'language', 1, 1),
			'language',
			'eventdateformatoverride',
			'VARCHAR',
			array('length' => 50, 'null' => false, 'default' => '')
		);
	}

	/**
	 * Set language.eventdateformatoverride if needed
	 */
	public function step_2()
	{
		// For each installed language, check if locale is set, and if so,
		// populate eventdateformatoverride with a default value if empty,
		// since if it is left blank when locale is set, the event date
		// won't show at all. When locale is set, we require that all the
		// overrides be set as well.
		// This will essentially be any language that existed before this
		// version and already had locale set.

		$assertor = vB::getDbAssertor();

		// Get languages where locale is defined and eventdateformatoverride is empty
		$languages = $assertor->getRows('language', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array(
				'languageid',
				'title',
				'locale',
				'eventdateformatoverride',
			),
			vB_dB_Query::CONDITIONS_KEY => array(
				array(
					'field'    => 'locale',
					'value'    => '',
					'operator' => vB_dB_Query::OPERATOR_NE
				),
				array(
					'field'    => 'eventdateformatoverride',
					'value'    => '',
					'operator' => vB_dB_Query::OPERATOR_EQ
				),
			),
		));

		$count = count($languages);
		$index = 1;

		foreach ($languages AS $language)
		{
			// Default format if locale is specified: %#d %b
			$values = array('eventdateformatoverride' => '%#d %b');
			$condition = array('languageid' => $language['languageid']);
			$assertor->update('language', $values, $condition);

			$this->show_message(sprintf($this->phrase['version']['531a2']['setting_default_eventdateformatoverride_for_x_y_of_z'], $language['title'], $index, $count));
			++$index;
		}

		if ($count < 1)
		{
			$this->skip_message();
		}
	}

	public function step_3()
	{
		vB::getDatastore()->delete('vBUgChannelAccess');
		$this->show_message(sprintf($this->phrase['core']['remove_datastore_x'], 'vBUgChannelAccess'));
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
