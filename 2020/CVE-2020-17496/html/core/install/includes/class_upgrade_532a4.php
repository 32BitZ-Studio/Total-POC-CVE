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

class vB_Upgrade_532a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '532a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.2 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.2 Alpha 3';

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
	 * Add field for datetime picker format
	 */
	public function step_1()
	{
		// this matches the code in sync_database to add this field
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'language', 1, 1),
			'language',
			'pickerdateformatoverride',
			'VARCHAR',
			array('length' => 50, 'null' => false, 'default' => '')
		);
	}

	/**
	 * Populate language.pickerdateformatoverride if needed
	 */
	public function step_2()
	{
		// For each installed language, check if locale is set, and if so,
		// populate pickerdateformatoverride with a default value if empty,
		// since if it is left blank when locale is set, the picker date/time
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
				'pickerdateformatoverride',
			),
			vB_dB_Query::CONDITIONS_KEY => array(
				array(
					'field'    => 'locale',
					'value'    => '',
					'operator' => vB_dB_Query::OPERATOR_NE
				),
				array(
					'field'    => 'pickerdateformatoverride',
					'value'    => '',
					'operator' => vB_dB_Query::OPERATOR_EQ
				),
			),
		));

		$count = count($languages);
		$index = 1;

		foreach ($languages AS $language)
		{
			// Default format if locale is specified: d-m-Y H:i
			$values = array('pickerdateformatoverride' => 'd-m-Y H:i');
			$condition = array('languageid' => $language['languageid']);
			$assertor->update('language', $values, $condition);

			$this->show_message(sprintf($this->phrase['version']['532a4']['setting_default_pickerdateformatoverride_for_x_y_of_z'], $language['title'], $index, $count));
			++$index;
		}

		if ($count < 1)
		{
			$this->skip_message();
		}
	}

	public function step_3()
	{
		$this->show_message($this->phrase['version']['532a4']['rebuild_prefix_datastore']);
		//the datastore format has changed, make sure we have the correct version
		vB_Library::instance('prefix')->buildDatastore();
	}

	/**
	 * Add widgetdefinition.descriptionphrase
	 */
	public function step_4()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'widgetdefinition', 1, 1),
			'widgetdefinition',
			'descriptionphrase',
			'VARCHAR',
			array('length' => 250, 'null' => false, 'default' => '')
		);
		$this->long_next_step();
	}

	public function step_5()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'created', TABLE_PREFIX . 'node'),
			'node',
			'created',
			array('created')
		);
		$this->long_next_step();
	}

	public function step_6()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'totalcount', TABLE_PREFIX . 'node'),
			'node',
			'totalcount',
			array('totalcount')
		);
		$this->long_next_step();
	}

	public function step_7()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'joindate', TABLE_PREFIX . 'user'),
			'user',
			'joindate',
			array('joindate')
		);
	}

	// update fcmqueue cron's minute field
	function step_8()
	{
		$assertor = vB::getDbAssertor();
		$check = $assertor->getRow('cron',
			array(
				'varname' => "fcmqueue",
			)
		);
		/*
			The old minute field was supposed to be:
			'a:12:{i:0;i:0;i:1;i:5;i:2;i:10;i:3;i:15;i:4;i:20;i:5;i:25;i:6;i:30;i:7;i:35;i:8;i:40;i:9;i:45;i:10;i:50;i:11;i:55;}'
			but turns out the column is only 100 chars, so it was cut off. Furthermore after the demo we decided to run this
			cron every 30min instead of every 5min.
		 */


		if (!empty($check) AND (strpos($check['minute'], 'a:12') === 0 OR $check['hour'] != -1))
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'cron', 1, 1));
			$newMinute = 'a:2:{i:0;i:0;i:1;i:30;}';
			$assertor->update(
				'cron',
				array( // value
					'minute'  => $newMinute,
					'hour' => -1,
				),
				array( // condition
					'varname' => 'fcmqueue',
				)
			);
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
