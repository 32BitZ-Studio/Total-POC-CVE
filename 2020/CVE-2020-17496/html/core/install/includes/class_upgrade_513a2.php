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

class vB_Upgrade_513a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '513a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.3 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.3 Alpha 1';

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
		$this->show_message($this->phrase['version']['513a2']['setting_page_types']);
		$parser = new vB_XML_Parser(false, DIR . '/install/vbulletin-pages.xml');
		$pages = $parser->parse();
		$pages = array_pop($pages);
		$guids = array();
		foreach($pages AS $page)
		{
			if ($page['pagetype'] == 'default')
			{
				$guids[] = $page['guid'];
			}
		}
		vB::getDbAssertor()->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => $guids), 'pagetype' => 'default'));
	}

	public function step_2()
	{
		$this->show_message($this->phrase['version'][$this->SHORT_VERSION]['removing_orphaned_subscription_records']);
		vB::getDbAssertor()->assertQuery('vBInstall:deleteOrphanedSubscriptionRecords');
	}

	public function step_3()
	{
		$this->show_message($this->phrase['version']['513a2']['preparing_routenew_table_for_adding_index']);
		//If there are empty string names update them to NULL
		$assertor = vB::getDbAssertor();
		$assertor->assertQuery('vBInstall:setEmptyStringsToNullRoutenew');

		// find all duplicates and get the lowest routeid for each
		$duplicates = $assertor->assertQuery('vBInstall:findDuplicateRouteNames');

		$can_add_index=true;
		//loop trough each duplicates name
		foreach($duplicates AS $duplicate)
		{
			// Get the record with the lowest routeid for this duplicate
			$record_min_routeid = $assertor->getRow('routenew', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'name', 'value' => $duplicate['name'], 'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'routeid', 'value' => $duplicate['min_routeid'], 'operator' =>  vB_dB_Query::OPERATOR_EQ)
					)
				)
			);
			//get all records for current duplicate name other than the one with the lowest routeid
			$current_duplicate_records = $assertor->getRows('routenew', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'name', 'value' => $duplicate['name'], 'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'routeid', 'value' => $duplicate['min_routeid'], 'operator' =>  vB_dB_Query::OPERATOR_NE)
					)
				)
			);

			//loop trough each duplicate record
			foreach ($current_duplicate_records as $record)
			{
				// check if it is a complete duplicate and delete if so
				$complate_duplicate = true;
				foreach ($record as $key=>$value)
				{

					if ($key != 'routeid' AND $value != $record_min_routeid[$key])
					{
						$complate_duplicate = false;
						$can_add_index =  false;
					}
				}
				if ($complate_duplicate)
				{
					//update page table
					$assertor->assertQuery('page', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'routeid', 'value' => $record['routeid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
						),
						'routeid' => $duplicate['min_routeid']
					));
					//update node table
					$assertor->assertQuery('vBForum:node', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'routeid', 'value' => $record['routeid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
						),
						'routeid' => $duplicate['min_routeid']
					));
					//delete the route record
					$assertor->assertQuery('routenew', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'routeid' => $record['routeid']
					));
				}
			}
		}
		if ($can_add_index)
		{
			$this->drop_index(
				sprintf($this->phrase['core']['altering_x_table'], 'routenew', 1, 2),
				'routenew',
				'route_name'
			);
			$this->add_index(
				sprintf($this->phrase['core']['altering_x_table'], 'routenew', 2, 2),
				'routenew',
				'route_name',
				array('name'),
				'unique'
			);
		}
		else
		{
			$this->add_adminmessage($this->phrase['version']['513a2']['cannot_add_routenew_index'],array());
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
