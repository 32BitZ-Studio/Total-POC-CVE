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

class vB_Upgrade_519a6 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '519a6';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.9 Alpha 6';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.9 Alpha 5';

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
	 * Step 1 - Add admin message for VBV-14825
	 */
	public function step_1()
	{
		$this->add_adminmessage(
			'after_upgrade_519_reinstall_products',
			array(
				'dismissable' => 1,
				'script'      => '',
				'action'      => '',
				'execurl'     => '',
				'method'      => '',
				'status'      => 'undone',
			)
		);
	}

	/**
	 * Step 2 - Remove widget records with duplicate GUIDs (THIS EFFECTIVELY REMOVES CUSTOM MODULES) except for one.
	 *			Collapse any newly orphaned widgetdefinition & widgetinstance records onto the single
	 *			remaining widgetid for the dupe-guid widget records.
	 */
	public function step_2($data = null)
	{
		$assertor = vB::getDbAssertor();
		$dupeCheck = $assertor->getRow('vBInstall:getDuplicateWidgetGuids');
		if (!$dupeCheck OR empty($dupeCheck['guid']))
		{
			if ($data === null)
			{
				$this->skip_message();
				return;
			}
			else
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
		}
		else
		{
			if ($data === null)
			{
				$this->show_message($this->phrase['version']['519a6']['deduping_widget_records']);
			}
		}

		$widgetRecords = $assertor->getRows('widget', array('guid' => $dupeCheck['guid']));
		$defaultWidget = array();
		$defaultDefinitions = array();
		$counter = 0;
		foreach ($widgetRecords AS $widget)
		{
			if (empty($defaultWidget))
			{
				$defaultWidget = $widget;
				$definitionsQry = $assertor->getRows('widgetdefinition', array('widgetid' => $widget['widgetid']));
				foreach ($definitionsQry AS $def)
				{
					// Change below to = $def if we need to use the definition data for some kind of smart merging below.
					$defaultDefinitions[$def['name']] = true;
				}
			}
			else
			{
				$counter++;
				// Delete this duplicate widget record, remove the unnecessary widgetdefinition records,
				// and update the widgetinstance records
				$assertor->delete('widget', array('widgetid' => $widget['widgetid']));

				// If the definition already exists for the "default", delete the dupe. Else, update it to
				// make it owned by the default.
				$widgetDefinitions = $assertor->getRows('widgetdefinition', array('widgetid' => $widget['widgetid']));
				foreach ($widgetDefinitions AS $def)
				{
					if (isset($defaultDefinitions[$def['name']]))
					{
						// At the moment, we don't try any kind of merging. These will likely be overwritten by final_upgrade anyway
						// when default widgets are imported.
						$assertor->delete(
							'widgetdefinition',
							array(
								'widgetid' => $def['widgetid'],
								'name' => $def['name']
							)
						);
					}
					else
					{
						$assertor->update('widgetdefinition',
							array( // VALUES
								'widgetid' => $defaultWidget['widgetid'],
							),
							array( // CONDITION
								'widgetid' => $def['widgetid'],
								'name' => $def['name'],
							)
						);
					// Change below to = $def & add $defaultDefinitions[$def['name']]['widgetid'] = $defaultWidget['widgetid']
					// if we need to use the definition data for some kind of smart merging above.
						$defaultDefinitions[$def['name']] = true;
					}
				}

				// Fix now-orphaned widgetinstances
				$assertor->update('widgetinstance',
					array( // VALUES
						'widgetid' => $defaultWidget['widgetid']
					),
					array( // CONDITION
						'widgetid' => $widget['widgetid']
					)
				);
			}
		}

		$this->show_message(sprintf($this->phrase['version']['519a6']['deduped_x_for_widget_y'], $counter, $defaultWidget['template']));

		$startat = isset($data['startat']) ? intval($data['startat']) : 0;
		return array('startat' => ++$startat);
	}

	/**
	 * Step 3 - Make widget.guid UNIQUE
	 */
	public function step_3()
	{
		// Step 2 should have removed/collapsed any widget records with a duplicate GUID.
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'widget', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "widget
			CHANGE guid guid char(150) NULL DEFAULT NULL UNIQUE"
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/