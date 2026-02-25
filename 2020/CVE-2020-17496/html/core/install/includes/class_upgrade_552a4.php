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

class vB_Upgrade_552a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	 * The short version of the script
	 *
	 * @var    string
	 */
	public $SHORT_VERSION = '552a4';

	/**
	 * The long version of the script
	 *
	 * @var    string
	 */
	public $LONG_VERSION = '5.5.2 Alpha 4';

	/**
	 * Versions that can upgrade to this script
	 *
	 * @var    string
	 */
	public $PREV_VERSION = '5.5.2 Alpha 3';

	/**
	 * Beginning version compatibility
	 *
	 * @var    string
	 */
	public $VERSION_COMPAT_STARTS = '';

	/**
	 * Ending version compatibility
	 *
	 * @var    string
	 */
	public $VERSION_COMPAT_ENDS = '';


	/**
	 * Convert widgetinstance.adminconfig. See VBV-19237
	 *
	 * @param null $data
	 */
	public function step_1($data = null)
	{
		$config = vB::getConfig();
		$assertor = vB::getDbAssertor();
		//First we need to get the default character set for table and database.  Because
		// the column charset can be set at the database, table, or column.  If the field is
		// already utf8 or utf8mb4 we do nothing.
		$defaultCharset = false;
		$dbCreate = $assertor->assertQuery(
			'vBInstall:getDbStructure',
			array('dbName' => $config['Database']['dbname'])
		);

		$dbInfo = $dbCreate->current();

		if ($dbInfo = $dbInfo['Create Database'])
		{
			$matches = array();

			if (preg_match("~DEFAULT CHARACTER SET (\w+)~i", $dbInfo, $matches)
				AND !empty($matches[1]))
			{
				$defaultCharset = $matches[1];
			}
		}

		$structure = $assertor->getRow(
			'vBInstall:getTableStructure',
			array('tablename' => 'widgetinstance')
		);

		$lines = explode("\n", $structure['Create Table']);
		$changeit = false;
		$changeCharset = false;

		foreach ($lines AS $line)
		{
			if (strpos($line, 'adminconfig') !== false)
			{
				$matches = array();

				if (strpos($line, 'blob'))
				{
					$changeit = true;
				}

				if (preg_match("~DEFAULT CHARSET\s?=\s?(\w+)~i", $line, $matches)
					AND !empty($matches[1]))
				{
					$charset = $matches[1];
				}
			}
			else if (strpos($line, 'ENGINE') !== false)
			{
				if (preg_match("~DEFAULT CHARSET\s?=\s?(\w+)~i", $line, $matches)
					AND !empty($matches[1]))
				{
					$defaultCharset = $matches[1];
				}
			}
		}

		if (empty($charset))
		{
			$charset = $defaultCharset;
		}

		if (empty($charset) OR ($charset != 'utf8'))
		{
			$changeCharset = true;
		}

		if ($changeit)
		{
			$this->show_message($this->phrase['version']['552a4']['updating_widgetinstance_adminconfig']);

			if ($changeCharset)
			{
				$assertor->assertQuery('vBInstall:makeWidgetInstanceConfBinary', array());
				$assertor->assertQuery('vBInstall:updtWidgetInstanceConf', array());
			}
			$assertor->assertQuery('vBInstall:makeWidgetInstanceConfUtf8', array());
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add the new default widget instances to group related pages if they are not already
	 * there. As the normal default, we don't add new widget instances, but in some cases
	 * it makes sense to do so.
	 */
	public function step_2()
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-pagetemplates.xml'));

		$pageTemplateFile = DIR . '/install/vbulletin-pagetemplates.xml';
		if (!($xml = file_read($pageTemplateFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pagetemplates.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		// update the specified pages, inserting specific widget instances
		// that were added in this release
		$options = vB_Xml_Import::OPTION_ADDSPECIFICWIDGETS;
		$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', $options);

		// set up the specific modules that need to be added to what pages
		$modulesToAdd = array(
			// ----- GROUPS HOME PAGE -----
			// Group Categories Module (channel navigation module)
			array(
				'pagetemplateguid' => 'vbulletin-4ecbdac93742a5.43676037',
				'widgetguid' => 'vbulletin-widget_cmschannelnavigation-4eb423cfd6dea7.34930875',
			),
			// ----- GROUPS CATEGORY PAGE -----
			// My Groups Module (search module)
			array(
				'pagetemplateguid' => 'vbulletin-sgcatlist93742a5.43676040',
				'widgetguid' => 'vbulletin-widget_search-4eb423cfd6a5f3.08329785',
				// comparison function needed since there might be other
				// search modules on this page template
				'comparisonFunction' => function($existingModuleInstance)
				{
					$adminconfig = $existingModuleInstance['adminconfig'];
					if (!empty($adminconfig['searchJSON']))
					{
						$searchJSON = json_decode($adminconfig['searchJSON'], true);
						if (
							$searchJSON AND
							!empty($searchJSON['my_channels']) AND
							!empty($searchJSON['my_channels']['type']) AND
							$searchJSON['my_channels']['type'] == 'group'
						)
						{
							return true;
						}
					}

					return false;
				},
			),
			// ----- GROUP PAGE -----
			// Group Categories Module (channel navigation module)
			array(
				'pagetemplateguid' => 'vbulletin-sgroups93742a5.43676038',
				'widgetguid' => 'vbulletin-widget_cmschannelnavigation-4eb423cfd6dea7.34930875',
			),
			// Latest Group Topics Module (search module)
			array(
				'pagetemplateguid' => 'vbulletin-sgroups93742a5.43676038',
				'widgetguid' => 'vbulletin-widget_search-4eb423cfd6a5f3.08329785',
				// comparison function needed since there might be other
				// search modules on this page template
				'comparisonFunction' => function($existingModuleInstance) use ($assertor)
				{
					$adminconfig = $existingModuleInstance['adminconfig'];
					if (!empty($adminconfig['searchJSON']))
					{
						$searchJSON = json_decode($adminconfig['searchJSON'], true);
						if ($searchJSON)
						{
							$groupsChannelGuid = 'vbulletin-4ecbdf567f3a38.99555306';

							if (!empty($searchJSON['channelguid']) AND $searchJSON['channelguid'] == $groupsChannelGuid)
							{
								return true;
							}

							if (!empty($searchJSON['channel']))
							{
								$channel = $assertor->getRow('vBForum:channel', array('channelid' => $searchJSON['channel']));
								if ($channel['guid'] == $groupsChannelGuid)
								{
									return true;
								}
							}
						}
					}

					return false;
				},
			),
			// ----- GROUP TOPIC PAGE -----
			// Group Summary Module
			array(
				'pagetemplateguid' => 'vbulletin-sgtopic93742a5.43676039',
				'widgetguid' => 'vbulletin-widget_groupsummary-4eb423cfd6dea7.34930863',
			),
		);
		$xml_importer->setWidgetsToAdd($modulesToAdd);

		// only modify these page templates
		$onlyThisGuid = array(
			// groups home
			'vbulletin-4ecbdac93742a5.43676037',
			// groups category page
			'vbulletin-sgcatlist93742a5.43676040',
			// group
			'vbulletin-sgroups93742a5.43676038',
			// group discussion/topic
			'vbulletin-sgtopic93742a5.43676039',
		);
		$xml_importer->importFromFile($pageTemplateFile, $onlyThisGuid);

		$this->show_message($this->phrase['core']['import_done']);
	}

	public function step_3()
	{
		//note that we actually do two updates, but this isn't substantial enough to warrent the overhead
		//of an extra upgrade step.  If this times out the webserver, there are much larger problems.
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], TABLE_PREFIX . 'usergroup', 1, 1));

		$db = vB::getDbAssertor();

		$datastore = vB::getDatastore();
		$permissions = $datastore->getValue("bf_ugp_genericoptions");
		$perm = $permissions['showmemberlist'];

		//first turn the flag on for all groups.
		$db->update('usergroup',
			array(
				vB_dB_Query::BITFIELDS_KEY => array (
					array('field' => 'genericoptions', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $perm),
				)
			),
			vB_dB_Query::CONDITION_ALL
		);

		$groupsToExclude = array(
			vB_Api_UserGroup::UNREGISTERED_SYSGROUPID,
			vB_Api_UserGroup::AWAITINGEMAIL_SYSGROUPID,
			vB_Api_UserGroup::AWAITINGMODERATION_SYSGROUPID,
			vB_Api_UserGroup::BANNED,
		);

		//the remove the flag for the ones that don't pick it up in the install
		$db->update('usergroup',
			array(
				vB_dB_Query::BITFIELDS_KEY => array (
					array('field' => 'genericoptions', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $perm),
				)
			),
			array(
				'systemgroupid' => $groupsToExclude
			)
		);
	}

	public function step_4()
	{
		if ($this->field_exists('language', 'imagesoverride'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'language', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "language DROP COLUMN imagesoverride"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_5()
	{
		require_once(DIR . '/install/unserializefix.php');
		$db = vB::getDbAssertor();

		$result = $db->select('widgetinstance', array(), false, array('adminconfig', 'widgetinstanceid'));
		foreach($result AS $row)
		{
			$data = $row['adminconfig'];
			$widgetinstanceid = $row['widgetinstanceid'];

			if(strlen($data))
			{
				if (unserialize($data) === false)
				{
					$value = vB_Install_UnserializeFix::unserialize($data);
					$value = serialize($value);

					$db->update('widgetinstance', array('adminconfig' => $value), array('widgetinstanceid' => $widgetinstanceid));
				}
			}
		}
	}
}
/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103385 $
|| ####################################################################
\*======================================================================*/
