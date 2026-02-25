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

class vB_Upgrade_520a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '520a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.0 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.0 Alpha 2';

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
	 * Add style.styleattributes.
	 * I don't believe this will take too long, as I am not expecting any site to have hundreds of styles.
	 */
	public function step_1()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'style', 1, 1),
			'style',
			'styleattributes',
			'tinyint',
			array('null' => false, 'default' => vB_Library_Style::ATTR_DEFAULT)
		);
	}

	/*
	 * Add the write-protected theme parent, and move the current theme parent under it, and make it editable.
	 */
	public function step_2()
	{
		$this->show_message($this->phrase['version']['520a3']['adding_editable_theme_parent']);

		vB_Upgrade::createAdminSession();
		$xml_importer = new vB_Xml_Import_Theme();
		$themeGrandParent = $xml_importer->getDefaultGrandParentTheme();
		$themeParent = $xml_importer->getDefaultParentTheme();
		$needsUpdates = (
			$themeParent['parentid'] != $themeGrandParent['styleid'] ||
			$themeParent['styleattributes'] != vB_Library_Style::ATTR_DEFAULT
		);
		if ($needsUpdates)
		{
			$this->show_message(sprintf($this->phrase['version']['520a3']['setting_attributes_for_style'], $themeParent['title'], $themeParent['styleid']));
			$assertor = vB::getDbAssertor();
			$assertor->update('vBForum:style',
				array(// update values
					'parentid' => $themeGrandParent['styleid'], // Keep in sync with theme importer's getDefaultParentTheme()
					'styleattributes' => vB_Library_Style::ATTR_DEFAULT,
				),
				array(// update conditions
					'guid' => vB_Xml_Import_Theme::DEFAULT_PARENT_GUID
				)
			);

			$this->doStyleCleanUp($themeParent);
		}
	}

	/*
	 * Create temporary table to hold style record info as we shift things around
	 */
	public function step_3()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		// Hope this query doesn't break, because this will only run once.
		if (!$this->tableExists('style_temporary_helper'))
		{
			// Add a helper table to hold some temp information
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'style_temporary_helper'),
				"CREATE TABLE " . TABLE_PREFIX . "style_temporary_helper (
					styleid SMALLINT UNSIGNED NOT NULL DEFAULT '0',
					parentid SMALLINT NOT NULL DEFAULT '0',
					guid char(150) NULL DEFAULT NULL UNIQUE,
					children VARCHAR(250) NOT NULL DEFAULT ''
				) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
			);
		}
		else
		{
			$this->skip_message();
			return;
		}
	}

	public function step_4()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		if (!$this->tableExists('style_temporary_helper'))
		{
			// Not sure if this could ever happen, but if it does, let's print a warning and die.
			$this->echo_phrase(sprintf($this->phrase['version']['520a3']['run_step_x_first'], 3));
			exit(1); // do not log this step, as it needs to run again.
		}

		/*
			Only the themes that have XMLs will be overwritten by upgrade. Let's go through the files
			and grab each GUID
		 */
		vB_Upgrade::createAdminSession();

		$assertor = vB::getDbAssertor();
		$guids = array();
		$themeFiles = $this->grabThemeFiles();
		foreach ($themeFiles AS $filename)
		{
			$xml = vB_Xml_Import::parseFile($filename);
			if (!empty($xml['guid']))
			{
				$guids[$xml['guid']] = $xml['guid'];
			}
		}

		$insertThese = array();
		$styleidsByParent = array();
		$addChildren = array();
		$styles = $assertor->getRows('style'); // grab all styles
		if (!empty($styles))
		{
			foreach ($styles AS $row)
			{
				if (!empty($row['guid']) AND isset($guids[$row['guid']]))
				{
					$insertThese[$row['guid']] = array(
						$row['styleid'],
						$row['parentid'],
						$row['guid'],
					);
					$addChildren[$row['guid']] = $row['styleid'];
				}
				$styleidsByParent[$row['parentid']][$row['styleid']] = $row['styleid'];
			}
		}

		foreach ($addChildren AS $key_guid => $value_styleid)
		{
			$insertThese[$key_guid]['children'] = json_encode($styleidsByParent[$value_styleid]);
		}

		// store all data
		$try = $assertor->assertQuery(
			'vBInstall:style_temporary_helper',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_MULTIPLEINSERT,
				vB_dB_Query::FIELDS_KEY => array('styleid', 'parentid', 'guid', 'children'),
				vB_dB_Query::VALUES_KEY => $insertThese
			)
		);

		// break GUIDs
		$assertor->update(
			'style',
			array( // values
				'guid' => vB_dB_Query::VALUE_ISNULL,
			),
			array( // conditions
				'guid' => $guids,
			));

		$this->show_message($this->phrase['version']['520a3']['added_temporary_theme_data']);
		$this->long_next_step();
	}


	public function step_5($data = null)
	{
		// This can actually run more than once since it just imports themes, but it'll be a waste of time to do it again
		// so let's just limit it to one run.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$result = $finalUpgrader->importThemes($data);
		if (!empty($result['messages']))
		{
			foreach ($result['messages'] AS $msg)
			{
				$this->show_message($msg);
			}
		}

		if (isset($result['startat']))
		{
			return array('startat' => $result['startat'] );
		}
	}

	public function step_6()
	{
		$this->long_next_step();
	}


	public function step_7($data = null)
	{
		vB_Upgrade::createAdminSession();

		if (!$this->tableExists('style_temporary_helper'))
		{
			$this->skip_message();
			return;
		}

		$assertor = vB::getDbAssertor();

		$chosenOne = $assertor->getRow('vBInstall:style_temporary_helper');
		if (empty($chosenOne))
		{
			$this->run_query(
				sprintf($this->phrase['core']['dropping_old_table_x'], TABLE_PREFIX . "style_temporary_helper"),
				"DROP TABLE IF EXISTS " . TABLE_PREFIX . "style_temporary_helper"
			);

			// clear stylecache & rebuild datastore.stylecache from DB, rebuild template list info etc. Basically
			// everything we do not want to do by hand.
			vB_Library::instance('style')->buildAllStyles(0, 0, true);

			$this->show_message($this->phrase['core']['process_done']);
			return;
		}

		if (!isset($data['startat']))
		{
			$data['startat'] = 0;
		}

		$data['startat']++; // startat has no real significance, it's just a way to allow us to loop this step.

		/*
		Here's the sketchy back-alley magic.
		We broke the guids in the previous step so that new theme parents will be imported.
		Now, we go through the old theme style records, and replace each new editable theme child with the
		old record by stealing its guid & parentid, then nuking the new record.
		This is all so that any old theme(s) that was set as a page/channel/user default will not break,
		and the theme customizations (ATM only css_additional & titleimage) will be maintained.
		*/
		$protectedStyle = $assertor->getRow('style', array('guid' => $chosenOne['guid']));
		$editableChild = $assertor->getRow('style', array('parentid' => $protectedStyle['styleid'], 'styleattributes' => vB_Library_Style::ATTR_DEFAULT));
		if (empty($editableChild))
		{
			// This should never happen, but who knows with wild databases out there. Let's just gracefully skip it for now.
			$this->show_message(sprintf($this->phrase['version']['520a3']['warning_theme_child_not_found'], $protectedStyle['title']));
			return $data;
		}

		// There are a bunch of actions that must be done together. Let's wrap them up in a transaction.
		if ($assertor->inTransaction())
		{
			$assertor->rollbackTransaction();
		}
		$assertor->beginTransaction();

		// drop all dupe templates & stylevars except css_additional & site logo
		$assertor->assertQuery(
			'vBInstall:deleteDupeThemeTemplates',
			array('styleid' => $chosenOne['styleid'])
		);
		$assertor->assertQuery(
			'vBInstall:deleteDupeThemeStylevars',
			array('styleid' => $chosenOne['styleid'])
		);

		// Keep css_additional & titleimage only if they're different from the parent's
		$parentTemplate = $assertor->getRow('template', array('title' => 'css_additional.css', 'styleid' => $protectedStyle['styleid']));
		$childTemplate = $assertor->getRow('template', array('title' => 'css_additional.css', 'styleid' => $chosenOne['styleid']));
		if (!empty($parentTemplate) AND !empty($childTemplate))
		{
			// this one hasn't changed, just inherit from parent and delete current.
			if ($parentTemplate['template_un'] == $childTemplate['template_un'])
			{
				$assertor->assertQuery(
					'template',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
						'templateid' => $childTemplate['templateid']
					)
				);
			}
		}

		$parentStylevar = $assertor->getRow('stylevar', array('stylevarid' => 'titleimage', 'styleid' => $protectedStyle['styleid']));
		$childStylevar = $assertor->getRow('stylevar', array('stylevarid' => 'titleimage', 'styleid' => $chosenOne['styleid']));
		if (!empty($parentStylevar) AND !empty($childStylevar))
		{
			// this one hasn't changed, just inherit from parent and delete current.
			if ($parentStylevar['value'] == $childStylevar['value'])
			{
				$assertor->assertQuery(
					'template',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
						'stylevarid' => $childStylevar['stylevarid'],
						'styleid' => $childStylevar['styleid']
					)
				);
			}
		}

		// The ephemeral child style has outlived its usefulness, and we're taking its identity. Let's get rid of the evidence.
		$styleApi = vB_Api::instanceInternal('style');
		$styleApi->deleteStyle($editableChild['styleid'], true); // this doesn't work right ATM

		// Steal the GUID of the deleted child,
		$currentRecord = $assertor->getRow('style', array('styleid' => $chosenOne['styleid']));
		$newValues = array(
			'parentid' => $protectedStyle['styleid'],
			'styleattributes' => vB_Library_Style::ATTR_DEFAULT,
			'guid' => $editableChild['guid'],
			'filedataid' => 0,			// refcount cleanup is down below, look down a few lines.
			'previewfiledataid' => 0,	// ''
		);
		$assertor->update('vBForum:style',
			$newValues, // update values
			array(// update conditions
				'styleid' => $chosenOne['styleid']
			)
		);

		// filedata record cleanup. No reason for an unprotected theme to have its own icons.
		if ($currentRecord['filedataid'] > 0)
		{
			vB::getDbAssertor()->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['filedataid']));
		}
		if ($currentRecord['previewfiledataid'] > 0)
		{
			vB::getDbAssertor()->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['previewfiledataid']));
		}

		$cleanStyle = array(
			'styleid' => $currentRecord['styleid'],
			'title' => $currentRecord['title'],
		);
		$this->doStyleCleanUp($cleanStyle);

		// Remove this from the HELPER table
		$assertor->assertQuery(
			'vBInstall:style_temporary_helper',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'guid' => $chosenOne['guid']
			)
		);

		// Done. Let's commit this chunk and move onto the next one.
		$assertor->commitTransaction();

		$this->show_message(sprintf($this->phrase['version']['520a3']['moving_theme_child'], $protectedStyle['title']));
		return $data;
	}


	public function step_8()
	{

		// Place holder to allow iRan() to work properly, as the last step gets recorded as step '0' in the upgrade log for CLI upgrade.

		$this->skip_message();
		return;

	}

	protected function updateParentList($style)
	{
		$styleLib = vB_Library::instance('style');
		// Force parentlist recreation. Some steps in this upgrade will break parentage.
		$parentlist = $styleLib->fetchTemplateParentlist($style['styleid'], true);
		$try = vB::getDbAssertor()->assertQuery('vBForum:updatestyleparent', array(
			'parentlist' => $parentlist,
			'styleid' => $style['styleid']
		));
	}

	protected function doStyleCleanUp($style)
	{
		vB_Upgrade::createAdminSession();
		// Taken from style API's insertStyle(), basically do all the "cleanup" required after a style change.

		$this->updateParentList($style);
		$styleLib = vB_Library::instance('style');
		$styleLib->buildStyle($style['styleid'], $style['title'], array(
				'docss' => 1,
				'dostylevars' => 1,
				'doreplacements' => 1,
				'doposteditor' => 1
		), false);
		$styleLib->buildStyleDatastore();
	}

	protected function grabThemeFiles()
	{
		$themesdir = DIR . '/install/themes/';
		$themeFiles = array();
		foreach (scandir($themesdir) AS $filename)
		{
			if (!is_dir($themesdir . '/' . $filename)
					AND (strtolower(pathinfo($filename, PATHINFO_EXTENSION)) === 'xml')
			)
			{
				$themeFiles[] = $themesdir . $filename;
			}
		}

		return $themeFiles;
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
