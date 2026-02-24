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

class vB_Upgrade_514b3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '514b3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.4 Beta 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.4 Beta 2';

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
	* Step #1 - Import screenlayoutids. This is required before step_2(). VBV-13771
	*
	*/
	function step_1()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'screenlayout', 1, 1),
			'screenlayout',
			'sectiondata',
			'text',
			array('null' => false, 'default' => '')
		);

		$this->execute();

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_5();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'screenlayout'));
	}

	/**
	* Step #2 - Fix pagetemplate records with missing screenlayoutids. VBV-13771
	*
	*/
	function step_2()
	{
		$assertor = vB::getDbAssertor();

		$fixThese = $assertor->getRows('pagetemplate', array('screenlayoutid' => 0));

		if (empty($fixThese))
		{
			$this->skip_message();
			return;
		}

		$this->show_message($this->phrase['version']['514b3']['fixing_pagetemplate_missing_screenlayoutid']);

		// If we're in debug mode, this step will throw errors or output notices if broken database records are found that cannot
		// be fixed by this step. The point is to catch any errors pagetemplate add/update/delete in development.
		$config = vB::getConfig();

		// Let's go through the pagetemplates file & grab the GUIDs, so we don't have to make a hard-coded list that might need
		// to be updated manually in the future.
		$pageTemplateFile = DIR . '/install/vbulletin-pagetemplates.xml';
		if (!($xml = file_read($pageTemplateFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pagetemplates.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}
		$pageTemplateParsed = vB_Xml_Import::parseFile($pageTemplateFile);

		// Translates pagetemplate's GUID to screenlayout's GUID
		$pagetemplateGuidToScreenlayoutGuid = array();
		// Hold all unique screenlayoutguids so that we can fetch their screenlayoutids from the `screenlayout` table,
		// then check that ALL screenlayoutids exist in the database.
		$screenlayoutGuidsToFetch = array();
		foreach ($pageTemplateParsed['pagetemplate'] AS $key => $pagetemplateData)
		{
			if (isset($pagetemplateData['guid']) AND isset($pagetemplateData['screenlayoutguid']))
			{
				$pagetemplateGuidToScreenlayoutGuid[$pagetemplateData['guid']] = $pagetemplateData['screenlayoutguid'];
				$screenlayoutGuidsToFetch[$pagetemplateData['screenlayoutguid']] = $pagetemplateData['screenlayoutguid'];
			}
		}


		/* I could probably create a temp table and do fancy a triple join update, but I don't know if that'd be any better
		 * than doing these foreach loops in PHP. There are only like 40 pagetemplate records to update (if there are more
		 * records, chances are they're custom records saved in a previous vB5 install meaning they never hit this issue
		 * in the first place) so I don't foresee an upgrade performance issue.
		 */

		$layouts = $assertor->getRows('screenlayout', array('guid' => $screenlayoutGuidsToFetch));
		$screenlayoutGuidsToId = array();
		foreach ($layouts AS $screenlayoutRecord)
		{
			$guid = $screenlayoutRecord['guid'];
			$id = $screenlayoutRecord['screenlayoutid'];
			$screenlayoutGuidsToId[$guid] = $id;
			unset($screenlayoutGuidsToFetch[$guid]);
		}

		if (!empty($screenlayoutGuidsToFetch))
		{
			/*
			 * I haven't actually hit this error, but I'm putting it here because I'm paranoid possibly due to being
			 * either slightly too deprived of or overdosed on coffee.
			 *
			 * If we ran $this->step_1() and we're STILL missing some screenlayout records, we're in some trouble.
			 *
			 * Time Capsule Message @ Future Dev(s):
			 * If anyone needs to look at this in the future, it probably means that either a screenlayoutguid that was
			 * added to the vbulletin-pagetemplates XML file is missing its component in the vbulletin-screenlayouts
			 * XML file, or the import step (currently final upgrade's step_5()) is broken. If it's the first issue,
			 * go find the person who edited the pagetemplates file & request that they update the screenlayouts file.
			 * If it's the latter, you'll have to figure out what broke with the importer and fix it. The importer is
			 * @ core/vb/xml/import/screenlayout.php .
			 * Those are the best guesses I have at the moment for why this step might be unhappy. Good luck.
			 */
			$guidString = implode(", \n ", $screenlayoutGuidsToFetch); // ATM i don't see a reason to escape this, as guids are pulled from internal FILES, not DB/user.
			$this->add_error(sprintf($this->phrase['version']['514b3']['missing_screenlayout_guids_x'], $guidString), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$updatedata = array();
		// notices/warnings for catching potential bugs in development. They will only be used while in debug mode.
		$notices = array();
		$warnings = array();
		foreach ($fixThese AS $pagetemplateRecord)
		{
			$pagetemplateGuid = $pagetemplateRecord['guid'];

			// there could be 2 cases. One is that
			if (empty($pagetemplateGuid))
			{
				// apparently there can be pagetemplate records with NULL guids and empty screenlayoutids, often also missing everything but the pagetemplateid.
				// In that case, let's ignore them but notify the installer.
				$notices[$pagetemplateRecord['pagetemplateid']] = intval($pagetemplateRecord['pagetemplateid']);
				continue;
			}


			/*

			$guid = $screenlayoutRecord['guid'];
			$id = $screenlayoutRecord['screenlayoutid'];
			$screenlayoutGuidsToId[$guid] = $id;
			 */
			if (!isset($pagetemplateGuidToScreenlayoutGuid[$pagetemplateGuid]))
			{
				/*
				 * Another error that currently doesn't happen, but catching just in case.
				 *
				 * Time Capsule Message @ Future Dev(s):
				 * If you hit this, you have a pagetemplate record in DB with screenlayoutid = 0, but it's not
				 * a default pagetemplate record that exists in the vbulletin-pagetemplates XML file.
				 * My best guess as to why this could happen is that someone added a new pagetemplate to the
				 * vbulletin-pagetemplates XML file but forgot to specify a valid screenlayoutguid while
				 * inserting the pagetemplate record into the DB manually instead of going through final_upgrade.
				 *
				 * If this isn't a newly added default pagetemplate record, and you don't care that its
				 * screenlayoutid is 0, you could try ignoring this error (comment out below).
				 *
				 * UPDATE 2014-11-03:
				 * The upgrade of live forum hit this error. Upon checking the DB, I saw that they had NULL guid,
				 * so I added a continue; with a notice for those records so that the admin may review the DB &
				 * delete them if they like.
				 * With the above change, if we got to this point, that means that they have 0 screenlayoutid,
				 * but a not-empty, unknown guid. That is, a custom page without a screenlayoutid, which is unusable.
				 * I'm going to change this from an error to a warning. The reason I'm changing it from an error is that
				 * the forum *probably* can continue living without this record, as it's not a default one. However,
				 * the guid indicates that it's a more recent record rather than an obsolte one, and it might indicate
				 * an error in the page save or delete code that we will want to know about & fix. As such I'm going to
				 * make this a warning instead of a notice like the above.
				 */
				$warnings[$pagetemplateGuid] = vB_String::htmlSpecialCharsUni($pagetemplateGuid);
				continue;
			}
			$screenlayoutGuid = $pagetemplateGuidToScreenlayoutGuid[$pagetemplateGuid];
			$screenlayoutId = $screenlayoutGuidsToId[$screenlayoutGuid];

			// add to map for bulk update query
			$updatedata[] = array(
				'pagetemplateid' => intval($pagetemplateRecord['pagetemplateid']),
				'screenlayoutid' => intval($screenlayoutId),
			);
		}


		if (!empty($updatedata))
		{
			$assertor->assertQuery('vBInstall:updatePagetemplateScreenlayoutid', array('pagetemplaterecords' => $updatedata));
		}

		if (!empty($config['Misc']['debug']))
		{
			if (!empty($notices))
			{
				// These are probably obsolete records. Let the admin that they can delete them.
				$idsString = implode(", \n ", $notices); // ATM i don't see a reason to escape this, as guids are pulled from internal files.
				$this->add_message(sprintf($this->phrase['version']['514b3']['notice_empty_guid_x'], $idsString));
			}

			if (!empty($warnings))
			{
				$idsString = implode(", \n ", $warnings); // ATM i don't see a reason to escape this, as guids are pulled from internal files.
				$this->add_message(sprintf($this->phrase['version']['514b3']['warning_undefined_pagetemplateguid_x'], $idsString));
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
