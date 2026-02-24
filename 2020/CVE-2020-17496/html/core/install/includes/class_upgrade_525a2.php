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

class vB_Upgrade_525a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '525a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.5 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.5 Alpha 1';

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

	/*
	 * Steps 1 ~ 3
	 * Change 'pmchat' product from route, page, & pagetemplate records. This was left over from
	 * when it used to be in its own product during dev, but it's been part of vbulletin core before release.
	 * We only update the route, page & pagetemplate records, not widget, widgetdef, or phrase records.
	 * `widget` has product = vbulletin for the pmchat_widget_chat, because the XML file was imported with vB_Xml_Import_Widget::productid = 'vbulletin'
	 * (see saveWidget() function)
	 * widget importer updates widgetdefinition in final upgrade.
	 * Similarly, the page & pagetemplate imports all take care of replacing the phrase records for us in final upgrade.
	 */
	public function step_1()
	{
		// hard coded in vbulletin-routes.xml
		$guid = 'vbulletin-pmchat-route-chat-573cbacdc65943.65236568';
		$assertor = vB::getDbAssertor();
		$row = $assertor->getRow('routenew', array('guid' => $guid));
		if (!empty($row['product']) AND $row['product'] == 'pmchat')
		{
			$this->show_message(sprintf($this->phrase['version']['525a2']['fixing_product_for_pmchat_table_x'], 'routenew'));
			$assertor->assertQuery('routenew',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array('guid' => $guid),
					'product' => 'vbulletin'
				)
			);
		}
		else
		{
			// we're okay.
			$this->skip_message();
			return;
		}
	}

	public function step_2()
	{
		// hard coded in vbulletin-pages.xml
		$guid = 'vbulletin-pmchat-page-chat-573cba8f1d2283.90944371';
		$assertor = vB::getDbAssertor();
		$row = $assertor->getRow('page', array('guid' => $guid));
		if (!empty($row['product']) AND $row['product'] == 'pmchat')
		{
			$this->show_message(sprintf($this->phrase['version']['525a2']['fixing_product_for_pmchat_table_x'], 'page'));
			$assertor->assertQuery('page',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array('guid' => $guid),
					'product' => 'vbulletin'
				)
			);
		}
		else
		{
			// we're okay.
			$this->skip_message();
			return;
		}
	}

	public function step_3()
	{
		// hard coded in vbulletin-pagetemplates.xml
		$guid = 'vbulletin-pmchat-pagetemplate-chat-573ca81b74e5b0.79208063';
		$assertor = vB::getDbAssertor();
		$row = $assertor->getRow('pagetemplate', array('guid' => $guid));
		if (!empty($row['product']) AND $row['product'] == 'pmchat')
		{
			$this->show_message(sprintf($this->phrase['version']['525a2']['fixing_product_for_pmchat_table_x'], 'pagetemplate'));
			$assertor->assertQuery('pagetemplate',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array('guid' => $guid),
					'product' => 'vbulletin'
				)
			);
		}
		else
		{
			// we're okay.
			$this->skip_message();
			return;
		}
	}

	/*
	 *	If widgetinstance record is missing for pmchat, re-load the pagetemplate.
	 */
	function step_4()
	{
		$assertor = vB::getDbAssertor();
		$pagetemplate = $assertor->getRow('pagetemplate', array('guid' => 'vbulletin-pmchat-pagetemplate-chat-573ca81b74e5b0.79208063'));
		$widget = $assertor->getRow('widget', array('guid' => 'vbulletin-pmchat-widget-chat-573cb2b3a78a93.12390691'));
		$widgetinstance = $assertor->getRow('widgetinstance', array('pagetemplateid' => $pagetemplate['pagetemplateid']));
		// if pagetemplate is empty, we might be a fresh upgrade and not actually have any pmchat related stuff...
		if (!empty($pagetemplate) AND
			(
				empty($widget) OR
				empty($widgetinstance) OR 	// we've only seen this case, and only in upgradeTests.
				($widgetinstance['widgetid'] != $widget['widgetid'])
			)
		)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-pagetemplates.xml'));


			$pageTemplateFile = DIR . '/install/vbulletin-pagetemplates.xml';
			if (!($xml = file_read($pageTemplateFile)))
			{
				$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pagetemplates.xml'), self::PHP_TRIGGER_ERROR, true);
				return;
			}


			// TODO: there might be some upgrades in which we do want to add some widgetinstances
			$options = (vB_Xml_Import::OPTION_OVERWRITE | vB_Xml_Import::OPTION_ADDWIDGETS );
			$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', $options);
			$onlyThisGuid = 'vbulletin-pmchat-pagetemplate-chat-573ca81b74e5b0.79208063';
			$xml_importer->importFromFile($pageTemplateFile, $onlyThisGuid);
			$this->show_message($this->phrase['core']['import_done']);


		}
		else
		{
			// we're okay.
			$this->skip_message();
			return;
		}
	}

	public function step_5()
	{
		$this->skip_message();
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
