<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

/**
 * vB_Api_PageTemplate
 *
 * @package vBApi
 * @access public
 */
class vB_Api_PageTemplate extends vB_Api
{
	/**
	 * Returns a list of all page templates and widget instances associated with them.
	 *
	 * @param  int   The pagetemplateid for the current page (when editing)
	 *
	 * @return array An array of pagetemplates. Each array element contains the fields
	 *               from the pagetemplate table, a 'title' element, and a 'widgetinstances'
	 *               element. Each element in 'widgetinstances' contains the fields from
	 *               the widgetinstance table, and a 'title' element.
	 */
	public function fetchPageTemplateList($pagetemplateid)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$pagetemplateid = (int) $pagetemplateid;
		if ($pagetemplateid < 0)
		{
			$pagetemplateid = 0;
		}

		$db = vB::getDbAssertor();

		// get all page templates that are not in the process of being created
		// always return the current page's page template, regardless
		$values = array('pagetemplateid' => $pagetemplateid);
		$result = $db->assertQuery('fetch_page_template_list', $values, 'title');

		$phraseLib = vB_Library::instance('phrase');
		$phrasestofetch = array();
		foreach ($result AS $row)
		{
			$phrasestofetch[] = 'pagetemplate_' . $phraseLib->cleanGuidForPhrase($row['guid']) . '_title';
		}
		$vbphrases = vB_Api::instanceInternal('phrase')->fetch(array_unique($phrasestofetch));


		$pageTemplates = array();
		foreach ($result AS $row)
		{
			$guidforphrase = $phraseLib->cleanGuidForPhrase($row['guid']);
			$phrasename = 'pagetemplate_' . $guidforphrase . '_title';

			if (!empty($vbphrases[$phrasename]))
			{
				$row['title'] = $vbphrases[$phrasename];
			}

			$pageTemplates[$row['pagetemplateid']] = $row;
		}

		foreach ($pageTemplates AS $k => $v)
		{
			$pageTemplates[$k]['widgetinstances'] = array();
		}

		$widgets = $db->getRows('widget', array(), '', 'widgetid');

		$widgetInstances = $db->getRows('widgetinstance', array(), array('displaysection', 'displayorder'));
		foreach ($widgetInstances AS $widgetInstance)
		{
			$pageTemplateId = $widgetInstance['pagetemplateid'];
			if (isset($pageTemplates[$pageTemplateId]))
			{
				$widgetInstance['title'] = '';
				$pageTemplates[$pageTemplateId]['widgetinstances'][] = $widgetInstance;
			}
		}

		// remove the page template ID as the array indices
		return array_values($pageTemplates);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
