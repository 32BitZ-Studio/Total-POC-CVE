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

class vB_Xml_Export_PageTemplate extends vB_Xml_Export
{
	public function getXml(vB_XML_Builder &$xml = NULL)
	{
		if (empty($xml))
		{
			$xml = new vB_XML_Builder();
			$returnString = TRUE;
		}
		else
		{
			$returnString = FALSE;
		}

		$xml->add_group('pagetemplates');

		$pageTemplateTable = $this->db->fetchTableStructure('pagetemplate');
		$pageTemplateTableColumns = array_diff($pageTemplateTable['structure'], array('guid', $pageTemplateTable['key']));

		$widgetInstanceTable = $this->db->fetchTableStructure('widgetinstance');
		$widgetInstanceTableColumns = array_diff($widgetInstanceTable['structure'], array('guid', 'widgetid', 'pagetemplateid', $widgetInstanceTable['key']));

		$pageTemplates = $this->db->assertQuery('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('product' => $this->productid)
		));

		$screenLayouts = $this->db->getRows('screenlayout', array(), false, 'screenlayoutid');

		if (!empty($pageTemplates))
		{
			foreach ($pageTemplates AS $pageTemplate)
			{
				$info[$pageTemplate[$pageTemplateTable['key']]] = $pageTemplate;
			}

			if (!empty($info))
			{
				// fetch widget instances
				$widgetsInfo = array();
				$widgetInstances = $this->db->getRows('widgetinstance', array('pagetemplateid' => array_keys($info)));
				foreach($widgetInstances AS $widgetInstance)
				{
					$info[$widgetInstance['pagetemplateid']]['widgets'][$widgetInstance['widgetinstanceid']] = $widgetInstance;
					$widgetsInfo[$widgetInstance['widgetid']] = '';
				}

				// fetch widget titles
				if (!empty($widgetsInfo))
				{
					$widgets = $this->db->getRows('widget', array('widgetid' => array_keys($widgetsInfo)));
					foreach($widgets AS $widget)
					{
						$widgetsInfo[$widget['widgetid']] = $widget['guid'];
					}
				}

				// create XML
				foreach ($info AS $pageTemplate)
				{
					$xml->add_group('pagetemplate', array('guid' => $pageTemplate['guid']));

					// adding pagetemplate elements
					foreach ($pageTemplateTableColumns AS $column)
					{
						if ($pageTemplate[$column] != NULL)
						{
							if ($column == 'screenlayoutid')
							{
								$screenLayoutId = $pageTemplate[$column];

								if (!empty($screenLayouts[$screenLayoutId]) AND !empty($screenLayouts[$screenLayoutId]['guid']))
								{
									$xml->add_tag('screenlayoutguid', $screenLayouts[$screenLayoutId]['guid']);
								}
								else
								{
									$xml->add_tag($column, $pageTemplate[$column]);
								}
							}
							else
							{
								$xml->add_tag($column, $pageTemplate[$column]);
							}
						}
					}

					// adding widgetinstances
					if (isset($pageTemplate['widgets']) AND !empty($pageTemplate['widgets']))
					{
						$xml->add_group('widgets');

						foreach ($pageTemplate['widgets'] AS $widgetInstance)
						{
							$xml->add_group('widgetinstance');

							foreach($widgetInstanceTableColumns AS $column)
							{
								$xml->add_tag($column, $widgetInstance[$column]);
							}
							// add widget title
							$xml->add_tag('widgetguid', $widgetsInfo[$widgetInstance['widgetid']]);

							$xml->close_group();
						}

						$xml->close_group();
					}

					$xml->close_group();
				}
			}
		}

		$xml->close_group();

		if ($returnString)
		{
			return $xml->fetch_xml();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
