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

class vB_Xml_Export_Widget extends vB_Xml_Export
{
	public static function createGUID($record, $source = 'vbulletin')
	{
		return vB_GUID::get("$source-{$record['template']}-");
	}

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

		$xml->add_group('widgets');

		$widgetTable = $this->db->fetchTableStructure('widget');
		$widgetTableColumns = array_diff($widgetTable['structure'], array('guid', $widgetTable['key']));

		$widgets = $this->db->assertQuery('widget', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('product' => $this->productid)
		));

		// parent widget guid lookup table
		$widgetGuidInfo = $this->db->assertQuery('widget', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('widgetid', 'guid')
		));
		$widgetIdToGuid = array();
		foreach ($widgetGuidInfo AS $one)
		{
			$widgetIdToGuid[$one['widgetid']] = $one['guid'];
		}
		unset($widgetGuidInfo, $one);

		if (!empty($widgets))
		{
			foreach ($widgets AS $widget)
			{
				unset($widget['title']);
				$widgetInfo[$widget[$widgetTable['key']]] = $widget;
			}

			if (!empty($widgetInfo))
			{
				$widgetDefinitions = $this->db->assertQuery('widgetdefinition', array('widgetid' => array_keys($widgetInfo)));

				if (!empty($widgetDefinitions))
				{
					$definitionTable = $this->db->fetchTableStructure('widgetdefinition');
					$definitionTableColumns = array_diff($definitionTable['structure'], array('guid', $widgetTable['key'], $definitionTable['key']));

					foreach($widgetDefinitions AS $widgetDefinition)
					{
						unset($widgetDefinition['label']);
						$widgetInfo[$widgetDefinition[$widgetTable['key']]]['definitions'][] = $widgetDefinition;
					}
				}

				foreach ($widgetInfo AS $widget)
				{
					$xml->add_group('widget', array('guid' => $widget['guid']));
					foreach ($widgetTableColumns AS $column)
					{
						if ($widget[$column] != NULL)
						{
							// special case parentid and change it to parentguid
							if ($column == 'parentid')
							{
								if ($widget[$column] > 0 AND !empty($widgetIdToGuid[$widget[$column]]))
								$xml->add_tag('parentguid', $widgetIdToGuid[$widget[$column]]);
							}
							else
							{
								$xml->add_tag($column, $widget[$column]);
							}
						}
					}

					if (isset($widget['definitions']) AND !empty($widget['definitions']))
					{
						$xml->add_group('definitions');

						foreach ($widget['definitions'] AS $definition)
						{
							$xml->add_group('definition');

							foreach($definitionTableColumns AS $column)
							{
								if ($definition[$column] != NULL)
								{
									$xml->add_tag($column, $definition[$column]);
								}
							}

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
