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

class vB_Xml_Export_Page extends vB_Xml_Export
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
		
		$xml->add_group('pages');
		
		$pageTable = $this->db->fetchTableStructure('page');
		$pageTableColumns = array_diff($pageTable['structure'], array('guid', 'routeid', 'pagetemplateid', 'parentid', $pageTable['key']));
		
		$pages = $this->db->assertQuery('getPageInfoExport', array('productid' => $this->productid));
		
		if (!empty($pages))
		{
			foreach ($pages AS $page)
			{
				$xml->add_group('page', array('guid' => $page['guid']));
				foreach ($pageTableColumns AS $column)
				{
					if ($page[$column] != NULL)
					{
						$xml->add_tag($column, $page[$column]);
					}
				}
				$xml->add_tag('parentGuid', $page['parentGuid']);
				$xml->add_tag('pageTemplateGuid', $page['pageTemplateGuid']);
				$xml->add_tag('routeGuid', $page['routeGuid']);
				$xml->close_group();
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
