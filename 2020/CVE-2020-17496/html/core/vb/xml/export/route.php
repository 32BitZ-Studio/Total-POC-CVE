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

class vB_Xml_Export_Route extends vB_Xml_Export
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
		
		$xml->add_group('routes');
		
		$routeTable = $this->db->fetchTableStructure('routenew');
		$routeTableColumns = array_diff($routeTable['structure'], array('guid', 'contentid', $routeTable['key']));
		
		$routes = $this->db->assertQuery('routenew', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('product' => $this->productid)
		));
		
		if (!empty($routes))
		{
			foreach ($routes AS $route)
			{
				$routeClass = (isset($route['class']) AND !empty($route['class']) AND class_exists($route['class'])) ? $route['class'] : vB5_Route::DEFAULT_CLASS;
				$route['arguments'] = call_user_func(array($routeClass, 'exportArguments'), $route['arguments']);

				$xml->add_group('route', array('guid' => $route['guid']));
				foreach ($routeTableColumns AS $column)
				{
					if ($route[$column] != NULL)
					{
						$xml->add_tag($column, $route[$column]);
					}
				}
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
