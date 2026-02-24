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

/**
 * vB_Utility_PageRestore
 *
 * @package vBulletin
 * @access  public
 */
class vB_Utility_PageRestore
{
	//this class shouldn't be in Utility, it doesn't follow the
	//dependecy rules.  So let's use the main trait
	use vB_Trait_NoSerialize;

	/**
	 * Directory to look for the XML files in.
	 * @var string
	 */
	protected $xmldir = '';

	/**
	 * Array of filenames and their versions to display to the user.
	 * @var array
	 */
	protected $fileVersions = array();

	/**
	 * Array of parsed XML information read from files.
	 * @var array
	 */
	protected $xml = array();

	/**
	 * Database assertor object
	 * @var object
	 */
	protected $assertor = null;

	/**
	 * Constructor
	 *
	 * @param string Directory where the XML files are located
	 */
	public function __construct($xmldir)
	{
		$this->xmldir = (string) $xmldir;

		$this->assertor = vB::getDbAssertor();

		$items = array('page', 'route', 'pagetemplate');
		foreach ($items AS $item)
		{
			$this->xml[$item] = $this->loadXmlFile($item);
		}
	}

	/**
	 * Loads and parses an XML file into the $this->xml property.
	 *
	 * @param string The name of the item (page, route, pagetemplate) to load
	 */
	protected function loadXmlFile($itemname)
	{
		$filename = "vbulletin-{$itemname}s.xml";
		$xml = vB_Xml_Import::parseFile("$this->xmldir/$filename");

		$items = array();
		foreach ($xml[$itemname] AS $item)
		{
			$items[$item['guid']] = $item;
		}

		$this->fileVersions[$filename] = $xml['vbversion'];

		return $items;
	}

	/**
	 * Returns the phrased page title based on the GUID
	 *
	 * @param string Page GUID
	 */
	public function getPageTitleByGuid($guid)
	{
		$phraseLib = vB_Library::instance('phrase');
		$phraseVarname = 'page_' . $phraseLib->cleanGuidForPhrase($guid) . '_title';
		$phrases = vB_Api::instanceInternal('phrase')->fetch(array($phraseVarname));

		return $phrases[$phraseVarname];
	}

	/**
	 * Returns the array of file names and versions for display to user.
	 *
	 * @return array File names and versions
	 */
	public function getFileVersions()
	{
		$output = array();
		foreach ($this->fileVersions AS $filename => $version)
		{
			$output[] = "$filename: $version";
		}

		return $output;
	}

	/**
	 * Returns the page array from the XML file, based on the passed GUID
	 *
	 * @param  string Page GUID
	 *
	 * @return array  Array of page information from the XML file
	 */
	public function getPageFromXmlByGuid($guid)
	{
		return $this->xml['page'][$guid];
	}

	/**
	 * Returns an array of all pages from the XML file.
	 *
	 * @param  string Page GUID
	 *
	 * @return array  Array of page information from the XML file
	 */
	public function getPagesFromXml()
	{
		return $this->xml['page'];
	}

	/**
	 * Returns an array of page information for the matching page. The page is matched
	 * based on the route "name". If no route name is available, it is matched
	 * based on the page GUID.
	 *
	 * @param  string Page GUID
	 *
	 * @return array  Array of page information from the database
	 */
	public function getMatchingPageFromDbByXmlGuid($guid)
	{
		$routeGuid = $this->xml['page'][$guid]['routeGuid'];
		if (empty($this->xml['route'][$routeGuid]['name']))
		{
			// match by page guid
			$page = $this->assertor->getRow('page', array('guid' => $guid));
		}
		else
		{
			// match by route name
			$route = $this->assertor->getRow('routenew', array('name' => $this->xml['route'][$routeGuid]['name']));
			$args = unserialize($route['arguments']);
			$page = $this->assertor->getRow('page', array('pageid' => $args['pageid']));
		}

		return $page;
	}

	/**
	 * Returns a route array from the XML file. The route is matched from
	 * the passed Page GUID.
	 *
	 * @param  string Page GUID
	 *
	 * @return array  Array of route information from the XML file
	 */
	public function getXmlRouteByPageGuid($guid)
	{
		$page = $this->xml['page'][$guid];

		return $this->xml['route'][$page['routeGuid']];
	}

	/**
	 * Returns a route array from the database
	 *
	 * @param  int    Route ID
	 *
	 * @return array  Array of route information from the database
	 */
	public function getDbRouteByRouteId($routeid)
	{
		return $this->assertor->getRow('routenew', array('routeid' => $routeid));
	}

	/**
	 * Returns a page template array from the XML file. The page template is matched from
	 * the passed Page GUID.
	 *
	 * @param  string Page GUID
	 *
	 * @return array  Array of page template information from the XML file
	 */
	public function getXmlPageTemplateByPageGuid($guid)
	{
		$page = $this->xml['page'][$guid];

		return $this->xml['pagetemplate'][$page['pageTemplateGuid']];
	}

	/**
	 * Returns a page template array from the database
	 *
	 * @param  int    Page template ID
	 *
	 * @return array  Array of page template information from the database
	 */
	public function getDbPageTemplateByPageTemplateId($pagetemplateid)
	{
		return $this->assertor->getRow('pagetemplate', array('pagetemplateid' => $pagetemplateid));
	}

	/**
	 * Restores a page.
	 *
	 * Specifically, this restores the page, page template, and route
	 * information so it reflects the values present at initial install. This is meant
	 * to be used only on the vBulletin default pages.
	 *
	 * @param  string Page GUID
	 * @param  bool   Print the Page title or not
	 */
	public function restorePage($guid, $printMessage = true)
	{
		$xmlpage = $this->xml['page'][$guid];
		$xmlroute = $this->getXmlRouteByPageGuid($xmlpage['guid']);
		$xmlpagetemplate = $this->getXmlPageTemplateByPageGuid($xmlpage['guid']);

		$dbpage = $this->getMatchingPageFromDbByXmlGuid($xmlpage['guid']);
		$dbroute = $this->getDbRouteByRouteId($dbpage['routeid']);
		$dbpagetemplate = $this->getDbPageTemplateByPageTemplateId($dbpage['pagetemplateid']);

		if ($printMessage)
		{
			echo $xmlpage['title'];
		}

		// delete existing records
		$this->assertor->delete('page', array('guid' => $xmlpage['guid']));
		$this->assertor->delete('pagetemplate', array('guid' => $xmlpagetemplate['guid']));
		$this->assertor->delete('routenew', array('guid' => $xmlroute['guid']));

		// remove name from current db route so xml route can be restored w/o an index conflict
		if ($dbroute['guid'] != $xmlroute['guid'])
		{
			$this->assertor->update('routenew', array('name' => vB_dB_Query::VALUE_ISNULL), array('routeid' => $dbroute['routeid']));
		}

		// restore pagetemplate record
		$options = vB_Xml_Import::OPTION_OVERWRITE;
		$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', $options);
		$xml_importer->importFromFile("$this->xmldir/vbulletin-pagetemplates.xml", $xmlpagetemplate['guid']);
		$xml_importer->replacePhrasePlaceholdersInWidgetConfigs();

		// restore page record
		$options = vB_Xml_Import::OPTION_OVERWRITE;
		$xml_importer = new vB_Xml_Import_Page('vbulletin', $options);
		$xml_importer->importFromFile("$this->xmldir/vbulletin-pages.xml", $xmlpage['guid']);

		// restore route record
		$options = vB_Xml_Import::OPTION_OVERWRITE;
		$xml_importer = new vB_Xml_Import_Route('vbulletin', $options);
		$xml_importer->importFromFile("$this->xmldir/vbulletin-routes.xml", $xmlroute['guid']);

		// update page route
		$xml_importer = new vB_Xml_Import_Page('vbulletin', 0);
		$parsedXML = $xml_importer->parseFile("$this->xmldir/vbulletin-pages.xml");
		$xml_importer->updatePageRoutes($parsedXML);

		// get the new route
		$newRoute = $this->assertor->getRow('routenew', array('guid' => $xmlroute['guid']));

		// set previous db route to 301 redirect
		if ($dbroute['guid'] != $xmlroute['guid'])
		{
			$this->assertor->update('routenew', array('redirect301' => $newRoute['routeid']), array('routeid' => $dbroute['routeid']));
		}

		// update node routeid
		$this->assertor->update('vbForum:node', array('routeid' => $newRoute['routeid']), array('routeid' => $dbroute['routeid']));

		// clear cache
		vB_Cache::resetAllCache();
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
