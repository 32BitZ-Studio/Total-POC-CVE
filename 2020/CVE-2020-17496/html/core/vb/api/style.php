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
 * vB_Api_Style
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Style extends vB_Api
{
	// TODO: some of these methods shouldn't be public. We should move them to vB_Library_Style instead to avoid exposing them in the API.

	protected $disableWhiteList = array('fetchStyles', 'fetchStyleVars', 'useCssFiles', 'getCssStyleUrlPath');

	protected $library;

	protected $userContext;

	private $cssFileLocation;

	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Style');
	}

	/**
	 *	Get the style from the list of preferences -- will check that the
	 *	desired styles exist and are available for the user to
	 *
	 *	@param array $stylePreference -- various styles in the order we should check them
	 */
	public function getValidStyleFromPreference($stylePreference)
	{
		$styleid =  $this->library->getValidStyleFromPreference($stylePreference);
		return $styleid;
	}

	/**
	 *	Get Style Vars
	 *
	 *	@param array $stylePreference -- various styles in the order we should check them
	 */
	public function fetchStyleVars($stylePreference)
	{
		$styleId = $this->library->getValidStyleFromPreference($stylePreference);

		// fetch style from datastore
		$style = $this->library->fetchStyleByID($styleId);

		if (is_array($style) AND isset($style['newstylevars']))
		{
			return unserialize($style['newstylevars']);
		}
		else
		{
			return false;
		}
	}


	/**
	 * Fetch All styles
	 *
	 * @param 	bool 	$withdepthmark If true, style title will be prepended with depth mark
	 * @param 	bool 	$userselectonly If true, this method returns only styles that allows user to select
	 * @param	mixed	array of options: currently only understands "themes"-includes themes
	 *
	 * @return 	array 	All styles' information
	 */
	public function fetchStyles($withdepthmark = false, $userselectonly = false, $nocache = false, $options = array())
	{
		// todo: if we don't need stylevars, set the second flag to false
		$stylecache = $this->library->fetchStyles($nocache, true, $options);
		$defaultStyleId = vB::getDatastore()->getOption('styleid');

		foreach ($stylecache AS $k => $v)
		{
			if (
				$userselectonly AND !$v['userselect']
				// always treat the default style as selectable even if it's not userselectable
				AND ($v['styleid'] != $defaultStyleId)
			)
			{
				unset($stylecache[$k]);
			}

			if (isset($stylecache[$k]) && $withdepthmark)
			{

				$stylecache[$k]['title_plain'] = $v['title'];
				$stylecache[$k]['title'] = str_repeat('-', $v['depth']) . ' ' . $v['title'];
			}
		}

		// library->fetchStyles() removed read-protected styles.
		return $stylecache;
	}

	/**
	 * Insert style
	 *
	 * @param string $title Style title
	 * @param integer $parentid New parent style ID for the style.
	 * @param boolean $userselect Whether user is able to choose the style.
	 * @param integer $displayorder Display order.
	 * @param string $guid Theme GUID
	 * @param binary $icon Theme icon
	 * @param binary $previewImage Theme preview image
	 *
	 * @return array array('styleid' => newstyleid)
	 */
	public function insertStyle(
		$title,
		$parentid,
		$userselect,
		$displayorder,
		$guid = '',
		$icon = '',
		$previewImage = '',
		$styleattributes = vB_Library_Style::ATTR_DEFAULT,
		$dateline = null
	)
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$result = $this->library->insertStyle($title, $parentid, $userselect, $displayorder, $guid, $icon, $previewImage, $styleattributes, $dateline);
		return array('styleid' => $result);
	}

	/**
	 * Update style
	 *
	 * @param integer $dostyleid Style ID to be updated.
	 * @param string $title Style title.
	 * @param integer $parentid New parent style ID for the style.
	 * @param boolean $userselect Whether user is able to choose the style.
	 * @param integer $displayorder Display order of the style.
	 * @param boolean $rebuild Whether to rebuild style
	 * @param string $guid Theme GUID
	 * @param binary $icon Theme icon
	 * @param boolean $iconRemove Whether to remove the current icon (if there is one, and we're not uploading a new one)
	 * @param binary $previewImage Theme preview image
	 * @param boolean $previewImageRemove Whether to remove the current preview image (if there is one, and we're not uploading a new one)
	 */
	public function updateStyle(
		$dostyleid,
		$title,
		$parentid,
		$userselect,
		$displayorder,
		$guid = '',
		$icon = '',
		$iconRemove = false,
		$previewImage = '',
		$previewImageRemove = false
	)
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$this->library->updateStyle($dostyleid, $title, $parentid, $userselect, $displayorder, $guid, $icon, $iconRemove, $previewImage, $previewImageRemove);

		return true;
	}

	/**
	 * Can this style be deleted
	 *
	 * This will either return an standard success array or will throw and exception
	 * This exists for contexts where we want to confirm the delete before actually doing it, but
	 * don't want to throw and error *after* the delete is confirmed.
	 *
	 * @param int $dostyleid Style ID to be deleted.
	 *
	 * @return array('success' => true);
   */
	public function canDeleteStyle($dostyleid)
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$vboptions = vB::getDatastore()->getValue('options');
		if ($dostyleid == $vboptions['styleid'])
		{
			throw new vB_Exception_Api('cant_delete_default_style');
		}

		$style = $this->library->getStyleById($dostyleid);
		if ($style['userselect'] == 1)
		{
			$db = vB::getDbAssertor();

			//check how many user selectable styles we have.
			$count = $db->getField('style', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
				'userselect' => 1,
			));

			//if this is the last one, don't allow the delete.
			if($count == 1)
			{
				throw new vB_Exception_Api('cant_delete_last_style');
			}
		}

	 	return array('success' => true);
	}

	/**
	 * Delete style
	 *
	 * @param int $dostyleid Style ID to be deleted.
	 */
	public function deleteStyle($dostyleid, $skipRebuild = false)
	{
		//if we get past this function we're good to delete
		$this->canDeleteStyle($dostyleid);

		$db = vB::getDbAssertor();

		//delete the css style directories.  We attempt to do this regardless of wether we are
		//currently writing css to disk (for this or any other style) because we aren't currently
		//cleaning up the css when switching back to db mode.  Even if we fix that we should
		//probably leave it this way for people who already be affected.
		//The delete function properly handles the situation were the directory doesn't exist.
		require_once(DIR . '/includes/adminfunctions_template.php');
		delete_style_css_directory($dostyleid, 'ltr');
		delete_style_css_directory($dostyleid, 'rtl');

		//these could probably be turned into a single multi-table delete query but honestly it's not
		//worth it and those queries can be finicky to deal with.
		$db->assertQuery('template_deletefrom_templatemerge', array('styleid' => $dostyleid));
		$db->delete('style', array('styleid' => $dostyleid));
		$db->delete('templatehistory', array('styleid' => $dostyleid));
		$db->delete('template', array('styleid' => $dostyleid));
		$db->delete('stylevar', array('styleid' => $dostyleid));

		//this is cached so fetching from both this and canDeleteStyle isn't a duplicated query
		$style = $this->library->getStyleById($dostyleid);

		// If style/theme has an icon or preview image, remove it (decrement refcount and let the cron job clean it up)
		// we don't modify publicview here, since this file may be used somewhere else that needs
		// publicview=1, for example as the site header image.
		if ($style['filedataid'] > 0)
		{
			$db->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['filedataid']));
		}

		if ($style['previewfiledataid'] > 0)
		{
			$db->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['previewfiledataid']));
		}

		//update parent info for child styles
		//the "parentlist" is a csv list of the current styleid along with all of the ancestors in order
		//the parent list value here is all kinds of incorrect since it will have the now-removed id of the
		//style we just deleted as well not having the id of the style being updated.  We should either
		//1) Remove the update for the parentlist and convert this to a table query
		//2) Strip the old style id from the list and update the query to prepend the id of each style we
		//	are updating to the list
		//(Note that the the query, as it stands, could be made a table query, but that would complicate
		//implementing option 2)
		//
		//Also note that if the children also have children we don't even attempt to update *their*
		//parentlists here so it's not clear what purpose updating some of the affected parentlists serves
		//It appears that all of this gets cleaned up regardless by the buildAllStyles below, so the
		//likely solution is to just remove the parent list and let the rebuild handle it.

		$db->assertQuery('style_updateparent', array(
			'styleid' =>	$dostyleid,
			'parentid' =>	$style['parentid'],
			'parentlist' =>	$style['parentlist'],
		));

		/*
			Something about below will revert parentlist changes
			during upgrades if the parentlist actually changed.
			It's probably something to do with in-memory variables
			not being cleared properly, but I wasn't able to figure
			it out, so placing a workaround for now.
			Upgrade 520a3 step_7 will call buildAllStyles() on its own
			after it's done, which seems to preserve the parentlist
			changes.
		 */
		if (!$skipRebuild)
		{
			$this->library->buildAllStyles(0, 0);
		}

		return true;
	}

	/**
	* Builds all data from the template table into the fields in the style table
	*
	* @param boolean $renumber -- no longer used, feature has been removed.
	* @param boolean	If true, will fix styles with no parent style specified
	* @param boolean	If true, reset the master cache
	* @param boolean -- true if successful, otherwise throws an exception
	*/
	public function buildAllStyles($renumber = 0, $install = 0, $resetcache = false)
	{
		$usercontext = vB::getUserContext();
		if (
			!$usercontext->hasAdminPermission('canadminstyles') AND
			!$usercontext->hasAdminPermission('canadminads') AND
			!$usercontext->hasAdminPermission('canadmintemplates')
		)
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->buildAllStyles(false, $install, $resetcache);
	}

	public function generateStyle($scheme, $type, $parentid, $title, $displayorder = 1, $userselect = false)
	{
		if (!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		define('NO_IMPORT_DOTS', true);

		$merge = $scheme['primary'];

		if (!empty($scheme['secondary']))
		{
			$merge = array_merge($merge, $scheme['secondary']);
		}

		if (!empty($scheme['complement']))
		{
			$merge = array_merge($merge, $scheme['complement']);
		}

		foreach ($merge as $val)
		{
			$hex[] = $val['hex'];
		}

		switch ($type)
		{
			case 'lps': // Color : Primary and Secondary
				$sample_file = "style_generator_sample_light.xml";
				break;
			case 'lpt': // White : Similar to the current style
				$sample_file = "style_generator_sample_white.xml";
				break;
			case 'gry': // Grey :: Primary 3 and Primary 4 only
				$sample_file = "style_generator_sample_gray.xml";
				break;
			case 'drk': // Dark : Primary 3 and Primary 4 only
			default:// Dark : Default to Dark
				$sample_file = "style_generator_sample_dark.xml";
				break;
		}

		$xmlobj = new vB_XML_Parser(false, DIR . '/includes/xml/' . $sample_file);
		$styledata = $xmlobj->parse();

		if($title === '')
		{
			$title = 'Style ' . time();
		}

		$xml = new vB_XML_Builder();
		$xml->add_group('style', array(
			'name' => $title,
			'vbversion' => vB::getDatastore()->getOption('templateversion'),
			'product' => 'vbulletin',
			'type' => 'custom',
		));
		$xml->add_group('stylevars');

		foreach($styledata['stylevars']['stylevar'] AS $stylevars)
		{
			// The XML Parser outputs 2 values for the value field when one is set as an attribute.
			// The work around for now is to specify the first value (the attribute). In reality
			// the parser shouldn't add a blank 'value' if it exists as an attribute.
			if (!empty($stylevars['colCat']))
			{
				list($group, $nr) = explode('-', $stylevars['colCat']);
				$group = ($group == 'sec' ? 'secondary' : 'primary');
				$stylevars['value'] = '{"color":"#' . $scheme[$group][$nr]['hex'] . '"}';
			}

			$thisValue = json_decode($stylevars['value'], true);

			if (strpos($stylevars['name'], '_border') !== false)
			{
				// @todo, make this inherit the border style & width from the default style?
				$thisValue['width'] = 1;
				$thisValue['units'] = 'px';
				$thisValue['style'] = 'solid';
			}

			$xml->add_tag('stylevar', '', array(
				'name' => htmlspecialchars($stylevars['name']),
				'value' =>  base64_encode(serialize($thisValue)),
			));
		}

		// Close stylevar group
		$xml->close_group();
		// Close style group
		$xml->close_group();

		$doc = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n\r\n";
		$doc .= $xml->output();
		$xml = null;
		$imported = $this->library->importStyleFromXML($doc, $title, $parentid, -1, true, $displayorder, $userselect, true);
		$this->buildAllStyles();
		//xml_import_style($doc, -1, $parentid, $title, $anyversion, $displayorder, $userselect, null, null, true);
		return $imported;
	}

	/**
	 * Gets the css File Location, which only means something if storecssasfiles is on.
	 *
	 * @return	string.
	 */
	private function fetchCssLocation()
	{
		if (!isset($this->cssFileLocation))
		{
			$fileLocation = vB::getDatastore()->getOption('cssfilelocation');

			if (!empty($fileLocation))
			{
				$this->cssFileLocation = ltrim($fileLocation, '/');
			}
			else
			{
				//this shouldn't happen any more, but leave this for now.
				$this->cssFileLocation = 'cache/css';
			}
		}
		return($this->cssFileLocation);
	}

	/**
	 *	Gets the directory for the css on the filestystem
	 *
	 *	@param int $styleid
	 *	@param string $textdir -- either 'ltr' or 'rtl' (unknown values treated as 'rtl')
	 *
	 *	@return array -- array('directory' => string) the full directory path without a trailing slash
	 */
	public function getCssStyleDirectory($styleid, $textdir)
	{
		$styleid = intval($styleid);
		$textdir = strval($textdir);

		$cssDir = $this->fetchCssLocation();
		$styledir = DIR . '/' . $cssDir . '/' . $this->getCssDirname($styleid, $textdir);
		return array('directory' => $styledir);
	}

	/**
	 *	Gets the directory for the css on the filestystem as a url relative to the site root.
	 *
	 *	@param int $styleid
	 *	@param string $textdir -- either 'ltr' or 'rtl' (unknown values treated as 'rtl')
	 *
	 *	@return array -- array('directory' => string) the full directory path without a trailing slash
	 */
	public function getCssStyleUrlPath($styleid, $textdir)
	{
		$styleid = intval($styleid);
		$textdir = strval($textdir);

		$cssDir = $this->fetchCssLocation();
		$styledir = 'core/' . $cssDir . '/' . $this->getCssDirname($styleid, $textdir);
		return array('directory' => $styledir);
	}

	private function getCssDirname($styleid, $textdir)
	{
		return 'style' . str_pad($styleid, 5, '0', STR_PAD_LEFT) . ($textdir == 'ltr' ? 'l' : 'r');
	}

	/**
	 * Returns an array of theme information if the user has permission.
	 * The theme parent style is skipped.
	 *
	 * @return	array 	array where each element contains an array of theme information, eg:
	 *			array(
	 *				"themes" => array(
	 *					0 => array(
	 *						"styleid" => {theme1's styleid}
	 *						"title" => {theme1's title},
	 *						"iconurl" => {URL to theme1's icon},
	 *						"previewurl" => {URL to theme1's preview image (empty if there is no preview image)},
	 *					),
	 *					1 => array(
	 *						"styleid" => {theme2's styleid}
	 *						"title" => {theme2's title},
	 *						"iconurl" => {URL to theme2's icon},
	 *						"previewurl" => {URL to theme2's preview image (empty if there is no preview image)},
	 *					), [...]
	 *				)
	 *			)
	 */
	public function getThemeInfo()
	{
		// must be able to administrate settings (the limited settings
		// perm is sufficient) or styles to use the themes tab in sb.
		if (
			!$this->hasAdminPermission('canadminsettings') AND
			!$this->hasAdminPermission('canadminsettingsall') AND
			!$this->hasAdminPermission('canadminstyles')
		)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$themesQuery = vB::getDbAssertor()->getRows(
			'style',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('styleid', 'parentlist', 'guid', 'title', 'filedataid', 'previewfiledataid', 'styleattributes'),
			),
			array(
				'field' => array('title', 'displayorder'),
				'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC),
			),
			'styleid'
		);

		// If any styles don't have an icon and previewimage, inherit from the nearest
		// parent that has one.
		foreach ($themesQuery AS $k => $v)
		{
			$parentids = explode(',', $v['parentlist']);

			// icon
			if (!$v['filedataid'])
			{
				foreach ($parentids AS $parentid)
				{
					if (isset($themesQuery[$parentid]) AND $themesQuery[$parentid]['filedataid'])
					{
						$themesQuery[$k]['filedataid'] = $themesQuery[$parentid]['filedataid'];
						break;
					}
				}
			}

			// preview image
			if (!$v['previewfiledataid'])
			{
				foreach ($parentids AS $parentid)
				{
					if (isset($themesQuery[$parentid]) AND $themesQuery[$parentid]['previewfiledataid'])
					{
						$themesQuery[$k]['previewfiledataid'] = $themesQuery[$parentid]['previewfiledataid'];
						break;
					}
				}
			}
		}

		$themesList = array();
		$defaultTheme = null;
		$urlPrefix = 'filedata/fetch?filedataid=';
		$defaultIcon = vB::getDatastore()->getOption('frontendurl') . '/images/misc/theme-default.png';
		foreach ($themesQuery AS $theme)
		{
			// skip the default theme parent, since it's only there for organizational
			// purposes and isn't really a theme (it would display the same as the default style)
			if (
				$theme['guid'] == vB_Xml_Import_Theme::DEFAULT_PARENT_GUID
				OR $theme['guid'] == vB_Xml_Import_Theme::DEFAULT_GRANDPARENT_GUID
			)
			{
				continue;
			}

			// Do not return any read-protected styles/themes.
			if (!$this->library->checkStyleReadProtection(null, $theme))
			{
				continue;
			}

			$themeInfo = array(
				'styleid' => $theme['styleid'],
				'title'   => $theme['title'],
				'iconurl' => (!empty($theme['filedataid']) ? $urlPrefix . $theme['filedataid'] : $defaultIcon),
				'previewurl' => (!empty($theme['previewfiledataid']) ? $urlPrefix . $theme['previewfiledataid'] : ''),
			);

			// @TODO - DEFAULT_THEME_GUID is deprecated, the style was removed in VBV-14913
			if ($theme['guid'] === vB_Xml_Import_Theme::DEFAULT_THEME_GUID)
			{
				$defaultTheme = $themeInfo;
			}
			else
			{
				$themesList[] = $themeInfo;
			}
		}

		// ensure the default theme is always at the beginning of the list.
		if ($defaultTheme !== null)
		{
			array_unshift($themesList, $defaultTheme);
		}

		return array('themes' => $themesList);
	}

	/**
	 * Sets the site default style
	 *
	 * @param	int	Styleid to set as default
	 *
	 * @return	array	Array containing the bool 'success' element
	 */
	public function setDefaultStyle($styleid)
	{
		// must be able to administrate settings (the limited settings
		// perm is sufficient) or styles to set default theme/style
		if (
			!$this->hasAdminPermission('canadminsettings') AND
			!$this->hasAdminPermission('canadminsettingsall') AND
			!$this->hasAdminPermission('canadminstyles')
		)
		{
			throw new vB_Exception_Api('no_permission');
		}

		return vB_Library::instance('Options')->updateValue('styleid', $styleid);
	}

	/**
	 * This is used mostly by the adminCP style importer. This checks if the current user has
	 * enough permissions to import the specified XML data.
	 * Caller using this function must ensure that the $xmlString data matches what's in an
	 * uploaded XML file, if they are separately specified.
	 *
	 * @param	string  $xmlString  XML data
	 *
	 * @return	array	Array containing the bool 'canimport' & string 'reason'.
	 *                  - canimport : true if user has enough perms
	 *                  - reason : only set if canimport is false. Phrase label for the reason
	 *                      why the current user cannot import the XML.
	 *
	 */
	public function checkCanImportStyleXML($xmlString)
	{
		$userContext =  vB::getUserContext();
		$canadmintemplates = $userContext->hasAdminPermission('canadmintemplates');
		$canadminstyles = $userContext->hasAdminPermission('canadminstyles');

		if ($canadmintemplates)
		{
			return array(
				'canimport' => true,
			);
		}

		// If they have neither permission then they can't upload styles period.
		if (!$canadminstyles)
		{
			return array(
				'canimport' => false,
				'reason' => 'no_permission',
			);
		}

		// If we're here then they don't have canadmintemplates but they have canadminstyles.
		// So they can only upload styles without templates (so just stylevars), or styles with
		// textonly templates (not yet implemented in XML exports)


		$parsedXML = null;
		$xmlobj = new vB_XML_Parser($xmlString);
		$parsedXML = $xmlobj->parse();

		if (!empty($parsedXML['templategroup']))
		{
			// Handle cases where there's only 1 templategroup that's empty or has a single child.
			if (empty($parsedXML['templategroup'][0]))
			{
				$parsedXML['templategroup'] = array($parsedXML['templategroup']);
			}

			foreach ($parsedXML['templategroup'] AS $templategroup)
			{
				// Taken from xml_import_template_groups(), handle cases where the array
				// isn't consistent if there is only 1 template node in this templategroup
				// node.
				if (empty($templategroup['template'][0]))
				{
					$tg = array($templategroup['template']);
				}
				else
				{
					$tg = $templategroup['template'];
				}


				foreach($tg AS $template)
				{
					if (empty($template['textonly']))
					{
						return array(
							'canimport' => false,
							'reason' => 'no_permission_cannot_import_templates_stylesonly',
						);
					}

					/*
						TODO:
							xml_import_template_groups() only runs compile_template() on templatetype = 'template', but
							frontend vB5_Template::render() seems to ignore templatetype & run eval() (or include() for
							templates in filesystem) without prejudice.

							Figure out how we should handle the different templatetypes (or if we should at all).
					 */
				}
			}
		}
		return array(
			'canimport' => true,
		);
	}

	/**
	 *  Determines if the css for the style should be loaded from a static file cache or from the database
	 *
	 *  @param int $styleid
	 *  @return array -- array('usefiles' => boolean)
	 */
	public function useCssFiles($styleid)
	{
		$usefiles = $this->library->useCssFiles($styleid);
		return array('usefiles' => $usefiles);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103572 $
|| #######################################################################
\*=========================================================================*/
