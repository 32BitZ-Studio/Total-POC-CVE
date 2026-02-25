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
 * vB_Library_Style
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Style extends vB_Library
{
	private $stylecache = array();
	private $stylesById = array();

	private $stylevarcache = array();
	private $ts_arraycache = array();

	/**
	 * Contains styles that were forced in a channel
	 * @var array
	 */
	protected $forcedStyles = null;

	/*
		IF ATTR_WRITE: Debug not required to edit templates & stylevars
		IF ATTR_READ: Debug not required to view this in adminCP & (site builder ?)

		ATTR_DEFAULT: Defaults for regular styles.
	 */
	const ATTR_WRITE  = 1; // 0b0001
	const ATTR_READ   = 2; // 0b0010

	const ATTR_PROTECTED = 0; // Completely protected, theme styles & master style
	const ATTR_DEFAULT = 3; // ATTR_WRITE | ATTR_READ

	protected function __construct()
	{
		/*
			Regenerate stylecache if datastore got nuked.
		 */
		$check = vB::getDatastore()->getValue('stylecache');
		if (empty($check))
		{
			$this->buildStyleDatastore();
		}
	}

	/**
	 * Adds missing stylevars to a style array
	 * @param array $styles
	 * @param	int	optional styleid needed
	 */
	protected function addStylevars(&$styles, $styleids = false)
	{
		$pending = array();

		if (!empty($styleids))
		{
			//only do the requested styles
			$notFound = $this->preCacheStylevars($styleids, $styles);

			// no cache found
			if (!empty($notFound))
			{
				$loadStyles = vB::getDbAssertor()->assertQuery('style', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array('styleid' => $notFound),
					vB_dB_Query::COLUMNS_KEY => array('styleid', 'newstylevars')
				));

				if ($loadStyles->valid())
				{
					foreach($loadStyles AS $style)
					{
						$this->setStylevars(intval($style['styleid']), $style['newstylevars'], $styles);
					}
				}
			}

			return;
		}

		//Need to all styles
		foreach($styles AS $key => $style)
		{
			if (isset($style['styleid']) AND
				(!isset($style['newstylevars']) OR empty($style['newstylevars'])))
			{
				$stylevars = $this->getStylevars($style['styleid']);

				if (empty($stylevars))
				{
					$pending[] = intval($style['styleid']);
				}
			}
		}

		if (!empty($pending))
		{
			$result = vB::getDbAssertor()->assertQuery('style', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('styleid' => $pending),
				vB_dB_Query::COLUMNS_KEY => array('styleid', 'newstylevars')
			));

			if ($result->valid())
			{
				foreach($result AS $style)
				{
					$this->setStylevars(intval($style['styleid']), $style['newstylevars'], $styles);
				}
			}
		}

		// Add cache back
		foreach ($styles as $k => $style)
		{
			if (isset($style['styleid']))
			{
				$newstylevars = $this->getStylevars(intval($style['styleid']));
				if ($newstylevars)
				{
					$styles[$k]['newstylevars'] = $newstylevars;
				}
			}
		}
	}

	/**
	 * This preloads a list of stylevars, and returns a list of those not found
	 *
	 *	@param array $styleids	array of style ids
	 *	@param array &$styles array of cached styles which will be modified in place
	 *	@return	array	array of integers, which may be empty- those styles that must be queried.
	 */
	protected function preCacheStylevars($styleids, &$styles)
	{
		$notFound = array();
		foreach($styleids AS $key => $styleid)
		{
			//don't try to set the stylevars for a style not in cache
			//bad things will result.
			if (isset($styles[$styleid]))
			{
				if (!empty($this->stylevarcache[$styleid]))
				{
					$styles[$styleid]['newstylevars'] = $this->stylevarcache[$styleid];
					unset($styleids[$key]);
				}
				else
				{
					$notFound[$styleid] = 'stylevar_cache_' . $styleid;
				}
			}
		}

		if (empty($styleids))
		{
			return array();
		}

		$found = vB_Cache::instance()->read($notFound);

		foreach ($notFound as $styleid => $cacheKey)
		{
			if (!empty($found[$cacheKey]))
			{
				$this->stylevarcache[$styleid] = $found[$cacheKey];
				$styles[$styleid]['newstylevars'] = $found[$cacheKey];
				unset($notFound[$styleid]);
			}
		}
		return array_keys($notFound);
	}

	protected function getStylevars($styleid)
	{
		$styleid = intval($styleid);
		if (empty($this->stylevarcache[$styleid]))
		{
			$result = vB_Cache::instance()->read('stylevar_cache_' . $styleid);

			if (!empty($result))
			{
				$this->stylevarcache[$styleid] = $result;
				return $result;
			}
			else
			{
				return null;
			}
		}
		else
		{
			return $this->stylevarcache[$styleid];
		}
	}

	/**
	 * 	Update various caches with the stylevar data for a style
	 *
	 *	@param int $styleid
	 *	@param array $data -- The stylevar data for the style
	 *	@param array $styles -- The style cache to update the new stylvar data
	 */
	protected function setStylevars($styleid, $data, &$styles)
	{
		$styleid = intval($styleid);
		$this->stylevarcache[$styleid] = $data;

		if (isset($styles[$styleid]))
		{
			$styles[$styleid]['newstylevars'] = $data;
		}

		vB_Cache::instance()->write(
			'stylevar_cache_' . $styleid,
			$data,
			0,
			array('vB_Library_Style_stylevar_cache',
		));
	}

	/**
	 * Returns a valid style to be used from the candidates
	 *
	 * @param array $stylePreference - Style candidates ordered by preference
	 * @return int
	 */
	public function getValidStyleFromPreference($stylePreference)
	{
		$styleId = false;

		$datastore =  vB::getDatastore();
		$db = vB::getDbAssertor();

		if (is_array($stylePreference) AND !empty($stylePreference))
		{
			// fetch info and verify styles exist
			$styles = $datastore->getValue('stylecache');

			reset($stylePreference);
			$style = current($stylePreference);
			while ($style !== false AND $styleId === false)
			{
				if (isset($styles[$style]))
				{
					if ($styles[$style]['userselect'] OR vB::getUserContext()->isAdministrator())
					{
						$styleId = $styles[$style]['styleid'];
					}
					else
					{
						// We cannot be certain that the user is actually looking at a specific channel,
						// so if a user doesn't have permission for certain style and that style is among
						// the forced ones, we still let the user get it. This will reduce the window for
						// spoofing.
						$forcedStyles = $this->loadForcedStyles();
						if (in_array($styles[$style]['styleid'], $forcedStyles))
						{
							$styleId = $styles[$style]['styleid'];
						}
					}
				}

				// go to next style candidate
				$style = next($stylePreference);
			}
		}

		if ($styleId !== false)
		{
			return $styleId;
		}
		else
		{
			return $datastore->getOption('styleid');
		}
	}

	private function loadForcedStyles()
	{
		if (is_null($this->forcedStyles))
		{
			$datastore =  vB::getDatastore();
			$db = vB::getDbAssertor();

			$styles = $datastore->getValue('stylecache');
			$forumOptions = $datastore->getValue('bf_misc_forumoptions');

			$this->forcedStyles = $db->getColumn('vBForum:channel', 'styleid', array(
				vB_dB_Query::CONDITIONS_KEY => array (
					'styleid' => array_keys($styles),
				)
			));

			$this->forcedStyles = array_unique($this->forcedStyles);
		}

		return $this->forcedStyles;
	}

	/**
	 * Removes orphaned stylevars
	 *
	 * @param bool echo progress comments
	 * @return nothing
	 */
	public function deleteOrphanStylevars($echo = false)
	{
		$assertor = vB::getDbAssertor();

		if ($echo)
		{
			$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('orphan_stylevar_deleted'));
		}

		// Get installed products (includes any that are disabled)
		$products = vB::getDatastore()->getValue('products');
		$productlist = array_keys($products);

		// Find any stylevars not linked to a product
		$assertor->update('vBForum:stylevardfn', array('styleid' => -10),
			array(array('field'=>'product', 'value'=>$productlist, 'operator' => vB_dB_Query::OPERATOR_NE))
		);

		//	Zap old definitions
		$assertor->delete('vBForum:stylevardfn', array('styleid' => -10));

		$orphans = array();
		$deletelist = array();
		$svdata = $assertor->getRows('fetchMasterStylevars');

		// Build list, phrases will be removed later
		foreach ($svdata as $stylevar)
		{
			$deletelist[$stylevar['stylevarid']][] = 'Master';
			$orphans[] =  $stylevar['stylevarid'];
		}

		// Zap em !
		if (!empty($orphans))
		{
			$assertor->delete('vBForum:stylevar', array('stylevarid' => $orphans));
		}

		// Get remaining stylevar data
		$svdata = $assertor->select('vBForum:stylevar', vB_dB_Query::CONDITION_ALL, false, array('styleid','stylevarid'));

		// Generate master and custom lists
		$masterlist = array();
		foreach ($svdata AS $svlist)
		{
			$style = $svlist['styleid']	;
			$stylevar = $svlist['stylevarid'];

			if ($style == -1)
			{
				$masterlist[$stylevar] = true;
			}
			else
			{
				$deletelist[$stylevar][] = $style;
			}
		}

		// Clear valid stylevars from delete list
		foreach($deletelist AS $stylevar => $styles)
		{
			if ($masterlist[$stylevar])
			{
				unset($deletelist[$stylevar]);
			}
		}

		/* What we have left is orphaned stylevars,
		   so now its time to get rid of them */
		foreach($deletelist AS $stylevar => $styles)
		{
			foreach($styles AS $style)
			{
				$rundelete = false;

				if ($style != 'Master')
				{
					$rundelete = true; // We only deleted the master version earlier
					if ($echo) echo construct_phrase($vbphrase['orphan_stylevar_deleted'],$stylevar,"Style $style");
				}
				else
				{
					if ($echo) echo construct_phrase($vbphrase['orphan_stylevar_deleted'],$stylevar,'Master Style');
				}
			}

			// Zap stylevar
			if ($rundelete)
			{
				$assertor->delete('vBForum:stylevar', array('stylevarid' => $stylevar));
			}

			// Zap phrases
			$assertor->delete('vBForum:phrase', array('fieldname' => 'style',
				varname => array("stylevar_{$stylevar}_name", "stylevar_{$stylevar}_description")));
		}

		// Rebuild languages
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);
	}

	/**
	 * Loads style information (selected style and style vars)
	 *
	 * This is different from fetchStyleByID(). The style fetched
	 * by this method may not be the style specified in $styleid parameter.
	 *
	 * If the style with $styleid doesn't allow user to use (The user isn't admin either),
	 * default style specified in vBulletin Settings will be returned.
	 *
	 * @param int $styleid
	 *
	 * @return array Style information.
	 * 	-- See fetchStyleByID
	 */
	public function fetchStyleRecord($styleid, $nopermissioncheck = false)
	{
		$userContext = vB::getUserContext();

		//This gets called if we have an error during initialization, and we want to display something useful
		if (!empty($userContext) AND is_object($userContext))
		{
			$isAdmin = $userContext->hasAdminPermission('cancontrolpanel');
		}
		else
		{
			$isAdmin = false;
		}
		$thisStyle = null;

		if (isset($this->stylesById[$styleid]))
		{
			$thisStyle = $this->stylesById[$styleid];
			if ($isAdmin || $thisStyle['userselect'] || $nopermissioncheck)
			{
				return $thisStyle;
			}
		}

		$options = vB::getDatastore()->getValue('options');
		$defaultStyleId = $options['styleid'];

		$defaultStyle = null;
		if (isset($this->stylesById[$defaultStyleId]))
		{
			$defaultStyle = $this->stylesById[$defaultStyleId];

			//intentionally checking $thisStyle here.  If we don't have thisStyle, then we need to
			//look it up (below) because we may have a valid style that we just haven't loaded yet.
			//if we have $thisStyle then we've already looked at it and rejected it.
			if ($thisStyle)
			{
				return $defaultStyle;
			}
		}

		$conditions = array();
		if (!$isAdmin AND !$nopermissioncheck)
		{
			$conditions['userselect'] = 1;
		}

		//reset and reload
		$thisStyle = null;
		$defaultStyle = null;
		$result = array();
		$stylecache = vB::getDatastore()->getValue('stylecache');
		if (empty($conditions['userselect']))
		{
			//determine which styles we need to look up.
			$styleids = array();
			if (!$thisStyle)
			{
				$styleids[] = $styleid;
			}

			//if we have the default style we don't need to query for it again.
			if (!$defaultStyle)
			{
				$styleids[] = $defaultStyleId;
			}
			$conditions['styleid'] = $styleids;

			if (!empty($stylecache))
			{
				foreach ($stylecache as $style)
				{
					if (in_array($style['styleid'], $styleids))
					{
						if ((!empty($conditions['userselect']) AND !empty($style['userselect'])) OR empty($conditions['userselect']))
						{
							$result[] = $style;
						}
					}
				}
			}
		}
		else
		{
			foreach ($stylecache as $style)
			{
				if (($style['styleid'] == $styleid AND $style['userselect']) OR $style['styleid'] == $defaultStyleId)
				{
					$result[] = $style;
				}
			}
		}

		foreach($result as $style)
		{
			if ($style['styleid'] == $styleid)
			{
				$thisStyle = $style;
			}

			/*
			 *	Default style should always be returned, regardless of userselect. VBV-12556
			 */
			if ($style['styleid'] == $defaultStyleId)
			{
				$defaultStyle = $style;
			}
		}

		if ($thisStyle)
		{
			if ($isAdmin || $thisStyle['userselect'] || $nopermissioncheck)
			{
				return $this->fetchStyleByID($thisStyle['styleid']);
			}
		}

		if ($defaultStyle)
		{
			return $this->fetchStyleByID($defaultStyle['styleid']);
		}

		//if we don't have anything.
		return false;
	}

	/**
	 * Import style from XML Data
	 *
	 * @param string $xmldata XML Data to be imported as style.
	 * @param string $title Style title.
	 * @param integer $parentid Parent style ID.
	 * @param integer $overwritestyleid Style ID to be overwritten.
	 * @param boolean $anyversion Whether to ignore style version.
	 * @param integer $displayorder Style display order.
	 * @param boolean $userselect Whether the style allows user selection.
	 */
	public function importStyleFromXML($xmldata, $title, $parentid, $overwritestyleid, $anyversion, $displayorder, $userselect, $scilent = false)
	{
		require_once(DIR . '/includes/adminfunctions_template.php');
		$imported = xml_import_style($xmldata,
			$overwritestyleid, $parentid, $title,
			$anyversion, $displayorder, $userselect,
			null, null, $scilent
		);

		return $imported;
	}

	/**
	 * Import style from Server File
	 *
	 * @param string $serverfile Server file name to be imported.
	 * @param string $title Style title.
	 * @param integer $parentid Parent style ID.
	 * @param integer $overwritestyleid Style ID to be overwritten.
	 * @param boolean $anyversion Whether to ignore style version.
	 * @param integer $displayorder Style display order.
	 * @param boolean $userselect Whether the style allows user selection.
	 */
	public function importStyleFromServer($serverfile, $title, $parentid, $overwritestyleid, $anyversion, $displayorder, $userselect)
	{
		require_once(DIR . '/includes/adminfunctions.php');

		if (file_exists($serverfile))
		{
			$xml = file_read($serverfile);
		}
		else
		{
			throw new vB_Exception_Api('no_file_uploaded_and_no_local_file_found_gerror');
		}

		return $this->importStyleFromXML($xml, $title, $parentid, $overwritestyleid, $anyversion, $displayorder, $userselect);
	}

	/**
	 * Returns an array of all styles that are parents to the style specified
	 *
	 * @param	integer	Style ID
	 *
	 * @return	array
	 */
	public function fetchTemplateParentlist($styleid, $overwriteCache = false)
	{
		if (empty($styleid))
		{
			return '';
		}

		// overwrite is required if we're forcing parentlist changes in the
		// same session memory
		if (!$overwriteCache AND isset($this->ts_arraycache["$styleid"]))
		{
			return $this->ts_arraycache["$styleid"];
		}

		$ts_info = vB::getDbAssertor()->getRow('style', array('styleid' => $styleid));
		$ts_array = $styleid;

		if ($ts_info['parentid'] >= 0)
		{
			$parentlist = $this->fetchTemplateParentlist($ts_info['parentid'], $overwriteCache);
			if (!empty($parentlist))
			{
				$ts_array .= ',' . $parentlist;
			}
		}

		if (substr($ts_array, -2) != '-1')
		{
			$ts_array .= ',-1';
		}
		return $this->ts_arraycache["$styleid"] = $ts_array;
	}


	/**
	 * Fetch style information by its ID.
	 *
	 * @param integer $styleid Style ID.
	 * @param bool abort or return empty array ?
	 *
	 * @return array Style information.  Same as fetchStyleByID except
	 *	--newstylevars array -- stylevar array
	 *	--userselect bool -- is this style user selectable?
	 */
	public function getStyleById($styleid)
	{
		$style = $this->fetchStyleByID($styleid);
		$style['newstylevars'] = unserialize($style['newstylevars']);
		$style['userselect'] = (bool) $style['userselect'];
		return $style;
	}

	/**
	 * Fetch style information by its ID.
	 *
	 * @param integer $styleid Style ID.
	 * @param bool abort or return empty array ?
	 *
	 * @return array Style information.
	 *	--styleid int
	 *	--title string
	 *	--parentid int
	 *	--parentlist string -- comma seperated list of ancestors styles (includes this style)
	 *	--templatelist array -- templatename => templateid for this style (might include templates
	 *		from ancestors)
	 *	--newstylevars string -- serialized stylevar array
	 *	--replacements -- replacement vars?
	 *	--editorstyles ???
	 *	--userselect int -- is this style user selectable? (0/1)
	 *	--displayorder int -- order to display this style in
	 *	--dateline
	 *	--guid string -- unique id for theme styles (styles with a guid are considered themes and have
	 *		special handling)
	 *	--filedataid int ???
	 *	--previewfiledataid int -- the fileid for the theme preview image
	 *	--styleattributes ???
	 *
	 *	@deprecated use getStyleById
	 */
	public function fetchStyleByID($styleid, $abort = true)
	{
		if (!isset($this->stylesById[$styleid]))
		{
			$style = vB::getDbAssertor()->getRow('style', array('styleid' => $styleid));
			if (!$style)
			{
				if (!$abort)
				{
					return array();
				}
				else
				{
					throw new vB_Exception_Api('invalidid', array('styleid'));
				}
			}
			$style['templatelist'] = unserialize($style['templatelist']);
			$this->stylesById[$styleid] = $style;
		}

		if (empty($this->stylesById[$styleid]['newstylevars']))
		{
			$parents = array();
			if (!empty($this->stylesById[$styleid]['parentid']))
			{
				$parents = explode(',', $this->stylesById[$styleid]['parentid']);

				//There is no -1 style.
				if ($parents[0] == '-1')
				{
					unset($parents[0]);
				}
			}

			if (!in_array($styleid, $parents))
			{
				$parents[] = $styleid;
			}

			$this->addStylevars($this->stylesById, $parents);
		}

		return $this->stylesById[$styleid];
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
	 * @return int The new styleid
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
		/*
			Keep this code in sync with vB_Xml_Import_Theme::doInsertTheme()
		 */

		if (!$title)
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		if (is_null($dateline))
		{
			$dateline = vB::getRequest()->getTimeNow();
		}

		$result = vB::getDbAssertor()->insert('style', array(
			'title' => $title,
			'parentid' => $parentid,
			'userselect' => intval($userselect),
			'displayorder' => $displayorder,
			'styleattributes' => $styleattributes,
			'dateline' => $dateline,
		));

		if (is_array($result))
		{
			$result = array_pop($result);
		}

		require_once(DIR . '/includes/adminfunctions_template.php');
		build_template_parentlists();

		// add theme data
		$this->addThemeData($result, $guid, $icon, false, $previewImage, false);

		$this->buildStyle($result, $title, array(
				'dostylevars' => 1,
				'doreplacements' => 1,
				'doposteditor' => 1
		), false);

		$this->buildStyleDatastore();
		return $result;
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
		$datastore = vB::getDatastore();
		$vboptions = $datastore->getValue('options');

		if ($vboptions['styleid'] == $dostyleid)
		{
			// If a style is default style, we should always allow user to select it.
			$userselect = 1;
		}

		if (!$title)
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		// SANITY CHECK (prevent invalid nesting)
		if ($parentid == $dostyleid)
		{
			throw new vB_Exception_Api('cant_parent_style_to_self');
		}
		$parents = array();
		if ($parentid != -1)
		{
			$ts_info = $this->fetchStyleByID($parentid);
			$parents = explode(',', $ts_info['parentlist']);
		}

		foreach($parents AS $childid)
		{
			if ($childid == $dostyleid)
			{
				throw new vB_Exception_Api('cant_parent_x_to_child', array('style'));
			}
		}
		// end Sanity check

		$rebuild = false;
		$rebuildChildren = false;

		$style = $this->fetchStyleByID($dostyleid);
		if ($style['parentid'] != $parentid)
		{
			$rebuild = true;
			$rebuildChildren = true;
		}

		//if the user select is changed we need to rebuild the style but not the children
		if ($style['userselect'] != intval($userselect))
		{
			$rebuild = true;
		}

		vB::getDbAssertor()->update('style',
			array(
				'title' => $title,
				'parentid' => $parentid,
				'userselect' => intval($userselect),
				'displayorder' => $displayorder
			),
			array('styleid' => $dostyleid)
		);

		//we just updated the record but the cache is used by the rebuild process so
		//we can't be entirely sure that it will work correctly if we don't clear it.
		unset($this->stylesById[$dostyleid]);

		$style = $this->fetchStyleByID($dostyleid);
		$styles = $datastore->getValue('stylecache');

		// add theme data
		$this->addThemeData($dostyleid, $guid, $icon, $iconRemove, $previewImage, $previewImageRemove);
		if ($rebuild)
		{
			$this->replaceStyleInDatastore($datastore, $dostyleid);
			require_once(DIR . '/includes/adminfunctions_template.php');
			build_template_parentlists();
			$actions = array(
				'dostylevars' => 1,
				'doreplacements' => 1,
				'doposteditor' => 1
			);

			$this->buildStyle($dostyleid, $title, $actions, false, $rebuildChildren);
		}

		$this->clearStyleCache();
		$this->buildStyleDatastore();

		return true;
	}

	/**
	 * Adds theme data (GUID, icon, preview image) to a style if in debug mode. (used by update & insert)
	 *
	 * @param	string	$guid Theme GUID
	 * @param	binary	$icon Theme icon
	 * @param	boolean	$iconRemove Whether to remove the current icon (if there is one, and we're not uploading a new one)
	 * @param	binary	$previewImage Theme preview image
	 * @param	boolean	$previewImageRemove Whether to remove the current preview image (if there is one, and we're not uploading a new one)
	 */
	private function addThemeData($dostyleid, $guid, $icon, $iconRemove, $previewImage, $previewImageRemove)
	{
		$config = vB::getConfig();
		if (empty($config['Misc']['debug']))
		{
			// only modify theme information in debug mode.
			return;
		}

		$style = $this->fetchStyleByID($dostyleid);
		$themeImporter = new vB_Xml_Import_Theme();
		$updateValues = array();

		// ----- GUID -----
		if (!empty($guid))
		{
			$updateValues['guid'] = $guid;
		}
		else
		{
			$updateValues['guid'] = vB_dB_Query::VALUE_ISNULL;
		}

		// ----- Icon -----
		if (!empty($icon))
		{
			// upload it & get a filedataid
			$filedataid = $themeImporter->uploadThemeImageData($icon);
			if ($filedataid > 0 AND $filedataid != $style['filedataid'])
			{
				$updateValues['filedataid'] = $filedataid;
			}
		}

		if ($style['filedataid'] > 0 AND ($iconRemove OR !empty($updateValues['filedataid'])))
		{
			// remove previous icon (if there was one and they checked 'remove' or if there was one and we just uploaded a new one)
			vB::getDbAssertor()->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['filedataid']));
			// set icon to blank if we don't have a new one
			if (empty($updateValues['filedataid']))
			{
				$updateValues['filedataid'] = 0;
			}
		}

		// ----- Preview Image -----
		if (!empty($previewImage))
		{
			// upload it & get a previewfiledataid
			$previewfiledataid = $themeImporter->uploadThemeImageData($previewImage);
			if ($previewfiledataid > 0 AND $previewfiledataid != $style['previewfiledataid'])
			{
				$updateValues['previewfiledataid'] = $previewfiledataid;
			}
		}

		if ($style['previewfiledataid'] > 0 AND ($previewImageRemove OR !empty($updateValues['previewfiledataid'])))
		{
			// remove previous preview image (if there was one and they checked 'remove' or if there was one and we just uploaded a new one)
			vB::getDbAssertor()->assertQuery('decrementFiledataRefcount', array('filedataid' => $style['previewfiledataid']));
			// set preview image to blank if we don't have a new one
			if (empty($updateValues['previewfiledataid']))
			{
				$updateValues['previewfiledataid'] = 0;
			}
		}

		// save
		if (!empty($updateValues))
		{
			vB::getDbAssertor()->update('style', $updateValues, array('styleid' => $dostyleid));
		}
	}

	/**
	 * Builds the $stylecache array
	 *
	 * This is a recursive function - call it with no arguments
	 *
	 * @param boolean $styleid Style ID to start with
	 * @param integer $depth Current depth
	 * @return none
	 */
	private function cacheStyles($styleid = -1, $depth = 0)
	{
		static $cache = array();
		static $loaded = array();

		//the cache appears to be for the benefit of the recursive calls.  We'll reset if called
		//from the top to avoid problems if we need to regenerate the cache after a change
		//(mostly for the unit tests).
		if ($styleid == -1)
		{
			$cache = array();
			$loaded = array();
			/*
				Some callers may not explicitly clear this before calling cacheStyles. When performing
				actions like deleting styles, calling cacheStyles() then saving the stylecache to the datastore will
				leave behind ghost records in the datastore, which is problematic. This may be the cause of issues like
				upgrades occassionally failing with references to nonexistent styles, though I cannot verify that
				as I was never able to reproduce such issues.
				In any case, if someone calls cacheStyles() with $styleid = -1, they really want to clear everything
				and rebuild, so let's just clear $stylecache for them as well.
			 */
			$this->stylecache = array();
		}

		$vboptions = vB::getDatastore()->getValue('options');

		// check to see if we have already got the results from the database
		if (empty($cache))
		{
			$counter = 0;
			$styles = vB::getDbAssertor()->assertQuery('style', array(
				// VBV-4174: excluding csscolors, css and stylevars since they are deprecated
				vB_dB_Query::COLUMNS_KEY => array(
					'styleid',
					'parentid',
					'title',
					'parentlist',
					'newstylevars',
					'replacements',
					'editorstyles',
					'userselect',
					'displayorder',
					'dateline',
					'guid',
					'filedataid',
					'previewfiledataid',
					'styleattributes',
				),
			), 'displayorder');

			foreach ($styles as $style)
			{
				if (!empty($loaded[$style['styleid']]))
				{
					continue;
				}

				if (trim($style['parentlist']) == '')
				{
					$parentlist = $this->fetchTemplateParentlist($style['styleid']);
					vB::getDbAssertor()->assertQuery('vBForum:updatestyleparent', array(
						'parentlist' => $parentlist,
						'styleid' => intval($style['styleid']),
					));
					$style['parentlist'] = $parentlist;
				}

				// If a style is a default style, we need to make sure user can select it.
				if ($style['styleid'] == $vboptions['styleid'])
				{
					$style['userselect'] = 1;
				}

				$loaded[$style['styleid']] = true;
				$cache[$style['parentid']][$style['displayorder']][$style['styleid']] = $style;
				$counter++;
			}

			foreach ($cache as $parentid => &$styles)
			{
				ksort($styles);
			}

			if (!defined('STYLECOUNT'))
			{
				define('STYLECOUNT', $counter);
			}
		}

		// database has already been queried
		if (!empty($cache["$styleid"]) AND is_array($cache["$styleid"]))
		{
			foreach ($cache["$styleid"] AS $holder)
			{
				foreach ($holder AS $style)
				{
					$this->stylecache["$style[styleid]"] = $style;
					$this->stylecache["$style[styleid]"]['depth'] = $depth;
					$this->cacheStyles($style['styleid'], $depth + 1, false);
				}
			}
		}
	}

	/**
	 * Fetch All styles
	 *
	 * @param bool	$nocache         Refresh Styles from database
	 * @param bool	$fetchStylevars  if true it will return stylevars for each style
	 * @param mixed	$options         array of options: currently only understands
	 *                                   "themes":false - exclude themes,
	 *                                   "skipReadCheck":true - include protected styles
	 *
	 * @return array All styles' information
	 */
	public function fetchStyles($nocache = false, $fetchStylevars = true, $options = array())
	{
		if ($nocache)
		{
			$this->stylecache = array();

			// this will fetch the stylevars from db
			$this->cacheStyles();
		}
		elseif (empty($this->stylecache))
		{
			$this->stylecache = vB::getDatastore()->getValue('stylecache');

			if ($fetchStylevars)
			{
				$this->addStylevars($this->stylecache);
			}
		}

		if (isset($options['themes']) AND !$options['themes'])
		{
			$result = array();
			foreach ($this->stylecache AS $key => $style)
			{
				if (empty($style['guid']))
				{
					$result[$key] = $style;
				}
			}
		}
		else
		{
			$result = $this->stylecache;
		}

		if (isset($options['skipReadCheck']) AND $options['skipReadCheck'])
		{
			return $result;
		}
		else
		{
			return $this->removeReadProtectedStyles($result);
		}
	}

	protected function removeReadProtectedStyles($styles)
	{
		$vb5_config = &vB::getConfig();
		if ( !$vb5_config['Misc']['debug'] )
		{
			foreach ($styles AS $key => $style)
			{
				if (!$this->checkStyleReadProtection(null, $style))
				{
					unset($styles[$key]);
				}
			}

			// fix the style depth
			foreach ($styles AS $key => $style)
			{
				$parents = explode(',', $style['parentlist']);
				foreach ($parents AS $parent)
				{
					// decrement depth for each parent that has been removed
					// from the list of styles. Skip the master style, as that
					// indentation is handled separately.
					if ($parent != -1 AND empty($styles[$parent]))
					{
						--$styles[$key]['depth'];
					}
				}
			}
		}

		return $styles;
	}

	/**
	 * Returns true if style is not read-protected and can be viewed.
	 *
	 * @param int $styleid If style being checked exists, its styleid.
	 *	Alternatively, provide the style array as $style
	 * @param array $style	(Optional) Style array with 'styleattributes' field.
	 * 	If not provided, function will only use $styleid.
	 *
	 * @return bool		Style can be viewed
	 */
	public function checkStyleReadProtection($styleid = null, $style = array(), $ignore_debug = false)
	{
		$vb5_config = &vB::getConfig();
		if ( $vb5_config['Misc']['debug'] AND !$ignore_debug )
		{
			// Debug  mode allows read on protected styles
			return true;
		}

		if (empty($style) AND empty($styleid))
		{
			// if styleid is null or 0, assume it's a new style and has no read protection.
			return true;
		}

		// Assume "master style" is always readable?
		if ($styleid == -1)
		{
			return true;
		}

		// Only fetch a style if it wasn't provided. TODO: check if provided $style has $styleid for styleid if latter is not null?
		if (empty($style))
		{
			$style = $this->fetchStyleByID($styleid);
		}
		$canRead = (bool) ($style['styleattributes'] & vB_Library_Style::ATTR_READ);
		return $canRead;
	}

	/**
	 *	Determine if we should use on disk files for this style based on the following rules
	 *
	 * 	1. We have storecssasfile enabled
	 * 	2. The style user selectable and/or a "force" style used for specific channels
	 * 	3. The style is readable (not a hidden them style).
	 *
	 *	@param int $styleid
	 *	@return boolean
	 */
	public function useCssFiles($styleid)
	{
		$datastore = vB::getDatastore();

		//we aren't storing anything as a file.
		if (!$datastore->getOption('storecssasfile'))
		{
			return false;
		}

		//we shouldn't be calling this on the master style, but let's not throw an error if we do
		//the master style doesn't have a proper style record to load.
		if ($styleid == -1)
		{
			return false;
		}

		$styles = $datastore->getValue('stylecache');

		//when adding a style it is not yet in the stylecache.  So if it isn't we need to
		//explicitly load it.
		if (isset($styles[$styleid]))
		{
			$style = $styles[$styleid];
		}
		else
		{
			$style = $this->fetchStyleByID($styleid);
		}

		//if we still don't have a valid style then we have a problem.  This shouldn't happen
		if (!$style)
		{
			throw new vB_Exception_Api('invalidid', array('styleid'));
		}

		//this is a hidden theme style (why are we attempting to view it?)
		if (!$this->checkStyleReadProtection($styleid, $style, true))
		{
			return false;
		}

		//if either of these checks pass, then we're good (either user selectable OR associated with a channel).
		if (!$style['userselect'])
		{
			$forcedStyles = $this->loadForcedStyles();
			if (!in_array($styleid, $forcedStyles))
			{
				return false;
			}
		}

		//if we can't think of reason not to use files, then we should use the files.
		return true;
	}

	/**
	 * Clear style in class cache.
	 * Needed for unit testing
	 *
	 */
	public function clearStyleCache()
	{
		$this->stylecache = array();
		$this->stylesById = array();
		$this->stylevarcache = array();
	}

	/**
	 * This is intended to be used in tests, to be able to refresh the cache
	 */
	public function resetForcedStyles()
	{
		$this->forcedStyles = null;
	}

	/**
	 * Checks if a styleid is valid
	 *
	 * @param int $styleid
	 * @return bool
	 */
	public function validStyle($styleid)
	{
		$this->fetchStyles(false, false);

		return isset($this->stylecache[$styleid]);
	}


	/**
	 *	Switch the style for rendering
	 *	This really should be part of the bootstrap code except:
	 *	1) We don't actually load the bootstrap in the admincp
	 * 2) There is a lot to the style load that isn't easy to redo (header/footer templates for example)
	 *
	 * This handles the stylevars and template lists -- including reloading the template cache.
	 * This is enough to handle the css template rendering, but probably won't work for anything
	 * more complicated.
	 */
	public function switchCssStyle($styleid, $templates)
	{
		global $vbulletin;

		$style = $this->getStyleById($styleid);

		if (empty($style))
		{
			return false;
		}

		$this->cacheStyles();

		$vbulletin->stylevars = $style['newstylevars'];
		fetch_stylevars($style, vB::getCurrentSession()->fetch_userinfo());

		//clear the template cache, otherwise we might get old templates
		vB_Library::instance('template')->cacheTemplates($templates, $style['templatelist'], false, true);
	}

	/**
	 * Fetches a list of template IDs for the specified style
	 * @deprecated
	 * @param	integer	Style ID
	 * @param	boolean	If true, returns a list of template ids; if false, goes ahead and runs the update query
	 * @param	mixed	A comma-separated list of style parent ids (if false, will query to fetch the list)
	 *
	 * @return	mixed	Either the list of template ids, or nothing
	 */
	public function buildTemplateIdCache($styleid, $doreturn = false, $parentids = false)
	{
		if ($styleid == -1)
		{
			// doesn't have a cache
			return '';
		}

		//this is done as an array for historical reasons
		if ($parentids == 0)
		{
			$style['parentlist'] = $this->fetchTemplateParentlist($styleid);
		}
		else
		{
			$style['parentlist'] = $parentids;
		}

		$parents = explode(',', $style['parentlist']);
		$totalparents = sizeof($parents);

		$bbcodestyles = array();
		$templatelist = array();
		$assertor = vB::getDbAssertor();
		$templates = $assertor->assertQuery('vBForum:fetchTemplateIdsByParentlist', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'parentlist' => $style['parentlist'],
		));
		foreach ($templates as $template)
		{
			for ($tid = $totalparents; $tid > 0; $tid--)
			{
				if ($template["templateid_$tid"])
				{
					$templatelist["$template[title]"] = $template["templateid_$tid"];
					if (preg_match('#^bbcode_[code|html|php|quote]+$#si', trim($template['title'])))
					{
						$bbcodetemplate = $template['title'] . '_styleid';
						if ($template["styleid_$tid"])
						{
							$templatelist["$bbcodetemplate"] = $template["styleid_$tid"];
						}
						else
						{
							$templatelist["$bbcodetemplate"] = -1;
						}
					}
					break;
				}
			}
		}

		$customdone = array();
		$customtemps = $assertor->assertQuery('vBForum:fetchCustomtempsByParentlist', array(
			'parentlist' => $style['parentlist'],
		));

		foreach ($customtemps as $template)
		{
			if (!empty($customdone["$template[title]"]))
			{
				continue;
			}
			$customdone["$template[title]"] = 1;
			$templatelist["$template[title]"] = $template['templateid'];

			if (preg_match('#^bbcode_[code|html|php|quote]+$#si', trim($template['title'])))
			{
				$bbcodetemplate = $template['title'] . '_styleid';
				$templatelist["$bbcodetemplate"] = $template['styleid'];
			}
		}

		$templatelist = serialize($templatelist);

		if (!$doreturn)
		{
			$assertor->update(
				'template',
				array('templatelist' => $templatelist),
				array('styleid' => $styleid)
			);
		}
		else
		{
			return $templatelist;
		}
	}

	/**
	 * Resets the css cachebuster date.
	 */
	public function setCssDate()
	{
		vB_Cache::instance()->event('vB_Library_Style_stylevar_cache');
		$options = vB::getDatastore()->getValue('miscoptions');
		$options['cssdate'] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('miscoptions', serialize($options), 1);
	}

	/**
	 * Resets/sets the css file cachebuster date. Used when storing css as files
	 * @param int $styleid The style to set the date for.  Each style has its own date
	 * 	to prevent us from needing to rebuild the css for every style any time something
	 * 	changes.
	 */
	public function setCssFileDate($styleid)
	{
		$options = vB::getDatastore()->getValue('miscoptions');
		//temporary to handle transition from scalar to array -- code should only
		//run once on a given install.
		if (!empty($options['cssfiledate']) AND !is_array($options['cssfiledate']))
		{
			$date = $options['cssfiledate'];
			$stylecache = $this->fetchStyles(true, false, array('themes' => true));

			$options['cssfiledate'] = array();
			foreach (array_keys($stylecache) AS $oldstyleid)
			{
				$options['cssfiledate'][$oldstyleid] = $date;
			}
		}

		if (empty($options['cssfiledate']))
		{
			$options['cssfiledate'] = array();
		}

		$options['cssfiledate'][$styleid] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('miscoptions', serialize($options), 1);
	}

	/**
	 *	Gets the date that the css for this style was last updated
	 *
	 *	@param int $styleid
	 */
	public function getCssFileDate($styleid)
	{
		$options = vB::getDatastore()->getValue('miscoptions');

		//temporary during transition
		if (!is_array($options['cssfiledate']))
		{
			return $options['cssfiledate'];
		}

		return $options['cssfiledate'][$styleid];
	}


	private function replaceStyleInDatastore($datastore, $styleid)
	{
		$style = $this->fetchStyleByID($styleid);
		if (isset($style['newstylevars']))
		{
			unset($style['newstylevars']);
		}

		//this will cause us to build the datastore twice if a style is updated
		//in a way that requires a style rebuild.  We only *really* need to
		//update the the local datastore copy -- but the datastore doesn't allow
		//that because generally changing the local copy but not persisting is a
		//bad move.  The only exception is cases like this wehere we end up needed
		//an updated datastore for a rebuild process that ends with a proper datastore
		//refresh.  But this doesn't happen enough to worry about optimazation just yet.
		$styles = $datastore->getValue('stylecache');
		$styles[$styleid] = $style;
		$datastore->build('stylecache', serialize($styles), 1);
	}

	/**
	 * Rebuild the style datastore.
	 */
	public function buildStyleDatastore()
	{
		$this->setCssDate();

		/*
			calling cacheStyles() will fetch the stylevars from db.
			Bypass using $this->fetchStyles() to keep read-protected styles in datastore.
		 */
		$this->cacheStyles();
		$stylecache = $this->stylecache;

		foreach($stylecache AS $key => $style)
		{
			// VBV-4174: we don't want stylevars in the datastore
			if (isset($style['newstylevars']))
			{
				unset($stylecache[$key]['newstylevars']);
			}
		}

		vB::getDatastore()->build('stylecache', serialize($stylecache), 1);
		vB_Cache::allCacheEvent('vbCachedFullPage');
		vB_Library::instance('template')->rebuildTextonlyDS();

		return $stylecache;
	}



	/**
	 * Converts all data from the template table for a style into the style table
	 *
	 * @param	int $styleid -- Use -1 to rebuild all styles.
	 * @param	string $title (unused)
	 * @param	array	$actions --Array of actions set to true/false: dostylevars/doreplacements/doposteditor
	 * @param	bool $resetcache -- Reset the master cache
	 * @param bool $updateChildren -- if false does not recurse the rebuild.  If called incorrectly without
	 * 	child rebuilds, then the children may not display properly
	 */
	public function buildStyle($styleid, $title, $actions, $resetcache = false, $updateChildren = true)
	{
		return $this->buildStyleInternal($styleid, $title, $actions, '', $resetcache, $updateChildren);
	}

	/**
	 * Only used internally by the adminfunctions_template's build_style() to force in-memory cache clears.
	 */
	public function internalCacheClear($styleid)
	{
		unset($this->stylesById[$styleid]);
	}

	/**
	 *	Internal function to handle the recursion for buildStyle.
	 *
	 */
	private function buildStyleInternal($styleid, $title, $actions, $parentlist, $resetcache, $updateChildren)
	{
		$datastore = vB::getDatastore();
		$assertor = vB::getDbAssertor();

		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_template.php');

		//don't propagate any local changes to actions to child rebuilds.
		$originalactions = $actions;
		if ($styleid != -1)
		{
			$usecssfiles = $this->useCssFiles($styleid);

			//this is some *old* code.  I think it's due to some fields that writing css files
			//relies on not getting set, but it's been copied, tweaked, and mangled since cssasfiles
			//referred to the vB3 css and not the css template sheets so it's not 100% if it's needed
			//any longer.
			if (($actions['doreplacements'] OR $actions['dostylevars']) AND $usecssfiles)
			{
				$actions['doreplacements'] = true;
			}

			unset($this->stylesById[$styleid]);
			// build the templateid cache
			if (!$parentlist)
			{
				$parentlist = $this->fetchTemplateParentlist($styleid);
			}

			$templatelist = $this->buildTemplateIdCache($styleid, 1, $parentlist);
			$styleupdate = array();
			$styleupdate['templatelist'] = $templatelist;

			// cache special templates
			if ($actions['dostylevars'] OR $actions['doreplacements'] OR $actions['doposteditor'])
			{
				// get special templates for this style
				$template_cache = array();
				$templateids = unserialize($templatelist);
				$specials = vB_Api::instanceInternal('template')->fetchSpecialTemplates();

				if ($templateids)
				{
					$templates = $assertor->assertQuery('vBForum:fetchtemplatewithspecial', array(
						'templateids' => $templateids,
						'specialtemplates' => $specials
					));

					foreach ($templates as $template)
					{
						$template_cache["$template[templatetype]"]["$template[title]"] = $template;
					}
				}
			}

			// style vars
			if ($actions['dostylevars'])
			{
				if ($template_cache['stylevar'])
				{
					// rebuild the stylevars field for this style
					$stylevars = array();
					foreach($template_cache['stylevar'] AS $template)
					{
						$stylevars["$template[title]"] = $template['template'];
					}
				}

				// new stylevars
				static $master_stylevar_cache = null;
				if ($resetcache)
				{
					$resetcachedone = true;
					$master_stylevar_cache = null;
				}

				if ($master_stylevar_cache === null)
				{
					$master_stylevar_cache = array();
					$master_stylevars = $assertor->assertQuery('vBForum:getDefaultStyleVars');

					foreach ($master_stylevars AS $master_stylevar)
					{
						$tmp = unserialize($master_stylevar['value']);
						if (!is_array($tmp))
						{
							$tmp = array('value' => $tmp);
						}
						$master_stylevar_cache[$master_stylevar['stylevarid']] = $tmp;
						$master_stylevar_cache[$master_stylevar['stylevarid']]['datatype'] = $master_stylevar['datatype'];
					}
				}

				$newstylevars = $master_stylevar_cache;

				if (substr(trim($parentlist), 0, -3) != '')
				{
					$data = array(
						'stylelist' => explode(',', substr(trim($parentlist), 0, -3)),
						'parentlist' => $parentlist
					);
					$new_stylevars = $assertor->getRows('vBForum:getStylesFromList', $data);

					foreach ($new_stylevars as $new_stylevar)
					{
						ob_start();
						$newstylevars[$new_stylevar['stylevarid']] = unserialize($new_stylevar['value']);
						if (ob_get_clean() OR !is_array($newstylevars[$new_stylevar['stylevarid']]))
						{
							continue;
						}
						$newstylevars[$new_stylevar['stylevarid']]['datatype'] = $master_stylevar_cache[$new_stylevar['stylevarid']]['datatype'];
					}
				}

				$styleupdate['newstylevars'] = serialize($newstylevars);
			}

			// replacements
			if ($actions['doreplacements'])
			{
				// rebuild the replacements field for this style
				$replacements = array();
				if (is_array($template_cache['replacement']))
				{
					foreach($template_cache['replacement'] AS $template)
					{
						// set the key to be a case-insentitive preg find string
						$replacementkey = '#' . preg_quote($template['title'], '#') . '#si';

						$replacements["$replacementkey"] = $template['template'];
					}
					$styleupdate['replacements'] = serialize($replacements) ;
				}
				else
				{
					$styleupdate['replacements'] = "''";
				}
			}

			// post editor styles
			if ($actions['doposteditor'] AND $template_cache['template'])
			{
				$editorstyles = array();
				if (!empty($template_cache['template']))
				{
					foreach ($template_cache['template'] AS $template)
					{
						if (substr($template['title'], 0, 13) == 'editor_styles')
						{
							$title = 'pi' . substr($template['title'], 13);
							$item = fetch_posteditor_styles($template['template']);
							$editorstyles["$title"] = array($item['background'], $item['color'], $item['padding'], $item['border']);
						}
					}
				}
			}

			// do the style update query
			if (!empty($styleupdate))
			{
				$styleupdate['styleid'] = $styleid;
				$styleupdate[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_UPDATE;
				$assertor->assertQuery('vBForum:style', $styleupdate);
			}

			//write out the new css -- do this *after* we update the style record
			if ($usecssfiles)
			{
				if (!write_style_css_directory($styleid, $parentlist, 'ltr'))
				{
					return fetch_error("rebuild_failed_to_write_css");
				}
				else if (!write_style_css_directory($styleid, $parentlist, 'rtl'))
				{
					return fetch_error("rebuild_failed_to_write_css");
				}
			}
		}

		if ($updateChildren)
		{
			$childsets = $assertor->getRows('style', array('parentid' => $styleid));
			if (count($childsets))
			{
				foreach ($childsets as $childset)
				{
					if ($error = $this->buildStyleInternal($childset['styleid'], $childset['title'], $originalactions, $childset['parentlist'], false, true))
					{
						return $error;
					}
				}
			}
		}

		//We want to force a fastDS rebuild, but we can't just call rebuild. There may be dual web servers,
		// and calling rebuild only rebuilds one of them.
		$options = $datastore->getValue('miscoptions');
		$options['tmtdate'] = vB::getRequest()->getTimeNow();
		$datastore->build('miscoptions', serialize($options), 1);
	}


	/**
	 * Builds all data from the template table into the fields in the style table
	 *
	 * @param	boolean Not used, feature removed.
	 * @param	boolean	If true, will fix styles with no parent style specified
	 * @param	boolean	If true, reset the master cache
	 * @param boolean -- true if successful, otherwise throws an exception
	 */
	public function buildAllStyles($renumber = 0, $install = 0, $resetcache = false)
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('master_style'));

		require_once(DIR . '/includes/adminfunctions_template.php');
		build_template_parentlists();

		$styleactions = array('dostylevars' => 1, 'doreplacements' => 1, 'doposteditor' => 1);

		$this->buildStyle(-1, $vbphrase['master_style'], $styleactions, $resetcache);

		$this->buildStyleDatastore();
		return true;
	}

	public function checkStyleWriteProtection($styleid)
	{
		if (empty($styleid))
		{
			// if styleid is null or 0, assume it's a new style and has no write protection.
			return true;
		}

		$vb5_config = &vB::getConfig();
		if ( $vb5_config['Misc']['debug'] )
		{
			// Debug  mode allows write on protected styles
			return true;
		}

		// The "master style" doesn't exist. Assume it's write protected
		if ($styleid == -1)
		{
			if (VB_AREA == 'Upgrade' OR VB_AREA == 'Install')
			{
				// temporary debugging bypass. bad bad bad
				return true;
			}
			return false;
		}

		$style = $this->fetchStyleByID($styleid);
		$canWrite = (bool) ($style['styleattributes'] & vB_Library_Style::ATTR_WRITE);
		return $canWrite;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
