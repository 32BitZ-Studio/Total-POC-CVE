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

class vB_Xml_Import_Theme extends vB_Xml_Import
{
	const DEFAULT_GRANDPARENT_GUID = 'vbulletin-theme-parent-readonly-5660da3dd0cc42.92747689';
	const DEFAULT_PARENT_GUID = 'vbulletin-theme-parent-53516be9caa311.54941284';
	// @TODO - DEFAULT_THEME_GUID is deprecated, the style was removed in VBV-14913
	const DEFAULT_THEME_GUID = 'vbulletin-theme-default-ead8b80bfd72e5257178b41f45c64178';

	protected static $themeGrandParent;
	protected static $themeParent;

	/*
	 *	Import theme from an array of already parsed XML data. This function should be called from the adminCP
	 */
	public function importAdminCP($parsedXML, $startat = 0, $perpage = 1, $overwrite = false, $styleid = -1, $anyversion = false, $extra = array())
	{
		/*
		 *	Since this function allows passing in a string rather than pulling a file from the filesystem, we should
		 *	be more careful about who can call it
		 *	This check is based on the admincp/template.php script @ if ($_REQUEST['do'] == 'upload'). We should keep them in line.
		 */
		$canAdminTemplates = vB::getUserContext()->hasAdminPermission('canadmintemplates');
		$canAdminStyles = vB::getUserContext()->hasAdminPermission('canadminstyles');
		if (!($canAdminTemplates OR $canAdminStyles))
		{
			require_once(DIR . '/includes/adminfunctions.php');
			print_cp_no_permission();
		}

		// If we came in through adminCP, we probably already checked this.
		// But let's do it again just in case...
		$styleApi = vB_Api::instanceInternal('style');
		$canImportCheck = $styleApi->checkCanImportStyleXML($xml);
		if (!$canImportCheck['canimport'])
		{
			require_once(DIR . '/includes/adminfunctions.php');
			print_stop_message($canImportCheck['reason']);
		}

		if (empty($parsedXML['guid']))
		{
			// todo: some error handling here if basic xml file validation isn't okay.
		}
		$this->parsedXML['theme'] = $parsedXML;

		// make sure we have the theme parent, as any imported themes will be its children
		if (empty(self::$themeParent['guid']))
		{
			$this->getDefaultParentTheme();
		}

		/*
		 *	drop any unexpected extra variables.
		 *	Let's also clean them, since there might be someway a user w/ the right permissions
		 *	hits this function directly. So here we have an issue. If coming through the adminCP page,
		 *	things will already be cleaned, so STRINGS will already be escaped. However, I don't think
		 *	the title should contain any special HTML characters, so I think we don't have to worry about
		 *	double escaping here. If we do end up having to worry about double escaping, we need to remove
		 *	the cleaning here, and just rely on the adminCP page's cleaning, then make sure NOTHING HERE
		 *	GOES STRAIGHT TO DB without going through the assertor in adminfunctions_template.php
		 */
		$unclean = $extra;
		$extra = array();
		$cleanMap = array(
			'title' => vB_Cleaner::TYPE_STR,
			'parentid' => vB_Cleaner::TYPE_INT,
			'displayorder' => vB_Cleaner::TYPE_INT,
			'userselect' => vB_Cleaner::TYPE_BOOL,
		);
		foreach ($unclean AS $key => $value)
		{
			if (isset($cleanMap[$key]))
			{
				$extra[$key] = vB::getCleaner()->clean($value,  $cleanMap[$key]);
			}
		}

		$result = $this->import($startat, $perpage, $overwrite, $styleid, $anyversion, $extra);

		//we should pass the phrase through to the caller an let them deal with it,
		//but that's out of scope of this issue (VBV-17022).  Generally we don't want to
		//be rendering phrases deep in code.
		$phrases = vB_Api::instanceInternal('phrase')->renderPhrases(array('output' => $result['output']));
		$result['output'] = $phrases['phrases']['output'];

		return $result;
	}

	/*
	 *	Performs the gritty work of importing the parsed XML data into the database
	 *	Before calling this function, the caller must ensure that $this->parsedXML['theme'] is set with
	 *	the parsed XML data. See where this function is called from within function importThemes() for
	 *	an example.
	 *
	 *	Todo: We need some sort of consistent error handling here when provided data is incomplete or
	 *	some errors arise while importing the XML data. AFAIK this function will be accessed from two
	 *	locations, the installer & adminCP.
	 */
	protected function import($startat = 0, $perpage = 1, $overwrite = false, $styleid = -1, $anyversion = false, $extra = array())
	{
		require_once(DIR . '/includes/adminfunctions_template.php');
		require_once(DIR . '/includes/adminfunctions.php');

		$xml = $this->parsedXML['theme'];
		$themeName = $xml['name'];
		unset($this->parsedXML['theme']);

		// At the very least we need guid (icon is optional) for a theme
		if (empty($xml['guid']))
		{
			return array(
				'done'    => true,
				'output'  => array('theme_x_invalid_data_skipped', $xml['name']),
				"error" => "GUID and icon must be specified for a theme!",
			);
		}

		/*
			On import the theme import should fail if the theme is already installed (per the guid value)
			unless an overwrite is requested. If an overwrite is requested than any parent/title information
			for the import is ignored and the existing theme is overwritten by the import.
		*/
		// we don't add the GUID until we're done, so this check works even when we're in the middle of
		// importing a theme in partitions
		$existingTheme = $this->db->getRow('style', array('guid' => $xml['guid']));
		if (!empty($existingTheme))
		{
			// TODO: need to test that overwrite works correctly
			if ($overwrite)
			{
				// ignore parent & title info, overwrite existing theme.
				unset($xml['name']);
				$title = $existingTheme['title'];
				// If styleid is not -1, xml_import_style will ignore the parentid, so it's only used for the style record creation.
				// This works with overwrite (ignore parent relation).
				$parentid = $existingTheme['parentid'];
				$styleid = $existingTheme['styleid'];
				$product = (empty($xml['product']) ? 'vbulletin' : $xml['product']);
				// grab rest form user input if set. Otherwise, use defaults.
				$userselect = (empty($extra['userselect']) ? false : $extra['userselect']);
				$displayorder = (empty($extra['displayorder']) ? 1 : $extra['displayorder']);
			}
			else
			{
				/*
					TODO: The admincp should be updated to attempt the import without overwrite and request
						confirmation for overwrite if the install fails due to the theme already existing.
				 */
				return array(
					'done'    => true,
					'output'  => array('theme_x_exists_skipped', $xml['name']),
					"warning" => "The theme exists, and overwrite was not specified. Skipping import.",
				);
				// we're not in overwrite mode, and theme already exists. Let's just return.
			}
		}
		elseif ($startat == 0)
		{
			/*
			 *	We need to add this new theme. Setting styleid to -1 should allow the existing import code
			 *	to take care of it for us.
			 */

			$styleid = -1;
			$product = (empty($xml['product']) ? 'vbulletin' : $xml['product']);
			/*
			 *	For a new import, use user selected data for title, parentid and userselect. If no user provided
			 *	input is available, use xml provided info or defaults.
			 *	User input will only be available for adminCP imports, not install/upgrades
			 */
			$title = (empty($extra['title']) ? (!empty($xml['name']) ? $xml['name'] : '') : $extra['title']);
			$parentid = (empty($extra['parentid']) ? self::$themeParent['styleid'] : $extra['parentid']);
			$userselect = (empty($extra['userselect']) ? false : $extra['userselect']);
			$displayorder = (empty($extra['displayorder']) ? 1 : $extra['displayorder']);
		}

		// If styleid is not -1, xml_import_style will ignore the parentid, so it's only used for the style record creation.
		// This works with overwrite (ignore parent relation).
		$requireUniqueTitle = false; // we intentionally have the same title for a new editable child created for a protected theme. Upgrade 520a3 requires this bypass
									 // as it tries to import *new* themes on top of old themes w/ null GUIDs, in order to preserve customizations.
		$info = xml_import_style(false, $styleid, $parentid, $title, $anyversion, $displayorder, $userselect, $startat, $perpage, false, $xml, $requireUniqueTitle);

		// If we're done importing all the templates 1 by 1, the stylevar definitions & style vars. Let's
		// add the theme-specific data.
		if ($info['done'])
		{
			// If import finished on 1 iteration (which it does if the theme/style has no template groups to import),
			// we need to grab the styleid of the new style record that was created because $styleid is still -1 at
			// this point.
			if ($info['overwritestyleid'] > -1)
			{
				$styleid = $info['overwritestyleid'];
			}

			$updateParams = array('guid' =>	$xml['guid']);

			if (!empty($xml['icon']))
			{
				try
				{
					$filedataid = $this->uploadThemeImage($xml['icon']);
					if ($filedataid)
					{
						$updateParams['filedataid'] = $filedataid;
					}
				}
				catch (Exception $e)
				{
					// ATM we just ignore errors in icon/preview image uploads and just import the theme without it
					// since icons & preview images are optional
					// A neat TODO would be to add a warning here instead, and have the upgrader or adminCP
					// pull all warnings out and display them after each theme's import is finished.
				}
			}

			if (!empty($xml['previewimage']))
			{
				try
				{
					$filedataid = $this->uploadThemeImage($xml['previewimage']);
					if ($filedataid)
					{
						$updateParams['previewfiledataid'] = $filedataid;
					}
				}
				catch (Exception $e)
				{
					// ATM we just ignore errors in icon/preview image uploads and just import the theme without it
					// since icons & preview images are optional
					// A neat TODO would be to add a warning here instead, and have the upgrader or adminCP
					// pull all warnings out and display them after each theme's import is finished.
				}
			}

			// In addition to the filedataid and previewdataid, handle any other theme-specific style table fields here

			$this->db->update('style',
				$updateParams,
				array('styleid' => $styleid)
			);

			// TODO: Figure out what this is used for
			vB_Xml_Import::setImportedId(vB_Xml_Import::TYPE_THEME, $xml['guid'], $styleid);

			if (empty($info['output']))
			{
				$info['output'] = array('theme_x_imported', $themeName);
			}
		}

		// Check if a child is needed, and add it.
		$this->addChild($xml['guid']);

		/*
			xml_import_style returns:
			return array(
				'version' => $version,
				'master'  => $master,
				'title'   => $title,
				'product' => $product,
				'done'    => $done,
				'overwritestyleid' => $styleid,
				'output'  => $outputtext,
				);
		 */
		return $info;
	}

	private function addChild($guid)
	{
		$parent = $this->db->getRow('style', array('guid' => $guid));
		if (empty($parent))
		{
			// If parent wasn't created for some reason, there's nothing we can do.
			// Shouldn't ever hit this though, unless addChild() is called from outside of
			// import()
			return;
		}

		// Ignore any children that do not have the DEFAULT styleattributes.
		$existing = $this->db->getRow('style', array('parentid' => $parent['styleid'], 'styleattributes' => vB_Library_Style::ATTR_DEFAULT));
		if (!empty($existing))
		{
			// A previous import (or a user) created at least 1 child of this theme. Do not create another child.
			return;
		}

		// Create a child. Note, this means if a user deletes a writeable theme-child, the upgrade will recreate a fresh copy!
		//
		$titleForGuid = strtolower(str_replace(' ', '', $parent['title']));
		$guid = vB_GUID::get("vbulletin-theme-" . $titleForGuid . "-writable-");
		// This method is called by the adminCP template page when a child is created.
		$this->doInsertTheme(
			$parent['title'], // . " (Writable)", // We may need to ensure that the child style's title is different to avoid conflicts with some code in xml_import_style()
			$parent['styleid'],
			$parent['userselect'],   // should these just default to something?
			$parent['displayorder'], // should these just default to something?
			$guid
		);
	}

	// Keep this in sync with vB_Api_Style::insertStyle()
	protected function doInsertTheme($title, $parentid, $userselect, $displayorder, $guid, $icon = '', $previewImage = '', $styleattributes = vB_Library_Style::ATTR_DEFAULT, $dateline = null)
	{
		/*
			For theme-related inserts, we need to be able to set the GUID whether it's read only or editable.
			The theme API blocks this based on debug mode, and it's nontrivial to open that up for themes but
			not *all* styles. For now, I'm just duplicating the API code.
		 */

		if (empty($guid))
		{
			// TODO: should we throw an exception if no guid is provided?
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
			'guid' => $guid,
			'dateline' => $dateline,
		));

		if (is_array($result))
		{
			// these do not work yet, because vB_dB_Query_Insert::doInserts() doesn't return the error in any form yet.
			if (!empty($result['error']))
			{
				return $result;
			}
			else if (!is_numeric($result) AND is_string($result))
			{
				// just in case the assertor does not return an error array, but returns some kind of string or something...
				return array('error' => $result);
			}
			$result = array_pop($result);
		}

		require_once(DIR . '/includes/adminfunctions_template.php');
		build_template_parentlists();

		$styleLib = vB_Library::instance('style');

		$styleLib->buildStyle($result, $title, array(
				'docss' => 1,
				'dostylevars' => 1,
				'doreplacements' => 1,
				'doposteditor' => 1
		), false);

		// Optimization TODO: Delay this until *all* imports are done, or does each style require this rebuild?
		$styleLib->buildStyleDatastore();

		return array('styleid' => $result);
	}

	/**
	 * Uploads a theme image (icon or preview image) from the image data
	 *
	 * @param	binary		Image data to upload
	 *
	 * @return	int|bool	Filedataid for the image or false if the image could not be uploaded.
	 */
	public function uploadThemeImageData($imageData)
	{
		$result = $this->uploadImageStreamStringToFiledata($imageData, 'vb_theme_image_');

		// Make the file data public & update style record w/ this filedataid
		if ($result AND !empty($result['filedataid']))
		{
			$this->db->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $result['filedataid']));

			return $result['filedataid'];
		}

		return false;
	}

	/**
	 * Uploads a theme image (icon or preview image)
	 *
	 * @param	string	Base64-encoded image data.
	 *
	 * @return	int|bool	Filedataid for the image or false if the image could not be uploaded.
	 */
	protected function uploadThemeImage($encodedImageData)
	{
		// Upload Icon
		$imageData = base64_decode($encodedImageData);

		if ($imageData !== false)
		{
			$result = $this->uploadImageStreamStringToFiledata($imageData, 'vb_theme_image_');

			// Make the file data public & update style record w/ this filedataid
			if ($result AND !empty($result['filedataid']))
			{
				$this->db->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $result['filedataid']));

				return $result['filedataid'];
			}
		}

		return false;
	}

	/*
	 *	Saves a string as a temporary file and uploads it to create a filedata record
	 *	TODO: Should we move this into the content_attach library?
	 *
	 *	@param	string	$imageContent	the binary image stream
	 *	@param 	string	$prefix			(Optional) filename prefix for the temporary file
	 *										created by this function. This file will be
	 *										deleted after the filedata record is created.
	 *	@return	array
	 *					key 'filedataid' : the filedataid of the new record that's created
	 */
	protected function uploadImageStreamStringToFiledata($imageContent, $prefix = 'vb_')
	{
		// It doesn't seem like we have existing functions to just save the raw image stream as filedata.
		// The existing content_attach functions seem to all require some temporary file to exist somewhere.
		// So let's save the image in a temporary file, save it to the file system using existing functions,
		// then remove the file.
		$tempIconFileLocation = vB_Utilities::getTmpFileName('', $prefix); // removal happens below, look for the unlink() call
		file_put_contents($tempIconFileLocation, $imageContent);

		// todo: scan the image stream??

		/*
		 * Below depends on the GD library
		 * http://www.php.net/manual/en/function.getimagesize.php
		 *	Index 0 and 1 contains respectively the width and the height of the image.
		 *	Index 2 is one of the IMAGETYPE_XXX constants indicating the type of the image.
		 *	Index 3 is a text string with the correct height="yyy" width="xxx" string that can be used directly in an IMG tag.
		 *	mime is the correspondant MIME type of the image. This information can be used to deliver images with the correct HTTP Content-type header:
		 */
		$imageSize = getimagesize($tempIconFileLocation);
		$extension = image_type_to_extension($imageSize[2], false);
		$fileArray = array();
		$fileArray['tmp_name'] = $tempIconFileLocation;

		// apparently fetchThumbnail() requires that the NAME has a valid extension... This is just bogus because we totally made up this file, but whatever
		$fileArray['name'] = 'image_' . md5(microtime(true)) . "." . $extension;

		$userid = vB::getCurrentSession()->get('userid');

		$result = vB_Library::instance('content_attach')->saveThemeIcon(
			$userid,
			$fileArray,
			$imageContent,
			filesize($tempIconFileLocation),
			$extension,
			true,
			true	// $skipUploadPermissionCheck IS A TEMPORARY SOLUTION.
		);

		// temp file deletion is not done automatically, so we must do it.
		if (!empty($tempIconFileLocation))
		{
			@unlink($tempIconFileLocation);
		}

		if (!isset($result['filedataid']))
		{
			/*
			 *	If we cannot upload an image, we should just continue importing the theme as
			 *	icons and preview image are optional.
			 *	I'm leaving an exception here in case we want to handle it better, or we want
			 *	to move this into an API class, so the caller should catch the exception and
			 *	handle it accordingly.
			 */
			throw new vB_Exception_Api('theme_icon_upload_error');
		}

		 /*
		 *	Note, this function returns an array to adhere to API standards just in	case this
		 *	ends up being moved into an API class. If we do move it into an API class, we may
		 *	want to change the Exception above to be a vB_Exception_Api
		 */
		return array('filedataid' => $result['filedataid']);
	}

	/*
	 * We're adding another level on top of the theme parent that's read-only, and
	 * making the theme parent writable. This function does basically what getDefaultParentTheme() does,
	 * but for guid DEFAULT_GRANDPARENT_GUID instead.
	 */
	public function getDefaultGrandParentTheme()
	{
		if (empty(self::$themeGrandParent))
		{
			self::$themeGrandParent = $this->db->getRow('style', array('guid' => self::DEFAULT_GRANDPARENT_GUID));
		}

		// If the default parent theme exists, return it. Else, create it & return it.
		if (!empty(self::$themeGrandParent['guid']))
		{
			return self::$themeGrandParent;
		}
		else
		{
			/*
				The main difference betweent his & themeParent is the guid, parentid & styleattributes.
			 */
			$parentTitle = vB_Api::instanceInternal('phrase')->fetch('theme_parent_name');
			$parentTitle = $parentTitle['theme_parent_name'];
			// we need to add the blank style
			$insertResult = $this->doInsertTheme(
				$parentTitle,	// title
				-1,				// parentid
				0,				// userselect
				0,				// displayorder
				self::DEFAULT_GRANDPARENT_GUID,	// guid
				'', 			// icon
				'',				// preview image
				vB_Library_Style::ATTR_PROTECTED // styleattributes
			);
			if (empty($insertResult['styleid']) OR !is_numeric($insertResult['styleid']))
			{
				// if we can't create the default parent, we don't want to recurse forever.
				throw new vB_Exception_AdminStopMessage(array('theme_failed_to_create_parent_readonly', $insertResult['error']));
			}

			return $this->getDefaultGrandParentTheme();
		}
	}

	/*
	 *	Gets the default parent theme & sets it to self::$themeParent class variable as well as
	 *	returning it. If the theme isn't found, it inserts one to the style table.
	 */
	public function getDefaultParentTheme()
	{
		$this->getDefaultGrandparentTheme();
		if (empty(self::$themeParent))
		{
			self::$themeParent = $this->db->getRow('style', array('guid' => self::DEFAULT_PARENT_GUID));
		}

		// If the default parent theme exists, return it. Else, create it & return it.
		if (!empty(self::$themeParent['guid']))
		{
			return self::$themeParent;
		}
		else
		{
			/*
				VBV-12430 Automatically install packaged themes :
					If there are themes to install, create an empty style call themes.
					Make all installed themes children of this new style.
					This style should itself be a theme (so it is not editable, etc) but should not be displayed or selected
			 */
			$parentTitle = vB_Api::instanceInternal('phrase')->fetch('theme_parent_name');
			$parentTitle = $parentTitle['theme_parent_name'];
			// we need to add the blank style
			$insertResult = $this->doInsertTheme(
				$parentTitle,	// title
				self::$themeGrandParent['styleid'],				// parentid
				0,				// userselect
				0,				// displayorder
				self::DEFAULT_PARENT_GUID,	// guid
				'', 			// icon
				'',				// preview image
				vB_Library_Style::ATTR_DEFAULT	// styleattributes
			);
			if (empty($insertResult['styleid']) OR !is_numeric($insertResult['styleid']))
			{
				// if we can't create the default parent, we don't want to recurse forever.
				throw new vB_Exception_AdminStopMessage(array('theme_failed_to_create_parent', $insertResult['error']));
			}

			// no reason to copy code. The DB Fetch at the beginning of this function will handle retrieving
			// the newly created style.
			return $this->getDefaultParentTheme();
		}
	}

	/*
	 *	Automatically import the themes included in the theme folder
	 */
	public function importThemes($perpage = 1, $overwrite = false)
	{
		$themesdir = DIR . '/install/themes/';
		if (is_dir($themesdir))
		{
			/*
			 *	There's a bug in the upgrader where only the 'startat' parameter can be returned & used in
			 *	the upgrade steps. Since the same upgrade step will be run for a single file, and we have
			 *	multiple files to process, we need to keep track of 1) which file we were on and 2) which
			 *	iteration of that file we are on. Since we only have 1 variable to keep track of at least
			 *	multiple values, we need another way to keep track of data between sessions.
			 */
			$datastore = vB::getDatastore();
			$dataTitle = "themeImportProgress";
			$importProgress = $datastore->getValue($dataTitle);
			if (is_null($importProgress))
			{
				$importProgress = '';
			}
			$importProgress = json_decode($importProgress, true);
			/*
			 * json_encode-d array of
			 *	'finished' => 	{array of fully imported filenames},
			 *	'current'  => 	{array
			 *						'filename' => {current filename},
			 *						'startat' => {current progress index} ,
			 *						'styleid' => {styleid of added style record if we're not at startat==0}
			 *					},
			 *	'remaining'	=> 	{array of remaining filenames}
			 *
			 *	I'm not storing the parsed XML in here, because I'm not certain if the json_encoded data with the parsed
			 *	XML can be guaranteed to be less than mediumtext's (type of datastore.data) limit of	2^24 + 3 bytes.
			 */
			if (empty($importProgress))
			{
				$importProgress = array(
					'finished' => array(),
					'remaining' =>
						array_filter(
							scandir($themesdir),
							function($filename) use ($themesdir)
							{
								return (
									!is_dir($themesdir . '/' . $filename)
									AND (strtolower(pathinfo($filename, PATHINFO_EXTENSION)) === 'xml')
								); // skip directories and make sure it has xml extension
							}
						),
				);
				// TODO: need better check to grab REAL files only. One approach is to use a filename prefix and check for that, like how customlanguages does it
			}

			// Let's grab the file to work on next if we don't have one
			if (empty($importProgress['current']))
			{
				// we have no files remaining to import
				if (empty($importProgress['remaining']))
				{
					$datastore->build($dataTitle, '', 0);
					return array('done' => true, 'continue' => false, 'output' => '');
				}
				else
				{
					$importProgress['current']['filename'] = $themesdir . '/' . array_shift($importProgress['remaining']);
					$importProgress['current']['startat'] = 0;
					$importProgress['current']['styleid'] = -1;
				}
			}

			// make sure we have the theme parent, as any imported themes will be its children
			if (empty(self::$themeParent['guid']))
			{
				$this->getDefaultParentTheme();
			}

			// fetch the XML file and parse it into something we can understand
			$this->parsedXML['theme'] = vB_Xml_Import::parseFile($importProgress['current']['filename']);

			// ensure that imported theme is a child of the blank parent theme. Any other kind of
			// default data setting global to all "auto-import @ install" themes should happen here.
			$this->parsedXML['theme']['parentid'] = self::$themeParent['styleid'];

			// overwrite check happens inside import()
			$info = $this->import($importProgress['current']['startat'], $perpage, $overwrite, $importProgress['current']['styleid'], true);

			if ($info['done'])
			{
				$importProgress['finished'][] = $importProgress['current']['filename'];
				unset($importProgress['current']);
			}
			else
			{
				$importProgress['current']['styleid'] = $info['overwritestyleid'];
				$importProgress['current']['startat'] += $perpage;
			}

			$importProgress = json_encode($importProgress);

			$datastore->build($dataTitle, $importProgress, 0);

			// move onto the next iteration of this file (or the next file, whichever is appropriate).
			return array('done' => false, 'continue' => true, 'output' => $info['output']);
		}
		else
		{
			// themes folder does not exist. nothing to import
			return array('done' => true, 'continue' => false, 'output' => '', 'debug' => "Theme folder ({$themesdir}) does not exist or is not a directory.");
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102679 $
|| #######################################################################
\*=========================================================================*/
