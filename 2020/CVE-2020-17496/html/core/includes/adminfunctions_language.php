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

error_reporting(E_ALL & ~E_NOTICE);

/**
* Fetches either the entire languages array, or a single language
* If only languageid and title are required, use 'languagecache' in datastore instead.
*
* @param	integer	Lanugage ID - if specified, will return only that language, otherwise all languages
* @param	boolean	If true, fetch only languageid and title
*
* @return	array
*/
function fetch_languages_array($languageid = 0, $baseonly = false)
{
	$bf_misc_languageoptions = vB::getDatastore()->getValue('bf_misc_languageoptions');
	$languages = vB::getDbAssertor()->getRows('fetchLanguages', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
		'baseonly' => $baseonly,
		'direction' => $bf_misc_languageoptions['direction'],
		'languageid' => $languageid,
	));

	if (count($languages) == 0)
	{
		// TODO: throw exception
		throw new Exception('invalid_language_specified');
	}

	if ($languageid)
	{
		return array_pop($languages);
	}
	else
	{
		$languagearray = array();
		foreach ($languages as $language)
		{
			$languagearray["$language[languageid]"] = $language;
		}
		return $languagearray;
	}

}

/**
* Fetches an array of existing phrase types from the database
*
* @param	boolean	If true, will return names run through ucfirst()
*
* @return	array
*/
function fetch_phrasetypes_array($doUcFirst = false)
{
	return vB_Api::instanceInternal('phrase')->fetch_phrasetypes($doUcFirst);
}

/**
* Builds the languages datastore item
*
* @return	array	The data inserted into datastore
*/
function build_language_datastore()
{
	$languagecache = array();
	$languages = vB::getDbAssertor()->assertQuery('language',
		array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('languageid', 'title', 'userselect', 'charset', 'options')
		),
		'title'
	);

	$bf_misc_languageoptions = vB::getDatastore()->getValue('bf_misc_languageoptions');
	foreach ($languages as $language)
	{
		$language['direction'] = ($language['options'] & $bf_misc_languageoptions['direction']) ? 'ltr' : 'rtl';
		$languagecache["$language[languageid]"] = $language;
	}

	build_datastore('languagecache', serialize($languagecache), 1);

	return $languagecache;
}

/**
* Reads a language or languages and updates the language db table with the denormalized phrase cache
*
* @param	integer	ID of language to be built; if -1, build all
* @param	integer	Not sure actually... any ideas?
* @param	boolean.  Wether to reset the static vars the function uses to cache items for recursing
* 			when we we build the master language.  Otherwise if we attempt to call this function
* 			twice in the same pageload we don't actually manage to update any changes after the first
* 			call.
* 			The better approach would be to use an internal function and a master function t
* 			hat generates the cached values once and passes them in.
* 			However that means unwinding this function which works but is... odd.
*/
function build_language($languageid = -1, $phrasearray = 0, $reset_static=true)
{
	static $masterlang = null, $jsphrases = null;
	require_once(DIR . '/includes/adminfunctions.php');

	if($reset_static)
	{
		$masterlang = null;
		$jsphrases = null;
	}

	// load js safe phrases
	if ($jsphrases === null)
	{
		$xmlobj = new vB_XML_Parser(false, DIR . '/includes/xml/js_safe_phrases.xml');
		$safephrases = $xmlobj->parse();

		$jsphrases = array();

		if (is_array($safephrases['phrase']))
		{
			foreach ($safephrases['phrase'] AS $varname)
			{
				$jsphrases["$varname"] = true;
			}
		}
		unset($safephrases, $xmlobj);
	}


	// update all languages if this is the master language
	if ($languageid == -1)
	{
		$languages = vB::getDatastore()->getValue('languagecache');

		if (empty($languages))
		{
			// during install, the datastore is empty
			$languages = vB::getDbAssertor()->assertQuery('language', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('languageid')
			));
		}

		foreach ($languages as $language)
		{
			build_language($language['languageid'], 0, false);
		}

		return;
	}

	// get phrase types for language update
	$gettypes = array();
	$getphrasetypes = vB::getDbAssertor()->getRows('vBForum:fetchphrasetypes', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED));
	foreach ($getphrasetypes as $getphrasetype)
	{
		$gettypes[] = $getphrasetype['fieldname'];
	}
	unset($getphrasetype);

	//This can be called early in the install process, before phrases have been inserted
	if (empty($gettypes))
	{
		return true;
	}

	if (empty($masterlang))
	{
		$masterlang = array();

		$phrases = vB::getDbAssertor()->assertQuery('vBForum:phrase', array(
			'languageid' => array(-1, 0),
			'fieldname' => $gettypes,
			vB_dB_Query::COLUMNS_KEY => array('fieldname', 'varname', 'text')
		));

		foreach ($phrases as $phrase)
		{
			if (isset($jsphrases["$phrase[varname]"]))
			{
				$phrase['text'] = fetch_js_safe_string($phrase['text']);
			}
			if (strpos($phrase['text'], '{1}') !== false)
			{
				$phrase['text'] = str_replace('%', '%%', $phrase['text']);
			}

			$phrase['text'] = str_replace(
				array('', ''),
				'',
				$phrase['text']
			);

			$masterlang["{$phrase['fieldname']}"]["$phrase[varname]"] = $phrase['text'];
		}
	}

	// get phrases for language update
	$phrasearray = $masterlang;
	$phrasetemplate = array();

	$phrases = vB::getDbAssertor()->assertQuery('vBForum:phrase', array(
		'languageid' => $languageid,
		'fieldname' => $gettypes,
		vB_dB_Query::COLUMNS_KEY => array('fieldname', 'varname', 'text')

	));

	foreach ($phrases as $phrase)
	{
		if (isset($jsphrases["$phrase[varname]"]))
		{
			$phrase['text'] = fetch_js_safe_string($phrase['text']);
		}
		if (strpos($phrase['text'], '{1}') !== false)
		{
			$phrase['text'] = str_replace('%', '%%', $phrase['text']);
		}
		$phrasearray["{$phrase['fieldname']}"]["$phrase[varname]"] = $phrase['text'];
	}
	unset($phrase);

	if (!empty($phrasearray))
	{
		vB::getDbAssertor()->assertQuery('vBForum:rebuildLanguage', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'phrasearray' => $phrasearray,
			'languageid' => $languageid,
		));
	}

	vB_Cache::instance()->event("vB_Language_languageCache");
	// If we hit this through the installer, then all the caches are set to vB_Cache_Null and above won't do anything...
	// Try to trigger this event on the STD cache that vB_Language uses.
	if (defined('VB_AREA') AND
		(VB_AREA == "Install" OR VB_AREA == "Upgrade") AND
		is_a(vB_Cache::instance(), "vB_Cache_Null", false)
	)
	{
		// See upgrade_final's "Reset all caches" step for where it reverts the config.Cache values.
		$config =& vB::getConfig();
		if (!empty($config['Backup']['Cache']['class'][vB_Cache::CACHE_STD]))
		{
			try
			{
				$config['Cache']['class']['temp_standard'] = $config['Backup']['Cache']['class'][vB_Cache::CACHE_STD];
				vB_Cache::instance("temp_standard")->event("vB_Language_languageCache");
				// we don't clear "temp_standard", and instead rely on upgrade_final's call to vB_Cache::resetAllCache() to
				// deal with it so that we avoid clearing the cache multiple times unnecessarily.
			}
			catch (Exception $e)
			{
				// If this failed, there's not much we can do.
				unset($config['Cache']['class']['temp_standard']);
			}
		}
	}
}

/**
* Fetches an array of phrases not present in the master language
*
* @param	integer	Language ID - language from which to fetch phrases
* @param	integer	Phrase fieldname - '' = all, -1 = all normal (special = 0), x = specified fieldname
*
* @return	array	array(array('varname' => 'phrase_varname', 'text' => 'Phrase Text'), array(... ))
*/
function fetch_custom_phrases($languageid, $fieldname = '')
{
	if ($languageid == -1)
	{
		return array();
	}

	$phrases = vB::getDbAssertor()->assertQuery('fetchPhrases', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
		'languageid' => $languageid,
		'fieldname' => $fieldname,
		'type' => 0
	));

	if (!$phrases OR !$phrases->valid())
	{
		return array();
	}

	$phrasearray = array();

	foreach ($phrases as $phrase)
	{
		if ($phrase['p2var'] != NULL)
		{
			$phrase['varname'] = $phrase['p2var'];
		}
		else
		{
			$phrase['varname'] = $phrase['p1var'];
		}
		if ($phrase['found'] == 0)
		{
			$phrase['text'] = $phrase['default_text'];
		}
		$phrasearray[] = $phrase;
	}

	return $phrasearray;

}

/**
* Fetches an array of phrases found in the master set
*
* @param	integer	Language ID
* @param	integer	Phrase fieldname - '' = all, -1 = all normal (special = 0), x = specified fieldname
* @param	integer	Offset key for returned array
*
* @return	array	array(array('varname' => 'phrase_varname', 'text' => 'Phrase Text'), array(... ))
*/
function fetch_standard_phrases($languageid, $fieldname = '', $offset = 0)
{
	$phrases = vB::getDbAssertor()->assertQuery('fetchPhrases', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'languageid' => $languageid,
			'fieldname' => $fieldname,
			'type' => -1
	));

	if (!$phrases OR !$phrases->valid())
	{
		return array();
	}

	$phrasearray = array();

	foreach ($phrases as $phrase)
	{
		if ($phrase['p2var'] != NULL)
		{
			$phrase['varname'] = $phrase['p2var'];
		}
		else

		{
			$phrase['varname'] = $phrase['p1var'];
		}
		if ($phrase['found'] == 0)
		{
			$phrase['text'] = $phrase['default_text'];
		}
		$phrasearray["$offset"] = $phrase;
		$offset++;
	}

	return $phrasearray;
}


/*
 *	This function requires that the new vb framework is initialized.
 */
function get_language_export_xml($languageid, $product, $custom, $just_phrases, $charset = 'UTF-8')
{
	global $vbulletin;

	//moved here from the top of language.php
	$default_skipped_groups = array(
		'cphelptext',
		'pagemeta',
	);

	$vBUtilString = vB::getString();
	if ($languageid == -1)
	{
		//		$language['title'] = $vbphrase['master_language'];
		$language['title'] = new vB_Phrase('language', 'master_language');
		/*
			We don't actually keep track of the master language charset...

			For now, just set it to the export charset so we skip the conversion, as we have absolutely no idea what the
			master phrases are encoded with.

			Later on, we might want to assume that it's the board's charset, after we ensure that every time a master
			phrase is saved or the board language is changed, the master pharses are converted to the board charset &
			updated.
		 */
		if (empty($language['charset']))
		{
			//$language['charset'] = $vBUtilString->getCharset();
			$language['charset'] = $charset;
		}
	}
	else
	{
		$language = vB::getDbAssertor()->getRow('language', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'languageid' => $languageid,
		));
	}

	$title = str_replace('"', '\"', $language['title']);
	$version = str_replace('"', '\"', $vbulletin->options['templateversion']);
	$vblangcode = str_replace('"', '\"', $language['vblangcode']);
	$revision = str_replace('"', '\"', $language['revision']);

	$phrasetypes = fetch_phrasetypes_array(false);

	$phrases = array();

	$getphrases = vB::getDbAssertor()->assertQuery('fetchPhrasesForExport', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
		'languageid'             => $languageid,
		'custom'                 => $custom,
		'product'                => $product,
		'default_skipped_groups' => $default_skipped_groups,
	));
	foreach ($getphrases as $getphrase)
	{
		if (!$custom AND $getphrase['iscustom'])
		{
			continue;
		}
		$phrases["$getphrase[fieldname]"]["$getphrase[varname]"] = $getphrase;
	}
	unset($getphrase);

	if (empty($phrases) AND $just_phrases)
	{
		throw new vB_Exception_AdminStopMessage('download_contains_no_customizations');
	}

	$xml = new vB_XML_Builder(null, $charset);

	$languagegroup = array(
		'name'      => $title,
		'vbversion' => $version,
		'product'   => $product,
		'type'      => $languageid == -1 ? 'master' : ($just_phrases ? 'phrases' : 'custom')
	);
	$vb5_config =& vB::getConfig();
	if (!empty($vblangcode) AND !empty($revision))
	{
		$languagegroup += array(
			'vblangcode' => $vblangcode,
			'revision'   => $revision,
		);
	}
	$xml->add_group('language', $languagegroup);


	/*
		If the language's charset or the target charset is not listed in the
		string class's mappings, trying to instance the class on the charset
		or do conversions between them with throw an exception.
		In that case, let's allow just exporting the language without doing
		conversions when the charsets are equal, and throw the exception when
		they're not equal.
	 */
	try
	{
		/*
			Trying to instance the string class on an unknown charset will throw an exception,
			while just running areCharsetsEqual() will return false if a charset is uknown OR if
			both charsets are known & different from each other. In the first case, trying to call toCharset()
			will throw an exception, so we have to check those cases in this fashion.
		 */
		$vBUtilString->toDefault("test", $charset);
		$vBUtilString->toDefault("test", $language['charset']);
		$doCharsetConversation = !($vBUtilString->areCharsetsEqual($language['charset'], $charset));

	}
	catch (Exception $e)
	{
		/*
			In the case where one or both charsets are unknown, just allow export if the language.charset
			& target charset are the same.
			If they're different AND at least one is unknown we don't know how to convert them so just
			rethrow the exception.
		 */
		if (strtolower($charset) == strtolower($language['charset']))
		{
			$doCharsetConversation = false;
		}
		else
		{
			// If you got to this point, please create a JIRA specifying what the language's charset &
			// export charset are, with a DB dump.
			// We'll have to determine if we can add the charset mappings (iff the internal conversion
			// functions know how to handle them) on a case by case basis.
			throw $e;
		}
	}

	if ($languageid != -1 AND !$just_phrases)
	{
		$xml->add_group('settings');
		$ignorefields = array('languageid', 'title', 'userselect', 'vblangcode', 'revision');
		foreach ($language AS $fieldname => $value)
		{

			if ($doCharsetConversation AND $fieldname == "charset")
			{
				// We'll convert charsets in the next loop, so we should specify
				// language.charset as the output charset, not the input/native charset.
				// Note that we already specify the XML's encoding attribute to $charset at the very
				// end of this function.
				// Note, in some cases, this charset & the XML encoding may be different strings,
				// if there are multiple names for the given canonical charset name.
				$value = $charset;
			}

			if (substr($fieldname, 0, 12) != 'phrasegroup_' AND !in_array($fieldname, $ignorefields))
			{
				/*
					We skip charset conversion on $value here, because the only DB fields with charset
					sensitive strings would be in the phrasegroup_X fields and *actual* phrases are added
					to the XML in the next loop.
					Note that the phrasegroup_X fields are serialized, so if we want to convert charsets
					for whatever reason, we'd need to first unserialize, convert each element, then reserialize.
				 */
				$xml->add_tag($fieldname, $value, array(), true);
			}
		}
		$xml->close_group();
	}

	if ($languageid == -1 AND !empty($default_skipped_groups))
	{
		$xml->add_group('skippedgroups');
		foreach ($default_skipped_groups AS $skipped_group)
		{
			$xml->add_tag('skippedgroup', $skipped_group);
		}
		$xml->close_group();
	}

	foreach ($phrases AS $_fieldname => $typephrases)
	{
		$xml->add_group('phrasetype', array('name' => $phrasetypes["$_fieldname"]['title'], 'fieldname' => $_fieldname));
		foreach ($typephrases AS $phrase)
		{
			$attributes = array(
				'name' => $phrase['varname']
			);

			if ($phrase['dateline'])
			{
				$attributes['date'] = $phrase['dateline'];
			}
			if ($phrase['username'])
			{
				$attributes['username'] = $phrase['username'];
			}
			if ($phrase['version'])
			{
				$attributes['version'] = htmlspecialchars_uni($phrase['version']);
			}
			if ($custom AND $phrase['languageid'] == 0)
			{
				$attributes['custom'] = 1;
			}

			if ($doCharsetConversation)
			{
				$phrase['text'] = $vBUtilString->toCharset($phrase['text'], $language['charset'], $charset);
			}

			$xml->add_tag('phrase', $phrase['text'], $attributes, true);
		}
		$xml->close_group();
	}

	$xml->close_group();

	$doc = "<?xml version=\"1.0\" encoding=\"{$charset}\"?>\r\n\r\n";
	$doc .= $xml->output();
	$xml = null;

	return $doc;
}

/**
* Imports a language from a language XML file
*
* @param	string	XML language string
* @param	integer	Language to overwrite
* @param	string	Override title for imported language
* @param	boolean	Allow import of language from mismatched vBulletin version
* @param	boolean	Allow user-select of imported language
* @param	boolean	Echo output..
*
* @return	Returns false if the custom language was not imported (used in final_upgrade) OR
*			returns the languageid if, if the custom language import was successful (also used in final_upgrade)
*/
function xml_import_language($xml = false, $languageid = -1, $title = '', $anyversion = false, $userselect = true, $output = true)
{
	global $vbulletin, $vbphrase;

	print_dots_start('<b>' . $vbphrase['importing_language'] . "</b>, $vbphrase[please_wait]", ':', 'dspan');

	require_once(DIR . '/includes/functions_misc.php');

	$xmlobj = new vB_XML_Parser($xml, $GLOBALS['path']);
	if ($xmlobj->error_no() == 1)
	{
			print_dots_stop();
			print_stop_message2('no_xml_and_no_path');
	}
	else if ($xmlobj->error_no() == 2)
	{
			print_dots_stop();
			print_stop_message('please_ensure_x_file_is_located_at_y', 'vbulletin-language.xml', $GLOBALS['path']);
	}

	if(!$arr =& $xmlobj->parse('UTF-8'))
	{
		print_dots_stop();
		print_stop_message('xml_error_x_at_line_y', $xmlobj->error_string(), $xmlobj->error_line());
	}

	if (!$arr['phrasetype'])
	{
		print_dots_stop();
		print_stop_message2('invalid_file_specified');
	}

	$title = (empty($title) ? $arr['name'] : $title);
	$version = $arr['vbversion'];
	$master = ($arr['type'] == 'master' ? 1 : 0);
	$just_phrases = ($arr['type'] == 'phrases' ? 1 : 0);
	// These are the fields typically defined in the "settings" block of a language translation XML.
	// Also see far below where we update the `language` record for a non-master, existing language.
	$preserveExistingSettings = array(
		'options',
		'languagecode',
		'charset',
		'locale',
		'dateoverride',
		'timeoverride',
		'decimalsep',
		'thousandsep',
		'registereddateoverride',
		'calformat1override',
		'calformat2override',
		'eventdateformatoverride',
		'pickerdateformatoverride',
		'logdateoverride',
	);
	$assertor = vB::getDbAssertor();
	$existingLanguage = $assertor->getRow('language', array('languageid' => $languageid));

	/*
		For translations, there's usually the "default" (product="vbulletin") translation that's analogous
		to the master language XML, and a product translation (product="{relevant productid, e.g. nativo}")
		that's analogous to the phrases block of a product XML.
		A product translation lacks the "settings" block, and that's meant to defer to the relevant "default"
		translation's settings block.
		Let's do so by pulling the existing language and deferring to its settings when we think that we're
		importing a translation. Otherwise, we have weird unintended behaviors like wiping out the text
		direction (LTR/1 -> RTL/0), decimal separator, etc
	 */
	if (!empty($arr['settings']))
	{
		$langinfo = $arr['settings'];
		/*
			Even if we have settings defined in XML, if this is an update we do not want to
			accidentally wipe out existing settings that aren't defined in this particular XML
			(mostly newer settings like eventdateformatoverride may not be defined in the XMLs)
			todo: what about any language setting changes that an admin made? Should probably
			throw up an admin message after the import.
		 */
		if (
			// If this is an official translation...
			!$master AND
			!empty($arr['revision']) AND
			!empty($arr['vblangcode']) AND
			$arr['product'] == "vbulletin" AND
			// and this is an upgrade, not a fresh import
			$languageid > 0 AND
			!empty($existingLanguage)
		)
		{
			/*
				Switch this to false to preserve any settings that an admin made.
				Switch this to true to make XML defined settings to overwrite any existing settings
				Starting off with overwrite to preserve old/default behavior. Also doing so will
				allow official translations to set/update older settings that were previously not
				defined or outdated/incorrect.
			 */
			$doOverwriteExistingSettings = true;
			foreach ($preserveExistingSettings AS $__key)
			{
				if (!isset($existingLanguage[$__key]))
				{
					// unlikely to hit this, but possibly when we get a new setting and an XML with
					// the new setting gets imported before the language table changes?
					// In any case, there's nothing to preserve in that case.
					continue;
				}
				if (!isset($langinfo[$__key]))
				{
					$langinfo[$__key] = $existingLanguage[$__key];
				}
				else if (!$doOverwriteExistingSettings)
				{
					$langinfo[$__key] = $existingLanguage[$__key];
				}
			}
		}
	}
	else
	{
		$langinfo = array();
		if (
			// If this is an official *product* translation...
			$languageid > 0 AND
			!$master AND
			!empty($arr['revision']) AND
			!empty($arr['vblangcode']) AND
			$arr['product'] != "vbulletin" AND
			!empty($existingLanguage) AND
			$existingLanguage['vblangcode'] === $arr['vblangcode']
		)
		{
			foreach ($preserveExistingSettings AS $__key)
			{
				if (!isset($existingLanguage[$__key]))
				{
					// unlikely to hit this, but possibly when we get a new setting and an XML with
					// the new setting gets imported before the language table changes?
					// In any case, there's nothing to preserve in that case.
					continue;
				}
				if (!isset($langinfo[$__key]))
				{
					$langinfo[$__key] = $existingLanguage[$__key];
				}
			}

			/*
				Revision... Let's just always go with the "default" revision.
				In most cases, the product's revision will be the same or lower than the "default"
				revision, unless they explicitly set it up to have an outdated default translation
				vs. a product translation.
				Note that if we don't set this here, we'll end up wiping the revision accidentally
				in the "officialcustom" check below
			 */
			if (!empty($existingLanguage['revision']))
			{
				$langinfo['revision'] = $existingLanguage['revision'];
			}
			// Note, we don't actually update the vblangcode in the UPDATE query below, but that might
			// just be an oversight. Set it so that if the update query changes, we do not lose it.
			// Unlike revision we already checked the vblangcode match above, so there's no decision here.
			if (!empty($existingLanguage['vblangcode']))
			{
				$langinfo['vblangcode'] = $existingLanguage['vblangcode'];
			}
		}
	}

	// Note: this was written before we had product translations.. as it turns out
	// product translations do not get flagged as "officialcustom" since the product != vbulletin
	// see the code above that pulls a number of info from the existing language setting if it's
	// a product translation.
	$officialcustom = false;
	//Check custom language revision. See also VBV-9215.
	if (!$master AND $arr['product'] == 'vbulletin' AND !empty($arr['revision']) AND !empty($arr['vblangcode']))
	{
		$test = $vbulletin->db->query_first("SELECT * FROM " . TABLE_PREFIX . "language WHERE vblangcode = '" . $vbulletin->db->escape_string($arr['vblangcode']) . "'");
		if ($test['languageid'])
		{
			if (intval($test['revision']) >= intval($arr['revision']))
			{
				// Same or newer language revision has been installed
				// We shouldn't print_stop_message() as the upgrader may continue processing other custom languages
				return false;
			}

			$languageid = $test['languageid'];
		}
		$langinfo['revision'] = intval($arr['revision']);
		$langinfo['vblangcode'] = trim($arr['vblangcode']);
		$officialcustom = true;
	}
	else
	{
		/*
			As we only have 1 language record to keep track of default translations & product translations, there
			are some inconsistencies in handling various aspects of the two types of translations.

			One of those is that a product translation is allowed to overwrite at any time, while a default
			translation is only allowed to overwrite an existing language if its revision is greater than the
			existing one. This is more of an undefined behavior on the product translation part rather than
			an intentional difference in the two.

			In any case, this means that in the unorthdox case where a product translation is imported without/
			before a default translation (e.g. they upload them manually via adminCP in that order), iff we
			set a language revision from the XML for a product, we might not be able to actually import the
			default language file.

			That's why we just default it to 0 here and wait for the default file import to give us the revision
			number.
		 */
		if (empty($langinfo['revision']))
		{
			$langinfo['revision'] = 0;
			//$langinfo['revision'] = (empty($arr['revision']) ? 0 : $arr['revision']);
		}

		if (empty($langinfo['vblangcode']))
		{
			$langinfo['vblangcode'] = (empty($arr['vblangcode']) ? '' : $arr['vblangcode']);
		}
	}


	$langinfo['product'] = (empty($arr['product']) ? 'vbulletin' : $arr['product']);

	// look for skipped groups
	$skipped_groups = array();
	if (!empty($arr['skippedgroups']))
	{
		$skippedgroups =& $arr['skippedgroups']['skippedgroup'];

		if (!is_array($skippedgroups))
		{
			$skippedgroups = array($skippedgroups);
		}

		foreach ($skippedgroups AS $skipped)
		{
			if (is_array($skipped))
			{
				$skipped_groups[] = $vbulletin->db->escape_string($skipped['value']);
			}
			else
			{
				$skipped_groups[] = $vbulletin->db->escape_string($skipped);
			}
		}
	}

	if ($skipped_groups)
	{
		$sql_skipped = "AND " . TABLE_PREFIX . "phrase.fieldname NOT IN ('" . implode("', '", $skipped_groups) . "')";
	}
	else
	{
		$sql_skipped = '';
	}


	foreach ($langinfo AS $key => $val)
	{
		$langinfo["$key"] = $vbulletin->db->escape_string(trim($val));
	}
	$langinfo['options'] = intval($langinfo['options']);
	$langinfo['revision'] = intval($langinfo['revision']);

	if ($version != $vbulletin->options['templateversion'] AND !$master)
	{
		if (strtok($version,'.') != strtok($vbulletin->options['templateversion'],'.'))
		{
			print_dots_stop();
			print_stop_message('upload_file_created_with_different_major_version', $vbulletin->options['templateversion'], $version);
		}
		if (!$anyversion)
		{
			print_dots_stop();
			print_stop_message('upload_file_created_with_different_version', $vbulletin->options['templateversion'], $version);
		}
	}


	//set up the phrase array
	$arr = $arr['phrasetype'];
	if (!is_array($arr[0]))
	{
		$arr = array($arr);
	}

	/*
		Check if we need to convert the phrases to the current board or language charset.
		If we're re-importing or upgrading an existing language, prefer the language's
		charset as to not have charset conflicts/corruptions within a single language.
		E.g. if the board has french ISO-8859-1 and we're now importing product translations
		into the existing language, do NOT blindly change that to UTF-8 (since existing phrases
		will be in ISO-8859-1), instead convert the product phrases into ISO-8859-1.
	 */
	$convertPhrases = false;
	$preferredCharset = $boardCharset = vB_Template_Runtime::fetchStyleVar('charset');
	if (!empty($existingLanguage['charset']))
	{
		$preferredCharset = $existingLanguage['charset'];
	}

	/*
	Regardless of the $readcharset option, we need to get the current phrase charset from the
	xml object.
	The xml object gets the charset in the xml node's encoding attribute, then may or may not
	convert it to ISO-8859-1 (*that* part depends on the $readcharset option, but doesn't
	change the fact that the xml object is the only one who's sure of it at this point).

	If, for some whatever convoluted reason we have no idea what the phrases in memory's charset
	is, fall back to the settings.charset if that was specified in the XML (and assume that the
	parse did not convert the phrases to something else), then fall back to the board or existing
	charset. But it really shouldn't ever happen for well formed, standard vbulletin XMLs.
	 */
	$phrasesCharset = $xmlobj->get_target_encoding() ?? ($arr['settings']['charset'] ?? $preferredCharset);

	// TODO, vB_Utility_String::areCharsetsEqual()
	if (!empty($preferredCharset) AND (strtolower($preferredCharset) != strtolower($phrasesCharset)))
	{
		$convertPhrases = true;
		// since we're converting the phrases' charset, make sure the inserted language
		// matches this charset & informs the browser correctly.
		$langinfo['charset'] = $preferredCharset;
	}
	//spin through the phrases to check validity.  We want to do this *before* we prep for import
	//so that if we abort do to an error, we haven't made any changes first
	foreach (array_keys($arr) AS $key)
	{
		$phraseTypes =& $arr["$key"];
		if (is_array($phraseTypes['phrase']))
		{
			foreach($phraseTypes['phrase'] AS $key2 => $phrase)
			{
				if (is_array($phrase))
				{
					$check = $phrase['value'];
				}
				else
				{
					$check = $phrase;
				}
				if ($convertPhrases)
				{
					// convert it from the language file's (or currently vB_Xml_Parser-converted)
					// encoding to the board's (or preferrably existing language's) encoding
					$check = vB_String::toCharset($check, $phrasesCharset, $preferredCharset);
					if (is_array($phrase))
					{
						$arr[$key]['phrase'][$key2]['value'] = $check;
					}
					else
					{
						$arr[$key]['phrase'][$key2] = $check;
					}
				}

				if (!validate_string_for_interpolation($check))
				{
					print_dots_stop();
					print_stop_message2(array('phrase_text_not_safe',  $phrase['name']));
				}
			}
		}
	}


	// prepare for import
	if ($master)
	{
		// lets stop it from dieing cause someone borked a previous update
		$vbulletin->db->query_write("DELETE FROM " . TABLE_PREFIX . "phrase WHERE languageid = -10");
		// master style
		if ($output AND VB_AREA != 'Install' AND VB_AREA != 'Upgrade')
		{
			echo "<h3>$vbphrase[master_language]</h3>\n<p>$vbphrase[please_wait]</p>";
			vbflush();
		}

		$vbulletin->db->query_write("
			UPDATE " . TABLE_PREFIX . "phrase SET
				languageid = -10
			WHERE languageid = -1
				AND (product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR product = ''") . ")
				$sql_skipped
		");
		$languageid = -1;
	}
	else
	{
		if ($languageid == 0)
		{
			// creating a new language
			if ($just_phrases)
			{
				print_dots_stop();
				print_stop_message2(array('language_only_phrases',  $title));
			}
			else if ($test = $vbulletin->db->query_first("SELECT languageid FROM " . TABLE_PREFIX . "language WHERE title = '" . $vbulletin->db->escape_string($title) . "'"))
			{
				if ($officialcustom)
				{
					// Rename the old language
					$vbulletin->db->query_write("UPDATE " . TABLE_PREFIX . "language SET title = CONCAT(title, '_old') WHERE title = '" . $vbulletin->db->escape_string($title) . "' AND languagecode");
				}
				else
				{
					print_dots_stop();
					print_stop_message2(array('language_already_exists',  $title));
				}
			}

			if ($output AND VB_AREA != 'Install' AND VB_AREA != 'Upgrade')
			{
				echo "<h3><b>" . construct_phrase($vbphrase['creating_a_new_language_called_x'], $title) . "</b></h3>\n<p>$vbphrase[please_wait]</p>";
				vbflush();
			}

			/*insert query*/
			$vbulletin->db->query_write("
				INSERT INTO " . TABLE_PREFIX . "language (
					title, options, languagecode,
					charset, revision, vblangcode,
					dateoverride, timeoverride, decimalsep, thousandsep,
					registereddateoverride, calformat1override, calformat2override, eventdateformatoverride, pickerdateformatoverride, locale, logdateoverride
				) VALUES (
					'" . $vbulletin->db->escape_string($title) . "', $langinfo[options], '$langinfo[languagecode]',
					'$langinfo[charset]', $langinfo[revision], '" . $vbulletin->db->escape_string($langinfo['vblangcode']) . "',
					'$langinfo[dateoverride]', '$langinfo[timeoverride]', '$langinfo[decimalsep]', '$langinfo[thousandsep]',
					'$langinfo[registereddateoverride]', '$langinfo[calformat1override]', '$langinfo[calformat2override]', '$langinfo[eventdateformatoverride]', '$langinfo[pickerdateformatoverride]', '$langinfo[locale]', '$langinfo[logdateoverride]'
				)
			");
			$languageid = $vbulletin->db->insert_id();
		}
		else
		{
			// overwriting an existing language
			if ($getlanguage = $vbulletin->db->query_first("SELECT title FROM " . TABLE_PREFIX . "language WHERE languageid = $languageid"))
			{
				if (!$just_phrases)
				{
					if ($output AND VB_AREA != 'Install' AND VB_AREA != 'Upgrade')
					{
						echo "<h3><b>" . construct_phrase($vbphrase['overwriting_language_x'], $getlanguage['title']) . "</b></h3>\n<p>$vbphrase[please_wait]</p>";
						vbflush();
					}

					$vbulletin->db->query_write("
						UPDATE " . TABLE_PREFIX . "language SET
							options = $langinfo[options],
							languagecode = '$langinfo[languagecode]',
							charset = '$langinfo[charset]',
							locale = '$langinfo[locale]',
							dateoverride = '$langinfo[dateoverride]',
							timeoverride = '$langinfo[timeoverride]',
							decimalsep = '$langinfo[decimalsep]',
							thousandsep = '$langinfo[thousandsep]',
							registereddateoverride = '$langinfo[registereddateoverride]',
							calformat1override = '$langinfo[calformat1override]',
							calformat2override = '$langinfo[calformat2override]',
							eventdateformatoverride = '$langinfo[eventdateformatoverride]',
							pickerdateformatoverride = '$langinfo[pickerdateformatoverride]',
							logdateoverride = '$langinfo[logdateoverride]',
							revision = $langinfo[revision]
						WHERE languageid = $languageid
					");

					$vbulletin->db->query_write("
						UPDATE " . TABLE_PREFIX . "phrase, " . TABLE_PREFIX . "phrase AS phrase2
						SET " . TABLE_PREFIX . "phrase.languageid = -11
						WHERE " . TABLE_PREFIX . "phrase.languageid = $languageid
							AND (" . TABLE_PREFIX . "phrase.product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR " . TABLE_PREFIX . "phrase.product = ''") . ")
							AND (phrase2.product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR phrase2.product = ''") . ")
							AND " . TABLE_PREFIX . "phrase.varname = phrase2.varname
							AND phrase2.languageid = 0
							AND " . TABLE_PREFIX . "phrase.fieldname = phrase2.fieldname
							$sql_skipped
					");

					$vbulletin->db->query_write("
						UPDATE " . TABLE_PREFIX . "phrase SET
							languageid = -10
						WHERE languageid = $languageid
							AND (product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR product = ''") . ")
							$sql_skipped
					");
				}
			}
			else
			{
				print_stop_message2('cant_overwrite_non_existent_language');
			}
		}
	}

	// get current phrase types
	$current_phrasetypes = fetch_phrasetypes_array(false);

	if (!$master)
	{
		$globalPhrases = array();
		$getphrases = $vbulletin->db->query_read("
			SELECT varname, fieldname
			FROM " . TABLE_PREFIX . "phrase
			WHERE languageid IN (0, -1)
		");
		while ($getphrase = $vbulletin->db->fetch_array($getphrases))
		{
			$globalPhrases["$getphrase[varname]~$getphrase[fieldname]"] = true;
		}
	}

	// import language

	// track new phrasetypes
	$new_phrasetypes = array();
	foreach (array_keys($arr) AS $key)
	{
		$phraseTypes =& $arr["$key"];

		$sql = array();
		$strlen = 0;

		if ($phraseTypes['fieldname'] == '' OR !preg_match('#^[a-z0-9_]+$#i', $phraseTypes['fieldname'])) // match a-z, A-Z, 0-9,_ only
		{
			continue;
		}
		$fieldname = $phraseTypes['fieldname'];

		if (!is_array($phraseTypes['phrase'][0]))
		{
			$phraseTypes['phrase'] = array($phraseTypes['phrase']);
		}

		// check if the phrasetype is new
		if (!isset($current_phrasetypes[$fieldname]) AND !empty($phraseTypes['phrase']))
		{
			$new_phrasetypes[] = array('fieldname' => $fieldname, 'title' => $phraseTypes['name']);
		}

		// Send some output to the browser inside this loop so certain hosts
		// don't artificially kill the script. See bug #34585
		if ($output)
		{
			echo ' ';
			vbflush();
		}

		foreach($phraseTypes['phrase'] AS $phrase)
		{
			if ($master)
			{
				$insertLanguageId = -1;
			}
			else if (!isset($globalPhrases["$phrase[name]~$fieldname"]))
			{
				$insertLanguageId = 0;
			}
			else if ($phrase['custom'])
			{
				// this is a custom phrase (language 0) -- we don't want it to end up in the custom language
				continue;
			}
			else
			{
				$insertLanguageId = $languageid;
			}

			$sql[] = "
				($insertLanguageId,
				'" . $vbulletin->db->escape_string($fieldname) . "',
				'" . $vbulletin->db->escape_string($phrase['name']) . "',
				'" . $vbulletin->db->escape_string($phrase['value']) . "',
				'" . $vbulletin->db->escape_string($langinfo['product']) . "',
				'" . $vbulletin->db->escape_string($phrase['username']) . "',
				" . intval($phrase['date']) . ",
				'" . $vbulletin->db->escape_string($phrase['version']) . "')
			";

			$strlen += strlen(end($sql));

			if ($strlen > 102400)
			{
				// insert max of 100k of phrases at a time
				/*insert query*/
				$vbulletin->db->query_write("
					REPLACE INTO " . TABLE_PREFIX . "phrase
						(languageid, fieldname, varname, text, product, username, dateline, version)
					VALUES
						" . implode(",\n", $sql)
				);

				$sql = array();
				$strlen = 0;
			}

			// Send some output to the browser inside this loop so certain hosts
			// don't artificially kill the script. See bug #34585
			if ($output)
			{
				echo ' ';
				vbflush();
			}
		}

		if ($sql)
		{
			/*insert query*/
			$vbulletin->db->query_write("
				REPLACE INTO " . TABLE_PREFIX . "phrase
					(languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES
					" . implode(",\n", $sql)
			);
		}

		unset($arr["$key"], $phraseTypes);
	}
	unset($sql, $arr, $current_phrasetypes);

	// insert any new phrasetypes
	foreach ($new_phrasetypes AS $phrasetype)
	{
		add_phrase_type($phrasetype['fieldname'], $phrasetype['title'], $langinfo['product']);
	}

	$vbulletin->db->query_write("
		UPDATE IGNORE " . TABLE_PREFIX . "phrase
		SET " . TABLE_PREFIX . "phrase.languageid = $languageid
		WHERE " . TABLE_PREFIX . "phrase.languageid = -11
			AND (" . TABLE_PREFIX . "phrase.product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR " . TABLE_PREFIX . "phrase.product = ''") . ")
			$sql_skipped
	");

	// now delete any phrases that were moved into the temporary language for safe-keeping
	$vbulletin->db->query_write("
		DELETE FROM " . TABLE_PREFIX . "phrase
		WHERE languageid IN (-10, -11)
			AND (product = '" . $vbulletin->db->escape_string($langinfo['product']) . "'" . iif($langinfo['product'] == 'vbulletin', " OR product = ''") . ")
			$sql_skipped
	");

	vB_Library::instance('phrase')->setPhraseDate();
	print_dots_stop();

	return $languageid;
}

/**
* Fetches a string specifying the type of a phrase
*
* @param	integer	Language ID of phrase
* @param	string	Phrase name
*
* @return	string	Either $vbphrase['standard_phrase'], $vbphrase['custom_phrase'] or construct_phrase($vbphrase['x_translation'], $title)
*/
function fetch_language_type_string($languageid, $title)
{
	global $vbphrase;
	switch($languageid)
	{
		case -1:
			return $vbphrase['standard_phrase'];
		case  0:
			return $vbphrase['custom_phrase'];
		default:
			return construct_phrase($vbphrase['x_translation'], $title);
	}
}

/**
* Highlights search terms in text
*
* @param	string	Needle
* @param	string	Haystack
* @param	boolean	True if you want to ignore case (case insensitive)
*
* @return	string	Highlighted HTML
*/
function fetch_highlighted_search_results($searchstring, $text, $ignorecase = true)
{
	return preg_replace(
		'/(' . preg_quote(htmlspecialchars_uni($searchstring), '/') . ')/sU' . ($ignorecase ? 'i' : ''),
		'<span class="col-i" style="text-decoration:underline;">\\1</span>',
		htmlspecialchars_uni($text)
	);
}

/**
* Wraps an HTML tag around a string.
*
* @param	string	Text to be wrapped
* @param	string	Tag name and attributes (eg: 'span class="smallfont"')
* @param	mixed	Optional - if evaluates to false, wrapping will not occur
*
* @return	string
*/
function fetch_tag_wrap($text, $tag, $condition = '1=1')
{
	if ($condition)
	{
		if ($pos = strpos($tag, ' '))
		{
			$endtag = substr($tag, 0, $pos);
		}
		else
		{
			$endtag = $tag;
		}
		return "<$tag>$text</$endtag>";
	}
	else
	{
		return $text;
	}
}

/**
* Prints a language row for use in language.php?do=modify
*
* @param	array	Language array containing languageid, title
*/
function print_language_row($language)
{
	global $vbulletin, $typeoptions, $vbphrase;
	$vb5_config = vB::getConfig();
	$languageid = $language['languageid'];

	$cell = array();
	$cell[] = iif($vb5_config['Misc']['debug'] AND $languageid != -1, '-- ', '') . fetch_tag_wrap($language['title'], 'b', $languageid == $vbulletin->options['languageid']);
	$cell[] = "<a href=\"admincp/language.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dolanguageid=$languageid\">" . construct_phrase($vbphrase['edit_translate_x_y_phrases'], $language['title'], '') . "</a>";
	$cell[] =
		iif($languageid != -1,
			construct_link_code($vbphrase['edit_settings_glanguage'], "language.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit_settings&amp;dolanguageid=$languageid").
			construct_link_code($vbphrase['delete'], "language.php?" . vB::getCurrentSession()->get('sessionurl') . "do=delete&amp;dolanguageid=$languageid")
		) .
		construct_link_code($vbphrase['download'], "language.php?" . vB::getCurrentSession()->get('sessionurl') . "do=files&amp;dolanguageid=$languageid")
		;

	$celltext = '';
	if($languageid != -1)
	{
		$celltext = "<input type=\"button\" class=\"button\" value=\"$vbphrase[set_default]\" tabindex=\"1\"";
		if($languageid == $vbulletin->options['languageid'])
		{
			$celltext .= ' disabled="disabled"';
		}
		$celltext .= " onclick=\"vBRedirect('admincp/language.php?" . vB::getCurrentSession()->get('sessionurl') .
			"do=setdefault&amp;dolanguageid=$languageid');\" />";
	}

	$cell[] = $celltext;
	print_cells_row($cell, 0, '', -2);
}

/**
* Prints a phrase row for use in language.php?do=edit
*
* @param	array	Phrase array containing phraseid, varname, text, languageid
* @param	integer	Number of rows for textarea
* @param	integer	Not used?
* @param	string	ltr or rtl for direction
*/
function print_phrase_row($phrase, $editrows, $key = 0, $dir = 'ltr')
{
	global $vbphrase, $vbulletin;
	static $bgcount = 0;

	if ($vbulletin->GPC['languageid'] == -1)
	{
		$phrase['found'] = 0;
	}

	if ($bgcount++ % 2 == 0)
	{
		$class = 'alt1';
		$altclass = 'alt2';
	}
	else
	{
		$class = 'alt2';
		$altclass = 'alt1';
	}

	construct_hidden_code('def[' . urlencode($phrase['varname']) . ']', $phrase['text']);
	construct_hidden_code('prod[' . urlencode($phrase['varname']) . ']', (empty($phrase['product']) ? 'vbulletin' : $phrase['product']));

	if($phrase['found'])
	{
		$phrasedfn = " <dfn><br /><label for=\"rvt$phrase[phraseid]\"><input type=\"checkbox\" name=\"rvt[$phrase[varname]]\"" .
			" id=\"rvt$phrase[phraseid]\" value=\"$phrase[phraseid]\" tabindex=\"1\" />$vbphrase[revert_gcpglobal]</label></dfn>";
		$label = "<label for=\"rvt$phrase[phraseid]\">" . nl2br(htmlspecialchars_uni($phrase['default_text'])) . "</label>";
		$code = 'c';
	}
	else
	{
		$phrasedfn = '';
		$label = nl2br(htmlspecialchars_uni($phrase['default_text']));
		$code = 'g';
	}

	print_label_row(
		"<span class=\"smallfont\" title=\"\$vbphrase['$phrase[varname]']\" style=\"word-spacing:-5px\">
			<b>" . str_replace('_', '_ ', $phrase['varname']) . "</b>
			</span>" . $phrasedfn,
		"<div class=\"$altclass\" style=\"padding:4px; border:inset 1px;\"><span class=\"smallfont\" title=\"" . $vbphrase['default_text'] . "\">" . $label .
			"</span></div><textarea class=\"code-" . $code . "\" name=\"phr[" . urlencode($phrase['varname']) .
			"]\" rows=\"$editrows\" cols=\"70\" tabindex=\"1\" dir=\"$dir\">" . htmlspecialchars_uni($phrase['text']) . "</textarea>",
		$class
	);
	print_description_row('<img src="images/clear.gif" width="1" height="1" alt="" />', 0, 2, 'thead');
}

/**
* Constructs a version of a phrase varname that is browser-wrappable for display
*
* @param	string	Phrase varname
* @param	string	Extra CSS
* @param	string	CSS Classname
* @param	string	Wrap return value in this tag (eg: span, div)
*
* @return	string	HTML string
*/
function construct_wrappable_varname($varname, $extrastyles = '', $classname = 'smallfont', $tagname = 'span')
{
	return "<$tagname" . iif($classname, " class=\"$classname\"") . " style=\"word-spacing:-5px;" . iif($extrastyles, " $extrastyles") . "\" title=\"$varname\">" . str_replace('_', '_ ', $varname) . "</$tagname>";
}

/**
* Turns 'my_phrase_varname_global' into $varname = 'my_phrase_varname' ; $fieldname = global;
*
* @param	string	Incoming phrase varname (my_phrase_varname_3)
* @param	string	(Reference) Outgoing phrase varname
* @param	integer	(Reference)	Outgoing phrase fieldname
*/
function fetch_varname_fieldname($key, &$varname, &$fieldname)
{
	$firstatsignpos = strpos($key, '@');

	$varname = urldecode(substr($key, 0, $firstatsignpos));
	$fieldname = substr($key, $firstatsignpos + 1);
}

/**
* Allows plugins etc. to add a phrasetype easily
*
* @param	string	Phrasetype name
* @param	string	Phrasetype title
* @param	string	Product ID
*
* @return	mixed	If insert succeeds, returns inserted fieldname
*/
function add_phrase_type($phrasegroup_name, $phrasegroup_title, $productid = 'vbulletin')
{
	global $vbulletin;

	if (!preg_match('#^[a-z0-9_]+$#i', $phrasegroup_name)) // match a-z, A-Z, 0-9,_ only
	{
		return false;
	}

	// first lets check if it exists
	if ($check = $vbulletin->db->query_first("SELECT * FROM " . TABLE_PREFIX . "phrasetype WHERE fieldname = '$phrasegroup_name'"))
	{
		return false;
	}
	else
	{
		/*insert query*/
		$vbulletin->db->query_write("
			INSERT INTO " . TABLE_PREFIX . "phrasetype
				(fieldname, title, editrows, product)
			VALUES
				('" . $vbulletin->db->escape_string($phrasegroup_name) . "',
				'" . $vbulletin->db->escape_string($phrasegroup_title) . "',
				3,
				'" . $vbulletin->db->escape_string($productid) . "')
		");

		if (!$vbulletin->db->query_first($sql = "SHOW FULL COLUMNS FROM " . TABLE_PREFIX . "language LIKE 'phrasegroup_" . $vbulletin->db->escape_string($phrasegroup_name) . "'"))
		{
			$vbulletin->db->query_write("ALTER TABLE " . TABLE_PREFIX . "language ADD phrasegroup_" . $vbulletin->db->escape_string($phrasegroup_name) . " MEDIUMTEXT NOT NULL");
		}

		return $phrasegroup_name;
	}

	return false;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103550 $
|| #######################################################################
\*=========================================================================*/
