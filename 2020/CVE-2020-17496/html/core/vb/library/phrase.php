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
 * vB_Library_Phrase
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Phrase extends vB_Library
{

	const VALID_CLASS = 'A-Za-z0-9_\.\[\]';

	/**
	 * Add a new phrase or update an existing phrase
	 * @param string $fieldname New Phrase Type for adding, old Phrase Type for editing
	 * @param string $varname New Varname for adding, old Varname for editing
	 * @param array $data Phrase data to be added or updated
	 *              'text' => Phrase text array.
	 *              'oldvarname' => Old varname for editing only
	 *              'oldfieldname' => Old fieldname for editing only
	 *              't' =>
	 *              'ismaster' =>
	 *              'product' => Product ID of the phrase
	 * @param bool   $skipBuildLanguage  (Optional) Set to true to skip build_language() call.
	 *                                   Used by the page importer to delay build_language until
	 *                                   the old page title & desc restore queries are finished.
	 * @return void
	 */
	public function save($fieldname, $varname, $data, $skipBuildLanguage = false)
	{
		$fieldname = trim($fieldname);
		$varname = trim($varname);
		$vb5_config =& vB::getConfig();
		$install = false;
		if (defined('VBINSTALL') AND VBINSTALL)
		{
			$install = true;
		}
		$session = vB::getCurrentSession();
		if (!empty($session))
		{
			$userinfo = $session->fetch_userinfo();
		}
		else
		{
			$userinfo = vB_User::fetchUserinfo(1);
		}

		require_once(DIR . '/includes/adminfunctions.php');
		$full_product_info = fetch_product_list(true);

		if (empty($varname))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		if (!preg_match('#^[' . self::VALID_CLASS . ']+$#', $varname)) // match a-z, A-Z, 0-9, '.', ',', _ only .. allow [] for help items
		{
			throw new vB_Exception_Api('invalid_phrase_varname');
		}

		require_once(DIR . '/includes/functions_misc.php');
		foreach ($data['text'] AS $text)
		{
			if (!validate_string_for_interpolation($text))
			{
				throw new vB_Exception_Api('phrase_text_not_safe', array($varname));
			}
		}

		$db = vB::getDbAssertor();

		$phraseCount = $db->getRow('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
			'varname' => $varname,
			'languageid' => array(0,-1),
		));

		// it's an update
		if (!empty($data['oldvarname']) AND !empty($data['oldfieldname']))
		{
			if ($phraseCount['count'])
			{
				// Don't check if we are moving a phrase to another group but keeping the same name. See VBV-4192.
				if ($varname != $data['oldvarname'] AND $fieldname != $data['oldfieldname'])
				{
					throw new vB_Exception_Api('there_is_already_phrase_named_x', array($varname));
				}

				if ($varname != $data['oldvarname'])
				{
					throw new vB_Exception_Api('variable_name_exists', array($data['oldvarname'], $varname));
				}

			}

			if (!is_array($data['oldfieldname']))
			{
				$data['oldfieldname'] = array($data['oldfieldname']);
			}

			if (!in_array($fieldname, $data['oldfieldname']))
			{
				$data['oldfieldname'][] = $fieldname;
			}

			// delete old phrases
			$db->assertQuery('deleteOldPhrases', array(
				'varname' => $data['oldvarname'],
				'fieldname' => $data['oldfieldname'],
				't' => $data['t'],
				'debug' => (empty($data['skipdebug']) && ($vb5_config['Misc']['debug'] OR $install)),
			));

			$this->setPhraseDate();
		}
		else
		{
			if ((empty($data['text'][0]) AND $data['text'][0] != '0' AND !$data['t']) OR empty($varname))
			{
				throw new vB_Exception_Api('please_complete_required_fields');
			}

			if ($phraseCount['count'])
			{
				throw new vB_Exception_Api('there_is_already_phrase_named_x', array($varname));
			}
		}

		if ($data['ismaster'])
		{
			if (($vb5_config['Misc']['debug'] OR $install) AND !$data['t'])
			{
				/*insert query*/
				$db->assertQuery('phrase', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_REPLACE,
					'languageid' => -1,
					'varname' => $varname,
					'text' => $data['text'][0],
					'fieldname' => $fieldname,
					'product' => $data['product'],
					'username' => $userinfo['username'],
					'dateline' => vB::getRequest()->getTimeNow(),
					'version' =>$full_product_info[$data['product']]['version']
				));
			}

			unset($data['text'][0]);
		}

		foreach($data['text'] AS $_languageid => $txt)
		{
			$_languageid = intval($_languageid);

			if (!empty($txt) OR $txt == '0')
			{
				/*insert query*/
				$db->assertQuery('phrase', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_REPLACE,
					'languageid' => $_languageid,
					'varname' => $varname,
					'text' => $txt,
					'fieldname' => $fieldname,
					'product' => $data['product'],
					'username' => $userinfo['username'],
					'dateline' => vB::getRequest()->getTimeNow(),
					'version' =>$full_product_info[$data['product']]['version']
				));
			}
		}

		if (!$skipBuildLanguage)
		{
			vB_Library::instance('language')->rebuildAllLanguages();
		}
	}

	/**
	 * Resets the phrase cachebuster date.
	 */
	public function setPhraseDate()
	{
		vB_Cache::instance()->event("vB_Language_languageCache");
		$options = vB::getDatastore()->getValue('miscoptions');
		$options['phrasedate'] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('miscoptions', serialize($options), 1);
	}

	/**
	 * Cleans a guid to match phrase valid class (self::VALID_CLASS).
	 * This is used to build phrases for import items.
	 * Example: title and description for pages
	 *				- 'page_' . $guidforphrase . '_title'
	 *				- 'page_' . $guidforphrase . '_description'
	 *
	 * @param 	string 	GUID string.
	 *
	 * @return 	string 	GUID for phrase.
	 **/
	public function cleanGuidForPhrase($guid)
	{
		$guidforphrase = str_replace(array('.', 'vbulletin-'), array(''), $guid);
		$guidforphrase = str_replace(array('-'), array('_'), $guidforphrase);

		return $guidforphrase;
	}

	/**
	 * Replaces instances of vBulletin options and config variables in a phrase with
	 * the value held in the variable.
	 *
	 * This function currently supports variables such as $vbulletin->config[xxx][yyy]
	 * and $vbulletin->options[xxx], and is intended to be used in Admin CP phrases,
	 * primarily help phrases.
	 *
	 * This function is placed here in the spirit of DRY, since
	 * it's needed in various places, and for namespacing. It's not
	 * dependent on anything else in the phrase library.
	 *
	 * @param	string	The phrase text
	 *
	 * @return	string	The phrase textafter replacements are done.
	 */
	public function replaceOptionsAndConfigValuesInPhrase($text)
	{
		// Orig preg_replace in admincp/search.php:
		// $title_map["$phrase[varname]"]  = preg_replace('#\{\$([a-z0-9_>-]+([a-z0-9_]+(\[[a-z0-9_]+\])*))\}#ie', '(isset($\\1) AND !is_array($\\1)) ? $\\1 : \'$\\1\'', $phrase['text']);

		// Orig preg_replace in admincp/help.php:
		// $helpphrase["$phrase[varname]"] = preg_replace('#\{\$([a-z0-9_>-]+([a-z0-9_]+(\[[a-z0-9_]+\])*))\}#ie', '(isset($\\1) AND !is_array($\\1)) ? $\\1 : \'$\\1\'', $phrase['text']);

		// Orig preg_replace in modcp/help.php:
		// $helpphrase["$phrase[varname]"] = preg_replace('#\{\$([a-z0-9_>-]+(\[[a-z0-9_]+\])*)\}#ie', '(isset($\\1) AND !is_array($\\1)) ? $\\1 : \'$\\1\'', $phrase['text']);

		return preg_replace_callback(
			'#\{\$([a-z0-9_>-]+([a-z0-9_]+(\[[a-z0-9_]+\])*))\}#i',
			function($matches)
			{
				// match is, e.g., vbulletin->config[xxx][yyy]
				$match = $matches[1];

				// this was previously using preg_match with the /e modifier
				// to eval() the replacement. This makes it easy to eval
				// the match as-is, without knowing what is in it, and get the
				// contents of the variable. Since we can't eval here, we need
				// to "parse" the string and "dereference" the object properties
				// and/or the array elements to drill down to the base value
				// that is to be inserted into the phrase.

				// break the match into tokens, where the tokens are
				// identifier names OR an operation, which is either an object
				// property dereference (->) or and array element dereference ([]).
				// for example, vbulletin->config[xxx][yyy] is tokenized as:
				// vbulletin, object_property, config, array_element, xxx, array_element, yyy
				$tokens = array();
				$parts = explode('->', $match);
				foreach ($parts AS $part)
				{
					// extract any additional operations from 'part'
					$subparts = explode('[', $part);
					foreach ($subparts AS $subpart)
					{
						// the preceeding var name (for parts or subparts)
						$tokens[] = rtrim($subpart, ']');

						// the operation ([])
						$tokens[] = 'array_element';
					}
					// remove trailing operation, since there are no more 'subparts'
					array_pop($tokens);

					// the operation (->)
					$tokens[] = 'object_property';
				}
				// remove trailing operation, since there are no more 'parts'
				array_pop($tokens);

				// The replacements being made are for instances
				// of $vbulletin->options[xxx], and $vbulletin->config[xxx][yyy]
				// etc., in the admin cp help phrases. If we need to
				// support anything other than $vbulletin->something, we
				// could look for $finalVar (below) in the global scope instead.
				// however, allowing arbitrary replacements could be riskier
				// as well.
				// Create a local "$vbulletin" variable to match the variables
				// that are being requested in the phrase. This whitelists
				// two config values, and allows all "public" options.

				$vbulletin = new stdClass();

				$vbconfig = vB::getConfig();
				$vbulletin->config = array(
					'Misc' => array(
						'admincpdir' => 'admincp',
						'modcpdir' => $vbconfig['Misc']['modcpdir'],
					),
				);

				$vbulletin->options = vB::getDatastore()->getValue('publicoptions');


				// the first token is the starting variable
				$var = array_shift($tokens);
				if ($var !== 'vbulletin')
				{
					// return the original text if they try to access any other var
					return '$' . $match;
				}
				$varFinal = $$var;

				// remaining tokens are pairs: variable and operation
				// loop and point varFinal to the target value
				$sets = array_chunk($tokens, 2);
				foreach ($sets AS $item)
				{
					$op = $item[0];
					$subvar = $item[1];

					if ($op == 'object_property')
					{
						if (property_exists($varFinal, $subvar))
						{
							$varTemp = $varFinal->$subvar;
						}
						else
						{
							// return the original text if they try to access a non-existent property
							return '$' . $match;
						}
					}
					else if ($op == 'array_element')
					{
						if (isset($varFinal[$subvar]))
						{
							$varTemp = $varFinal[$subvar];
						}
						else
						{
							// return the original text if they try to access a non-existent element
							return '$' . $match;
						}
					}

					unset($varFinal);
					$varFinal = $varTemp;
					unset($varTemp);
				}

				// varFinal is now pointing to the requested value
				// if it exists and isn't an array, return the value, if not,
				// return the original string
				return (isset($varFinal) AND !is_array($varFinal)) ? $varFinal : '$' . $match;

			},
			$text
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99976 $
|| #######################################################################
\*=========================================================================*/
