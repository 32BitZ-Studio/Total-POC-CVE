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
 * vB_Library_Language
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Language extends vB_Library
{
	protected $languages = array();

	/**
	 * Clears language whole cache or cache for a specific languageid
	 * @param type $languageId
	 */
	public function clearLanguageCache($languageId = FALSE)
	{
		$languageId = intval($languageId);
		if ($languageId !== FALSE)
		{
			unset($this->languages[$languageId]);
		}
		else
		{
			$this->languages = array();
		}
	}

	// TODO: add required fields as key?
	/**
	 *
	 * @param mixed $languageIds - Language id or array of language ids
	 * @return array - Array of languages including:
	 *					- languageid
	 *					- dateoverride
	 *					- timeoverride
	 *					- locale
	 *					- charset
	 */
	public function fetchLanguages($languageIds)
	{
		$result = array();

		if (empty($languageIds))
		{
			return $result;
		}
		else if (is_array($languageIds))
		{
			array_walk($languageIds, 'intval');
		}
		else
		{
			$languageIds = array(intval($languageIds));
		}

		$missing = array();
		foreach ($languageIds AS $languageId)
		{
			if (isset($this->languages[$languageId]))
			{
				$result[$languageId] = $this->languages[$languageId];
			}
			else
			{
				$missing[$languageId] = $languageId;
			}
		}

		if (!empty($missing))
		{
			$query = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('languageid', 'dateoverride', 'timeoverride', 'locale', 'charset'),
				vB_dB_Query::CONDITIONS_KEY => array('languageid' => $missing),
			);
			$dbLanguages = vB::getDbAssertor()->assertQuery('language', $query);
			foreach ($dbLanguages AS $lang)
			{
				$this->languages[$lang['languageid']] = $lang;
				$result[$lang['languageid']] = $lang;
			}
		}

		return $result;
	}

	/**
	 *	Rebuild the language data structures
	 */
	//a quick cover for the legacy code -- we should really port it over.  Note
	//that at some point we will probably want a rebuildLanguage($id) function
	//but we should get away from the -1 magic number for signaling that.
	public function rebuildAllLanguages()
	{
		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99976 $
|| #######################################################################
\*=========================================================================*/
