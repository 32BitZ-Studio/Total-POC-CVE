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

class vB_Language
{
	use vB_Trait_NoSerialize;

	protected static $phraseGroups = array();
	protected static $languageCache = array();

	/**
	 * Stores phrasegroups for later loading
	 *
	 * @param	mixes	string or array of string;
	 *
	 */
	public static function preloadPhraseGroups($phraseGroups)
	{
		if (!is_array($phraseGroups))
		{
			self::$phraseGroups[] = $phraseGroups;
		}
		else
		{
			self::$phraseGroups = array_merge(self::$phraseGroups, $phraseGroups);
		}
	}

	public static function getPhraseInfo($languageId, $phraseGroups = array())
	{
		self::$phraseGroups = array_merge(self::$phraseGroups, $phraseGroups);

		$params[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_METHOD;
		$params['languageid'] = $languageId;
		$params['phrasegroups'] = self::$phraseGroups;
		self::$phraseGroups = array();

		ksort($params);
		$cacheKey = md5(json_encode($params));

		$ret = self::getPhraseCache($cacheKey);
		if (!$ret)
		{
			$result = vB::getDbAssertor()->assertQuery('fetchLanguage', $params);

			if ($result AND $result->valid())
			{
				$current = $result->current();
				if (isset($current['phrasegroup_global']))
				{
					vB_Phrase::addPhrases(array('global' => unserialize($current['phrasegroup_global'])));
				}

				self::setPhraseCache($cacheKey, $current);
				$ret = $current;
			}
		}

		return $ret;
	}

	private static function getPhraseCache($cacheKey)
	{
		if (empty(self::$languageCache[$cacheKey]))
		{
			$result = vB_Cache::instance()->read($cacheKey);
			if (!empty($result))
			{
				self::$languageCache[$cacheKey] = $result;
				return $result;
			}
			else
			{
				return null;
			}
		}
		else
		{
			return self::$languageCache[$cacheKey];
		}
	}

	private static function setPhraseCache($cacheKey, $data)
	{
		self::$languageCache[$cacheKey] = $data;
		vB_Cache::instance()->write($cacheKey, $data, false, "vB_Language_languageCache");
	}

}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
