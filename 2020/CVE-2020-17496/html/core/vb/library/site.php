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
 * vB_Library_Site
 *
 * @package vBLibrary
 */

class vB_Library_Site extends vB_Library
{
	// Assertor object
	protected $assertor;

	// fields for navbars -- everything else will be removed
	protected $fields = array(
		'title' => vB_Cleaner::TYPE_STR,
		'phrase' => vB_Cleaner::TYPE_STR,
		'url' => vB_Cleaner::TYPE_STR,
		'attr' => vB_Cleaner::TYPE_STR,
		'usergroups' => vB_Cleaner::TYPE_ARRAY_UINT,
		'newWindow' => vB_Cleaner::TYPE_BOOL,
		'subnav' => vB_Cleaner::TYPE_ARRAY,
	);

	//all boolean fields need to be listed here because
	//"false" is an empty value.
	private $emptyAllowed = array(
		'subnav',
		'usergroups',
		'phrase',
		'attr',
		'newWindow',
	);


	// cleaner instance
	protected $cleanerObj;

	protected $sitescache = array();

	/**
	 * Array of cached channelInfo, used by getChannelType
	 * @var	array
	 */
	protected $channelInfo = array();

	/**
	 * Phrases that need to be cached for the navbar/footer items
	 *
	 * @var array
	 */
	protected $requiredPhrases = array();

	/**
	 * Cached phrases used for navbar/footer items
	 *
	 * @var array
	 */
	protected $phraseCache = array();

	/**
	 * Initializes an Api Site object
	 */
	public function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
		$this->cleanerObj = new vB_Cleaner();
	}

	/**
	 * Stores the header navbar data.
	 *
	 * @param	int			The storing data siteid (currently ignored).
	 * @param	mixed		Array of elements containing data to be stored for header navbar. Elements might contain:
	 * 			title		--	string		Site title. *required
	 * 			url			--	string		Site url. *required
	 * 			usergroups	--	array		Array of ints.
	 * 			newWindow	--	boolean		Flag used to display site in new window. *required
	 * 			subnav		--	mixed		Array of subnav sites (containing same site data structure).
	 * 				id			--	int		Id of subnav site.
	 * 				title		--	string	Title of subnav site.
	 * 				url			--	string	Url of subnav site.
	 * 				usergroups	--	array	Array of ints.
	 * 				newWindow	--	boolean	Flag used to display subnav site in new window.
	 * 				subnav		--	mixed	Array of subnav sites (containing same site data structure).
	 * @return	boolean		To indicate if save was succesfully done.
	 */
	public function saveHeaderNavbar($siteId, $data)
	{
		/** We expect an array of elements for cleaning */
		$cleanedData = array();
		foreach ($data AS $key => $element)
		{
			$cleanedData[$key] = $this->cleanData($element);
		}

		/** Required fields check */
		$this->hasEmptyData($cleanedData);
		$phrases = array();
		foreach ($cleanedData AS &$element)
		{
			$this->saveNavbarPhrase($element, $phrases);
		}

		//rebuild the language after saving phrases
		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);

		/** At this point we can store the data */
		$cleanedData = serialize($cleanedData);
		$response = $this->assertor->update('vBForum:site', array('headernavbar' => $cleanedData), vB_dB_Query::CONDITION_ALL);

		// reset cache
		unset($this->sitescache);
		return true;
	}

	/**
	 * Stores the footer navbar data.
	 *
	 * @param	int			The storing data siteid (currently ignored).
	 * @param	mixed		Array of data to be stored for footer navbar.
	 * 			title		--	string		Site title.
	 * 			url			--	string		Site url.
	 * 			usergroups	--	array		Array of ints.
	 * 			newWindow	--	boolean		Flag used to display site in new window.
	 * 			subnav		--	mixed		Array of subnav sites (containing same site data structure).
	 * 				id			--	int		Id of subnav site.
	 * 				title		--	string	Title of subnav site.
	 * 				url			--	string	Url of subnav site.
	 * 				usergroups	--	array	Array of ints.
	 * 				newWindow	--	boolean	Flag used to display subnav site in new window.
	 * 				subnav		--	mixed	Array of subnav sites (containing same site data structure).
	 * @return	boolean		To indicate if save was succesfully done.
	 */
	public function saveFooterNavbar($siteId, $data)
	{
		/** We expect an array of elements for cleaning */
		$cleanedData = array();
		foreach ($data AS $key => $element)
		{
			$cleanedData[$key] = $this->cleanData($element);
		}

		/** Required fields check */
		$this->hasEmptyData($cleanedData);
		$phrases = array();
		foreach ($cleanedData AS &$element)
		{
			$this->saveNavbarPhrase($element, $phrases);
		}

		//rebuild the language after saving phrases
		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);

		/** At this point we can store the data */
		$cleanedData = serialize($cleanedData);
		$response = $this->assertor->update('vBForum:site', array('footernavbar' => $cleanedData), vB_dB_Query::CONDITION_ALL);

		// reset cache
		unset($this->sitescache);

		return true;
	}

	/**
	 * Gets the header navbar data
	 *
	 * @param	int		Site id requesting header data.
	 * @param	string		URL
	 * @param	int		Edit mode so allow all links if user can admin sitebuilder
	 * @param	int		Channel ID (optional, used to determine current header navbar tab)
	 *
	 * @return	mixed	Array of header navbar data (Described in save method).
	 */
	public function loadHeaderNavbar($siteId, $url = false, $edit = false, $channelId = 0)
	{
		return $this->getNavbar('header', $siteId, $url, $edit, $channelId);
	}

	/**
	 * Gets the footer navbar data
	 *
	 * @param	int		Site id requesting footer data.
	 * @param	string		URL
	 * @param	int		Edit mode so allow all links if user can admin sitebuilder
	 *
	 * @return	mixed	Array of footer navbar data (Described in save method).
	 */
	public function loadFooterNavbar($siteId, $url = false, $edit = false)
	{
		return $this->getNavbar('footer', $siteId, $url, $edit);
	}

	/**
	 * Gets the navbar data for the header or the footer
	 *
	 * @param	int		Site id requesting header/footer data. (currently ignored).
	 * @parma	string		URL
	 * @param	int		Edit mode so allow all links if user can admin sitebuilder
	 * @param	int		Channel ID (optional, used to determine current header navbar tab)
	 *
	 * @return	mixed	Array of header/footer navbar data (Described in save method).
	 */
	private function getNavbar($type, $siteId, $url = false, $edit = false, $channelId = 0)
	{
		if (empty($this->sitescache))
		{
			$queryParams = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT);
			$this->sitescache = $this->assertor->getRow('vBForum:site', $queryParams);

			$header = unserialize($this->sitescache['headernavbar']);
			$footer = unserialize($this->sitescache['footernavbar']);

			try
			{
				$this->removeRestrictedTabs($header, $edit);
				$this->addDerivedData($header);

				//only the header needs a current mark -- and only if we've been
				//given an indication that we should mark it.
				if ($url OR $channelId)
				{
					$this->markCurrentTab($header, $url, $edit, $channelId);
				}

				$this->removeRestrictedTabs($footer, $edit);
				$this->addDerivedData($footer);
			}
			catch (Exception $e)
			{
				// This only really happens in unit tests, but if we hit an exception during the preparation above,
				// it means never finished saving the _prepared data to memory. If multiple calls to loadHeaderNavbar()
				// are made, it can cause weird behavior.
				// On a related note, the fact that we don't cache by $channelId means that only the *first valid*
				// (no exception) loadHeaderNavbar() call will be guaranteed to be correct. . .
				unset($this->sitescache);
				throw $e;
			}

			// when editing, phrases need to be loaded from language 0 specifically
			// other language translations can be edited in the Admin CP
			// when not editing, phrases are pulled via the template tag vb:phrase
			if ($edit)
			{
				$this->cachePhrases($edit);
				$this->addPhrasesToData($header);
				$this->addPhrasesToData($footer);
			}

			$this->sitescache['headernavbar_prepared'] = $header;
			$this->sitescache['footernavbar_prepared'] = $footer;
		}

		return $this->sitescache[$type . 'navbar_prepared'];
	}

	private function markCurrentTab(array &$data, $url, $edit, $channelId)
	{
		$baseurl = vB::getDatastore()->getOption('frontendurl');
		$baseurl_short = vB_String::parseUrl($baseurl, PHP_URL_PATH);

		//if we don't have a url or we are at the root we're basically going
		//to match a bunch of things of dubious merit.
		//
		//We'll default to the root url (if it's in the nav) if we don't find anything else
		if ($url)
		{
			if ($this->setBestMatchFromUrl($data, $baseurl, $baseurl_short, $url))
			{
				return;
			}
		}

		$channelId = (int) $channelId;
		if ($channelId > 0)
		{
			//this is a little bogus, but some people have change the url on the
			//base pages without changing the navbar.  This will continue to work
			//in some cases because of 301 redirects and this logic mapping to the
			//default tab urls.  Leaving it in to prevent existing sites from
			//randomly breaking on upgrade.
			$channelTabMap = array(
				'blog' => 'blogs',
				'group' => 'social-groups',
				'article' => 'articles',
			);

			$type = $this->getChannelType($channelId);
			if (isset($channelTabMap[$type]))
			{
				if ($this->setBestMatchFromUrl($data, $baseurl, $baseurl_short, $baseurl_short . '/' . $channelTabMap[$type]))
				{
					return;
				}
			}

			$channelApi = vB_Api::instance('content_channel');
			$topChannels = $channelApi->fetchTopLevelChannelIds();
			if (isset($topChannels[$type]))
			{
				//we have an (unused) channel page for the forum channel that is distinct from the
				//"home" page which is what most people associate with the forums.  This
				//is unfortunate, but it's going to be difficult to unwind at this point.
				//so let's work around it.
				$channelid = ($type == "forum" ? 1 : $topChannels[$type]);

				$channel = $channelApi->getBareContent($channelid);
				$channel = reset($channel);
				$url = vB5_Route::buildUrl($channel['routeid']);

				//the channel url starts with '/' from the route even though it shouldn't
				//however the implications of correcting this are a little scary so it hasn't
				//happened yet.  The ltrim future proofs this so it won't break if we
				//fix it.
				$url = $baseurl_short . '/' . ltrim($url, '/');
				if ($this->setBestMatchFromUrl($data, $baseurl, $baseurl_short, $url))
				{
					return;
				}
			}
		}

		//try to find the root page
		if ($this->setBestMatchFromUrl($data, $baseurl, $baseurl_short, $baseurl_short . '/'))
		{
			return;
		}

		//mark the first tab so *something* is highlighted.
		$data[0]['current'] = true;
	}

	private function setBestMatchFromUrl(array &$data, $baseurl, $baseurl_short, $url)
	{
		$bestMatchTab = null;
		$bestMatchLength = 0;

		foreach ($data AS $k => &$item)
		{
			if (!empty($item['subnav']) AND is_array($item['subnav']))
			{
				foreach($item['subnav'] AS $subKey => &$subItem)
				{
					$matchLen = $this->getPossibleTabMatchLength($baseurl, $baseurl_short, $subItem, $url);
					if ($matchLen > $bestMatchLength)
					{
						//deliberately track the parent tab and not the subtab
						$bestMatchTab = &$item;
						$bestMatchLength = $matchLen;
					}
				}
			}

			$matchLen = $this->getPossibleTabMatchLength($baseurl, $baseurl_short, $item, $url);
			if ($matchLen > $bestMatchLength)
			{
				$bestMatchTab = &$item;
				$bestMatchLength = $matchLen;
			}
		}

		if ($bestMatchLength > 0)
		{
			$bestMatchTab['current'] = true;
			return true;
		}

		return false;
	}

	private function getPossibleTabMatchLength($baseurl, $baseurl_short, $item, $currentUrl)
	{
		//try to normalize the item url against what we get passed as the "currentUrl"
		if ($item['isAbsoluteUrl'])
		{
			//if the absolute url for doesn't match the site path, then we should never
			//flag it.  However if the path happens to be a prefix of baseurl, then it
			//*can* trigger a match in the logic below.  When that happens and we don't
			//have a better match then we'll use it -- potentially at the expense of
			//other, better rules that we would fall to without a match.
			if (strpos($item['normalizedUrl'], $baseurl) !== 0)
			{
				return 0;
			}

			$itemUrl = vB_String::parseUrl($item['normalizedUrl'], PHP_URL_PATH);
		}
		else
		{
			$itemUrl = $baseurl_short . '/' . $item['normalizedUrl'];
		}

		$currentLower = strtolower($currentUrl);
		$itemLower = strtolower($itemUrl);
		$currentLen = strlen($currentUrl);
		$itemLen = strlen($itemUrl);

		//exact match, this is probably the winner
		if ($currentLower == $itemLower)
		{
			return $itemLen;
		}

		//if the url we are testing is longer than the tab/subtab url then we might have
		//a match.  However we don't want to test if the item url is blank because that
		//can cause spurious matches (the base_url will match *anything*) and prevent
		//fall through to some of the the other match urls (channel based, etc)
		if ($item['normalizedUrl'] AND $currentLen > $itemLen)
		{
			//$itemLower is a prefix of $currentUrl then we have a possible match.  Return the
			//prefix length so we can compute the best one
			$prefixLower = strtolower(substr($currentUrl, 0, -($currentLen - $itemLen)));
			if ($prefixLower == $itemLower)
			{
				return $itemLen;
			}
		}

		return 0;
	}

	private function addDerivedData(array &$data)
	{
		foreach ($data AS $k => &$item)
		{
			$this->addDerivedDataToItem($item);
			if (!empty($item['subnav']) AND is_array($item['subnav']))
			{
				foreach($item['subnav'] AS $subKey => &$subItem)
				{
					$this->addDerivedDataToItem($subItem);
				}
			}
		}
	}

	private function addDerivedDataToItem(array &$item)
	{
		//not entirely sure what purpose this serves
		$this->requiredPhrases[] = $item['title'];

		$item['phrase'] = $item['title'];
		$item['isAbsoluteUrl'] = (bool) preg_match('#^https?://#i', $item['url']);
		$item['normalizedUrl'] = ltrim($item['url'], '/');
		$item['newWindow'] = ($item['newWindow'] ? 1 : 0);
	}

	private function removeRestrictedTabs(array &$data, $edit = false)
	{
		$canusesitebuilder = vB::getUserContext()->hasAdminPermission('canusesitebuilder');

		$userinfo = vB_Api::instanceInternal('user')->fetchCurrentUserInfo();
		$usergroups = array();
		if ($userinfo['membergroupids'])
		{
			$usergroups = explode(',', $userinfo['membergroupids']);
		}
		$usergroups[] = $userinfo['usergroupid'];
		sort($usergroups);

		$showAll = ($edit AND $canusesitebuilder);

		$removed_element = false;
		foreach ($data AS $k => &$item)
		{
			if ($this->shouldRemoveItem($showAll, $usergroups, $item))
			{
				unset($data[$k]);
				$removed_element = true;
			}
			else
			{
				if (!empty($item['subnav']) AND is_array($item['subnav']))
				{
					$removed_element_sub = false;
					foreach($item['subnav'] AS $subKey => &$subItem)
					{
						if ($this->shouldRemoveItem($showAll, $usergroups, $subItem))
						{
							unset($item['subnav'][$subKey]);
							$removed_element_sub = true;
						}
					}

					if ($removed_element_sub)
					{
						$item['subnav'] = array_values($item['subnav']);
					}
				}
			}
		}

		// Reset the keys of the array, because in js it will be considered as an object
		// Only want to do if needed (and only once per array) since it can be expensive.
		if ($removed_element)
		{
			$data = array_values($data);
		}
	}

	private function shouldRemoveItem($showAll, $usergroups, array $item)
	{
		//not sure if this is still needed.  It was added with a cryptic comment about
		//making unit tests pass and skips some processing we should always be doing
		//More over each item should be an array with a url field -- if that's not
		//true we have a problem.  So we'll just quietly remove it here and assume
		//it's good later.  This is a change of behavior from previously.
		if (!is_array($item) OR !isset($item['url']))
		{
			return true;
		}

		//if we aren't showing everything and we have usergroups set in the item
		//we might want to hide the tab (no usergroups means allow all)
		else if (!$showAll AND !empty($item['usergroups']))
		{
			$itemgroups = $item['usergroups'];
			sort($itemgroups);

			if (!$this->compareGroupLists($usergroups, $itemgroups))
			{
				return true;
			}
		}

		return false;
	}

	/**
	 *	Returns true if any of needle exist in haystack
	 *
	 *	*ASSUMES THAT BOTH NEEDLE AND HAYSTACK ARE SORTED ASCENDING*
	 *
	 *	@param array $needle
	 *	@param array $haystack
	 *	@return bool
	 */
	private function compareGroupLists($needle, $haystack)
	{
		$needleindex = 0;
		$needlelen = count($needle);

		$haystackindex = 0;
		$haystacklen = count($haystack);

		//while we haven't hit the end of the array
		while (($needleindex < $needlelen) AND ($haystackindex < $haystacklen))
		{
			if ($needle[$needleindex] == $haystack[$haystackindex])
			{
				return true;
			}
			else if ($needle[$needleindex] < $haystack[$haystackindex])
			{
				$needleindex++;
			}
			else
			{
				$haystackindex++;
			}
		}

		//we hit the end of one of the lists without finding a match
		return false;
	}


	/**
	 * Returns the channel type for the given channel ID
	 * @param  int          The channel associated with the page.  If a non channel node is provided
	 * 											we will use that nodes channel instead.
	 * @return string|false The channel type, or an false if there was a problem,
	 *                      for example the user doesn't have access to the channel.
	 */
	protected function getChannelType($channelId)
	{
		if (!isset($this->channelInfo[$channelId]))
		{
			try
			{
				//this is supposed to be a channel id but it isn't always.  However all we actually care about is the
				//channel type, which is set for any node based on its ancestor channel.  If we ever need more
				//information about the channel than that we can explicitly look up the node's channel if it isn't
				//one already.
				$info = vB_Library::instance('node')->getNodeFullContent($channelId);
				$this->channelInfo[$channelId]['channeltype'] = $info[$channelId]['channeltype'];
			}
			catch (vB_Exception_Api $e)
			{
				if ($e->has_error('no_permission'))
				{
					return false;
				}
				else
				{
					throw $e;
				}
			}
		}

		if (isset($this->channelInfo[$channelId]) AND isset($this->channelInfo[$channelId]['channeltype']))
		{
			return $this->channelInfo[$channelId]['channeltype'];
		}

		return false;
	}

	protected function cachePhrases($edit = false)
	{
		if (!empty($this->requiredPhrases))
		{
			// when editing, use the default language phrase
			// translations can be made in the Admin CP.
			// instanceinternal?
			$this->phraseCache = vB_Api::instance('phrase')->fetch($this->requiredPhrases, ($edit ? 0 : null));
			$this->requiredPhrases = array();
		}
	}

	protected function addPhrasesToData(&$data)
	{
		foreach ($data as $k => &$item)
		{
			$item['phrase'] = $item['title'];
			$item['title'] = (isset($this->phraseCache[$item['phrase']]) AND !empty($this->phraseCache[$item['phrase']]))
				? $this->phraseCache[$item['phrase']] : $item['phrase'];

			if (!empty($item['subnav']) AND is_array($item['subnav']))
			{
				$this->addPhrasesToData($item['subnav']);
			}
		}
	}

	/**
	 * Check if data array is empty
	 *
	 * @param	mixed		Array of site data (described in save methods) to check.
	 *
	 * @throws 	Exception	missing_required_field if there's an empty field in site data.
	 */
	protected function hasEmptyData($data)
	{
		if (empty($data) OR !is_array($data))
		{
			throw new vB_Exception_Api('missing_required_field');
		}

		foreach ($data AS $field => $value)
		{
			//it's O.K. to have some empty fields.
			//we have both numeric and named fields that flow through here -- the numeric ones
			//are for tabs/subtabs as a whole and hit the recursive call below.  However because
			//of nastiness with PHPs auto type conversions, 0 == 'subnav' is true (even indirectly
			//with functions like in_array) so we validate that $field is not an empty value
			//to avoid a case.  It shouldn't matter anyway since empty($value) should never be
			//true for field 0 but a previous version of this code had a flaw were that wasn't checked
			//properly.  It's best to be completely correct here.
			if (!empty($field) AND (empty($value)) AND in_array($field, $this->emptyAllowed))
			{
				continue;
			}

			if (is_array($value))
			{
				$this->hasEmptyData($value);
			}
			else
			{
				if (empty($value))
				{
					throw new vB_Exception_Api('missing_required_field');
				}
			}
		}
	}

	protected function cleanData($data)
	{
		/** should be an array data */
		if (!is_array($data))
		{
			throw new vB_Exception_Api('invalid_data');
		}


		foreach ($data AS $fieldKey => $fieldVal)
		{
			if (isset($this->fields[$fieldKey]))
			{
				//if the field isn't present, don't add it.
				if (isset($data[$fieldKey]))
				{
					// clean array of subnav items properly
					if ($fieldKey === 'subnav')
					{
						foreach ($data[$fieldKey] AS $idx => $val)
						{
							$data[$fieldKey][$idx] = $this->cleanData($data[$fieldKey][$idx]);
						}
					}
					else
					{
						$data[$fieldKey] = $this->cleanerObj->clean($data[$fieldKey], $this->fields[$fieldKey]);
					}
				}
			}
			else
			{
				unset($data[$fieldKey]);
			}
		}

		return $data;
	}

	protected function saveNavbarPhrase(&$element, &$phrases)
	{
		if (
			!isset($element['phrase']) OR
			empty($element['phrase']) OR
			strpos($element['phrase'], 'navbar_') !== 0 OR
			/* we cannot have two different values for the same phrase */
			(isset($phrases[$element['phrase']]) AND $phrases[$element['phrase']] != $element['title'])
		)
		{
			$words = explode(' ', $element['title']);
			array_walk($words, 'trim');
			$phrase = strtolower(implode('_', $words));

			//translating some special characters to their latin form
			$phrase = vB_String::latinise($phrase);

			// remove any invalid chars
			$phrase = preg_replace('#[^' . vB_Library_Phrase::VALID_CLASS . ']+#', '', $phrase);

			$phrase = 'navbar_' . $phrase;

			$suffix = 0;
			$tmpPhrase = $phrase;
			while (isset($phrases[$tmpPhrase]) AND $phrases[$tmpPhrase] != $element['title'])
			{
				$tmpPhrase = $phrase . (++$suffix);
			}

			$element['phrase'] = $tmpPhrase;
		}

		// Store the phrase-value so that we can check
		$phrases[$element['phrase']] = $element['title'];

		$existingPhrases = vB::getDbAssertor()->getRows('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'varname' => $element['phrase'],
		));

		// don't destroy translations
		$text = array();
		foreach ($existingPhrases as $existingPhrase)
		{
			$text[$existingPhrase['languageid']] = $existingPhrase['text'];
		}
		// the edited phrase
		$text[0] = $element['title'];

		vB_Library::instance('phrase')->save(
			'navbarlinks',
			$element['phrase'],
			array(
				'text' => $text,
				'oldvarname' => $element['phrase'],
				'oldfieldname' => 'navbarlinks',
				't' => 0,
				'ismaster' => 0,
				'product' => 'vbulletin'
			),
			true
		);

		// store phrase name instead of title
		$element['title'] = $element['phrase'];
		unset($element['phrase']);

		// do the same for subnavigation
		if (isset($element['subnav']) AND !empty($element['subnav']))
		{
			foreach($element['subnav'] AS &$subnav)
			{
				$this->saveNavbarPhrase($subnav, $phrases);
			}
		}
	}

	/**
	 * Returns an array of general statistics for the site
	 *
	 * @return	array	Statistics.
	 */
	public function getSiteStatistics()
	{
		$statistics = array();

		// topics & posts
		$topChannels = vB_Api::instanceInternal('Content_Channel')->fetchTopLevelChannelIds();
		$parentid = $topChannels['forum'];
		$forumStats = vB_Api::instanceInternal('Node')->getChannelStatistics($topChannels['forum']);
		$statistics['topics'] = $forumStats['topics'];
		$statistics['posts'] = $forumStats['posts'];

		// members
		$userstats = vB::getDatastore()->getValue('userstats');
		$statistics['members'] = $userstats['numbermembers'];
		$statistics['activeMembers'] = $userstats['activemembers'];

		// latest member
		$statistics['newuser'] = array(
			'username' => $userstats['newusername'],
			'userid' => $userstats['newuserid'],
		);

		// @TODO: blogs, groups, articles

		return array(
			'statistics' => $statistics,
		);
	}

	/**
	 * Clears the internal site cache.
	 *
	 * WARNING: Only intended for use by unit tests. Do not use in
	 * any other context
	 */
	public function clearSiteCache()
	{
		if (!defined('VB_UNITTEST'))
		{
			throw new Exception('This method should be called only from unit tests');
		}
		else
		{
			$this->sitescache = array();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
