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
 * vB_Library_Page
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Page extends vB_Library
{
	protected $lastCacheData = array();

	// array of info used for precaching
	protected $preCacheInfo = array();

	//Last time we saved cache- useful to prevent thrashing
	protected $lastpreCache = false;

	//Minimum time between precache list updates, in seconds
	const MIN_PRECACHELIFE = 300;


	/**
	 * This preloads information for the current page.
	 *
	 * @param	string	the identifier for this page, which comes from the route class.
	 */
	public function preload($pageKey)
	{
		$this->lastCacheData = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read("vbPre_$pageKey");

		//If we don't have anything, just return;
		if (!$this->lastCacheData)
		{
			return;
		}

		$this->lastpreCache = $this->lastCacheData['cachetime'];

		if (!empty($this->lastCacheData['data']))
		{
			foreach ($this->lastCacheData['data'] AS $class => $tasks)
			{
				try
				{
					$library = vB_Library::instance($class);
					foreach ($tasks AS $method => $params)
					{
						if (method_exists($library, $method))
						{
							$reflection = new ReflectionMethod($library, $method);
							$reflection->invokeArgs($library, $params);
						}
					}

				}
				catch(exception $e)
				{
					//nothing to do. Just try the other methods.
				}
			}
		}
	}

	/**
	 * This saves preload information for the current page.
	 * @param string $pageKey -- the identifier for this page, which comes from the route class.
	 */
	public function savePreCacheInfo($pageKey)
	{
		$timenow = vB::getRequest()->getTimeNow();

		if (empty($this->preCacheInfo) OR
			(($timenow - intval($this->lastpreCache)) < self::MIN_PRECACHELIFE)
		)
		{
			return;
		}
		$data = array('cachetime' => $timenow, 'data' => $this->preCacheInfo);

		vB_Cache::instance(vB_Cache::CACHE_LARGE)->write("vbPre_$pageKey", $data, 300);
	}

	/**
	 * This saves preload information for the current page.
	 *
	 *	@param	string $apiClass -- name of the api class
	 * 	@param	string $method -- name of the api method that should be called
	 *	@param	mixed $params -- array of method parameters that should be passed
	 */
	public function registerPrecacheInfo($apiClass, $method, $params)
	{
		//if we have cached within the last five minutes do nothing.
		if ((vB::getRequest()->getTimeNow() - intval($this->lastpreCache)) < self::MIN_PRECACHELIFE)
		{
			return;
		}

		if (!isset($this->preCacheInfo[$apiClass]))
		{
			$this->preCacheInfo[$apiClass] = array();
		}

		$this->preCacheInfo[$apiClass][$method] = $params;
	}

	/*
	 *	Should have a delete($pageid) function here that does the same as the API
	 *	function without the permissions checks.  But that requires pulling a bunch
	 *	of logic from the API function into this class which is beyond the scope
	 *	of the current effort.
	 */

	/**
	 *	Delete a page
	 *
	 *	@param array $page -- the page info
	 *	@return true|array -- either on sucess true or an error array
	 */
	public function deleteFromPageInfo($page)
	{
		$assertor = vB::getDbAssertor();
		$check = $assertor->delete('page', array('pageid' => $page['pageid']));

		if ($check AND empty($check['errors']))
		{
			vB5_Route::deleteRoute($page['routeid']);
			return true;
		}
		else
		{
			return $check;
		}
	}


	public function getURLs($params = array())
	{
		$usercontext = vB::getUserContext();
		$assertor = vB::getDbAssertor();

		if (empty($params['type']))
		{
			/*
				Supports:
				all
				pages
				custom_pages
				channels_and_conversations
			 */
			// For now, just filter via PHP & use jquery ui tabs.
			$params['type'] = 'all';
		}

		if (empty($params['sortby']))
		{
			// This was mostly useful for debugging/testing, but leaving it in place for now.
			// url|pagetitle
			$params['sortby'] = 'pagetitle';
		}

		$rows = $assertor->getRows('vBForum:getURLs', $params);

		/*
			Fetch the nodeids of certain channels we need to exclude from the list.
		 */
		$excludedChannelGUIDs = array(
			vB_Channel::DEFAULT_CHANNEL_PARENT, // 'special' channel
			vB_Channel::PRIVATEMESSAGE_CHANNEL,
			vB_Channel::VISITORMESSAGE_CHANNEL,
			vB_Channel::ALBUM_CHANNEL,
			vB_Channel::REPORT_CHANNEL,
			vB_Channel::INFRACTION_CHANNEL,
		);
		$excludedChannels = vB::getDbAssertor()->assertQuery('vBForum:channel', array('guid' => $excludedChannelGUIDs));
		$excludedChannelsByChannelid = array();
		foreach ($excludedChannels AS $row)
		{
			$excludedChannelsByChannelid[$row['nodeid']] = $row;
		}


		// bulk fetch phrases for page title
		$phraseidsByPageGuid = array();
		$phraseLIB = vB_Library::instance('phrase');
		foreach ($rows AS $row)
		{
			$phraseKey = 'page_' .  $phraseLIB->cleanGuidForPhrase($row['page_guid']) . '_title';
			$phraseidsByPageGuid[$row['page_guid']] = $phraseKey;
		}
		$phrases = vB_Api::instanceInternal('phrase')->fetch($phraseidsByPageGuid);

		$baseurl = (empty($params['doabsoluteurl']) ? "" : vB::getDatastore()->getOption('frontendurl')  . "/");
		$data = array();
		$custom_pages = array();
		foreach ($rows AS $row)
		{
			// contentid can be pageid or nodeid depending on the type of the route.
			// For channels, contentid is the nodeid of the channel. See vB5_Route_Channel::validInput()
			if ($row['class'] == 'vB5_Route_Channel' AND
				!empty($row['contentid']) AND
				isset($excludedChannelsByChannelid[$row['contentid']])
			)
			{
				continue;
			}

			// I don't think this is necessary, but let's make this safe to use as a relative url
			// (or prepended to {frontendurl}/ if $param['doabsoluteurl'] == true) in the href attribute
			$url = ltrim($row['prefix'], '/');
			$phraseid = $phraseidsByPageGuid[$row['page_guid']];
			$pagetitle = $phrases[$phraseid];
			$label =  $pagetitle;
			$label_after_anchor = " (/$url)";
			/*
			if (empty($url))
			{
				// Special case, show *something* for the home URL.
				// We don't allow "/" as a prefix by itself, so using this for the label is OK.
				// If we want to use the PAGE TITLE instead, we need to fetch the page.guid, escape it through vB_Library::instance('phrase')->cleanGuidForPhrase(),
				// & fetch the phrase from the phrase table. We can't do it all in the same query as vBForum:getURLs
				$label .= ' (/)';
			}
			else
			{
				$label .=  ' (' . $url . ')';
			}
			*/

			// key *should* be unique, as the URL is unique. Unless in some freaky convoluted case where
			// a madman generates a page title + URL combination to somehow collide
			// with another page. The delimiter ":::" is there to help with that, as the URL shouldn't
			// contain those characters, and we're always ending the key with the URL...
			// We prefix the key with the pagetitle, as to sort it alphabetically via pagetitle first.
			$delimiter = ":::";
			switch ($params['sortby'])
			{
				case 'url':
					$key = $url . $delimiter . $pagetitle;
					break;
				case 'pagetitle':
				default:
					$key = $pagetitle . $delimiter . $url;
					break;
			}

			if (!isset($data[$key]))
			{
				$extra = array(
					'class' => $row['class'],
					'pagetype' => $row['pagetype'],
					'name' => $row['name'],
				);
				$data[$key] = array(
					'url' => $baseurl . $url,
					'label' => $label,
					'label_after_anchor' => $label_after_anchor,
					// in case we want to add some raw HTML around the label in the future.
					'raw_label' => vB_String::htmlSpecialCharsUni($label),
					'extra' => array(
						$row['routeid'] => $extra,
					),
				);
			}
			else
			{
				$extra = array(
					'class' => $row['class'],
					'pagetype' => $row['pagetype'],
					'name' => $row['name'],
				);
				$data[$key]['extra'][$row['routeid']] = $extra;
			}

			$checkPerms = array(
				'vB5_Route_Channel' => true,
				'vB5_Route_Conversation' => true,
				'vB5_Route_Article' => true,
			);
			if (isset($checkPerms[$row['class']]))
			{
				$arguments = unserialize($row['arguments']);
				if (isset($arguments['channelid']) AND is_numeric($arguments['channelid']))
				{
					$channelid = intval($arguments['channelid']);
					if (!$usercontext->getChannelPermission('forumpermissions', 'canview', $channelid))
					{
						// No view perms on this node-associated route.
						unset($data[$key]);
					}

				}
			}

			if (isset($data[$key]) AND $row['class'] == 'vB5_Route_Page' AND $row['pagetype'] == 'custom')
			{
				$custom_pages[$key] = $data[$key];
			}
		}

		// Sort alphabetically by pagetitle (or whatever the array keys are defined with).
		ksort($data, SORT_NATURAL );
		ksort($custom_pages, SORT_NATURAL );



		/*
		foreach ($data AS $__url => $__pagedata)
		{
			// Todo: only show "custom" page routes?
			// Todo: at least one default conversation route is showing as "custom" instead of "default"
			if (count($__pagedata['extra']) > 1)
			{
				// This is most likely a channel + conversation group of routes
				// ...
			}
		}
		*/


		$perpage = 10;
		$paginated = array_chunk($data, $perpage, true);
		$paginated_custom_pages = array_chunk($custom_pages, $perpage, true);

		// We could potentially skip orphan checks if $params['pageid'] is not empty, since
		// if we're looking for specific pages, by definition those pages won't be orphaned templates.
		$orphans = $this->getOrphanedPagetemplates($params);


		return array(
			'all' => array(
				'pagenav' => array(
					'currentpage' => 1,
					'totalpages' => count($paginated),
				),
				'paginated' => $paginated,
				'empty_phraseid' => 'error', // we should never have 0 pages. Something seriously went wrong here.
			),
			'custom_pages' => array(
				'pagenav' => array(
					'currentpage' => 1,
					'totalpages' => count($paginated_custom_pages),
				),
				'paginated' => $paginated_custom_pages,
				'empty_phraseid' => 'sbpanel_pagelist_empty_placeholder_custompages',
			),
			'orphans' => $orphans['orphans'],
		);
	}


	public function getOrphanedPagetemplates($params = array())
	{
		$usercontext = vB::getUserContext();
		$assertor = vB::getDbAssertor();

		$rows = $assertor->getRows('vBForum:getOrphanedPagetemplates');

		$defaultPagetemplateGUIDs = vB_Page::getDefaultPageTemplateGUIDs();

		$table_headers = array(
			"pagetemplateid" => "pagetemplateid",
			"title" => "title",
			//"guid",
		);


		$phrases = vB_Api::instanceInternal('phrase')->fetch(array(
			'pagetemplate_no_title',
		));

		$data = array();
		$sortbykey = 'pagetemplateid';
		foreach ($rows AS $__row)
		{
			$__key = $__row[$sortbykey];
			$__guid = $__row['guid'];
			if (isset($defaultPagetemplateGUIDs[$__guid]))
			{
				continue;
			}

			$__title = $__row['title'];
			if (empty($__title))
			{
				$__title = $phrases['pagetemplate_no_title'];
			}

			// keep this in sync with $table_headers above
			$data[$__key] = array(
				"pagetemplateid" => $__row['pagetemplateid'],
				"title" => $__title,
				//"guid" => $__guid,
			);
		}

		// Sort by pagetemplateid
		ksort($data, SORT_NATURAL );


		$perpage = 10;
		$paginated = array_chunk($data, $perpage, true);

		return array(
			'orphans' => array(
				'pagenav' => array(
					'currentpage' => 1,
					'totalpages' => count($paginated),
				),
				'paginated' => $paginated,
				'table_headers' => $table_headers,
				'empty_phraseid' => 'sbpanel_pagelist_empty_placeholder_orphans', // "no orphaned pagetemplates"
			),
		);
	}

	/**
	 * Returns a list of pages to show as the home page options in quick config
	 */
	public function getHomePages()
	{
		$pageguids = array(
			'vbulletin-4ecbdac82ef5d4.12817784',
			'vbulletin-page-homeclassic-5d5f1629c20b77.42318601',
			'vbulletin-page-homecommunity-5d6039ff53c7b6.02957268',
		);

		// allow products to add pages to the list
		vB::getHooks()->invoke('hookLibraryPageGetHomePages', array(
			'pageguids' => &$pageguids,
		));

		$pages = vB::getDbAssertor()->getRows('vBForum:getHomePages', array('pageguids' => $pageguids));

		if (!empty($pages))
		{
			$foundHomeRoute = false;
			$homeRouteId = false;
			$cleanGuids = array();
			$phraseVarnames = array();

			$phraseLib = vB_Library::instance('phrase');
			$phraseApi = vB_Api::instanceInternal('phrase');

			foreach ($pages AS $page)
			{
				// clean guid is used for phrase & thumbnail URL
				$cleanGuid = $phraseLib->cleanGuidForPhrase($page['guid']);
				$cleanGuids[$page['guid']] = $cleanGuid;

				// get home page title phrases (this is not the same phrase as the page's displaytitle)
				$phraseVarnames[$page['guid']] = 'page_' . $cleanGuid . '_homepagetitle';

				// check if one of these pages is set as home page
				if ($page['ishomeroute'] == 1)
				{
					$foundHomeRoute = true;
					$homeRouteId = $page['routeid'];
				}
			}
			$phrases = $phraseApi->fetch($phraseVarnames);

			foreach ($pages AS $k => $page)
			{
				// add home page title
				$varname = $phraseVarnames[$page['guid']];
				$pages[$k]['title'] = $phrases[$varname] ?? '~~' . $varname . '~~';

				// add thumbnail URLs
				$cleanGuid = $cleanGuids[$page['guid']];
				$pages[$k]['thumbnailurl'] = 'images/sitebuilder/page-thumb-' . $cleanGuid . '.png';

				// is this one selected?
				$pages[$k]['selected'] = ($page['ishomeroute'] == 1);
			}

			if (!$homeRouteId)
			{
				// custom home page
				$homeRoute = vB::getDbAssertor()->getRow('routenew', array('ishomeroute' => 1));
				$homeRouteId = $homeRoute['routeid'];
			}

			return array(
				'success' => true,
				'pages' => $pages,
				'foundhomeroute' => $foundHomeRoute,
				'homerouteid' => $homeRouteId,
			);
		}

		return array('success' => false);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102755 $
|| #######################################################################
\*=========================================================================*/
