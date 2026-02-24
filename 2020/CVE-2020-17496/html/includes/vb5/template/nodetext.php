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

class vB5_Template_NodeText
{
	const PLACEHOLDER_PREFIX = '<!-- ##nodetext_';
	const PLACEHOLDER_SUFFIX = '## -->';

	protected static $instance;
	protected $cache = array();
	protected $pending = array();
	protected $bbCodeOptions = array();
	protected $placeHolders = array();
	protected $contentPages = array();
	protected $previewOnly = array();
	protected $cacheIdToNodeid = array();
	protected $previewLength = false;

	/**
	 * Returns a reference to the singleton instance of this class
	 *
	 * @return	mixed	reference to the vB5_Template_NodeText object
	 */
	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	/**
	 * Returns preview info for one node
	 *
	 * @param	int		the nodeid to be returned
	 * @param	mixed	optional reference to the presentation api interface
	 * @param	string	previewtext
	 */
	public function fetchOneNodePreview($nodeId, &$api = false)
	{
		if (empty($api))
		{
			$api = Api_InterfaceAbstract::instance();
		}
		$nodeid = intval($nodeId);
		$canview =  $api->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions',
				'permission' => 'canviewthreads',
				'nodeid' => $nodeId,
			)
		);

		if (!$canview)
		{
			$node = $api->callApi(
			'node', 'getNode',
			array(
				'nodeid' => $nodeId,)
			);

			if (empty($node['canviewthreads']))
			{
				return '';
			}
		}
		$cangetattachments =  $api->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions2',
				'permission' => 'cangetimgattachment',
				'nodeid' => $nodeId,
			)
		);

		// Use += array() to prevent from it overwrites "allowimages" which is set in $bbCodeOptions parameter
		$bbCodeOptions = array('cangetimgattachment' => $cangetattachments > 0);
		// - VBV-3236

		$cache = $api->cacheInstance(0);
		// since we're replacing phrases, we need the cachekey to be languageid sensitive
		$cacheKey = $this->getCacheKey($nodeId, $bbCodeOptions, true, $canview);
		$found = $cache->read($cacheKey);

		if ($found !== false)
		{
			return $found;
		}
		list($previewText, $parsed) = $this->doParse($nodeId, $bbCodeOptions, $api, $cache);

		return $previewText;
	}

	/**
	 * Returns text info for one node
	 *
	 * 	@param	int		the nodeid to be returned
	 * 	@param	mixed	optional reference to the presentation api interface
	 * 	@param	int		optional content page
	 *
	 *	@return	string	text of the page
	 */
	public function fetchOneNodeText($nodeId, &$api = false, $contentPage = 1)
	{
		if (empty($api))
		{
			$api = Api_InterfaceAbstract::instance();
		}
		$nodeid = intval($nodeId);
		$canview =  $api->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions',
				'permission' => 'canviewthreads',
				'nodeid' => $nodeId,
			)
		);

		if (!$canview)
		{
			$node = Api_InterfaceAbstract::instance()->callApi(
			'node', 'getNode',
			array(
				'nodeid' => $nodeId,)
			);

			if (empty($node['canviewthreads']))
			{
				return '';
			}
		}
		$cangetattachments =  $api->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions2',
				'permission' => 'cangetimgattachment',
				'nodeid' => $nodeId,
			)
		);

		$bbCodeOptions = array('cangetimgattachment' => $cangetattachments > 0); // Use += array() to prevent from it overwrites "allowimages" which is set in $bbCodeOptions parameter
		// - VBV-3236

		$cache = $api->cacheInstance(0);
		// since we're replacing phrases, we need the cachekey to be languageid sensitive
		$cacheKey = $this->getCacheKey($nodeId, $bbCodeOptions, false, $canview);

		$found = $cache->read($cacheKey);

		if ($found == false)
		{
			list($previewText, $found) = $this->doParse($nodeId, $bbCodeOptions, $api, $cache);
		}

		if (empty($found))
		{
			return '';
		}
		else if (!is_array($found))
		{
			return $found;
		}
		$contentPage = intval($contentPage);

		if ($contentPage < 2 OR (count($found) <= $contentPage))
		{
			return $found[0]['pageText'];
		}

		//Remember the cached data uses zero-based key
		return $found[$contentPage - 1]['pageText'];

	}

	/**
	 * returns the title of a page
	 *
	 * 	@param	int		the nodeid to be returned
	 * 	@param	int		optional content page
	 *
	 *	@return	string	title of the article page
	 */
	public function fetchPageTitle($nodeId, $contentPage = 1)
	{
		$paging = $this->fetchArticlePaging($nodeId);

		if (!empty($paging[$contentPage]))
		{
			return $paging[$contentPage];
		}

		return '';
	}


	/**
	 * Returns paging information
	 *
	 * @param	int		nodeid for which we need information
	 * @return	mixed	array of int => string.
	 */
	public function fetchArticlePaging($nodeId)
	{
		$nodeId = intval($nodeId);
		$api = Api_InterfaceAbstract::instance();
		$canview =  $api->callApi(
		'user', 'hasPermissions',
		array(
			'group' => 'forumpermissions',
			'permission' => 'canviewthreads',
			'nodeid' => $nodeId,
		)
		);

		if (!$canview)
		{
			return '';
		}
		$cache = $api->cacheInstance(0);

		$cacheKey = $this->getPagingCacheKey($nodeId);
		$found = $cache->read($cacheKey);

		//We need to do the parse, which will set in cache.
		if ($found === false)
		{
			$cangetattachments =  $api->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions2',
				'permission' => 'cangetimgattachment',
				'nodeid' => $nodeId,
			)
			);
			$bbCodeOptions = array('cangetimgattachment' => $cangetattachments > 0);
			$this->doParse($nodeId, $bbCodeOptions, $api, $cache);
			$found = $cache->read($cacheKey);
		}

		return $found;
	}

	/**
	 * Register userids for avatar preloading
	 *
	 * @param  array  $textDataArray that comes from the getDataForParse API call
	 */
	protected function registerUseridsForAvatarPreloading($textDataArray)
	{
		$avatarUserIds = array();
		foreach ($textDataArray AS $node)
		{
			if (is_array($node['avatar_userids']))
			{
				foreach ($node['avatar_userids'] AS $avatarUserid)
				{
					$avatarUserIds[$avatarUserid] = $avatarUserid;
				}
			}
		}

		if (!empty($avatarUserIds))
		{
			Api_InterfaceAbstract::instance()->callApi('User', 'registerNeedAvatarForUsers', array($avatarUserIds));
		}
	}

	protected function doParse($nodeId, $bbCodeOptions, &$api, &$cache)
	{
		$textDataArray =  $api->callApi('content_text', 'getDataForParse', array(intval($nodeId), $bbCodeOptions));

		// preload avatars
		$this->registerUseridsForAvatarPreloading($textDataArray);

		// writing to cache has been copied from parseNode() to here so that
		// the cached text has the placeholders replaced. VBV-9507
		// any changes to the node requires update
		$events = array('nodeChg_' . $nodeId);
		// need to update cache if channel changes options
		$events[] = 'nodeChg_' .  $textDataArray[$nodeId]['channelid'];
		// also need to update if phrases have been modified
		$events[] = 'vB_Language_languageCache';

		if (empty($textDataArray))
		{
			return array('', '');
		}
		else if (!empty($textDataArray[$nodeId]['previewtext']))
		{
			$cache->write($this->getCacheKey($nodeId, $bbCodeOptions, false, false), $textDataArray[$nodeId]['previewtext'], 10080, $events);
			$cache->write($this->getCacheKey($nodeId, $bbCodeOptions, true, false), $textDataArray[$nodeId]['previewtext'], 10080, $events);
			return array($textDataArray[$nodeId]['previewtext'], $textDataArray[$nodeId]['previewtext']);
		}
		$canview = true;

		list($previewText, $parsed) = $this->parseNode($textDataArray, $nodeId, $bbCodeOptions);
		// we need to replace the place holders before we can write to cache.
		$templateCache = vB5_Template_Cache::instance();
		$templateCache->setRenderTemplatesInReverseOrder(true);
		$templateCache->replacePlaceholders($parsed);
		$templateCache->setRenderTemplatesInReverseOrder(false);
		// also replace phrases & urls
		vB5_Template_Phrase::instance()->replacePlaceholders($parsed);
		vB5_Template_Url::instance()->replacePlaceholders($parsed);

		// write the parsed text to cache. cache for a week.
		$cache->write($this->getCacheKey($nodeId, $bbCodeOptions, false, $canview), $parsed, 10080, $events);
		$cache->write($this->getCacheKey($nodeId, $bbCodeOptions, true, $canview), $previewText, 10080, $events);

		return array($previewText, $parsed);
	}

	/**
	 * Registers location for node text, to be filled with the parsed text later.
	 *
	 *	@param	int		nodeid
	 * 	@param	mixed	optianal bbcode options
	 * 	@param	int		optional content page, for articles only
	 *
	 *	@return	string	the placeholder text
	 */
	public function register($nodeId, $bbCodeOptions = array(), $contentPage = 1)
	{
		$canview =  Api_InterfaceAbstract::instance()->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions',
				'permission' => 'canviewthreads',
				'nodeid' => $nodeId,
			)
		);

		if (!$canview)
		{
			$node = Api_InterfaceAbstract::instance()->callApi(
				'node', 'getNode',
				array('nodeid' => $nodeId)
			);

			if (empty($node['public_preview']))
			{
				return '';
			}
			$previewOnly[$nodeId] = 1;
		}

		//  + VBV-3236 Add usergroup based permissions here for images
		$cangetattachments =  Api_InterfaceAbstract::instance()->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions2',
				'permission' => 'cangetimgattachment',
				'nodeid' => $nodeId,
			)
		);

		// Use += array() to prevent from it overwrites "allowimages" which is set in $bbCodeOptions parameter
		// - VBV-3236
		$bbCodeOptions += array('cangetimgattachment' => $cangetattachments > 0);

		$placeHolder = $this->getPlaceholder($nodeId, $bbCodeOptions, $contentPage);
		$this->pending[$placeHolder] = $nodeId;
		$cacheKey = $this->getCacheKey($nodeId, $bbCodeOptions, false, $canview);
		$this->placeHolders[$cacheKey] = $placeHolder;
		$this->cacheIdToNodeid[$cacheKey] = $nodeId;
		$this->contentPages[$placeHolder] = $contentPage;
		$this->bbCodeOptions[$placeHolder] = $bbCodeOptions;

		return $placeHolder;
	}


	/**
	 * Registers preview for node text, to be filled with the parsed text later.
	 *
	 *	@param	int		nodeid
	 * 	@param	mixed	optianal bbcode options
	 *
	 *	@return	string	the placeholder text
	 */
	public function registerPreview($nodeId, $bbCodeOptions = array())
	{
		$canview =  Api_InterfaceAbstract::instance()->callApi(
			'user',
			'hasPermissions',
			array(
				'group' => 'forumpermissions',
				'permission' => 'canviewthreads',
				'nodeid' => $nodeId,
			)
		);

		if (!$canview)
		{
			$node = Api_InterfaceAbstract::instance()->callApi('node', 'getNode',	array('nodeid' => $nodeId));
			if (empty($node['public_preview']))
			{
				return '';
			}
			$previewOnly[$nodeId] = 1;
		}

		//  + VBV-3236 Add usergroup based permissions here for images
		$cangetattachments =  Api_InterfaceAbstract::instance()->callApi(
			'user', 'hasPermissions',
			array(
				'group' => 'forumpermissions2',
				'permission' => 'cangetimgattachment',
				'nodeid' => $nodeId,
			)
		);
		// Use += array() to prevent from it overwrites "allowimages" which is set in $bbCodeOptions parameter
		// - VBV-3236
		$bbCodeOptions += array('cangetimgattachment' => $cangetattachments > 0);

		$placeHolder = $this->getPlaceholderPre($nodeId, $bbCodeOptions);

		$this->pending[$placeHolder] = $nodeId;
		$cacheKey = $this->getCacheKey($nodeId, $bbCodeOptions, true, $canview);
		$this->placeHolders[$cacheKey] = $placeHolder;
		$this->bbCodeOptions[$placeHolder] = $bbCodeOptions;
		$this->cacheIdToNodeid[$cacheKey] = $nodeId;

		return $placeHolder;
	}

	/**
	 * Resets the array of items pending
	 */
	public function resetPending()
	{
		$this->pending = array();
	}

	/**
	 * This is the main function, called by the page renderer. It replaces all the placeholders with the parsed content.
	 *
	 * @param  string The page content. This currently will have all the placeholders
	 *
	 * @return string Page content with all the placeholders replaced with the parsed text.
	 */
	public function replacePlaceholders(&$content)
	{
		$this->fetchNodeText();

		foreach($this->cache AS $placeHolder => $replace)
		{
			if (is_array($replace))
			{
				if (
					!empty($this->contentPages[$placeHolder]) AND
					intval($this->contentPages[$placeHolder])	AND
					intval($this->contentPages[$placeHolder]) AND
					(intval($this->contentPages[$placeHolder]) <= count($replace)))
				{
					$contentPage = intval($this->contentPages[$placeHolder]);
				}
				else
				{
					$contentPage = 1;
				}
				//Remember the array of page information starts at zero, not one.
				$content = str_replace($placeHolder, $replace[$contentPage - 1]['pageText'], $content);

			}
			else
			{
				$content = str_replace($placeHolder, $replace, $content);
			}
		}
	}

	protected function getPlaceholder($nodeId, $bbCodeOptions, $contentPage = 1)
	{
		if (empty($bbCodeOptions))
		{
			$result = self::PLACEHOLDER_PREFIX . $nodeId . '|' . $contentPage . self::PLACEHOLDER_SUFFIX;
		}
		else
		{
			ksort($bbCodeOptions);
			$result = self::PLACEHOLDER_PREFIX . $nodeId . '|' . $contentPage . ':'  . serialize($bbCodeOptions) . self::PLACEHOLDER_SUFFIX;
		}

		return $result;
	}

	protected function getPlaceholderPre($nodeId, $bbCodeOptions)
	{
		if (empty($bbCodeOptions))
		{
			return self::PLACEHOLDER_PREFIX . '_pre_' . $nodeId . self::PLACEHOLDER_SUFFIX;
		}
		ksort($bbCodeOptions);

		return self::PLACEHOLDER_PREFIX  . '_pre_'. $nodeId. ':'  . serialize($bbCodeOptions) . self::PLACEHOLDER_SUFFIX;
	}

	/**
	 * Returns the cache key to be used by vB_Cache
	 * @param type $nodeId
	 * @return string
	 */
	protected function getCacheKey($nodeId, $bbCodeOptions, $preview = false, $canview)
	{
		$styleId = vB5_Template_Stylevar::instance()->getPreferredStyleId();
		$languageId = vB5_User::getLanguageId();

		$cacheKey = "vbNodeText". ($preview ? "_pre_" : '') . "{$nodeId}_{$styleId}_{$languageId}";

		if (!$canview)
		{
			$cacheKey .= '_pvo)';
		}
		else if (!empty($bbCodeOptions))
		{
			ksort($bbCodeOptions);
			$cacheKey .= ':' . md5(json_encode($bbCodeOptions));
		}

		return strtolower($cacheKey);
	}

	protected function fetchNodeText()
	{
		if (!empty($this->placeHolders))
		{
			// first try with cache
			$api = Api_InterfaceAbstract::instance();
			$cache = $api->cacheInstance(0);
			$found = $cache->read(array_keys($this->placeHolders));

			if (!empty($found))
			{
				$foundValues = array();
				foreach($found AS $cacheKey => $parsedText)
				{

					if (($parsedText !== false) AND !empty($this->cacheIdToNodeid[$cacheKey]))
					{
						$nodeId = $this->cacheIdToNodeid[$cacheKey];
						$placeHolder = $this->placeHolders[$cacheKey];
						$this->cache[$placeHolder] = $parsedText;
						unset($this->placeHolders[$cacheKey]);
						unset($this->pending[$placeHolder]);
					}
				}
			}

			if (!empty($this->pending))
			{
				// we still have to parse some nodes, fetch data for them
				$textDataArray =  Api_InterfaceAbstract::instance()->callApi('content_text', 'getDataForParse', array($this->pending));

				// preload avatars
				$this->registerUseridsForAvatarPreloading($textDataArray);

				$templateCache = vB5_Template_Cache::instance();
				$phraseCache = vB5_Template_Phrase::instance();
				$urlCache = vB5_Template_Url::instance();

				// In BBCode parser, the templates of inner BBCode are registered first,
				// so they should be replaced after the outer BBCode templates. See VBV-4834.

				//Also- if we have a preview we're likely to need the full text, and vice versa. So if either is requested
				// let's parse both.
				$templateCache->setRenderTemplatesInReverseOrder(true);

				if (empty($this->previewLength))
				{
					$options =  Api_InterfaceAbstract::instance()->callApiStatic('options', 'fetchStatic', array('previewLength'));
					$this->previewLength = $options['previewLength'];
				}

				foreach($this->placeHolders AS $cacheKey => $placeHolder)
				{
					$nodeId = isset($this->pending[$placeHolder]) ? $this->pending[$placeHolder] : 0;

					if ($nodeId AND !empty($textDataArray[$nodeId]))
					{
						//If we got previewtext in textDataArray, we are done.
						if (isset($textDataArray[$nodeId]['preview_only']))
						{
							$previewText = $parsed = $textDataArray[$nodeId]['previewtext'];
							$canview = false;
						}
						else
						{
							$canview = true;
							list($previewText, $parsed) = $this->parseNode($textDataArray, $nodeId, $this->bbCodeOptions[$placeHolder]);

							// It's safe to do it here cause we already are in delayed rendering.
							$templateCache->replacePlaceholders($parsed);
							$phraseCache->replacePlaceholders($parsed);
							$urlCache->replacePlaceholders($parsed);

							// also need to replace phrase & url placeholders for preview text
							$phraseCache->replacePlaceholders($previewText);
							$urlCache->replacePlaceholders($previewText);
							$canview = true;
						}

						// writing to cache has been moved from parseNode() to here so that
						// the cached text has the placeholders replaced. (VBV-9507)
						// any changes to the node requires update
						$events = array('nodeChg_' . $nodeId);
						// need to update cache if channel changes options
						$events[] = 'nodeChg_' .  $textDataArray[$nodeId]['channelid'];
						// also need to update if phrases have been modified
						$events[] = 'vB_Language_languageCache';

						// write the parsed text values to cache. cache for a week.
						$cache->write($this->getCacheKey($nodeId, $this->bbCodeOptions[$placeHolder], false, $canview), $parsed, 10080, $events);
						$cache->write($this->getCacheKey($nodeId, $this->bbCodeOptions[$placeHolder], true, $canview), $previewText, 10080, $events);

						if ($parsed !== false)
						{
							if (stripos($placeHolder, '_pre_') === false)
							{
								$this->cache[$placeHolder] = $parsed;
							}
							else
							{
								$this->cache[$placeHolder] = $previewText;
							}
						}
					}
				}

				$templateCache->setRenderTemplatesInReverseOrder(false);
			}
		}
	}

	/**
	 * gets the key used for storing page information
	 *
	 *	@param	int		the nodeid
	 *	@return	string  the cache key string
	 */
	protected function getPagingCacheKey($nodeid)
	{
		return 'vB_ArtPaging_' . $nodeid . '_' . vB5_User::getLanguageId();
	}

	/**
	 * @param $textDataArray
	 * @param $nodeId
	 * @param $bbcodeOptions
	 * @return array
	 */
	protected function parseNode($textDataArray, $nodeId, $bbcodeOptions)
	{
		$textData = $textDataArray[$nodeId];
		$skipBbCodeParsing = $textData['disable_bbcode']; // if disable_bbcode is set (static pages), just use the rawtext

		$parser = new vB5_Template_BbCode();
		$parser->setRenderImmediate(true);
		$parser->setMultiPageRender($textData['channeltype'] == 'article');

		if (isset($textData['attachments']))
		{
			$parser->setAttachments($textData['attachments']);
		}
		if (isset($textData['attachments']) AND empty($textData['attachments']))
		{
			$parser->getAndSetAttachments($nodeId);
		}
		//make sure we have values for all the necessary options
		foreach (array('allowimages', 'allowimagebbcode', 'allowbbcode', 'allowsmilies') AS $option)
		{
			if (!empty($bbcodeOptions) AND isset($bbcodeOptions[$option]))
			{
				$textData['bbcodeoptions'][$option] = $bbcodeOptions[$option];
			}
			else if (!isset($textData['bbcodeoptions'][$option]))
			{
				$textData['bbcodeoptions'][$option] = false;
			}
		}


		/*
			bbcodeOptions['allowhtml'] comes from channel.options & 256 (bf_misc_forumoptions.allowhtml),
			except for public_preview > 0 articles that the user can't view... (see function vB_Api_Content_Text->getDataForParse() & queryef vBForum:getDataForParse)
			so we should actually be ignoring that, and using htmlstate only.
			Unfortunately, we can't just ignore it in the parser's doParse() function, because there is at least 1 other thing that seems to use allowhtml: announcements. I'm placing
			the change here instead of the parser in order to minimize risk.
			Alternatively, we could just make sure that every single channel is created with allowhtml set, but that'd also mean we're keeping this option, and adding
			an upgrade step to fix all old channels that may have been created with allowhtml unset.
		*/
		$textData['bbcodeoptions']['allowhtml'] = in_array($textData['htmlstate'], array('on', 'on_nl2br'));

		$allowimages = false;
		if (!empty($bbcodeOptions) AND !empty($bbcodeOptions['allowimages']))
		{
			$allowimages = $bbcodeOptions['allowimages'];
		}
		else if (!empty($bbcodeOptions['cangetimgattachment']))
		{
			$allowimages = $bbcodeOptions['cangetimgattachment'];
		}
		else if (!empty($textData['bbcodeoptions']['allowimages']))
		{
			$allowimages = $textData['bbcodeoptions']['allowimages'];
		}
		else if (!empty($textData['bbcodeoptions']['allowimagecode']))
		{
			$allowimages = $textData['bbcodeoptions']['allowimagecode'];
		}


		if ($textData['channeltype'] == 'article')
		{
			if (!$skipBbCodeParsing)
			{
				//If it's paginated we parse it here.
				$matches = array();
				$check = preg_match_all('#\[page\].*\[\/page\]#siU', $textData['rawtext'], $matches, PREG_OFFSET_CAPTURE);
				$start = 0;
				$title = $textData['title'];
				$parsed = array();

				// If [page] is at the beginning of the text, use it for the first page title
				// instead of using the article title for the first one.
				$hasFirstPageTitle = (bool) preg_match('#^\s*\[PAGE\]#siU', $textData['rawtext']);

				if (!empty($matches[0]))
				{
					foreach($matches[0] AS $match)
					{
						if ($hasFirstPageTitle)
						{
							$hasFirstPageTitle = false;
							$start = strlen($match[0]) + $match[1];
							$title = vB_String::stripBbcode($match[0]);
							continue;
						}

						$rawtext = substr($textData['rawtext'], $start, $match[1] - $start);
						$currentText = $parser->doParse(
							$rawtext,
							$textData['bbcodeoptions']['allowhtml'],
							$textData['bbcodeoptions']['allowsmilies'],
							$textData['bbcodeoptions']['allowbbcode'],
							$allowimages,
							true, // do_nl2br
							false, // cachable
							$textData['htmlstate'],
							false, // minimal
							$textData['rawtext']	// fulltext
						);
						$parsed[] = array('title' => $title, 'pageText' => $currentText);
						$start = strlen($match[0]) + $match[1];
						$title = vB_String::stripBbcode($match[0]);
					}

					if (!empty($start) AND ($start < strlen($textData['rawtext'])))
					{
						$rawtext = substr($textData['rawtext'], $start);
						$currentText = $parser->doParse(
							$rawtext,
							$textData['bbcodeoptions']['allowhtml'],
							$textData['bbcodeoptions']['allowsmilies'],
							$textData['bbcodeoptions']['allowbbcode'],
							$allowimages,
							true, // do_nl2br
							false, // cachable
							$textData['htmlstate'],
							false, // minimal
							$textData['rawtext']	// fulltext
						);
						$parsed[] = array('title' => $title, 'pageText' => $currentText);
					}
				}

				$paging = array();
				$pageNo = 1;
				$phrases = vB5_Template_Phrase::instance();
				foreach ($parsed as $page)
				{
					if (empty($page['title']))
					{
						$page['title'] = $phrases->getPhrase('page_x', $pageNo);
					}
					$paging[$pageNo] = $page['title'];
					$pageNo++;
				}
				Api_InterfaceAbstract::instance()->cacheInstance(0)->write($this->getPagingCacheKey($nodeId), $paging, 1440, 'nodeChg_' . $nodeId);

			}
			else
			{
				$parsed = $textData['rawtext'];
				$matches[0] = 1; // skip re-parsing below.
			}
		}

		if (empty($matches[0]))
		{
			// Get full text
			$parsed = $parser->doParse(
				$textData['rawtext'],
				// todo: Remove this. We should be using htmlstate, not an outdated forum option that we're planning to remove.
				$textData['bbcodeoptions']['allowhtml'],
				$textData['bbcodeoptions']['allowsmilies'],
				$textData['bbcodeoptions']['allowbbcode'],
				$allowimages,
				true, // do_nl2br
				false, // cachable
				$textData['htmlstate']
			);
		}

		// Get preview text
		if (empty($this->previewLength))
		{
			if (isset($textData['previewLength']))
			{
				$this->previewLength = $textData['previewLength'];
			}
			else
			{
				$options =  Api_InterfaceAbstract::instance()->callApiStatic('options', 'fetchStatic', array('previewLength'));
				$this->previewLength = $options['previewLength'];
			}
		}

		// if textData has previewLength set, we always want to use it (articles)
		if (isset($textData['previewLength']))
		{
			$previewLength = $textData['previewLength'];
		}
		else
		{
			$previewLength = $this->previewLength;
		}

		if ($skipBbCodeParsing)
		{
			// static pages from vb4 should always have text.previewtext set, taken from cms_nodeconfig.value where name = 'previewtext'
			// As such, we should always set the previewtext for static pages created in vB5.
			$previewText = $textData['previewtext'];
		}
		else
		{
			$previewText = $parser->get_preview(
				$textData['rawtext'],
				$previewLength,
				$textData['bbcodeoptions']['allowhtml'],
				true,
				$textData['htmlstate'],
				array('do_smilies' => $textData['bbcodeoptions']['allowsmilies'], 'allowPRBREAK' => (!empty($textData['disableBBCodes']['prbreak'])))
			);
		}

		if (is_array($parsed))
		{
			// for multi-paged articles, $parsed is an array, let's check the length
			// of the first page of that article for purposes of appending the ellipsis
			$parsedLength = strlen($parsed[0]['pageText']);
		}
		else
		{
			$parsedLength = strlen($parsed);
		}

		// Append ellipsis if preview text is shorter than parsed full text.
		// One special case to note is if previewText has 0 length. This could happen if the previewText is
		// entirely composed of bbcodes that are stripped via parsing
		// If we want special behavior, we should check for that case here and not append the ellipsis
		if ($parsedLength > strlen($previewText))
		{
			$previewText .= '...';
		}

		return array($previewText, $parsed);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103168 $
|| #######################################################################
\*=========================================================================*/
