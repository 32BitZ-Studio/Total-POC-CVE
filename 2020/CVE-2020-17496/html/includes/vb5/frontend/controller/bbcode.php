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

class vB5_Frontend_Controller_Bbcode extends vB5_Frontend_Controller
{
	protected static $needDebug = false;

	/**
	 * Parses bbode in arbitrary text.
	 *
	 * @param  string Test to parse
	 * @param  array  Options
	 * @param  array  Attachments
	 * @param  array  An array of cache info to generate a cache key
	 *
	 * @return string The parsed text
	 */
	public static function parse($text, $options = array(), $attachments = array(), $cacheInfo = array())
	{
		//if we have a nodeid, let's try to cache this.
		if (!empty($cacheInfo))
		{
			//TODO- Find a caching method that doesn't break collapsed mode.
			if (!empty($cacheInfo['nodeid']))
			{
				$cacheKey = 'vbNodeText' . $cacheInfo['nodeid'];
			}
			else if (!empty($cacheInfo['signatureid']))
			{
				$cacheKey = 'vbSig' . $cacheInfo['signatureid'];
			}
			if (!empty($cacheKey))
			{
				$cacheKey .= strval($options);
				$parsed = vB_Cache::instance()->read($cacheKey);

				if ($parsed)
				{
					return $parsed;
				}
			}
		}

		$result = self::parseInternal(new vB5_Template_BbCode(), $text, $options, $attachments);

		if (!empty($cacheKey))
		{
			if (!empty($cacheInfo['nodeid']))
			{
				$cacheEvent = 'nodeChg_' . $cacheInfo['nodeid'];
			}
			else if (!empty($cacheInfo['signatureid']))
			{
				$cacheEvent = 'userChg_' . $cacheInfo['signatureid'];
			}
			vB_Cache::instance()->write($cacheKey, $result, 86400, $cacheEvent);
		}

		return $result;
	}

	public static function parseWysiwyg($text, $options = array(), $attachments = array())
	{
		//if this isn't an array it's not going to go well so let's
		//just use the defaults in this case.
		if (!is_array($options))
		{
			$options = array();
		}

		return self::parseInternal(new vB5_Template_BbCode_Wysiwyg(), $text, $options, $attachments);
	}

	public static function verifyImgCheck($text, $options = array())
	{
		//we don't want to count simlies against the limit, so don't parse them here
		//even if we will later parse them as part of the post
		$options['allowsmilies'] = false;
		$parsed = self::parseWysiwygForImages($text, $options);
		$vboptions = vB5_Template_Options::instance()->getOptions();
		if ($vboptions['options']['maximages'])
		{
			$imagecount = substr_count(strtolower($parsed), '<img');
			if ($imagecount > $vboptions['options']['maximages'])
			{
				return array('toomanyimages', $imagecount, $vboptions['options']['maximages']);
			}
		}
		return true;
	}

	private static function parseWysiwygForImages($text, $options = array())
	{
		$api = Api_InterfaceAbstract::instance();
		$text = $api->callApi('bbcode', 'convertWysiwygTextToBbcode', array($text, array('autoparselinks' => false)));
		$parser = new vB5_Template_BbCode_Imgcheck();

		if (!isset($options['allowhtml']))
		{
			$options['allowhtml'] = false;
		}
		if (!isset($options['allowsmilies']))
		{
			$options['allowsmilies'] = true;
		}
		if (!isset($options['allowbbcode']))
		{
			$options['allowbbcode'] = true;
		}
		if (!isset($options['allowimagebbcode']))
		{
			$options['allowimagebbcode'] = true;
		}

		return $parser->doParse($text, $options['allowhtml'], $options['allowsmilies'], $options['allowbbcode'], $options['allowimagebbcode']);
	}

	public static function parseWysiwygForPreview($text, $options = array(), $attachments = array())
	{
		$api = Api_InterfaceAbstract::instance();
		$text = $api->callApi('bbcode', 'parseWysiwygHtmlToBbcode', array($text));
		$parser = new vB5_Template_BbCode();

		if (!isset($options['allowhtml']))
		{
			$options['allowhtml'] = false;
		}
		if (!isset($options['allowsmilies']))
		{
			$options['allowsmilies'] = true;
		}
		if (!isset($options['allowbbcode']))
		{
			$options['allowbbcode'] = true;
		}
		if (!isset($options['allowimagebbcode']))
		{
			$options['allowimagebbcode'] = true;
		}
		if (isset($options['userid']))
		{
			$parser->setParseUserinfo($options['userid']);
		}

		$parser->setAttachments($attachments);

		$templateCache = vB5_Template_Cache::instance();
		$phraseCache = vB5_Template_Phrase::instance();

		// In BBCode parser, the templates of inner BBCode are registered first,
		// so they should be replaced after the outer BBCode templates. See VBV-4834.
		$templateCache->setRenderTemplatesInReverseOrder(true);

		// Parse the bbcode
		$result = $parser->doParse($text, $options['allowhtml'], $options['allowsmilies'], $options['allowbbcode'], $options['allowimagebbcode'], true, false, $options['htmlstate']);

		$templateCache->replacePlaceholders($result);
		$phraseCache->replacePlaceholders($result);
		$templateCache->setRenderTemplatesInReverseOrder(false);

		return $result;
	}

	private static function parseInternal(vB5_Template_BbCode $parser, $text, $options = array(), $attachments = array())
	{
		if (!isset($options['allowhtml']))
		{
			$options['allowhtml'] = false;
		}

		if (!isset($options['allowsmilies']))
		{
			$options['allowsmilies'] = true;
		}

		if (!isset($options['allowbbcode']))
		{
			$options['allowbbcode'] = true;
		}

		if (!isset($options['allowimagebbcode']))
		{
			$options['allowimagebbcode'] = true;
		}

		if (isset($options['userid']))
		{
			$parser->setParseUserinfo($options['userid']);
		}

		$parser->setAttachments($attachments);

		/*
		 * If we have new attachments, we need to know whether it's an image or not so we can choose the correct
		 * tag (img or a). We need to grab & check the file extension for that, which is saved in the filedata table.
		 * Let's prefetch all of them so we don't have to hit the DB one at a time.
		 */
		preg_match_all('#\[attach(?:=(right|left|config))?\]temp_(\d+)_(\d+)_(\d+)\[/attach\]#i', $text, $matches);
		if (!empty($matches[2]))
		{
			$filedataids = array();
			foreach($matches[2] AS $filedataid)
			{
				$filedataids[$filedataid] = $filedataid;
			}
			$parser->prefetchFiledata($filedataids);
		}

		// Parse the bbcode
		$result = $parser->doParse($text, $options['allowhtml'], $options['allowsmilies'], $options['allowbbcode'], $options['allowimagebbcode']);

		return $result;
	}

	public function actionResolveIp($ip)
	{
		return @gethostbyaddr($ip);
	}

	/**
	 * Parse the text table's rawtext field. At this point we just register. We do the parse and replace later in a block
	 *
	 * @param	int		the nodeid
	 * @param	mixed	array of bbcode options
	 *
	 * @return	string
	 */
	public function parseNodeText($nodeid, $bbCodeOptions = array(), $contentPage = 1)
	{
		if (!is_array($bbCodeOptions))
		{
			$bbCodeOptions = array();
		}

		if (empty($nodeid) OR !is_numeric($nodeid))
		{
			return '';
		}

		if (empty($contentPage) OR !is_numeric($contentPage))
		{
			$contentPage = 1;
		}

		return vB5_Template_NodeText::instance()->register($nodeid, $bbCodeOptions, $contentPage);
	}

	/**
	 *	Create a placeholder for a notice phrase
	 */
	public function parseNotice($noticephrase, $options)
	{
		if(is_string($noticephrase))
		{
			$noticephrase = array($noticephrase);
		}

		$result = vB5_Template_Phrase::instance()->register($noticephrase, $options);
		return $result;
	}

	/**
	 * Parse the text table's rawtext field. At this point we just register. We do the parse and replace later in a block
	 *
	 * @param	int $nodeid
	 * @param	array $bbCodeOptions -- array of bbcode options
	 *
	 * @return	string
	 */
	public function parseNodePreview($nodeid, $bbCodeOptions = array())
	{
		if (empty($nodeid))
		{
			return '';
		}

		return  vB5_Template_NodeText::instance()->registerPreview($nodeid, $bbCodeOptions);
	}

	/**
	 * Gets a single page title.
	 *
	 *	@param int $nodeid
	 *	@param int $contentPageId -- the content page. Defaults to one
	 */
	public function fetchPageTitle($nodeid, $contentPageId = 1)
	{
		return vB5_Template_NodeText::instance()->fetchPageTitle($nodeid, $contentPageId);
	}

	/**
	 * Gets a single page title.
	 */
	public function fetchArticlePaging($nodeid)
	{
		return vB5_Template_NodeText::instance()->fetchArticlePaging($nodeid);
	}

	/**
	 * Returns a placeholder for the debug information.
	 *
	 * @return string
	 */
	public static function debugInfo()
	{
		self::$needDebug = true;
		return '<!-DebugInfo-->';
	}

	/**
	 * Returns the flag saying whether we should add debug information
	 *
	 *	@return bool
	 */
	public static function needDebug()
	{
		return self::$needDebug;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103168 $
|| #######################################################################
\*=========================================================================*/
