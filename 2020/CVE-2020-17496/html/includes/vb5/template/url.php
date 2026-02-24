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

class vB5_Template_Url
{
	const PLACEHOLDER_PREFIX = '!!VB:URL';
	const PLACEHOLDER_SUFIX = '!!';

	/**
	 * Singleton instance of this class.
	 *
	 * @var	vB5_Template_Url
	 */
	protected static $instance;

	/**
	 * Array of URL definitions:
	 * [route] - Route identifier (routeid or name)
	 * [$data] - Data for building route
	 * [extra] - Additional data to be added
	 * [options] - Options for building URL
	 *	- noBaseUrl: skips adding the baseurl
	 *
	 * @var	array
	 */
	protected $delayedUrlInfo = array();

	/**
	 * Array of the keys used by $delayedUrlInfo above
	 *
	 * @var	array
	 */
	protected $delayedUrlKeys = array();


	/**
	 * Keeps track of which hashKeys in $delayedUrlInfo still need to be built.
	 * Once a URL is built, its hashkey is moved from this array to $builtUrlList
	 * as <haskkey> => <built URL>
	 * The keys in $needBuilding hold the replacement hashkeys for URLs.
	 * The values in $needBuilding are meaningless, and are just boolean true
	 *
	 * @var array
	 */
	protected $needBuilding = array();

	/**
	 * Array of already built URLs.
	 * Each element is a key:value pair of {String Hashkey}:{String Built URL}
	 *
	 * @var array
	 */
	protected $builtUrlList = array();

	/**
	 * Array of the keys used by $builtUrlList above
	 * Each element is a key:value pair of {String Hashkey}:{String Hashkey}, which are
	 * the *keys* for $builtUrlList.
	 *
	 * @var array
	 */
	protected $builtUrlKeys = array();

	/**
	 * Flag, whether finalBuildUrls() called route API's preloadRoutes() or not
	 *
	 * @var bool
	 */
	protected $loadedUrlKeys = false;

	/**
	 * Singleton instance getter
	 *
	 * @return vB5_Template_Url
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
	 * Returns the full URL placeholder based on the passed hash
	 *
	 * @param	string	The hash
	 *
	 * @return	string	The full placeholder
	 */
	protected function getPlaceholder($hash)
	{
		return self::PLACEHOLDER_PREFIX . $hash . self::PLACEHOLDER_SUFIX;
	}

	/**
	 * Registers the information needed (route, data, etc) to create a URL and returns a placeholder
	 * so that template rendering can continue. The placeholders will be replaced in one go at the
	 * end of the rendering process.
	 *
	 * @param	int|string	The textual name of a route, along with optional modifiers. If
	 *				modifiers are added they are separated with a pipe (|). OR the
	 *				integer routeid of a route.
	 * @param	array	Data needed to generate the URL. Normally the node array is passed. Fields
	 *			potentially used are:
	 *				'title', 'startertitle', 'channeltitle', 'urlident','starterurlident',
	 *				'channelurlident', 'page', 'channelroute','starterroute' ,
	 *				'contenttypeid', 'starter', 'channelid', 'nodeid', 'routeid', 'userid',
	 *				'authorname', 'contentpagenum'
	 * @param	array	Array of key:value pairs to be added to the URL as query parameters.
	 * @param	array	Array of options to modify the generated URL. Currently supports:
	 *				(this list may not be complete)
	 *				'anchor' => The anchor name for the #anchor hash at the end of the URL.
	 *
	 * @return	string	A string placeholder which is temporarily inserted in the rendered template.
	 */
	public function register($route, $data = array(), $extra = array(), $options = array())
	{
		if (empty($data))
		{
			$data = array();
		}
		else if (!is_array($data))
		{
			throw new vB5_Exception_Api('route', 'getUrl', $data, 'Invalid data for URL creation');
		}

		if (empty($extra))
		{
			$extra = array();
		}
		else if (!is_array($extra))
		{
			throw new vB5_Exception_Api('route', 'getUrl', $extra, 'Invalid extra data for URL creation');
		}
		//Most of the time we have a node record. Let's keep just what we need;
		if (!empty($data['nodeid']) AND isset($data['contenttypeid']))
		{
			//Let's unset the values we don't need
			foreach ($data AS $key => $field)
			{
				if (!in_array($key, array('title', 'startertitle', 'channeltitle', 'urlident','starterurlident', 'channelurlident',
					'page', 'channelroute','starterroute' , 'contenttypeid', 'starter', 'channelid', 'nodeid', 'routeid', 'userid', 'authorname',
					'contentpagenum')))
				{
					unset($data[$key]);
				}
			}
		}

		$hash = md5($route . serialize($data). serialize($extra) . serialize($options));

		//We often call for the same url more than once on the page. Don't do this more than once.
		$replaceStr = $this->getPlaceholder($hash);
		if (empty($this->delayedUrlInfo[$replaceStr]))
		{
			$this->needBuilding[$replaceStr] = true;
			$this->delayedUrlInfo[$replaceStr] = array('route' => $route, 'data' => $data, 'extra' => $extra, 'options' => $options);
			$this->delayedUrlKeys[$replaceStr] = $replaceStr;
		}
		elseif (!empty($data) AND empty($this->delayedUrlInfo[$replaceStr]['data']))
		{
			$this->delayedUrlInfo[$replaceStr]['data'] = $data;
		}

		return $replaceStr;
	}

	/**
	 * Returns the URLs for the routes with the passed parameters
	 *
	 * @param String[] 	$delayedUrlKeys 	HashKeys that exist in the URL definitions list class var $this->delayedUrlInfo
	 *
	 * @return String[]
	 *		hashKey => replacement URL
	 */
	public function finalBuildUrls($delayedUrlKeys)
	{
		// the only reason for this method to be public is that it is required in vB5_Frontend_Controller_Page::index
		// todo: check if we can avoid this

		/*
		 *	TODO: CLEAN THIS CLASS UP SO WE ONLY CALL finalBuildUrls() WHEN IT'S ABSOLUTELY NEEDED.
		 *		I've done a patch job here with adding $this->needBuilding() to minimize calls to this function
		 *		& the redudant work done by this function, but I can't help but feel that there's a cleaner way
		 *		to do this. Also, the above note about this function being required to be public might cause
		 *		problems in cleaning this up, so we should tackle it at the same time.
		 */

		if (!$this->loadedUrlKeys)
		{
			$urlIds = array();
			foreach($this->delayedUrlInfo as $urlInfo)
			{
				$options = explode('|', $urlInfo['route']);
				$urlIds[] = $options[0];
			}
			$check = Api_InterfaceAbstract::instance()->callApi('route', 'preloadRoutes', array('routeid' => array_unique($urlIds)));
			$this->loadedUrlKeys = true;
		}

		$addBaseURLs = array();
		$missing_replacements = array();

		$baseUrl =  vB5_Template_Options::instance()->get('options.frontendurl');
		foreach ($delayedUrlKeys AS $hashKey)
		{
			// I honestly have NO idea when this happens, but I'm reluctant to change old error handling code.
			// This might not be the best way to go about this, since *if* this happens, we will be constantly
			// expanding the replacements list when every node parse calls vb5_template_url->replacePlaceholders()
			// At the moment I'm assuming that this actually does NOT happen, while being too afraid to chop it out.
			if (!isset($this->delayedUrlInfo[$hashKey]))
			{
				$missing_replacements[$hashKey] = '#';
				$addBaseURLs[] = $hashKey;
				continue; // if it's missing the required information, do not bother trying to build the URL
			}

			if (!isset($this->needBuilding[$hashKey]))
			{
				continue; // already built in a previous call, unless something failed
			}

			/*
			 * I posit that if we have a hash/replacement string that we've already built a URL for, we can continue
			 * to use that already-built-URL for the rest of the session.
			 *
			 * If above is true, we should keep track of all the ones we've built & short-circuit those out as much as possible.
			 *
			 * If we have the replacment URLs, save it in memory ($this->builtUrlList @ end of this function) and do not send
			 * anything to vB5_Route::buildUrls(). Something's seriously wrong with this & the route class's buildURL caching,
			 * and I think we're instancing route classes way more than we need to.
			 */
			unset($this->needBuilding[$hashKey]);

			$info[$hashKey]['route'] = $this->delayedUrlInfo[$hashKey]['route'];
			$info[$hashKey]['data'] = $this->delayedUrlInfo[$hashKey]['data'];
			$info[$hashKey]['extra'] = $this->delayedUrlInfo[$hashKey]['extra'];
			$info[$hashKey]['options'] = $this->delayedUrlInfo[$hashKey]['options'];

			if (empty($info[$hashKey]['options']['noBaseUrl']))
			{
				/*	Note, if the option includes fullurl or bburl, the route class will already
				 *	prepend the frontend url. The fact that we're also prepending the frontendurl
				 *	here without checking for that option seems a bit fragile & magical (as in,
				 *	the caller has to remember to add 'noBaseUrl' if they added 'bburl') to me.
				 *	@TODO: investigate above & clean this up.
				 */
				$addBaseURLs[] = $hashKey;
			}

		}

		if (!empty($info))
		{
			$replacements = Api_InterfaceAbstract::instance()->callApi('route', 'getUrls', array('info' => $info));
			if (isset($replacements['errors']))
			{
				// VBV-9940 suggests that sometimes the API might return errors, and in that case, we should just not do the replacement.
				// In order to ensure that the replacements array will only contain strings, not other arrays, we just ditch the errors array if we get one.
				$replacements = array();
			}
			if (!empty($missing_replacements))
			{
				$replacements += $missing_replacements;
			}
		}
		else
		{
			$replacements = $missing_replacements;
		}

		//we need to append the base url because the routes incorrect return relative urls that
		//start with '/'.  Some of the routes have been fixed, but others haven't.  We'll
		//handle both for the time being.
		foreach ($addBaseURLs as $hashKey)
		{
			if ($replacements[$hashKey] AND $replacements[$hashKey][0] == '/')
			{
				$replacements[$hashKey] = $baseUrl . $replacements[$hashKey];
			}
			else
			{
				$replacements[$hashKey] = $baseUrl . '/' . $replacements[$hashKey];
			}
		}

		if (!empty($replacements))
		{
			$this->builtUrlList += $replacements;
			// There might be a more efficient way to do this (e.g have the route class build up the keys
			// separately & return it or loop through $replacements and add each element to builtUrlList
			// one at a time while also adding its key to builtUrlKeys), but any more could obfuscate the
			// code too much to be worth the gain and this is an improvement from calling
			// array_keys($replacements) @ every call to replacePlaceholders() considering the assumption
			// that $this->needBuilding will be empty or sparse most of the time on subsequent calls, meaning
			// we deal with this once with a large array. If the assumption breaks, that's probably a
			// serious bug in the calling code since this is meant to be called delayed *after* all URLs have been registered.
			foreach ($replacements AS $k => $v)
			{
				// builtUrlKeys consists of key=>key pairs
				$this->builtUrlKeys[$k] = $k;
			}
		}

		return $this->builtUrlList;
	}

	/**
	 * Replaces the placeholders with the actual URL in the passed content.
	 * Builds any URLs that have not been built yet.
	 *
	 * @param	string	The content containing the placeholders (Passed by reference)
	 *
	 * @return	null
	 */
	public function replacePlaceholders(&$content)
	{
		if (!empty($this->delayedUrlKeys) AND !empty($this->needBuilding))
		{
			$this->finalBuildUrls($this->delayedUrlKeys);
		}

		if (!empty($this->builtUrlList))
		{
			$content = str_replace($this->builtUrlKeys, $this->builtUrlList, $content);
		}

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
