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

class vB5_Route_PrivateMessage extends vB5_Route
{
	const CONTROLLER = 'page';
	const DEFAULT_PREFIX = 'privatemessage';
	const REGEXP = '(?P<action>[A-Za-z0-9_\-]+)(?P<params>(/[^\?]+)*)';

	protected $actionClass;
	protected $actionInternal;

	public function __construct($routeInfo, $matches, $queryString = '', $anchor)
	{
		// if no action is defined, use index
		if (!isset($matches['action']) || empty($matches['action']))
		{
			$matches['action'] = 'index';
		}

		// set action class
		$actionClassName = 'vB5_Route_PrivateMessage_' . ucfirst($matches['action']);

		if (!class_exists($actionClassName))
		{
			$actionClassName = 'vB5_Route_PrivateMessage_Index';
			$matches['action'] = 'index';
		}

		$this->actionClass = new $actionClassName($routeInfo, $matches, $queryString);

		// Add action to arguments (required for rebuilding the URL for this action)
		$routeInfo['arguments']['action'] = $matches['action'];
		$this->actionInternal= $matches['action'];
		parent::__construct($routeInfo, $matches, $queryString, $anchor);

		// add action parameters to route arguments
		$actionParameters = $this->actionClass->getParameters();
		$this->arguments = empty($this->arguments) ? $actionParameters : array_merge($this->arguments, $actionParameters);

		// This might need to be changed into switch statement with cases that can be applied for different locations in the message center
		if (!empty($this->arguments['messageid']))
		{
			$msgInfo = vB_Library::instance('node')->getNodeBare($actionParameters['messageid']);
			$senderUrl = vB5_Route::buildUrl('profile', $msgInfo);
			$this->setUserAction('viewing_private_message', $msgInfo['authorname'], $senderUrl);
		}
		else
		{
			$this->setUserAction('viewing_private_message');
		}

		// set breadcrumbs
		$this->breadcrumbs = $this->actionClass->getBreadcrumbs();

		// add querystring parameters for permalink (similar to vB5_Route_Conversation)
		if (!empty($matches['nodeid']) AND ($nodeId = intval($matches['nodeid']))
			AND !empty($matches['innerPost']) AND ($innerPost = intval($matches['innerPost'])))
		{
			if ($innerPost != $nodeId)
			{
				// it's not the starter, either a reply or a comment
				$this->queryParameters['p'] = intval($matches['innerPost']);

				if (isset($matches['innerPostParent']) AND ($innerPostParent = intval($matches['innerPostParent']))
						AND $nodeId != $innerPostParent)
				{
					// it's a comment
					$this->queryParameters['pp'] = $innerPostParent;
				}
			}
		}
	}

	protected static function validInput(array &$data)
	{
		if (!isset($data['prefix']) OR !is_string($data['prefix']))
		{
			return false;
		}

		$data['prefix'] = $data['prefix'];
		$data['regex'] = $data['prefix'] . '/' . self::REGEXP;
		$data['class'] = __CLASS__;
		$data['controller']	= self::CONTROLLER;

		return parent::validInput($data);
	}

	protected static function updateContentRoute($oldRouteInfo, $newRouteInfo)
	{
		$db = vB::getDbAssertor();
		$events = array();

		$updateIds = self::updateRedirects($db, $oldRouteInfo['routeid'], $newRouteInfo['routeid']);
		foreach($updateIds AS $routeid)
		{
			$events[] = "routeChg_$routeid";
		}

		vB_Cache::allCacheEvent($events);
	}

	public function getAction()
	{
		return 'index';
	}

	public function getUrl()
	{
		$url = "/{$this->prefix}/" . $this->actionInternal . $this->actionClass->getUrlParameters();

		if (strtolower(vB_String::getCharset()) != 'utf-8')
		{
			$url = vB_String::encodeUtf8Url($url);
		}

		return $url;
	}

	/**
	 * Build URLs using a single instance for the class. It does not check permissions
	 * @param string $className
	 * @param array $URLInfoList
	 *				- route
	 *				- data
	 *				- extra
	 *				- anchor
	 *				- options
	 * @return array
	 */
	protected static function bulkFetchUrls($className, $URLInfoList)
	{
		$results = array();

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);

		foreach($URLInfoList AS $hash => $info)
		{
			try
			{
				// we need different instances, since we need to instantiate different action classes
				$route = new $className($info['routeInfo'], $info['data'], http_build_query($info['extra']), $info['anchor']);

				$options = explode('|', $info['route']);
				$routeId = $options[0];

				$fullURL = $route->getFullUrl($options);
				$cache->write($info['innerHash'], $fullURL, 1440, array('routeChg_' . $routeId));
			}
			catch (Exception $e)
			{
				$fullURL = '';
			}

			$results[$hash] = $fullURL;
		}

		return $results;
	}

	public function getCanonicalRoute()
	{
		return $this;
	}

	/**
	 * Returns breadcrumbs to be displayed in page header
	 * @return array
	 */
	public function getBreadcrumbs()
	{
		return $this->breadcrumbs;
	}


	public static function exportArguments($arguments)
	{
		$data = unserialize($arguments);

		$page = vB::getDbAssertor()->getRow('page', array('pageid' => $data['pageid']));
		if (empty($page))
		{
			throw new Exception('Couldn\'t find page');
		}
		$data['pageGuid'] = $page['guid'];
		unset($data['pageid']);

		return serialize($data);
	}

	public static function importArguments($arguments)
	{
		$data = unserialize($arguments);

		$page = vB::getDbAssertor()->getRow('page', array('guid' => $data['pageGuid']));
		if (empty($page))
		{
			throw new Exception('Couldn\'t find page');
		}
		$data['pageid'] = $page['pageid'];
		unset($data['pageGuid']);

		return serialize($data);
	}

	public static function importContentId($arguments)
	{
		return $arguments['pageid'];
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103597 $
|| #######################################################################
\*=========================================================================*/
