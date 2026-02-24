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

class vB5_Route
{
	use vB_Trait_NoSerialize;

	const DEFAULT_CLASS = 'vB5_Route';
	const PREFIX_MAXSIZE = 200;
	const REGEX_MAXSIZE = 400;

	protected $routeId;
	protected $routeGuid;

	/**
	 * Current route Id for current for request
	 */
	protected $redirect301;
	/**
	 * Prefix for the route. Always encoded in UTF-8.
	 * @var string
	 */
	protected $prefix;

	//this is the actual prefix stored in the DB, even if the route is the homeroute.
	protected $rawprefix;

	/**
	 * Regular expression to be matched by URL. Always encoded in UTF-8.
	 * @var string
	 */
	protected $regex;

	/**
	 * This is the actual regex stored in the DB, even if the route is the homeroute.
	 * @var string
	 */
	protected $rawregex;

	protected $ishomeroute;

	/**
	 * (Optional) Stores controller to be called
	 * @var string
	 */
	protected $controller;
	/**
	 * (Optional) Stores action to be invoked in controller
	 * @var string
	 */
	protected $action;
	/**
	 * (Optional) Stores template id to be loaded
	 *
	 * @var string
	 */
	protected $template;
	/**
	 * Contains parameters stored in db and extracted from URL
	 * @var array
	 */
	protected $arguments;
	/**
	 * Contains the matches passed to the class
	 * @var array
	 */
	protected $matches;
	/**
	 * Contains query string parameters
	 * @var array
	 */
	protected $queryParameters;
	/**
	 * Contains anchor id
	 * @var string
	 */
	protected $anchor;

	/**
	 * Contains the page key for preloading cache
	 * @var string
	 */
	protected $pageKey = FALSE;

	/**
	 * Stores user action associated to the route.
	 * The route class cannot register this action because
	 * we don't know whether we are parsing a URL or just displaying a link.
	 * @var mixed
	 */
	protected $userAction = FALSE;

	/**
	 * @var vB5_Route
	 */
	protected $canonicalRoute;

	/**
	 * Contains the breadcrumbs for header
	 * @var array
	 */
	protected $breadcrumbs;

	/**
	 * Contains the links for header
	 * @var array
	 */
	protected $headlinks;

	protected static $routeidentcache = array();

	protected function __construct($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		$this->initRoute($routeInfo, $matches, $queryString, $anchor);
	}

	protected function initRoute($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		$this->matches = $matches;
		$this->routeId = $routeInfo['routeid'];
		$this->routeGuid = isset($routeInfo['guid']) ? $routeInfo['guid'] : '';
		$this->arguments = $this->queryParameters = array();
		$this->redirect301 = isset($routeInfo['redirect301']) ? $routeInfo['redirect301'] : false;
		$this->prefix = $routeInfo['prefix'];
		$this->rawprefix = $routeInfo['prefix'];
		$this->regex = $routeInfo['regex'];
		$this->rawregex = $routeInfo['regex'];
		$this->ishomeroute = isset($routeInfo['ishomeroute']) ? $routeInfo['ishomeroute'] : null;

		if ($this->ishomeroute)
		{
			$this->regex = self::removePrefixFromRe($this->regex, $this->prefix, get_class($this));
			$this->prefix = '';
		}

		// set field defaults
		$this->controller = "";
		if (isset($routeInfo['controller']))
		{
			$this->controller = $routeInfo['controller'];
		}

		$this->action = "";
		if (isset($routeInfo['action']))
		{
			$this->action = $routeInfo['action'];
		}

		$this->template = "";
		if (isset($routeInfo['template']))
		{
			$this->template = $routeInfo['template'];
		}

		if (isset($routeInfo['contentid']))
		{
			$contentid = (int) $routeInfo['contentid'];
			if ($contentid > 0)
			{
				$this->arguments['contentid'] = $contentid;
			}
		}

		// replace with matches
		foreach ($matches AS $name => $matched)
		{
			//One of the unit tests depends on the fact that the "matches" won't overwrite route arguments
			//unless they are of the form "$name".  It's possible that other code also depends on this
			//so we put in a check for it.  Anything starting with $ is intended to be replaced.
			if (
				is_scalar($matched) AND
				isset($routeInfo['arguments'][$name][0]) AND
				is_string($routeInfo['arguments'][$name]) AND
				$routeInfo['arguments'][$name][0] == '$')
			{
				$this->arguments[$name] = $matched;
			}
		}

		if (isset($routeInfo['arguments']) AND is_array($routeInfo['arguments']))
		{
			foreach ($routeInfo['arguments'] as $key => $value)
			{
				if (!isset($this->arguments[$key]))
				{
					$this->arguments[$key] = $value;
				}
			}
		}

		if (!empty($queryString))
		{
			// add query string parameters
			parse_str($queryString, $queryStringParameters);
			foreach ($queryStringParameters AS $key => $value)
			{
				$this->queryParameters[$key] = $value;
			}
		}

		if (!empty($matches['innerPost']))
		{
			$this->anchor = 'post' . intval($matches['innerPost']);
		}
		elseif (!empty($anchor) AND is_string($anchor))
		{
			$this->anchor = $anchor;
		}
		else
		{
			$this->anchor = '';
		}
	}

	public function getRouteId()
	{
		return $this->routeId;
	}

	public function getRouteGuid()
	{
		return $this->routeGuid;
	}

	public function getRedirect301()
	{
		return $this->redirect301;
	}

	public function getPrefix()
	{
		return $this->prefix;
	}

	public function getRawPrefix()
	{
		return $this->rawprefix;
	}

	public function getIsHomeRoute()
	{
		return $this->ishomeroute;
	}

	public function getController()
	{
		return $this->controller;
	}

	public function getAction()
	{
		return $this->action;
	}

	public function getTemplate()
	{
		return $this->template;
	}

	public function getArguments()
	{
		return $this->arguments;
	}

	public function getQueryParameters()
	{
		return $this->queryParameters;
	}

	public function getAnchor()
	{
		return $this->anchor;
	}

	protected function setPageKey()
	{
		$parameters = func_get_args();
		if (empty($parameters))
		{
			$this->pageKey = FALSE;
		}
		else
		{
			$baseClass = get_class() . '_';
			$this->pageKey = strtolower(str_replace($baseClass, '', get_class($this))) . $this->routeId;

			foreach($parameters as $param)
			{
				$this->pageKey .= isset($this->arguments[$param]) ? ('.' . $this->arguments[$param]) : '';
			}
		}
	}

	public function getPageKey()
	{
		return $this->pageKey;
	}

	protected function setUserAction()
	{
		$parameters = func_get_args();
		if (empty($parameters))
		{
			$this->userAction = false;
		}
		else
		{
			$this->userAction = array();
			foreach ($parameters AS $param)
			{
				$this->userAction[] = strval($param);
			}
		}
	}

	/**
	 * Returns the user action associated with the route
	 * @return mixed
	 */
	public function getUserAction()
	{
		return $this->userAction;
	}

	 /**
	 * Sets the breadcrumbs for the route
	 */
	protected function setBreadcrumbs()
	{
		$this->breadcrumbs = array();
		if (isset($this->arguments['channelid']) && $this->arguments['channelid'])
		{
			$this->addParentNodeBreadcrumbs($this->arguments['channelid']);
		}
	}

	/**
	 * Adds breadcrumb entries for all the parents of the passed node id.
	 * This is inclusive of the passed node id, but excludes "home".
	 * Modifies $this->breadcrumbs
	 *
	 * @param	int	Node ID
	 * @param	bool	If true, only add the top-most parent after home, and ignore the rest.
	 */
	protected function addParentNodeBreadcrumbs($nodeId, $onlyAddTopParent = false)
	{
		try
		{
			// obtain crumbs
			$nodeLibrary = vB_Library::instance('node');
			$nodeParents = $nodeLibrary->getNodeParents($nodeId);
			$nodeParentsReversed = array_reverse($nodeParents);
			$parentsInfo = $nodeLibrary->getNodes($nodeParentsReversed);
			$routeIds = array();
			foreach ($nodeParentsReversed AS $parentId)
			{
				if ($parentId != 1)
				{
					$routeIds[] = $parentsInfo[$parentId]['routeid'];

					if ($onlyAddTopParent)
					{
						break;
					}
				}
			}
			vB5_Route::preloadRoutes($routeIds);
			foreach ($nodeParentsReversed AS $parentId)
			{
				if ($parentId != 1)
				{
					$this->breadcrumbs[] = array(
						'title' => $parentsInfo[$parentId]['title'],
						'url' => vB5_Route::buildUrl($parentsInfo[$parentId]['routeid'])
					);

					if ($onlyAddTopParent)
					{
						break;
					}
				}
			}
		}
		catch (vB_Exception $e)
		{
			// if we don't have permissions to view the channel, then skip this
		}
	}

	/**
	 *	Checks to see if a user can access the page represented by this route. Will
	 *	throw a vB_Exception_NodePermission if the user is not allowed to view the
	 *	page.  Does nothing otherwise.  This is intended to get the permission
	 *	checks out of the route constructors so that we don't get random
	 *	exceptions while trying to create urls.
	 *
	 */
	protected function checkRoutePermissions()
	{
		return;
	}

	/**
	 * Returns breadcrumbs to be displayed in page header
	 * @return array
	 */
	public function getBreadcrumbs()
	{
		$this->setBreadcrumbs();
		return $this->breadcrumbs;
	}

	/**
	 * Get the url of this route. To be overriden by child classes.
	 * This should always return the path encoded in UTF-8. If vB_String::getCharset() is not utf-8,
	 * the url should be percent encoded using vB_String::encodeUtf8Url().
	 *
	 * @return	mixed	false|string
	 */
	public function getUrl()
	{
		return false;	// why do some implementations of getUrl() return false instead of empty string?
	}

	/*
	 * Returns the url of this route. May include the frontendurl depending on specified $options. All information
	 * required for building the URL must be set during this route's construction (TODO: this seems overkill & seems too expensive, fix routes to
	 * not require an instance for every URL). Also, why is this called "fullurl
	 *
	 * @param  array|string A list of options (or a string of options delimited by the | character). Can include
	 *                      'fullurl' or 'bburl' to prepend frontendurl to the URL to make it absolute.
	 *                      'urlencode' URL encodes the result.
	 *
	 * @return string       The constructed URL. It will include the frontendurl if 'bburl' or 'fullurl' was included in $options.
	 *                      Appended by query parameters & anchor if the data was set during route's construction.
	 */
	public function getFullUrl($options = "")
	{
		if (!is_array($options))
		{
			$options = explode('|', $options);
		}

		$params = $this->queryParameters;

		if (in_array('nohomeurl', $options) AND $this->ishomeroute)
		{
			// even though this is the home route, we want to be able to output
			// its full URL in some cases instead of "<site-URL>/"
			$this->regex = $this->rawregex;
			$this->prefix = $this->rawprefix;
		}

		//Force the string to be a url.
		//Sometimes, getUrl() can return boolean false rather than an empty string. This might be a bug.
		//Having string return type is required for VBV-13731
		$url = (string) $this->getUrl();

		$base = '';
		if ((in_array('fullurl', $options) OR in_array('bburl', $options)) AND strpos($url, '://') === false)
		{
			//Out of an abundance of caution, ensure this is also a string
			$base = (string) vB::getDatastore()->getOption('frontendurl');
		}

		$response = $base;

		//the "relative" urls are to the host root rather than to the app root for many routes
		//this forces us to make "relative" urls fully qualified in the front end if it's not
		//requested in the routing code (or to always request fully qualified urls from the
		//routing code) because otherwise the urls simply don't work.  This allows us to
		//switch the routes over one by one without the code breaking for either the
		//new or old situation.  If we don't have a fully qualified url we don't want to
		//add the seperator even if it's not there.
		if ($base AND $url AND $url[0] != '/')
		{
			 $response .= '/';
		}

		$response .= $url;

		if (!empty($params))
		{
			$response .= '?' . http_build_query($params);
		}

		if (!empty($this->anchor))
		{
			$response .= '#' . $this->anchor;
		}

		if (in_array('urlencode', $options))
		{
			$response = urlencode($response);
		}

		return $response;
	}

	/**
	 * Returns the route referenced by the associated item
	 * @return vB5_Route
	 */
	public function getCanonicalRoute()
	{
		// only subclasses know how to obtain this
		return false;
	}

	public function getCanonicalPrefix()
	{
		if ($canonicalRoute = $this->getCanonicalRoute())
		{
			return $canonicalRoute->getPrefix();
		}
		else
		{
			return false;
		}
	}

	/**
	 * Returns the canonical url which may be based on a different route
	 */
	public function getCanonicalUrl()
	{
		if ($canonicalRoute = $this->getCanonicalRoute())
		{
			$url = $canonicalRoute->getUrl();

			$parameters = $canonicalRoute->getQueryParameters();
			if (!empty($parameters))
			{
				$url .= '?' . http_build_query($parameters);
			}

			$anchor = $canonicalRoute->getAnchor();
			if (!empty($anchor))
			{
				$url .= '#' . $anchor;
			}

			return $url;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Returns false if query parameters do not determine canonicality
	 * otherwise return query parameters
	 */
	public function getCanonicalQueryParameters()
	{
		return false;
	}

	protected static function prepareTitle($title)
	{
		$title = vB_String::getUrlIdent($title);
		return self::prepareUrlIdent($title);
	}

	protected static function prepareUrlIdent($ident)
	{
		//ident can't start with a number
		if (preg_match('/^[0-9]+-/', $ident))
		{
			$ident = '-' . $ident;
		}
		return $ident;
	}

	/**
	 * Checks if route info is valid and performs any required sanitation
	 *
	 * @param array $data
	 * @return bool Returns TRUE iff data is valid
	 */
	protected static function validInput(array &$data)
	{
		if (!isset($data['guid']) OR empty($data['guid']))
		{
			$data['guid'] = vB_Xml_Export_Route::createGUID($data);
		}

		$prefixLength = strlen($data['prefix']);
		if (!isset($data['prefix']) OR  $prefixLength> self::PREFIX_MAXSIZE)
		{
			if (defined('VB_AREA') AND in_array(VB_AREA, array('Install', 'Upgrade')))
			{
				// We need to automatically shorten the URL
				$parts = array_reverse(explode('/', $data['prefix']));

				$newPath[] = $part = array_shift($parts);
				$length = strlen($part);

				if ($length > self::PREFIX_MAXSIZE)
				{
					// the last element is itself too long
					$newPrefix = substr($part, 0, self::PREFIX_MAXSIZE);
				}
				else
				{
					// prepend parts until we reach the limit
					while (($part = array_shift($parts)) AND ($length + 1 + strlen($part)) <= self::PREFIX_MAXSIZE)
					{
						array_unshift($newPath, $part);
						$length += 1 + strlen($part);
					}

					$newPrefix = implode('/', $newPath);
				}

				// replace in regex
				$data['regex'] = preg_replace("#^{$data['prefix']}#", $newPrefix, $data['regex']);

				$data['prefix'] = $newPrefix;
			}
			else
			{
				throw new vB_Exception_Api('url_too_long', array($prefixLength, self::PREFIX_MAXSIZE));
			}
		}

		if (!isset($data['regex']) OR strlen($data['regex']) > self::REGEX_MAXSIZE)
		{
			return false;
		}

		return true;
	}

	/**
	 * Checks if the prefix is already in use.
	 *
	 * Note that redirect routes are not considered "in use" since they are
	 * will be overwritten as needed by new/edited pages.
	 *
	 * @param string $prefix - Prefix to be validated
	 * @return boolean
	 */
	public static function isPrefixUsed($prefix)
	{
		$route = vB::getDbAssertor()->getRow(
			'routenew',
			array(
				vB_dB_Query::CONDITIONS_KEY => array(
					'prefix' => $prefix,
					array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL),
				)
			)
		);
		return !empty($route);
	}

	/**
	 * Stores route in db and returns its id
	 * @param type $data
	 * @return int
	 */
	protected static function saveRoute($data, $condition = array())
	{
		$assertor = vB::getDbAssertor();

		$routeTable = $assertor->fetchTableStructure('routenew');
		$info = array();
		foreach ($routeTable['structure'] AS $field)
		{
			if (isset($data[$field]))
			{
				$info[$field] = $data[$field];
			}
		}

		if (empty($condition))
		{
			return $assertor->insert('routenew', $info);
		}
		else
		{
			return $assertor->update('routenew', $info, $condition);
		}
	}

	public static function createRoute($class, $data)
	{
		if (!class_exists($class))
		{
			throw new Exception('Invalid route class');
		}

		if (!call_user_func_array(array($class, 'validInput'), array(&$data)))
		{
			throw new vB_Exception_Api('Invalid route data');
		}

		//not sure why this uses the regex rather than the prefix like other places.
		//don't want to change that behavior, but allow new routes to override 301s
		$route = vB::getDbAssertor()->getRow(
			'routenew',
			array(
				vB_dB_Query::CONDITIONS_KEY => array(
					'regex' => $data['regex'],
					array('field' => 'redirect301', 'operator' =>  vB_dB_Query::OPERATOR_ISNULL),
				)
			)
		);

		//checking for existing/duplicate route info
		if ($route)
		{
			throw new Exception('Duplicate route data: '. $data['regex']);
		}

		return self::saveRoute($data);
	}

	/**
	 *	Update the route.
	 *
	 *	If the url has changed this may result in a new route being created and the
	 *	old route being turned into a 301 redirect.
	 *
	 *	@param int $routeId
	 *	@param array $data -- fields of the route to update
	 *
	 *	@return int -- the ID of the route created/updated.
	 */
	public static function updateRoute($routeId, $data, $cloneRoute = false)
	{
		$assertor = vB::getDbAssertor();

		$events = array();

		//do this before loading the old route data.  There are cases where we need to compare
		//the oldroute ot the new route to look at changes and in this case we want to value
		//of the oldroute *after* we've reset the homepage info (if needed).
		//do this before we save the record so we don't need to exclude any routes we
		//might update to be "homepage" routes.
		if (!empty($data['ishomeroute']))
		{
			$events = self::removeExistingHomepageRoutes($assertor);
		}

		$oldRouteInfo = $assertor->getRow('routenew', array('routeid' => $routeId));
		if (!$oldRouteInfo)
		{
			return false;
		}

		if (isset($oldRouteInfo['arguments']) AND !empty($oldRouteInfo['arguments']))
		{
			$arguments = unserialize($oldRouteInfo['arguments']);
			foreach ($arguments AS $key => $val)
			{
				$oldRouteInfo[$key] = $val;
			}
		}

		$oldprefix = $oldRouteInfo['prefix'];
		$class = $oldRouteInfo['class'];
		$new_data = array_merge($oldRouteInfo, $data);

		//note that this doesn't currently work correctly for conversation/channel routes in most cases because we
		//preg_quote the channel ident before we construct the route regex.  Since we use a hyphen to replace a
		//space many of not most channels will be affected.  Note that the preg_quote below is not sufficient because
		//running it through preg_replace will implicitly unescape it (complicating the intuition here is the fact that
		//in most cases unescaped hypens will match a hyphen just fine so if hypens are the only special characters and
		//they don't appear in the special RE context then a single preg_quote won't have any effect).
		//We can't fix this by double quoting the prefix because that will break other routes that have the hyphen
		//unescaped in the route regex.
		//The new_data RE will be replaced anyway in the affected routes' validInput method below so this
		//function works after a fashion.  But it's confusing.
		if (isset($data['prefix']))
		{
			$new_data['regex'] = preg_replace('#^' . preg_quote($oldprefix) . '#', $data['prefix'], $oldRouteInfo['regex']);
		}

		unset($new_data['routeid']);
		// When we're updating a conversation route for a topic that was previously under a channel with a custom URL,
		// the old route has a redirect301 that causes a redirect loop.
		unset($new_data['redirect301']);

		if (!call_user_func_array(array($class, 'validInput'), array(&$new_data)))
		{
			throw new Exception('Invalid route data');
		}

		$deletedRoutes = array();
		if ((isset($new_data['prefix']) AND $new_data['prefix'] !== $oldRouteInfo['prefix']) OR $cloneRoute)
		{
			$deletedRoutes = self::deleteConflictingRedirect($assertor, $new_data['prefix']);

			//if the old route has a name, clear it.  Only one route should ever have a name and it belongs to the route
			//we are about to create
			//
			//This may be unnecesary now and is probably bad in some hypothetical edge cases.  If we are "cloning" a
			//page with a named route
			if ($oldRouteInfo['name'])
			{
				$assertor->update('routenew', array('name' => vB_dB_Query::VALUE_ISNULL), array('routeid' => $oldRouteInfo['routeid']));
			}

			// url has changed: create a new route and update old ones and page record
			$newrouteid = self::saveRoute($new_data);
			if (is_array($newrouteid))
			{
				$newrouteid = (int) array_pop($newrouteid);
			}
			$new_data['routeid'] = $newrouteid;

			call_user_func(array($class, 'updateContentRoute'), $oldRouteInfo, $new_data);
			$result = $newrouteid;
		}
		else
		{
			// url has not changed, so there is no need to create a new route
			$save_data = $new_data;

			//we didn't update the routeid so set it back for use by some of the callback functions
			$new_data['routeid'] = $oldRouteInfo['routeid'];

			unset($save_data['prefix']);
			unset($save_data['regex']);
			unset($save_data['arguments']);
			self::saveRoute($save_data, array('routeid' => $oldRouteInfo['routeid']));
			$result = $oldRouteInfo['routeid'];

			//if the route is no longer the home route, we need to call the class specific
			//processing function for when a route is not longer the home route.
			//This may delete the route we just updated if determine we no longer need it.
			if ($oldRouteInfo['ishomeroute'] AND !$new_data['ishomeroute'])
			{
				$newevents = call_user_func(array($class, 'removeHomepageRoute'), $new_data);
				$events = array_merge($events, $newevents);
			}
		}

		if (!empty($data['ishomeroute']))
		{
			$newevents = call_user_func(array($class, 'updateSecondaryHomepageRoutes'), $oldRouteInfo, $new_data);
			$events = array_merge($events, $newevents);
			$events[] = 'vB_routesChgMultiple';
		}
		else
		{
			// check if a common route was modified.
			// we don't have to check it if we've already flagged the change multiple event
			$common = self::fetchCommonRoutes();
			foreach ($common AS $route)
			{
				if (array_key_exists($route['routeid'], $events))
				{
					$events[] = 'vB_routesChgMultiple';
					break;
				}
			}
		}

		// invalidate cache
		$events[$oldRouteInfo['routeid']] = "routeChg_" . $oldRouteInfo['routeid'];
		foreach ($deletedRoutes AS $routeid)
		{
			$events[$routeid] = "routeChg_" . $routeid;
		}

		//the event is poorly named but better to keep it because it already exists in
		//caches.  Let's just clear this because there are all kinds of ways we can
		//potentially change a named route and cause problems
		$events[] = 'vB_Route_AddNamedUrl';

		//clearing the internal cache is probably only needed for unit tests
		//the chance of changing a route on the same page load in which we look
		//it up are slim.  But it's still wrong (and could impact command line scripts
		//which have a similar situation to the unit tests where memory stored cache
		//is more persistant).
		self::resetRouteIdentCache();
		vB_Cache::allCacheEvent($events);

		return $result;
	}

	private static function removeExistingHomepageRoutes($db)
	{
		$events = array();
		$routeids = array();

		$result = $db->select('routenew', array('ishomeroute' => 1));
		foreach($result AS $routeInfo)
		{
			$routeids[] = $routeInfo['routeid'];
			$events[$routeInfo['routeid']] = "routeChg_" . $routeInfo['routeid'];

			$newevents = call_user_func(array($routeInfo['class'], 'removeHomepageRoute'), $routeInfo);
			$events = array_merge($events, $newevents);
		}

		$db->update('routenew', array('ishomeroute' => 0), array('routeid' => $routeids));

		return $events;
	}

	private static function deleteConflictingRedirect($db, $prefix)
	{
		//delete the old redirects
		$conditions301 = array(
			vB_dB_Query::CONDITIONS_KEY => array(
				'prefix' => $prefix,
				array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNOTNULL),
			),
		);

		// used for cache invalidation below
		$deletedRoutes = $db->getColumn('routenew', 'redirect301', $conditions301, false, 'routeid');

		//we shouldn't need to do this because we should be updating the nodes to point to the
		//recent routes.  However this hasn't always been done correctly and old databases might
		//have nodes pointing to redirects.  Which causes bad things to happen if we delete them.
		foreach($deletedRoutes AS $routeid => $redirectid)
		{
			//faster to just update instead of checking if we have a such a node.
			//this is on an index so the noop queries should be fast and we don't change
			//urls all that often.
			$db->update('vBForum:node', array('routeid' => $redirectid), array('routeid' => $routeid));
		}

		$routeids = array_keys($deletedRoutes);
		$db->delete('routenew', array('routeid' => $routeids));
		return $routeids;
	}

	protected static function updateRedirects($db, $oldrouteid, $newrouteid)
	{
		$routeIds = array();
		// update redirect301 fields
		$updateIds = $db->assertQuery('get_update_route_301', array('oldrouteid' => $oldrouteid));
		if (!empty($updateIds))
		{
			foreach($updateIds AS $route)
			{
				$routeIds[] = $route['routeid'];
			}
			$db->update(
				'routenew',
				array(
					'redirect301' => $newrouteid,
					'name' => vB_dB_Query::VALUE_ISNULL,
					'ishomeroute' => vB_dB_Query::VALUE_ISNULL,
				),
				array('routeid' => $routeIds)
			);
		}

		return $routeIds;
	}

	//separate out the event logic so that we can combine events internally
	//for the route code.  External callers probably shouldn't have the option
	//so they can't screw it up.
	protected static function deleteRouteInternal($db, $routeid)
	{
		$routeIds = array();
		// update redirect301 fields
		$updateIds = $db->assertQuery('get_update_route_301', array('oldrouteid' => $routeid));
		if (!empty($updateIds))
		{
			foreach($updateIds AS $route)
			{
				$routeIds[] = $route['routeid'];
			}
			$db->delete('routenew',	array('routeid' => $routeIds));
		}

		return $routeIds;
	}


	/**
	 *	Deletes the route
	 *
	 *	This will also delete any redirects to the route being deleted
	 *	(which don't have much purpose without the route)
	 *
	 *	It will also clear the cache for the routes deleted.
	 */
	public static function deleteRoute($routeid)
	{
		$db = vB::getDbAssertor();
		$routeids = self::deleteRouteInternal($db, $routeid);

		// check if a common route was modified.
		// we don't have to check it if we've already flagged the change multiple event
		$routeidsInverse = array_flip($routeids);
		$common = self::fetchCommonRoutes();
		foreach ($common AS $route)
		{
			if (array_key_exists($route['routeid'], $routeidsInverse))
			{
				$events[] = 'vB_routesChgMultiple';
				break;
			}
		}

		$events = array();
		foreach ($routeids AS $routeid)
		{
			$events[] = "routeChg_" . $routeid;
		}
		vB_Cache::allCacheEvent($events);
	}

	protected static function updateSecondaryHomepageRoutes($oldRouteInfo, $new_data)
	{
		return array();
	}

	/**
	 *	Do any extra processing required if this route is changed from a
	 *	homepage route to a regular route.
	 *
	 *	The flag will be changed automatically by the core function.  This is
	 *	for any class specific logic.
	 *
	 *	@param array $routeInfo -- the route being changed.
	 */
	protected static function removeHomepageRoute($routeInfo)
	{
		return array();
	}

	/**
	 * Generates an array with all prefixes for $url
	 *
	 * @param string $url
	 * @return array
	 */
	public static function getPrefixSet($url)
	{
		// Generate all prefixes of the url where the prefix is
		// everything up to a slash and sort
		// e.g. for my/path/file.html:
		// 1 - my/path/file.html
		// 2 - my/path
		// 3 - my
		$prefixes[] = $temp = $url;
		while (($pos = strrpos($temp, '/')) !== FALSE)
		{
			$prefixes[] = $temp = substr($temp, 0, $pos);
		}

		// if there was no '/', it could be a home page channel/convo route instead of a relay route
		if (count($prefixes) == 1)
		{
			$prefixes[] = '';
		}

		return $prefixes;
	}

	/**
	 * Returns the route that best fits the pathInfo in $matchedRoutes
	 * @param string $pathInfo
	 * @param string $queryString
	 * @param array $matchedRoutes
	 * @return null|vB5_Route +
	 */
	public static function selectBestRoute($pathInfo, $queryString = '', $anchor = '', $matchedRoutes = array())
	{
		// loop through matched routes and select best match
		// if you find exact match, we are done
		// if not, find longest matching route
		// after finding best route, set urlData with subpatterns info, this will be use to complete parsing
		if (!is_array($matchedRoutes) OR empty($matchedRoutes))
		{
			return null;
		}

		//the regex should never be a fully qualified.  However since it may have to do with old custom
		//pages I'm a little concerned about removing it.
		//we also shouldn't be accessing the $_SERVER variable here.
		if (isset($_SERVER['SERVER_PORT']))
		{
			$port = intval($_SERVER['SERVER_PORT']);
			$https = (($port == 443) OR (isset($_SERVER['HTTPS']) AND $_SERVER['HTTPS'] AND ($_SERVER['HTTPS'] != 'off'))) ? true : false;
			$fullPath = 'http' . ($https ? 's' : '') . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
		}
		else
		{
			//we're in test mode.
			$fullPath = $pathInfo;
		}

		usort($matchedRoutes, array('vB5_Route', 'compareRoutes'));
		foreach ($matchedRoutes as $routeInfo)
		{
			// pattern matching is case-insensitive
			$pattern = '#^' . $routeInfo['regex'] . '(?:/)?$#i';

			if (preg_match('#^https?://#', $routeInfo['regex']))
			{
				$matchPath = $fullPath;
			}
			else
			{
				$matchPath = $pathInfo;
			}

			$route = self::checkRoute($routeInfo, $routeInfo['regex'], $matchPath, $queryString, $anchor);
			if ($route)
			{
				return $route;
			}
		}

		//we want to check for the homepage route(s) *last*
		foreach ($matchedRoutes AS $routeInfo)
		{
			if ($routeInfo['ishomeroute'])
			{
				//treat the route as if it didn't have a prefix.
				$className = self::getRouteClass($routeInfo);
				$re = self::removePrefixFromRe($routeInfo['regex'], $routeInfo['prefix'], $className);
				$route = self::checkRoute($routeInfo, $re, $pathInfo, $queryString, $anchor);
				if ($route)
				{
					return $route;
				}
			}
		}

		// if we got here, there were no matching routes
		return null;
	}

	private static function removePrefixFromRe($re, $prefix, $className)
	{
		//the $prefix is quoted in the re for channel/conversation routes
		$re_prefix = $prefix;
		if (in_array($className, array('vB5_Route_Channel', 'vB5_Route_Conversation')))
		{
			$re_prefix = preg_quote($prefix);
		}

		//if there is a slash after the prefix we also want to remove that.
		$removeRe = '#^' . preg_quote($re_prefix, '#') . '/?#';

		$newre = preg_replace($removeRe, '', $re);
		return $newre;
	}

	private static function getRouteClass($routeInfo)
	{
		if (!empty($routeInfo['class']) AND class_exists($routeInfo['class']))
		{
			$className = $routeInfo['class'];
		}
		else
		{
			$className = self::DEFAULT_CLASS;
		}

		return $className;
	}

	private static function checkRoute($routeInfo, $re, $matchPath, $queryString, $anchor)
	{
		// pattern matching is case-insensitive
		$pattern = '#^' . $re . '(?:/)?$#i';
		if (preg_match($pattern, $matchPath, $matches))
		{
			$className = self::getRouteClass($routeInfo);
			$route = new $className($routeInfo, $matches, $queryString, $anchor);
			$route->checkRoutePermissions();
			return $route;
		}

		return null;
	}

	protected static function compareRoutes($route1, $route2)
	{
		return (strlen($route2['prefix']) - strlen($route1['prefix']));
	}

	public static function getRouteByIdent($routeident)
	{
		if (empty($routeident))
		{
			return false;
		}

		if (empty(self::$routeidentcache))
		{
			// Loads all named routes together. The named routes will grow slowly so it's OK to load them all together
			self::loadNameRoutes();
		}

		if (is_numeric($routeident))
		{
			if (!isset(self::$routeidentcache['routeid'][$routeident]))
			{
				// cache the route to avoid querying it again
				self::$routeidentcache['routeid'][$routeident] = vB::getDbAssertor()->getRow('routenew', array('routeid' => $routeident));
			}

			$route = self::$routeidentcache['routeid'][$routeident];
		}
		else
		{
			$route = self::$routeidentcache['name'][$routeident];
		}

		if (empty($route) OR !empty($route['errors']))
		{
			$route = false;
		}

		return $route;
	}

	/**
	 * Returns the route info for the generic conversation route for the given channel
	 *
	 * @param	int	Channel node ID
	 *
	 * @return	array|bool	The route info or false on error.
	 */
	public static function getChannelConversationRouteInfo($channelId)
	{
		$channelId = (int) $channelId;

		if (empty($channelId))
		{
			return false;
		}

		if (empty(self::$routeidentcache))
		{
			self::loadNameRoutes();
		}

		$conversationroutes = array(
			'vB5_Route_Conversation',
			'vB5_Route_Article',
		);

		// if the route we want is already loaded, use it
		foreach (self::$routeidentcache AS $type)
		{
			foreach ($type AS $route)
			{
				if ($route AND in_array($route['class'], $conversationroutes, true) AND $route['contentid'] == $channelId)
				{
					return $route;
				}
			}
		}

		$route = vB::getDbAssertor()->getRow('routenew', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				'class' => $conversationroutes,
				'contentid' => $channelId,
				array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL),
			)
		));

		// cache it for subsequent requests
		self::$routeidentcache['routeid'][$route['routeid']] = $route;
		if (!empty($route['name']))
		{
			self::$routeidentcache['name'][$route['name']] = $route;
		}

		return $route;
	}

	public static function preloadRoutes($routeIds)
	{
		if (empty(self::$routeidentcache))
		{
			// Loads all named routes together. The named routes will grow slowly so it's OK to load them all together
			self::loadNameRoutes();
		}

		if (!empty($routeIds))
		{
			//make sure we don't load these again
			//If it's a named route it's already loaded
			$routes = vB::getDbAssertor()->assertQuery('routenew',	array('routeid' => $routeIds));
			$nodeids = array();
			//Now load from the database.
			foreach($routes AS $route)
			{
				// cache the route to avoid querying it again
				self::$routeidentcache['routeid'][$route['routeid']] = $route;
			}
		}
		return true;
	}

	/**
	 * Loads list of named routes, which changes rarely
	 */
	protected static function loadNameRoutes()
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
		$cacheKey = 'vB_NamedRoutes';

		self::$routeidentcache = $cache->read($cacheKey);
		if (self::$routeidentcache)
		{
			return;
		}

		$routes = vB::getDbAssertor()->getRows('routenew', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'name', 'operator' => vB_dB_Query::OPERATOR_ISNOTNULL)
			)
		));

		self::$routeidentcache = array();
		foreach ($routes AS $route)
		{
			self::$routeidentcache['name'][$route['name']] = $route;
			self::$routeidentcache['routeid'][$route['routeid']] = $route;
		}

		//no point in caching an empty value here.  This should only happen during an install
		//because we haven't installed the routes yet.
		if (self::$routeidentcache)
		{
			$cache->write($cacheKey, self::$routeidentcache, 1440, 'vB_Route_AddNamedUrl');
		}
	}

	protected static function getClassName($routeId, &$routeInfo = array())
	{
		$routeInfo = self::getRouteByIdent($routeId);
		if (!$routeInfo)
		{
			return false;
		}
		if (is_string($routeInfo['arguments']))
		{
			$routeInfo['arguments'] = @unserialize($routeInfo['arguments']);
		}
		return (isset($routeInfo['class']) AND !empty($routeInfo['class']) AND class_exists($routeInfo['class'])) ? $routeInfo['class'] : self::DEFAULT_CLASS;
	}

	public static function getRoute($routeId, $data = array(), $extra = array(), $anchor = '')
	{
		$routeInfo = array();
		$className = self::getClassName($routeId, $routeInfo);
		return new $className($routeInfo, $data, http_build_query($extra), $anchor);
	}


	/**
	 * Returns the URL associated to the route info. It does not use canonical route.
	 *
	 * @param 	string	$options	A string of routeid & options delimited by | beginning
	 *								with routeid which can be an (int) routeid or a (string)
	 *								route class identifier (ex. 'node', 'visitormessage').
	 *								Must begin with routeid, but the order of the subsequent
	 *								options do not matter
	 *								Accepted option string (TODO:complete this list):
	 *									nosession: DEPRECATED - DO NOT USE
	 *									fullurl, bburl: Prepends the frontendurl to the relative url
	 *								Ex. '51|fullurl'
	 *									'node'
	 *									'visitormessage|bburl'
	 * @param 	array 	$data		An array of "matches" that the route constructor and initRoute()
	 *								can use to generate the route. Usually the "matches" data is translated
	 *								to the route arguments by initRoute(), or query parameters or anchors.
	 *								Typically you will want to pass in all the required arguments for the
	 *								route fetching/generation (ex. 'nodeid' for a conversation route or
	 *								'userid' for a profile route, 'contentpagenum' and 'pagenum' for an
	 *								article route) and additional data that's only provided	internally to
	 *								for URL generation (ex. 'innerPost' for a conversation to add an
	 *								anchor)
	 *								See the specific route's constructor & initRoute() functions for
	 *								more details about what parameters are used.
	 *								Ex. array('nodeid' => 42, 'innerPost' => '99')
	 * @param 	array	$extra		An array of query data. Will be translated into a query string.
	 *								Ex. array('foo' => 'bar', 'life' => '42') will append
	 *								?foo=bar&life=42 to the url
	 * @param 	string	$anchor		A string specifying the anchor tag without the hash symbol '#'
	 *								Ex. 'post42' will append become #post42 to the url
	 *
	 * @return string	The URL. Will return '#' if URL generation fails (typically occurs when a
	 *					route identifier is provided in $options but is an invalid identifier, e.g.
	 *					(int) routeid does not exist in routenew table or (string) routeid isn't a
	 *					valid route class name)
	 *
	 * @throws Exception("error_no_routeid")	if routeid was unable to be retrived from $options
	 */
	public static function buildUrl($options, $data = array(), $extra = array(), $anchor = '')
	{
		$options = explode('|', $options);
		$routeId = $options[0];
		if (empty($routeId))
		{
			throw new Exception("error_no_routeid");
		}
		if (!$extra)
		{
			$extra = array();
		}
		$routeInfo = array();
		$className = self::getClassName($routeId, $routeInfo);
		if (!class_exists($className))
		{
			return '#';
		}
		$hashKey = $className::getHashKey($options, $data, $extra);
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$fullURL = $cache->read($hashKey);
		if (empty($fullURL))
		{
			$route = new $className($routeInfo, $data, http_build_query($extra), $anchor);
			if (empty($route))
			{
				throw new Exception('invalid_routeid');
			}
			$fullURL = $route->getFullUrl($options);
			$cache->write($hashKey, $fullURL, 1440, array('routeChg_' . $routeId));
		}

		return $fullURL;
	}

	/**
	 * get the urls in one batch
	 *
	 * @param array $URLInfoList	Array of data required for URL generation. Each key should uniquely identify
	 *								each requested URL, and these keys will be used by the output array.
	 *								Each element is an array with the following data:
	 *									- route
	 *									- data
	 *									- extra
	 *									- options
	 *									- options.anchor
	 *
	 * @return	string[] 	URLs built based on the input. Keys are a subset of the keys of the input array $URLInfoList.
	 */
	public static function buildUrls($URLInfoList)
	{
		// Note: If a new argument was added that affects the URL, you may want to consider
		// adding it to the 'safe' list in vB5_Template_Url->register(). Look for unset($data[$key]);
		// Without adding the new argument to that list, you will not be able change the URL by adding
		// the argument to the data array from templates.
		$URLs = array();

		// first we are going to collect inner hashes
		$innerHashes = array();
		$routeData = array();
		foreach ($URLInfoList AS $hash => $info)
		{
			$options = explode('|', $info['route']);
			$routeId = $options[0];

			if (empty($routeId))
			{
				// we don't have a routeid, so we can skip this and return an empty URL
				$URLs[$hash] = '';
				unset($URLInfoList[$hash]);
				continue;
			}

			if (isset($routeData[$routeId]))
			{
				$URLInfoList[$hash]['routeInfo'] = $routeData[$routeId]['routeInfo'];
				$URLInfoList[$hash]['class'] = $routeData[$routeId]['className'];
				$className = $routeData[$routeId]['className'];
			}
			else
			{
				$routeInfo = array();
				$className = self::getClassName($routeId, $routeInfo);

				$routeData[$routeId] = array('className' => $className, 'routeInfo' => $routeInfo);

				$URLInfoList[$hash]['routeInfo'] = $routeInfo;
				$URLInfoList[$hash]['class'] = $className;
			}


			if (!class_exists($className))
			{
				// class doesn't exist (same as buildUrl)
				$URLs[$hash] = '#';
				unset($URLInfoList[$hash]);
				continue;
			}

			$URLInfoList[$hash]['anchor'] = (empty($info['options']['anchor'])  OR !is_string($info['options']['anchor'])) ? '' : $info['options']['anchor'];
			$URLInfoList[$hash]['innerHash'] = $innerHash = $className::getHashKey($options, $info['data'], $info['extra']);

			$innerHashes[$innerHash] = $hash;
		}

		if (!empty($innerHashes))
		{
			// now fetch as many URLs as possible from cache
			$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
			$hits = $cache->read(array_keys($innerHashes));

			foreach($hits AS $innerHash => $url)
			{
				// If it's not a string, it is not a valid URL.
				if ($url !== false AND is_string($url))
				{
					$hash = $innerHashes[$innerHash];
					$URLs[$hash] = $url;
					unset($URLInfoList[$hash]);
				}
			}
		}

		// do we still have URLs to build?
		if (!empty($URLInfoList))
		{
			// group by route class
			$classes = array();
			foreach ($URLInfoList AS $hash => $info)
			{
				$classes[$info['class']][$hash] = $info;
			}
			// now process URLs per class
			foreach($classes AS $className => $items)
			{
				$URLs += $className::bulkFetchUrls($className, $items);
			}
		}
		return $URLs;
	}

	/**
	 * Build URLs using a single instance for the class. It does not check permissions. Used by buildUrls()
	 *
	 * @param string $className		Route class of this bulk of URLs
	 * @param array $URLInfoList	Array of data required for URL generation. Each key should uniquely identify
	 *								each requested URL, and these keys will be used by the output array.
	 *								Each element is an array with the following data:
	 *									- route
	 *									- routeInfo
	 *									- data
	 *									- extra
	 *									- anchor
	 *									- innerHash
	 *								@TODO: Expand above with more detail.
	 *
	 * @return string[]		String array of URLs. The keys will be the same as those provided in input $URLInfoList.
	 *						URL may be an empty string if route/url construction failed with an exception.
	 */
	protected static function bulkFetchUrls($className, $URLInfoList)
	{
		$results = array();
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);

		foreach($URLInfoList AS $hash => $info)
		{
			try
			{
				if (!isset($route))
				{
					$route = new $className($info['routeInfo'], $info['data'], http_build_query($info['extra']), $info['anchor']);
				}
				else
				{
					$route->initRoute($info['routeInfo'], $info['data'], http_build_query($info['extra']), $info['anchor']);
				}

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

	/**
	 * Returns arguments to be exported
	 * @param string $arguments
	 * @return array
	 */
	public static function exportArguments($arguments)
	{
		return $arguments;
	}

	/**
	 * Returns an array with imported values for the route
	 * @param string $arguments
	 * @return string
	 */
	public static function importArguments($arguments)
	{
		return $arguments;
	}

	/**
	 * Returns the content id from the imported values of the route after being parsed
	 * @param string $arguments
	 * @return int
	 */
	public static function importContentId($arguments)
	{
		return 0;
	}

	public function getHash($route, array $data, array $extra)
	{
		$options = explode('|', $route);
		if (empty($options[0]))
		{
			return '!!empty!!_' . md5(time());
//			$className = self::DEFAULT_CLASS;
		}
		else
		{
			$className = self::getClassName($options[0]);
		}
		return $className::getHashKey($options, $data, $extra);
	}

	protected static function getHashKey($options = array(), $data = array(), $extra = array())
	{
		/*
		 * 	Before, this bit was doing a bunch of O(n) array operations (array_shift, array_flip, array_keys).
		 *	I don't think array indices really matter. We don't even sort the arrays $options, $data, $extra, so
		 *	it seems to me that we don't care about duplicate data with different hashkeys, but only care about
		 *	assuring enough entropy. Since we *know* $options[0] will be missing every time, I don't particularly
		 *	see a reason we should re-index the array after we pull the routeid.
		 *	So rather than using array_shift(), let's just grab the routeID & unset it.
		 *
		 *	We still have 3 serialize() calls below, so removing these won't make much of a performance difference.
		 *	And even if we remove serialize(), these arrays are usually so small (~5 elements probably) that it
		 *	probably wouldn't make a perceptible difference (rough tests show ~5ms -> 1.6ms for 800 getHashKey calls).
		 */
		$routeId = $options[0];
		unset($options[0]);

		$hashKey = 'vbRouteURL_'. $routeId;
		$hash_add = (empty($options) ? '' : serialize($options)) . (empty($data) ? '' : serialize($data)) . (empty($extra) ? '' : serialize($extra));
		if (!empty($hash_add))
		{
			$hashKey .= '_' . md5($hash_add);
		}
		return $hashKey;
	}

	function getRouteSegments()
	{
		return explode('/', $this->prefix);
	}

	public function getHeadLinks()
	{
		$this->setHeadLinks();
		return $this->headlinks;
	}

	public function setHeadLinks()
	{
		$this->headlinks = array();

		if (vB::getDatastore()->getOption('externalrss'))
		{
			// adding headlink
			$route = vB_Library::instance('external')->getExternalRoute(array('type' => vB_Api_External::TYPE_RSS2));
			$this->headlinks[] = array(
				'rel' => 'alternate',
				'title' => vB::getDatastore()->getOption('bbtitle'),
				'type' => 'application/rss+xml',
				'href' => $route,
				'rsslink' => 1
			);
		}
	}

	/**
	 * Returns a list of common routes. We check these to see if we can avoid the far most expensive selectBestRoute call
	 *
	 * @return array of string => string	map of url to route class.
	 */
	public static function fetchCommonRoutes()
	{
		if (($common = vB_Cache::instance(vB_Cache::CACHE_STD)->read('vB_CommonRoutes')) AND !empty($common))
		{
			return $common;
		}
		$guids = array(
			vB_Channel::MAIN_CHANNEL, vB_Channel::DEFAULT_FORUM_PARENT,
			vB_Channel::MAIN_FORUM, vB_Channel::MAIN_FORUM_CATEGORY,
			vB_Channel::DEFAULT_BLOG_PARENT, vB_Channel::DEFAULT_SOCIALGROUP_PARENT,
			vB_Channel::PRIVATEMESSAGE_CHANNEL, vB_Channel::VISITORMESSAGE_CHANNEL,
			// TODO: SHOULD PROBABLY ADD ARTICLE CHANNEL ROUTE HERE
		);
		// todo, also add empty prefix channel route for when home page has been changed?

		$routes = vB::getDbAssertor()->assertQuery('vBForum:getRouteFromChGuid', array('guid' => $guids));
		$common = array();
		foreach ($routes AS $route)
		{
			$common[$route['prefix']] = $route;
			$common[$route['prefix']]['length'] = strlen($route['prefix']);
		}

		vB_Cache::instance(vB_Cache::CACHE_STD)->write('vB_CommonRoutes', $common, 1440, 'vB_routesChgMultiple');

		return $common;
	}

	/**
	 * Resets the route ident cache. This is only intended to be used externally for unit tests,
	 * where mulitple tests run during the same request, causing invalid routes (from
	 * a previous test to be in $routeidentcache. This doesn't happen on a normal
	 * page request, because $routeidentcache is in memory only for the duration of
	 * the request. VBV-12736
	 *
	 * We use it internally to clear the cache when it changes
	 */
	public static function resetRouteIdentCache()
	{
		self::$routeidentcache = array();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103869 $
|| #######################################################################
\*=========================================================================*/
