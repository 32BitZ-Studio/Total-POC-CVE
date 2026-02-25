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
 * This class is used for creating redirects of legacy URLs
 * The getRedirect301 function will compute new route info,
 * which will be used to build the new URL afterwards
 */
abstract class vB5_Route_Legacy extends vB5_Route
{
	
	abstract protected function getNewRouteInfo();
	
	public function __construct($routeInfo = array(), $matches = array(), $queryString = '')
	{
		if (!empty($routeInfo))
		{
			parent::__construct($routeInfo, $matches, $queryString);
		}
		else
		{
			// We are not parsing the route
			$this->arguments = array();
		}
	}
	
	/**
	 * discard all query parameters
	 * caches the new route and return it every time
	 * this is the simplest form of redirection
	 * if subclass is any complicate than this, override is needed
	 */
	public function getRedirect301()
	{
		$this->queryParameters = array();
		$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
		$cacheKey = get_class($this);
		$data = $cache->read($cacheKey);
		if (!$data)
		{
			$data = $this->getNewRouteInfo();
			$cache->write($cacheKey, $data, 86400);
		}
		return $data;
	}

	public function getRegex()
	{
		return $this->prefix;
	}

	// we cannot create nor update these routes
	final protected static function validInput(array &$data)
	{
		throw new Exception('Invalid route data');
	}

	// we cannot update content for these routes
	final protected static function updateContentRoute($oldRouteInfo, $newRouteInfo)
	{
		throw new Exception('Invalid route data');
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
