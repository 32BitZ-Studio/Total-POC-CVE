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

class vB5_Route_Profile extends vB5_Route
{
	const DEFAULT_PREFIX = 'member';
	const REGEXP = '(?P<userid>[0-9]+)(?P<username>(-[^\?/]*)*)(?:/(?P<tab>activities|subscribed|about|media|infractions))?(?:/page(?P<pagenum>[0-9]+))?';
	protected static $availableTabs = array(
			'activities' => true,
			'subscribed' => true,
			'about' => true,
			'media' => true,
			'infractions' => true
		);
	protected static $doNotIndexTabs = array(
			'infractions' => true
		);
	protected static $tabsWithPagination = array(
			'media' => true,
			'infractions' => true
		);

	public function __construct($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		parent::__construct($routeInfo, $matches, $queryString, $anchor);
		$this->setPageKey('pageid', 'userid');

		//this is a bad place for this... since it will get called whenever a route class is loaded and not just when the
		//user goes to the profile page.
		if (!empty($this->arguments['username']))
		{
			$this->setUserAction('viewing_user_profile', $this->arguments['username'], $this->getFullUrl('fullurl'));
		}
	}

	protected function initRoute($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		parent::initRoute($routeInfo, $matches, $queryString, $anchor);

		// if we don't have a numeric userid at this point, make it 0
		$this->arguments['userid'] = isset($this->arguments['userid']) ? intval($this->arguments['userid']) : 0;

		//there are lots of places we can get the username from if we don't have it, check them.
		if (!empty($this->arguments['userid']) AND empty($this->arguments['username']))
		{
			//node records provide both the username and the userid but under a different value.  We generate profile links for node
			//display frequently and we'd like to avoid an extra database trip
			if (!empty($matches['authorname']))
			{
				$this->arguments['username'] = $matches['authorname'];
			}
			else
			{
				//a lot of our profile links are for the current user -- who's information we have cached.
				$currentuser = vB::getCurrentSession()->fetch_userinfo();
				if ($this->arguments['userid'] == $currentuser['userid'])
				{
					$this->arguments['username'] = $currentuser['username'];
				}

				//if all else fails try to load from the database
				else
				{
					$user = vB_User::fetchUserinfo($this->arguments['userid']);
					$this->arguments['username']  = $user['username'];
				}
			}
		}
	}

	protected function checkRoutePermissions()
	{
		$currentUser = vB::getUserContext();

		if (!$currentUser->hasPermission('genericpermissions', 'canviewmembers') AND ($this->arguments['userid'] != vB::getCurrentSession()->get('userid')))
		{
			throw new vB_Exception_NodePermission('profile');
		}
	}

	/**
	* Sets the breadcrumbs for the route
	*/
	protected function setBreadcrumbs()
	{
		//if we are coming in for a route (instead of generating a URL) then the $this->arguments['username'] is the
		//url slug, which we don't want.  The API call is cached and will be called later anyway to generate the
		//profile page so its not a bit performance hit to load this way.
		$userInfo = vB_Api::instanceInternal('user')->fetchProfileInfo($this->arguments['userid']);
		$this->breadcrumbs = array(
			0 => array(
				'title' => $userInfo['username'],
				'url'	=> ''
			),
		);
	}

	protected static function validInput(array &$data)
	{
		if (
			!isset($data['pageid'])
			OR !is_numeric($data['pageid'])
			OR !isset($data['prefix'])
		)
		{
			return FALSE;
		}
		$data['pageid'] = intval($data['pageid']);

		$data['prefix'] = $data['prefix'];
		$data['regex'] = $data['prefix'] . '/' . self::REGEXP;
		$data['arguments'] = serialize(array(
			'userid'	=> '$userid',
			'pageid'	=> $data['pageid'],
			'tab'		=> '$tab'
		));

		$data['class'] = __CLASS__;
		$data['controller']	= 'page';
		$data['action']		= 'index';
		// this field will be used to delete the route when deleting the channel (contains channel id)

		unset($data['pageid']);

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

	public function getUrl()
	{
		if (!empty($this->arguments['userid']) AND !empty($this->arguments['username']))
		{
			$result = '/' . $this->prefix . '/' . $this->arguments['userid'] . '-' . vB_String::getUrlIdent($this->arguments['username']);
		}
		else
		{
			return false;
		}

		// append the tab to URL only if it's a valid tab.
		if (isset($this->arguments['tab']))
		{
			if (isset(self::$availableTabs[$this->arguments['tab']]))
			{
				$result .= '/' . $this->arguments['tab'];

				if (isset(self::$doNotIndexTabs[$this->arguments['tab']]))
				{
					$this->arguments['noindex'] = true;
				}

				// append the page number if pagenum argument is set & if a tab with pagination is set
				if (
					isset($this->arguments['pagenum']) AND
					is_numeric($this->arguments['pagenum']) AND
					$this->arguments['pagenum'] > 1 AND
					isset(self::$tabsWithPagination[$this->arguments['tab']])
				)
				{
					$result .= '/page' . intval($this->arguments['pagenum']);
				}
			}
			else
			{
				// invalid tab, unset it
				unset($this->arguments['tab']);
			}
		}

		if (strtolower(vB_String::getCharset()) != 'utf-8')
		{
			$result = vB_String::encodeUtf8Url($result);
		}

		return $result;
	}

	public function getCanonicalRoute()
	{
		if (!isset($this->canonicalRoute))
		{
			$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
			$hashKey = 'routepageid_' . $this->arguments['pageid'];
			$page = $cache->read($hashKey);
			if (empty($page))
			{
				$page = vB::getDbAssertor()->getRow('page', array('pageid' => $this->arguments['pageid']));
				$cache->write($hashKey, $page, 1440, 'routepageid_Chg_' . $this->arguments['pageid']);
			}
			$this->canonicalRoute = self::getRoute($page['routeid'], $this->arguments, $this->queryParameters);
		}

		return $this->canonicalRoute;
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

	protected static function getHashKey($options = array(), $data = array(), $extra = array())
	{
		$routeId = $options[0];
		$hashKey = 'vbRouteURL_'. $routeId;
		if (!empty($data['userid']))
		{
			$hashKey = 'vbRouteURL_'. $routeId . '_' . $data['userid'];
		}
		elseif (!empty($data['username']))
		{
			$hashKey = 'vbRouteURL_'. $routeId . '_' . $data['username'];
		}
		return $hashKey;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102676 $
|| #######################################################################
\*=========================================================================*/
