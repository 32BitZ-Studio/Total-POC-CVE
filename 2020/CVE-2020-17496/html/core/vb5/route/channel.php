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

class vB5_Route_Channel extends vB5_Route
{
	public function __construct($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		parent::__construct($routeInfo, $matches, $queryString);

		if (isset($this->arguments['channelid']))
		{
			if (! vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $this->arguments['channelid']))
			{
				throw new vB_Exception_NodePermission($this->arguments['channelid']);
			}
			// check if we need to force a styleid
			$channel = vB_Library::instance('Content_Channel')->getBareContent($this->arguments['channelid']);
			if (is_array($channel))
			{
				$channel = array_pop($channel);
			}

			if (!empty($channel['styleid']))
			{
				$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
				if ($channel['options']['styleoverride'])
				{
					// the channel must force the style
					$this->arguments['forceStyleId'] = $channel['styleid'];
				}
				else
				{
					// the channel suggests to use this style
					$this->arguments['routeStyleId'] = $channel['styleid'];
				}
			}

			if (!empty($this->queryParameters))
			{
				$this->arguments['noindex'] = 1;
			}

			if (!empty($channel['description']))
			{
				$this->arguments['nodedescription'] = $channel['description'];
			}

			// rss info
			$this->arguments['rss_enabled'] = $channel['rss_enabled'];
			$this->arguments['rss_route'] = $channel['rss_route'];
			$this->arguments['rss_title'] = $channel['title'];
			// because conversation routes also add their parent channel's rss info into the arguments,
			// this flag helps us tell channels apart from conversations when we're adding the RSS icon next to the page title
			$this->arguments['rss_show_icon_on_pagetitle'] = $channel['rss_enabled'];

			// styleid for channels are not final at this point, so let's not include them in the key
			$this->setPageKey('pageid', 'channelid');

			// set user action
			$this->setUserAction('viewing_forum_x', $channel['title'], $this->getFullUrl('fullurl'));
		}
	}

	public function setBreadCrumbs()
	{
		parent::setBreadCrumbs();
		// remove link from last crumb
		if (count($this->breadcrumbs) > 0)
		{
			$this->breadcrumbs[(count($this->breadcrumbs) - 1)]['url'] = '';
		}
	}

	/**
	 * Verifies the channel prefix from a title or a url identifier and the parent channel.
	 *
	 * @param	array	The data we are using to create the channel
	 */
	public static function validatePrefix($data)
	{
		// see self::validInput
		if (!isset($data['prefix']))
		{
			//use urlident if we have it.
			if (empty($data['urlident']))
			{
				$url = self::createPrefix($data['parentid'], $data['title'], false);
			}
			else
			{
				$url = self::createPrefix($data['parentid'], $data['urlident'], true);
			}
			$data['prefix'] = $data['regex'] = $url;
		}
		else
		{
			$data['regex'] = $data['prefix'];
		}

		// this will return an exception is prefix/regex is invalid
		parent::validInput($data);
	}

	/**
	 * Create the channel prefix from a title or a url identifier and the parent channel.
	 *
	 * @param	int		The channel id of the parent channel.
	 * @param	string	The title (or url identifier) of this channel
	 * @param	bool	If true, $title is treated as if it's already been turned into a url identifier (already url safe, already utf-8)
	 *
	 * @return	string	The prefix of the title combined with the parent's prefix. (UTF-8 encoded)
	 */
	public static function createPrefix($parentId, $title, $isUrlIdent)
	{
		$channelApi = vB_Api::instanceInternal('content_channel');

		//its not likely that we'll be playing with the root channel but if we are we don't have a parent
		//so we'll need to account for that.  It can happen during the 5.0.0 beta 26 upgrade in step 1.
		$parentUrl = '';
		if ($parentId > 0)
		{
			$parentChannel = $channelApi->fetchChannelById($parentId);

			$parentRoute= self::getRoute($parentChannel['routeid']);
			//if the parent isn't a channel something is very wrong and this isn't going to work anyway.
			//we'll just default to an empty parent to keep things going
			if($parentRoute instanceOf vB5_Route_Channel)
			{
				$parentUrl = $parentRoute->getChannelUrl();
			}

			if ($parentUrl AND $parentUrl[0] == '/')
			{
				$parentUrl = substr($parentUrl, 1);
			}
		}


		$url = '';
		if (!empty($parentUrl))
		{
			$url .= $parentUrl . '/';
			if (strtolower(vB_String::getCharset()) != 'utf-8')
			{
				// buildUrl will return an encoded url in this case.
				$url = urldecode($url);
			}
		}

		if ($isUrlIdent)
		{
			$url .= self::prepareUrlIdent($title);
		}
		else
		{
			$url .= self::prepareTitle($title);
		}

		return $url;
	}

	protected static function validInput(array &$data)
	{
		// ignore page number
		unset($data['pagenum']);

		if (isset($data['channelid']))
		{
			$data['nodeid'] = $data['channelid'];
			unset($data['channelid']);
		}

		if (
			!isset($data['nodeid']) OR !is_numeric($data['nodeid']) OR
			!isset($data['pageid']) OR !is_numeric($data['pageid']) // this is used for rendering the page
		)
		{
			return false;
		}
		$data['nodeid'] = intval($data['nodeid']);
		$data['pageid'] = intval($data['pageid']);

		if (!isset($data['prefix']))
		{
			$newChannel = vB_Library::instance('node')->getNodeBare($data['nodeid']);

			//use urlident if we have it.
			if (empty($data['urlident']))
			{
				$url = self::createPrefix($newChannel['parentid'], $newChannel['title'], false);
			}
			else
			{
				$url = self::createPrefix($newChannel['parentid'], $newChannel['urlident'], true);
			}
			$data['prefix'] = $url;
		}

		$data['regex'] = preg_quote($data['prefix']) . '(?:(?:/|^)page(?P<pagenum>[0-9]+))?';

		$data['class'] = __CLASS__;
		$data['controller'] = 'page';
		$data['action'] = 'index';
		$data['arguments'] = serialize(array(
			'channelid' => $data['nodeid'],
			'nodeid' => $data['nodeid'],
			'pagenum'	=> '$pagenum',
			'pageid' => $data['pageid'],
		));
		// this field will be used to delete the route when deleting the channel (contains channel id)
		$data['contentid'] = $data['nodeid'];

		unset($data['nodeid']);
		unset($data['pageid']);

		return parent::validInput($data);
	}

	protected static function updateContentRoute($oldRouteInfo, $newRouteInfo)
	{
		$db = vB::getDbAssertor();
		$events = array();
		$events[] = "vB_ChannelStructure_chg";	// invalidate vB_ChTree... record so that channels' routes are updated

		$updateIds = self::updateRedirects($db, $oldRouteInfo['routeid'], $newRouteInfo['routeid']);
		foreach($updateIds AS $routeid)
		{
			$events[] = "routeChg_$routeid";
		}

		// update routeid in nodes table
		$updateIds = $db->assertQuery('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('nodeid'),
			vB_dB_Query::CONDITIONS_KEY => array('routeid' => $oldRouteInfo['routeid']),
		));

		if (!empty($updateIds))
		{
			$nodeIds = array();
			foreach($updateIds AS $node)
			{
				$nodeid = $node['nodeid'];
				// this does not affect parents, so we don't need to clear they cache
				$events[] = "nodeChg_$nodeid";
				$nodeIds[] = $nodeid;
			}
			$db->update('vBForum:node', array('routeid' => $newRouteInfo['routeid']), array('nodeid' => $nodeIds));
		}

		/*
		 * The code below implies that multiple conversation routes could exist under a single channel. However, I don't know
		 * when this might be the case. When moving channels/topics, the routes are untouched. Topic redirects are handled by
		 * the redirect & node tables.
		 */
		// update conversation generic route
		$routes = $db->getRows('routenew', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field'=>'class',	'value' => array('vB5_Route_Conversation', 'vB5_Route_Article')),
				array('field'=>'prefix','value' => $oldRouteInfo['prefix']),
				array('field'=>'contentid',	'value' => $oldRouteInfo['channelid']),
				array('field'=>'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL),
			),
		));

		foreach ($routes AS $route)
		{
			$events[] = "routeChg_{$route['routeid']}";

			//if the old route has a name, clear it.  Only one route should ever have a name and it belongs to the route
			//we are about to create.
			if ($route['name'])
			{
				$db->update('routenew', array('name' => vB_dB_Query::VALUE_ISNULL), array('routeid' => $route['routeid']));
			}

			// create new conversation route using most of the old route's data
			$newConversationRoute = $route;
			unset($newConversationRoute['routeid']);
			unset($newConversationRoute['redirect301']);
			$newConversationRoute['prefix'] = $newRouteInfo['prefix'];

			// special case, if prefix is empty (i.e. this is a new home page) then we must leave out the leading '/',
			// or selectBestRoute will not be able to match the path (which never has a leading '/') to regex.
			$newConversationRoute['regex'] = (($newRouteInfo['prefix'] === '')?'':preg_quote($newRouteInfo['prefix']) . '/') . vB5_Route_Conversation::REGEXP;

			// save the new route. If you need to call validInput(), be sure to unset prefix first, otherwise it'll think it's
			// a custom conversation url (as opposed to custom channel url, which this is)
			$newConversationRouteid = vB5_Route_Conversation::saveRoute($newConversationRoute);
			if (is_array($newConversationRouteid))
			{
				$newConversationRouteid = (int) array_pop($newConversationRouteid);
			}

			//there shouldn't be multiple pages pointing to the old route, but if there are
			//we probably shouldn't mess with them.
			$args = unserialize($route['arguments']);
			if (isset($args['pageid']))
			{
				$pageid = $args['pageid'];
				$events[] = "pageChg_$pageid";
				$db->update('page', array('routeid' => $newConversationRouteid), array('pageid' => $pageid));
			}

			// update routeids for conversation nodes
			// Copied from the channel node updates above.
			$updateIds = $db->assertQuery('vBForum:node', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('nodeid'),
				vB_dB_Query::CONDITIONS_KEY => array('routeid' => $route['routeid']),
			));

			if (!empty($updateIds))
			{
				$nodeIds = array();
				foreach($updateIds AS $node)
				{
					$nodeid = $node['nodeid'];
					// this does not affect parents, so we don't need to clear their cache
					$events[] = "nodeChg_$nodeid";
					$nodeIds[] = $nodeid;
				}
				// if there are ever cases of multiple conversation routes per channel, and they're sizable, it might be
				// worth creating a method query to handle all node updates at once instead of per conversation route.
				$db->update('vBForum:node', array('routeid' => $newConversationRouteid), array('nodeid' => $nodeIds));
			}

			// update redirect301 fields for the previous conversation redirects
			// this will also update the route for $route['routeid']
			$updateIds = self::updateRedirects($db, $route['routeid'], $newConversationRouteid);
			foreach($updateIds AS $routeid)
			{
				$events[] = "routeChg_$routeid";
			}
		}

		vB_Cache::allCacheEvent($events);
	}

	protected static function updateSecondaryHomepageRoutes($oldRouteInfo, $newRouteInfo)
	{
		$events = array();

		if ($newRouteInfo['ishomeroute'])
		{
			$db = vB::getDbAssertor();

			$conditions = array(
				array('field'=>'class',	'value' => array('vB5_Route_Conversation', 'vB5_Route_Article')),
				array('field'=>'prefix','value' => $newRouteInfo['prefix']),
				array('field'=>'contentid',	'value' => $oldRouteInfo['channelid']),
				array('field'=>'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL),
			);

			$route = $db->getRow('routenew', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => $conditions,
			));

			if ($route)
			{
				$db->update('routenew', array('ishomeroute' => 1), array('routeid' => $route['routeid']));

				$events[] = 'routeChg_' . $route['routeid'];
			}
		}

		return $events;
	}

	public function getUrl()
	{
		// if not home page, reroute by node if that's selected
		if ($this->prefix !== '' AND vB::getDatastore()->getOption('routebynode'))
		{
			if (!isset($this->arguments['nodeid']))
			{
				$this->arguments['nodeid'] = $this->arguments['channelid'];
			}

			//this requires that the node route accept all of the parameters that the
			//channel route does.
			return self::getRoute('node', $this->arguments, $this->queryParameters)->getUrl();
		}


		//otherwise use the normal channel url
		return $this->getChannelUrl();
	}

	private function getChannelUrl()
	{
		// do not append '/' if prefix is empty string (happens for home page)
		$url = '';
		if ($this->prefix !== '')
		{
			$url = '/' . $this->prefix;
		}

		if (isset($this->arguments['pagenum']) AND is_numeric($this->arguments['pagenum']) AND $this->arguments['pagenum'] > 1)
		{
			$url .= '/page' . intval($this->arguments['pagenum']);
		}

		if (strtolower(vB_String::getCharset()) != 'utf-8')
		{
			$url = vB_String::encodeUtf8Url($url);
		}

		return $url;
	}

	public function getCanonicalRoute()
	{
		if (!isset($this->canonicalRoute))
		{
			if (empty($this->arguments['channelid']))
			{
				return array();
			}

			$node = vB_Library::instance('node')->getNodeBare($this->arguments['channelid']);
			$data = array();

			if (isset($this->arguments['pagenum']) AND is_numeric($this->arguments['pagenum']) AND $this->arguments['pagenum'] > 1)
			{
				$data['pagenum'] = $this->arguments['pagenum'];
			}

			$this->canonicalRoute = self::getRoute($node['routeid'], $data, $this->queryParameters);
		}

		return $this->canonicalRoute;
	}

	public static function exportArguments($arguments)
	{
		$data = unserialize($arguments);

		$channel = vB::getDbAssertor()->getRow('vBForum:channel', array('nodeid' => $data['channelid']));
		if (empty($channel))
		{
			throw new Exception('Couldn\'t find channel');
		}
		$data['channelGuid'] = $channel['guid'];
		unset($data['channelid']);

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

		$channel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => $data['channelGuid']));
		if (empty($channel))
		{
			throw new Exception('Couldn\'t find channel');
		}
		$data['channelid'] = $channel['nodeid'];
		unset($data['channelGuid']);

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
		return $arguments['channelid'];
	}

	public function setHeadLinks()
	{
		$this->headlinks = array();

		if (vB::getDatastore()->getOption('externalrss'))
		{
			// adding headlink
			$routedata = vB_Api::instance('external')->buildExternalRoute(vB_Api_External::TYPE_RSS2);
			$bbtitle = vB::getDatastore()->getOption('bbtitle');
			$this->headlinks[] = array(
				'rel' => 'alternate',
				'title' => $bbtitle,
				'type' => 'application/rss+xml',
				'href' => $routedata['route'],
				'rsslink' => 1,
			);

			if ($this->arguments['rss_enabled'])
			{
				$this->headlinks[] = array(
					'rel' => 'alternate',
					'title' => $bbtitle . ' -- ' . $this->arguments['rss_title'],
					'type' => 'application/rss+xml',
					'href' => $this->arguments['rss_route'],
					'rsslink' => 1,
				);
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103460 $
|| #######################################################################
\*=========================================================================*/
