<?php
if (!defined('VB_ENTRY')) die('Access denied.');
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
 * vB_Library_RouteFix
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_RouteFix extends vB_Library
{
	protected $assertor;
	protected $channels;
	protected $routes;
	protected $pages;
	protected $xmlLocation;
	protected $defaultChannelRoute;
	protected $defaultChannelPage;
	protected $forumHomePrefix;
	protected $errPhrase;
	protected $statusPhrase;
	protected $fixedNodes = array();
	protected $fixedPages = array();
	protected $messages = array();
	protected $phraseLib;
	protected $phrases = array(
		'skipping_for_node_x_y' => 'Skipping for Node {1}, {2}',
		'node_x_y_needs_route' => 'Node {1}, {2} needs a route',
		'route_updates' => 'Route Updates and Issues',
		'route_x_y_z_missing_nodeid' => 'Route #{1} at node {2},  {3} doesn\'t have a nodeid',
		'route_x_y_z_has_mismatched_nodeid' => 'Route #{1} at node {2}, {3} has mismatched nodeid ',
		'error_x' => 'Error {1}',
		'cannot_fix_x_y_z_need_a' => 'Cannot fix {1} guid {2}, need a valid {3} for guid {4}',
		'have_route_x_for_node_y' => 'Have route {1} for node {2}',
		'found_route_params_for_node_x' => 'Found route parameters in the xml file for node {1}',
		'created_route_for_x' => 'Created new Route for node {1}',
		'failed_to_create_route_x' => 'failed to create new Route for {1}',
		'updating_route_x_to_y' => 'Updating Route to {1} for node {2}',
		'just_deleted_routes_x' => 'Just deleted routes {1}',
		'conflict_with_node_x' => 'Unable to fix node {1}- more than channel route is pointing to it',
		'correcting_route_for_node_x' => 'Correcting routeid for node {1}',
		'route_x_missing_argument' => 'Route #{1} is missing arguments and cannot be fixed.',
		'created_page_for_route_x' => 'Created new page for route {1}',
		'conflict_with_page_x' => 'Unable to fix page {1}- more than route is pointing to it',
		'correcting_route_for_page_x' => 'Correcting routeid for page {1}',
		'created_new_route_guid_x_for_y' => 'Created new route guid {1} for {2}',
		'processing_complete' => 'Completed Processing',
		'route_x_missing_channel' => 'Route {1} is missing the channelid and cannot be automatically repaired',
		'no_forum_home' => 'Unable to find forum home.  I cannot fix this',
		'no_forum_home_route' => 'Unable to find or create either forum or home route. These are critical and without them I cannot continue',
		'cannot_set_forum_home' => 'Unable to set home page route.  I cannot fix this route table',
		'deleting_unmatched_pages_x' => 'Delete pages with invalid routeid\'s- {1}',
		'correcting_conversation_regex_x' => 'Correcting conversation regex for {1}',
		'failed_to_create_conversation_route_for_x', 'failed to create new conversation route for node#{1}',
		'failed_to_create_channel_route_for_x', 'failed to create new channel route for node#{1}',
	);

	public function __construct()
	{
		$this->assertor = vB::getDbAssertor();
		$this->getDefaults();
		$this->messages = array();
		$this->phraseLib = vB_Library::instance('phrase');
	}

	/**
	 * @return array|bool
	 */
	public function fixRoutes()
	{
		$this->messages = array();
		set_error_handler(array($this, 'catchError'));

		//Make sure we have the latest pages
		$pageFile = DIR . '/install/vbulletin-pages.xml';
		if (!($xml = file_read($pageFile)))
		{
			return array(array('error', 'Need vbulletin-pages.xml in install folder'));
		}

		$page_importer = new vB_Xml_Import_Page('vbulletin', 0);
		$page_importer->importFromFile($pageFile);

		if (!$this->checkHomePage() OR !$this->checkForumHome())
		{
			$this->messages[] = array('error', $this->fetchPhrase('no_forum_home_route'));
			return $this->messages;
		}
		$this->checkSearchRoute();
		$this->checkAdvancedSearchRoute();
		$this->deleteUnusedRoutes();

		/*Scan the node records. If the node record routeid points to a channel route record, check that the nodeid in the route record
			arguments points back to same node. If not, check to see if there is such a valid node.
			If there is, leave the route record alone. If there is not an existing node record with the nodeid
			 from the route record, change the argument node to be consistent with the node record.*/
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getChannelRoutes', array());

		$specials = vB_Channel::getDefaultGUIDs();
		unset($specials['MAIN_FORUM']);
		unset($specials['DEFAULT_FORUM_PARENT']);


		foreach ($routeQry AS $routeRec)
		{
			//If it's one of the special channels, e.g. blogs, this check will fail
			if (in_array($routeRec['channelguid'], $specials))
			{
				$this->messages[] = array('status', $this->fetchPhrase('skipping_for_node_x_y',
					array($routeRec['nodeid'], $routeRec['title'])));
				continue;
			}

			if (empty($routeRec['routeid']))
			{
				$routeid = $this->createChannelRoute($routeRec['nodeid']);
				$this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'nodeid' => $routeRec['nodeid'],
					'routeid' => $routeid));
			}
			else
			{
				$arguments = unserialize($routeRec['arguments']);

				if (empty($arguments['channelid']))
				{
					$this->messages[] = array('status', $this->fetchPhrase('route_x_y_z_missing_nodeid',
						array($routeRec['routeid'], $routeRec['nodeid'], $routeRec['title'])));
					$arguments['nodeid'] = $routeRec['nodeid'];
					$arguments['channelid'] = $routeRec['nodeid'];
					$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'arguments' => serialize($arguments), 'contentid' => $routeRec['nodeid'], 'routeid' => $routeRec['routeid']));
				}
				else if ($arguments['channelid'] != $routeRec['nodeid'])
				{
					$routeid = $this->createChannelRoute($routeRec['nodeid']);
					$this->messages[] = array('status', $this->fetchPhrase('route_x_y_z_has_mismatched_nodeid', array($routeRec['routeid'],
						$routeRec['nodeid'], $routeRec['title'])));
				}

			}
			$this->makeRouteGuidUnique($routeRec['routeid'], $routeRec['routeguid']);
		}
		//last, make sure there's a matching conversation route for each channel route.
		$this->checkConversationRoutes();
		$this->checkPrefixes();
		$this->checkPageInfo();
		$this->clearBadRedirects();
		$this->fixPounds();
		vB_Cache::resetAllCache();
		return $this->messages;
	}

	protected function fetchPhrase($key, $params = array())
	{
		if (array_key_exists($key, $this->phrases))
		{
			$response = $this->phrases[$key];
		}
		else
		{
			$response = $key;
		}

		if (is_array($params) AND !empty($params))
		{

			foreach ($params AS $paramNo => $param)
			{
				$response = str_replace('{' . ($paramNo + 1) . '}', $param, $response);
			}
		}

		return $response;
	}

	/**
	 * Check all routeprefixes.  Make sure the hierarchy is clean. Urlident should match prefix, and child prefix should match parent.
	 */
	protected function checkPrefixes()
	{
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getChannelPrefixes', array(
			'channeltype' => vB_Types::instance()->getContentTypeID('vBForum_Channel')));

		//This queries sorts by depth, so a channel will always come after its parent.
		$channelRegex = '(?:/page(?P<pagenum>[0-9]+))?';

		foreach($routeQry AS $route)
		{

			if ($route['nodeid'] == 1)
			{
				$prefix = '';
				$regex = '';
			}
			else
			{
				$prefix = vB5_Route_Channel::createPrefix($route['parentid'], $route['urlident'], true);
				$regex = preg_quote($prefix) . $channelRegex;
				$conversationRegex = preg_quote($prefix) . '/'. vB5_Route_Conversation::REGEXP;
			}

			if (($route['prefix'] != $prefix) OR ($route['regex'] != $regex))
			{
				$this->messages[] = array('status',"fixing route for node " . $route['nodeid']);
				$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'routeid' => $route['routeid'], 'prefix' => $prefix, 'regex' => $regex));

				if (!empty($route['convRouteId']))
				{

					$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'routeid' => $route['convRouteId'], 'prefix' => $prefix, 'regex' => $conversationRegex));
				}
			}

		}
	}



	/**
	 * Check all channel and conversation routes.  Make sure the mapping between route arguments page and page routeid is clean.
	 */
	protected function checkPageInfo()
	{
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getBothChannelRoutes', array('channeltype' =>
			vB_Types::instance()->getContentTypeID('vBForum_Channel')));

		foreach($routeQry AS $routeInfo)
		{
			$args = unserialize($routeInfo['arguments']);

			if (empty($args['pageid']) OR (empty($routeInfo['pageid'])) OR (!is_numeric($args['pageid'])) OR ($routeInfo['pageid'] != $args['pageid']))
			{
				if (!empty($routeInfo['pageid']) AND is_numeric($routeInfo['pageid']))
				{
					$args['pageid'] = $routeInfo['pageid'];
				}
				else if ($routeInfo['class'] == 'vB5_Route_Channel')
				{
					$node = $this->assertor->getRow('vBForum:node', array('nodeid' =>$routeInfo['nodeid']));
					$args['pageid'] = $this->makeChannelPage($routeInfo['routeid'], $node);
				}
				else
				{
					$node = $this->assertor->getRow('vBForum:node', array('nodeid' =>$routeInfo['nodeid']));
					$args['pageid'] = $this->makeConversationPage($routeInfo['routeid'], $node);
				}

				$result = $this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array ('routeid' => $routeInfo['routeid']),
					'arguments' => serialize($args)) );
				$routeInfo['arguments'] = serialize($args);
			}

			$this->fixPageTemplate($routeInfo);
			$this->assertor->assertQuery('vBAdmincp:deleteDupChannelPages', array('routeid' => $routeInfo['routeid'],
				'pageid' => $args['pageid']));

		}
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getPagesWithBadRoutes', array());
		$pageids = array();
		foreach($routeQry AS $routeInfo)
		{
			$pageids[] = $routeInfo['pageid'];
		}

		if (!empty($pageids))
		{
			$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'pageid' => $pageids));
			$this->messages[] = array('status', $this->fetchPhrase('deleting_unmatched_pages_x', array(implode(', ', $pageids))));
		}
	}

	/**
	 * checks and if necessary creates a new pagetemplate record
	 * @param $routeInfo
	 *
	 */
	protected function fixPageTemplate($routeInfo)
	{
		//note that it's possible we may have an invalid pagetemplate record, but in that case the admin should be able
		// to edit and save as a new pagetemplate record. So at least for now we're just making sure there is something
		// so the page displays.

		if (!empty($routeInfo['pagetemplateid']))
		{
			return true;
		}

		//We need to create a new record
		$args = unserialize($routeInfo['arguments']);

		if (!isset($args['channelid']))
		{
			$this->messages[] = array('error', $this->fetchPhrase('route_x_missing_channel', array($routeInfo['routeid'])));
			return;
		}
		$channel = vB_Library::instance('node') -> getNodeFullContent($args['channelid']);
		$channel = reset($channel);
		switch($channel['channeltype'])
		{
			case 'blog':
				$pageTemplateId = vB_Page::getBlogChannelPageTemplate();
				break;
			case 'article':
				$pageTemplateId = vB_Page::getArticleChannelPageTemplate();
				break;

			case 'group':
				if ($routeInfo['class'] == 'vB5_Route_Conversation')
				{
					$pageTemplateId = vB_Page::getSGChannelPageTemplate();
				}
				else
				{
					$pageTemplateId = vB_Page::getSGChannelPageTemplate();
				}
				break;

			default :
				if ($routeInfo['class'] == 'vB5_Route_Conversation')
				{
					$pageTemplateId = vB_Page::getConversPageTemplate();
				}
				else
				{
					$pageTemplateId = vB_Page::getChannelPageTemplate();
				}
		}

		$this->assertor->assertquery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, vB_dB_Query::CONDITIONS_KEY => array('pageid' => $routeInfo['pageid']) ,
				'pagetemplateid' => $pageTemplateId));
	}


	/**
	 * @param string $errno
	 * @param string $errstr
	 * @param string $errfile
	 * @param string $errline
	 */
	public function catchError($errno, $errstr, $errfile, $errline)
	{
		$errMessage = 'Error ' . $errstr . ', #' . $errno . ' in ' . $errfile . ', line ' .$errline;
		$this->messages[] = array('error', $this->fetchPhrase('error_x', array($errMessage)));
	}

	protected function fixPounds()
	{
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getForumRoutes', array());

		foreach ($routeQry AS $routeRec)
		{
			if (substr($routeRec['prefix'], 0, 1) == '#')
			{
				$this->removePound($routeRec);
			}
		}

	}


	protected function checkSearchRoute()
	{
		$this->connectRouteToPage('vbulletin-4ecbdacd6aa3b7.75359902', 'vbulletin-4ecbdac82f2815.04471586', 'search');
	}

	/**
	 * @param mixed	record from the route Query
	 */
	protected function checkAdvancedSearchRoute()
	{
		$this->connectRouteToPage('vbulletin-4ecbdacd6a8335.81846640', 'vbulletin-4ecbdac82efb61.17736147', 'advanced_search');

	}

	/**
	 * @param string	route guid
	 * @param string	page guid
	 * @param string	string to identify the route that could not be fixed. It should be a phrase key.
	 */
	protected function connectRouteToPage($routeGuid, $pageGuid, $identKey)
	{
		$route = $this->assertor->getRow('routenew', array('guid' => $routeGuid));

		if (empty($route) OR !empty($route['errors']))
		{
			foreach ($this->routes['route']  AS $defaultRoute)
			{
				if ($defaultRoute['guid'] == $routeGuid)
				{
					$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
						'guid' => $routeGuid, 'name' => $defaultRoute['name'], 'prefix' => $defaultRoute['prefix'],
						'regex' => $defaultRoute['regex'], 'class' => $defaultRoute['class'],
						'controller' => $defaultRoute['controller'], 'action' => $defaultRoute['action'],
						'arguments' => $defaultRoute['arguments']));
					$route =   $this->assertor->getRow('routenew', array('guid' => $routeGuid));
				}

			}
			if (empty($route) OR !empty($route['errors']))
			{
				$type = $this->fetchPhrase($identKey);
				$this->messages[] = array('status', $this->fetchPhrase('cannot_fix_x_y_z_need_a', array($type, $pageGuid, 'routenew', $routeGuid)));
				return;
			}
		}
		$page = $this->assertor->getRow('page', array('guid' => $pageGuid));

		if (empty($page) OR !empty($page['errors']))
		{
			foreach ($this->pages['page']  AS $defaultPage)
			{
				if ($defaultPage['guid'] == $pageGuid)
				{
					$pageTemplate = $this->assertor->getRow('pageTemplate', array('guid' => $defaultPage['pageTemplateGuid']));

					if (!empty($pageTemplate) AND empty($pageTemplate['errors']))
					{
						$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
							'guid' => $pageGuid, 'pagetemplateid' => $pageTemplate['pagetemplateid'], 'routeid' => $route['routeid'],
							'parentid' => 0, 'metaDescription' => $defaultPage['metaDescription'], 'moderatorid' => $defaultPage['moderatorid'],
							'displayorder' => $defaultPage['displayorder'], 'pagetype' => $defaultPage['pagetype'],
							'title' => $defaultPage['title']));
						$page =  $this->assertor->getRow('page', array('guid' => $pageGuid));
					}

				}

			}
			if (empty($page) OR !empty($page['errors']))
			{
				$type = $this->fetchPhrase($identKey);
				$this->messages[] = array('status', $this->fetchPhrase('cannot_fix_x_y_z_need_a', array($type, $routeGuid, 'page', $pageGuid)));
				return;
			}
		}

		if ($page['routeid'] != $route['routeid'])
		{
			$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array('pageid' => $page['pageid']), 'routeid' => $route['routeid']));
		}

		$arguments = unserialize($route['arguments']);

		if ($page['pageid'] != $arguments['pageid'])
		{
			$arguments['pageid'] = $page['pageid'];
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array('routeid' => $route['routeid']), 'arguments' => $arguments));
		}
		$this->checkPageTemplate($page);
		$this->makeRouteGuidUnique($route['routeid'], $routeGuid);
	}

	/**
	 * @param mixed		can be an int pageid or a record from the page table.
	 */
	protected function checkPageTemplate($page)
	{
		if (!is_array($page))
		{
			$page = $this->assertor->getRow('page', array('pageid' => $page));

			if (empty($page) OR !empty($page['errors']))
			{
				return false;
			}

		}
		$pageTemplate = $this->assertor->getRow('pagetemplate', array('pagetemplateid' => $page['pagetemplateid']));

		if (!empty($pageTemplate) AND empty($pageTemplate['errors']))
		{
			return true;
		}


		foreach ($this->pages['page']  AS $defaultPage)
		{
			if ($defaultPage['guid'] == $page['guid'])
			{
				$pageTemplate = $this->assertor->getRow('pageTemplate', array('guid' => $defaultPage['pageTemplateGuid']));

				if (!empty($pageTemplate) AND empty($pageTemplate['errors']))
				{
					$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'pageid' => $page['pageid'], 'pagetemplateid' => $pageTemplate['pagetemplateid']));
				}

			}

		}

	}

	protected function checkConversationRoutes()
	{
		//We get a list of all channel and conversation routes. They should be in pairs, matched by prefix.
		//So it's just:get a channel route.  Is the next one a conversation route with the same prefix?  If not,
		//get the channel.  If the channel is not a category,
		//create a new conversation route.  Now get the next channel route.
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getConversationRouteMatch', array());
		$nodeLib = vB_Library::instance('node');
		foreach ($routeQry  AS $routeMatch)
		{
			if (empty($routeMatch['convrouteid']))
			{
				//That means there is a channel route but no matching conversation route. If the node is a category that's correct.
				$arguments = unserialize($routeMatch['arguments']);

				if (empty($arguments['channelid']))
				{
					continue;
				}
				$channel = $nodeLib->getNodeBare($arguments['channelid']);

				if (empty($channel))
				{
					continue;
				}
				$channel = $this->assertor->getRow('vBForum:channel', array('nodeid' => $arguments['channelid']));

				if ($channel['category'] != 1)
				{
					$this->createConversationRoute($routeMatch);
				}
			}
			else
			{
				if ($routeMatch['convregex'] != preg_quote($routeMatch['prefix']) . '/'. vB5_Route_Conversation::REGEXP)
				{
					$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'routeid' => $routeMatch['convrouteid'], 'regex' => preg_quote($routeMatch['prefix']) . '/'. vB5_Route_Conversation::REGEXP));
					$this->messages[] = array('status', $this->fetchPhrase('correcting_conversation_regex_x', array($routeMatch['prefix'])));
				}
			}
		}

	}

	protected function clearBadRedirects()
	{
		// if we have a route that redirects to a route that doesn't exist, we have a choice. If the route looks valid we can
		// remove the redirect.  Or if the route is bad we delete it.
		$routes = $this->assertor->assertQuery('vBAdmincp:getBadRedirects', array());

		$clears = array();
		$deletes = array();
		foreach($routes AS $route)
		{
			//if it's a channel or conversation route we can at least make sure it's valid.
			if ($route['class'] == 'vB5_Route_Channel')
			{
				$arguments = unserialize($route['arguments']);

				if (empty($arguments['channelid']))
				{
					$deletes[] = $route['routeid'];
				}
				else
				{
					$check = $this->assertor->getRow('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $arguments['channelid']));

					if (!empty($check) AND empty ($check['errors']) AND ($check['contenttypeid'] == vB_Types::instance()->getContentTypeId('vBForum_Channel')))
					{
						$clears[] = $route['routeid'];
					}
					else
					{
						$deletes[] = $route['routeid'];
					}
				}
			}
			else if ($route['class'] == 'vB5_Route_Conversation')
			{
				$arguments = unserialize($route['arguments']);

				if (empty($arguments['nodeid']))
				{
					$deletes[] = $route['routeid'];
				}
				else
				{
					$check = $this->assertor->getRow('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $arguments['nodeid']));

					if (!empty($check) AND empty($check['errors']) AND ($check['contenttypeid'] == vB_Types::instance()->getContentTypeId('vBForum_Channel')))
					{
						$clears[] = $route['routeid'];
					}
					else
					{
						$deletes[] = $route['routeid'];
					}
				}
			}
			else
			{
				//All we can do is clear the redirect and hope it works.
				$clears[] = $route['routeid'];
			}
		}
		unset($routes);

		if (!empty($clears))
		{
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' => $clears, 'redirect301' => vB_dB_Query::VALUE_ISNULL));
		}
		if (!empty($deletes))
		{
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'routeid' => $deletes));
		}
	}

	protected function checkHomePage()
	{
		//Ensure the home page (nodeid 1) has the route with empty prefix.
		$routes = $this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'prefix' => ''), 'routeid');
		$page = $this->assertor->getRow('page', array('guid' => vB_Page::PAGE_HOME));

		$deleteRoutes = array();
		$currentRoute = false;
		foreach ($routes AS $route)
		{
			if (!empty($currentRoute) OR ($route['class'] !=  'vB5_Route_Channel'))
			{
				// There can only be one route with empty prefix.
				$deleteRoutes[] = $route['routeid'];
			}
			else
			{
				$currentRoute = $route;

			}
		}

		if (!empty($deleteRoutes))
		{
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'routeid' => $deleteRoutes));
		}


		if (empty($currentRoute))
		{
			$routeid = $this->createChannelRoute(1);
			$currentRoute = $this->assertor->getRow('routenew', array('routeid' => $routeid));
		}

		if (empty($currentRoute['routeid']))
		{
			$this->messages[] = array('error', $this->fetchPhrase('cannot_set_forum_home'));
			return false;
		}

		$updates = array();

		if (!empty($currentRoute['redirect301']))
		{
			$updates['redirect301'] = vB_dB_Query::VALUE_ISNULL;
		}
		$arguments = unserialize($currentRoute['arguments']);

		if (empty($arguments['channelid']) OR ($arguments['channelid'] != 1) OR empty($arguments['pageid']) OR ($arguments['pageid'] != $page['pageid']))
		{
			$arguments['channelid'] = 1;
			$arguments['pageid'] = $page['pageid'];
			$updates['arguments'] = serialize($arguments);
			$updates['contentid'] = 1;
		}

		if ($currentRoute['controller'] != 'page')
		{
			$updates['controller'] = 'page';
		}

		if ($currentRoute['action'] != 'index')
		{
			$updates['action'] = 'index';
		}

		if (!empty($updates))
		{
			$updates[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_UPDATE;
			$updates['routeid'] = $currentRoute['routeid'];
			$this->assertor->assertQuery('routenew', $updates);

		}
		$this->fixChannelRoute($currentRoute, 1, $page);
		$this->makeRouteGuidUnique($currentRoute['routeid'], $currentRoute['guid']);
		return true;
	}

	protected function checkForumHome()
	{
		//Ensure the forum home page (channel guid  vbulletin-4ecbdf567f2c35.70389590) has a non-empty prefix. Default is 'forum'.
		$channel = $this->assertor->getRow('vBForum:channel', array('guid' => 'vbulletin-4ecbdf567f2c35.70389590'));

		if (empty($channel['nodeid']))
		{
			$this->messages[] = array('status', $this->fetchPhrase('no_forum_home'));
			return(false);
		}
		$node = $this->assertor->getRow('vBForum:node', array('nodeid' => $channel['nodeid']));
		$route = $this->assertor->getRow('routenew', array('routeid' => $node['routeid'], 'class' => 'vB5_Route_Channel'));

		if (empty($route) OR !empty($route['errors']))
		{
			$routeid = $this->createChannelRoute($channel['nodeid']);
			$route = $this->assertor->getRow('routenew', array('routeid' => $routeid));
		}

		$this->messages[] = array('status', $this->fetchPhrase('have_route_x_for_node_y', array($route['routeid'], $channel['nodeid'])));

		if (empty($route['routeid']))
		{
			$this->messages[] = array('status', $this->fetchPhrase('cannot_set_forum_home'));
			return false;
		}

		$arguments = unserialize($route['arguments']);

		if (empty($arguments['channelid']) OR ($arguments['channelid'] != $channel['nodeid']))
		{
			$arguments['channelid'] = $channel['nodeid'];
			$arguments['nodeid'] = $channel['nodeid'];
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'routeid' => $route['routeid'], 'arguments' => serialize($arguments), 'contentid' => $channel['nodeid']));
		}

		if (empty($route['prefix']))
		{
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, vB_dB_Query::CONDITIONS_KEY => array('routeid' => $route['routeid']),
				'prefix' => 'forum'));
			$this->forumHomePrefix = 'forum';
		}
		else
		{
			$this->forumHomePrefix = $route['prefix'];
		}
		$page = $this->assertor->getRow('page', array('pageid' => $arguments['pageid']));

		$this->fixChannelRoute($route,$node['nodeid'], $page);
		$this->makeRouteGuidUnique($route['routeid'], $channel['nodeid']);
		return true;

	}

	protected function removePound($routeRec)
	{
		//we're only called in the route prefix starts with '#';
		$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' =>
			$routeRec['routeid'], 'prefix' => $this->forumHomePrefix . '/' . substr($routeRec['prefix'], 2)));
	}

	/***
	 *
	 * @param 	integer	channel nodeid for which we are creating a route
	 * @param	string	optional route prefix
	 *
	 * @return 	integer	routeid
	 */
	public function createChannelRoute($nodeid)
	{
		$nodeInfo = $this->assertor->getRow('vBForum:node', array('nodeid' => $nodeid));
		$channelInfo = $this->assertor->getRow('vBForum:channel', array('nodeid' => $nodeid));
		$routeinfo =  array('nodeid' => $nodeid);
		$routeinfo['prefix'] = vB5_Route_Channel::createPrefix($nodeInfo['parentid'], $nodeInfo['urlident'], true);
		$routeinfo['guid'] = vB_Xml_Export_Route::createGUID(array());
		// pageid is set below via makeChannelPage()
		$this->assertor->beginTransaction();

		try
		{
			$routeinfo['pageid'] = $this->makeChannelPage(0, $nodeInfo);
			$routeid = vB5_Route::createRoute('vB5_Route_Channel', $routeinfo);
			$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' => $routeid, 'pageid' => $routeinfo['pageid']));
		}
		catch (exception $e)
		{
			$this->assertor->rollbackTransaction();
			$this->messages[] = array('exception', $e->getMessage());
			return false;
		}

		if (is_numeric($routeid)  AND intval($routeid))
		{
			$this->assertor->commitTransaction();
			$this->messages[] = array('status', $this->fetchPhrase('created_route_for_x', array($nodeid)));
			$this->messages[] = array('status',$this->fetchPhrase('updating_route_x_to_y', array($routeid, $nodeid)));
			$this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'nodeid' => $nodeid, 'routeid' => $routeid ));
		}
		else
		{
			$this->messages[] = array('status', $this->fetchPhrase('failed_to_create_channel_route_for_x', array($nodeid)));
			$this->assertor->rollbackTransaction();
			return false;
		}

		return $routeid;
	}

	/**
	 * @param 	integer	primary key from routenew table
	 * @param mixed		node record
	 * @return	either an integer or an error array
	 *
	 */
	protected function makeChannelPage($routeid, $node)
	{
		// Create phrases for page of channel title
		$guid = vB_Xml_Export_Page::createGUID(array());
		$this->createPagePhrases($node['title'], $node['description'], $guid);

		//This is a bit annoying.  The createRoute function won't let you create a route until you have a page,
		// and the page needs the routeid.  So if we don't have a routeid let's just stick in a number- say 99999- for pageid and fix it later
		if (empty($routeid))
		{
			$routeid = 99999;
		}

		// It appears that *channel* pages need to be pagetype="custom" and
		// *channel conversation* pages need to be pagetype="default".
		// This matches what the previous behavior of upgrade_final step_11
		// (before VBV-14725 was fixed), and what happens when you create a
		// channel in the Admin CP.
		// Compare to makeConversationPage() in this class
		return $this->assertor->assertQuery('page', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'routeid' => $routeid,
			'title' => $node['title'],
			'pagetemplateid' => vB_Page::getChannelPageTemplate(),
			'parentid' => 0,
			'pagetype' => vB_Page::TYPE_CUSTOM,
			'product' => 'vbulletin',
			'guid' => $guid,
		));
	}

	/**
	 * @param array		route record for the matching vB5_Route_Channel record
	 */
	public function createConversationRoute($channelRoute)
	{
		$channelArgs = unserialize($channelRoute['arguments']);
		$nodeInfo = $this->assertor->getRow('vBForum:node', array('nodeid' => $channelArgs['channelid']));
		$routeinfo = array(
			'channelid' => $channelArgs['channelid'],
			// pageid is set below via makeConversationPage()
			//'prefix' => $channelRoute['prefix'],	// pre-baking a prefix in is only allowed for custom URLs.
			'guid' => vB_Xml_Export_Route::createGUID(array()),
		);
		$this->assertor->beginTransaction();

		try
		{
			$routeinfo['pageid'] = $this->makeConversationPage(0, $nodeInfo);
			$routeid = vB5_Route::createRoute('vB5_Route_Conversation', $routeinfo);
			$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' => $routeid, 'pageid' => $routeinfo['pageid']));

			if (is_numeric($routeid)  AND intval($routeid))
			{
				$this->assertor->commitTransaction();
				$this->assertor->assertQuery('vBAdmincp:fixChildNodeRoutes', array('nodeid' => $channelArgs['channelid'], 'routeid' => $routeid ));
			}
			else
			{
				$this->messages[] = array('status', $this->fetchPhrase('failed_to_create_conversation_route_for_x', array($channelRoute['routeid'])));
				$this->assertor->rollbackTransaction();
				return false;
			}
		}
		catch (exception $e)
		{
			$this->assertor->rollbackTransaction();
			$this->messages[] = array('exception', $e->getMessage());
			return false;
		}

		return $routeid;
	}


	/**
	 * @param int 		routeid
	 * @param mixed		node record
	 * @return int		pageid of new page
	 *
	 */
	protected function makeConversationPage($routeid, $node)
	{
		$guid = vB_Xml_Export_Page::createGUID(array());
		$this->createPagePhrases($node['title'], $node['description'], $guid);

		//This is a bit annoying.  The createRoute function won't let you create a route until you have a page,
		// and the page needs the routeid.  So if we don't have a routeid let's just stick in a number- say 99999- for pageid and fix it later
		if (empty($routeid))
		{
			$routeid = 99998;
		}

		// It appears that *channel* pages need to be pagetype="custom" and
		// *channel conversation* pages need to be pagetype="default".
		// This matches what the previous behavior of upgrade_final step_11
		// (before VBV-14725 was fixed), and what happens when you create a
		// channel in the Admin CP.
		// Compare to makeChannelPage() in this class
		return $this->assertor->assertQuery('page', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'routeid' => $routeid,
			'title' => $node['title'],
			'pagetemplateid' => vB_Page::getConversPageTemplate(),
			'parentid' => 0,
			'pagetype' => vB_Page::TYPE_DEFAULT,
			'product' => 'vbulletin',
			'guid' => $guid,
		));
	}

	/**
	 * @param 	string	title of channel
	 * @param 	string	description of channel
	 * @param 	string	page guid
	 */
	protected function createPagePhrases($title, $description, $guid)
	{
		$guidforphrase = vB_Library::instance('phrase')->cleanGuidForPhrase($guid);

		$this->phraseLib->save('pagemeta',
			'page_' . $guidforphrase . '_title',
			array(
				'text' => array($title),
				'ismaster' => 1,
				'product' => 'vbulletin',
				't' => 0,
				'oldvarname' => 'page_' . $guidforphrase . '_title',
				'oldfieldname' => 'global',
			)
		);
		$this->phraseLib->save('pagemeta',
			'page_' . $guidforphrase . '_metadesc',
			array(
				'text' => array($description),
				'ismaster' => 1,
				'product' => 'vbulletin',
				't' => 0,
				'oldvarname' => 'page_' . $guidforphrase . '_metadesc',
				'oldfieldname' => 'global',
			)
		);
	}

	protected function deleteUnusedRoutes()
	{
		//Delete any routes that aren't used by any nodes.
		$routeQry = $this->assertor->assertQuery('vBAdmincp:getUnmatchedRoutes', array());
		$deleteRoutes = array();

		foreach ($routeQry AS $routeRec)
		{
			$arguments = unserialize($routeRec['arguments']);

			//if it's a valid redirect, leave it.
			if (!empty($routeRec['redirect301']))
			{
				$redirected = $this->assertor->getRow('routenew', array('routeid' => $routeRec['redirect301']));
				if (empty($redirected) OR !empty($redirected['errors']))
				{
					$deleteRoutes[] = $routeRec['routeid'];
				}

			}
			else if (empty($arguments['channelid']))
			{
				$deleteRoutes[] = $routeRec['routeid'];
			}
			else
			{
				$node = $this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $arguments['channelid']));

				if (!$node->valid())
				{
					$deleteRoutes[] = $routeRec['routeid'];
				}
			}
		}

		if (!empty($deleteRoutes))
		{
			$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'routeid' => $deleteRoutes));
			$this->messages[] = array('status', $this->fetchPhrase('just_deleted_routes_x', array(implode(', ', $deleteRoutes))));
		}
	}

	/**
	 * @param mixed		route table record
	 * @param mixed		node table record
	 * @param mixed 	page table record
	 *
	 */
	protected function fixChannelRoute($route, $nodeid, $page = false)
	{
		$node = vB_Library::instance('node')->getNodeBare($nodeid);

		if ($node['routeid'] != $route['routeid'])
		{
			if (array_key_exists($node['nodeid'], $this->fixedNodes))
			{
				$this->messages[] = array('status', $this->fetchPhrase('conflict_with_node_x', array($nodeid)));
			}
			else
			{
				$this->messages[] = array('status',  $this->fetchPhrase('correcting_route_for_node_x', array($nodeid)));
				$this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' => $route['routeid'], 'nodeid' => $node['nodeid']));
				$this->fixedNodes[$node['nodeid']] = $node['nodeid'];
			}
		}

		if (empty($route['arguments']))
		{
			$this->messages[] = array('status',  $this->fetchPhrase('route_x_missing_argument', array($route['routeid'])));
			return;
		}

		if (empty($page))
		{
			$pageid = $this->makeChannelPage($route['routeid'], $node);
			$this->messages[] = array('status',$this->fetchPhrase('created_page_for_route_x', array($route['routeid'])));
			$this->fixedPages[$page['pageid']] = $page['pageid'];
		}
		else if (($page['routeid'] != $route['routeid']))
		{
			if (array_key_exists($page['pageid'], $this->fixedPages))
			{
				$this->messages[] = array('status',  $this->fetchPhrase('conflict_with_page_x', array($page['pageid'])));
			}
			else
			{
				$this->messages[] = array('status',$this->fetchPhrase('correcting_route_for_page_x', array($page['pageid'])));
				$this->assertor->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'routeid' => $route['routeid'],
					vB_dB_Query::CONDITIONS_KEY => array('pageid' => $page['pageid'])));
				$this->fixedPages[$page['pageid']] = $page['pageid'];
			}
		}
	}

	protected function getDefaults()
	{
		if (file_exists(DIR . '/install/vbulletin-channels.xml'))
		{
			$this->xmlLocation = DIR . '/install/';
		}
		else
		{
			$this->xmlLocation = dirname(__FILE__) . '/';
		}

		$this->channels = vB_Xml_Import::parseFile($this->xmlLocation . 'vbulletin-channels.xml');
		$this->pages = vB_Xml_Import::parseFile($this->xmlLocation . 'vbulletin-pages.xml');
		$this->routes = vB_Xml_Import::parseFile($this->xmlLocation . 'vbulletin-routes.xml');
		//reload the page template file
		$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', 0);
		$xml_importer->importFromFile($this->xmlLocation . 'vbulletin-pagetemplates.xml');

		foreach ($this->routes['route'] AS $route)
		{
			if (!empty($route['arguments']))
			{
				$args = unserialize($route['arguments']);

				if (isset($args['channelGuid']) AND ($args['channelGuid'] == vB_Channel::MAIN_CHANNEL))
				{
					$this->defaultChannelRoute = $route;

					foreach ($this->pages['page'] AS $page)
					{
						if ($page['guid'] == $args['pageGuid'])
						{
							$this->defaultChannelPage = $page;
							break;
						}
					}
					break;
				}
			}
		}
	}


	/**
	 * @param int routeid
	 * @param string route guid
	 *
	 */
	protected function makeRouteGuidUnique($routeid, $guid)
	{
		$duplicates = $this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => $guid)));
		$updates = array();

		foreach ($duplicates AS $duplicate)
		{
			//If you update immediately you are likely to confuse the mysql engine.  Better to get the list first, then update.
			if ($duplicate['routeid'] != $routeid)
			{
				$updates[] = $duplicate['routeid'];
			}
		}
		if (!empty($updates))
		{
			foreach ($updates AS $updateRoute)
			{
				$newGuid = vB_Xml_Export_Route::createGUID(array());
				$this->messages[] = array('status', $this->fetchPhrase('created_new_route_guid_x_for_y', array($newGuid, $updateRoute)));
				$this->assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'guid' => $newGuid,
					vB_dB_Query::CONDITIONS_KEY => array('routeid' => $updateRoute)));
			}
		}

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
