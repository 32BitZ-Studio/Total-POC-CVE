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

class vB5_Frontend_Controller_Ajax extends vB5_Frontend_Controller
{
	/*
	 *	Much of what this controller nominally handles is currently
	 *	handled by applicationlight internally.  We should rework
	 *	application light to handle routing/call controllers explicitly
	 *	but currently this controller needs work before that's possible
	 *	(in particular we need to make changes so that the actions handle
	 *	their own output rather than rely in the index method to do it
	 *	for them, especially since its no longer a one size fits all
	 *	issue).
	 *
	 *	(This includes the apidetach action not found here)
	 */


	// NOTE:
	// ajax/api/* is now handled by application light
	// ajax/render/* is now handled by application light


	/**
	 * Handles all calls to /ajax/* and routes them to the correct method in
	 * this controller, then sends the result as JSON.
	 *
	 * @param	string	Route
	 */
	public function index($route)
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		ob_start();
		$route = trim(strval($route), '/');
		$segments = explode('/', $route);

		// change method-name to actionMethodName
		$method = array_shift($segments);
		$method = preg_replace_callback('#-(.)#',
			function ($matches)
			{
				return strtoupper($matches[1]);
			}, strtolower($method)
		);
		$method = 'action' . ucfirst($method);

		if (method_exists($this, $method))
		{
			$returnValue = call_user_func_array(array($this, $method), $segments);
		}
		else
		{
			exit('Invalid AJAX method called');
		}
		$errors = trim(ob_get_clean());
		if (!empty($errors))
		{
			if (!is_array($returnValue))
			{
				$returnValue = array($returnValue);
				$returnValue['wasNotArray'] = 1;
			}

			if (empty($returnValue['errors']))
			{
				$returnValue['errors'] = array();
			}
			array_push($returnValue['errors'], $errors);
		}
		$this->sendAsJson($returnValue);
	}

	/**
	 * Ajax calls to /ajax/call/[controller]/[method] allow calling a
	 * presentation controller
	 *
	 * @param	string	API controller
	 * @param	string	API method
	 *
	 * @param	mixed	The return value of the API call
	 */
	public function actionCall($controller, $method)
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (!empty($controller))
		{
			$args = array_merge($_GET, $_POST);
			$class = 'vB5_Frontend_Controller_' . ucfirst($controller);

			// TODO: This is a temporary fix for VBV-4731. Only 'action' methods can be called from ajax/call
			if (strpos($method, 'action') !== 0)
			{
				$method = 'action' . $method;
			}

			if (!class_exists($class) || !method_exists($class, $method))
			{
				return null;
			}
			else
			{
				$object = new $class;
			}

			$reflection = new ReflectionMethod($object, $method);

			if($reflection->isConstructor() || $reflection->isDestructor() || $reflection->isStatic() )
			{
				return null;
			}

			$php_args = array();
			foreach($reflection->getParameters() as $param)
			{
				if(isset($args[$param->getName()]))
				{
					$php_args[] = &$args[$param->getName()];
				}
				else
				{
					if ($param->isDefaultValueAvailable())
					{
						$php_args[] = $param->getDefaultValue();
					}
					else
					{
						throw new Exception('Required argument missing: ' . htmlspecialchars($param->getName()));
						return null;
					}
				}
			}

			return $reflection->invokeArgs($object, $php_args);
		}
		return null;
	}

	/**
	 * Renders a widget or screen layout admin template in the presentation layer and
	 * returns it as JSON
	 * Ajax calls should go to /ajax/admin-template/widget or /ajax/admin-template/screen-layout
	 *
	 * @param	string	The type of template requested (widget or screen-layout)
	 */
	public function actionAdminTemplate($type)
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ($type == 'widget')
		{
			$pagetemplateid = isset($_REQUEST['pagetemplateid']) ? intval($_REQUEST['pagetemplateid']) : 0;

			if (isset($_REQUEST['widgets']) AND is_array($_REQUEST['widgets']))
			{
				// requesting multiple widget admin templates
				$requestedWidgets = array();
				$requestedWidgetIds = array();
				$requestedWidgetInstanceIds = array();
				foreach ($_REQUEST['widgets'] AS $widget)
				{
					$widgetId = isset($widget['widgetid']) ? intval($widget['widgetid']) : 0;
					$widgetInstanceId = isset($widget['widgetinstanceid']) ? intval($widget['widgetinstanceid']) : 0;

					if ($widgetId < 1)
					{
						continue;
					}

					$requestedWidgets[] = array(
						'widgetid' => $widgetId,
						'widgetinstanceid' => $widgetInstanceId,
					);
					$requestedWidgetIds[] = $widgetId;
					$requestedWidgetInstanceIds[] = $widgetInstanceId;
				}

				$requestedWidgetIds = array_unique($requestedWidgetIds);
				$requestedWidgetInstanceIds = array_unique($requestedWidgetInstanceIds);

				if (!empty($requestedWidgetIds))
				{
					$widgets = Api_InterfaceAbstract::instance()->callApi('widget', 'fetchWidgets', array('widgetids' => $requestedWidgetIds));
				}
				else
				{
					$widgets = array();
				}

				if (!empty($requestedWidgetInstanceIds))
				{
					$widgetInstances = Api_InterfaceAbstract::instance()->callApi('widget', 'fetchWidgetInstances', array('widgetinstanceids' => $requestedWidgetInstanceIds));
				}
				else
				{
					$widgetInstances = array();
				}

				$widgetsOut = array();
				foreach ($requestedWidgets AS $requestedWidget)
				{
					if (!isset($widgets[$requestedWidget['widgetid']]))
					{
						continue;
					}

					$widget = $widgets[$requestedWidget['widgetid']];

					// we may want to pull the whole widget instance and send it to the template if needed
					$widget['widgetinstanceid'] = $requestedWidget['widgetinstanceid'];

					$templateName = empty($widget['admintemplate']) ? 'widget_admin_default' : $widget['admintemplate'];
					$templater = new vB5_Template($templateName);
					$templater->register('widget', $widget);

					if (isset($widgetInstances[$widget['widgetinstanceid']]) AND is_array($widgetInstances[$widget['widgetinstanceid']]))
					{
						$widgetInstance = $widgetInstances[$widget['widgetinstanceid']];
						$displaySection = $widgetInstance['displaysection'] >= 0 ? $widgetInstance['displaysection'] : 0;
						$displayOrder = $widgetInstance['displayorder'] >= 0 ? $widgetInstance['displayorder'] : 0;
					}
					else
					{
						$displaySection = $displayOrder = 0;
					}

					$widgetsOut[] = array(
						'widgetid'         => $widget['widgetid'],
						'widgetinstanceid' => $widget['widgetinstanceid'],
						'displaysection'   => $displaySection,
						'displayorder'     => $displayOrder,
						'pagetemplateid'   => $pagetemplateid,
						'template'         => $templater->render(),
					);
				}

				$output = array(
					'widgets'        => $widgetsOut,
					'pagetemplateid' => $pagetemplateid,
				);
			}
			else
			{
				// requesting one widget admin template
				$widgetid = isset($_REQUEST['widgetid']) ? intval($_REQUEST['widgetid']) : 0;
				$widgetinstanceid = isset($_REQUEST['widgetinstanceid']) ? intval($_REQUEST['widgetinstanceid']) : 0;

				$widget = Api_InterfaceAbstract::instance()->callApi('widget', 'fetchWidget', array('widgetid' => $widgetid));

				// we may want to pull the whole widget instance and send it to the template if needed
				$widget['widgetinstanceid'] = $widgetinstanceid;

				$templateName = empty($widget['admintemplate']) ? 'widget_admin_default' : $widget['admintemplate'];
				$templater = new vB5_Template($templateName);
				$templater->register('widget', $widget);

				$output = array(
					'widgetid'         => $widgetid,
					'widgetinstanceid' => $widgetinstanceid,
					'pagetemplateid'   => $pagetemplateid,
					'template'         => $templater->render(),
				);
			}

			return $output;
		}
		else if ($type == 'screen-layout')
		{
			// @todo implement this
		}
	}

	/**
	 * Returns the widget admin template
	 *
	 * Ajax calls should go to /ajax/fetch-widget-template
	 *
	 * @param	string	The type of template requested (widget or screen-layout)
	 */
	public function actionFetchWidgetTemplate()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();

		$widgetId = intval($_POST['widgetid']);

		$widget = $api->callApi('widget', 'fetchWidget', array($widgetId));

		$templateName = empty($widget['admintemplate']) ? 'widget_admin_default' : $widget['admintemplate'];
		$templater = new vB5_Template($templateName);
		$templater->register('widget', $widget);

		try
		{
			$template = $templater->render();
		}
		catch (Exception $e)
		{
			$template = FALSE;
		}

		return $template;
	}

	/**
	 * Returns an array of widget objects which include some of the widget information available
	 * via the widget-fetchWidgets API call *and* the rendered admin template to display the
	 * widget on the page canvas when editing a page template. The widget admin template
	 * is rendered here (client side)
	 *
	 * Ajax calls should go to /ajax/fetch-widget-admin-template-list
	 *
	 * @param	string	The type of template requested (widget or screen-layout)
	 */
	public function actionFetchWidgetAdminTemplateList()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();

		if (isset($_POST['widgetids']) AND is_array($_POST['widgetids']))
		{
			$widgetids = array_map('intval', $_POST['widgetids']);
			$widgetids = array_unique($widgetids);
		}
		else
		{
			$widgetids = array(); // retrieve all widgets
		}

		// second param is removeNonPlaceableWidgets = true
		// this removes the System and Abstract widgets
		// (System widgets only removed when not in debug mode)
		$widgets = $api->callApi('widget', 'fetchWidgets', array($widgetids, true));

		// adding array_values here because the api call returns the widgets indexed
		// by the widgetid, and this function (actionFetchWidgetAdminTemplateList) was
		// previously returning the widgets with an incrementing numeric index
		// this may not be necessary, but for the moment I want to avoid any potential
		// problems that may arise from changing the return value
		return array_values($widgets);
	}

	/**
	 * Replace securitytoken
	 *
	 */
	public function actionReplaceSecurityToken()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userinfo = vB_User::fetchUserinfo();

		return array('newtoken' => $userinfo['securitytoken']);
	}

	/**
	 * Returns the sitebuilder template markup required for using sitebuilder
	 *
	 * @param	int	The page id
	 */
	public function actionActivateSitebuilder()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();
		$canuse = $api->callApi('user', 'hasPermissions', array('adminpermissions', 'canusesitebuilder'));
		if(isset($canuse['errors']))
		{
			return $canuse;
		}

		if(!$canuse)
		{
			return array('errors' => array(array('inlinemodauth_required')));
		}

		$sb = array();
		$pageId = isset($_REQUEST['pageid']) ? intval($_REQUEST['pageid']) : 0;
		if ($pageId > 0)
		{
			//should change this to take the route data regardless of what it is to
			//avoid further breakage for other information we may store with a route.
			$arguments = array(
				'pageid'	=>	$pageId,
				'nodeid' 	=>	isset($_REQUEST['nodeid']) ? intval($_REQUEST['nodeid']) : 0,
				'userid' 	=>	isset($_REQUEST['userid']) ? intval($_REQUEST['userid']) : '',
			);

			$page = $api->callApi('page', 'fetchPageById', array($pageId, $arguments));

			$loadMenu = !empty($_REQUEST['loadMenu']);

			if ($page)
			{
				$router = vB5_ApplicationAbstract::instance()->getRouter();
				$page['routeInfo'] = array(
					'routeId' => $router->getRouteId(),
					'arguments'	=> $arguments
				);

				//we should explicitly pass and clean the arguments from the request array
				//this previously blindly copied the query string over to the page array whic
				//is bad mojo (especially if things don't get properly cleaned).
				foreach ($arguments AS $key => $value)
				{
					$page[$key] = $value;
				}

				$templates = array(
					'css' => '',
					'menu' => '',
					'main' => '',
					'extra' => '',
				);

				if ($loadMenu)
				{
					$templates['css'] = vB5_Template::staticRenderAjax('stylesheet_block', array(
						'cssFiles' => array('sitebuilder-after.css'),
					));

					$templates['menu'] = vB5_Template::staticRenderAjax('admin_sitebuilder_menu');
				}

				$templates['main'] = vB5_Template::staticRenderAjax('admin_sitebuilder', array(
					'page' => $page,
				));


				// output
				$sb['templates'] = array();
				$sb['css_links'] = array();
				foreach ($templates AS $key => $value)
				{
					if (!empty($value))
					{
						$sb['templates'][$key] = $value['template'];
						$sb['css_links'] = array_merge($sb['css_links'], $value['css_links']);
					}
				}
			}
		}

		return $sb;
	}

	/**
	 * Get layouts and modules for the sitebuilder layout UI.
	 *
	 * @return array Array of layout and widget info & templates:
	 *               'screenlayoutlist' - rendered screenlayouts to insert in DOM
	 *               'widgets' - array of widgets with rendered widget admin template
	 *               'css_links' - any css links needed to display rendered templates
	 */
	public function actionGetLayoutsForSitebuilder()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$pagetemplateid = (int) isset($_REQUEST['pagetemplateid']) ? $_REQUEST['pagetemplateid'] : 0;
		$channelid = (int) isset($_REQUEST['channelid']) ? $_REQUEST['channelid'] : 0;

		$css_links = array();
		// If user has canusesitebuilder permission, it will return all modules, ignoring
		// the instance usergroup view checks, so the admin can edit the modules even if they
		// accidentally locked themselves out of that module.
		$admincheck = true;
		$widgets = Api_InterfaceAbstract::instance()->callApi('widget', 'fetchHierarchicalWidgetInstancesByPageTemplateId', array('pagetemplateid' => $pagetemplateid, 'channelid' => $channelid, 'admincheck' => $admincheck));

		foreach ($widgets AS $sectionnumber => $sectionwidgets)
		{
			// this adds the 'rendered_template' to each widget (including
			// any subModules), and populates the $css_links array
			// if there are any CSS links.
			$this->addRenderedWidgetAdminTemplates($widgets[$sectionnumber], $css_links);
		}

		$screenlayouttemplate = vB5_Template::staticRenderAjax('screenlayout_screenlayoutlist');

		return array(
			'screenlayoutlist' => $screenlayouttemplate['template'],
			'widgets' => $widgets,
			'css_links' => $css_links,
		);
	}

	/**
	 * Renders the admin template for each widget and adds it to the passed widget array.
	 * Handles recursive 'subModules' as well.
	 *
	 * @param	array	Reference to an array of widgets (this array is modified)
	 * @param	array	Reference to an array of css links (this array is modified)
	 */
	protected function addRenderedWidgetAdminTemplates(array &$widgets, array &$css_links)
	{
		foreach ($widgets AS $key => $widget)
		{
			// add template & css links
			$template = !empty($widget['admintemplate']) ? $widget['admintemplate'] : 'widget_admin_default';
			$rendered = vB5_Template::staticRenderAjax($template, array('widget' => $widget));
			$widgets[$key]['rendered_template'] = $rendered['template'];
			$css_links = array_merge($css_links, $rendered['css_links']);

			// handle any sub modules
			if (!empty($widget['subModules']) AND is_array($widget['subModules']))
			{
				$this->addRenderedWidgetAdminTemplates($widgets[$key]['subModules'], $css_links);
			}
		}
	}

	/**
	 * Posts a comment to a conversation reply.
	 *
	 */
	public function actionPostComment()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$results = array();
		$input = array(
			'text' => (isset($_POST['text']) ? trim(strval($_POST['text'])) : ''),
			'parentid' => (isset($_POST['parentid']) ? intval($_POST['parentid']) : 0),
			'postindex' => (isset($_POST['postindex']) ? intval($_POST['postindex']) : 1),
			'view'	=> (isset($_POST['view']) ? trim(strval($_POST['view'])) : 'thread'),
			'redirecturl' => (isset($_POST['redirecturl']) ? intval($_POST['redirecturl']) : 0),
			'isblogcomment' => (isset($_POST['isblogcomment']) ? intval($_POST['isblogcomment']) : 0),
			'isarticlecomment' => (isset($_POST['isarticlecomment']) ? intval($_POST['isarticlecomment']) : 0),
			'hvinput' => (isset($_POST['humanverify']) ? $_POST['humanverify'] : ''),
		);

		if ($input['parentid'] > 0)
		{
			$api = Api_InterfaceAbstract::instance();
			$user  = $api->callApi('user', 'fetchUserinfo', array());
			$textData = array(
				'parentid' => $input['parentid'],
				// when *editing* comments, it uses create-content/text
				// when *creating* comments, it uses ajax/post-comment
				// NOTE: Keep this in sync with
				//       vB5_Frontend_Controller_CreateContent:: index()
				//
				// htmlspecialchars and nl2br puts the text into the same state
				// it is when the text api receives input from ckeditor
				// specifically, newlines are passed as <br /> and any HTML tags
				// that are typed literally into the editor are passed as HTML-escaped
				// because non-escaped HTML that is sent is assumed to be formatting
				// generated by ckeditor and will be parsed & converted to bbcode.
				'rawtext' => nl2br($api->stringInstance()->htmlspecialchars($input['text'], ENT_NOQUOTES)),
				'userid' => $user['userid'],
				'authorname' => $user['username'],
				'created' => time(),
				'hvinput' => $input['hvinput'],
				'publishdate' => $api->callApi('content_text', 'getTimeNow', array())
			);

			$nodeId = $api->callApi('content_text', 'add', array($textData, array('skipUpdateLastContent' => 1)));

			if (is_int($nodeId) AND $nodeId > 0)
			{
				$node = $api->callApi('node', 'getNodeContent', array($nodeId));
				if ($node AND !isset($node['errors']))
				{
					$node = $node[$nodeId];

					if ($input['redirecturl'])
					{
						//send redirecturl to the client to indicate that it must redirect to the starter detail page after posting a comment to a reply
						$starterNode = $api->callApi('node', 'getNode', array($node['starter']));
						$results['redirecturl'] = vB5_Template_Options::instance()->get('options.frontendurl') .
							vB5_Route::buildUrl($starterNode['routeid'], $starterNode, array('view' => 'stream', 'p' => $nodeId)) . '#post' . $nodeId;
					}
					else
					{
						//get parent node
						$parentNode = $api->callApi('node', 'getNodeContent', array($input['parentid']));
						if (!empty($parentNode))
						{
							$parentNode = $parentNode[$input['parentid']];
						}

						/*
							Keep these params in sync with display_Comments template.
							The page & perpage values may not match up with the dynamic
							values set in the template, but those *shouldn't* matter
							for the totalCounts.
						*/
						$params = array(
							'parentid' => $input['parentid'],
							'page' => 1,
							'perpage' => 25,
							'depth' => 1,
							'contenttypeid' => null,
							'options' => array(
								'sort' => array(
									"created" => "DESC",
								),
								'nolimit' => 1,
							),
						);
						$callNamed = true;
						$count = $api->callApi('node', 'listNodeFullContentCount', $params, $callNamed);
						// Preserving old "no zero" behavior
						$totalComments = max($count['totalCount'], 1);

						// send subscribed info for updating the UI
						if (!empty($parentNode['starter']))
						{
							$topicSubscribed = $api->callApi('follow', 'isFollowingContent', array('contentId' => $parentNode['starter']));
						}
						else
						{
							$topicSubscribed = 0;
						}

						$templater = new vB5_Template('conversation_comment_item');
						$templater->register('conversation', $node);
						$templater->register('commentIndex', $totalComments);
						$templater->register('conversationIndex', $input['postindex']);
						$templater->register('parentNodeIsBlog', $input['isblogcomment']);
						$templater->register('parentNodeIsArticle', $input['isarticlecomment']);

						$enableInlineMod = (
							!empty($parentNode['moderatorperms']['canmoderateposts']) OR
							!empty($parentNode['moderatorperms']['candeleteposts']) OR
							!empty($parentNode['moderatorperms']['caneditposts']) OR
							!empty($parentNode['moderatorperms']['canremoveposts'])
						);
						$templater->register('enableInlineMod', $enableInlineMod);

						$results['template'] = $templater->render();
						$results['totalcomments'] = $totalComments;
						$results['nodeId'] = $nodeId;
						$results['topic_subscribed'] = $topicSubscribed;
					}
				}
				else
				{
					$node = $api->callApi('node', 'getNode', array($nodeId));
					if ($node AND empty($node['errors']))
					{
						if (empty($node['approved']))
						{
							$results['needmod'] = true;
						}
					}
				}
			}
			else
			{
				$results['errors'] = $nodeId['errors'];
			}
		}
		else
		{
			//this isn't proper, but I'm not sure it can happen without serious abuse.
			//should really rely on the API function to handle, but not sure it does
			//adequately.  Not worth creating a new phrase over but this at least gets
			//it into the proper return format.
			$results['errors'] = array('error_x', 'Cannot post comment.');
		}

		return $results;
	}

	/**
	 * Fetches comments of a conversation reply.
	 *
	 */
	public function actionFetchComments()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$results = array();
		$input = array(
			'parentid'			=> (isset($_POST['parentid']) ? intval($_POST['parentid']) : 0),
			'page'				=> (isset($_POST['page']) ? intval($_POST['page']) : 0),
			'postindex'			=> (isset($_POST['postindex']) ? intval($_POST['postindex']) : 1),
			'isblogcomment' 	=> (isset($_POST['isblogcomment']) ? intval($_POST['isblogcomment']) : 0),
			'isarticlecomment' 	=> (isset($_POST['isarticlecomment']) ? intval($_POST['isarticlecomment']) : 0),
			'widgetInstanceId'	=> (isset($_POST['widgetInstanceId']) ? intval($_POST['widgetInstanceId']) : 0),
		);
		if ($input['page'] == 0)
		{
			$is_default = true;
			$input['page'] = 1;
		}
		if ($input['parentid'] > 0)
		{
			$params = array(
				'parentid'			=> $input['parentid'],
				'page'				=> $input['page'],
				'perpage'			=> 25, // default to 25
				'depth'				=> 1,
				'contenttypeid'		=> null,
				'options'			=> array('sort' => array('created' => 'ASC'))
			);

			$api = Api_InterfaceAbstract::instance();

			// get comment perpage setting from widget config
			$widgetConfig = $api->callApi('widget', 'fetchConfig', array($input['widgetInstanceId']));
			$params['perpage'] = $commentsPerPage = !empty($widgetConfig['commentsPerPage']) ? $widgetConfig['commentsPerPage'] : 25;
			$initialCommentsPerPage = isset($widgetConfig['initialCommentsPerPage']) ? $widgetConfig['initialCommentsPerPage'] : 3;
			//get parent node's total comment count
			$parentNode = $api->callApi('node', 'getNodeContent', array($input['parentid']));
			$totalComments = 1;
			if ($parentNode)
			{
				$parentNode = $parentNode[$input['parentid']];
				$totalComments = $parentNode['textcount'];
			}
			$totalPages = ceil($parentNode['textcount'] / $commentsPerPage);
			// flip the pages, first page will have the oldest comments
			$params['page'] = $totalPages - $input['page'] + 1;
			if (!empty($is_default) AND $params['page'] == $totalPages AND ($rem =  $parentNode['textcount'] % $commentsPerPage) > 0 AND $rem <= $initialCommentsPerPage)
			{
				$params['page'] --;
			}
			$nodes = $api->callApi('node', 'listNodeContent', $params);
			if ($nodes)
			{

				$results['totalcomments'] = $totalComments;
				$results['page'] = $totalPages - $params['page'] + 1;
				$commentIndex = (($params['page'] - 1) * $params['perpage']) + 1;
				if ($commentIndex < 1)
				{
					$commentIndex = 1;
				}

				$enableInlineMod = (
					!empty($parentNode['moderatorperms']['canmoderateposts']) OR
					!empty($parentNode['moderatorperms']['candeleteposts']) OR
					!empty($parentNode['moderatorperms']['caneditposts']) OR
					!empty($parentNode['moderatorperms']['canremoveposts'])
				);

				$results['templates'] = array();
				$templater = new vB5_Template('conversation_comment_item');
//				$nodes = array_reverse($nodes, true);
				//loop backwards because we need to display the comments in ascending order
// 				for ($i = count($nodes) - 1; $i >= 0; $i--)
// 				{
// 					$node = $nodes[$i];
// 					$templater->register('conversation', $node['content']);
// 					$templater->register('commentIndex', $commentIndex);
// 					$templater->register('conversationIndex', $input['postindex']);
// 					$results['templates'][$node['nodeid']] = $templater->render();
// 					++$commentIndex;
// 				}

				foreach ($nodes as $node)
				{
					$templater->register('conversation', $node['content']);
					$templater->register('commentIndex', $commentIndex);
					$templater->register('conversationIndex', $input['postindex']);
					$templater->register('parentNodeIsBlog', $input['isblogcomment']);
					$templater->register('parentNodeIsArticle', $input['isarticlecomment']);
					$templater->register('enableInlineMod', $enableInlineMod);
					$results['templates'][$node['nodeid']] = $templater->render();
					++$commentIndex;
				}
				//$results['templates'] = array_reverse($results['templates'], true);
			}
			else
			{
				$results['error'] = 'Error fetching comments.';
			}
		}
		else
		{
			$results['error'] = 'Cannot fetch comments.';
		}

		return $results;
	}

	public function actionFetchHiddenModules()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();

		$result = array();

		if (isset($_POST['modules']) AND !empty($_POST['modules']))
		{
			$widgets = $api->callApi('widget', 'fetchWidgetInstanceTemplates', array($_POST['modules']));

			if ($widgets)
			{
				// register the templates, so we use bulk fetch
				$templateCache = vB5_Template_Cache::instance();
				foreach($widgets AS $widget)
				{
					$templateCache->register($widget['template'], array());
				}

				// now render them
				foreach($widgets AS $widget)
				{
					$result[] = array(
						'widgetinstanceid' => $widget['widgetinstanceid'],
						'template' => vB5_Template::staticRender($widget['template'], array(
							'widgetid' => $widget['widgetid'],
							'widgetinstanceid' => $widget['widgetinstanceid'],
							'isWidget' => 1,
						))
					);
				}
			}
		}

		return $result;
	}

	/**
	 * Fetch node's preview
	 *
	 */
	public function actionFetchNodePreview()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$preview = '';
		// nodeid can come in via query string, see qtip.js's initializeTopicPreviews() function
		$nodeid = isset($_REQUEST['nodeid']) ? intval($_REQUEST['nodeid']) : array();

		if (!empty($nodeid))
		{
			if (!vb::getUserContext()->getChannelPermission('forumpermissions', 'canviewthreads', $nodeid))
			{
				return '';
			}

			$contenttypes = vB_Types::instance()->getContentTypes();
			$typelist = array();
			foreach ($contenttypes as $key => $type)
			{
				$typelist[$type['id']] = $key;
			}

			$api = Api_InterfaceAbstract::instance();
			$contentTypes = array('vBForum_Text', 'vBForum_Gallery', 'vBForum_Poll', 'vBForum_Video', 'vBForum_Link', 'vBForum_Event');

			$nodes = $api->callApi('node', 'getNodeContent', array($nodeid));
			$node = $nodes[$nodeid];
			$contentType = $typelist[$node['contenttypeid']];

			if (in_array($contentType, $contentTypes))
			{
				$preview = vB5_Template_NodeText::instance()->fetchOneNodePreview($nodeid, $api);
			}

			$previewLength = vB5_Template_Options::instance()->get('options.threadpreview');
			if (strlen($preview) > $previewLength)
			{
				$preview = substr($preview, 0, $previewLength);
			}
		}

		return $preview;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101443 $
|| #######################################################################
\*=========================================================================*/
