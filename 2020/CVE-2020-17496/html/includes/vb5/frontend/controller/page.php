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

class vB5_Frontend_Controller_Page extends vB5_Frontend_Controller
{
	public function index($pageid)
	{
		//the api init can redirect.  We need to make sure that happens before we echo anything
		$api = Api_InterfaceAbstract::instance();

		$top = '';
		if (
			!vB5_Config::instance()->debug AND
			vB5_Request::get('cachePageForGuestTime') > 0 AND
			!vB5_User::get('userid') AND
			(empty($_REQUEST['routestring']) OR ($_REQUEST['routestring'] != 'register' AND $_REQUEST['routestring'] != 'lostpw'))
		)
		{
			// languageid should be in the pagekey to fix VBV-8095
			$fullPageKey = 'vBPage_' . md5(serialize($_REQUEST)) . '_' . vB::getCurrentSession()->get('languageid');

			$styleid = vB5_Cookie::get('userstyleid', vB5_Cookie::TYPE_UINT);
			if (!empty($styleid))
			{
				$fullPageKey .= '_' . $styleid;
			}
			$fullPage = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($fullPageKey);

			if (!empty($fullPage))
			{
				echo $fullPage;
				exit;
			}
		}

		$preheader = vB5_ApplicationAbstract::getPreheader();
		$top .= $preheader;

		if (vB5_Request::get('useEarlyFlush'))
		{
			//we may want to create PHP sessions at some point but we don't know yet
			//and this is our last change to initalize it properly.  Creating the
			//session is likley less overhead than figuring out if we need to
			//and we'd like to expand the user of PHP sessions in the future.
			if(session_status() == PHP_SESSION_NONE)
			{
				session_start();
			}
			echo $preheader;
			flush();
		}

		$router = vB5_ApplicationAbstract::instance()->getRouter();
		$arguments = $router->getArguments();
		$userAction = $router->getUserAction();
		$pageKey = $router->getPageKey();

		$api->callApi('page', 'preload', array($pageKey));

		if (!empty($userAction))
		{
			$api->callApi(
				'wol',
				'register',
				array(
					$userAction['action'],
					$userAction['params'],
					$pageKey, vB::getRequest()->getScriptPath(),
					(!empty($arguments['nodeid']) ? $arguments['nodeid'] : 0)
				)
			);
		}

		if (isset($arguments['pagenum']))
		{
			$arguments['pagenum'] = intval($arguments['pagenum']) > 0 ? intval($arguments['pagenum']) : 1;
		}
		$pageid = (int) (isset($arguments['pageid']) ? $arguments['pageid'] : (isset($arguments['contentid']) ? $arguments['contentid'] : 0));

		if ($pageid < 1)
		{
			// @todo This needs to output a user-friendly "page not found" page
			throw new Exception('Could not find page.');
		}

		$page = $api->callApi('page', 'fetchPageById', array($pageid, $arguments));

		$api->invokeHook('hookGetPageMain', array(
			'pageid' => $pageid,
			'useraction' => $userAction,
			'page' => &$page,
			'pagekey' => &$pageKey,
			'arguments' => &$arguments,
		));

		if (!$page)
		{
			// @todo This needs to output a user-friendly "page not found" page
			throw new Exception('Could not find page.');
		}

		// Go to the first new / unread post for this user in this topic
		if (!empty($_REQUEST['goto']) AND $_REQUEST['goto'] == 'newpost' AND !empty($arguments['nodeid']) AND !empty($arguments['channelid']))
		{
			if ($this->vboptions['threadmarking'] AND vB5_User::get('userid'))
			{
				// Database read marking
				$channelRead = $api->callApi('node', 'getNodeReadTime', array($arguments['channelid']));
				$topicRead = $api->callApi('node', 'getNodeReadTime', array($arguments['nodeid']));
				$topicView = max($topicRead, $channelRead, time() - ($this->vboptions['markinglimit'] * 86400));
			}
			else
			{
				// Cookie read marking
				$topicView = intval(vB5_Cookie::fetchBbarrayCookie('discussion_view', $arguments['nodeid']));
				if (!$topicView)
				{
					$topicView = vB5_User::get('lastvisit');
				}
			}
			$topicView = intval($topicView);

			// Get the first unread reply
			$goToNodeId = $api->callApi('node', 'getFirstChildAfterTime', array($arguments['nodeid'], $topicView));

			if (empty($goToNodeId))
			{
				$thread = $api->callApi('node', 'getNodes', array(array($arguments['nodeid'])));
				if (!empty($thread) AND isset($thread[$arguments['nodeid']]))
				{
					$goToNodeId = $thread[$arguments['nodeid']]['lastcontentid'];
				}
			}

			if ($goToNodeId)
			{
				// Redirect to the new post
				$urlCache = vB5_Template_Url::instance();
				$urlKey = $urlCache->register($router->getRouteId(), array('nodeid' => $arguments['nodeid']), array('p' => $goToNodeId));
				$replacements = $urlCache->finalBuildUrls(array($urlKey));
				$url = $replacements[$urlKey];
				if ($url)
				{
					$url .= '#post' . $goToNodeId;
					if (headers_sent())
					{
						echo '<script type="text/javascript">window.location = "' . $url . '";</script>';
					}
					else
					{
						header('Location: ' . $url);
					}
					exit;
				}
			}
		}

		$page['routeInfo'] = array(
			'routeId' => $router->getRouteId(),
			'arguments'	=> $arguments,
			'queryParameters' => $router->getQueryParameters()
		);
		$page['crumbs'] = $router->getBreadcrumbs();
		$page['headlinks'] = $router->getHeadLinks();
		$page['pageKey'] = $pageKey;

		// default value for pageSchema
		$page['pageSchema'] = 'http://schema.org/WebPage';

		$queryParameters = $router->getQueryParameters();
		/*
		 *	VBV-12506
		 *	this is where we would add other things to clean up dangerous query params.
		 *	For VBV-12486, I'll just unset anything here that can't use vb:var in the templates,
		 *	but really we should just make a whitelist of expected page object parameters that
		 *	come from the query string and unset EVERYTHING else. For the expected ones, we
		 *	should also force the value into the expected (and hopefully safer) range
		*/
		/*
		 *	VBV-12506
		 *	$doNotReplaceWithQueryParams is a list of parameters that the page object usually
		 *	gets naturally/internally, and we NEVER want to replace with a user provided query
		 *	parameter. (In fact, *when* exactly DO we want to do this???)
		 *	If we don't do this, it's a potential XSS vulnerability for the items that we
		 *	cannot send through vb:var for whatever reason (title for ex)
		 * 	and even if they *are* sent through vb:var, the replacements can sometimes just
		 *	break the page even when it's sent through vb:var (for example, ?pagetemplateid=%0D,
		 *	the new line this inserts in var pageData = {...} in the header template tends to
		 *	break things (tested on Chrome).
		 *	Furthermore, any script that uses the pageData var would get the user injected data
		 *	that might cause more problems down the line.
		 *	Parameter Notes:
		 *		'titleprefix'
		 *			As these two should already be html escaped, we don't want to double escape
		 *			them. So we can't us vb:var in the templates. As such, we must prevent a
		 *			malicious querystring from being injected into the page object here.
		 *		'title'
		 *			Similar to above, but channels are allowed to have HTML in the title, so
		 *			they are intentinoally not escaped in the DB, and the templates can't use
		 *			vb:var.
		 *		'pageid', 'channelid', 'nodeid'
		 *			These are usually set in the arguments, so the array_merge below usually
		 *			takes care of not passing a pageid query string through to the page object,
		 *			but I'm leaving them in just in case.
		 */
		$doNotReplaceWithQueryParams = array(
			'titleprefix', 'title',
			'pageid', 'channelid', 'nodeid',
			'pagetemplateid', 'url', 'pagenum',
			'tagCloudTitle',
		);
		foreach ($doNotReplaceWithQueryParams AS $key)
		{
			unset($queryParameters[$key]);
		}

		$arguments = array_merge($queryParameters, $arguments);
		foreach ($arguments AS $key => $value)
		{
			$page[$key] = $value;
		}

		$options = vB5_Template_Options::instance();
		$page['phrasedate'] = $options->get('miscoptions.phrasedate');
		$page['optionsdate'] = $options->get('miscoptions.optionsdate');

		// if no meta description, use node data or global one instead, prefer node data
		if (empty($page['metadescription']) AND !empty($page['nodedescription']))
		{
			$page['metadescription'] = $page['nodedescription'];
		}
		if (empty($page['metadescription']))
		{
			$page['metadescription'] = $options->get('options.description');
		}

		$config = vB5_Config::instance();
		// Non-persistent notices @todo - change this to use vB_Cookie
		$page['ignore_np_notices'] = vB5_ApplicationAbstract::getIgnoreNPNotices();

		$templateCache = vB5_Template_Cache::instance();
		$templater = new vB5_Template($page['screenlayouttemplate']);

		//IMPORTANT: If you add any variable to the page object here,
		// please make sure you add them to other controllers which create page objects.
		// That includes at a minimum the search controller (in two places currently)
		// and vB5_ApplicationAbstract::showErrorPage

		$templater->registerGlobal('page', $page);
		$page = $this->outputPage($templater->render(), false);
		$fullPage = $top . $page;

		if (!empty($fullPageKey) and is_string($fullPageKey))
		{
			vB_Cache::instance(vB_Cache::CACHE_LARGE)->write($fullPageKey, $fullPage, vB5_Request::get('cachePageForGuestTime'), 'vbCachedFullPage');
		}

		// these are the templates rendered for this page
		$loadedTemplates = vB5_Template::getRenderedTemplates();

		$api->callApi('page', 'savePreCacheInfo', array($pageKey));

		if (!vB5_Request::get('useEarlyFlush'))
		{
			echo $fullPage;
		}
		else
		{
			echo $page;
		}
	}

	/**
	 * This method is used from template code to render a template and store it in a variable
	 * @param string $templateName
	 * @param array $data
	 * @param bool $isParentTemplate
	 */
	public static function renderTemplate($templateName, $data = array(), $isParentTemplate=true)
	{
		if (empty($templateName))
		{
			return null;
		}

		return vB5_Template::staticRender($templateName, $data, $isParentTemplate);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
