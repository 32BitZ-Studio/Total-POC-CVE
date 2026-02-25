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

class vB5_Frontend_Controller_Activity extends vB5_Frontend_Controller
{
	protected function fetchChannelNodes($parent, $page, $perpage, $depth = 3, $contentype = 0, $options = false)
	{
		$api = Api_InterfaceAbstract::instance();
		$optionsArray = array();
		if (!$contentype)
		{
			$contentype = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		}

		$params = array(
			'parentid'		=> $parent,
			'page'			=> $page,
			'perpage'		=> $perpage,
			'depth'			=> $depth,
			'contenttypeid'		=> $contentype,
			'options'		=> $options
		);

		return $api->callApi('node', 'listNodeFullContent', $params);
	}

	public function actionGet()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$filters = isset($_POST['filters']) ? $_POST['filters'] : array();

		if (empty($filters['view']))
		{
			$result = array('error' => 'invalid_request');
			$this->sendAsJson($result);
			return;
		}

		$search = array();
		$stickySearchOptions = array('sticky_only' => 1);
		$stickynodes = array();
		$incrementNodeview = false; // call node API's incrementNodeview if we're viewing a thread

		if (isset($filters['q']) AND trim($filters['q']) != '')
		{
			$search['keywords'] = $filters['q'];
		}
		else
		{
			$filters['q'] = false;
		}

		if (!empty($filters['exclude_type']))
		{
			$search['exclude_type'] = $filters['exclude_type'];
		}

		if (!empty($filters['userid']))
		{
			$search['authorid'] = $filters['userid'];
		}
		else if (!empty($filters['filter_blogs']) AND $filters['filter_blogs'] == 'show_my')
		{
			$search['authorid'] = vB5_User::get('userid');
		}

		if (isset($filters['filter_prefix']))
		{
			if (!empty($filters['filter_prefix']))
			{
				if ($filters['filter_prefix'] == '-1')
				{
					$search['no_prefix'] = 1;
				}
				else if ($filters['filter_prefix'] == '-2')
				{
					$search['has_prefix'] = 1;
				}
				else
				{
					$search['prefix'] = $filters['filter_prefix'];
				}
			}
			else
			{
				// Any thread, regardless of prefix, don't set $search['prefix']
			}
		}

		if (isset($filters['nodeid']) AND intval($filters['nodeid']) > 0)
		{
			$search['channel'] = $filters['nodeid'];
		}

		switch ($filters['view'])
		{
			// topic view is used by channeldisplay.
			case 'topic':
				$search['view'] = vB_Api_Search::FILTER_VIEW_TOPIC;
				$search['exclude_sticky'] = true;
				$search['nolimit'] = !empty($filters['nolimit']);
				if (!empty($filters['depth']))
				{
					$search['depth'] = $filters['depth'];
				}
				$search['depth_exact'] = !empty($filters['depth_exact']);
				break;

			//Channel view is the same with Activity view except that Channel view's search scope is within
			//that channel only as specified by the channel nodeid in the 'channel' filter
			case 'channel':
				$search['include_sticky'] = true;
				// drop through to 'activity'

			case 'activity':
				//Per Product, if New Topics filter in activity stream is ON, display latest starters only.
				//if OFF, display latest starter, reply or comment per topic
				if (isset($filters['filter_new_topics']) AND $filters['filter_new_topics'] == '1')
				{
					$search['starter_only'] = true;
				}
				$search['view'] = vB_Api_Search::FILTER_VIEW_ACTIVITY;
				break;

			case 'stream':
				$search['view'] = vB_Api_Search::FILTER_VIEW_CONVERSATION_STREAM;
				$search['include_starter'] = true;
				// Stream view used to show starters at the top even though
				// it used created DESC sorting.
				// That was never intentional, and WFs show starters at the bottom.
				// ATM there's no "sorting" UI for thread/stream views, so
				// the expected sorting is default created DESC for stream view.
				// So we won't check & change the isstarter sorting here.
				$search['sort']['isstarter'] = 'asc';
				$search['sort']['created'] = 'desc';
				$search['depth'] = 2;
				break;

			case 'thread':
				$search['view'] = vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD;
				$search['include_sticky'] = true;
				$search['include_starter'] = true;
				// This is viewing a single thread, so show starters first.
				// ATM there's no "sorting" UI for thread/stream views, so
				// the expected sorting is default created ASC for thread view
				// So we won't check & change the isstarter sorting here.
				$search['sort']['isstarter'] = 'desc';
				$search['sort']['created'] = 'asc';
				/*
					TODO: The "include_sticky" above (which I'm not sure is even
					correct or necessary when we're looking at a single topic thread)
					causes some additional sorting, including a "closure.depth ASC"
					that makes isstarter sorting pointless.
					But I think it's "more correct" to have the isstarter sorting here,
					especially if it turns out the include_sticky isn't supposed to be
					there.
				 */
				$search['depth'] = 1;
				$search['nolimit'] = !empty($filters['nolimit']);
				if ($filters['q'])
				{
					$search['view'] = vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD_SEARCH;
				}
				$incrementNodeview = true;
				break;

			case 'article':
				$search['starter_only'] = true;
				$search['view'] = vB_Api_Search::FILTER_VIEW_ACTIVITY;
				$search['include_sticky'] = true;
				$search['include_starter'] = true;
				//$search['depth'] = 1;
				//$search['nolimit'] = !empty($filters['nolimit']);
				break;
		}

		if (!empty($filters[vB_Api_Node::FILTER_DEPTH]))
		{
			$search['depth'] = intval($filters[vB_Api_Node::FILTER_DEPTH]);
		}

		if (isset($filters['filter_sort']))
		{
			switch($filters['filter_sort'])
			{
				case vB_Api_Node::FILTER_SORTFEATURED:
					$search['featured'] = 1;
					break;
				case vB_Api_Node::FILTER_SORTPOPULAR:
					$search['sort']['votes'] = 'desc';
					break;
				case vB_Api_Node::FILTER_SORTOLDEST:
					if (isset($filters['view']) AND $filters['view'] == 'topic')
					{
						$search['sort']['lastcontent'] = 'asc';
					}
					else
					{
						$search['sort']['created'] = 'asc';
					}
					break;
				case vB_Api_Node::FILTER_SORTMOSTRECENT:
				default:
					if (empty($filters['filter_order']))
					{
						$filters['filter_order'] = 'desc';
					}

					if (isset($filters['view']) AND $filters['view'] == 'topic')
					{
						$search['sort'][$filters['filter_sort']] = $filters['filter_order'];
					}
					else
					{
						$search['sort']['created'] = 'desc';
					}
					break;
			}
		}
		else
		{
			if ($filters['view'] == 'thread')
			{
				$search['sort']['created'] = 'asc';
			}
			elseif (in_array($filters['view'], array('topic', 'activity')))
			{
				$search['sort']['lastcontent'] = 'desc';
			}
		}

		if (isset($filters['checkSince']) AND is_numeric($filters['checkSince']))
		{
			$search['date']['from'] = $filters['checkSince'] + 1;
		}
		elseif (isset($filters['date']) OR isset($filters['filter_time']))
		{
			$date_filter = empty($filters['date']) ? $filters['filter_time'] : $filters['date'];
			switch($date_filter)
			{
				case 'time_today':
					$search['date']['from'] = 'lastDay';//vB_Api_Search::FILTER_LASTDAY;
				break;
				case 'time_lastweek':
					$search['date']['from'] = 'lastWeek';//vB_Api_Search::FILTER_LASTWEEK;
				break;
				case 'time_lastmonth':
					$search['date']['from'] = 'lastMonth';//vB_Api_Search::FILTER_LASTMONTH;
				break;
				case 'time_lastyear':
					$search['date']['from'] = 'lastYear';//vB_Api_Search::FILTER_LASTYEAR;
				break;
				case 'time_all':
				default:
					$search['date'] = 'all';
				break;
			}
		}

		if (isset($filters[vB_Api_Node::FILTER_SHOW]) AND strcasecmp($filters[vB_Api_Node::FILTER_SHOW], vB_Api_Node::FILTER_SHOWALL) != 0)
		{
			$search['type'] = $filters[vB_Api_Node::FILTER_SHOW];
		}

		$search['ignore_protected'] = 1;

		if (!empty($filters['context']) AND $filters['context'] === "channeldisplay")
		{
			$search['context'] = $filters['context'];
			$nodes = Api_InterfaceAbstract::instance()->callApi('search', 'getChannelTopics', array(
					$search,
					empty($filters['per-page']) ? false : $filters['per-page'],
					empty($filters['pagenum']) ? false : $filters['pagenum']
			));

		}
		else
		{
			$nodes = Api_InterfaceAbstract::instance()->callApi('search', 'getInitialResults', array(
					$search,
					empty($filters['per-page']) ? false : $filters['per-page'],
					empty($filters['pagenum']) ? false : $filters['pagenum'],
					true
			));
		}



		if ($incrementNodeview)
		{
			Api_InterfaceAbstract::instance()->callApi('node', 'incrementNodeview', array($filters['nodeid']));
		}

		if (!empty($nodes) AND !empty($nodes['errors']))
		{
			$result = array('error' => $nodes['errors'][0][0]);
			$this->sendAsJson($result);
			return;
		}

		//the same selected search filters except 'exclude_sticky' should also be applied when fetching sticky topics
		if (($filters['view'] == 'topic') AND (empty($filters['pagenum']) OR $filters['pagenum'] == 1 OR vB::getDatastore()->getOption('showstickies')))
		{
			$stickySearchOptions = array_merge($search, $stickySearchOptions);
			unset($stickySearchOptions['exclude_sticky']);
			// todo... is it ok if all view = 'topic' go through getChannelTopics ?

			if (!empty($filters['context']) AND $filters['context'] === "channeldisplay")
			{
				$stickynodes = Api_InterfaceAbstract::instance()->callApi('search', 'getChannelTopics', array(
					$stickySearchOptions,
					0, // perpage, 0 means "infinite" (999 in reality)
					1, // page
					true // skipCount
				));
			}
			else
			{
				$stickynodes = Api_InterfaceAbstract::instance()->callApi('search', 'getInitialResults', array($stickySearchOptions));
			}
		}

		if (empty($filters['maxpages']))
		{
			$filters['maxpages'] = 0;
		}

		switch($filters['view'])
		{
			case 'activity':
				$result = $this->processActivityStream($nodes, true, $filters['maxpages']);
				break;

			case 'thread':
			case 'stream':
				$result = $this->processConversationDetail($nodes, $filters, $filters['maxpages']);
				break;

			case 'topic':
				$result = $this->processTopics($nodes, $stickynodes, $filters['maxpages']);
				break;

			case 'article':
				$articleDisplayColumns = !empty($_POST['article_display_columns']) ? strval($_POST['article_display_columns']) : '';
				$result = $this->processArticles($nodes, $filters['maxpages'], $articleDisplayColumns);
				break;

			case 'channel':
			default:
				$result = $this->processActivityStream($nodes, false, $filters['maxpages']);
				break;
		}

		if (!$result['lastDate'])
		{
			$result['lastDate'] = time();
		}

		$this->sendAsJson($result);
	}

	public function actionBloglist()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$channels = $channelHierarchy = array();
		$api = Api_InterfaceAbstract::instance();
		$blogChannel = $api->callApi('blog', 'getBlogChannel', array());
		$nodes = $this->fetchChannelNodes(9, 1, 100);
		$templater = new vB5_Template('display_Forums');

		if (!empty($nodes) AND empty($nodes['errors']))
		{

			foreach ($nodes AS $node)
			{
				$channels[$node['nodeid']] = array(
					'nodeid' 		=> $node['nodeid'],
					'routeid' 		=> $node['routeid'],
					'title'			=> $node['title'],
					'description'		=> $node['description'],
					'parentid' 		=> $node['parentid'],
					'textcount'		=> $node['textcount'],
					'totalcount'		=> $node['totalcount'],
					'viewing'		=> 0, //@TODO: is the number of 'viewing' users implemented in api?
					'lastcontent' 	=> array(
						'nodeid'	=> $node['lastcontentid'],
						'title'		=> '',
						'authorname'	=> $node['lastcontentauthor'],
						'userid'	=> $node['lastauthorid'],
						'starter'	=> array(),
					),
					'subchannels'		=> array(),
				);
			}

			foreach ($channels as $channel)
			{
				$nodeId = $channel['nodeid'];
				$parentId = $channel['parentid'];
				if ($channel['lastcontent']['nodeid'] > 0)
				{
					$node = $api->callApi('node', 'getFullContentforNodes', array(array($channel['lastcontent']['nodeid'])));
					if (is_array($node))
					{
						$node = array_pop($node);
					}
					$channels[$nodeId]['lastcontent']['title'] = $node['content']['title'];
					$channels[$nodeId]['lastcontent']['created'] = $node['content']['created'];
					$channels[$nodeId]['lastcontent']['parentid'] = $node['content']['parentid'];
					$channels[$nodeId]['lastcontent']['starter']['nodeid'] = $node['content']['starter'];
					$channels[$nodeId]['lastcontent']['starter']['routeid'] = $node['content']['starterroute'];
					$channels[$nodeId]['lastcontent']['starter']['title'] = $node['content']['startertitle'];
				}

				if (isset($channels[$parentId]))
				{
					// assign by reference, so subchannels can be filled in later
					$channels[$parentId]['subchannels'][$nodeId] =& $channels[$nodeId];
				}
				else
				{
					// assign by reference, so subchannels can be filled in later
					$channelHierarchy[$nodeId] =& $channels[$nodeId];
				}
			}
			$templater->register('channels', $channelHierarchy);
		}
		else
		{
			$templater->register('channels', $nodes);
		}

		$this->outputPage($templater->render());
	}

	protected function processActivityStream($nodes, $showChannelInfo, $maxpages = 0)
	{
		$result = array(
			'total'				=> 0,
			'total_with_sticky'	=> 0,
			'lastDate'			=> 0,
			'template'	=>		'',
			'pageinfo'	=>		array(
				'pagenumber'	=> 1,
				'totalpages'	=> 1
			),
			'css_links' => array()
		);
		if(!isset($nodes['errors']) AND !empty($nodes['results']))
		{
			$api = Api_InterfaceAbstract::instance();

			foreach ($nodes['results'] AS $node)
			{
				if (empty($node['content']))
				{
					$conversation = $node;
				}
				else
				{
					$conversation = $node['content'];
				}

				$templateName = 'display_contenttype_conversationreply_' . $conversation['contenttypeclass'];
				$templater = new vB5_Template($templateName);
				$templater->register('conversation', $conversation);
				$templater->register('reportActivity', true);
				$templater->register('showChannelInfo', $showChannelInfo);
				$templater->register('currentNodeIsBlog', (bool)($conversation['channeltype'] == 'blog'));
				$templater->register('currentNodeIsArticle', (bool)($conversation['channeltype'] == 'article'));

				$result['template'] .= "\n" . $templater->render(true, true) . "\n";
				$result['total']++;
				$result['lastDate'] = max($result['lastDate'], $node['publishdate']);
			}
			$result['pageinfo']['pagenumber'] = $nodes['pagenumber'];
			$result['pageinfo']['totalpages'] = (!empty($maxpages) AND $maxpages < $nodes['totalpages']) ? $maxpages : $nodes['totalpages'];
			$result['pageinfo']['resultId'] = isset($nodes['resultId']) ? $nodes['resultId'] : null;
		}
		$result['total_with_sticky'] = $result['total'];
		$result['nodes'] = $nodes['results'];
		$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();

		return $result;
	}

	/**
	 * Processes article results to prepare the rendered templates for returning.
	 *
	 * @param	array	Node search result
	 * @param	int	Max pages of results
	 * @param	string	Article display columns setting
	 *
	 * @return	array	Array of rendered results for display
	 */
	protected function processArticles($nodes, $maxpages = 0, $articleDisplayColumns = '')
	{
		$result = array(
			'total'             => 0,
			'total_with_sticky' => 0,
			'lastDate'          => 0,
			'template'          => '',
			'pageinfo'          => array(
				'pagenumber' => 1,
				'totalpages' => 1,
			),
			'css_links' => array(),
		);

		if(!isset($nodes['errors']) AND !empty($nodes['results']))
		{
			$api = Api_InterfaceAbstract::instance();

			// add article views
			$nodes['results'] = $api->callApi('node', 'mergeNodeviewsForTopics', array($nodes['results']));

			foreach ($nodes['results'] AS $node)
			{

				$result['total']++;
				$result['lastDate'] = max($result['lastDate'], $node['publishdate']);
			}

			// Render the list together
			$templater = new vB5_Template('widget_cmschanneldisplay_list');
			$templater->register('nodes', $nodes['results']);
			$templater->register('displayColumns', $articleDisplayColumns);
			$templater->register('reportActivity', true);
			$templater->register('showChannelInfo', false);
			$templater->register('currentNodeIsBlog', false);
			$templater->register('currentNodeIsArticle', true);

			$result['template'] = $templater->render(true, true);

			$result['pageinfo']['pagenumber'] = $nodes['pagenumber'];
			$result['pageinfo']['totalpages'] = (!empty($maxpages) AND $maxpages < $nodes['totalpages']) ? $maxpages : $nodes['totalpages'];
			$result['pageinfo']['resultId'] = isset($nodes['resultId']) ? $nodes['resultId'] : null;
		}

		$result['total_with_sticky'] = $result['total'];
		$result['nodes'] = $nodes['results'];
		$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();

		return $result;
	}

	protected function processConversationDetail($nodes, $filters, $maxpages = 0)
	{
		$view = $filters['view'];
		$result = array(
			'total' 	=> 0,
			'lastDate'	=> 0,
			'template'	=> '',
			'pageinfo'	=> array(
				'pagenumber'	=> 1,
				'totalpages'	=> 1,
			),
			'css_links' => array()
		);
		if(!isset($nodes['errors']) AND !empty($nodes['results']))
		{
			$showInlineMod = ($view == 'thread');
			if ($view == 'thread')
			{
				$showInlineMod =  true;
				$templateSuffix = 'starter';
				$pagingInfo = array(
					'currentpage'	=> $filters['pagenum'],
					'perpage'		=> $filters['per-page']
				);
			}
			else
			{
				$showInlineMod = false;
				$templateSuffix = 'reply';
				$pagingInfo = array();
			}
			$baseTemplateName = 'display_contenttype_' . ($view == 'stream' ? 'conversation%s_' : 'conversation%s_threadview_');
			$postIndex = 0;
			$signatures = array();
			foreach ($nodes['results'] AS $node)
			{
				$signatures[$node['userid']] = $node['content']['signature'];
			}

			$parsed_signatures = Api_InterfaceAbstract::instance()->callApi('bbcode', 'parseSignatures', array(array_keys($signatures), $signatures));
			foreach ($nodes['results'] AS $node)
			{
				$updateIndex = true;
				$templateName = $baseTemplateName;

				if (!empty($parsed_signatures[$node['userid']]) AND !empty($node['content']['canSign']))
				{
					$node['content']['parsedSignature'] = $parsed_signatures[$node['userid']];
				}

				if ($node['content']['starter'] == $node['content']['nodeid'])
				{
					$templateName = sprintf($templateName, $templateSuffix);
					$templateName .= $node['content']['contenttypeclass'];
					$conversation = $node['content'];
					$postIndex = 1;
					$updateIndex = false;

					$conversation['can_use_multiquote'] = $this->canUseMultiquote($node['content']['starter']);
				}
				elseif ($view == 'thread' AND $node['content']['parentid'] != $node['content']['starter'])
				{
					//we don't need comments for thread view
					continue;
				}
				else
				{
					$templateName = sprintf($templateName, 'reply');
					$templateName .= $node['content']['contenttypeclass'];
					$conversation = $node['content'];

					$conversation['can_use_multiquote'] = $this->canUseMultiquote($node['content']['starter']);
				}

				$templater = new vB5_Template($templateName);
				$templater->register('nodeid', $conversation['nodeid']);
				$templater->register('conversation', $conversation);
				$templater->register('reportActivity', false);
				$templater->register('showInlineMod', $showInlineMod);
				$templater->register('pagingInfo', $pagingInfo);
				$templater->register('view', $view);
				if ($conversation['unpublishdate'])
				{
					$templater->register('hidePostIndex', true);
					$templater->register('postIndex', null);
				}
				else
				{
					$templater->register('postIndex', $postIndex);
					if ($updateIndex)
					{
						$postIndex++;
					}
				}

				$result['template'] .= "\n" . $templater->render(true, true) . "\n";
				$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();
				$result['total']++;
				$result['lastDate'] = max($result['lastDate'], $node['publishdate']);
			}
			$result['pageinfo']['pagenumber'] = $nodes['pagenumber'];
			$result['pageinfo']['totalpages'] = (!empty($maxpages) AND $maxpages < $nodes['totalpages']) ? $maxpages : $nodes['totalpages'];
			$result['pageinfo']['resultId'] = isset($nodes['resultId']) ? $nodes['resultId'] : null;
		}
		$result['total_with_sticky'] = $result['total'];
		return $result;
	}

	//designed to duplicated some logic in the widget_conversationdisplay template that updates a flag on the nodes used
	//by the conversation_footer template.  This really needs to be pushed back on the node API, but that's a riskier fix
	protected function canUseMultiquote($starterid)
	{
		static $cache = array();

		if(!isset($cache[$starterid]))
		{
			$api = Api_InterfaceAbstract::instance();
			$starter = $api->callApi('node', 'getNodeFullContent', array($starterid));

			if (!isset($starter['error']))
			{
				$cache[$starterid] = ($starter[$starterid]['canreply'] AND ($starter[$starterid]['channeltype'] != 'blog'));
			}
			else
			{
				//explicitly handle the error case.  This is unlikely and throwing an error here would be bad.
				//so we'll ignore it and just return false as the safest behavior.
				$cache[$starterid] = false;
			}
		}

		return $cache[$starterid];
	}

	protected function processTopics($nodes, $stickynodes, $maxpages = 0)
	{
		$result = array(
			'total' 			=> 0,
			'total_with_sticky'	=> 0,
			'lastDate'			=> 0,
			'template'			=> '',
			'pageinfo'	=> array(
				'pagenumber'	=> 1,
				'totalpages'	=> 1,
			),
			'css_links' => array()
		);

		$templater = new vB5_Template('display_Topics');
		$canmoderate  = false;
		if (!isset($nodes['errors']) AND !empty($nodes['results']))
		{
			foreach ($nodes['results'] AS $key => $node)
			{
				//only include the starter
				if ($node['content']['contenttypeclass'] == 'Channel' OR $node['content']['starter'] != $node['content']['nodeid'])
				{
					unset($nodes['results'][$key]);
				}
				else
				{
					$result['lastDate'] = max($result['lastDate'], $node['content']['publishdate']);
				}
				if (!empty($node['content']['permissions']['canmoderate']) AND !$canmoderate)
				{
					$canmoderate = 1;
					$templater->register('canmoderate', $canmoderate);
				}
			}

			$templater->register('topics', $nodes['results']);

			$result['total_with_sticky'] = $result['total'] = count($nodes['results']);
			$result['pageinfo']['pagenumber'] = $nodes['pagenumber'];
			$result['pageinfo']['totalpages'] = (!empty($maxpages) AND $maxpages < $nodes['totalpages']) ? $maxpages : $nodes['totalpages'];
			$result['pageinfo']['resultId'] = isset($nodes['resultId']) ? $nodes['resultId'] : null;
		}
		elseif (isset($nodes['errors']))
		{
			$templater->register('topics', $nodes);
		}

		if (!isset($stickynodes['errors']) AND !empty($stickynodes['results']))
		{
			$result['total_with_sticky'] = $result['total'] + count ($stickynodes['results']);
			$sticky_templater = new vB5_Template('display_Topics');
			$sticky_templater->register('topics', $stickynodes['results']);
			$sticky_templater->register('topic_list_class', 'sticky-list');

			if (!$canmoderate AND empty($nodes['results']))
			{
				//It is safe to assume that if user has canmoderate permission for the first topic node in a forum,
				//he/she has the same permission for all the nodes.
				$firstTopic = reset($stickynodes['results']);
				$canmoderate = $firstTopic['content']['permissions']['canmoderate'];
			}
			$sticky_templater->register('canmoderate', $canmoderate);

			$result['template'] .= "\n" . $sticky_templater->render() . "\n";
			$templater->register('no_header', 1);
		}

		if (!empty($nodes['results']) OR empty($stickynodes['results']))
		{
			$result['template'] .= "\n" . $templater->render(true, true) . "\n";
			$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();
		}
		return $result;
	}


	/**
	 * This gets nodeText for a single node.
	 */
	public function actionfetchtext()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (empty($_REQUEST['nodeid']) OR !intval($_REQUEST['nodeid']))
		{
			return '';
		}
		$api = Api_InterfaceAbstract::instance();
		$nodeHandler = vB5_Template_NodeText::instance();
		$nodeText = $nodeHandler->fetchOneNodeText(intval($_REQUEST['nodeid']), $api);

		//make sure that we don't get any weird null results.
		if (empty($nodeText))
		{
			$nodeText = '';
		}

		$this->sendAsJson(array('nodeText' => $nodeText));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102500 $
|| #######################################################################
\*=========================================================================*/
