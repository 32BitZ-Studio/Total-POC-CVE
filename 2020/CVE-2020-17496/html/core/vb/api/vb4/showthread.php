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
 * vB_Api_Vb4_showthread
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_showthread extends vB_Api
{
	public function call($threadid, $perpage = 0, $pagenumber = 1, $postid = 0)
	{
		$thread = vB_Api::instance('node')->getFullContentforNodes(array($threadid));
		if(empty($thread))
		{
			return array("response" => array("errormessage" => array("invalidid")));
		}

		// count topic view
		vB_Api::instanceInternal('node')->incrementNodeview($threadid);

		$thread = $thread[0];
		$modPerms = vB::getUserContext()->getModeratorPerms($thread);
		$perpage  = vB_Library::instance('vb4_functions')->getUsersPostPerPage($perpage);

		$posts = array();
		$page_nav = vB_Library::instance('vb4_functions')->pageNav(1, $perpage, 1);

		$search = array("channel" => $threadid);
		$search['view'] = vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD;
		$search['depth'] = 1;
		$search['include_starter'] = true;
		$search['sort']['isstarter'] = 'desc';
		$search['sort']['created'] = 'asc';
		$search['nolimit'] = 1;
		$searchAPI = vB_Api::instanceInternal('search');
		// If postid is passed in, try to calculate the page (& index, later) from it.
		// Based on vB5_Route_Conversation::getCanonicalRoute()
		if (!empty($postid))
		{
			// Try the API for validation & viewperm checking.
			$node = vB_Api::instance('node')->getNode($postid, false, false);
			if (!empty($node['starter']) OR $threadid != $node['starter'])
			{
				$starter = vB_Library::instance('node')->getNodeBare($node['starter']);
				$pagenumber = $searchAPI->getPageNumber(
					$postid,
					$starter,
					$perpage,
					$search['depth'],
					$search['sort']['lastcontent'],
					$search['include_starter']
				);
			}
			else
			{
				// something went wrong.
				$postid = null;
			}
		}
		$post_search = $searchAPI->getInitialResults($search, $perpage, $pagenumber, true);
		// todo: should position be 0-indexed or 1-indexed?
		// Currently 1-indexed to make it consistent with pagenumber
		$position = 0;
		$foundPosition = false;

		if (!isset($post_search['errors']) AND !empty($post_search['results']))
		{
			$assertor = vB::getDbAssertor();
			$options = vB::getDatastore()->getValue('options');
			$userInfo = vB_Api::instance('user')->fetchUserinfo();

			if ($options['threadmarking'] AND $userInfo['userid'])
			{
				$threadInfo = vB_Library::instance('node')->getNodeBare($threadid);;

				$threadread = $assertor->getRow('vBForum:noderead', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $threadid,
					'userid' => $userinfo['userid'],
				));
				$threadread = ($threadread) ? $threadread['readtime'] : 0;

				$forumread = $assertor->getRow('vBForum:noderead', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $threadInfo['parentid'],
					'userid' => $userinfo['userid'],
				));
				$forumread = ($forumread) ? $forumread['readtime'] : 0;

				$timenow = vB::getRequest()->getTimeNow();
				$threadview = max($threadread, $forumread, $timenow - ($options['markinglimit'] * 86400));
			}
			else
			{
				$threadview = intval(fetch_bbarray_cookie('thread_lastview', $threadid));
				if (!$threadview)
				{
					$threadview = $userInfo['lastvisit'];
				}
			}
			$firstpostid = 0;
			$lastpostid = 0;
			$firstunread = 0;
			$poll = array();
			foreach ($post_search['results'] AS $key => $node)
			{
				if (in_array($node['contenttypeclass'], array('Link', 'Text', 'Gallery', 'Poll', 'Video', 'Event')))
				{
					if ($firstpostid === 0)
					{
						$firstpostid = $node['nodeid'];
					}
					if ($firstunread === 0 AND $node['publishdate'] > $threadview)
					{
						$firstunread = $node;
					}
					// yes this means if replies ever are allowed to have polls, only the first
					// poll will show, but the legacy mobile spec just won't work with such a
					// feature, so we have to go with the simplest fix for now and worry about
					// such an issue later only if it does show up.
					list($posts[], $temp) = vB_Library::instance('vb4_functions')->parsePost($node);
					if (empty($poll) AND !empty($temp))
					{
						$poll = $temp;
					}
					$lastpostid = $node['nodeid'];

					if (!$foundPosition AND !empty($postid))
					{
						$position++;
						if ($postid == $node['nodeid'])
						{
							$foundPosition = true;
						}
					}
				}
			}

			$page_nav = vB_Library::instance('vb4_functions')->pageNav($post_search['pagenumber'], $perpage, $post_search['totalRecords']);
		}

		// BEWARE content->subscribed LIES, it will be true if we are following
		// the author so make this call to get the proper data.

		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		if ($userinfo['userid'] > 0)
		{
			$subscribed = vB_Api::instance('follow')->isFollowingContent($thread['nodeid']);
		}
		else
		{
			$subscribed = 0;
		}

		$tagList = array();
		if (!empty($thread['content']['taglist']))
		{
			$nodeTags = explode(',', $thread['content']['taglist']);
			// Note, vB4's tag_list array starts with a 1 not a 0 for some reason.
			// However I'm going to assume the client doesn't care about the index.
			foreach ($nodeTags AS $tag)
			{
				$tagList[] = array(
					'tag' => $tag,
				);
			}
		}

		$response = array();
		$response['response']['thread'] = vB_Library::instance('vb4_functions')->parseThreadInfo($thread);
		$response['response']['postbits'] = $posts;
		// nested tag_list => tag_list is intended (vb4 behavior).
		$response['response']['tag_list'] = array('tag_list' => $tagList);
		if (!empty($poll))
		{
			$response['response']['poll'] = $poll;
		}
		$response['response']['pagenav'] = $page_nav;
		$response['response']['pagenumber'] = intval($pagenumber);
		if ($foundPosition)
		{
			$response['response']['position'] = $position;
		}
		$response['response']['FIRSTPOSTID'] = intval($firstpostid);
		$response['response']['LASTPOSTID'] = intval($lastpostid);
		$response['response']['firstunread'] = ($firstunread === 0) ? '' : vB5_Route::buildUrl($firstunread['routeid'], $firstunread);
		$response['response']['firstunreadid'] = ($firstunread === 0) ? '' : intval($firstunread['nodeid']);
		$response['show'] = array(
			'inlinemod' => $thread['content']['canmoderate'] ? 1 : 0,
			'spamctrls' => $modPerms['candeleteposts'] > 0 ? 1 : 0,
			'openclose' => $modPerms['canopenclose'] > 0 ? 1 : 0,
			'approvepost' => $modPerms['canmoderateposts'] > 0 ? 1 : 0,
			'deleteposts' => $modPerms['candeleteposts'] > 0 ? 1 : 0,
			'subscribed' => $subscribed,
		);
		return $response;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102429 $
|| #######################################################################
\*=========================================================================*/
