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
 * vB_Api_Vb4_subscription
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_subscription extends vB_Api
{
	// Top channels of the board
	protected $topChannels = array();

	public function viewsubscription($searchType = 0)
	{
		$node_api = vB_Api::instance('node');
		$follow_api = vB_Api::instance('follow');

		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		if ($userinfo['userid'] <= 0)
		{
			return array('response' => array('errormessage' => 'nopermission_loggedout'));
		}

		//init cleaner
		$cleaner = vB::getCleaner();

		//clean $_REQUEST params
		$searchType = $cleaner->clean($searchType, vB_Cleaner::TYPE_STR);

		//get node id for forums
		$top = vB_Api::instance('content_channel')->fetchTopLevelChannelIds();
		$forumid = $top['forum'];
		//get node id for blogs
		$blogTopChannel = vB_Api::instance('blog')->getBlogChannel();

		//getFollowingContent based on $_REQUEST param searchType
		if($searchType=="forum"){
			//filter using $forumid
			$subscribed = $follow_api->getFollowingContent(
				$userinfo['userid'],
				vB_Api_Follow::FOLLOWTYPE_ALL,
				array(vB_Api_Follow::FOLLOWFILTERTYPE_SORT => vB_Api_Follow::FOLLOWFILTER_SORTALL),
				null,
				array('parentid' => $forumid)
			);
		}
		else if($searchType=="blog"){
			//filter using $blogTopChannel
			$subscribed = $follow_api->getFollowingContent(
				$userinfo['userid'],
				vB_Api_Follow::FOLLOWTYPE_ALL,
				array(vB_Api_Follow::FOLLOWFILTERTYPE_SORT => vB_Api_Follow::FOLLOWFILTER_SORTALL),
				null,
				array('parentid' => $blogTopChannel)
			);
		}
		else {
			//no filter, returns all relevent content
			$subscribed = $follow_api->getFollowingContent(
				$userinfo['userid'],
				vB_Api_Follow::FOLLOWTYPE_ALL,
				array(vB_Api_Follow::FOLLOWFILTERTYPE_SORT => vB_Api_Follow::FOLLOWFILTER_SORTALL),
				null
			);
		}

		if (!empty($subscribed['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$nodes = $node_api->getFullContentforNodes(array_keys($subscribed['nodes']));
		if (!empty($nodes['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		//index by nodeid since mergeNodeviewsForTopics requires it.
		$nodestemp = array();
		foreach($nodes AS $node)
		{
			$nodestemp[$node['nodeid']] = $node;
		}
		unset($nodes);

		$nodes = $node_api->mergeNodeviewsForTopics($nodestemp);
		if (!empty($nodes['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$processedbit = array();
		$subscribedbits = array();

		foreach ($nodes as $node)
		{
			if (empty($node['content']))
			{
				$conversation = $node;
			}
			else
			{
				$conversation = $node['content'];
			}

			$itemSection = $this->getSection($node);
			if ($itemSection == 'album' OR $itemSection == 'socialgroup')
			{
				continue;
			}


			$subscribedbit = $this->nodeToApiFormat($conversation);
			$activityType = $this->getActivityType($itemSection, $node);

			$subscribedbits[] = $subscribedbit;
		}

		$out = array(
			'response' => array(
				'HTML' => array(
					'folderjump' => array(),
					//the app doesn't care
					'pagenav' => array(),
					//should most likely be the total count of items, but we
					//don't have that and the app doesn't care
					'totalallthreads' => count($subscribedbits),
					'threadbits' => $subscribedbits,
				),
				'show' => array(
					'havethreads' => (count($subscribedbits) > 0 ? 1 : 0)
				)
			)
		);
		return $out;
	}

	private function nodeToApiFormat($node)
	{
		$thread = array(
			'thread' => array(
				'threadid' => $node['nodeid'],
				'threadtitle' => vB_String::unHtmlSpecialChars($node['title']),
				'postusername' => $node['authorname'],
				'postuserid' => $node['userid'],
				//Copied from vB4 mapi doc example, doesn't seem to affect App in any way.
				'status' => array('dot' => 'dot'),
				'moderatedprefix' => '',
				'realthreadid' => $node['nodeid'],
				//replaced with likes in vB5, but no good way to map
				'rating' => 0,
				'preview' => vB_Library::instance('vb4_functions')->getPreview($node['rawtext']),
				//these are the counts of the posts for the current user to the thread.
				//I don't believe vB5 currently tracks this and I doesn't appear to affect the
				//mobile app
				'dot_count' => 0,
				'dot_lastpost' => 0,
				'threadiconpath' => $node['iconpath'],
				//this isn't provided in the node data and does not appear to be used by the app
				//no good reason to jump through tons of hoops to get info that won't be used.
				'threadicontitle' => '',
				//not sure what this is.  Not in the wiki docs, never set in vB4 in testing
				'typeprefix' => '',
				'prefix_rich' => $node['prefix_rich'],
				'starttime' => $node['lastcontent'],
				'attach' => count($node['attach']),
				'forumid' => $node['channelid'],
				'forumtitle' => $node['channeltitle'],
				'replycount' => $node['textcount'],
				'views' => $node['views'],
				'lastposttime' => $node['lastcontent'],
				'lastpostid' => $node['lastcontentid'],
				'lastposter' => $node['lastcontentauthor'],
				'lastposterid' => $node['lastauthorid']
			),
			'avatar' => array(
				'hascustom' => $node['avatar']['hascustom'],
				'0' => $node['avatar']['avatarpath'],
				'1' => ''
			),
			'show' => array(
				'rexpires' => 0,
				'rmanage' => 0,
				'threadmoved' => 0,
				'paperclip' => (count($node['attach']) ? 1 : 0),
				'unsubscribe' => 0,
				'sticky' => $node['sticky'],
				'threadicon' => ($node['iconid'] ? 1 : 0),
				'gotonewpost' => 0,
				'subscribed' => 0,
				'pagenav' => 0,
				'guestuser' => 0,
				'threadrating' => 0,
				'threadcount' => 1,
				'taglist' => 0,
				'avatar' => 1
			)
		);

		return $thread;
	}

	private function getSection($node)
	{
		$section = '';

		$topChannels = $this->getTopChannels();

		if (in_array($topChannels['forum'], $node['parents']))
		{
			$section = 'forum';
		}
		else if (in_array($topChannels['blog'], $node['parents']))
		{
			$section = 'blog';
		}
		else if (in_array($topChannels['groups'], $node['parents']))
		{
			$section = 'socialgroup';
		}
		else if (in_array($topChannels['special'], $node['parents']))
		{
			$section = 'album';
		}

		if (empty($section))
		{
			// @TODO: This must not happen. Or this should throw an error.
		}

		return $section;
	}

	/**
	 * Returns the top channels
	 *
	 * @return [array] [Top channels array]
	 */
	private function getTopChannels()
	{
		if (empty($this->topChannels))
		{
			$this->topChannels = vB_Api::instance('content_channel')->fetchTopLevelChannelIds();
		}

		return $this->topChannels;
	}


	/**
	 * Gets the activity type for that section
	 *
	 * @param  [string] $section
	 * @param  [array]  $node
	 * @return [string]
	 */
	private function getActivityType($section, $node)
	{
		$type = '';

		switch ($section) {
		case 'forum':
			if (!empty($node['setfor']))
			{
				// @TODO: This will not happen. In vb5 in order to get visitor messages you need to pass a flag,
				// so we probably want to set this as filter
				$type = 'visitormessage';
			}
			elseif ($node['nodeid'] == $node['starter'])
			{
				$type = 'thread';
			}
			else
			{
				$type = 'post';
			}
			break;
		case 'blog':
			if ($node['nodeid'] == $node['starter'])
			{
				$type = 'entry';
			}
			else
			{
				$type = 'comment';
			}
			break;
		case 'socialgroup':
			$topChannels = $this->getTopChannels();

			if ($topChannels['groups'] == $node['parentid'])
			{
				$type = 'group';
			}
			elseif ($node['nodeid'] == $node['starter'])
			{
				$type = 'discussion';
			}
			else
			{
				$type = 'groupmessage';
			}
			break;
		case 'album':
			// The other options (comment and album) are not applicable
			$type = 'photo';
			break;
		default:
			// @TODO: This should not happen or it should throw an error
			break;
		}

		return $type;
	}


	public function removesubscription($threadid = "", $forumid = "")
	{
		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		if ($userinfo['userid'] <= 0)
		{
			return array('response' => array('errormessage' => 'nopermission_loggedout'));
		}

		$cleaner = vB::getCleaner();
		$threadid = $cleaner->clean($threadid, vB_Cleaner::TYPE_UINT);
		$forumid = $cleaner->clean($forumid, vB_Cleaner::TYPE_UINT);

		if ($threadid > 0)
		{
			$nodeid = $threadid;
		}
		else if ($forumid > 0)
		{
			$nodeid = $forumid;
		}
		else
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$success = vB_Api::instance('follow')->delete($nodeid, vB_Api_Follow::FOLLOWTYPE_CONTENT);
		if (!empty($success['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}
		return array('response' => array('errormessage' => 'redirect_subsremove_thread'));
		return null;
	}

	public function addsubscription()
	{
		return array('response' => array('HTML' => array('emailselected' => array(0))));
	}

	public function doaddsubscription($threadid = "", $forumid = "")
	{
		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		if ($userinfo['userid'] <= 0)
		{
			return array('response' => array('errormessage' => 'nopermission_loggedout'));
		}

		$cleaner = vB::getCleaner();
		$threadid = $cleaner->clean($threadid, vB_Cleaner::TYPE_UINT);
		$forumid = $cleaner->clean($forumid, vB_Cleaner::TYPE_UINT);

		if ($threadid > 0)
		{
			$nodeid = $threadid;
		}
		else if ($forumid > 0)
		{
			$nodeid = $forumid;
		}
		else
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$success = vB_Api::instance('follow')->add($nodeid, vB_Api_Follow::FOLLOWTYPE_CONTENT, $userinfo['userid']);
		if (!empty($success['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}
		return array('response' => array('errormessage' => 'redirect_subsadd_thread'));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
