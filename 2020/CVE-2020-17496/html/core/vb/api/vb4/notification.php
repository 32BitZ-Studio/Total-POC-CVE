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
 * vB_Api_Vb4_notification
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_notification extends vB_Api
{
	/**
	 * Dismisses a notification by triggering the "read_topic" event on the $threadid.
	 * If threadid is not provided, it will attempt to dismiss the provided $dismissid
	 * notification directly.
	 *
	 * @param  int		$threadid	Optional integer threadid that is the
	 *								subject of a content-related notification
	 * @param  int		$dismissid	Optional numeric id of specific notification
	 *								to be dismissed. Only used if threadid is empty.
	 *
	 * @return [array]
	 */
	public function dismiss($threadid = 0, $dismissid = 0)
	{
		$cleaner = vB::getCleaner();

		// Clean the input params
		$threadid = $cleaner->clean($threadid, vB_Cleaner::TYPE_UINT);
		$dismissid = $cleaner->clean($dismissid, vB_Cleaner::TYPE_UINT);

		if (!empty($threadid))
		{
			$lib = vB_Library::instance('notification');
			// Copied from vB_Library_Node::markRead()
			$lib->triggerNotificationEvent('read_topic', array('nodeid' => $threadid));
			return array('response' => array('dismissed' => true));
		}

		if (!empty($dismissid))
		{
			$api = vB_Api::instance('notification');
			$result = $api->dismissNotification($dismissid);

			if (empty($result['error']) AND empty($result['errors']))
			{
				// If we care about checking the validity of dismissid, you could try
				// checking for (bool)$result['affected_rows']
				return array('response' => array('dismissed' => true));
			}
			else
			{
				// The client can't really handle all of the api errors that could
				// happen. Let's just dumb it down
				return array('response' => array('errormessage' => array('dismiss_failed')));
			}
		}

		return array('response' => array('errormessage' => array('no_threadid_or_dismissid')));

	}

	/**
	 * Dismisses visitormessage notifications for the current user by triggering the "read_vms" event.
	 *
	 * @return [array]
	 */
	public function dismissVms()
	{
		// The class handles providing current userid if missing.
		$lib = vB_Library::instance('notification');
		// Copied from vB_Library_Node::markRead()
		$lib->triggerNotificationEvent('read_vms');

		return array('response' => array('dismissed' => true));
	}

	/**
	 * Fetch unread notifications of the specified type, descending by date
	 *
	 * @param  String	$notificationid	Subscription|Reply
	 * @param  int		$perpage
	 * @param  int		$pagenumber
	 *
	 * @return [array]
	 */
	public function get($notificationid, $perpage, $pagenumber)
	{
		/*
			NOTE 1:
			vB_Input_Cleaner automagically translates a "page" GET/POST/GLOBAL parameter into
			"pagenumber". So although the initial API spec requested "page", not "pagenumber",
			the function definition must be "pagenumber", otherwise the api.php will just
			keep throwing "invalid_api_signature", because it "stuffs" a "pagenumber"
			param into the GET/POST array (whichever had the original "page" param).
			See convert_shortvars() & vB_Input_Cleaner() in core/includes/class_core.php
			for where this happens.

			NOTE 2:
			"notificationid" IS NOT the numeric auto_increment `notification`.notificationid
			used in the backend. It's just a string that maps to the `notificationtypes`.typename,
			but because of legacy code, and for the sake of not confusing the hell out of each other
			when talking to the mobile devs, we had to stick w/ using the term 'notificationid'.
		 */
		$cleaner = vB::getCleaner();

		// Clean the input params
		$notificationid = $cleaner->clean($notificationid, vB_Cleaner::TYPE_STR);
		$perpage = $cleaner->clean($perpage, vB_Cleaner::TYPE_UINT);
		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);

		/*
			Note, this function DOES NOT HANDLE 'vmunreadcount' for $notificationid, because
			that's a legacy thing w/ its OWN handling in the app (opens the user's profile/wall page)
			If we want this function to handle that, we should update the spec so it returns the
			NEW typename string, so we don't have to add a stupid amount of code maintenance to
			"map legacy to new string" handling.
		 */
		// Keep this in sync with vB_Api_Vb4_forum::call()
		$supportedTypes = array(
			vB_Notification_Content_GroupByStarter_Subscription::TYPENAME
				=> true,
			vB_Notification_Content_GroupByStarter_Reply::TYPENAME
				=> true,
			vB_Notification_Content_GroupByParentid_Comment::TYPENAME
				=> true,
			vB_Notification_Content_GroupByParentid_ThreadComment::TYPENAME
				=> true,
			"Flag" => true, // Flag reports...
		);

		if (!isset($supportedTypes[$notificationid]))
		{
			return array('response' => array('errormessage' => array('unsupported_notification_type')));
		}

		if ($perpage < 1)
		{
			return array('response' => array('errormessage' => array('perpage_too_small')));
		}

		if ($pagenumber < 1)
		{
			return array('response' => array('errormessage' => array('page_too_small')));
		}

		if ($notificationid == "Flag")
		{
			return $this->getReports($perpage, $pagenumber);
		}

		/*
			We can't pass in pagenumber & perpage here, because we need to return "totalpages" &
			"total" counts
		*/

		$data = array(
			'typename' => $notificationid,
			'readFilter' => 'unread_only',
		);
		$library = vB_Library::instance('notification');
		$notifications = $library->fetchNotificationsForCurrentUser($data);

		// return bits
		$total = count($notifications);
		$totalpages = ceil($total / $perpage);

		$notificationsOnPage = array_slice(
			$notifications,
			($pagenumber - 1) * $perpage,// offset
			$perpage,	// length
			true	// preserve keys
		);

		// First, cluster the node fetches into 1 call so we can bulk fetch from DB
		$nodesToFetch = array();
		foreach ($notificationsOnPage AS $nid => $notification)
		{
			if (!empty($notification['sentbynodeid']))
			{
				$nodesToFetch[$notification['sentbynodeid']] = $notification['sentbynodeid'];
			}
		}
		// According to the doc block, this function is supposed to maintain the original keys.
		$nodes = vB_Api::instance('node')->getFullContentforNodes($nodesToFetch);

		$func_lib = vB_Library::instance('vb4_functions');
		$notificationbits = array();
		foreach ($notificationsOnPage AS $nid => $notification)
		{
			if (!empty($notification['sentbynodeid']))
			{
				$node = $nodes[$notification['sentbynodeid']];
				if (empty($node) OR $node['nodeid'] !== $notification['sentbynodeid'])
				{
					// dev exception only. I've never hit this in testing, so leaving it out for now.
					//throw new vB_Exception_Api('getFullContentforNodes preserving keys was a lie. Like the cake.');
				}
				$users = array();
				if (!empty($notification['others']))
				{
					foreach ($notification['others'] AS $user)
					{
						$users[]['user'] = array(
							"userid"    => $user['userid'],
							"username"  => $user['username'],
							"avatarurl" => $this->getAbsoluteAvatarUrl($user['avatarurl']),
						);
					}
				}
				$__commentid = null;
				$__postid = null;
				if (!empty($node['starter'])
					AND $node['starter'] != $node['nodeid']
					AND $node['starter'] != $node['parentid']
				)
				{
					$__commentid = $node['nodeid'];
					$__postid = $node['parentid'];
				}

				$notificationbits[]['notification'] = array(
					"threadid"          => $node['starter'],
					"threadtitle"       => $node['content']['startertitle'],
					"preview"           => $func_lib->getPreview($node['content']['rawtext']),
					"posttime"          => $node['publishdate'],
					"forumid"           => $node['content']['channelid'],
					"forumtitle"        => $node['content']['channeltitle'],
					"notificationtime"  => $notification['lastsenttime'],
					"notificationid"    => $notificationid, // the "Type" string passed in from the app
					// This is confusing, but we can't get around this naming conflict
					// due to legacy code on the app using "notificationid".
					"dismissid"         => $notification['notificationid'],
					"users"             => $users,
					// VBV_17551. Report related fields. For non-reports, these are null.
					"reason"            => null,
					"closed"            => null,
					"report_nodeid"     => null,
					"vm_user"           => null,
					// postid may be null for non-comment non-reports, but will be
					// the parentid for comments
					"postid"            => $__postid,
					// VBV-18076 Support comment notifications
					"commentid"         => $__commentid,
				);
				unset($users);
			}
		}

		$response = array();
		$response['response'] = array(
			'pagenumber'    => $pagenumber,
			'perpage'       => $perpage,
			'totalpages'    => $totalpages,
			'total'         => $total,
		);

		$response['response']['notificationbits'] = $notificationbits;
		return $response;
	}

	/**
	 * Fetch open AND closed flag reports mapped to the output format of notifications
	 * in function get().
	 *
	 * @param  int		$perpage
	 * @param  int		$pagenumber
	 *
	 * @return [array]
	 */
	private function getReports($perpage, $pagenumber)
	{
		$canViewSpecials = vB_Api::instance('content_channel')->canViewReportsAndInfractions();
		if (!empty($canViewSpecials['result']['can_view_reports']))
		{
			/*
				We still need the absolute total for pagination / totalcount calculations, until
				we get flag report filtering/sorting
			 */
			$total = vB::getDbAssertor()->getRow('vBForum:report', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT));
			$total = $total['count'];
			/*
				As of VBV-19979 , we want to return the "Open" counts for "total", to match the message center.
				Note that this count will NOT match the actual count of notificationbits returned, because
				at the moment we have no way to filter out closed reports via the existing node or search
				methods.
				See VBV-19979 & VBV-17551 for more info.
			 */
			$totalOpen = vB::getDbAssertor()->getRow('vBForum:report',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
					vB_dB_Query::CONDITIONS_KEY => array(
						'closed' => 0,
					),
				)
			);
			$totalOpen = $totalOpen['count'];

			$notificationbits = $this->fetchReportNotificationBits($perpage, $pagenumber);

		}
		else
		{
			// They shoudln't be able to get anything out of the node API anyways, but let's hide the "total" count as well.
			$total = 0;
			$notificationbits = array();
		}

		$totalpages = ceil($total / $perpage);
		$response = array();
		$response['response'] = array(
			'pagenumber'    => $pagenumber,
			'perpage'       => $perpage,
			'totalpages'    => $totalpages,
			'total'         => $totalOpen,
			'notificationbits' => $notificationbits,
		);

		return $response;
	}


	private function fetchReportNotificationBits($perpage, $pagenumber)
	{

		/*
		Based on privatemessage_report template.
		As far as I can tell there's no way to fetch just "open" reports.

		{vb:data reportchannelid, node, fetchReportChannel}
		{vb:set sortOption.created, 'DESC'}
		{vb:set options.sort, {vb:raw sortOption}}
		{vb:set options.includeProtected, true}
		{vb:set options.nolimit, 1}

		{vb:data nodes, node, listNodeContent, {vb:raw reportchannelid}, {vb:raw page.pagenum}, 20, 0, null, {vb:raw options}}
		*/
		$nodeApi = vB_Api::instanceInternal("node");
		$nodeLib = vB_Library::instance("node");
		$reportApi = vB_Api::instanceInternal("content_report");

		$reportChannelId = $nodeApi->fetchReportChannel();
		$options = array(
			'sort' => array('created' => 'DESC'),
			'includeProtected' => true,
			'nolimit' => 1,
		);
		//$pagenum = 0;
		//$perpage = 20;
		$depth = 0;
		$contenttypeid = null;
		// Note, the way reports are saved can "leak" thread titles to moderators who do not have view permissions on the
		// reported node. This isn't an issue with mapi, but a core issue with flag reports.
		$reports = $nodeApi->listNodeContent($reportChannelId, $pagenum, $perpage, $depth, $contenttypeid, $options);
		$notificationbits = array();
		foreach ($reports AS $__node)
		{
			$__reportedNodeid = $__node['content']['reportnodeid'];
			if (empty($__reportedNodeid))
			{
				$__threadid = null;
				$__commentid = null;
				$__postid = null;
			}
			else
			{
				$__reportedNode = $nodeLib->getNodeBare($__reportedNodeid);
				$__threadid = $__reportedNodeid;
				$__commentid = null;
				$__postid = $__reportedNodeid;
				if (!empty($__node['content']['reportparentnode']))
				{
					$__threadid = $__node['content']['reportparentnode']['starter'];
				}

				if (!empty($__reportedNode['starter'])
					AND $__reportedNode['nodeid'] != $__reportedNode['starter']
					AND $__reportedNode['parentid'] != $__reportedNode['starter']
				)
				{
					// reported node is a comment
					$__commentid = $__reportedNode['nodeid'];
					$__postid = $__reportedNode['parentid'];
				}
			}

			// This is the reporter's user info.
			$__users = array();
			$__users[]['user'] = array(
				'userid'    => $__node['content']['userinfo']['userid'],
				'username'  => $__node['content']['userinfo']['username'],
				'avatarurl' => $this->getAbsoluteAvatarUrl($__node['content']['avatar']['avatarpath']),
			);

			$__vmUser = null;
			// isVisitorMessage() has no content-type-specific dependencies
			// so we can just use the content_report instance
			if (!empty($__reportedNodeid))
			{
				$isVM = $reportApi->isVisitorMessage($__reportedNodeid);
				if ($isVM)
				{
					if (!empty($__reportedNode['setfor']))
					{
						$__vmUser = $__reportedNode['setfor'];
					}
				}
			}

			$notificationbits[]['notification'] = array(
				"threadid"          => $__threadid,
				// Per specifications, this is the phrased report's title, like "Comentar en un tema: Cool Thread",
				// NOT the reported node's title, like "Cool Thread".
				"threadtitle"       => $__node['title'],
				"preview"           => null,
				"posttime"          => null,
				"forumid"           => null,
				"forumtitle"        => null,
				"notificationtime"  => $__node['publishdate'],
				"notificationid"    => "Flag", // the "Type" string passed in from the app
				"dismissid"         => null,
				"users"             => $__users,
				// VBV_17551 - mapping flag reports into notificationbits
				"reason"            => $__node['content']['rawtext'],
				"closed"            => $__node['content']['closed'],
				"report_nodeid"     => $__node['nodeid'],
				"vm_user"           => $__vmUser,
				// postid will be the parentid instead of the reported node
				// if reported node is a comment
				"postid"            => $__postid,
				// VBV-18076 Support comment notifications
				"commentid"         => $__commentid,
			);
		}

		return $notificationbits;
	}


	protected function getAbsoluteAvatarUrl($url)
	{
		/*
			So far, all of the avatar URLs were relative without a starting '/',
			so this is mostly to prepend it w/ the frontendurl + '/', with some
			"just in case" checks.
		 */
		if (substr($url, 0, 7) === 'http://' OR substr($url, 0, 8) === 'https://')
		{
			return $url;
		}
		else
		{
			$options = vB::getDatastore()->getValue('options');
			$baseurl_cdn = $vboptions['cdnurl'];

			if($baseurl_cdn)
			{
				$baseurl_corecdn = $baseurl_cdn . '/core';
			}
			else
			{
				//if we haven't set a cdn url, then let's default to the actual site urls.
				$baseurl_corecdn = rtrim($options['frontendurl'], '/') . '/core';
			}
			$url = ltrim($url, '/');

			return $baseurl_corecdn . '/' . $url;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104032 $
|| #######################################################################
\*=========================================================================*/
