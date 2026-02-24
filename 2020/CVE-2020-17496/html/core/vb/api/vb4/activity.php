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
 * vB_Api_Vb4_activity
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_activity extends vB_Api
{
	const FILTER_SORTBY_RECENT  = 'recent';
	const FILTER_SORTBY_POPULAR = 'popular';
	const FILTER_LASTDAY 		= 'today';
	const FILTER_LASTWEEK 		= 'week';
	const FILTER_LASTMONTH 		= 'month';
	//const FILTER_SHOW_ALL  		= 'all';
	const FILTER_SHOW_SOCIALGROUP = 'socialgroup';
	const FILTER_SHOW_BLOG 		= 'blog';
	const FILTER_SHOW_CMS		= 'cms';
	const FILTER_SHOW_FORUM		= 'forum';
	const FILTER_SHOW_PHOTOS	= 'photos';

	/**
	 *  Results per page
	 */
	protected $perpage = 15;

	// Resovling the result structure block name
	protected $section = array(
		// Commented out are not yet implemented in vb5
		'album' 	  => 'albuminfo',
		//'calendar'	  => 'calendarinfo',
		'forum' 	  => 'foruminfo',
		'socialgroup' => 'groupinfo',
		/*
			I don't know what actually *uses* $this->section (other sections are all hard-coded
			but items with section == 'cms' will have 'nodeinfo' & 'articleinfo' blocks...
			I have no idea where 'cmsinfo' came from.
		 */
		//'cms' 		  => 'cmsinfo',
		'cms' => array('nodeinfo', 'articleinfo'),
		'blog' 		  => 'bloginfo',
	);

	// Top channels of the board
	protected $topChannels = array();

	/**
	 * Default activity call.
	 *
	 * @param  integer $userid      [userid]
	 * @param  integer $mindateline [The dateline of the min record currently shown]
	 * @param  integer $maxdateline [The dateline of the max record currently shown]
	 * @param  integer $minscore    []
	 * @param  mixed   $minid       [CSV of the ids of the items with mindateline]
	 * @param  string  $maxid       [CSV of the ids of the items with maxdateline]
	 * @param  string  $sortby      [Sorting the results. Possible values see constant with FILTER_SORT_BY_*]
	 * @param  string  $time        [Filtering the results. Possible values see constant with FILTER_*]
	 * @param  string  $show        [Filtering the results by section. Possible values see constant with FILTER_SHOW_*]
	 * @return array                [Result structure]
	 */
	public function call(
		$userid = 0,
		$mindateline = 0,
		$maxdateline = 0,
		$minscore = 0,
		$minid = '',
		$maxid = '',
		$sortby = '',
		$time = '',
		$show = '',
		$pagenumber = 0
	)
	{
		$cleaner = vB::getCleaner();

		$userid 	 = $cleaner->clean($userid, vB_Cleaner::TYPE_UINT);
		$mindateline = $cleaner->clean($mindateline, vB_Cleaner::TYPE_UINT);
		$maxdateline = $cleaner->clean($maxdateline, vB_Cleaner::TYPE_UINT);
		$minscore	 = $cleaner->clean($minscore, vB_Cleaner::TYPE_NUM);
		$minid 		 = $cleaner->clean($minid, vB_Cleaner::TYPE_STR);
		$maxid 		 = $cleaner->clean($maxid, vB_Cleaner::TYPE_STR);
		$sortby 	 = $cleaner->clean($sortby, vB_Cleaner::TYPE_STR);
		$time 		 = $cleaner->clean($time, vB_Cleaner::TYPE_STR);
		$show 		 = $cleaner->clean($show, vB_Cleaner::TYPE_STR);
		$pagenumber  = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);

		$usedFilter = false;

		$searchJSON = array();

		$searchJSON['view'] = vB_Api_Search::FILTER_VIEW_ACTIVITY;

		if (!empty($userid))
		{
			$searchJSON['authorid'] = $userid;
		}

		// In vb4 when you send $mindateline You send the minid(s) (when you click on show more)
		// and with that info you get older set of data for the stream
		if (!empty($mindateline))
		{
			$searchJSON['date']['to'] = $mindateline;
			$usedFilter = true;
		}

		// In vb4 when you send $maxdateline You send the maxid(s)
		// and with that info you get any newer results that are there (if any)
		if (!empty($maxdateline))
		{
			$searchJSON['date']['from'] = $maxdateline;
			$usedFilter = true;
		}

		if (!empty($sortby))
		{
			if ($sortby == self::FILTER_SORTBY_RECENT)
			{
				$searchJSON['sort'] = array('dateline' => 'desc');
			}
			else
			{
				// Best we have in vB5 is replies, this could also be votes if desired
				$searchJSON['sort'] = array('replies' => 'desc');
				$usedFilter = true;
			}
		}

		if (!empty($time))
		{
			$usedFilter = true;
			if ($time == self::FILTER_LASTDAY)
			{
				$searchJSON['date']['from'] = vB_Api_Search::FILTER_LASTDAY;
			}
			elseif ($time == self::FILTER_LASTWEEK)
			{
				$searchJSON['date']['from'] = vB_Api_Search::FILTER_LASTWEEK;
			}
			elseif ($time == self::FILTER_LASTMONTH)
			{
				$searchJSON['date']['from'] = vB_Api_Search::FILTER_LASTMONTH;
			}
		}
		else
		{
			$searchJSON['date']['from'] = vB_Api_Search::FILTER_LASTYEAR;
		}

		if (!empty($show))
		{
			$usedFilter = true;
			$topChannels = $this->getTopChannels();

			if ($show == self::FILTER_SHOW_SOCIALGROUP)
			{
				//get the sg channel
				$searchJSON['channel'] = $topChannels['groups'];
			}
			elseif ($show == self::FILTER_SHOW_BLOG)
			{
				// get the blog channel
				$searchJSON['channel'] = $topChannels['blog'];
			}
			elseif ($show == self::FILTER_SHOW_CMS)
			{
				// get the articles channel
				$searchJSON['channel'] = $topChannels['articles'];
			}
			elseif ($show == self::FILTER_SHOW_FORUM)
			{
				// get the forum channel
				$searchJSON['channel'] = $topChannels['forum'];
			}
			elseif ($show == self::FILTER_SHOW_PHOTOS)
			{
				// In vb4 this means getting the photos from the socialgroups and albums
				// NOTE: This has different result layout then the others
				$searchJSON['type'] = array('vBForum_Photo');
			}
		}

		$searchJSON['exclude_type'] = array(
			// Exclude PMs. vB4 didn't seem to show these in the activities.
			'vBForum_PrivateMessage',
			// Exclude Visitor Messages, as we currently don't parse those causing "gaps"
			// in the final returned results. See VBV-19433
			'vBForum_VisitorMessage',
		);

		$result = vB_Api::instance('search')->getInitialResults($searchJSON, $this->perpage, (empty($pagenumber) ? 1 : $pagenumber), true);

		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		// search API just returns the last page if the requested pagenumber is greater than
		// the total # of pages. Check the limit ourselves and return an empty result to avoid
		// endlessly repeating the last page on mobile client.
		if ($pagenumber > $result['totalpages'])
		{
			$activitybits = array();
		}
		else
		{
			$activitybits = $this->prepareSearchData($result, $show);
		}

		$count = count($activitybits);

		// Where do I get the data for 'actdata' (perpage, refresh) and for 'show' -> Need to investigate how this is done in vb4 activity
		$response = array(
			'actdata' => array(
				'mindateline' => $mindateline,
				'maxdateline' => $maxdateline,
				'minscore' 	  => $minscore,
				'minid' 	  => $minid,
				'maxid' 	  => $maxid,
				'count' 	  => $count,
				'totalcount'  => $result['totalRecords'],
				'perpage' 	  => $this->perpage,
				'time' 		  => $time,
				'sortby' 	  => $sortby,
				'refresh' 	  => 1,
			),
			'show' => array(
				'more_results' => $result['hasMore'],
				'as_blog' => true,
				'as_cms' => true ,
				'as_socialgroup' => true,
				'filterbar' => $usedFilter,
			),
		);

		$response['activitybits'] = $activitybits;

		return array(
			'response' => $response,
		);
	}

	/**
	 * Structuring the result data for output
	 *
	 * @param  [Array]  $result [Array with the search result]
	 * @param  [String] $show   [See constant FILTER_SHOW_*. Only when it has value 'photos' it changes the output structure]
	 *
	 * @return [array]			[Formatted structure for output]
	 */
	private function prepareSearchData($result, $show)
	{
		$bbcodeParserInstance = new vB_Library_BbCode(true, true);
		$nodeLib = vB_Library::instance('node');
		$nodeApi = vB_Api::instance('node');
		$activitybits = array();
		/*
			view counts are only tracked for starters, but not everything in the
			results is a starter, so we have to fetch them separately rather than
			calling vB_Api_Node::mergeNodeviewsForTopics()
		*/
		$starters = array();
		foreach ($result['results'] AS $__node)
		{
			$starters[$__node['starter']] = $__node['starter'];
		}
		$nodeViews = $nodeLib->getNodeviews($starters);


		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		$topChannels = $this->getTopChannels();
		$functionsLib = vB_Library::instance('vb4_functions');

		foreach ($result['results'] AS $node)
		{
			$activitybit = array();

			if (empty($node['content']))
			{
				$conversation = $node;
			}
			else
			{
				$conversation = $node['content'];
			}

			$itemSection  = $this->getSection($node);

			if (empty($itemSection))
			{
				// This might be some weird node under the special channel or some other node
				// that shouldn't have ended up here. Just skip it.
				continue;
			}

			// Socialgroup not handled in the apps
			// TODO: Need to look into this.
			if ($itemSection == 'socialgroup')
			{
				continue;
			}
			$activityType = $this->getActivityType($itemSection, $node);

			$activitybit['activity'] = array(
				'posttime' => vbdate('h:i A', $conversation['publishdate']),
				'postdate' => vbdate('m-d-Y', $conversation['publishdate']),
				'section'  => $itemSection,
				'type'	   => $activityType,
				'score'	   => 0.000,
			);

			if ($show == self::FILTER_SHOW_PHOTOS)
			{
				// TODO: TEST THIS
				$activitybit['attachmentinfo'] = array(
					// Hack to let attachment.php differentiate legacy vs vB5 attachments.
					'attachmentid'  => - intval($conversation['nodeid']),
					'dateline' 		=> $conversation['publishdate'],
					'thumbnail_width'  => '',
					'thumbnail_height' => '',
				);

				if ($itemSection == 'socialgroup')
				{
					$activitybit['groupinfo'] = array(
						'albumid' => $conversation['parentid'],
					);
				}
				else
				{
					$activitybit['albuminfo'] = array(
						'albumid' => $conversation['parentid'],
					);
				}
			}
			else
			{
				// Section specific info
				switch ($itemSection)
				{
					case 'forum':
						// @TODO: This is inside the special channel and not here, but at this moment the search api doesn't even return vm's.
						// Need to set up a filter for those or just a flag of ijf we should include or not.
						if (!empty($node['setfor']))
						{
							$activitybit['messageinfo'] = array(
								'vmid' 	  => $node['nodeid'],
								'preview' => $node['preview'],
							);

							$activitybit['userinfo2'] = array(
								'userid'   => $node['setfor'],
								'username' => vB_Library::instance('user')->fetchUserName($node['setfor']),
							);
						}
						else
						{
							$isPost = false;

							if ($node['nodeid'] == $node['starter'])
							{
								$forumInfo  = $nodeLib->getNodeBare($node['parentid']);
								$threadInfo = $node;

								$forumid  =	(int)$node['parentid'];
								$threadid = $postid = (int)$node['nodeid'];
								$threadPreview = $postPreview = $node['content']['rawtext'];
							}
							else
							{
								$threadInfo = $nodeLib->getNode($node['starter']);
								$forumInfo  = $nodeLib->getNodeBare($threadInfo['parentid']);

								$forumid  =	(int)$forumInfo['nodeid'];
								$threadid = (int)$threadInfo['nodeid'];
								$postid   = (int)$node['nodeid'];
								$threadPreview = $threadInfo['content']['rawtext'];
								$postPreview   = $node['content']['rawtext'];
								$isPost = true;
							}

							$activitybit['foruminfo'] = array(
								'forumid' => $forumid,
								'title'   => vB_String::unHtmlSpecialChars($forumInfo['title']),
							);

							$activitybit['threadinfo'] = array(
								'title'		 => vB_String::unHtmlSpecialChars($threadInfo['title']),
								'forumid'	 => $forumid,
								'replycount' => $threadInfo['totalcount'],
								'views'		 => $nodeViews[$threadid] ?? 0,
								'preview' => $functionsLib->getPreview($threadPreview),
							);

							if ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Poll'))
							{
								/*
									I have no idea where the old spec was from, but
									the examples in https://admin.vbulletin.com/wiki/VB4_API:activity
									show *both* threadid & pollid, and the app doesn't know what to do
									with *just* pollid, so I'm adding threadid here.
								*/
								$activitybit['threadinfo']['threadid'] = $threadid;
								$activitybit['threadinfo']['pollid'] = $node['nodeid'];
							}
							else
							{
								$activitybit['threadinfo']['threadid'] = $threadid;
							}

							if ($isPost)
							{
								$activitybit['postinfo'] = array(
									'postid'   => $postid,
									'threadid' => $threadid,
									'preview' => $functionsLib->getPreview($postPreview),
								);
							}

							$activitybit['show'] = array(
								'threadcontent' => true,
							);
						}
						break;

					case 'blog':
						$blogComment = false;

						if ($node['parentid'] == $topChannels['blog'])
						{
							// if it is a blog dont include it
							continue 2;
						}
						elseif ($node['nodeid'] == $node['starter'])
						{
							// blog entry
							$blogentryInfo  = $node;
							$blogInfo  		= $nodeLib->getNodeBare($node['parentid']);
						}
						else
						{
							// blog comment
							$blogentryInfo  = $nodeLib->getNode($node['parentid']);
							$blogInfo  		= $nodeLib->getNodeBare($blogentryInfo['parentid']);
							$blogComment = true;
						}

						$activitybit['bloginfo'] = array(
							'blogid' => $blogentryInfo['nodeid'],
							'title'  => vB_String::unHtmlSpecialChars($blogentryInfo['title']),
							'blog_title' => vB_String::unHtmlSpecialChars($blogInfo['title']),
							// TODO: This doesn't seem right but I'm not going to go search around
							// for this at this point. Should this be blogentryInfo['textcount'] instead?
							'comments_visible' => $blogInfo['textcount'],
							// Let's just go with the blog entry's views. We only keep track of starter views.
							'views' => $nodeViews[$blogentryInfo['nodeid']] ?? 0,
							'preview' => $functionsLib->getPreview($blogentryInfo['content']['rawtext']),
						);

						if ($blogComment)
						{
							$activitybit['blogtextinfo'] = array(
								'blogtextid' => $node['nodeid'],
								'preview' => $functionsLib->getPreview($node['content']['rawtext']),
							);
						}
						break;

					case 'cms':
						if ($node['contenttypeid'] == $channelTypeId)
						{
							/*
								Similar to the skip blog check above,
								if it's a section (vB5 channel), let's
								skip it
								todo: Do we need this? Should the search
								by default skip channels???
							 */
							continue 2;
						}
						elseif ($node['nodeid'] == $node['starter'])
						{
							// cms article
							$article  = $node;
						}
						else
						{
							// cms comment
							$article  = $nodeApi->getNodeFullContent($node['starter']);
							if (empty($article[$node['starter']]))
							{
								// If we don't have the node for some reason (permissions maybe?) skip.
								continue 2;
							}
							$article = $article[$node['starter']];
						}

						/*
							From looking at ActivityItemFactory, ActivityItem &
							ActivityItemViewAdapter java class (android app source)...

							ActivityItemViewAdapter::fillArticleView() & onClick() use the
							following bits:
							nodeinfo
								replycount
								viewcount
								title
								nodeid
							articleinfo
								preview

							articleinfo.preview seems to be the current node's preview, e.g. the comment
							not the parent article

						 */
						$activitybit['nodeinfo'] = array(
							'replycount' => (int) $article['content']['startertotalcount'] - 1,
							'viewcount' => (int) $nodeViews[$article['nodeid']] ?? 0,
							'title' => (string) $article['title'],
							'nodeid' => (int) $article['nodeid'],
						);

						$nodePreview = $functionsLib->getPreview($node['content']['rawtext']);
						$activitybit['articleinfo'] = array(
							'preview' => (string) $nodePreview,
							//'fullurl' => (string) "", // unused AFAIK, skipping for now to skip route instance
						);
						break;

					case 'socialgroup':
						$discussionInfo = false;
						$messageinfo = false;

						if ($node['parentid'] == $topChannels['groups'])
						{
							// group
							$groupInfo = $node;
						}
						elseif ($node['nodeid'] == $node['starter'])
						{
							// group discussion
							$discussionInfo = $node;
							$groupInfo 		= $nodeLib->getNodeBare($node['parentid']);
						}
						else
						{
							// group message
							$discussionInfo = $nodeLib->getNodeBare($node['parentid']);
							$groupInfo 		= $nodeLib->getNodeBare($discussionInfo['parentid']);
							$messageInfo 	= $node;
						}

						$activitybit['groupinfo'] = array(
							'groupid' => $groupInfo['nodeid'],
							'name'    => $groupInfo['title'],
						);

						if ($discussionInfo)
						{
							$activitybit['discussioninfo'] = array(
								'discussionid' => $discussionInfo['nodeid'],
								'title'		 => $discussionInfo['title'],
								'preview' => $functionsLib->getPreview($discussionInfo['content']['rawtext']),
								'visible'	 => 1,
							);
						}

						if ($messageInfo)
						{
							$activitybit['messageinfo'] = array(
								'gmid'     => $messageInfo['nodeid'],
								'preview' => $functionsLib->getPreview($discussionInfo['content']['rawtext']),
							);
						}

						break;

					case 'album':
						// Only show albums, not individual photos in albums.
						// For some reason, the search can return individual photos
						// added later to the album.
						if (!($node['nodeid'] == $node['starter']))
						{
							$album = $nodeLib->getNodeFullContent($node['starter']);
							if (empty($album[$node['starter']]))
							{
								// This shouldn't happen AFAIK. Maybe if there's data corruption/incomplete cleanup?
								continue 2;
							}
							$album = $album[$node['starter']];
						}
						else
						{
							$album = $node;
						}

						// There are some serious inconsistencies between getNodeFullContent() and
						// returned node array from search results...
						if (!isset($album['photo']) AND isset($album['content']['photo']))
						{
							$album['photo'] = $album['content']['photo'];
						}
						if (!isset($album['photopreview']) AND isset($album['content']['photopreview']))
						{
							$album['photopreview'] = $album['content']['photopreview'];
						}
						if (!isset($album['photocount']) AND isset($album['content']['photocount']))
						{
							$album['photocount'] = $album['content']['photocount'];
						}


						// Use actual thumbnail size if thumbnail is found.
						// TODO: include this as part of the regular 'photo' array info?
						$filedataids = array();
						foreach ($album['photopreview'] AS $key => $photo)
						{
							$filedataids[$photo['filedataid']] = $photo['filedataid'];
						}
						$thumbInfoQuery = vB::getDbAssertor()->getRows(
							'vBForum:filedataresize',
							array(
								vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
								vB_dB_Query::COLUMNS_KEY => array('filedataid', 'resize_width', 'resize_height'),
								vB_dB_Query::CONDITIONS_KEY => array(
									'resize_type' => vB_Api_Filedata::SIZE_THUMB,
									'filedataid' => $filedataids
								),
							)
						);
						$thumbInfo = array();
						foreach ($thumbInfoQuery AS $row)
						{
							$thumbInfo[$row['filedataid']] = $row;
						}

						/*
							Since this is an "album", let's just ignore any attachments that
							the user might've added to the post. Especially since clicking on
							an album doesn't show the post, just the photos in the gallery.
							vB4 didn't have a "gallery", so it didn't have this issue.
						*/

						$activitybit['albuminfo'] = array(
							'albumid' => $album['nodeid'],
							'title'		 => $album['title'],
							// Both of these are missing in the examples in wiki
							'picturecount'	 => $album['photocount'],
							'views'	 => $nodeViews[$album['nodeid']] ?? 0,
						);
						$activitybit['photocount'] = $album['photocount'];
						$activitybit['attach'] = array();

						// Let's just use the photo preview for this view. It never shows more than 3 photos anyways.
						foreach ($album['photopreview'] as $photo) {
							$thumburl = $bbcodeParserInstance->getAttachmentLink($photo, vB_Api_Filedata::SIZE_THUMB);
							$filedataid = $photo['filedataid'];
							if (isset($thumbInfo[$filedataid]))
							{
								$thumbwidth = $thumbInfo[$filedataid]['resize_width'];
								$thumbheight = $thumbInfo[$filedataid]['resize_height'];
							}
							else
							{
								$thumbwidth = $photo['width'];
								$thumbheight = $photo['height'];
							}

							$activitybit['attach'][] = array(
								// Hacky hack to let attachment.php know that this negative attachmentid is a vB5 attachment
								// not legacy.
								'attachmentid'  => - intval($photo['nodeid']),
								'thumburl' => $thumburl,
								'dateline'		=> $photo['dateline'],
								'thumbnail_width'	 => $thumbwidth,
								'thumbnail_height'	 => $thumbheight,
							);
						}

						break;

					default:
						break;
				}
			}

			$userInfo = vB_Library::instance('user')->fetchUserinfo($node['userid'], array('avatar'));

			$activitybit['userinfo'] = array(
				'userid'   => $userInfo['userid'],
				'username' => $userInfo['username'],
				'avatarurl'  => vB_Library::instance('vb4_functions')->avatarUrl($userInfo['userid']),
				'showavatar' => $userInfo['showavatars'],
			);

			$activitybits[] = $activitybit;
		}

		return $activitybits;
	}

	/**
	 * Determins the section of the node. Map it to the vb4 sections
	 *
	 * @param  [array]  $node    [The node that needs to be mapped]
	 * @return [string] $section [The section]
	 */
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
		else if (in_array($topChannels['articles'], $node['parents']))
		{
			$section = 'cms';
		}
		else if (in_array($topChannels['groups'], $node['parents']))
		{
			$section = 'socialgroup';
		}
		else if (in_array($topChannels['special'], $node['parents']))
		{
			// There are more than just "albums" in the special channel. For ex. PMs, reports, infractions...
			if (isset($node['content']['channeltype']) AND $node['content']['channeltype'] == 'album')
			{
				$section = 'album';
			}
			else if (!isset($node['content']['channeltype']))
			{
				$channelAPI = vB_Api::instance('content_channel');
				$albumChannelId = $channelAPI->fetchChannelIdByGUID(vB_Channel::ALBUM_CHANNEL);
				if (in_array($albumChannelId, $node['parents']))
				{
					$section = 'album';
				}
			}
		}

		if (empty($section))
		{
			// @TODO: This must not happen. Or this should throw an error.
			// UPDATE: this can happen because we don't exclude the special channel
			// which might have more than just "albums" in it.
			// Let's change the behavior to have the parser ignore anything with
			// an empty section.
			// We might be able to narrow down the result set if the 'channel' filter
			// allows for multiples and we specify all the highest level channels
			// (ex. Forum, Article, Blog, Social Group?, Album)
		}

		return $section;
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

		switch ($section)
		{
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
			case 'cms':
				/*
					See ActivityItem.java
						public static String TYPE_CMS_ARTICLE = "article";
						public static String TYPE_CMS_COMMENT = "comment";
				 */
				if ($node['nodeid'] == $node['starter'])
				{
					$type = 'article';
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
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104030 $
|| #######################################################################
\*=========================================================================*/
