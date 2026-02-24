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

class vB5_Frontend_Controller_Profile extends vB5_Frontend_Controller
{
	/**
	 * Gets the default Avatars- echo's html
	 */
	public function actionGetdefaultavatars()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();
		$avatars = $api->callApi('profile', 'getDefaultAvatars', array());
		$templater = new vB5_Template('defaultavatars');
		$templater->register('avatars', $avatars);
		$this->outputPage($templater->render());
	}

	/**
	 * gets the avatar url for a specific user.
	 */
	public function actionGetAvatarUrl()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (!empty($_REQUEST['userid']))
		{
			$api = Api_InterfaceAbstract::instance();
			$avatarUrl = $api->callApi('user', 'fetchAvatar', array('userid' => $_REQUEST['userid']));
			$this->outputPage($avatarUrl['avatarpath']);
		}
	}

	/**
	 * sets avatar to one of the defaults
	 */
	public function actionSetDefaultAvatar()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// avatarid comes in via query string, see profile.js's setDefaultAvatar() function
		if (!empty($_REQUEST['avatarid']))
		{
			$api = Api_InterfaceAbstract::instance();
			$avatarUrl = $api->callApi('user', 'setDefaultAvatar', array('avatarid' => $_REQUEST['avatarid']));
			$this->sendAsJson($avatarUrl);
		}
	}

	/**
	 * resets the avatar to the default/no avatar
	 */
	public function actionResetAvatar()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$api = Api_InterfaceAbstract::instance();
		$avatarUrl = $api->callApi('profile', 'resetAvatar', array('profile'));
		$this->sendAsJson($avatarUrl);
	}


	/**
	 * uploads an image and sets it to be the avatar
	 */
	public function actionUploadProfilepicture()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ($_FILES AND !empty($_FILES['profilePhotoFile']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('profile', 'upload', array('file' => $_FILES['profilePhotoFile'], 'data' => $_REQUEST));
		}
		elseif (!empty($_POST['filedataid']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('profile', 'cropFileData', array('filedataid' => $_POST['filedataid'], 'data' => $_REQUEST));
		}
		elseif (!empty($_POST['profilePhotoUrl']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('profile', 'uploadUrl', array('url' => $_POST['profilePhotoUrl'], 'data' => $_REQUEST));
		}
		elseif (!empty($_FILES['profilePhotoFull']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('content_attach', 'uploadProfilePicture', array('file' => $_FILES['profilePhotoFull']));
			$response['imageUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'];
		}
		else
		{
			$response['errors'] = "No files to upload";
		}
		$this->sendAsJson($response);
	}

	/**
	 * Sets a filter and returns the filtered Activity list
	 */
	public function actionApplyfilter()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$filters = $_REQUEST['filters'];
		$result = array(
			'total' => 0,
			'total_with_sticky' => 0,
			'template' => '',
			'resultId' => 0,
			'css_links' => array(),
		);

		$resultId = isset($filters['result-id']) ? intval($filters['result-id']) : 0;
		$pagenumber = isset($filters['pagenum']) ? intval($filters['pagenum']) : false;
		$perpage = (isset($filters['per-page'])) ? intval($filters['per-page']) : false;
		$api = Api_InterfaceAbstract::instance();

		// if resultid
		if (!empty($resultId))
		{
			$nodes = $api->callApi('search', 'getMoreResults', array($resultId, 'perpage' => $perpage, 'pagenumber' => $pagenumber));
			$templater = new vB5_Template('profile_activity');
			$templater->register('nodes', $nodes['results']);
			$result['template'] = $templater->render(true, true);
			$result['total'] = $result['total_with_sticky'] = count($nodes['results']);
			$showSeeMore = ($nodes['totalpages'] > $pagenumber) ? true : false;
			$result['resultId'] = $nodes['resultId'];
			$result['pageinfo'] = array('pagenumber' => $pagenumber, 'totalpages' => $nodes['totalpages'], 'showseemore' => $showSeeMore);
			$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();
			$this->sendAsJson($result);
		}
		else
		{
			//We need at least a userid
			if (empty($filters['userid']) OR !intval($filters['userid']))
			{
				$this->sendAsJson($result);
				return;
			}
			else
			{
				$searchJson = array('authorid' => $filters['userid'], 'view' => 'conversation_stream');
			}

			// source filter
			if (isset($filters['filter_source']))
			{
				switch ($filters['filter_source'])
				{
					case 'source_user':
						$searchJson['ignore_protected'] = 1;
						break;
					case 'source_vm':
						$searchJson['visitor_messages_only'] = 1;
						break;
					default:
						// source all
						$searchJson['include_visitor_messages'] = 1;
						break;
				}
			}

			if (!empty($filters['filter_show']) AND $filters['filter_show'] != 'show_all')
			{
				$searchJson['type'] = $filters['filter_show'];
			}

			if (!empty($filters['filter_time']))
			{
				switch ($filters['filter_time'])
				{
					case 'time_today':
						$searchJson['date']['from'] = 'lastDay';//vB_Api_Search::FILTER_LASTDAY
					break;
					case 'time_lastweek':
						$searchJson['date']['from'] = 'lastWeek';//vB_Api_Search::FILTER_LASTWEEK
					break;
					case 'time_lastmonth':
						$searchJson['date']['from'] = 'lastMonth';//vB_Api_Search::FILTER_LASTMONTH
					break;
					case 'time_lastyear':
						$searchJson['date']['from'] = 'lastYear';//vB_Api_Search::FILTER_LASTYEAR
					break;
					default:
					case 'time_all':
						$searchJson['date'] = 'all';
					break;
				}
			}
			else if (empty($filters['filter_time']) OR ($filters['filter_time'] == 'time_all'))
			{
				$searchJson['date'] = 'channelAge';
			}

			if (!empty($filters['exclude_visitor_messages']))
			{
				$searchJson['exclude_visitor_messages'] = 1;
				if (isset($searchJson['include_visitor_messages']))
				{
					unset($searchJson['include_visitor_messages']);
				}
			}
			$searchJson['exclude_type'] = array('vBForum_PrivateMessage', 'vBForum_Channel');

			$nodes = $api->callApi('search', 'getInitialResults', array('search_json' => $searchJson, 'perpage' => $perpage, 'pagenumber' => $pagenumber, 'getStarterInfo' => 1));
			if (!empty($nodes['errors']))
			{
				$this->sendAsJson($nodes);
				return;
			}
			$templater = new vB5_Template('profile_activity');
			$templater->register('nodes', $nodes['results']);
			$templater->register('userid', $filters['userid']);
			$userInfo = $api->callApi('user', 'fetchUserinfo', array());
			if (!empty($userInfo['userid']))
			{
				foreach ($nodes['results'] as $conversation)
				{
					if((!empty($conversation['setfor'])) AND ($userInfo['userid'] == $conversation['setfor']) AND (
							($conversation['content']['moderatorperms']['canmoderateposts'] > 0)
							OR ($conversation['content']['moderatorperms']['candeleteposts'] > 0)
							OR ($conversation['content']['moderatorperms']['caneditposts'] > 0)
							OR ($conversation['content']['moderatorperms']['canopenclose'] > 0)
							OR ($conversation['content']['moderatorperms']['canmassmove'] > 0)
							OR ($conversation['content']['moderatorperms']['canremoveposts'] > 0)
							OR ($conversation['content']['moderatorperms']['cansetfeatured'] > 0)
					))
					{
						$templater->register('showInlineMod', 1);
						break;
					}
				}
			}
			$result['template'] = $templater->render(true, true);
			$result['total'] = $result['total_with_sticky'] = count($nodes['results']);
			$result['resultId'] = $nodes['resultId'];
			$showSeeMore = ($nodes['totalpages'] > $pagenumber) ? true : false;
			$result['pageinfo'] = array('pagenumber' => $pagenumber, 'totalpages' => $nodes['totalpages'], 'showseemore' => $showSeeMore);
			$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();
			$this->sendAsJson($result);
		}

	}

	/** Add/delete following from user **/
	public function actionFollowButton()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// do, follower & type can come in via query string, see the click handlers for
		// '#groupSubscribersAll .action_button' in group_summary.js,
		// '.following_remove' in privatemessage.js,
		// '.profileTabs .action_button' in profile.js,
		// & function actionSubscribeButton() in subscription.js
		if (!empty($_REQUEST['follower']) AND !empty($_REQUEST['type']) AND !empty($_REQUEST['do']))
		{
			$follower = $_REQUEST['follower'];
			$type = $_REQUEST['type'];
			$action = $_REQUEST['do'];

			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('follow', $action, array('follower' => $follower, 'type' => $type));
			$this->sendAsJson($response);
		}
	}

	/** Fetches the info applying the filter criteria. **/
	public function actionFollowingFilter()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$result = array(
			'total' => 0,
			'total_with_sticky' => 0,
			'template' => '',
			'pagenavTemplate' => ''
		);

		$filters = $_REQUEST['filters'];
		$follower = $filters['userid'];
		if (empty($follower) OR !intval($follower))
		{
			$this->sendAsJson($result);
			return;
		}

		$type = (isset($filters['type']) AND !empty($filters['type'])) ? $filters['type'] : 'follow_all';
		$sortBy = ((isset($filters['filter_sort']) AND in_array($filters['filter_sort'], array('leastactive', 'mostactive', 'all')))) ? $filters['filter_sort'] : 'all';

		//pagination data
		$perPage = (isset($filters['per-page']) AND is_numeric($filters['per-page'])) ? $filters['per-page'] : 100;
		$page = (isset($filters['pagenum']) AND is_numeric($filters['pagenum'])) ? $filters['pagenum'] : 1;

		$api = Api_InterfaceAbstract::instance();
		$templater = new vB5_Template('subscriptions_one');

		//fetch profile info of the viewing user
		$userInfo = $api->callApi('user', 'fetchProfileInfo', array());

		//for guest users, 'incorrect_data exception' is thrown. but that's fine, as we only need the userInfo if the viewing user is the profile owner
		if (!empty($userInfo) AND !empty($userInfo['errors']))
		{
			$userInfo['userid'] = 0;
		}

		if ($follower == $userInfo['userid']) //viewing user is the profile owner
		{
			$templater->register('showOwner', true);
			$templater->register('userInfo', $userInfo);
			$response = $api->callApi('follow', 'getFollowingForCurrentUser', array('type' => $type, 'options' => array('page' => $page, 'perpage' => $perPage, 'filter_sort' => $sortBy)));
		}
		else //viewing user is either a guest user or a member but not the profile owner
		{
			$params = array('userid' => $follower, 'type' => $type, 'filters' => array('filter_sort' => $sortBy), null, 'options' => array('page' => $page, 'perpage' => $perPage));
			$response = $api->callApi('follow', 'getFollowing', $params);
		}
		$templater->register('followings', $response['results']);
		$result['template'] = $templater->render();
		$result['total'] = $result['total_with_sticky'] = $response['paginationInfo']['totalcount'];
		$result['pageinfo'] = array('pagenumber' => $response['paginationInfo']['page'], 'totalpages' => $response['paginationInfo']['totalpages']);

		$this->sendAsJson($result);
	}

	/** Add/delete followers from user. **/
	public function actionFollowers()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (!empty($_REQUEST['follower']) AND !empty($_REQUEST['do']))
		{
			$follower = $_REQUEST['follower'];
			$action = $_REQUEST['do'];
			$params = array('follower' => $follower);

			if (!empty($_REQUEST['type']) AND $_REQUEST['type'] == 'follower')
			{
				$action = $action . 'Follower';
			}
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('follow', $action, $params);

			$this->sendAsJson($response);
		}
	}

	/** Handles subscribers page pagination */
	public function actionFollowersPagination()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$result = array(
			'total' => 0,
			'total_with_sticky' => 0,
			'template' => '',
			'pagenavTemplate' => ''
		);

		$filters = $_REQUEST['filters'];

		if (empty($filters['follower']) OR !intval($filters['follower']))
		{
			$this->sendAsJson($result);
			return;
		}

		$follower = $filters['follower'];
		$sortBy = (isset($filters['filter_sort']) AND !empty($filters['filter_sort'])) ? $filters['filter_sort'] : 'all';
		$page = (isset($filters['pagenum']) AND is_numeric($filters['pagenum'])) ? $filters['pagenum'] : 1;
		$perPage = (isset($filters['perpage']) AND is_numeric($filters['perpage'])) ? $filters['perpage'] : 100;
		$api = Api_InterfaceAbstract::instance();
		$templater = new vB5_Template('subscriptions_two');

		//fetch profile info of the viewing user
		$userInfo = $api->callApi('user', 'fetchProfileInfo', array());

		//for guest users, 'incorrect_data exception' is thrown. but that's fine, as we only need the userInfo if the viewing user is the profile owner
		if (!empty($userInfo) AND !empty($userInfo['errors']))
		{
			$userInfo['userid'] = 0;
		}

		if ($follower == $userInfo['userid']) //viewing user is the profile owner
		{
			$templater->register('showOwner', true);
			$templater->register('userInfo', $userInfo);
			$response = $api->callApi('follow', 'getFollowersForCurrentUser', array('options' => array('page' => $page, 'perpage' => $perPage, 'filter_sort' => $sortBy)));
		}
		else //viewing user is either a guest user or a member but not the profile owner
		{
			$response = $api->callApi('follow', 'getFollowers', array('userid' => $follower, 'options' => array('page' => $page, 'perpage' => $perPage, 'filter_sort' => $sortBy)));
		}

		$paginationInfo = $response['paginationInfo'];

		$templater->register('followers', $response['results']);
		$result['template'] = $templater->render();
		$result['total'] = $result['total_with_sticky'] = $paginationInfo['totalcount'];

		$templater = new vB5_Template('pagenavnew');
		$templater->register('pagenav', $paginationInfo);

		$result['pagenavTemplate'] = $templater->render();
		$result['pageinfo'] = array(
			'pagenumber' => $paginationInfo['currentpage'],
			'totalpages' => $paginationInfo['totalpages']
		);

		$this->sendAsJson($result);
	}

	/** Fetches the nodes info applying the following filter criteria. **/
	public function actionApplyFollowingFilter()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$result = array(
			'lastDate'		  => 0,
			'total'			 => 0,
			'total_with_sticky' => 0,
			'template'		  => '',
			'css_links' => array(),
		);

		$filters = $_REQUEST['filters'];
		$followerId = isset($filters['followerid']) ? intval($filters['followerid']) : intval(vB::getUserContext()->fetchUserId());

		if (!empty($followerId))
		{
			$followFilters = array();
			if (isset($filters['checkSince']) AND is_numeric($filters['checkSince']))
			{
				$followFilters['filter_time'] = $filters['checkSince'] + 1;
			}
			else
			{
				$followFilters['filter_time'] = isset($filters['filter_time']) ? $filters['filter_time'] : 'time_all';
			}
			$followFilters['filter_sort'] = isset($filters['filter_sort']) ? $filters['filter_sort'] : 'sort_recent';
			$typeFilter = isset($filters['filter_show']) ? $filters['filter_show'] : 'show_all';
			$followType = isset($filters['filter_follow']) ? $filters['filter_follow'] : 'follow_all';

			// Now we set the user options
			$options = array(
				'perpage' => isset($filters['per-page']) ? intval($filters['per-page']) : 20
			);

			if (isset($filters['pagenum']) AND !empty($filters['pagenum']))
			{
				$options['page'] = intval($filters['pagenum']);
			}
			if (isset($filters['nodeid']) AND !empty($filters['nodeid']))
			{
				$options['parentid'] = intval($filters['nodeid']);
			}

			$contentTypeClass = ($typeFilter AND strcasecmp($typeFilter, 'show_all') != 0) ? $typeFilter : '';

			$api = Api_InterfaceAbstract::instance();
			$resultNodes = $api->callApi(
				'follow',
				'getFollowingContentForTab',
				array(
					'userid'			=> $followerId,
					'type'				=> $followType,
					'filters'			=> $followFilters,
					'contenttypeclass'	=> $contentTypeClass,
					'options'			=> $options
			));

			$templater = new vB5_Template('profile_following');
			$templater->register('nodes', $resultNodes['nodes']);
			$templater->register('showChannelInfo', $filters['showChannelInfo']);
			$result['template'] = $templater->render(true, true);
			foreach($resultNodes['nodes'] AS $nodeid => $node)
			{
				$result['lastDate'] = max($result['lastDate'], $node['content']['publishdate']);
			}

			$result['total'] = $result['total_with_sticky'] = $resultNodes['totalcount'];
			$result['pageinfo'] = array('pagenumber' => $resultNodes['paginationInfo']['currentpage'], 'showseemore' => $resultNodes['paginationInfo']['showseemore']);
			$result['css_links'] = vB5_Template_Stylesheet::instance()->getAjaxCssLinks();
		}
		$this->sendAsJson($result);
	}

	/**
	 * Fetch Profile About content.
	 */
	public function actionfetchAbout()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = isset($_POST['userid']) ? intval($_POST['userid']) : 0;
		if ($userId < 1)
		{
			return '';
		}

		$api = Api_InterfaceAbstract::instance();
		$userInfo = $api->callApi('user', 'fetchProfileInfo', array($userId));

		$templater = new vB5_Template('profile_about');
		$templater->register('userInfo', $userInfo);
		$this->outputPage($templater->render());
	}

	/**
	 * Fetch Profile Media content.
	 */
	public function actionfetchMedia()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = isset($_POST['userid']) ? intval($_POST['userid']) : 0;
		if ($userId < 1)
		{
			return '';
		}

		$perpage = (isset($_POST['perpage']) AND intval($_POST['perpage']) > 0) ? intval($_POST['perpage']) : 15;
		$allowHistory = (isset($_POST['allowHistory'])) ? intval($_POST['allowHistory']) : 0;
		$includeJS =  (isset($_POST['includeJs'])?  ((bool) $_POST['includeJs']) : false);

		$api = Api_InterfaceAbstract::instance();
		$userInfo = $api->callApi('user', 'fetchProfileInfo', array($userId));

		$templateData = array(
			'userInfo' => $userInfo,
			'page' =>  array('userid' => $userId),
			'perpage' => $perpage,
			'uploadFrom' => 'profile',
			'allowHistory' => $allowHistory
		);
		$results = vB5_Template::staticRenderAjax('profile_media', $templateData);
		$this->sendAsJson($results);
	}

	/**
	 * Save profile settings from user
	 */
	public function actionSaveProfileSettings()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// userid comes in via query string, see usersettings_profile template
		$userId = intval($_REQUEST['userid']);
		if ($userId > 0)
		{
			$api = Api_InterfaceAbstract::instance();

			// usertitle might not be in settings
			if (isset($_POST['usertitle']))
			{
				//send as normal user title (value 2).  It probably won't matter because a
				//value of 1 (admin set) will get translated if the user doesn't have permissions
				//but we should be clean about it.
				$userInfo['customtitle'] = (isset($_POST['resettitle'])) ? 0 : 2;
				$userInfo['usertitle'] = isset($_POST['usertitle']) ? $_POST['usertitle'] : '';
			}

			if(!empty($_POST['bd_year']) AND !empty($_POST['bd_month']) AND !empty($_POST['bd_day']))
			{
				$userInfo['birthday_search'] = implode('-', array($_POST['bd_year'], $_POST['bd_month'], $_POST['bd_day']));

				// default option would be 2
				$userInfo['showbirthday'] = isset($_POST['dob_display']) ? $_POST['dob_display'] : 2;

				/**
				* @TODO Birthday would be in english format for the moment.
				*/
				$userInfo['birthday'] = implode('-', array($_POST['bd_month'], $_POST['bd_day'], $_POST['bd_year']));
			}
			else
			{
				$userInfo['birthday'] = "";
			}

			$userInfo['homepage'] = isset($_POST['homepage']) ? $_POST['homepage'] : '';
			$_POST['user_im_providers'] = isset($_POST['user_im_providers']) ? $_POST['user_im_providers'] : array();
			foreach(array('icq', 'aim', 'yahoo', 'msn', 'skype', 'google') as $value)
			{
				$key = array_search($value, $_POST['user_im_providers']);
				$empty = true;
				// if valid provider is set then...
				if (($key !== false) AND ((isset($_POST['user_screennames'][$key])) AND (!empty($_POST['user_screennames'][$key]))))
				{
					$userInfo[strtolower($value)] = $_POST['user_screennames'][$key];
					$empty = false;
				}

				if ($empty)
				{
					$userInfo[strtolower($value)] = '';
				}
			}

			$userFields = array();
			$response = $api->callApi('user', 'fetchUserProfileFields', array());

			if(!isset($response['errors']))
			{
				foreach ($response AS $uField)
				{
					$userFields[$uField] = isset($_POST[$uField]) ? $_POST[$uField] : '';
				}

				$response = $api->callApi('user', 'save', array(
						'userid' => $userId,
						'password' => '',
						'user' => $userInfo,
						'options' => array(),
						'adminoptions' => array(),
						'userfield' => $userFields,
						'notificationOptions' => array(),
						'hvinput' => array(),
						'extra' => array('acnt_settings' => 1)
					)
				);
			}
			$this->sendAsJson($response);
		}
	}

	/**
	 * Save account settings from user
	 */
	function actionSaveAccountSettings()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// userid comes in via query string, see usersettings_account template
		$userId = intval($_REQUEST['userid']);

		if ($userId > 0)
		{
			$extra = array(
				'email' => '',
				'newpass' => '',
				'password' => '',
				'acnt_settings' => 1
			);

			$api = Api_InterfaceAbstract::instance();

			// drag userinfo from post
			$userInfo = array();
			$userInfo['threadedmode'] = (isset($_POST['display_mode']) ? $_POST['display_mode'] : 0);
			$userInfo['maxposts'] = (isset($_POST['posts_per_page']) AND $_POST['posts_per_page'] != -1) ? $_POST['posts_per_page'] : 0;
			$userInfo['timezoneoffset'] = (isset($_POST['timezone'])) ? $_POST['timezone'] : '';
			$userInfo['startofweek'] = (isset($_POST['startofweek'])) ? $_POST['startofweek'] : -1;
			$userInfo['styleid'] = (isset($_POST['forum_skin'])) ? $_POST['forum_skin'] : 0;
			$userInfo['languageid'] = (isset($_POST['languageid'])) ? $_POST['languageid'] : 0;
			$userInfo['ignorelist'] = (isset($_POST['ignorelist'])) ? $_POST['ignorelist'] : '';
			$userInfo['showvbcode'] = (isset($_POST['showvbcode'])) ? $_POST['showvbcode'] : '';

			// Pass current password if set
			if (isset($_POST['current_pass'])
				AND !empty($_POST['current_pass'])
			)
			{
				$extra['password'] = $_POST['current_pass'];
			}

			// Check new e-mails match, and are not blank
			if (isset($_POST['new_email'])
				AND isset($_POST['new_email2'])
				AND !empty($_POST['new_email'])
				AND ($_POST['new_email'] == $_POST['new_email2'])
			)
			{
				$extra['email'] = $_POST['new_email'];
			}

			// Check new passwords match, and are not blank
			if (isset($_POST['new_pass'])
				AND isset($_POST['new_pass2'])
				AND !empty($_POST['new_pass'])
				AND $_POST['new_pass'] == $_POST['new_pass2']
			)
			{
				$extra['newpass'] = $_POST['new_pass'];
			}

			// and options
			$options = array();
			$options['invisible'] = (isset($_POST['invisible_mode'])) ? true : false;
			$options['showreputation'] = (isset($_POST['show_reputation'])) ? true : false;
			$options['receivepm'] = (isset($_POST['enable_pm'])) ? true : false;
			$options['receivepmbuddies'] = (isset($_POST['receive_pm']) AND $_POST['receive_pm'] == 'buddies') ? true : false;
			$options['vm_enable'] = (isset($_POST['enable_vm'])) ? true : false;
			$options['showusercss'] = (isset($_POST['other_customizations'])) ? true : false;
			$options['showavatars'] = (isset($_POST['showavatars'])) ? true : false;
			$options['showsignatures'] = (isset($_POST['showsignatures'])) ? true : false;
			$options['adminemail'] = (isset($_POST['adminemail'])) ? true : false;


			/*
				Need to distinguish between checkbox not being checked and its being missing from the form entirely
				due to global or UG turn off.
			 */
			$checkPMChatInput = $api->callApi('pmchat', 'canUsePMChat', array(true));
			if ($checkPMChatInput['canuse'])
			{
				// User API will maintain the old setting if it's not set in the function param $options.
				$options['enable_pmchat'] = (isset($_POST['enable_pmchat'])) ? true : false;
			}

			$userData = $api->callApi('user', 'fetchCurrentUserinfo', array($userId));

			if (isset($_POST['dst_correction']))
			{
				if ($_POST['dst_correction'] == 2)
				{
					$options['dstauto'] = true;
					$options['dstonoff'] = $userData['dstonoff'];
				}
				else if($_POST['dst_correction'] == 1)
				{
					$options['dstauto'] = false;
					$options['dstonoff'] = true;
				}
				else
				{
					$options['dstauto'] = false;
					$options['dstonoff'] = false;
				}
			}

			$response = $api->callApi('user', 'save', array(
					'userid' => $userId,
					'password' => '', // Passed via $extra
					'user' => $userInfo,
					'options' => $options,
					'adminoptions' => array(),
					'userfield' => array(),
					'notificationOptions' => array(),
					'hvinput' => array(),
					'extra' => $extra,
				)
			);

			//the return value isn't actually used here, and the save function
			//behaves badly and does not return an array on success.
			//Fixing this so that we can always add the token to the return value
			if (!is_array($response))
			{
				$response = array('userid' => $response);
			}

			//userinfo has probably changed, refetch.  But only reset the value if the current
			//user matches the user being edited.
			$newUserInfo = $api->callApi('user', 'fetchUserinfo', array('nocache' => true), true);
			if ($userId == $newUserInfo['userid'])
			{
				$response['newtoken'] = $newUserInfo['securitytoken'];
			}

			$this->sendAsJson(array('response' => $response));
		}
	}

	/**
	 * Updates the DST if needed
	 */
	public function actionSaveDst()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = intval($_REQUEST['userid']);

		if ($userId > 0)
		{
			$api = Api_InterfaceAbstract::instance();
			$userInfo = $api->callApi('user', 'fetchCurrentUserinfo', array($userId));

			if ($userInfo['userid'])
			{
				$options = array();

				if ($userInfo['dstauto'])
				{
					switch ($userInfo['dstonoff'])
					{
						case 1:
							$options['dstonoff'] = 0;
							break;

						case 0:
							$options['dstonoff'] = 1;
							break;
					}
				}

				$response = $api->callApi('user', 'save', array(
					'userid' => $userId,
					'password' => '', // Passed via $extra
					'user' => array(),
					'options' => $options,
					'adminoptions' => array(),
					'userfield' => array(),
				));

				$this->sendAsJson($response);
				return;
			}
		}

		$this->sendAsJson(array('errors' => array('invalid_userid')));
	}

	public function actionToggleProfileCustomizations()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$options['showusercss'] = !empty($_POST['showusercss']) ? true : false;
		$response = Api_InterfaceAbstract::instance()->callApi('user', 'save', array(
				'userid' => -1,
				'password' => '', // Passed via $extra
				'user' => array(),
				'options' => $options,
				'adminoptions' => array(),
				'userfield' => array(),
			)
		);

		$this->sendAsJson(array('response' => $response));

	}

	public function actionSaveNotificationSettings()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// userid comes in via query string, see usersettings_notifications template
		$userId = intval($_REQUEST['userid']);
		if ($userId > 0)
		{
			//notification settings
			$userInfo = array();
			$notificationOptions = array();

			$userInfo['autosubscribe'] = isset($_POST['autosubscribe']) ? $_POST['autosubscribe'] : 0;
			$userInfo['emailnotification'] = isset($_POST['emailnotification']) ? $_POST['emailnotification'] : 0;
			$settings = array(
				'general_followsyou',
				'general_followrequest',
				'general_vm',
				'general_voteconvs',
				'general_likespost',
				'general_usermention',
				'general_quote',
				'discussions_on',
				'discussion_comment',
			);
			foreach ($settings AS $setting)
			{
				$notificationOptions[$setting] = isset($_POST['notificationSettings'][$setting]) ? true : false;
			}

			$options = array();
			$optionNames = array('emailonpm', 'birthdayemail');
			foreach ($optionNames AS $optionName)
			{
				$options[$optionName] = isset($_POST[$optionName]);
			}

			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('user', 'save', array(
					'userid' => $userId,
					'password' => '',
					'user' => $userInfo,
					'options' => $options,
					'adminoptions' => array(),
					'userfield' => array(),
					'notificationOptions' => $notificationOptions
				)
			);

			$url = vB5_Template_Options::instance()->get('options.frontendurl') . '/settings/notifications';
			if (is_array($response) AND array_key_exists('errors', $response))
			{
				$message = $api->callApi('phrase', 'fetch', array('phrases' => $response['errors'][0][0]));

				vB5_ApplicationAbstract::handleFormError(array_pop($message), $url);

			}
			else
			{
				// and get back to settings
				header('Location: ' . $url);
			}
		}
	}

	public function actionSavePrivacySettings()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// userid comes in via query string, see usersettings_privacy template
		$userId = intval($_REQUEST['userid']);
		if ($userId > 0)
		{
			// privacy settings
			$options = array();
			$uesrInfo = array();
			if (isset($_POST['privacyOptions']))
			{
				$userInfo['privacy_options'] = $_POST['privacyOptions'];
			}

			if (isset($_POST['privacyconsent']))
			{
				// 0 means unknown, -1 is explicitly withdrawn consent, 1 is explicitly provided consent.
				$userInfo['privacyconsent'] = intval($_POST['privacyconsent']);
			}


			$options['moderatefollowers'] = isset($_POST['follower_request']) ? false : true;

			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('user', 'save', array(
					'userid' => $userId,
					'password' => '',
					'user' => $userInfo,
					'options' => $options,
					'adminoptions' => array(),
					'userfield' => array()
				)
			);

			$url = vB5_Template_Options::instance()->get('options.frontendurl') . '/settings/privacy';
			if (is_array($response) AND array_key_exists('errors', $response))
			{
				$message = $api->callApi('phrase', 'fetch', array('phrases' => $response['errors'][0][0]));

				vB5_ApplicationAbstract::handleFormError(array_pop($message), $url);

			}
			else
			{
				// and get back to settings
				header('Location: ' . $url);
			}
		}
	}

	public function actionWithdrawPrivacyConsent()
	{
		// require a POST request for this action
		$this->verifyPostRequest();


		$api = Api_InterfaceAbstract::instance();
		$userInfo = $api->callApi('user', 'fetchUserinfo', array());
		$result = $api->callApi('user', 'save', array(
				'userid' => $userInfo['userid'],
				'password' => '',
				'user' => array('privacyconsent' => -1),
				'options' => array(),
				'adminoptions' => array(),
				'userfield' => array()
			)
		);

		if (empty($result['errors']))
		{
			$userInfo = $api->callApi('user', 'fetchUserinfo', array());
			// Redirect to the logout page for cookie removal etc via http
			$logoutURL = vB5_Template_Options::instance()->get('options.frontendurl') . '/auth/logout?logouthash=' . $userInfo['logouthash'];
			return $this->sendAsJson(
				array(
					'url' => $logoutURL,
				)
			);
		}
		$this->sendAsJson($result);
	}

	public function actionUpdateStatus()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = intval($_REQUEST['userid']);
		if ($userId > 0)
		{
			$status = (isset($_POST['status'])) ? $_POST['status'] : '';
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('user', 'updateStatus', array(
					'userId' => $userId,
					'status' => $status
				)
			);

			$this->sendAsJson($response);
		}
	}

	/**
	 * Filter & sort media list
	 */
	public function actionApplyMediaFilter()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ( empty($_REQUEST['userid']))
		{
			return '';
		}
		$templater = new vB5_Template('profile_media_content');
		$userId = intval($_REQUEST['userid']);
		$api = Api_InterfaceAbstract::instance();

		if (isset($_REQUEST['perpage']) AND intval($_REQUEST['perpage']))
		{
			$perpage = intval($_REQUEST['perpage']);
		}
		else
		{
			$perpage = 15;
		}

		if (isset($_REQUEST['page']) AND intval($_REQUEST['page']))
		{
			$page = intval($_REQUEST['page']);
		}
		else
		{
			$page = 1;
		}

		$gallery = $api->callApi('profile', 'fetchMedia', array('userid' => $_REQUEST['userid'],
			'page' => $page, 'perpage' => $perpage, 'params' => $_REQUEST));
		$templater->register('gallery', $gallery);
		$userInfo = $api->callApi('user', 'fetchUserinfo', array('userid' => $_REQUEST['userid']));
		$templater->register('userInfo', $userInfo);
		$templater->register('perpage', $perpage);
		$this->outputPage($templater->render());
	}

	/**
	 * Show a single text detail page.
	 */
	public function actiontextDetail()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ( empty($_REQUEST['nodeid']))
		{
			return '';
		}
		$templater = new vB5_Template('profile_textphotodetail');
		$userId = intval($_REQUEST['nodeid']);
		$api = Api_InterfaceAbstract::instance();

		$node = $api->callApi('content_text', 'getFullContent', array('nodeid' => $_REQUEST['nodeid']));
		$templater->register('node', $node);
		$this->outputPage($templater->render());
	}

	/**
	 * Saves profile customization
	 */
	public function actionsaveStylevar()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = intval($_POST['userid']);
		$result = array();

		if ($userId < 1)
		{
			$result['error'][] = 'logged_out_while_editing_post';
		}

		if (!isset($_POST['stylevars']) OR (isset($_POST['stylevars']) AND empty($_POST['stylevars'])))
		{
			$result['error'][] = 'there_are_no_changes_to_save';
		}

		if (!isset($result['error']))
		{
			$api = Api_InterfaceAbstract::instance();

			$result = $api->callApi('stylevar', 'save', array('stylevars' => $_POST['stylevars']));
		}

		$this->sendAsJson($result);
	}

	/**
	 * Get default stylevar values
	 */
	public function actionrevertStylevars()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = intval($_POST['userid']);
		$result = array();

		if ($userId < 1)
		{
			$result['error'][] = 'logged_out_while_editing_post';
		}

		if (empty($_POST['stylevars']))
		{
			$result['error'][] = 'there_are_no_changes';
		}

		if (!isset($result['error']))
		{
			$api = Api_InterfaceAbstract::instance();

			if (count($_POST['stylevars']) == 1)
			{
				$result = $api->callApi('stylevar', 'get', array('stylevarname' => $_POST['stylevars'][0]));
			}
			else
			{
				$result = $api->callApi('stylevar', 'fetch', array('stylevars' => $_POST['stylevars']));
			}

			// resolve inheritance
			foreach ($result AS $name => $parts)
			{
				foreach ($parts AS $key => $value)
				{
					if (substr($key, 0, 9) == 'stylevar_')
					{
						$nonInheritKey = substr($key, 9);
						if (!empty($value) AND empty($parts[$nonInheritKey]))
						{
							// if we're here, we need to get the inherited value of this part
							$result[$name][$nonInheritKey] = vB5_Template_Runtime::fetchCustomStylevar($name . '.' . $nonInheritKey);
						}
					}
				}
			}
		}

		$this->sendAsJson($result);
	}

	/**
	 * Save current style as default for the site
	 */
	public function actionsaveDefault()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$userId = intval($_POST['userid']);
		$result = array();

		if ($userId < 1)
		{
			$result['error'][] = 'logged_out_while_editing_post';
		}

		$api = Api_InterfaceAbstract::instance();

		if (!$api->callApi('stylevar', 'canSaveDefault'))
		{
			$result['error'][] = 'no_permission_styles';
		}

		if (!isset($result['error']))
		{
			$stylevars = $api->callApi('stylevar', 'fetch', array('stylevars' => false));

			if (isset($_POST['stylevars']) AND is_array($_POST['stylevars']))
			{
				foreach ($_POST['stylevars'] as $stylevarid => $value)
				{
					$styelvars[$stylevarid] = $value;
				}
			}

			$result = $api->callApi('stylevar', 'save_default', array('stylevars' => $stylevars));
		}

		$this->sendAsJson($result);
	}

	/**
	 * Resetting the user changed stylevars to default values
	 */
	public function actionresetDefault()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$result = array();
		$userId = intval($_POST['userid']);

		if ($userId < 1)
		{
			$result['error'][] = array('logged_out_while_editing_post');
		}

		if (!isset($result['error']))
		{
			$api = Api_InterfaceAbstract::instance();

			// Fetching all user changed stylevars
			$user_stylevars = $api->callApi('stylevar', 'fetch_user_stylevars');
			$changed_stylevars = array_keys($user_stylevars);

			// Deleteing userstylevars
			$api->callApi('stylevar', 'delete', array('stylevars' => $changed_stylevars));

			// To revert unsaved changes
			if (isset($_POST['stylevars']) AND is_array($_POST['stylevars']))
			{
				$changed_stylevars = array_merge($changed_stylevars, $_POST['stylevars']);
				$changed_stylevars = array_unique($changed_stylevars);
			}

			$result = $api->callApi('stylevar', 'fetch', array('stylevars' => $changed_stylevars));
		}

		$this->sendAsJson($result);
	}

	/**
	 * Fetch the tab info for the photo selector
	 */
	public function actiongetPhotoTabs()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$user = vB::getCurrentSession()->fetch_userinfo();
		if (empty($user) OR empty($user['userid']))
		{
			//@TODO: return not logged in status?
			return;
		}

		$result = array();

		$api = Api_InterfaceAbstract::instance();

		$tabsInfo = $api->callApi('profile', 'fetchMedia', array(array('userId' => $user['userid']), 1, 12, array('type' => 'photo')));

		if (empty($tabsInfo['count']))
		{
			$tabsInfo['errors'] = array(array('no_photos_or_albums'));
		}

		$this->sendAsJson($tabsInfo);
	}

	/**
	 * Fetch the photo tab content for the photo selector
	 */
	public function actiongetPhotoTabContent()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$user = vB::getCurrentSession()->fetch_userinfo();
		if (empty($user) OR empty($user['userid']))
		{
			//@TODO: return not logged in status?
			return;
		}


		// nodeid & ppr come in via query string, see content_entry_box.js's insertTabContent() function
		$nodeid = isset($_GET['nodeid']) ? intval($_GET['nodeid']) : 0;
		$nodeid = ($nodeid ? $nodeid : -2);
		$photosPerRow = isset($_GET['ppr']) ? intval($_GET['ppr']) : 2;
		$tabContent = "";

		$api = Api_InterfaceAbstract::instance();
		$nodes = $api->callApi('profile', 'getAlbum', array(
			array(
				'nodeid' => $nodeid,
				'page' => 1,
				'perpage' => 60,
				'userid' => $user['userid']
			)
		));

		foreach ($nodes as $nodeid => $node)
		{
			$items = array();
			$photoFiledataids = array();
			$attachParentNodeids = array();
			$photoCount = 0;

			foreach ($node['photo'] as $photoid => $photo)
			{
				// if it's an attachment, we use the 'id=' param. If it's a photo, 'photoid='
				$paramname = (isset($photo['isAttach']) AND $photo['isAttach']) ? 'id' : 'photoid';
				$items[$photoid] = array(
					'title' => $photo['title'],
					'imgUrl' => 'filedata/fetch?' . $paramname . '=' . $photoid . '&type=thumb',
				);

				if (!isset($photo['filedataid']) OR !$photo['filedataid'])
				{
					// If it's an attachment, we need more data and check if it's an image.
					// We need to keep track of the parent nodeids as that's required by getNodeAttachmentsPublicInfo()
					if($photo['isAttach'])
					{
						$attachParentNodeids[$photo['parentnode']] = $photo['parentnode'];
					}
					else
					{
						$photoFiledataids[] = $photoid;
					}
				}
				else
				{
					$items[$photoid]['filedataid'] = $photo['filedataid'];
				}

				if ($photosPerRow AND ++$photoCount % $photosPerRow == 0)
				{
					$items[$photoid]['lastinrow'] = true;
				}
			}

			if (!empty($photoFiledataids))
			{
				$photoFileids = $api->callApi('filedata', 'fetchPhotoFiledataid', array($photoFiledataids));

				foreach ($photoFileids as $nodeid => $filedataid)
				{
					$items[$nodeid]['filedataid'] = $filedataid;
				}
			}

			if (!empty($attachParentNodeids))
			{
				$attachFullData = $api->callApi('node', 'getNodeAttachmentsPublicInfo', array($attachParentNodeids));
				foreach ($attachFullData AS $parentid => $attaches)
				{
					foreach ($attaches AS $attachid => $attachData)
					{
						/*
							Certain attachments can actually be non-image (ex. zip, txt), and it doesn't make
							sense to allow those attachments to be added as part of a "gallery", so we skip
							them here. Although only thumbnails are shown by the template rendered in this function,
							we intentionally skip the $type param for isImage(), and allow it to default to a FULLSIZE
							check as we want to know whether the actual file is an image, not just its thumbnail (eg pdf).
						 */

						$isImage = $api->callApi('content_attach', 'isImage', array($attachData['extension']));
						if($isImage AND isset($items[$attachid]))
						{
							$items[$attachid]['filedataid'] = $attachData['filedataid'];
						}
						else
						{
							unset($items[$attachid]);
						}
					}
				}
			}

			$templater = new vB5_Template('photo_item');
			$templater->register('items', $items);
			$templater->register('photoSelector', 1);
			$tabContent = $templater->render();
		}

		$this->outputPage($tabContent);
	}

	//not currently used but keeping in case we add signature previews back.
	public function actionPreviewSignature()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$parser = new vB5_Template_BbCode();
		$userInfo = Api_InterfaceAbstract::instance()->callApi('user', 'fetchUserinfo', array());
		$sigInfo =  Api_InterfaceAbstract::instance()->callApi('user', 'fetchSignature', array($userInfo['userid']));
		$signature = empty($_REQUEST['signature']) ? $sigInfo['raw'] : $_REQUEST['signature'];
		$signature = $parser->doParse($signature, $sigInfo['permissions']['dohtml'], $sigInfo['permissions']['dosmilies'],
				$sigInfo['permissions']['dobbcode'], $sigInfo['permissions']['dobbimagecode']);
		$this->sendAsJson($signature);
	}

	/**
	 *
	 */
	public function actionExportPersonalData()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		// The api call supports admins downloading other users' data. We
		// could accept and pass a userid param to allow that to happen
		// via this controller if & when we implement a UI for that.

		$api = Api_InterfaceAbstract::instance();
		$personalData = $api->callApi('user', 'getPersonalData');

		// get phrases
		$phraseKeys = array();
		$phraseKeys[] = 'dump_personaldata';
		$nestedArraysWithPhrases = array(
			'customFields',
			'externallogin',
		);
		// use phrases for custom fields & external login data so they are not "field4_title"
		// don't use phrases for any of the other items, since we don't
		// necessarily have phrases for all of the keys.
		foreach ($nestedArraysWithPhrases AS $key)
		{
			foreach ($personalData[$key] AS $unused1 => $fields)
			{
				foreach ($fields AS $fieldName => $unused2)
				{
					$phraseKeys[] = $fieldName;
				}
			}
		}
		$phrases = $api->callApi('phrase', 'fetch', array('phrases' => $phraseKeys));

		// generate CSV data
		$csv = array();
		foreach ($personalData AS $key => $value)
		{
			// special case device tokens
			if ($key == 'devicetokens')
			{
				if (empty($value))
				{
					$value[] = '';
				}
				array_unshift($value, $key);
				// output as key then any number of tokens
				$csv[] = $value;
			}
			// special case custom user profile fields
			else if ($key == 'customFields')
			{
				// ignore categories and output each field & value
				// as its own row
				foreach ($value AS $categoryName => $fields)
				{
					foreach ($fields AS $fieldName => $fieldValueInfo)
					{
						// use phrases for custom fields so they are not "field4_title"
						$name = !empty($phrases[$fieldName]) ? $phrases[$fieldName] : $fieldName;
						$csv[] = array($name, $fieldValueInfo['val']);
					}
				}
			}
			else if ($key == 'externallogin')
			{
				// ignore categories and output each field & value
				// as its own row
				foreach ($value AS $libid => $fields)
				{
					foreach ($fields AS $fieldName => $fieldValue)
					{
						// use phrases for custom fields so they are not "field4_title"
						$name = !empty($phrases[$fieldName]) ? $phrases[$fieldName] : $fieldName;
						$csv[] = array($name, $fieldValue);
					}
				}
			}
			// regular scalar values
			else
			{
				$csv[] = array($key, $value);
			}
		}

		// escape CSV data
		foreach ($csv as $i => $row)
		{
			foreach ($row AS $j => $value)
			{
				$csv[$i][$j] = $this->escapeCsvValue($csv[$i][$j]);
			}
			$csv[$i] = implode(',', $csv[$i]);
		}
		$csv = implode("\n", $csv);

		$user = vB::getCurrentSession()->fetch_userinfo();
		$timenow = vB5_Request::get('timeNow');
		$dateformat = vB5_Template_Options::instance()->get('options.dateformat');
		$date = vB5_Template_Runtime::date($timenow, $dateformat, false);
		$filename = $phrases['dump_personaldata'] . '-' . $user['username'] . "-" . $date . '.csv';
		$filename = str_replace(array('\\', '/'), '-', $filename);

		// send the file for download
		require_once(DIR . '/includes/functions_file.php');
		file_download($csv, $filename, 'text/x-csv');
	}

	/**
	 * Escapes a value for insertion in a CSV file.
	 *
	 * @param  mixed A Scalar value to escape
	 * @return mixed The escaped value.
	 */
	protected function escapeCsvValue($value)
	{
		// Unfortunately, there is no single spec for CSV files,
		// so we'll do some escaping/quoting that should work for
		// a majority of casual users.
		// RFC: https://tools.ietf.org/html/rfc4180

		$value = (string) $value;

		if (strcspn($value, ",\"\r\n") !== strlen($value))
		{
			// contains a character that requires value to be quoted
			$value = '"' . str_replace('"', '""', $value) . '"';
		}

		return $value;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104018 $
|| #######################################################################
\*=========================================================================*/
