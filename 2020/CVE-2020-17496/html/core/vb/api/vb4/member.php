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
 * vB_Api_Vb4_member
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_member extends vB_Api
{
	public function call(
		$username = null,
		$userid = 0,
		$tab = 'friends',
		$perpage = 10,
		$pagenumber = 1,
		$vmid = null
	)
	{
		$cleaner = vB::getCleaner();

		if ($username)
		{
			$username = $cleaner->clean($username, vB_Cleaner::TYPE_STR);
			$userinfo = vB_Api::instance('user')->fetchByUsername($username);
			$userid = $userinfo['userid'];
		}
		else if($userid)
		{
			$userid = $cleaner->clean($userid, vB_Cleaner::TYPE_UINT);
			$userinfo = vB_Api::instance('user')->fetchUserinfo($userid);
		}
		else
		{
			$userinfo = vB_Api::instance('user')->fetchUserinfo();
			$userid = $userinfo['userid'];
		}

		$tab = $cleaner->clean($tab, vB_Cleaner::TYPE_STR);
		$perpage = $cleaner->clean($perpage, vB_Cleaner::TYPE_UINT);
		if ($perpage < 1)
		{
			$perpage = 10;
		}
		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);

		if ($userid == 0)
		{
			return array('response' => array('errormessage' => 'unregistereduser'));
		}

		$profile = vB_Api::instance('user')->fetchProfileInfo($userid);
		if (empty($profile) OR isset($profile['errors']))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$current_userinfo = vB_Api::instanceInternal('user')->fetchUserinfo();
		$following = vB_Api::instance('follow')->isFollowingUser($userid);
		$values = array();

		if (!empty($profile['birthday']))
		{
			if ($userinfo['showbirthday'] == 1) {
				$values[] = array(
					'profilefield' => array(
						'title' => (string)(new vB_Phrase('global', 'age')),
						'value' => "$profile[age]",
					),
				);
			}

			if ($userinfo['showbirthday'] == 2)
			{
				if (!empty($profile['age']))
				{
					$values[] = array(
						'profilefield' => array(
							'title' => (string)(new vB_Phrase('user', 'birthday_guser')),
							'value' => $profile['birthday'] . ' (' . $profile['age'] .')',
						),
					);
				}
			}

			if ($userinfo['showbirthday'] == 3)
			{
				$birthday = explode('-', $profile['birthday']);
				unset($birthday[2]);
				$birthday = implode('-', $birthday);
				$values[] = array(
					'profilefield' => array(
						'title' => (string)(new vB_Phrase('user', 'birthday_guser')),
						'value' => $birthday,
					),
				);
			}
		}

		foreach($profile['customFields']['default'] as $name => $value) {
			$value = $value['val'];
			if ($value === null) {
				$value = '';
			}
			$values[] = array(
				'profilefield' => array(
					'title' => (string) new vB_Phrase('cprofilefield', $name),
					'value' => $value,
				),
			);
		}

		$groups = array();
		$groups[] = array(
			'category' => array(
				'title' => (string)(new vB_Phrase('global', 'basicinfo')),
				'fields' => $values,
			),
		);

		$values = array();
		if ($userinfo['homepage'])
		{
			$values[] = array(
				'profilefield' => array(
					'title' => (string)(new vB_Phrase('global', 'web')),
					'value' => $userinfo['homepage'],
				),
			);
		}


		// Keep this in sync with im_providers in vB_Api_User::fetchUserSettings()
		// and usersettings_profile template.
		$imProviders = array(
			'aim' => 'aim',
			'google' => 'google_talk_im',
			'skype' => 'skype',
			'yahoo' => 'yahoo',
			'icq' => 'icq',
			// This apparently isn't supported in vB5 anymore? Let's return it if we have it.
			// The 'msn' phrase still exists but not in the "Messaging" group... using the available one
			// rather than adding a specific one.
			'msn' => 'msn',
		);
		$imPhrases = vB_Api::instance('phrase')->fetch(array_values($imProviders));
		foreach ($imProviders AS $provider => $phraseKey)
		{
			if (!empty($userinfo[$provider]))
			{
				$values[] = array(
					'profilefield' => array(
						'title' => $imPhrases[$phraseKey] ?? $phraseKey,
						'value' => $userinfo[$provider],
					),
				);
			}
		}
		if (!empty($values))
		{
			// By the way this is NOT to vB4 spec per documentation, but this
			// was how it was returned previously, and mobile team has apparently
			// gotten used to it so we're keeping the return structure as before.
			$groups[] = array(
				'category' => array(
					'title' => (string)(new vB_Phrase('global', 'contact')),
					'fields' => $values,
				),
			);
		}


		$values = array();

		$values[] = array(
			'profilefield' => array(
				'title' => (string)(new vB_Phrase('global', 'total_posts')),
				'value' => $userinfo['posts'],
			),
		);

		$values[] = array(
			'profilefield' => array(
				'title' => (string)(new vB_Phrase('global', 'posts_per_day')),
				'value' => $profile['postPerDay'],
			),
		);

		$values[] = array(
			'profilefield' => array(
				'title' => (string)(new vB_Phrase('global', 'visitor_messages')),
				'value' => $profile['vmCount'],
			),
		);

		$values[] = array(
			'profilefield' => array(
				'title' => (string)(new vB_Phrase('global', 'referrals')),
				'value' => $profile['referralsCount'],
			),
		);

		$groups[] = array(
			'category' => array(
				'title' => (string)(new vB_Phrase('global', 'statistics')),
				'fields' => $values,
			),
		);

		foreach ($groups as &$group)
		{
			foreach ($group['category']['fields'] as &$field)
			{
				if ($field['profilefield']['value'] === null)
				{
					$field['profilefield']['value'] = "";
				}
				$field['profilefield']['value'] = (string)$field['profilefield']['value'];
			}
		}

		$canbefriend = (($following == 0) && ($current_userinfo['userid'] != $userid)) ? 1 : 0;
		$options = vB::getDatastore()->getValue('options');

		$avatarurl = vB_Library::instance('vb4_functions')->avatarUrl($userid);
		$out = array(
			'response' => array(
				'prepared' => array(
					'userid' => $userid,
					'username' => $userinfo['username'],
					'usertitle' => $userinfo['usertitle'],
					'profilepicurl' => $avatarurl,
					'avatarurl' => $avatarurl,
					'canbefriend' => $canbefriend,
					'usecoppa' => $options['usecoppa'],
				),
				'blocks' => array(
					'aboutme' => array(
						'block_data' => array(
							'fields' => $groups,
						),
					),
				),
			),
			'show' => array(
				'vm_block' => $userinfo['vm_enable'],
				'post_visitor_message' => $userinfo['vm_enable'],
				'addbuddylist' => $canbefriend,
			),
		);

		if ($tab == 'friends')
		{
			$followers = vB_Api::instance('follow')->getFollowers($userid, array('page' => $pagenumber, 'perpage' => $perpage));
			$friends = array();

			foreach($followers['results'] as $friend) {
				$avatarurl = vB_Library::instance('vb4_functions')->avatarUrl($friend['userid']);
				$friendinfo = vB_Api::instance('user')->fetchUserinfo($friend['userid']);
				$friends[] = array(
					'user' => array(
						'userid' => $friend['userid'],
						'username' => $friend['username'],
						'usertitle' => $friendinfo['usertitle'],
						'avatarurl' => $avatarurl,
					),
				);
			}

			$pagenav = vB_Library::instance('vb4_functions')->pageNav($pagenumber, $perpage, $followers['paginationInfo']['totalcount']);
			$out['response']['blocks']['friends']['block_data']['friendbits'] = $friends;
			$out['response']['blocks']['friends']['block_data']['pagenav'] = $pagenav;
		}
		else if ($tab == 'visitor_messaging')
		{
			if (!empty($vmid))
			{
				$vmPagenumber = $this->fetchVMPage($vmid, $userid, $perpage);
				if (!empty($vmPagenumber))
				{
					$pagenumber = $vmPagenumber;
				}
			}


			/*
				https://admin.vbulletin.com/wiki/VB5_-_Search_JSON#sentto
				sentto
					This filter is used in conjunction with the visitor message content
					type filter and specifies the user the message was sent to.

				https://admin.vbulletin.com/wiki/VB5_-_Search_JSON#visitor_messages_only
				visitor_messages_only
					used in conjunction with the authorid filter and will include only the
					visitor messages that the author sent OR received
					There's no need to specify the "visitor_messages_only" filter when using
					the "sentto" filter as it is enforced anyway.
			 */
			$search = array('sentto' => $userid);
			$search['view'] = vB_Api_Search::FILTER_VIEW_ACTIVITY;
			$search['date'] = vB_Api_Search::FILTER_CHANNELAGE;
			$vm_search = vB_Api::instance('search')->getInitialResults($search, $perpage, $pagenumber, true);

			$vms = array();
			$page_nav = vB_Library::instance('vb4_functions')->pageNav(1, 1, 0);
			if (!empty($vm_search) || !isset($vm_search['errors']))
			{
				foreach ($vm_search['results'] AS $key => $node)
				{
					$avatarurl = vB_Library::instance('vb4_functions')->avatarUrl($node['userid']);
					$vms[] = array(
						'message' => array(
							'vmid' => $node['nodeid'],
							'userid' => $node['userid'],
							'username' => $node['authorname'],
							'message' => $node['content']['rawtext'],
							'time' => $node['publishdate'],
							'avatarurl' => $avatarurl,
						),
					);
				}

				$page_nav = vB_Library::instance('vb4_functions')->pageNav($pagenumber, $perpage, $vm_search['totalRecords']);

			}
			$out['response']['blocks']['visitor_messaging']['block_data']['messagebits'] = $vms;
			$out['response']['blocks']['visitor_messaging']['block_data']['pagenav'] = $page_nav;
		}

		return $out;
	}

	private function fetchVMPage($vmid, $userid, $perpage)
	{
		/*
			Loosly based on vB4's  vB_ProfileBlock_VisitorMessaging::prepare_output()

		$getpagenum = $this->registry->db->query_first("
			SELECT COUNT(*) AS comments
			FROM " . TABLE_PREFIX . "visitormessage AS visitormessage
			WHERE userid = " . $this->profile->userinfo['userid'] . "
				AND (" . implode(" OR ", $state_or) . ")
				AND dateline >= $messageinfo[dateline]
		");
		$options['pagenumber'] = ceil($getpagenum['comments'] / $perpage);

			& on the select query when we do a sentto search:

		SELECT DISTINCT node.lastcontentid AS nodeid
		FROM {TABLE_PREFIX}node as node
		WHERE node.nodeid = node.starter
			AND node.contenttypeid <> {channel_contenttypeid}
			AND node.showpublished > 0 AND
			node.setfor = 1 AND
			node.inlist = 1 AND
			node.publishdate >= {cutoff}
		ORDER BY node.created DESC,node.nodeid ASC
		LIMIT 500

		We'll want to fetch the VM, and if it's showpublished > 0, then do a count query
		for all starters with setfor == userid, inlist = 1, showpublished > 0 & publishdate >=
		specified VM's publishdate.
		 */
		$isVM = vB_Api::instanceInternal("content_text")->isVisitorMessage($vmid);
		$node = vB_Library::instance("node")->getNodeBare($vmid);
		if (!$isVM OR empty($node['setfor']) OR $node['setfor'] != $userid)
		{
			return 0;
		}

		$count = vB::getDbAssertor()->getRow("vBForum:getVMCountAfterVMID",
			array(
				'userid' => $node['setfor'],
				'publishdate' => $node['publishdate'],
			)
		);
		$count = $count['vm_count'];
		$vmPagenumber = ceil($count / $perpage);

		return $vmPagenumber;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102961 $
|| #######################################################################
\*=========================================================================*/
