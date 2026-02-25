<?php
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ©2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| #        www.vbulletin.com | www.vbulletin.com/license.html        # ||
|| #################################################################### ||
\*======================================================================*/

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 103832 $');
define('NOZIP', 1);

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;

$phrasegroups = array('thread', 'threadmanage', 'prefix');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/functions_databuild.php');
require_once(DIR . '/includes/adminfunctions_prefix.php');

@set_time_limit(0);

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminthreads'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'channelid' => vB_Cleaner::TYPE_INT,
	'pollid'  => vB_Cleaner::TYPE_INT,
));

// ############################# LOG ACTION ###############################

$log = '';
if(!empty($vbulletin->GPC['channelid']))
{
	$log = "channel id = " . $vbulletin->GPC['channelid'];
}
else if (!empty($vbulletin->GPC['pollid']))
{
	$log = "poll id = " . $vbulletin->GPC['pollid'];
}
log_admin_action($log);

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

//not all of the original thread tools ported.  The remaining functionality
//can be found in the vb4 thread.php admincp file.

// ###################### Start Prune by user #######################
if ($_REQUEST['do'] == 'pruneuser')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'username'  => vB_Cleaner::TYPE_NOHTML,
		'channelid'   => vB_Cleaner::TYPE_INT,
		'subforums' => vB_Cleaner::TYPE_BOOL,
		'userid'    => vB_Cleaner::TYPE_UINT,
		'topicsposts'  => vB_Cleaner::TYPE_NOHTML,
	));

	// we only ever submit this via post
	$vbulletin->input->clean_array_gpc('p', array(
		'confirm'   => vB_Cleaner::TYPE_BOOL,
	));

	print_cp_header($vbphrase['topic_manager_admincp']);
	$assertor = vB::getDbAssertor();
	$nodeApi = vB_Api::instance('node');

	if (empty($vbulletin->GPC['username']) AND !$vbulletin->GPC['userid'])
	{
		print_stop_message2('invalid_user_specified');
	}
	else if (!$vbulletin->GPC['channelid'])
	{
		print_stop_message('invalid_channel_specified');
	}

	if ($vbulletin->GPC['channelid'] == -1)
	{
		$forumtitle = $vbphrase['all_forums'];
	}
	else
	{
		$channel = $nodeApi->getNode($vbulletin->GPC['channelid']);
		$forumtitle = $channel['title'] . ($vbulletin->GPC['subforums'] ? ' (' . $vbphrase['include_child_channels'] . ')' : '');
	}

	$conditions = array();
	if ($vbulletin->GPC['username'])
	{
		$conditions[] = array('field' => 'username', 'value' => $vbulletin->GPC['username'], 'operator' => vB_dB_Query::OPERATOR_INCLUDES);
	}
	else
	{
		$conditions['userid'] = $vbulletin->GPC['userid'];
	}

	$result = $assertor->select('user', $conditions, 'username', array('userid', 'username'));

	if (!$result->valid())
	{
		print_stop_message2('invalid_user_specified');
	}
	else
	{
		echo '<p>' . construct_phrase($vbphrase['about_to_delete_posts_in_forum_x_by_users'], $forumtitle) . '</p>';

		$filter = array(
			'channelid' => $vbulletin->GPC['channelid'],
			'subforums' =>  $vbulletin->GPC['subforums'],
		);

		foreach ($result AS $user)
		{
			$filter['userid'] = $user['userid'];

			$params = fetch_thread_move_prune_sql($assertor, $filter);
			$params['special']['topicsposts'] = $vbulletin->GPC['topicsposts'];
			$hiddenParams = sign_client_string(serialize($params));

			print_form_header('admincp/nodetools', 'donodesall');
			print_table_header(construct_phrase($vbphrase['prune_all_x_posts_automatically'], $user['username']), 2, 0);
			construct_hidden_code('type', 'prune');
			construct_hidden_code('criteria', $hiddenParams);
			print_submit_row(construct_phrase($vbphrase['prune_all_x_posts_automatically'], $user['username']), '', 2);

			print_form_header('admincp/nodetools', 'donodessel');
			print_table_header(construct_phrase($vbphrase['prune_x_posts_selectively'], $user['username']), 2, 0);
			construct_hidden_code('type', 'prune');
			construct_hidden_code('criteria', $hiddenParams);
			print_submit_row(construct_phrase($vbphrase['prune_x_posts_selectively'], $user['username']), '', 2);
		}
	}
}

// ###################### Start Prune #######################
if ($_REQUEST['do'] == 'prune')
{
	print_cp_header($vbphrase['topic_manager_admincp']);

	print_form_header('admincp/nodetools', 'donodes');
	print_table_header($vbphrase['prune_topics_manager']);
	print_description_row($vbphrase['pruning_many_threads_is_a_server_intensive_process']);

	construct_hidden_code('type', 'prune');
	print_node_filter_rows();
	print_submit_row($vbphrase['prune_topics']);

	print_form_header('admincp/nodetools', 'pruneuser');
	print_table_header($vbphrase['prune_by_username']);
	print_input_row($vbphrase['username'], 'username');
	print_move_prune_channel_chooser($vbphrase['channel'], 'channelid', $vbphrase['all_channels']);

	$buttons = array(
		'topics' => $vbphrase['topics'],
		'posts' => $vbphrase['posts'],
		'either' => $vbphrase['either'],
	);
	print_radio_row($vbphrase['select'], 'topicsposts', $buttons, 'either', 'normal', false, true);

	print_yes_no_row($vbphrase['include_child_channels'], 'subforums');
	print_submit_row($vbphrase['prune']);
}

// ###################### Start Move #######################
if ($_REQUEST['do'] == 'move')
{
	print_cp_header($vbphrase['topic_manager_admincp']);

	print_form_header('admincp/nodetools', 'donodes');
	print_table_header($vbphrase['move_topics']);

	construct_hidden_code('type', 'move');
	print_move_prune_channel_chooser($vbphrase['destination_channel'], 'destchannelid', '');
	print_node_filter_rows();
	print_submit_row($vbphrase['move_topics']);
}


// ###################### Start Close #######################
if ($_REQUEST['do'] == 'close')
{
	print_cp_header($vbphrase['topic_manager_admincp']);

	print_form_header('admincp/nodetools', 'donodes');
	print_table_header($vbphrase['close_topics']);

	construct_hidden_code('type', 'close');
	print_node_filter_rows(array('isopen' => 1));
	print_submit_row($vbphrase['close_topics']);
}


/************ GENERAL MOVE/PRUNE HANDLING CODE ******************/

/**
 *	@param $force -- in theory this will allow the caller to preset a filter row to a value and
 *		skip displaying the row.  This is intended for avoiding providing a nonsensical option
 *		for a specific filter (such as allowing searching for closed topics for the close action)
 *		In practice we've only implmented options for the filters the callers currently need.
 *		This is an internal function and it's kind of a pain to implement;
 */
function print_node_filter_rows($force = array())
{
	global $vbphrase;
	$nolimitdfn_0 = '<dfn>' . construct_phrase($vbphrase['note_leave_x_specify_no_limit'], '0') . '</dfn>';
	$nolimitdfn_neg1 = '<dfn>' . construct_phrase($vbphrase['note_leave_x_specify_no_limit'], '-1') . '</dfn>';

	print_description_row($vbphrase['date_options'], 0, 2, 'thead', 'center');
	print_input_row($vbphrase['original_post_date_is_at_least_xx_days_ago'], 'topic[originaldaysolder]', 0, 1, 5);
	print_input_row($vbphrase['original_post_date_is_at_most_xx_days_ago'] . $nolimitdfn_0, 'topic[originaldaysnewer]', 0, 1, 5);
	print_input_row($vbphrase['last_post_date_is_at_least_xx_days_ago'], 'topic[lastdaysolder]', 0, 1, 5);
	print_input_row($vbphrase['last_post_date_is_at_most_xx_days_ago'] . $nolimitdfn_0, 'topic[lastdaysnewer]', 0, 1, 5);

	print_description_row($vbphrase['view_options'], 0, 2, 'thead', 'center');
	print_input_row($vbphrase['topic_has_at_least_xx_replies'], 'topic[repliesleast]', 0, 1, 5);
	print_input_row($vbphrase['topic_has_at_most_xx_replies'] . $nolimitdfn_neg1, 'topic[repliesmost]', -1, 1, 5);
	print_input_row($vbphrase['topic_has_at_least_xx_views'], 'topic[viewsleast]', 0, 1, 5);
	print_input_row($vbphrase['topic_has_at_most_xx_views'] . $nolimitdfn_neg1, 'topic[viewsmost]', -1, 1, 5);

	print_description_row($vbphrase['status_options'], 0, 2, 'thead', 'center');
	print_yes_no_other_row($vbphrase['topic_is_sticky'], 'topic[issticky]', $vbphrase['either'], 0);

	print_yes_no_other_row($vbphrase['topic_is_unpublished'], 'topic[unpublished]', $vbphrase['either'], -1);
	print_yes_no_other_row($vbphrase['topic_is_awaiting_moderation'], 'topic[moderated]', $vbphrase['either'], -1);

	if(!isset($force['isopen']))
	{
		print_yes_no_other_row($vbphrase['topic_is_open'], 'topic[isopen]', $vbphrase['either'], -1);
	}

	print_yes_no_other_row($vbphrase['topic_is_redirect'], 'topic[isredirect]', $vbphrase['either'], 0);

	print_description_row($vbphrase['other_options'], 0, 2, 'thead', 'center');
	print_input_row($vbphrase['username'], 'topic[posteduser]');
	print_input_row($vbphrase['userid'] . '<dfn>' . $vbphrase['not_used_if_username'] . '</dfn>' , 'topic[userid]', '', 1, 5);
	print_input_row($vbphrase['title'], 'topic[titlecontains]');
	print_move_prune_channel_chooser($vbphrase['channel'], 'topic[channelid]', $vbphrase['all_channels']);
	print_yes_no_row($vbphrase['include_child_channels'], 'topic[subforums]');

	if ($prefix_options = construct_prefix_options(0, '', true, true))
	{
		print_label_row($vbphrase['prefix'], '<select name="topic[prefixid]" class="bginput">' . $prefix_options . '</select>', '', 'top', 'prefixid');
	}

	foreach($force AS $key => $value)
	{
		construct_hidden_code('topic[' . $key . ']', $value);
	}
}


//stripped down channel chooser that only has the options we need for move/prune and skips the special channels.
//print_channel_chooser already has to many impenetrable parameters to add another (though perhaps a version
//that allows passing the results of construct_channel_chooser_options might be generally useful)
function print_move_prune_channel_chooser($title, $name, $topname)
{
	$topchannels = vB_Api::instanceInternal('content_channel')->fetchTopLevelChannelIds();
	$channels = vB_Api::instanceInternal('search')->getChannels(false, array('exclude_subtrees' => $topchannels['special']));
	$channels = reset($channels);
	$channels = $channels['channels'];

	$options = construct_channel_chooser_options($channels, false, $topname, null);
	print_select_row($title, $name, $options, -1, 0, 0, false);
}

// ###################### Start genmoveprunequery #######################
function fetch_thread_move_prune_sql($db, $topic)
{
	$conditions = array();
	$channelinfo = array();
	$special = array();

	$timenow = vB::getRequest()->getTimeNow();

	//probably not needed because we'll have a starter check by default.  But we don't want
	//channels here regardless.
	$type = vB_Types::instance()->getContentTypeId('vBForum_Channel');
	$conditions[] = array('field' => 'node.contenttypeid', 'value' => $type, 'operator' => vB_dB_Query::OPERATOR_NE);

	// original post
	if (isset($topic['originaldaysolder']) AND intval($topic['originaldaysolder']))
	{
		$timecut = $timenow - ($topic['originaldaysolder'] * 86400);
		$conditions[] = array('field' => 'node.created', 'value' => $timecut, 'operator' => vB_dB_Query::OPERATOR_LTE);
	}

	if (isset($topic['originaldaysnewer']) AND intval($topic['originaldaysnewer']))
	{
		$timecut = $timenow - ($topic['originaldaysnewer'] * 86400);
		$conditions[] = array('field' => 'node.created', 'value' => $timecut, 'operator' => vB_dB_Query::OPERATOR_GTE);
	}

	// last post
	if (isset($topic['lastdaysolder']) AND intval($topic['lastdaysolder']))
	{
		$timecut = $timenow - ($topic['lastdaysolder'] * 86400);
		$conditions[] = array('field' => 'node.lastupdate', 'value' => $timecut, 'operator' => vB_dB_Query::OPERATOR_LTE);
	}

	if (isset($topic['lastdaysnewer']) AND intval($topic['lastdaysnewer']))
	{
		$timecut = $timenow - ($topic['lastdaysnewer'] * 86400);
		$conditions[] = array('field' => 'node.lastupdate', 'value' => $timecut, 'operator' => vB_dB_Query::OPERATOR_GTE);
	}

	// replies
	if (isset($topic['repliesleast']) AND intval($topic['repliesleast']) > 0)
	{
		$conditions[] = array('field' => 'node.textcount', 'value' => intval($topic['repliesleast']), 'operator' => vB_dB_Query::OPERATOR_GTE);
	}

	if (isset($topic['repliesmost']) AND intval($topic['repliesmost']) > -1)
	{
		$conditions[] = array('field' => 'node.textcount', 'value' => intval($topic['repliesmost']), 'operator' => vB_dB_Query::OPERATOR_LTE);
	}

	// views
	if (isset($topic['viewsleast']) AND intval($topic['viewsleast']) > 0)
	{
		$conditions[] = array('field' => 'nodeview.count', 'value' => intval($topic['viewsleast']), 'operator' => vB_dB_Query::OPERATOR_GTE);
	}

	if (isset($topic['viewsmost']) AND intval($topic['viewsmost']) > -1)
	{
		$conditions[] = array('field' => 'nodeview.count', 'value' => intval($topic['viewsmost']), 'operator' => vB_dB_Query::OPERATOR_LTE);
	}

	// sticky
	if (isset($topic['issticky']) AND $topic['issticky'] != -1)
	{
		$conditions['node.sticky'] = $topic['issticky'];
	}

	if (isset($topic['unpublished']) AND $topic['unpublished'] != -1)
	{
		if ($topic['unpublished'])
		{
			//this can't be handled with standard conditions
			$special['unpublished'] = 'yes';
			$special['timenow'] = $timenow;
		}
		else
		{
			$special['unpublished'] = 'no';
			$special['timenow'] = $timenow;
		}
	}

	if (isset($topic['moderated']) AND $topic['moderated'] != -1)
	{
		$conditions['node.approved'] = !$topic['moderated'];
	}

	//status
	if (isset($topic['isopen']) AND $topic['isopen'] != -1)
	{
		$conditions['node.open'] = $topic['isopen'];
	}

	if (isset($topic['isredirect']) AND $topic['isredirect'] != -1)
	{
		$op = (($topic['isredirect'] == 1) ? vB_dB_Query::OPERATOR_EQ : vB_dB_Query::OPERATOR_NE);
		$type = vB_Types::instance()->getContentTypeId('vBForum_Redirect');

		$conditions[] = array('field' => 'node.contenttypeid', 'value' => $type, 'operator' => $op);
	}

	// posted by
	if (!empty($topic['posteduser']))
	{
		$user = $db->getRow('user', array('username' => vB_String::htmlSpecialCharsUni($topic['posteduser'])));
		if (!$user)
		{
			print_stop_message('invalid_username_specified');
		}

		$conditions['node.userid'] = $user['userid'];
	}

	//specifically allow 0 as "guest user"
	else if (isset($topic['userid']) AND ($topic['userid'] != ''))
	{
		$conditions['node.userid'] = $topic['userid'];
	}

	// title contains
	if (!empty($topic['titlecontains']))
	{
		//we are still encoding the title in the DB so we need to do the same to the
		//string in order to get it to match.  This will likely prove fragile but not doing doesn't work.
		$contains = vB_String::htmlSpecialCharsUni($topic['titlecontains']);
		$conditions[] = array('field' => 'node.title', 'value' => $contains, 'operator' => vB_dB_Query::OPERATOR_INCLUDES);
	}

	// forum
	$topic['channelid'] = intval($topic['channelid']);

	if ($topic['channelid'] != -1)
	{
		$channelinfo['channelid'] = $topic['channelid'];
		$channelinfo['subforums'] = $topic['subforums'];
	}

	// prefixid
	if (isset($topic['prefixid']) AND $topic['prefixid'] != '')
	{
		$conditions['node.prefixid'] = ($topic['prefixid'] == '-1' ? '' : $topic['prefixid']);
	}

	$channelApi = vB_Api::instance('content_channel');
	$channels = $channelApi->fetchTopLevelChannelIds();
	if(isset($channels['errors']))
	{
		print_stop_message_array($channels['errors']);
	}

	$special['specialchannelid'] = $channels['special'];
	return array('conditions' => $conditions, 'channelinfo' => $channelinfo, 'special'=> $special);
}

// ###################### Start thread move/prune by options #######################
if ($_POST['do'] == 'donodes')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'type'        => vB_Cleaner::TYPE_NOHTML,
		'topic'      => vB_Cleaner::TYPE_ARRAY,
		'destchannelid' => vB_Cleaner::TYPE_INT,
	));

	print_cp_header($vbphrase['topic_manager_admincp']);

	$topic = $vbulletin->GPC['topic'];
	$type = $vbulletin->GPC['type'];
	$destchannelid = $vbulletin->GPC['destchannelid'];

	if ($topic['channelid'] == 0)
	{
		print_stop_message('please_complete_required_fields');
	}

	if ($type == 'move')
	{

		$channel = vB_Api::instance('content_channel')->getContent($destchannelid);
		$channel = $channel[$destchannelid];

		if(isset($channel['errors']))
		{
			print_stop_message_array($channel['errors']);
		}

		if ($channel['category'])
		{
			print_stop_message('destination_channel_cant_contain_topics');
		}
	}

	$assertor = vB::getDbAssertor();

	$params = fetch_thread_move_prune_sql($assertor, $vbulletin->GPC['topic']);
	$hiddenParams = sign_client_string(serialize($params));

	$count = $assertor->getRow('vBForum:getNodeToolsTopicsCount', $params);
	$count = $count['count'];

	if (!$count)
	{
		print_stop_message('no_topics_matched_your_query');
	}

	$typephrases = get_action_phrases($type);

	print_form_header('admincp\nodetools', 'donodesall');
	construct_hidden_code('type', $type);
	construct_hidden_code('criteria', $hiddenParams);

	print_table_header(construct_phrase($vbphrase['x_topic_matches_found'], $count));
	if ($type == 'move')
	{
		construct_hidden_code('destchannelid', $destchannelid);
	}

	print_submit_row($vbphrase[$typephrases['action_all_topics']], '');

	print_form_header('admincp\nodetools', 'donodessel');
	construct_hidden_code('type', $type);
	construct_hidden_code('criteria', $hiddenParams);
	print_table_header(construct_phrase($vbphrase['x_topic_matches_found'], $count));
	if ($type == 'move')
	{
		construct_hidden_code('destchannelid', $destchannelid);
	}

	print_submit_row($vbphrase[$typephrases['action_topics_selectively']], '');
}

// ###################### Start move/prune all matching #######################
if ($_POST['do'] == 'donodesall')
{
	require_once(DIR . '/includes/functions_log_error.php');

	$vbulletin->input->clean_array_gpc('p', array(
		'type'        => vB_Cleaner::TYPE_NOHTML,
		'criteria'    => vB_Cleaner::TYPE_STR,
		'destchannelid' => vB_Cleaner::TYPE_INT,
	));

	$assertor = vB::getDbAssertor();

	print_cp_header($vbphrase['topic_manager_admincp']);

	$params = unserialize(verify_client_string($vbulletin->GPC['criteria']));
	if($params)
	{
		$nodeids = $assertor->getColumn('vBForum:getNodeToolsTopics', 'nodeid', $params);
		print_node_action($vbulletin->GPC['type'], $vbphrase, $nodeids, $vbulletin->GPC['destchannelid']);
	}
}

// ###################### Start move/prune select #######################
if ($_POST['do'] == 'donodessel')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'type'        => vB_Cleaner::TYPE_NOHTML,
		'criteria'    => vB_Cleaner::TYPE_STR,
		'destchannelid' => vB_Cleaner::TYPE_INT,
	));

	print_cp_header($vbphrase['topic_manager_admincp']);

	$type = $vbulletin->GPC['type'];

	$assertor = vB::getDbAssertor();
	$nodeApi = vB_Api::instance('node');

	$nodes = array();

	$params = unserialize(verify_client_string($vbulletin->GPC['criteria']));
	if($params)
	{
		$nodeids = $assertor->getColumn('vBForum:getNodeToolsTopics', 'nodeid', $params);

		$nodes = $nodeApi->getNodes($nodeids);
		if(isset($nodes['errors']))
		{
			print_stop_message_array($nodes['errors']);
		}
	}

	$topicsOnly = true;
	$starterTitles = array();
	$needTitles = array();
	foreach($nodes AS $node)
	{
		if($node['starter'] == $node['nodeid'])
		{
			$starterTitles[$node['nodeid']] = $node['title'];
		}
		else
		{
			$topicsOnly = false;
			if (!isset($starterTitles[$node['starter']]))
			{
				$needTitles[] = $node['starter'];
			}
		}
	}

	//shouldn't happen, but let's check.  Weird things could happen if we are wrong.
	if(!$topicsOnly AND $type != 'prune')
	{
		print_stop_message2(array('action_only_topics', $type));
	}

	$needTitles = array_unique($needTitles);

	$starters = $nodeApi->getNodes($needTitles);
	foreach($starters AS $starter)
	{
		$starterTitles[$starter['nodeid']] = $starter['title'];
	}

	unset($staters);

	print_form_header('admincp/nodetools', 'donodesselfinish');
	construct_hidden_code('type', $type);
	construct_hidden_code('destchannelid', $vbulletin->GPC['destchannelid']);

	$typephrases = get_action_phrases($type);
	print_table_header($vbphrase[$typephrases[($topicsOnly ? 'action_topics_selectively' : 'action_nodes_selectively')]], 5);

	$cells = array(
		'<input type="checkbox" name="allbox" title="' . $vbphrase['check_all'] . '" onclick="js_check_all(this.form);" checked="checked" />',
		$vbphrase['title'],
		$vbphrase['user'],
		$vbphrase['replies'],
		$vbphrase['last_post'],
	);

	print_cells_row($cells, true, false, 0, 'top', false, false, false, array(1 => 'left'));

	foreach($nodes AS $node)
	{
		$prefix = '';
		if($node['prefixid'])
		{
			$prefix = '[' . vB_String::htmlSpecialCharsUni($vbphrase["prefix_$node[prefixid]_title_plain"]) . '] ';
		}

		if ($node['starter'] == $node['nodeid'])
		{
			$title = $node['title'];
			$nodeUrl = vB5_Route::buildUrl($node['routeid'] . '|fullurl', $node);
		}
		else
		{
			$title = construct_phrase($vbphrase['child_of_x'], $starterTitles[$node['starter']]) . ' (nodeid ' .  $node['nodeid'] . ')';
			$nodeUrl=	vB5_Route::buildUrl($node['routeid'] . '|fullurl',
				array(
					'nodeid' => $node['starter'],
					'innerPost' => $node['nodeid'],
					'innerPostParent' => $node['parentid'],
				)
			);
		}

		$cells = array();
		$cells[] = "<input type=\"checkbox\" name=\"nodes[$node[nodeid]]\" tabindex=\"1\" checked=\"checked\" />";
		$cells[] = $prefix . '<a href="' . $nodeUrl. '" target="_blank">' . $title . '</a>';

		if ($node['userid'])
		{
			$authorUrl = vB5_Route::buildUrl('profile|fullurl', $node);
			$cells[] = '<span class="smallfont"><a href="' . $authorUrl . '" target="_blank">' . $node['authorname'] . '</a></span>';
		}
		else
		{
			$cells[] = '<span class="smallfont">' . $node['authorname'] . '</span>';
		}

		$cells[] = "<span class=\"smallfont\">$node[textcount]</span>";
		$cells[] = '<span class="smallfont">' . vbdate($vbulletin->options['dateformat'] . ' ' . $vbulletin->options['timeformat'], $node['lastcontent']) . '</span>';

		print_cells_row($cells, false, false, 0, 'top', false, false, false, array(1 => 'left'));
	}
	print_submit_row($vbphrase['go'], NULL, 5);
}

// ###################### Start move/prune select - finish! #######################
if ($_POST['do'] == 'donodesselfinish')
{
	require_once(DIR . '/includes/functions_log_error.php');

	$vbulletin->input->clean_array_gpc('p', array(
		'type'        => vB_Cleaner::TYPE_NOHTML,
		'nodes'      => vB_Cleaner::TYPE_ARRAY_BOOL,
		'destchannelid' => vB_Cleaner::TYPE_INT,
	));

	print_cp_header($vbphrase['topic_manager_admincp']);

	$nodes = $vbulletin->GPC['nodes'];
	if (is_array($nodes) AND !empty($nodes))
	{
		$nodeids = array_keys($nodes);
		print_node_action($vbulletin->GPC['type'], $vbphrase, $nodeids, $vbulletin->GPC['destchannelid']);
	}
	else
	{
		print_stop_message2('please_select_at_least_one_node');
	}
}


function get_action_phrases($type)
{
	$basephrases = array(
		'action_all_topics' => '%s_all_topics',
		'action_topics_selectively' => '%s_topics_selectively',
		'action_nodes_selectively' => ''
	);

	$phrases = array();
	foreach($basephrases AS $key => $phrase)
	{
		$phrases[$key] = sprintf($phrase, $type);
	}

	//add any more complicated mappings.
	if ($type == 'prune')
	{
		//prune is the only action that allows non topics
		$phrases['action_nodes_selectively'] = 'prune_nodes_selectively';
	}
/*
	else if ($vbulletin->GPC['type'] == 'move')
	{
	}
	else if ($vbulletin->GPC['type'] == 'close')
	{
	}
 */
	return $phrases;
}

function print_node_action($type, $vbphrase, $nodeids, $destination)
{
	if ($type == 'prune')
	{
		print_prune_nodes($vbphrase, $nodeids);
	}
	else if ($type == 'move')
	{
		print_move_nodes($vbphrase, $nodeids, $vbulletin->GPC['destchannelid']);
	}
	else if ($type == 'close')
	{
		print_close_nodes($vbphrase, $nodeids);
	}
}

function print_prune_nodes($vbphrase, $nodeids)
{
	$nodeApi = vB_Api::instance('node');

	echo '<p><b>' . $vbphrase['deleting_topics'] . '</b>';

	$result = $nodeApi->deleteNodes($nodeids, true);
	if(isset($result['errors']))
	{
		print_stop_message_array($result['errors']);
	}
	echo ' ' . $vbphrase['done'] . '</p>';

	print_stop_message2('pruned_topics_successfully', 'admincp/nodetools', array('do' => 'prune'));
}

function print_move_nodes($vbphrase, $nodeids, $destination)
{
	$nodeApi = vB_Api::instance('node');

	echo '<p><b>' . $vbphrase['moving_topics'] . '</b>';

	$result = $nodeApi->moveNodes($nodeids, $destination);
	if(isset($result['errors']))
	{
		print_stop_message_array($result['errors']);
	}
	echo ' ' . $vbphrase['done'] . '</p>';

	print_stop_message2('moved_topics_successfully', 'admincp/nodetools', array('do' => 'move'));
}

function print_close_nodes($vbphrase, $nodeids)
{
	$nodeApi = vB_Api::instance('node');

	echo '<p><b>' . $vbphrase['closing_topics'] . '</b>';

	$result = $nodeApi->closeNode($nodeids);
	if(isset($result['errors']))
	{
		print_stop_message_array($result['errors']);
	}
	echo ' ' . $vbphrase['done'] . '</p>';

	print_stop_message2('closed_topics_successfully', 'admincp/nodetools', array('do' => 'close'));
}

print_cp_footer();

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org : $Revision: 103832 $
|| # $Date: 2020-01-10 18:10:40 -0800 (Fri, 10 Jan 2020) $
|| ####################################################################
\*======================================================================*/
?>
