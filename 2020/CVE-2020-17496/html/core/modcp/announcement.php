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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 100258 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
$phrasegroups = array('posting');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once('./global.php');

// ############################# LOG ACTION ###############################
$vbulletin->input->clean_array_gpc('r', array(	'announcementid' => vB_Cleaner::TYPE_INT));
log_admin_action(!empty($vbulletin->GPC['announcementid']) ? "announcement id = " . $vbulletin->GPC['announcementid'] : '');


// ########################################################################
// ######################### FUNCTIONS         ############################
// ########################################################################

//moved here from an include file -- these function are only used in this file
//and really shouldn't used anywhere else (possibly not even here).

/**
* Checks whether or not an administrator can post announcements
*
* @param	integer	Forum ID
*
* @return	integer	The return value of this function is really rubbish... who wrote this?
*/
function fetch_announcement_permission_error($forumid)
{
	global $vbulletin, $phrase;

	if ($forumid == -1 AND !($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['ismoderator']))
	{
		return 1;
	}
	else if ($forumid != -1 AND !can_moderate($forumid, 'canannounce'))
	{
		return 2;
	}

	return 0;
}

/**
* Returns the phrase name for an error message
*
* @param	integer	Magic error number
*
* @return	string
*/
function fetch_announcement_permission_error_phrase($errno)
{
	global $vbphrase;
	switch($errno)
	{
		case 1:
			return 'you_do_not_have_permission_global';
			break;
		case 2:
			return 'you_do_not_have_permission_forum';
			break;
		default:
			return construct_phrase($vbphrase['unknown_error'], $errno);
	}
}


// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

print_cp_header($vbphrase['announcement_manager']);

// ###################### Start add / edit #######################

if ($_REQUEST['do'] == 'add' OR $_REQUEST['do'] == 'edit')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'forumid' => vB_Cleaner::TYPE_INT,
	));

	print_form_header('modcp/announcement', 'update');

	if ($_REQUEST['do'] == 'add')
	{
		$announcement = array(
			'startdate' => TIMENOW,
			'enddate' => (TIMENOW + 86400 * 31),
			'forumid' => $vbulletin->GPC['forumid'],
			'announcementoptions' => 29
		);
		print_table_header($vbphrase['post_new_announcement']);
	}
	else
	{
		// query announcement
		$announcement = $db->query_first("SELECT * FROM " . TABLE_PREFIX . "announcement WHERE announcementid = " . $vbulletin->GPC['announcementid']);

		if ($retval = fetch_announcement_permission_error($announcement['forumid']))
		{
			print_table_header(fetch_announcement_permission_error_phrase($retval));
			print_table_break();
		}

		construct_hidden_code('announcementid', $vbulletin->GPC['announcementid']);
		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['announcement'], htmlspecialchars_uni($announcement['title']), $announcement['announcementid']));

	}

	$issupermod = $permissions['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['ismoderator'];

	//this section is intended to allow the forum/channel for the annoucement.  The old code attempted to check which forums the
	//moderator had permission to use.  However the code never made the jump from forums to channels and fundamentally doesn't work
	//if we restore this functionality we need to fix this (the code below attempts to preserve some broken behavior after functions
	//stopped working -- it will just show a default "all forums" option.
	//	print_moderator_forum_chooser('forumid', $announcement['forumid'], $vbphrase['all_forums'], $vbphrase['forum_and_children'], iif($issupermod, true, false), false, false,'canannounce');

	//moved from the the old print_moderator_forum_chooser
	// The forum options function doesn't work and was removed, this function is used by a page that isn't displayed
	// but might be restored in some form, for now we'll just use a single "all forums" option (which is what was being displayed
	// by the broken code).
	//	$select_options = fetch_moderator_forum_options($topname, $displaytop, $displayselectforum, $permcheck);
	$select_options['-1'] = $vbphrase['all_forums'];
	print_select_row($vbphrase['forum_and_children'], 'forumid', $select_options, $announcement['forumid'], 0, 0, false);
	print_input_row($vbphrase['title'], 'title', $announcement['title']);

	print_time_row($vbphrase['start_date'], 'startdate', $announcement['startdate'], 0);
	print_time_row($vbphrase['end_date'], 'enddate', $announcement['enddate'], 0);

	print_textarea_row($vbphrase['text'], 'pagetext', $announcement['pagetext'], 10, 50, 1, 0);

	if ($vbulletin->GPC['announcementid'])
	{
		print_yes_no_row($vbphrase['reset_views_counter'], 'reset_views', 0);
	}

	print_yes_no_row($vbphrase['allow_bbcode'], 'announcementoptions[allowbbcode]', ($announcement['announcementoptions'] & $vbulletin->bf_misc_announcementoptions['allowbbcode'] ? 1 : 0));
	print_yes_no_row($vbphrase['allow_smilies'], 'announcementoptions[allowsmilies]', ($announcement['announcementoptions'] & $vbulletin->bf_misc_announcementoptions['allowsmilies'] ? 1 : 0));
	print_yes_no_row($vbphrase['allow_html'], 'announcementoptions[allowhtml]', ($announcement['announcementoptions'] & $vbulletin->bf_misc_announcementoptions['allowhtml'] ? 1 : 0));
	print_yes_no_row($vbphrase['automatically_parse_links_in_text'], 'announcementoptions[parseurl]', ($announcement['announcementoptions'] & $vbulletin->bf_misc_announcementoptions['parseurl'] ? 1 : 0));
	print_yes_no_row($vbphrase['show_your_signature'], 'announcementoptions[signature]', ($announcement['announcementoptions'] & $vbulletin->bf_misc_announcementoptions['signature'] ? 1 : 0));

	print_submit_row(iif($_REQUEST['do'] == 'add', $vbphrase['add'], $vbphrase['save']));
}

// ###################### Start insert #######################
if ($_POST['do'] == 'update')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'startdate'           => vB_Cleaner::TYPE_UNIXTIME,
		'enddate'             => vB_Cleaner::TYPE_UNIXTIME,
		'forumid'             => vB_Cleaner::TYPE_INT,
		'title'               => vB_Cleaner::TYPE_STR,
		'pagetext'            => vB_Cleaner::TYPE_STR,
		'announcementoptions' => vB_Cleaner::TYPE_ARRAY_BOOL,
		'reset_views'         => vB_Cleaner::TYPE_BOOL,
	));

	if ($retval = fetch_announcement_permission_error($vbulletin->GPC['announcement']['forumid']))
	{
		print_stop_message(fetch_announcement_permission_error_phrase($retval));
	}

	// query original data
	if ($vbulletin->GPC['announcementid'] AND (!$original_data = $db->query_first("SELECT * FROM " . TABLE_PREFIX . "announcement WHERE announcementid = " . $vbulletin->GPC['announcementid'])))
	{
		print_stop_message('invalidid', $vbphrase['announcement']);
	}

	if (!trim($vbulletin->GPC['title']))
	{
		$vbulletin->GPC['title'] = $vbphrase['announcement'];
	}

	$anncdata =& datamanager_init('Announcement', $vbulletin, vB_DataManager_Constants::ERRTYPE_CP);

	if ($vbulletin->GPC['announcementid'])
	{
		$anncdata->set_existing($original_data);

		if ($vbulletin->GPC['reset_views'])
		{
			define('RESET_VIEWS', true);
			$anncdata->set('views', 0);
		}
	}
	else
	{
		$anncdata->set('userid', $vbulletin->userinfo['userid']);
	}

	$anncdata->set('title', $vbulletin->GPC['title']);
	$anncdata->set('pagetext', $vbulletin->GPC['pagetext']);
	$anncdata->set('forumid', $vbulletin->GPC['forumid']);
	$anncdata->set('startdate', $vbulletin->GPC['startdate']);
	$anncdata->set('enddate', $vbulletin->GPC['enddate'] + 86399);

	foreach ($vbulletin->GPC['announcementoptions'] AS $key => $val)
	{
		$anncdata->set_bitfield('announcementoptions', $key, $val);
	}

	$announcementid = $anncdata->save();

	if ($original_data)
	{
		if ($vbulletin->GPC['reset_views'])
		{
			$db->query_write("DELETE FROM " . TABLE_PREFIX . "announcementread WHERE announcementid = " . $vbulletin->GPC['announcementid']);
		}
		$announcementid = $announcementinfo['announcementid'];
	}

	print_stop_message2(array('saved_announcement_x_successfully',  htmlspecialchars_uni($vbulletin->GPC['title']), 'forum'));
}

// ###################### Start Remove #######################

if ($_REQUEST['do'] == 'remove')
{
	$announcement = $db->query_first("
		SELECT forumid
		FROM " . TABLE_PREFIX . "announcement
		WHERE announcementid = " . $vbulletin->GPC['announcementid'] . "
	");
	if ($retval = fetch_announcement_permission_error($announcement['forumid']))
	{
		print_stop_message(fetch_announcement_permission_error_phrase($retval));
	}

	//this function no longer works correctly outside of the admincp as it will prepend
	//"admincp" to the action path (added to fix the admincp when the base tag was
	//added there).  Need to sort that out if/when this functionality is restored.
	print_delete_confirmation('announcement', $vbulletin->GPC['announcementid'], 'announcement', 'kill', 'announcement');
}

// ###################### Start Kill #######################

if ($_POST['do'] == 'kill')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'announcementid' 	=> vB_Cleaner::TYPE_UINT
	));

	if ($announcement = $db->query_first("SELECT * FROM " . TABLE_PREFIX . "announcement WHERE announcementid = " . $vbulletin->GPC['announcementid']))
	{
		if ($retval = fetch_announcement_permission_error($announcement['forumid']))
		{
			print_stop_message(fetch_announcement_permission_error_phrase($retval));
		}
		else
		{
			$anncdata =& datamanager_init('Announcement', $vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
			$anncdata->set_existing($announcement);
			$anncdata->delete();
		}

		print_stop_message2('deleted_announcement_successfully', 'forum');
	}
	else
	{
		print_stop_message('invalidid', $vbphrase['announcement']);
	}
}

print_cp_footer();



/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100258 $
|| #######################################################################
\*=========================================================================*/
