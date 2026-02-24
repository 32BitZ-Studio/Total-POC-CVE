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
define('CVS_REVISION', '$RCSfile$ - $Revision: 102796 $');
global $phrasegroups, $specialtemplates, $vbulletin, $vbphrase;

// #################### PRE-CACHE TEMPLATES AND DATA ######################
$phrasegroups = array('banning', 'cpuser', 'forum', 'timezone', 'user', 'cprofilefield', 'profilefield','cphome');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_profilefield.php');
require_once(DIR . '/includes/adminfunctions_user.php');

if ($_REQUEST['do'] == 'edit')
{
	$_REQUEST['do'] = 'viewuser';
}

// ############################# LOG ACTION ###############################
$vbulletin->input->clean_array_gpc('r', array('userid' => vB_Cleaner::TYPE_INT));
log_admin_action(iif($vbulletin->GPC['userid']!=0, 'user id = ' . $vbulletin->GPC['userid'], ''));

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();

print_cp_header($vbphrase['user_manager']);

// ############################# start do ips #########################
if ($_REQUEST['do'] == 'doips')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'depth'     => vB_Cleaner::TYPE_INT,
		'username'  => vB_Cleaner::TYPE_STR,
		'ipaddress' => vB_Cleaner::TYPE_NOHTML,
	));

	if (!can_moderate(0, 'canviewips'))
	{
		print_modcp_stop_message2('no_permission_ips');
	}

	if (($vbulletin->GPC['username'] OR $vbulletin->GPC['userid'] OR $vbulletin->GPC['ipaddress']) AND $_POST['do'] != 'doips')
	{
		// we're doing a search of some type, that's not submitted via post,
		// so we need to verify the CP sessionhash
		verify_cp_sessionhash();
	}

	// the following is now a direct copy of the contents of doips from admincp/user.php
	if (function_exists('set_time_limit'))
	{
		@set_time_limit(0);
	}

	if (empty($vbulletin->GPC['depth']))
	{
		$vbulletin->GPC['depth'] = 1;
	}

	if (!empty($vbulletin->GPC['username']))
	{
		if ($getuserid = $vbulletin->db->query_first("
			SELECT userid
			FROM " . TABLE_PREFIX . "user
			WHERE username = '" . $vbulletin->db->escape_string(htmlspecialchars_uni($vbulletin->GPC['username'])) . "'
		"))
		{
			$vbulletin->GPC['userid'] =& $getuserid['userid'];
		}
		else
		{
			print_modcp_stop_message2('invalid_user_specified');
		}

		$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
		if (!$userinfo)
		{
			print_modcp_stop_message2('invalid_user_specified');
		}
	}
	else if (!empty($vbulletin->GPC['userid']))
	{
		$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
		if (!$userinfo)
		{
			print_modcp_stop_message2('invalid_user_specified');
		}
		$vbulletin->GPC['username'] = unhtmlspecialchars($userinfo['username']);
	}

	if (!empty($vbulletin->GPC['ipaddress']) OR !empty($vbulletin->GPC['userid']))
	{
		if ($vbulletin->GPC['ipaddress'])
		{
			print_form_header('', '');
			print_table_header(construct_phrase($vbphrase['ip_address_search_for_ip_address_x'], $vbulletin->GPC['ipaddress']));
			$hostname = @gethostbyaddr($vbulletin->GPC['ipaddress']);
			if (!$hostname OR $hostname == $vbulletin->GPC['ipaddress'])
			{
				$hostname = $vbphrase['could_not_resolve_hostname'];
			}
			print_description_row('<div style="margin-' . vB_Template_Runtime::fetchStyleVar('left') . ':20px"><a href="user.php?' . vB::getCurrentSession()->get('sessionurl') . 'do=gethost&amp;ip=' . $vbulletin->GPC['ipaddress'] . '">' . $vbulletin->GPC['ipaddress'] . "</a> : <b>$hostname</b></div>");

			$results = construct_ip_usage_table($vbulletin->GPC['ipaddress'], 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['post_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			$results = construct_ip_register_table($vbulletin->GPC['ipaddress'], 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['registration_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			print_table_footer();
		}

		if ($vbulletin->GPC['userid'])
		{
			print_form_header('', '');
			print_table_header(construct_phrase($vbphrase['ip_address_search_for_user_x'], htmlspecialchars_uni($vbulletin->GPC['username'])));
			print_label_row($vbphrase['registration_ip_address'], $userinfo['ipaddress']);

			$results = construct_user_ip_table($vbulletin->GPC['userid'], 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['post_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			print_table_footer();
		}
	}

	print_form_header('modcp/user', 'doips');
	print_table_header($vbphrase['search_ip_addresses_gcphome']);
	print_input_row($vbphrase['find_users_by_ip_address'], 'ipaddress', $vbulletin->GPC['ipaddress'], 0);
	print_input_row($vbphrase['find_ip_addresses_for_user'], 'username', $vbulletin->GPC['username']);
	print_select_row($vbphrase['depth_to_search'], 'depth', array(1 => 1, 2 => 2), $vbulletin->GPC['depth']);
	print_submit_row($vbphrase['find']);
}

// ############################# start gethost #########################
if ($_REQUEST['do'] == 'gethost')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'ip' => vB_Cleaner::TYPE_NOHTML
	));

	print_form_header('', '');
	print_table_header($vbphrase['ip_address']);
	print_label_row($vbphrase['ip_address'], $vbulletin->GPC['ip']);
	$resolvedip = @gethostbyaddr($vbulletin->GPC['ip']);
	if ($resolvedip == $vbulletin->GPC['ip'])
	{
		print_label_row($vbphrase['host_name'], '<i>' . $vbphrase['n_a'] . '</i>');
	}
	else
	{
		print_label_row($vbphrase['host_name'], "<b>$resolvedip</b>");
	}
	print_table_footer();
}

// ###################### Start find #######################
if ($_REQUEST['do'] == 'find')
{
	if (
		!can_moderate(0, 'canunbanusers') AND
		!can_moderate(0, 'canbanusers') AND
		!can_moderate(0, 'canviewprofile') AND
		!can_moderate(0, 'caneditsigs') AND
		!can_moderate(0, 'caneditavatar')
	)
	{
		print_modcp_stop_message2('no_permission_search_users');
	}

	print_form_header('modcp/user', 'findnames');
	print_table_header($vbphrase['search_users']);
	print_input_row($vbphrase['username'], 'findname');
	print_yes_no_row($vbphrase['exact_match'], 'exact', 0);
	print_submit_row($vbphrase['search']);
}

// ###################### Start findname #######################
if ($_REQUEST['do'] == 'findnames')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'findname' => vB_Cleaner::TYPE_NOHTML,
		'exact'    => vB_Cleaner::TYPE_STR, // leave this as str because the main page sends a string value through
	));

	$canbanusers = can_moderate(0, 'canbanusers');
	$canunbanusers = can_moderate(0, 'canunbanusers');
	$canviewprofile = can_moderate(0, 'canviewprofile');
	$caneditsigs = can_moderate(0, 'caneditsigs');
	$caneditavatar = can_moderate(0, 'caneditavatar');

	if (!$canbanusers AND !$canunbanusers AND !$canviewprofile AND !$caneditsigs AND !$caneditavatar)
	{
		print_modcp_stop_message2('no_permission_search_users');
	}

	if (empty($vbulletin->GPC['findname']))
	{
		print_modcp_stop_message2('please_complete_required_fields');
	}

	if ($vbulletin->GPC['exact'])
	{
		$condition = "username = '" . $vbulletin->db->escape_string($vbulletin->GPC['findname']) . "'";
	}
	else
	{
		$condition = "username LIKE '%" . $vbulletin->db->escape_string_like($vbulletin->GPC['findname']) . "%'";
	}

	// get banned usergroups
	$querygroups = array('0' => true);
	foreach ($vbulletin->usergroupcache AS $usergroupid => $usergroup)
	{
		if (!($usergroup['genericoptions'] & $vbulletin->bf_ugp_genericoptions['isnotbannedgroup']))
		{
			$querygroups["$usergroupid"] = $usergroup['title'];
		}
	}

	$users = $vbulletin->db->query_read("
		SELECT userid, username, usergroupid IN(" . implode(',', array_keys($querygroups)) . ") AS inbannedgroup
		FROM " . TABLE_PREFIX . "user
		WHERE $condition
		ORDER BY username
	");
	if ($vbulletin->db->num_rows($users) > 0)
	{
		print_form_header('', '', 0, 1, 'cpform', '70%');
		print_table_header(construct_phrase($vbphrase['showing_users_x_to_y_of_z'], '1', $vbulletin->db->num_rows($users), $vbulletin->db->num_rows($users)), 7);
		while ($user = $vbulletin->db->fetch_array($users))
		{
			$cell = array("<b>$user[username]</b>");

			if ($canbanusers AND !$user['inbannedgroup'])
			{
				$cell[] = '<span class="smallfont">' .
					construct_link_code(
						$vbphrase['ban_user'],
						'modcp/banning.php?' . vB::getCurrentSession()->get('sessionurl') . "do=banuser&amp;u=$user[userid]",
						false,
						'',
						false,
						false
					) . '</span>';
			}
			elseif ($canunbanusers AND $user['inbannedgroup'])
			{
				$cell[] = '<span class="smallfont">' .
					construct_link_code(
						$vbphrase['lift_ban'],
						'modcp/banning.php?' . vB::getCurrentSession()->get('sessionurl') . "do=liftban&amp;u=$user[userid]",
						false,
						'',
						false,
						false
					) . '</span>';
			}
			else
			{
				$cell[] = '';
			}

			if ($canviewprofile)
			{
				$cell[] = '<span class="smallfont">' .
					construct_link_code(
						$vbphrase['view_profile'],
						'modcp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=viewuser&amp;u=$user[userid]",
						false,
						'',
						false,
						false
					) .
					'</span>';
			}
			else
			{
				$cell[] = ''; //empty column
			}

			if ($caneditsigs)
			{
				$cell[] = '<span class="smallfont">' .
					construct_link_code(
						$vbphrase['change_signature'],
						'modcp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=editsig&amp;u=$user[userid]",
						false,
						'',
						false,
						false
					) .
				'</span>';
			}
			else
			{
				$cell[] = ''; //empty column
			}

			print_cells_row($cell);
		}
		print_table_footer();
	}
	else
	{
		print_modcp_stop_message2('no_matches_found_gerror');
	}
}

// ###################### Start viewuser #######################
if ($_REQUEST['do'] == 'viewuser')
{
	if (!can_moderate(0, 'canviewprofile'))
	{
		print_modcp_stop_message2('no_permission');
	}

	$OUTERTABLEWIDTH = '95%';
	$INNERTABLEWIDTH = '100%';

	if (empty($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('invalid_user_specified');
	}

	$user = $vbulletin->db->query_first("
		SELECT user.*,usertextfield.signature,avatar.avatarpath, NOT ISNULL(customavatar.userid) AS hascustomavatar,
			customavatar.width AS avatarwidth, customavatar.height AS avatarheight,
			customavatar.dateline AS avatardateline, customavatar.extension AS avatarextension
		FROM " . TABLE_PREFIX . "user AS user
		LEFT JOIN " . TABLE_PREFIX . "avatar AS avatar ON avatar.avatarid = user.avatarid
		LEFT JOIN " . TABLE_PREFIX . "customavatar AS customavatar ON customavatar.userid = user.userid
		LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield ON (usertextfield.userid = user.userid)
		WHERE user.userid = " . $vbulletin->GPC['userid'] . "
	");

	$getoptions = convert_bits_to_array($user['options'], $vbulletin->bf_misc_useroptions);
	$user = array_merge($user, $getoptions);

	// get threaded mode options
	if ($user['threadedmode'] == 1 OR $user['threadedmode'] == 2)
	{
		$threaddisplaymode = $user['threadedmode'];
	}
	else
	{
		if ($user['postorder'] == 0)
		{
			$threaddisplaymode = 0;
		}
		else
		{
			$threaddisplaymode = 3;
		}
	}

	$userfield = $vbulletin->db->query_first("SELECT * FROM " . TABLE_PREFIX . "userfield WHERE userid=" . $vbulletin->GPC['userid']);

	// make array for daysprune menu
	$pruneoptions = array(
		'-1'   => '- ' . $vbphrase['use_forum_default'] . ' -',
		'1'    => $vbphrase['show_threads_from_last_day'],
		'2'    => construct_phrase($vbphrase['show_threads_from_last_x_days'], 2),
		'7'    => $vbphrase['show_threads_from_last_week'],
		'10'   => construct_phrase($vbphrase['show_threads_from_last_x_days'], 10),
		'14'   => construct_phrase($vbphrase['show_threads_from_last_x_weeks'], 2),
		'30'   => $vbphrase['show_threads_from_last_month'],
		'45'   => construct_phrase($vbphrase['show_threads_from_last_x_days'], 45),
		'60'   => construct_phrase($vbphrase['show_threads_from_last_x_months'], 2),
		'75'   => construct_phrase($vbphrase['show_threads_from_last_x_days'], 75),
		'100'  => construct_phrase($vbphrase['show_threads_from_last_x_days'], 100),
		'365'  => $vbphrase['show_threads_from_last_year'],
		'1000' => construct_phrase($vbphrase['show_threads_from_last_x_days'], 1000)
	);
	if ($pruneoptions["$user[daysprune]"] == '')
	{
		$pruneoptions["$user[daysprune]"] = construct_phrase($vbphrase['show_threads_from_last_x_days'], $user['daysprune']);
	}

	// Legacy Hook 'useradmin_edit_start' Removed //

	print_form_header('modcp/user', 'viewuser', 0, 0);
	construct_hidden_code('userid', $vbulletin->GPC['userid']);
	?>
	<table cellpadding="0" cellspacing="0" border="0" width="<?php echo $OUTERTABLEWIDTH; ?>" align="center"><tr valign="top"><td>
	<table cellpadding="4" cellspacing="0" border="0" align="center" width="100%" class="tborder">
	<?php

	// start main table
	require_once(DIR . '/includes/functions_misc.php');

	// PROFILE SECTION
	print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['user'], $user['username'], $user['userid']));
	print_input_row($vbphrase['username'], 'user[username]', $user['username'], 0);
	print_input_row($vbphrase['email'], 'user[email]', $user['email'], 0);
	print_select_row($vbphrase['language'], 'user[languageid]', fetch_language_titles_array('', 0), $user['languageid'] );
	print_input_row($vbphrase['user_title_guser'], 'user[usertitle]', $user['usertitle']);
	print_yes_no_row($vbphrase['custom_user_title'], 'options[customtitle]', $user['customtitle']);
	print_input_row($vbphrase['home_page_guser'], 'user[homepage]', $user['homepage'], 0);
	print_time_row($vbphrase['birthday'], 'birthday', $user['birthday'], 0, 1);
	$tempHTML = '';
	if (can_moderate(0, 'caneditsigs'))
	{
		$tempHTML = '<br /><br />' .
			construct_link_code(
				$vbphrase['edit_signature'],
				'modcp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=editsig&amp;u=$user[userid]",
				false,
				'',
				false,
				false
			);
	}
	print_textarea_row(
		$vbphrase['signature'] . $tempHTML,
		'signature',
		$user['signature'],
		8,
		45,
		1,
		0
	);
	unset($tempHTML);
	print_input_row($vbphrase['icq_uin'], 'user[icq]', $user['icq'], 0);
	print_input_row($vbphrase['aim_screen_name'], 'user[aim]', $user['aim'], 0);
	print_input_row($vbphrase['yahoo_id'], 'user[yahoo]', $user['yahoo'], 0);
	print_input_row($vbphrase['msn_id'], 'user[msn]', $user['msn'], 0);
	print_input_row($vbphrase['skype_name'], 'user[skype]', $user['skype'], 0);
	print_yes_no_row($vbphrase['coppa_user'], 'options[coppauser]', $user['coppauser']);
	print_input_row($vbphrase['parent_email_address'], 'user[parentemail]', $user['parentemail'], 0);
	print_input_row($vbphrase['post_count'], 'user[posts]', $user['posts']);
	if ($user['referrerid'])
	{
		$referrername = $vbulletin->db->query_first("SELECT username FROM " . TABLE_PREFIX . "user WHERE userid = $user[referrerid]");
		$user['referrer'] = $referrername['username'];
	}
	print_input_row($vbphrase['referrer'], 'referrer', $user['referrer']);
	if (can_moderate(0, 'canviewips'))
	{
		print_input_row($vbphrase['ip_address'], 'user[ipaddress]', $user['ipaddress']);
	}
	print_table_break('', $INNERTABLEWIDTH);

	// USER IMAGE SECTION
	print_table_header($vbphrase['image_options']);
	if ($user['avatarid'])
	{
		$avatarurl = resolve_cp_image_url($user['avatarpath']);
	}
	else
	{
		if ($user['hascustomavatar'])
		{
			if ($vbulletin->options['usefileavatar'])
			{
				$avatarurl = resolve_cp_image_url($vbulletin->options['avatarurl'] . "/avatar$user[userid]_$user[avatarrevision].$user[avatarextension]");
			}
			else
			{
				$avatarurl = '../image.php?' . vB::getCurrentSession()->get('sessionurl') . "u=$user[userid]&amp;dateline=$user[avatardateline]";
			}
			if ($user['avatarwidth'] AND $user['avatarheight'])
			{
				$avatarurl .= "\" width=\"$user[avatarwidth]\" height=\"$user[avatarheight]";
			}
		}
		else
		{
			$avatarurl = 'images/clear.gif';
		}
	}

	$tempHTML = '';
	if (can_moderate(0, 'caneditavatar'))
	{
		$tempHTML = '<br /><br />' .
			construct_link_code(
				$vbphrase['edit_avatar'],
				'modcp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=avatar&amp;u=$user[userid]",
				false,
				'',
				false,
				false
			);
	}
	print_label_row(
		$vbphrase['avatar'] .
		$tempHTML .
		'<input type="image" src="'.
		'images/clear.gif' .
		'" alt="" />','<img src="' . $avatarurl . '" alt="" align="top" />'
	);
	unset($tempHTML);
	print_table_break('', $INNERTABLEWIDTH);

	// PROFILE FIELDS SECTION
	$forms = array(
		0 => $vbphrase['edit_your_details'],
		1 => "$vbphrase[options]: $vbphrase[log_in] / $vbphrase[privacy]",
		2 => "$vbphrase[options]: $vbphrase[messaging] / $vbphrase[notification]",
		3 => "$vbphrase[options]: $vbphrase[thread_viewing]",
		4 => "$vbphrase[options]: $vbphrase[date] / $vbphrase[time]",
		5 => "$vbphrase[options]: $vbphrase[other]",
	);
	$currentform = -1;

	print_table_header($vbphrase['user_profile_fields']);

	$profilefields = $vbulletin->db->query_read("
		SELECT *
		FROM " . TABLE_PREFIX . "profilefield AS profilefield
		LEFT JOIN " . TABLE_PREFIX . "profilefieldcategory AS profilefieldcategory ON
			(profilefield.profilefieldcategoryid = profilefieldcategory.profilefieldcategoryid)
		ORDER BY profilefield.form, profilefieldcategory.displayorder, profilefield.displayorder
	");

	while ($profilefield = $vbulletin->db->fetch_array($profilefields))
	{
		if ($profilefield['form'] != $currentform)
		{
			print_description_row(construct_phrase($vbphrase['fields_from_form_x'], $forms["$profilefield[form]"]), false, 2, 'optiontitle');
			$currentform = $profilefield['form'];
		}
		print_profilefield_row('profile', $profilefield, $userfield, false);
	}

	// Legacy Hook 'useradmin_edit_column1' Removed //

	if ($vbulletin->options['cp_usereditcolumns'] == 2)
	{
		?>
		</table>
		</td><td>&nbsp;&nbsp;&nbsp;&nbsp;</td><td>
		<table cellpadding="4" cellspacing="0" border="0" align="center" width="100%" class="tborder">
		<?php
	}
	else
	{
		print_table_break('', $INNERTABLEWIDTH);
	}

	// USERGROUP SECTION
	print_table_header($vbphrase['usergroup_options_gcpuser']);
	print_chooser_row($vbphrase['primary_usergroup'], 'user[usergroupid]', 'usergroup', $user['usergroupid']);
	print_membergroup_row($vbphrase['additional_usergroups'], 'membergroup', 0, $user);
	print_table_break('', $INNERTABLEWIDTH);

	// reputation SECTION
	print_table_header($vbphrase['reputation']);
	print_yes_no_row($vbphrase['display_reputation_gcpuser'], 'options[showreputation]', $user['showreputation']);
	print_input_row($vbphrase['reputation_level_guser'], 'user[reputation]', $user['reputation']);
	print_table_break('',$INNERTABLEWIDTH);

	// BROWSING OPTIONS SECTION
	print_table_header($vbphrase['browsing_options']);
	print_yes_no_row($vbphrase['receive_admin_emails_guser'], 'options[adminemail]', $user['adminemail']);
	print_yes_no_row($vbphrase['invisible_mode_guser'], 'options[invisible]', $user['invisible']);
	print_yes_no_row($vbphrase['receive_private_messages_guser'], 'options[receivepm]', $user['receivepm']);
	print_yes_no_row($vbphrase['send_notification_email_when_a_private_message_is_received_guser'], 'options[emailonpm]', $user['emailonpm']);
	print_yes_no_row($vbphrase['pop_up_notification_box_when_a_private_message_is_received'], 'user[pmpopup]', $user['pmpopup']);
	print_yes_no_row($vbphrase['save_pm_copy_default_no_link'], 'options[pmdefaultsavecopy]', $user['pmdefaultsavecopy']);
	print_yes_no_row($vbphrase['display_signature'], 'options[showsignatures]', $user['showsignatures']);
	print_yes_no_row($vbphrase['display_avatars_gcpuser'], 'options[showavatars]', $user['showavatars']);
	print_yes_no_row($vbphrase['display_images_gcpuser'], 'options[showimages]', $user['showimages']);
	print_yes_no_row($vbphrase['send_birthday_email'], 'options[birthdayemail]', $user['birthdayemail']);

	print_yes_no_row($vbphrase['autosubscribe_when_posting'], 'user[autosubscribe]', $user['autosubscribe']);

	print_radio_row($vbphrase['usersetting_emailnotification'], 'user[emailnotification]', array(
		0  => $vbphrase['usersetting_emailnotification_none'],
		1  => $vbphrase['usersetting_emailnotification_on'],
		2  => $vbphrase['usersetting_emailnotification_daily'],
		3  => $vbphrase['usersetting_emailnotification_weekly'],
	), $user['emailnotification'], 'smallfont');

	print_radio_row($vbphrase['thread_display_mode_guser'], 'threaddisplaymode', array(
		0 => "$vbphrase[linear] - $vbphrase[oldest_first]",
		3 => "$vbphrase[linear] - $vbphrase[newest_first]",
		2 => $vbphrase['hybrid'],
		1 => $vbphrase['threaded']
	), $threaddisplaymode, 'smallfont');

	print_radio_row($vbphrase['message_editor_interface'], 'user[showvbcode]', array(
		0 => $vbphrase['do_not_show_editor_toolbar'],
		1 => $vbphrase['show_standard_editor_toolbar'],
		2 => $vbphrase['show_enhanced_editor_toolbar']
	), $user['showvbcode'], 'smallfont');

	construct_style_chooser($vbphrase['style'], 'user[styleid]', $user['styleid']);
	print_table_break('', $INNERTABLEWIDTH);

	// TIME FIELDS SECTION
	print_table_header($vbphrase['time_options']);
	print_description_row($vbphrase['timezone'].' <select name="user[timezoneoffset]" class="bginput" tabindex="1">' . construct_select_options(fetch_timezones_array(), $user['timezoneoffset']) . '</select>');
	print_label_row($vbphrase['default_view_age'], '<select name="user[daysprune]" class="bginput" tabindex="1">' . construct_select_options($pruneoptions, $user['daysprune']) . '</select>');
	print_time_row($vbphrase['join_date'], 'joindate', $user['joindate'], 0);
	print_time_row($vbphrase['last_visit_guser'], 'lastvisit', $user['lastvisit']);
	print_time_row($vbphrase['last_activity'], 'lastactivity', $user['lastactivity']);
	print_time_row($vbphrase['last_post'], 'lastpost', $user['lastpost']);

	// Legacy Hook 'useradmin_edit_column2' Removed //

	?>
	</table>
	</tr>
	<?php

	print_table_break('', $OUTERTABLEWIDTH);
	$tableadded = 1;
	print_table_footer();
}

// ###################### Start editsig #######################
if ($_REQUEST['do'] == 'editsig')
{

	if (!can_moderate(0, 'caneditsigs'))
	{
		print_modcp_stop_message2('no_permission_signatures');
	}

	if (empty($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('invalid_user_specified');
	}

	if (is_unalterable_user($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('user_is_protected_from_alteration_by_undeletableusers_var');
	}

	$user = $vbulletin->db->query_first("
		SELECT * FROM " . TABLE_PREFIX . "user AS user
		LEFT JOIN " . TABLE_PREFIX . "usertextfield AS usertextfield USING (userid)
		WHERE user.userid = " . $vbulletin->GPC['userid'] . "
	");

	print_form_header('modcp/user','doeditsig', 0, 1);
	construct_hidden_code('userid', $vbulletin->GPC['userid']);
	print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['signature'], $user['username'], $user['userid']));
	print_textarea_row($vbphrase['signature'], 'signature', $user['signature'], 8, 45, 1, 0);
	print_submit_row();

}

// ###################### Start doeditsig #######################
if ($_POST['do'] == 'doeditsig')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'signature' => vB_Cleaner::TYPE_STR
	));

	if (!can_moderate(0, 'caneditsigs'))
	{
		print_modcp_stop_message2('no_permission_signatures');
	}

	if (is_unalterable_user($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('user_is_protected_from_alteration_by_undeletableusers_var');
	}

	$user = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$user)
	{
		print_modcp_stop_message2('invalid_user_specified');
	}

	$userdm = new vB_Datamanager_User($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
	$userdm->set_existing($user);
	$userdm->set('signature', $vbulletin->GPC['signature'], true, false);
	$userdm->save();
	unset($userdm);

	if (can_moderate(0, 'canviewprofile'))
	{
		$file = 'user';
		$args = array(
			'do' => 'viewuser',
			'u' => $vbulletin->GPC['userid']
		);
	}
	else
	{
		$file = 'index';
		$args = array(
			'do' => 'home',
		);
	}
	print_modcp_stop_message2('saved_signature_successfully', $file, $args);

}

	/**
	 * VBV-13125 No longer applicable moderator permissions that should be removed Removed
	 * Removed the logic that handles forum profile picture change since it is not used in vB5
	 */

// ###################### Start modify Avatar ################
if ($_REQUEST['do'] == 'avatar')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'startpage' => vB_Cleaner::TYPE_INT,
		'perpage'   => vB_Cleaner::TYPE_INT
	));

	if (!can_moderate(0, 'caneditavatar'))
	{
		print_modcp_stop_message2('no_permission_avatars');
	}

	if (is_unalterable_user($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('user_is_protected_from_alteration_by_undeletableusers_var');
	}

	$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$userinfo)
	{
		print_modcp_stop_message2('invalid_user_specified');
	}

	$avatarchecked["{$userinfo['avatarid']}"] = 'checked="checked"';
	$nouseavatarchecked = '';
	if (!$avatarinfo = $vbulletin->db->query_first("SELECT * FROM " . TABLE_PREFIX . "customavatar WHERE userid = " . $vbulletin->GPC['userid']))
	{
		// no custom avatar exists
		if (!$userinfo['avatarid'])
		{
			// must have no avatar selected
			$nouseavatarchecked = 'checked="checked"';
			$avatarchecked[0] = '';
		}
	}
	if ($vbulletin->GPC['startpage'] < 1)
	{
		$vbulletin->GPC['startpage'] = 1;
	}
	if ($vbulletin->GPC['perpage'] < 1)
	{
		$vbulletin->GPC['perpage'] = 25;
	}
	$avatarcount = $vbulletin->db->query_first("SELECT COUNT(*) AS count FROM " . TABLE_PREFIX . "avatar");
	$totalavatars = $avatarcount['count'];
	if (($vbulletin->GPC['startpage'] - 1) * $vbulletin->GPC['perpage'] > $totalavatars)
	{
		if ((($totalavatars / $vbulletin->GPC['perpage']) - (intval($totalavatars / $vbulletin->GPC['perpage']))) == 0)
		{
			$vbulletin->GPC['startpage'] = $totalavatars / $vbulletin->GPC['perpage'];
		}
		else
		{
			$vbulletin->GPC['startpage'] = intval(($totalavatars / $vbulletin->GPC['perpage'])) + 1;
		}
	}
	$limitlower = ($vbulletin->GPC['startpage'] - 1) * $vbulletin->GPC['perpage'] + 1;
	$limitupper = ($vbulletin->GPC['startpage']) * $vbulletin->GPC['perpage'];
	if ($limitupper > $totalavatars)
	{
		$limitupper = $totalavatars;
		if ($limitlower > $totalavatars)
		{
			$limitlower = $totalavatars - $vbulletin->GPC['perpage'];
		}
	}
	if ($limitlower <= 0)
	{
		$limitlower = 1;
	}
	$avatars = $vbulletin->db->query_read("
		SELECT * FROM " . TABLE_PREFIX . "avatar
		ORDER BY title LIMIT " . ($limitlower-1) . ", " . $vbulletin->GPC['perpage'] . "
	");
	$avatarcount = 0;
	if ($totalavatars > 0)
	{
		print_form_header('modcp/user', 'avatar');
		construct_hidden_code('userid', $vbulletin->GPC['userid']);
		print_table_header(
			$vbphrase['avatars_to_show_per_page'] .
			': <input type="text" name="perpage" value="' . $vbulletin->GPC['perpage'] . '" size="5" tabindex="1" />
			<input type="submit" class="button" value="' . $vbphrase['go'] . '" tabindex="1" />
		');
		print_table_footer();
	}

	print_form_header('modcp/user', 'updateavatar', 1);
	print_table_header($vbphrase['avatars']);

	$output = '<table border="0" cellpadding="6" cellspacing="1" class="tborder" align="center" width="100%">';
	while ($avatar = $vbulletin->db->fetch_array($avatars))
	{
		$avatarid = $avatar['avatarid'];
		$avatar['avatarpath'] = resolve_cp_image_url($avatar['avatarpath']);
		if ($avatarcount == 0)
		{
			$output .= '<tr class="' . fetch_row_bgclass() . '">';
		}
		$output .= "<td valign=\"bottom\" align=\"center\"><input type=\"radio\" name=\"avatarid\" value=\"$avatar[avatarid]\" tabindex=\"1\" $avatarchecked[$avatarid] />";
		$output .= "<img src=\"$avatar[avatarpath]\" alt=\"\" /><br />$avatar[title]</td>";
		$avatarcount++;
		if ($avatarcount == 5)
		{
			echo '</tr>';
			$avatarcount = 0;
		}
	}
	if ($avatarcount != 0)
	{
		while ($avatarcount != 5)
		{
			$output .= '<td>&nbsp;</td>';
			$avatarcount++;
		}
		echo '</tr>';
	}
	if ((($totalavatars / $vbulletin->GPC['perpage']) - (intval($totalavatars / $vbulletin->GPC['perpage']))) == 0)
	{
		$numpages = $totalavatars / $vbulletin->GPC['perpage'];
	}
	else
	{
		$numpages = intval($totalavatars / $vbulletin->GPC['perpage']) + 1;
	}
	if ($vbulletin->GPC['startpage'] == 1)
	{
		$starticon = 0;
		$endicon = $vbulletin->GPC['perpage'] - 1;
	}
	else
	{
		$starticon = ($vbulletin->GPC['startpage'] - 1) * $vbulletin->GPC['perpage'];
		$endicon = ($vbulletin->GPC['perpage'] * $vbulletin->GPC['startpage']) - 1 ;
	}
	if ($numpages > 1)
	{
		for ($x = 1; $x <= $numpages; $x++)
		{
			if ($x == $vbulletin->GPC['startpage'])
			{
				$pagelinks .= " [<b>$x</b>] ";
			}
			else
			{
				$pagelinks .= " <a href=\"user.php?startpage=$x&pp=" . $vbulletin->GPC['perpage'] . "&do=avatar&u=" . $vbulletin->GPC['userid'] . "\">$x</a> ";
			}
		}
	}
	if ($vbulletin->GPC['startpage'] != $numpages)
	{
		$nextstart = $vbulletin->GPC['startpage'] + 1;
		$nextpage = " <a href=\"user.php?startpage=$nextstart&pp=" . $vbulletin->GPC['perpage'] . "&do=avatar&u=" . $vbulletin->GPC['userid'] . "\">" . $vbphrase['next_page'] . "</a>";
		$eicon = $endicon + 1;
	}
	else
	{
		$eicon = $totalavatars;
	}
	if ($vbulletin->GPC['startpage'] != 1)
	{
		$prevstart = $vbulletin->GPC['startpage'] - 1;
		$prevpage = "<a href=\"user.php?startpage=$prevstart&pp=" . $vbulletin->GPC['perpage'] . "&do=avatar&u=" . $vbulletin->GPC['userid'] . "\">" . $vbphrase['prev_page'] . "</a> ";
	}
	$sicon = $starticon +  1;
	if ($totalavatars > 0)
	{
		if ($pagelinks)
		{
			$colspan = 3;
		}
		else
		{
			$colspan = 5;
		}
		$output .= '<tr><td class="thead" align="center" colspan="' . $colspan . '">';
		$output .= construct_phrase($vbphrase['showing_avatars_x_to_y_of_z'], $sicon, $eicon, $totalavatars) . '</td>';
		if ($pagelinks)
		{
			$output .= "<td class=\"thead\" colspan=\"2\" align=\"center\">$vbphrase[page]: <span class=\"normal\">$prevpage $pagelinks $nextpage</span></td>";
		}
		$output .= '</tr>';
	}
	$output .= '</table>';

	if ($totalavatars > 0)
	{
		print_description_row($output);
	}

	if ($nouseavatarchecked)
	{
		print_description_row($vbphrase['user_has_no_avatar']);
	}
	else
	{
		print_yes_row($vbphrase['delete_avatar'], 'avatarid', $vbphrase['yes'], '', -1);
	}
	print_table_break();
	print_table_header($vbphrase['custom_avatar']);

	$userinfo['avatarurl'] = fetch_avatar_url($userinfo['userid']);

	if ($userinfo['avatarurl'] == '' OR $userinfo['avatarid'] != 0)
	{
		$userinfo['avatarurl'] = '<img src="images/clear.gif" alt="" border="0" />';
	}
	else
	{
		$userinfo['avatarurl'] = "<img src=\"../" . $userinfo['avatarurl'][0] . "\" " . $userinfo['avatarurl'][1] . " alt=\"\" border=\"0\" />";
	}
	print_yes_row(
		iif($avatarchecked[0] != '',
			$vbphrase['use_current_avatar'] . ' ' . $userinfo['avatarurl'],
			$vbphrase['add_new_custom_avatar']
		)
	, 'avatarid', $vbphrase['yes'], $avatarchecked[0], 0);

	cache_permissions($userinfo, false);
	if ($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel'] AND $userinfo['permissions']['genericpermissions'] & $vbulletin->bf_ugp_genericpermissions['canuseavatar'] AND ($userinfo['permissions']['avatarmaxwidth'] > 0 OR $userinfo['permissions']['avatarmaxheight'] > 0))
	{
		print_yes_no_row($vbphrase['resize_image_to_users_maximum_allowed_size'], 'resize');
	}
	print_input_row($vbphrase['enter_image_url_gcpuser'], 'avatarurl', 'http://www.');
	print_upload_row($vbphrase['upload_image_from_computer'], 'upload');
	construct_hidden_code('userid', $vbulletin->GPC['userid']);
	print_submit_row($vbphrase['save']);
}

// ###################### Start Update Avatar ################
if ($_POST['do'] == 'updateavatar')
{
	if (!can_moderate(0, 'caneditavatar'))
	{
		print_modcp_stop_message2('no_permission_avatars');
	}

	$vbulletin->input->clean_array_gpc('p', array(
		'avatarid'  => vB_Cleaner::TYPE_INT,
		'avatarurl' => vB_Cleaner::TYPE_STR,
		'resize'    => vB_Cleaner::TYPE_BOOL,
	));

	if (is_unalterable_user($vbulletin->GPC['userid']))
	{
		print_modcp_stop_message2('user_is_protected_from_alteration_by_undeletableusers_var');
	}

	$useavatar = iif($vbulletin->GPC['avatarid'] == -1, 0, 1);

	$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$userinfo)
	{
		print_modcp_stop_message2('invalid_user_specified');
	}

	// init user datamanager
	$userdata = new vB_Datamanager_User($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
	$userdata->set_existing($userinfo);

	if ($useavatar)
	{
		if (!$vbulletin->GPC['avatarid'])
		{
			// custom avatar
			$vbulletin->input->clean_gpc('f', 'upload', vB_Cleaner::TYPE_FILE);

			require_once(DIR . '/includes/class_upload.php');

			$upload = new vB_Upload_Userpic($vbulletin);

			$upload->data = new vB_DataManager_Userpic_Avatar($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
			$object =& vB_DataManager_Userpic::fetch_library($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
			$upload->data->validfields = array_merge($object->validfields, $upload->data->validfields);

			$upload->image =& vB_Image::instance();
			$upload->userinfo =& $userinfo;

			cache_permissions($userinfo, false);

			// user's group doesn't have permission to use custom avatars so set override
			if (!($userinfo['permissions']['genericpermissions'] & $vbulletin->bf_ugp_genericpermissions['canuseavatar']))
			{
				$userdata->set_bitfield('adminoptions', 'adminavatar', 1);
			}

			if (
					($userinfo['permissions']['avatarmaxwidth'] > 0 OR $userinfo['permissions']['avatarmaxheight'] > 0)
					AND
					(
						$vbulletin->GPC['resize']
							OR
						(!($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel']))
					)
				)
			{
				$upload->maxwidth = $userinfo['permissions']['avatarmaxwidth'];
				$upload->maxheight = $userinfo['permissions']['avatarmaxheight'];
			}

			if (!$upload->process_upload($vbulletin->GPC['avatarurl']))
			{
				print_modcp_stop_message2(array('there_were_errors_encountered_with_your_upload_x',  $upload->fetch_error()));
			}
		}
		else
		{
			// predefined avatar
			$userpic = new vB_DataManager_Userpic_Avatar($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
			$userpic->condition = array('userid' => $userinfo['userid']);
			$userpic->delete();
		}
	}
	else
	{
		// not using an avatar
		$vbulletin->GPC['avatarid'] = 0;
		$userpic = new vB_DataManager_Userpic_Avatar($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
		$userpic->condition = array('userid' => $userinfo['userid']);
		$userpic->delete();
	}

	$userdata->set('avatarid', $vbulletin->GPC['avatarid']);
	$userdata->save();

	if (can_moderate(0, 'canviewprofile'))
	{
		$file = 'user';
		$args = array(
			'do' => 'viewuser',
			'u' => $vbulletin->GPC['userid']
		);
	}
	else
	{
		$file = 'index';
		$args = array(
			'do' => 'home',
		);
	}
	print_modcp_stop_message2('saved_avatar_successfully', $file, $args);
}

// ###################### Start Moderate Group Join Requests #######################
if ($_REQUEST['do'] == 'viewjoinrequests')
{
	if ($permissions['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel'])
	{
		$userlink = '<a href="admincp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;u=%d\" target=\"_blank\">%s</a>";
		$grouplink = 'admincp/usergroup.php?' . vB::getCurrentSession()->get('sessionurl') . "do=viewjoinrequests&amp;usergroupid=%d";
	}
	else
	{
		$userlink = '<a href="modcp/user.php?' . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;u=%d\" target=\"_blank\">%s</a>";
		// "joinrequests.php" doesn't exist, not fixing the link.
		$grouplink = '../joinrequests.php?' . vB::getCurrentSession()->get('sessionurl') . "usergroupid=%d";
	}

	// get array of all usergroup leaders
	$bbuserleader = array();
	$leaders = array();
	$groupleaders = $vbulletin->db->query_read("
		SELECT ugl.*, user.username
		FROM " . TABLE_PREFIX . "usergroupleader AS ugl
		INNER JOIN " . TABLE_PREFIX . "user AS user USING(userid)
	");
	while ($groupleader = $vbulletin->db->fetch_array($groupleaders))
	{
		if ($groupleader['userid'] == $vbulletin->userinfo['userid'])
		{
			$bbuserleader[] = $groupleader['usergroupid'];
		}
		$leaders["$groupleader[usergroupid]"]["$groupleader[userid]"] = sprintf($userlink, $groupleader['userid'], $groupleader['username']);
	}
	unset($groupleader);
	$vbulletin->db->free_result($groupleaders);

	if (empty($bbuserleader) AND !($permissions['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel']))
	{
		print_modcp_stop_message2('no_permission');
	}

	$requests = $vbulletin->db->query_read("
		SELECT usergrouprequest.usergroupid, COUNT(usergrouprequestid) AS requests
		FROM " . TABLE_PREFIX . "usergrouprequest AS usergrouprequest
		LEFT JOIN " . TABLE_PREFIX . "user AS user USING (userid)
		WHERE user.userid IS NOT NULL
		GROUP BY usergroupid
	");
	while ($request = $vbulletin->db->fetch_array($requests))
	{
		$vbulletin->usergroupcache["$request[usergroupid]"]['requests'] = $request['requests'];
	}
	unset($request);
	$vbulletin->db->free_result($requests);

	print_form_header('', '');
	print_table_header($vbphrase['join_requests_manager'], 4);
	print_cells_row(array(
		$vbphrase['usergroup'],
		$vbphrase['usergroup_leader'],
		$vbphrase['join_requests'],
		$vbphrase['controls']
	), 1);
	foreach ($vbulletin->usergroupcache AS $usergroupid => $usergroup)
	{
		if ($usergroup['ispublicgroup'] AND in_array($usergroupid, $bbuserleader))
		{
			print_cells_row(array(
				$usergroup['title'],
				iif(empty($leaders["$usergroupid"]), "<i>$vbphrase[n_a]</i>", implode(', ', $leaders["$usergroupid"])),
				vb_number_format($usergroup['requests']),
				construct_link_code(
					$vbphrase['view_join_requests_gcpuser'],
					sprintf($grouplink, $usergroupid),
					false,
					'',
					false,
					false
				)
			));
		}
	}
	print_table_footer();

}

	/**
	 * VBV-13125 No longer applicable moderator permissions that should be removed Removed
	 * Removed the logic that handles reputation editing
	 */
print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102796 $
|| #######################################################################
\*=========================================================================*/
