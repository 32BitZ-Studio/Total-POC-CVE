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
define('CVS_REVISION', '$RCSfile$ - $Revision: 103411 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin, $usercache, $numcolors, $colorPickerType, $colorPickerWidth;
$phrasegroups = array('cpuser', 'forum', 'timezone', 'user');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_user.php');
$assertor = vB::getDbAssertor();

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminusers'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'avatarid' => vB_Cleaner::TYPE_INT,
	'userid'   => vB_Cleaner::TYPE_INT,
));

if (is_browser('webkit') AND $vbulletin->GPC['avatarid'] AND empty($_POST['do']))
{
	$_POST['do'] = $_REQUEST['do'] = 'updateavatar';
}

// ############################# LOG ACTION ###############################
log_admin_action(!empty($vbulletin->GPC['userid']) ? 'user id = ' . $vbulletin->GPC['userid'] : '');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

print_cp_header($vbphrase['user_manager']);

// ###################### Start Remove User's Subscriptions #######################
if ($_REQUEST['do'] == 'removesubs')
{
	print_delete_confirmation('user', $vbulletin->GPC['userid'], 'usertools', 'killsubs', 'subscriptions');
}

// ###################### Start Remove User's Subscriptions #######################
if ($_POST['do'] == 'killsubs')
{
	vB::getDbAssertor()->delete('vBForum:subscribediscussion', array('userid' => $vbulletin->GPC['userid']));
	print_stop_message2('deleted_subscriptions_successfully', 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
}


if ($_REQUEST['do'] == 'removetagassociations')
{
	print_delete_confirmation('user', $vbulletin->GPC['userid'], 'usertools', 'killtagassocations', 'tagassociations');
}

if ($_POST['do'] == 'killtagassocations')
{
	$api = vB_Api::instance('tags');
	$result = $api->deleteUserTagAssociations($vbulletin->GPC['userid']);
	if(isset($result['errors']))
	{
		print_stop_message_array($result['errors']);
	}

	print_stop_message2('deleted_tagassocations_successfully', 'user', array('do' => 'edit', 'u'=> $vbulletin->GPC['userid']));
}

// ###################### Start Remove User's PMs #######################
if ($_REQUEST['do'] == 'removepms')
{
	print_delete_confirmation('user', $vbulletin->GPC['userid'], 'usertools', 'killpms', 'private_messages_belonging_to_the_user');
}

// ###################### Start Remove User's PMs #######################
if ($_POST['do'] == 'killpms')
{
	$pmapi = vB_Api::instance('content_privatemessage');
	$result = $pmapi->deleteMessagesForUser($vbulletin->GPC['userid']);
	if(isset($result['errors']))
	{
		print_stop_message_array($result['errors']);
	}

	print_stop_message2(array('deleted_x_pms', $result['deleted']), 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
}

// ###################### Start Remove PMs Sent by User #######################
if ($_REQUEST['do'] == 'removesentpms')
{

	print_delete_confirmation('user', $vbulletin->GPC['userid'], 'usertools', 'killsentpms', 'private_messages_sent_by_the_user');
}

// ###################### Start Remove User's PMs #######################
if ($_POST['do'] == 'killsentpms')
{

	$pmapi = vB_Api::instance('content_privatemessage');
	$result = $pmapi->deleteSentMessagesForUser($vbulletin->GPC['userid']);
	if(isset($result['errors'][0]))
	{
		print_stop_message2($result['errors'][0]);
	}

	print_stop_message2('deleted_private_messages_successfully', 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
}

// ###################### Start Remove VMs Sent by User #######################
if ($_REQUEST['do'] == 'removesentvms')
{
	print_delete_confirmation('user', $vbulletin->GPC['userid'], 'usertools', 'killsentvms', 'visitor_messages_sent_by_the_user');
}

// ###################### Start Remove User's VMs #######################
if ($_POST['do'] == 'killsentvms')
{
	$vms = $assertor->getColumn('vBForum:node', 'nodeid', array(
		vB_dB_Query::CONDITIONS_KEY => array(
			'userid' => $vbulletin->GPC['userid'],
			array('field' => 'setfor', 'value' => 0, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE),
		)
	));

	if (empty($vms))
	{
		print_stop_message2('no_visitor_messages_matched_your_query', 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
	}
	else
	{
		try
		{
			vB_Api::instanceInternal('node')->deleteNodes($vms);
		}
		catch (vB_Exception_Api $ex)
		{
			print_stop_message2($ex->getMessage());
		}

		print_stop_message2('deleted_visitor_messages_successfully', 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
	}
}

// ###################### Reset Mfa #######################
if ($_REQUEST['do'] == 'resetmfa')
{

	$userApi = vB_Api::instance('user');
	$userinfo = $userApi->fetchUserinfo($vbulletin->GPC['userid']);

	print_form_header('admincp/usertools', 'doresetmfa');
	print_table_header($vbphrase['two_factor_authentication']);
	print_description_row(construct_phrase($vbphrase['confirm_mfa_reset'], $userinfo['username']));
	construct_hidden_code('u', $vbulletin->GPC['userid']);
	print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);
}

if ($_POST['do'] == 'doresetmfa')
{
	$userApi = vB_Api::instance('user');
	$user = $userApi->setMfaEnabled($vbulletin->GPC['userid'], false);
	if (isset($user['errors']))
	{
		print_stop_message_array($user['errors']);
	}

	print_stop_message2('successfully_reset_mfa', 'user', array('do' => 'edit', 'u' => $vbulletin->GPC['userid']));
}

// ###################### Start Merge #######################
if ($_REQUEST['do'] == 'merge')
{
	print_form_header('admincp/usertools', 'domerge');
	print_table_header($vbphrase['merge_users_gcpuser']);
	print_description_row($vbphrase['merge_allows_you_to_join_two_user_accounts']);
	print_input_row($vbphrase['source_username'], 'sourceuser');
	print_input_row($vbphrase['destination_username'], 'destuser');
	print_submit_row($vbphrase['continue']);

}

// ###################### Start Do Merge #######################
if ($_POST['do'] == 'domerge')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'sourceuser' => vB_Cleaner::TYPE_NOHTML,
		'destuser'   => vB_Cleaner::TYPE_NOHTML
	));

	if ($vbulletin->GPC['destuser'] == $vbulletin->GPC['sourceuser'])
	{
		print_stop_message2('source_and_destination_identical');
	}

	$sourceuserid = vB::getDbAssertor()->getField('user', array(
		'username' => $vbulletin->GPC['sourceuser'],
		vB_dB_Query::COLUMNS_KEY => array('userid'),
	));

	if (!$sourceuserid)
	{
		print_stop_message2('invalid_source_username_specified');
	}

	$destuserid = vB::getDbAssertor()->getField('user', array(
		'username' => $vbulletin->GPC['destuser'],
		vB_dB_Query::COLUMNS_KEY => array('userid'),
	));

	if (!$destuserid)
	{
		print_stop_message2('invalid_destination_username_specified');
	}

	try
	{
		$sourceinfo = vB_Api::instanceInternal('user')->fetchUserinfo($sourceuserid);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!$sourceinfo)
	{
		print_stop_message2('invalid_source_username_specified');
	}

	try
	{
		$destinfo = vB_Api::instanceInternal('user')->fetchUserinfo($destuserid);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!$destinfo)
	{
		print_stop_message2('invalid_destination_username_specified');
	}

	if (is_unalterable_user($sourceinfo['userid']) OR is_unalterable_user($destinfo['userid']))
	{
		print_stop_message2('user_is_protected_from_alteration_by_undeletableusers_var');
	}

	print_form_header('admincp/usertools', 'reallydomerge');
	construct_hidden_code('sourceuserid', $sourceinfo['userid']);
	construct_hidden_code('destuserid', $destinfo['userid']);
	print_table_header($vbphrase['confirm_merge']);
	print_description_row(construct_phrase($vbphrase['are_you_sure_you_want_to_merge_x_into_y'], $vbulletin->GPC['sourceuser'], $vbulletin->GPC['destuser']));
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
}

// ###################### Start Do Merge #######################
if ($_POST['do'] == 'reallydomerge')
{
	// Get info on both users
	$vbulletin->input->clean_array_gpc('p', array(
		'sourceuserid' => vB_Cleaner::TYPE_INT,
		'destuserid'   => vB_Cleaner::TYPE_INT
	));

	try
	{
		$sourceinfo = vB_Api::instanceInternal('user')->fetchUserinfo($vbulletin->GPC['sourceuserid']);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!$sourceinfo)
	{
		print_stop_message2('invalid_source_username_specified');
	}

	try
	{
		$destinfo = vB_Api::instanceInternal('user')->fetchUserinfo($vbulletin->GPC['destuserid']);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!$destinfo)
	{
		print_stop_message2('invalid_destination_username_specified');
	}

	try
	{
		vB_Api::instanceInternal('user')->merge($vbulletin->GPC['sourceuserid'], $vbulletin->GPC['destuserid']);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	// Legacy Hook 'useradmin_merge' Removed //

	print_stop_message2(array('user_accounts_merged', $sourceinfo['username'], $destinfo['username']),NULL, array(),'');

}

// ###################### Start modify Signature Pic ###########
if ($_REQUEST['do'] == 'sigpic')
{
	$userinfo = vB_User::fetchUserinfo($vbulletin->GPC['userid'], array(vB_Api_User::USERINFO_SIGNPIC));
	if (!$userinfo)
	{
		print_stop_message2('invalid_user_specified');
	}

	if ($userinfo['sigpicwidth'] AND $userinfo['sigpicheight'])
	{
		$size = " width=\"$userinfo[sigpicwidth]\" height=\"$userinfo[sigpicheight]\" ";
	}

	print_form_header('admincp/usertools', 'updatesigpic', 1);
	construct_hidden_code('userid', $userinfo['userid']);
	print_table_header($vbphrase['change_signature_picture'] . ": <span class=\"normal\">$userinfo[username]</span>");
	if ($userinfo['sigpic'])
	{
		$userinfo['sigpicurl'] = vB::getDatastore()->getOption('frontendurl') . '/filedata/fetch?filedataid=' . $userinfo['sigpicfiledataid'] . '&amp;sigpic=1';;
		print_description_row("<div align=\"center\"><img src=\"$userinfo[sigpicurl]\" $size alt=\"\" title=\"" . construct_phrase($vbphrase['xs_picture'], $userinfo['username']) . "\" /></div>");
		print_yes_no_row($vbphrase['use_signature_picture'], 'usesigpic', 1);
	}
	else
	{
		construct_hidden_code('usesigpic', 1);
	}

	// TODO: Doesn't work yet for vB5
//	cache_permissions($userinfo, false);
//	if ($userinfo['permissions']['signaturepermissions'] & $vbulletin->bf_ugp_signaturepermissions['cansigpic'] AND ($userinfo['permissions']['sigpicmaxwidth'] > 0 OR $userinfo['permissions']['sigpicmaxheight'] > 0))
//	{
//		print_yes_no_row($vbphrase['resize_image_to_users_maximum_allowed_size'], 'resize');
//	}
	print_input_row($vbphrase['enter_image_url_gcpuser'], 'sigpicurl', 'http://www.');
	print_upload_row($vbphrase['upload_image_from_computer'], 'upload');

	print_submit_row($vbphrase['save']);
}

// ###################### Start Update Profile Pic ################
if ($_POST['do'] == 'updatesigpic')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'userid'    => vB_Cleaner::TYPE_UINT,
		'usesigpic' => vB_Cleaner::TYPE_BOOL,
		'sigpicurl' => vB_Cleaner::TYPE_STR,
		'resize'    => vB_Cleaner::TYPE_BOOL,
	));

	$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$userinfo)
	{
		print_stop_message2('invalid_user_specified');
	}

	if ($vbulletin->GPC['usesigpic'])
	{
		$vbulletin->input->clean_gpc('f', 'upload', vB_Cleaner::TYPE_FILE);
		scanVbulletinGPCFile('upload');

		try
		{
			if ($vbulletin->GPC['sigpicurl'] AND $vbulletin->GPC['sigpicurl'] != 'http://www.')
			{
				$response = vB_Library::instance('content_attach')->uploadUrl($userinfo['userid'], $vbulletin->GPC['sigpicurl'], true, 'signature');
			}
			else
			{
				$vbulletin->GPC['upload']['uploadFrom'] = 'signature';
				$response = vB_Library::instance('content_attach')->uploadAttachment($userinfo['userid'], $vbulletin->GPC['upload']);
			}
		}
		catch (Exception $e)
		{
			print_stop_message2(array('there_were_errors_encountered_with_your_upload_x',  $e->getMessage()));
		}
	}
	else
	{
		vB_Library::instance('content_attach')->removeSignaturePicture($userinfo['userid']);
	}

	print_stop_message2('saved_signature_picture_successfully', 'user', array('do' => 'edit', 'u'=>$userinfo['userid']));
}


// ###################### Start modify Avatar ################
if ($_REQUEST['do'] == 'avatar')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'perpage'   => vB_Cleaner::TYPE_INT,
		'startpage' => vB_Cleaner::TYPE_INT,
	));

	$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$userinfo)
	{
		print_stop_message2('invalid_user_specified');
	}

	$avatarchecked["{$userinfo['avatarid']}"] = 'checked="checked"';
	$nouseavatarchecked = '';
	if (!$avatarinfo = $assertor->getRow('vBForum:customavatar', array('userid' => $vbulletin->GPC['userid'])))
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

	$avatarcount = $assertor->getRow('vBForum:avatar', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT));
	$totalavatars = $avatarcount['count'];
	if (($vbulletin->GPC['startpage'] - 1) * $vbulletin->GPC['perpage'] > $totalavatars)
	{
		if ((($totalavatars / $vbulletin->GPC['perpage']) - intval($totalavatars / $vbulletin->GPC['perpage'])) == 0)
		{
			$vbulletin->GPC['startpage'] = $totalavatars / $vbulletin->GPC['perpage'];
		}
		else
		{
			$vbulletin->GPC['startpage'] = intval($totalavatars / $vbulletin->GPC['perpage']) + 1;
		}
	}
	$limitlower = ($vbulletin->GPC['startpage'] - 1) * $vbulletin->GPC['perpage'] + 1;
	$limitupper = $vbulletin->GPC['startpage'] * $vbulletin->GPC['perpage'];
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

	$avatars = $assertor->getRowS('vBForum:getAvatarLimit', array('startat' => ($limitlower - 1), 'perpage' => $vbulletin->GPC['perpage']));
	$avatarcount = 0;
	if ($totalavatars > 0)
	{
		print_form_header('admincp/usertools', 'avatar');
		construct_hidden_code('userid', $vbulletin->GPC['userid']);
		print_table_header(
			$vbphrase['avatars_to_show_per_page_gcpuser'] .
			': <input type="text" name="perpage" value="' . $vbulletin->GPC['perpage'] . '" size="5" tabindex="1" />
			<input type="submit" class="button" value="' . $vbphrase['go'] . '" tabindex="1" />
		');
		print_table_footer();
	}

	print_form_header('admincp/usertools', 'updateavatar', 1);
	print_table_header($vbphrase['avatars_gcpglobal']);

	$output = "<table border=\"0\" cellpadding=\"6\" cellspacing=\"1\" class=\"tborder\" align=\"center\" width=\"100%\">";
	foreach ($avatars AS $avatar)
	{
		$avatarid = $avatar['avatarid'];
		$avatar['avatarpath'] = resolve_cp_image_url($avatar['avatarpath']);
		if ($avatarcount == 0)
		{
			$output .= '<tr class="' . fetch_row_bgclass() . '">';
		}
		$output .= "<td valign=\"bottom\" align=\"center\" width=\"20%\"><label for=\"av$avatar[avatarid]\"><input type=\"radio\" name=\"avatarid\" id=\"av$avatar[avatarid]\" value=\"$avatar[avatarid]\" tabindex=\"1\" $avatarchecked[$avatarid] />";
		$output .= "<img src=\"$avatar[avatarpath]\" alt=\"\" /><br />$avatar[title]</label></td>";
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
	if ((($totalavatars / $vbulletin->GPC['perpage']) - intval($totalavatars / $vbulletin->GPC['perpage'])) == 0)
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
				$pagelinks .= " <a href=\"admincp/usertools.php?startpage=$x&amp;pp=" . $vbulletin->GPC['perpage'] . "&amp;do=avatar&amp;u=" . $vbulletin->GPC['userid'] . "\">$x</a> ";
			}
		}
	}
	if ($vbulletin->GPC['startpage'] != $numpages)
	{
		$nextstart = $vbulletin->GPC['startpage'] + 1;
		$nextpage = " <a href=\"admincp/usertools.php?startpage=$nextstart&amp;pp=" . $vbulletin->GPC['perpage'] . "&amp;do=avatar&amp;u=" . $vbulletin->GPC['userid'] . "\">" . $vbphrase['next_page'] . "</a>";
		$eicon = $endicon + 1;
	}
	else
	{
		$eicon = $totalavatars;
	}
	if ($vbulletin->GPC['startpage'] != 1)
	{
		$prevstart = $vbulletin->GPC['startpage'] - 1;
		$prevpage = "<a href=\"admincp/usertools.php?startpage=$prevstart&amp;pp=" . $vbulletin->GPC['perpage'] . "&amp;do=avatar&amp;u=" . $vbulletin->GPC['userid'] . "\">" . $vbphrase['prev_page'] . "</a> ";
	}
	$sicon = $starticon + 1;
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
		$output .= construct_phrase($vbphrase['showing_avatars_x_to_y_of_z_gcpuser'], $sicon, $eicon, $totalavatars) . '</td>';
		if ($pagelinks)
		{
			$output .= "<td class=\"thead\" colspan=\"2\" align=\"center\">$vbphrase[page_gcpglobal]: <span class=\"normal\">$prevpage $pagelinks $nextpage</span></td>";
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

	if (empty($userinfo['avatarurl']) OR $userinfo['avatarid'] != 0)
	{
		$userinfo['avatarurl'] = '<img src="images/clear.gif" alt="" border="0" />';
	}
	else
	{
		$userinfo['avatarurl'] = "<img src=\"" . $userinfo['avatarurl'][0] . "\" " . $userinfo['avatarurl'][1] . " alt=\"\" border=\"0\" />";
	}

	if (!empty($avatarchecked[0]))
	{
		print_label_row($vbphrase['custom_avatar'], $userinfo['avatarurl']);
	}
	print_yes_row((!empty($avatarchecked[0]) ? $vbphrase['use_current_avatar'] : $vbphrase['add_new_custom_avatar']), 'avatarid', $vbphrase['yes'], $avatarchecked[0], 0);

	cache_permissions($userinfo, false);
// 	if ($userinfo['permissions']['genericpermissions'] & $vbulletin->bf_ugp_genericpermissions['canuseavatar'] AND ($userinfo['permissions']['avatarmaxwidth'] > 0 OR $userinfo['permissions']['avatarmaxheight'] > 0))
// 	{
// 		print_yes_no_row($vbphrase['resize_image_to_users_maximum_allowed_size'], 'resize');
// 	}
	print_input_row($vbphrase['enter_image_url_gcpuser'], 'avatarurl', 'http://');
	print_upload_row($vbphrase['upload_image_from_computer'], 'upload');
	construct_hidden_code('userid', $vbulletin->GPC['userid']);
	print_submit_row($vbphrase['save']);
}

// ###################### Start Update Avatar ################
if ($_POST['do'] == 'updateavatar')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'userid'    => vB_Cleaner::TYPE_UINT,
		'avatarid'  => vB_Cleaner::TYPE_INT,
		'avatarurl' => vB_Cleaner::TYPE_STR,
//		'resize'    => vB_Cleaner::TYPE_BOOL,
	));

	$useavatar = iif($vbulletin->GPC['avatarid'] == -1, 0, 1);

	$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
	if (!$userinfo)
	{
		print_stop_message2('invalid_user_specified');
	}

	if ($useavatar)
	{
		$crop = array();
		if (!empty($_FILES['upload']['tmp_name']))
		{
			$vbulletin->input->clean_gpc('f', 'upload', vB_Cleaner::TYPE_FILE);
			scanVbulletinGPCFile('upload');
			if (!file_exists($_FILES['upload']['tmp_name']))
			{
				throw new Exception('Upload failed. PHP upload error: ' . intval($_FILES['upload']['error']));
			}
			$filearray = $_FILES['upload'];
			$data['org_file_info'] = pathinfo($_FILES['upload']['name']);
			$filesize = filesize($_FILES['upload']['tmp_name']);

			$fileContents = file_get_contents($_FILES['upload']['tmp_name']);
			$filename = $_FILES['upload']['tmp_name'];
			$crop['org_file_info'] = pathinfo($_FILES['upload']['name']);
		}
		elseif (!empty($vbulletin->GPC['avatarurl']))
		{
			//Make a local copy
			require_once(DIR . '/includes/class_upload.php');
			$upload = new vB_Upload_Image($vbulletin);
			$upload->image = vB_Image::instance();
			$upload->path = vB_Utilities::getTmpDir();
			$filename = $upload->process_upload($vbulletin->GPC['avatarurl']);
		}

		if ($filename)
		{
			vB_Library::instance('user')->uploadAvatar($filename, $crop, $userinfo['userid'], true);
		}
		else
		{
			print_stop_message2('upload_file_failed');
		}
	}
	else
	{
		// not using an avatar
		$vbulletin->GPC['avatarid'] = 0;
		$userpic = new vB_Datamanager_Userpic_Avatar($vbulletin, vB_DataManager_Constants::ERRTYPE_CP);
		$userpic->condition = array(
				array('field' => 'userid', 'value' => $userinfo['userid'], 'operator' => vB_dB_Query::OPERATOR_EQ)
		);
		$userpic->delete();
	}

	print_stop_message2('saved_avatar_successfully', 'user', array('do' => 'edit', 'u'=>$vbulletin->GPC['userid']));
}

// ############################# start user pm stats #########################
if ($_REQUEST['do'] == 'pmfolderstats')
{
	$foldersQry = $assertor->assertQuery('vBForum:getUserPmFolders', array('userid' => $vbulletin->GPC['userid']));

	$userinfo = array();
	$foldernames = array();
	foreach ($foldersQry AS $folder)
	{
		if (!isset($userinfo['userid']))
		{
			$userinfo['userid'] = $folder['userid'];
		}
		if (!isset($userinfo['username']))
		{
			$userinfo['username'] = $folder['username'];
		}

		$foldernames[$folder['folderid']] = empty($folder['title']) ? $vbphrase[$folder['titlephrase']] : $folder['title'];
	}

	if (!$userinfo['userid'])
	{
		print_stop_message2('invalid_user_specified');
	}

	$pms = $assertor->getRows('vBForum:getUserPmFoldersCount', array('userid' => $userinfo['userid']));
	if (!count($pms))
	{
		print_stop_message2('no_matches_found_gerror');
	}

	$folders = array();
	$pmtotal = 0;
	foreach ($pms AS $pm)
	{
		$pmtotal += $pm['messages'];
		$folders[$pm['folderid']] = array('messages' => $pm['messages'], 'phrase' => $foldernames[$pm['folderid']]);
	}

	print_form_header('admincp/user', 'edit');
	construct_hidden_code('userid', $userinfo['userid']);
	print_table_header(construct_phrase($vbphrase['private_messages_for_x'], $userinfo['username']) . "</b> (userid: $userinfo[userid])<b>");
	print_cells_row(array($vbphrase['folder'], $vbphrase['number_of_messages']), 1);
	foreach($folders AS $folderid => $folderinfo)
	{
		print_cells_row(array($folderinfo['phrase'], $folderinfo['messages']));
	}
	print_cells_row(array('<b>' . $vbphrase['total'] . '</b>', "<b>$pmtotal</b>"));
	print_description_row('<div align="center">' . construct_link_code($vbphrase['delete_private_messages'], "usertools.php?" . vB::getCurrentSession()->get('sessionurl') . "do=removepms&amp;u=" . $vbulletin->GPC['userid']) . '</div>', 0, 2, 'thead');
	print_submit_row($vbphrase['edit_user'], 0);

}

// ############################# start PM stats #########################
if ($_REQUEST['do'] == 'pmstats')
{
	try
	{
		$pms = vB_Api::instanceInternal('user')->fetchUsersPms();
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	print_form_header('admincp/usertools', 'viewpmstats');
	print_table_header($vbphrase['private_message_statistics_gcpuser'], 3);
	print_cells_row(array($vbphrase['number_of_messages'], $vbphrase['number_of_users'], $vbphrase['controls']), 1);

	$groups = array();
	foreach ($pms AS $pm)
	{
		$groups["$pm[total]"]++;
	}
	foreach ($groups AS $key => $total)
	{
		$cell = array();
		$cell[] = $key . iif($vbulletin->options['pmquota'], '/' . $vbulletin->options['pmquota']);
		$cell[] = $total;
		$cell[] = construct_link_code(construct_phrase($vbphrase['list_users_with_x_messages'], $key), "usertools.php?" . vB::getCurrentSession()->get('sessionurl') . "do=pmuserstats&total=$key");
		print_cells_row($cell);
	}
	print_table_footer();

}

// ############################# start PM stats #########################
if ($_REQUEST['do'] == 'pmuserstats')
{

	$vbulletin->input->clean_array_gpc('r', array(
		'total' => vB_Cleaner::TYPE_UINT
	));

	try
	{
		$users = vB_Api::instanceInternal('user')->fetchUsersPms(
			array(
				'sortby' => array('fields' => 'user.username', 'direction' => vB_dB_Query::SORT_DESC),
				'total' => $vbulletin->GPC['total']
		));
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!count($users))
	{
		print_stop_message2('no_users_matched_your_query');
	}

	$vb5_options =& vB::getDatastore()->getValue('options');
	$bburl = $vb5_options['bburl'];

	// a little javascript for the options menus
	?>
	<script type="text/javascript">
	function js_pm_jump(userid,username)
	{
		value = eval("document.cpform.u" + userid + ".options[document.cpform.u" + userid + ".selectedIndex].value");
		var page = '';

		switch (value)
		{
			case 'pmstats': page = "admincp/usertools.php?do=pmfolderstats&u=" + userid; break;
			case 'profile': page = "admincp/user.php?do=edit&u=" + userid; break;
			case 'pmuser': page = "<?php echo $bburl; ?>/private.php?do=newpm&u=" + userid; break;
			case 'delete': page = "admincp/usertools.php?do=removepms&u=" + userid; break;
		}
		if (page != '')
		{
			vBRedirect(page + "&s=<?php echo vB::getCurrentSession()->get('sessionhash'); ?>");
		}
		else
		{
			vBRedirect("mailto:" + value);
		}
	}
	</script>
	<?php

	print_form_header('admincp/usertools', '');
	print_table_header(construct_phrase($vbphrase['users_with_x_private_messages_stored'], $vbulletin->GPC['pms']), 3);
	print_cells_row(array($vbphrase['username'], $vbphrase['last_activity'], $vbphrase['options']), 1);
	foreach ($users AS $user)
	{
		$cell = array();
		$cell[] = "<a href=\"" . vB5_Route::buildUrl('profile|bburl', $user) . "\" target=\"_blank\">$user[username]</a>";
		$cell[] = vbdate($vbulletin->options['dateformat'] . ', ' . $vbulletin->options['timeformat'], $user['lastactivity']);
		$cell[] = "
		<select name=\"u$user[userid]\" onchange=\"js_pm_jump($user[userid], '$user[username]');\" tabindex=\"1\" class=\"bginput\">
			<option value=\"pmstats\">" . $vbphrase['view_private_message_statistics'] . "</option>
			<option value=\"profile\">" . $vbphrase['edit_user'] . "</option>
			" . (!empty($user['email']) ? "<option value=\"$user[email]\">" . $vbphrase['send_email_to_user'] . "</option>" : "") . "
			<option value=\"pmuser\">" . $vbphrase['send_private_message_to_user'] . "</option>
			<option value=\"delete\">" . construct_phrase($vbphrase['delete_all_users_private_messages']) . "</option>
		</select><input type=\"button\" class=\"button\" value=\"$vbphrase[go]\" onclick=\"js_pm_jump($user[userid], '$user[username]');\" tabindex=\"1\" />\n\t";
		print_cells_row($cell);
	}
	print_table_footer();

}

// ############################# start do ips #########################
if ($_REQUEST['do'] == 'doips')
{
	if (function_exists('set_time_limit'))
	{
		@set_time_limit(0);
	}

	$vbulletin->input->clean_array_gpc('r', array(
		'depth'     => vB_Cleaner::TYPE_INT,
		'username'  => vB_Cleaner::TYPE_STR,
		'ipaddress' => vB_Cleaner::TYPE_NOHTML,
	));

	if (($vbulletin->GPC['username'] OR $vbulletin->GPC['userid'] OR $vbulletin->GPC['ipaddress']) AND $_POST['do'] != 'doips')
	{
		// we're doing a search of some type, that's not submitted via post,
		// so we need to verify the CP sessionhash
		verify_cp_sessionhash();
	}

	if (empty($vbulletin->GPC['depth']))
	{
		$vbulletin->GPC['depth'] = 1;
	}

	if ($vbulletin->GPC['username'])
	{
		try
		{
			$getuserid = vB_Api::instanceInternal('user')->fetchByUsername($vbulletin->GPC['username']);
		}
		catch (vB_Exception_Api $ex)
		{
			$getuserid = false;
		}

		$userid = intval($getuserid['userid']);

		$userinfo = $getuserid;
		if (!$userinfo)
		{
			print_stop_message2('invalid_user_specified');
		}
	}
	else if ($vbulletin->GPC['userid'])
	{
		$userid = $vbulletin->GPC['userid'];
		try
		{
			$userinfo = vB_Api::instanceInternal('user')->fetchUserinfo($vbulletin->GPC['userid']);
		}
		catch (vB_Exception_Api $ex)
		{
			$userinfo = false;
		}

		if (!$userinfo)
		{
			print_stop_message2('invalid_user_specified');
		}
		$vbulletin->GPC['username'] = vB_String::unHtmlSpecialChars($userinfo['username']);
	}
	else
	{
		$userid = 0;
	}

	if ($vbulletin->GPC['ipaddress'] OR $userid)
	{
		if ($vbulletin->GPC['ipaddress'])
		{
			print_form_header('admincp/', '');
			print_table_header(construct_phrase($vbphrase['ip_address_search_for_ip_address_x'], $vbulletin->GPC['ipaddress']));
			$hostname = @gethostbyaddr($vbulletin->GPC['ipaddress']);
			if (!$hostname OR $hostname == $vbulletin->GPC['ipaddress'])
			{
				$hostname = $vbphrase['could_not_resolve_hostname'];
			}

			$url = 'admincp/usertools.php?do=gethost&amp;ip=' . $vbulletin->GPC['ipaddress'];
			print_description_row("<div style=\"margin-" . vB_Template_Runtime::fetchStyleVar('left') . ":20px\"><a href=\"" .
				$url . "\">" . $vbulletin->GPC['ipaddress'] . "</a> : <b>$hostname</b></div>");

			$results = construct_ip_usage_table($vbulletin->GPC['ipaddress'], 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['post_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			$results = construct_ip_register_table($vbulletin->GPC['ipaddress'], 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['registration_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			print_table_footer();
		}

		if ($userid)
		{
			print_form_header('admincp/', '');
			print_table_header(construct_phrase($vbphrase['ip_address_search_for_user_x'], htmlspecialchars_uni($vbulletin->GPC['username'])));
			print_label_row($vbphrase['registration_ip_address'], ($userinfo['ipaddress'] ? $userinfo['ipaddress'] : $vbphrase['n_a']));

			$results = construct_user_ip_table($userid, 0, $vbulletin->GPC['depth']);
			print_description_row($vbphrase['post_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			if ($userinfo['ipaddress'])
			{
				$results = construct_ip_register_table($userinfo['ipaddress'], $userid, $vbulletin->GPC['depth']);
			}
			else
			{
				$results = '';
			}
			print_description_row($vbphrase['registration_ip_addresses'], false, 2, 'thead');
			print_description_row($results ? $results : $vbphrase['no_matches_found_gcpuser']);

			print_table_footer();
		}
	}

	print_form_header('admincp/usertools', 'doips');
	print_table_header($vbphrase['search_ip_addresses_gcpuser']);
	print_input_row($vbphrase['find_users_by_ip_address'], 'ipaddress', $vbulletin->GPC['ipaddress'], 0);
	print_input_row($vbphrase['find_ip_addresses_for_user'], 'username', $vbulletin->GPC['username']);
	print_select_row($vbphrase['depth_to_search'], 'depth', array(1 => 1, 2 => 2), $vbulletin->GPC['depth']);
	print_submit_row($vbphrase['find']);
}

// ############################# start gethost #########################
if ($_REQUEST['do'] == 'gethost')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'ip' => vB_Cleaner::TYPE_NOHTML,
	));

	print_form_header('admincp/', '');
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

	// Legacy Hook 'useradmin_gethost' Removed //

	print_table_footer();
}

// ############################# start referrers #########################
if ($_REQUEST['do'] == 'referrers')
{

	print_form_header('admincp/usertools', 'showreferrers');
	print_table_header($vbphrase['referrals_guser']);
	print_description_row($vbphrase['please_input_referral_dates']);
	print_time_row($vbphrase['start_date'], 'startdate', TIMENOW - 24 * 60 * 60 * 31, 1, 0, 'middle');
	print_time_row($vbphrase['end_date'], 'enddate', TIMENOW, 1, 0, 'middle');
	print_submit_row($vbphrase['find']);

}

// ############################# start show referrers #########################
if ($_POST['do'] == 'showreferrers')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'startdate' => vB_Cleaner::TYPE_ARRAY_INT,
		'enddate'   => vB_Cleaner::TYPE_ARRAY_INT
	));

	require_once(DIR . '/includes/functions_misc.php');
	$datequery = '';
	if ($vbulletin->GPC['startdate']['month'])
	{
		$datestartText = vbmktime(intval($vbulletin->GPC['startdate']['hour']), intval($vbulletin->GPC['startdate']['minute']), 0, intval($vbulletin->GPC['startdate']['month']), intval($vbulletin->GPC['startdate']['day']), intval($vbulletin->GPC['startdate']['year']));
		$datestart = vbdate($vbulletin->options['dateformat'] . ' ' .  $vbulletin->options['timeformat'], $datestartText);
	}
	else
	{
		$vbulletin->GPC['startdate'] = 0;
	}

	if ($vbulletin->GPC['enddate']['month'])
	{
		$dateendText = vbmktime(intval($vbulletin->GPC['enddate']['hour']), intval($vbulletin->GPC['enddate']['minute']), 0, intval($vbulletin->GPC['enddate']['month']), intval($vbulletin->GPC['enddate']['day']), intval($vbulletin->GPC['enddate']['year']));
		$dateend = vbdate($vbulletin->options['dateformat'] . ' ' . $vbulletin->options['timeformat'], $dateendText);
	}
	else
	{
		$vbulletin->GPC['enddate'] = 0;
	}

	if ($datestart OR $dateend)
	{
		$refperiod = construct_phrase($vbphrase['x_to_y'], $datestart, $dateend);
	}
	else
	{
		$refperiod = $vbphrase['all_time'];
	}

	try
	{
		$users = vB_Api::instanceInternal('user')->fetchReferrers($vbulletin->GPC['startdate'], $vbulletin->GPC['enddate']);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	if (!count($users))
	{
		print_stop_message2('no_referrals_matched_your_query', 'usertools', array('do'=>'referrers'));
	}
	else
	{
		print_form_header('admincp/', '');
		print_table_header($vbphrase['referrals_guser'] . ' - ' .	$refperiod);
		print_cells_row(array($vbphrase['username'], $vbphrase['total']), 1);
		foreach ($users AS $user)
		{
			print_cells_row(array("<a href=\"admincp/usertools.php?" . vB::getCurrentSession()->get('sessionurl') . "do=showreferrals&amp;referrerid=$user[userid]&amp;startdate=" . $vbulletin->GPC['startdate'] . "&amp;enddate=" . $vbulletin->GPC['enddate'] . "\">$user[username]</a>", vb_number_format($user['count'])));
		}
		print_table_footer();
	}
}

// ############################# start show referrals #########################
if ($_REQUEST['do'] == 'showreferrals')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'startdate'  => vB_Cleaner::TYPE_INT,
		'enddate'    => vB_Cleaner::TYPE_INT,
		'referrerid' => vB_Cleaner::TYPE_INT
	));

	if ($vbulletin->GPC['startdate'])
	{
		$datestart = vbdate($vbulletin->options['dateformat'] . ' ' . $vbulletin->options['timeformat'], $vbulletin->GPC['startdate']);
	}
	if ($vbulletin->GPC['enddate'])
	{
		$dateend = vbdate($vbulletin->options['dateformat'] . ' ' . $vbulletin->options['timeformat'], $vbulletin->GPC['enddate']);
	}

	if ($datestart OR $dateend)
	{
		$refperiod = construct_phrase($vbphrase['x_to_y'], $datestart, $dateend);
	}
	else
	{
		$refperiod = $vbphrase['all_time'];
	}

	try
	{
		$userInfo = vB_Api::instanceInternal('user')->fetchUserinfo($vbulletin->GPC['referrerid']);
	}
	catch (vB_Exception_Api $ex)
	{
		print_stop_message2($ex->getMessage());
	}

	$users = $assertor->getRows('userReferrals', array(
		'referrerid' => $vbulletin->GPC['referrerid'],
		'startdate' => $vbulletin->GPC['startdate'],
		'enddate' => $vbulletin->GPC['enddate']
	));

	print_form_header('admincp/', '');
	print_table_header(construct_phrase($vbphrase['referrals_for_x'], $userInfo['username']) . ' - ' .	$refperiod, 5);
	print_cells_row(array(
		$vbphrase['username'],
		$vbphrase['post_count'],
		$vbphrase['email'],
		$vbphrase['join_date'],
		$vbphrase['last_visit_guser']
	), 1);

	foreach ($users AS $user)
	{
		$cell = array();
		$cell[] = "<a href=\"admincp/user.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;u=$user[userid]\">$user[username]</a>";
		$cell[] = vb_number_format($user['posts']);
		$cell[] = "<a href=\"mailto:$user[email]\">$user[email]</a>";
		$cell[] = '<span class="smallfont">' . vbdate($vbulletin->options['dateformat'] . ', ' . $vbulletin->options['timeformat'], $user['joindate']) . '</span>';
		$cell[] = '<span class="smallfont">' . vbdate($vbulletin->options['dateformat'] . ', ' . $vbulletin->options['timeformat'], $user['lastvisit']) . '</span>';
		print_cells_row($cell);
	}
	print_table_footer();
}

// ########################################################################

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103411 $
|| #######################################################################
\*=========================================================================*/
