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

error_reporting(E_ALL & ~E_NOTICE);

function get_area_data($area)
{
	if ($area == 'AdminCP')
	{
		$data = array(
			'userscript' => 'usertools.php',
			'base' => 'admincp',
			'useraction' => 'edit',
		);
	}
	else
	{
		$data = array(
			'userscript' => 'user.php',
			'base' => 'modcp',
			'useraction' => 'viewuser',
		);
	}
	return $data;
}


// ###################### Start doipaddress #######################
function construct_ip_usage_table($ipaddress, $prevuserid, $depth = 1)
{
	return construct_ip_table_internal($ipaddress, $prevuserid, $depth, 'postipusers');
}

// ###################### Start construct_ip_register_table #######################
function construct_ip_register_table($ipaddress, $prevuserid, $depth = 1)
{
	return construct_ip_table_internal($ipaddress, $prevuserid, $depth, 'regipusers');
}

function construct_ip_table_internal($ipaddress, $prevuserid, $depth, $key)
{
	global $vbphrase;

	$depth--;

	//we play some games to handle the ModCP vs Admincp versions.
	$data = get_area_data(VB_AREA);
	$userscript = $data['userscript'];
	$base = $data['base'];
	$useraction = $data['useraction'];

	$users = vB_Api::instanceInternal('user')->searchUsersByIP($ipaddress, $depth);

	//this isn't right but let's go with it for now.  We probably need to fix searchUsersByIp
	$users = current($users[$key]);
	if ($users)
	{
		$retdata = '';
		foreach ($users AS $user)
		{
			$viewuserurl = htmlspecialchars($base . '/user.php?do=' . $useraction . '&u=' . $user['userid']);
			$resolveaddressurl = htmlspecialchars("$base/$userscript?do=gethost&ip=$user[ipaddress]");
			$usersearchurl = htmlspecialchars(vB5_Route::buildUrl('search|fullurl', array(), array('searchJSON' => json_encode(array('authorid' => $user['userid'])))));
			$otheripurl =  htmlspecialchars("$base/$userscript?do=doips&u=$user[userid]&hash=" . CP_SESSIONHASH);

			$retdata .= '<li>' .
				construct_link_code('<b>' . $user['username']. '</b>', $viewuserurl, false, '', false, false) . '&nbsp; ' .
				construct_link_code($user['ipaddress'], $resolveaddressurl, false, $vbphrase['resolve_address'], false, false) . '&nbsp; ' .
				construct_link_code($vbphrase['find_posts_by_user'], $usersearchurl, true, '', false, false) .
				construct_link_code($vbphrase['view_other_ip_addresses_for_this_user'], $otheripurl, false, '', false, false) .
			"</li>\n";

			if ($depth > 0)
			{
				$retdata .= construct_user_ip_table($user['userid'], $user['ipaddress'], $depth);
			}
		}
	}

	if (empty($retdata))
	{
		return '';
	}
	else
	{
		return '<ul>' . $retdata . '</ul>';
	}
}

// ###################### Start douseridip #######################
function construct_user_ip_table($userid, $previpaddress, $depth = 2)
{
	global $vbphrase;

	//we play some games to handle the ModCP vs Admincp versions.
	$data = get_area_data(VB_AREA);
	$userscript = $data['userscript'];
	$base = $data['base'];

	$depth --;
	$ips = vB_Api::instanceInternal('user')->searchIP($userid, $depth);

	$ips = current($ips['postips']);
	if($ips)
	{
		$retdata = '';
		foreach ($ips AS $ip)
		{
			$ipurl = htmlspecialchars("$base/$userscript?do=gethost&ip=$ip[ipaddress]");
			$moreusersurl = htmlspecialchars("$base/$userscript?do=doips&ipaddress=$ip[ipaddress]&hash=" . CP_SESSIONHASH);

			$retdata .= '<li>' .
				construct_link_code($ip['ipaddress'], $ipurl, false, $vbphrase['resolve_address'], false, false) . '&nbsp; ' .
				construct_link_code($vbphrase['find_more_users_with_this_ip_address'], $moreusersurl, false, '', false, false) .
			"</li>\n";

			if ($depth > 0)
			{
				$retdata .= construct_ip_usage_table($ip['ipaddress'], $userid, $depth);
			}
		}
	}

	if (empty($retdata))
	{
		return '';
	}
	else
	{
		return '<ul>' . $retdata . '</ul>';
	}
}

// ###################### Start makestylecode #######################
function construct_style_chooser($title, $name, $selvalue = -1, $extra = '')
{
	// returns a combo box containing a list of titles in the $tablename table.
	// allows specification of selected value in $selvalue
	global $vbulletin, $bgcounter;
	global $vbphrase;
	$tablename = 'style';

	//echo '<tr class="' . fetch_row_bgclass() . "\">\n<td><p>$title</p></td>\n<td><p><select name=\"$name\" size=\"1\" tabindex=\"1\" class=\"bginput\"" . iif($GLOBALS['debug'], " title=\"name=&quot;$name&quot;\"") . ">\n";
	$tableid = $tablename . "id";

	$result = $vbulletin->db->query_read("
		SELECT title, $tableid
		FROM " . TABLE_PREFIX . "$tablename
		WHERE userselect = 1
		ORDER BY title
	");

	$select = "<select name=\"$name\" size=\"1\" tabindex=\"1\" class=\"bginput\"" . iif($GLOBALS['debug'], " title=\"name=&quot;$name&quot;\"") . ">\n";
	$select .= "<option value=\"0\"" . iif($selvalue == 0, "selected=\"selected\"") . ">$vbphrase[use_forum_default]</option>\n";

	while ($currow = $vbulletin->db->fetch_array($result))
	{

		if ($selvalue == $currow["$tableid"])
		{
			$select .= "<option value=\"$currow[$tableid]\" selected=\"selected\">$currow[title]</option>\n";
		}
		else
		{
			$select .= "<option value=\"$currow[$tableid]\">$currow[title]</option>\n";
		}
	} // while

	if (!empty($extra))
	{
		if ($selvalue == -1)
		{
			$select .= "<option value=\"-1\" selected=\"selected\">$extra</option>\n";
		}
		else
		{
			$select .= "<option value=\"-1\">$extra</option>\n";
		}
	}

	$select .= "</select>\n";

	print_label_row($title, $select, '', 'top', $name);

	return 1;
}

// ###################### Start finduserhtml #######################
function print_user_search_rows($email = false)
{
	global $vbulletin, $vbphrase;

	print_label_row($vbphrase['username'], "
		<input type=\"text\" class=\"bginput\" name=\"user[username]\" tabindex=\"1\" size=\"35\"
		/><input type=\"image\" value=\"\" src=\"images/clear.gif\" width=\"1\" height=\"1\"
		/><input type=\"submit\" class=\"button\" value=\"$vbphrase[exact_match]\" tabindex=\"1\" name=\"user[exact]\" />
	", '', 'top', 'user[username]');

	if ($email)
	{
		global $iusergroupcache;
		$userarray = array('usergroupid' => 0, 'membergroupids' => '');
		$iusergroupcache = array();
		$usergroups = $vbulletin->db->query_read("SELECT usergroupid, title, (forumpermissions & " . $vbulletin->bf_ugp_forumpermissions['canview'] . ") AS CANVIEW FROM " . TABLE_PREFIX . "usergroup ORDER BY title");
		while ($usergroup = $vbulletin->db->fetch_array($usergroups))
		{
			if ($usergroup['CANVIEW'])
			{
				$userarray['membergroupids'] .= "$usergroup[usergroupid],";
			}
			$iusergroupcache["$usergroup[usergroupid]"] = $usergroup['title'];
		}
		unset($usergroup);
		$vbulletin->db->free_result($usergroups);

		print_checkbox_row($vbphrase['all_usergroups'], 'usergroup_all', 0, -1, $vbphrase['all_usergroups'], 'check_all_usergroups(this.form, this.checked);');
		print_membergroup_row($vbphrase['primary_usergroup'], 'user[usergroupid]', 2, $userarray);
		print_membergroup_row($vbphrase['additional_usergroups'], 'user[membergroup]', 2);
		print_yes_no_row($vbphrase['include_users_that_have_declined_email'], 'user[adminemail]', 0);
	}
	else
	{
		print_chooser_row($vbphrase['primary_usergroup'], 'user[usergroupid]', 'usergroup', -1, '-- ' . $vbphrase['all_usergroups'] . ' --');
		print_membergroup_row($vbphrase['additional_usergroups'], 'user[membergroup]', 2);
	}

	print_description_row('<div align="' . vB_Template_Runtime::fetchStyleVar('right') .'"><input type="submit" class="button" value=" ' . iif($email, $vbphrase['submit'], $vbphrase['find']) . ' " tabindex="1" /></div>');
	print_input_row($vbphrase['email'], 'user[email]');
	print_input_row($vbphrase['parent_email_address'], 'user[parentemail]');
	print_yes_no_other_row($vbphrase['coppa_user'], 'user[coppauser]', $vbphrase['either'], -1);
	print_input_row($vbphrase['home_page_guser'], 'user[homepage]');
	print_yes_no_other_row($vbphrase['facebook_connected'], 'user[facebook]', $vbphrase['either'], -1);
	print_input_row($vbphrase['icq_uin'], 'user[icq]');
	print_input_row($vbphrase['aim_screen_name'], 'user[aim]');
	print_input_row($vbphrase['yahoo_id'], 'user[yahoo]');
	print_input_row($vbphrase['msn_id'], 'user[msn]');
	print_input_row($vbphrase['skype_name'], 'user[skype]');
	print_input_row($vbphrase['signature'], 'user[signature]');
	print_input_row($vbphrase['user_title_guser'], 'user[usertitle]');
	print_input_row($vbphrase['join_date_is_after'] . $vbphrase['user_search_date_format_hint'], 'user[joindateafter]');
	print_input_row($vbphrase['join_date_is_before'] . $vbphrase['user_search_date_format_hint'], 'user[joindatebefore]');
	print_input_row($vbphrase['last_activity_is_after'] . $vbphrase['user_search_date_time_format_hint'], 'user[lastactivityafter]');
	print_input_row($vbphrase['last_activity_is_before'] . $vbphrase['user_search_date_time_format_hint'], 'user[lastactivitybefore]');
	print_input_row($vbphrase['last_post_is_after'] . $vbphrase['user_search_date_time_format_hint'], 'user[lastpostafter]');
	print_input_row($vbphrase['last_post_is_before'] . $vbphrase['user_search_date_time_format_hint'], 'user[lastpostbefore]');
	print_input_row($vbphrase['birthday_is_after'] . $vbphrase['user_search_date_format_hint'], 'user[birthdayafter]');
	print_input_row($vbphrase['birthday_is_before'] . $vbphrase['user_search_date_format_hint'], 'user[birthdaybefore]');
	print_input_row($vbphrase['posts_are_greater_than'], 'user[postslower]', '', 1, 7);
	print_input_row($vbphrase['posts_are_less_than'], 'user[postsupper]', '', 1, 7);
	print_input_row($vbphrase['reputation_is_greater_than'], 'user[reputationlower]', '', 1, 7);
	print_input_row($vbphrase['reputation_is_less_than'], 'user[reputationupper]', '', 1, 7);
	print_input_row($vbphrase['warnings_are_greater_than'], 'user[warningslower]', '', 1, 7);
	print_input_row($vbphrase['warnings_are_less_than'], 'user[warningsupper]', '', 1, 7);
	print_input_row($vbphrase['infractions_are_greater_than'], 'user[infractionslower]', '', 1, 7);
	print_input_row($vbphrase['infractions_are_less_than'], 'user[infractionsupper]', '', 1, 7);
	print_input_row($vbphrase['infraction_points_are_greater_than'], 'user[pointslower]', '', 1, 7);
	print_input_row($vbphrase['infraction_points_are_less_than'], 'user[pointsupper]', '', 1, 7);
	print_input_row($vbphrase['userid_is_greater_than'], 'user[useridlower]', '', 1, 7);
	print_input_row($vbphrase['userid_is_less_than'], 'user[useridupper]', '', 1, 7);
	print_input_row($vbphrase['registration_ip_address'], 'user[ipaddress]');
	// privacy consent search fields
	print_yes_no_other_row($vbphrase['admincp_privacyconsent_required_label'], 'user[eustatus_check]', $vbphrase['either'], -1);
	print_radio_row(
		$vbphrase['admincp_privacyconsent_status_label'],
		'user[privacyconsent]',
		array(
			'1' => $vbphrase['admincp_privacyconsent_provided'],
			'-1' => $vbphrase['admincp_privacyconsent_withdrawn'],
			'0' => $vbphrase['admincp_privacyconsent_unknown'],
			'any' => $vbphrase['admincp_privacyconsent_any'],
		),
		'any'
	);
	print_input_row($vbphrase['admincp_privacyconsentupdated_after'] . $vbphrase['user_search_date_format_hint'], 'user[privacyconsentupdatedafter]');
	print_input_row($vbphrase['admincp_privacyconsentupdated_before'] . $vbphrase['user_search_date_format_hint'], 'user[privacyconsentupdatedbefore]');

	// submit button
	print_description_row('<div align="' . vB_Template_Runtime::fetchStyleVar('right') .'"><input type="submit" class="button" value=" ' . iif($email, $vbphrase['submit'], $vbphrase['find']) . ' " tabindex="1" /></div>');

	$forms = array(
		0 => $vbphrase['edit_your_details'],
		1 => "$vbphrase[options]: $vbphrase[log_in] / $vbphrase[privacy]",
		2 => "$vbphrase[options]: $vbphrase[messaging] / $vbphrase[notification]",
		3 => "$vbphrase[options]: $vbphrase[thread_viewing]",
		4 => "$vbphrase[options]: $vbphrase[date] / $vbphrase[time]",
		5 => "$vbphrase[options]: $vbphrase[other_gprofilefield]",
	);

	$currentform = -1;

	print_table_header($vbphrase['user_profile_fields']);

	$profilefields = vB::getDbAssertor()->assertQuery('vBForum:fetchprofilefields');

	foreach ($profilefields as $profilefield)
	{
		if ($profilefield['form'] != $currentform)
		{
			print_description_row(construct_phrase($vbphrase['fields_from_form_x'], $forms["$profilefield[form]"]), false, 2, 'optiontitle');
			$currentform = $profilefield['form'];
		}

		print_profilefield_row('profile', $profilefield);
	}
	print_description_row('<div align="' . vB_Template_Runtime::fetchStyleVar('right') .'"><input type="submit" class="button" value=" ' . iif($email, $vbphrase['submit'], $vbphrase['find']) . ' " tabindex="1" /></div>');
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101107 $
|| #######################################################################
\*=========================================================================*/
