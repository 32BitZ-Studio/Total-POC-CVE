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
define('CVS_REVISION', '$RCSfile$ - $Revision: 100935 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $postinfo, $vbphrase, $userinfo;
$phrasegroups = array('user', 'cpuser', 'infraction', 'infractionlevel', 'banning');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminusers'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################
$vbulletin->input->clean_array_gpc('r', array(
	'infractionlevelid' => vB_Cleaner::TYPE_INT,
	'infractiongroupid' => vB_Cleaner::TYPE_UINT,
	'infractionbanid'   => vB_Cleaner::TYPE_UINT,
));
log_admin_action(!empty($vbulletin->GPC['infractionlevelid']) ? 'infractionlevel id = ' . $vbulletin->GPC['infractionlevelid'] : '');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

print_cp_header($vbphrase['user_infraction_manager_ginfraction']);

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'modify';
}


// ###################### Start add #######################
if ($_REQUEST['do'] == 'editlevel')
{
	$vb5_config = vB::getConfig();
	print_form_header('admincp/admininfraction', 'updatelevel');
	if (!empty($vbulletin->GPC['infractionlevelid']))
	{
		$infraction = vB::getDbAssertor()->getRow('infractionlevel', array('infractionlevelid' => $vbulletin->GPC['infractionlevelid']));
		$title = 'infractionlevel' . $infraction['infractionlevelid'] . '_title';

		$phrase = vB::getDbAssertor()->getRow('vBForum:phrase',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'languageid' => 0,
				'fieldname' => 'infractionlevel',
				'varname' => $title
			)
		);
		if ($phrase)
		{
			$infraction['title'] = $phrase['text'];
			$infraction['titlevarname'] = 'infractionlevel' . $infraction['infractionlevelid'] . '_title';
		}
		if ($infraction['period'] == 'N')
		{
			$infraction['expires'] = '';
		}

		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['user_infraction'], htmlspecialchars_uni($infraction['title']), $vbulletin->GPC['infractionlevelid']), 2, 0);
		construct_hidden_code('infractionlevelid', $vbulletin->GPC['infractionlevelid']);
	}
	else
	{
		$infraction = array(
			'warning'				=> 1,
			'expires'				=> 10,
			'period'				=> 'D',
			'points'				=> 1,
			'reputation_penalty'	=> 0,
			'extend'				=> 0,
		);
		print_table_header($vbphrase['add_new_user_infraction_level_gcpuser']);
	}

	if ($infraction['title'])
	{
		print_input_row($vbphrase['title'] . '<dfn>' . construct_link_code($vbphrase['translations'], "phrase.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&fieldname=infractionlevel&varname=$title&t=1", 1) . '</dfn>', 'title', $infraction['title']);
	}
	else
	{
		print_input_row($vbphrase['title'], 'title');
	}

	$periods = array(
		'H' => $vbphrase['hours'],
		'D' => $vbphrase['days'],
		'M' => $vbphrase['months'],
		'N' => $vbphrase['never'],
	);
	$input = '<input type="text" class="bginput" name="expires" size="5" dir="ltr" tabindex="1" value="' . $infraction['expires'] . '"' . ($vb5_config['Misc']['debug'] ? ' title="name=&quot;expires&quot;"' : '') . " />\r\n";
	$input .= '<select name="period" class="bginput" tabindex="1"' . ($vb5_config['Misc']['debug'] ? ' title="name=&quot;period&quot;"' : '') . '>' . construct_select_options($periods, $infraction['period']) . '</select>';

	print_label_row($vbphrase['expires_ginfraction'], $input, '', 'top', 'expires');
	print_input_row($vbphrase['points_ginfraction'], 'points', $infraction['points'], true, 5);
	print_input_row($vbphrase['reputation_penalty'], 'reputation_penalty', $infraction['reputation_penalty'], true, 5);
	print_yes_no_row($vbphrase['warning_ginfraction'], 'warning', $infraction['warning']);
	print_yes_no_row($vbphrase['extend'], 'extend', $infraction['extend']);

	print_submit_row($vbphrase['save']);
}


// ###################### Start do update #######################
if ($_POST['do'] == 'updatelevel')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'title'					=> vB_Cleaner::TYPE_STR,
		'points'				=> vB_Cleaner::TYPE_UINT,
		'reputation_penalty'	=> vB_Cleaner::TYPE_UINT,
		'expires'				=> vB_Cleaner::TYPE_UINT,
		'period'				=> vB_Cleaner::TYPE_NOHTML,
		'warning'				=> vB_Cleaner::TYPE_BOOL,
		'extend'				=> vB_Cleaner::TYPE_BOOL,
	));

	if (empty($vbulletin->GPC['title']) OR (empty($vbulletin->GPC['expires']) AND $vbulletin->GPC['period'] != 'N'))
	{
		print_stop_message2('please_complete_required_fields');
	}

	if (empty($vbulletin->GPC['infractionlevelid']))
	{
		$vbulletin->GPC['infractionlevelid'] = vB::getDbAssertor()->assertQuery('infractionlevel',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT, 'points' => 0)
		);
	}

	if ($vbulletin->GPC['period'] == 'N')
	{
		$vbulletin->GPC['expires'] = 0;
	}

	vB::getDbAssertor()->assertQuery('infractionlevel',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'points' => $vbulletin->GPC['points'],
			'reputation_penalty' => $vbulletin->GPC['reputation_penalty'],
			'expires' => $vbulletin->GPC['expires'],
			'period' => $vbulletin->GPC['period'],
			'warning' => $vbulletin->GPC['warning'],
			'extend' => $vbulletin->GPC['extend'],
			vB_dB_Query::CONDITIONS_KEY => array(
				'infractionlevelid' => $vbulletin->GPC['infractionlevelid']
			)
		)
	);

	vB::getDbAssertor()->assertQuery('replaceIntoPhrases',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'languageid' => 0,
			'fieldname' => 'infractionlevel',
			'varname' => 'infractionlevel' . $vbulletin->GPC['infractionlevelid'] . '_title',
			'text' => $vbulletin->GPC['title'],
			'product' => 'vbulletin',
			'enteredBy' => $vbulletin->userinfo['username'],
			'dateline' => TIMENOW,
			'version' => $vbulletin->options['templateversion']
		)
	);

	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language();

	print_stop_message2('saved_infraction_level_successfully', 'admininfraction', array('do'=>'modify'));
}


// ###################### Start Remove #######################
if ($_REQUEST['do'] == 'removelevel')
{
	print_form_header('admincp/admininfraction', 'killlevel');
	construct_hidden_code('infractionlevelid', $vbulletin->GPC['infractionlevelid']);
	print_table_header(construct_phrase($vbphrase['confirm_deletion_x'], htmlspecialchars_uni($vbphrase['infractionlevel' . $vbulletin->GPC['infractionlevelid'] . '_title'])));
	print_description_row($vbphrase['are_you_sure_you_want_to_delete_this_infraction_level']);
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);

}


// ###################### Start Kill #######################
if ($_POST['do'] == 'killlevel')
{
	$phrase = vB::getDbAssertor()->getRow('vBForum:phrase',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'text', 'value' => '', 'operator' => vB_dB_Query::OPERATOR_NE),
				array('field' => 'fieldname', 'value' => 'infractionlevel', 'operator' => vB_dB_Query::OPERATOR_NE),
				array('field' => 'varname', 'value' => 'infractionlevel' . $vbulletin->GPC['infractionlevelid'] . '_title', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'languageid', 'value' => array(0, $vbulletin->options['languageid']), 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		),
		array('field' => 'languageid', 'direction' => vB_dB_Query::SORT_ASC)
	);
	if ($phrase)
	{
		vB::getDbAssertor()->assertQuery('infraction',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'customreason' => $phrase['text'],
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'infractionlevelid', 'value' => $vbulletin->GPC['infractionlevelid'], 'operator' => vB_dB_Query::OPERATOR_EQ)
				)
			)
		);
	}

	vB::getDbAssertor()->assertQuery('infractionlevel',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'infractionlevelid' => $vbulletin->GPC['infractionlevelid'])
	);
	vB::getDbAssertor()->assertQuery('phrase',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'fieldname' => 'infractionlevel', 'varname' => 'infractionlevel' . $vbulletin->GPC['infractionlevelid'] . '_title')
	);

	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language();

	print_stop_message2('deleted_infraction_level_successfully', 'admininfraction', array('do'=>'modify'));
}


// ###################### Start modify #######################
if ($_REQUEST['do'] == 'modify')
{
	$infractions = vB::getDbAssertor()->getRows('infractionlevel',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT),
		array('field' => 'points', 'direction' => vB_dB_Query::SORT_ASC),
		'infractionlevelid'
	);

	?>
	<script type="text/javascript">
	function js_usergroup_jump(id, obj)
	{
		var task = obj.options[obj.selectedIndex].value;
		var page =  "admincp/admininfraction.php?<?php echo vB::getCurrentSession()->get('sessionurl_js'); ?>";
		switch (task)
		{
			case 'editlevel': page += "do=editlevel&infractionlevelid=" + id; break;
			case 'killlevel': page += "do=removelevel&infractionlevelid=" + id; break;
			case 'editgroup': page += "do=editgroup&infractiongroupid=" + id; break;
			case 'killgroup': page += "do=removegroup&infractiongroupid=" + id; break;
			case 'editban': page += "do=editbangroup&infractionbanid=" + id; break;
			case 'killban': page += "do=removebangroup&infractionbanid=" + id; break;
			default: return false; break;
		}

		vBRedirect(page);
	}
	</script>
	<?php

	$options = array(
		'editlevel' => $vbphrase['edit'],
		'killlevel' => $vbphrase['delete'],
	);

	print_form_header('admincp/admininfraction', 'editlevel');
	print_table_header($vbphrase['user_infraction_levels'], 7);

	print_cells_row(array($vbphrase['title'], $vbphrase['points_ginfraction'], $vbphrase['reputation_penalty'], $vbphrase['expires_ginfraction'], $vbphrase['warning_ginfraction'], $vbphrase['extend'], $vbphrase['controls']), 1);

	$missing_phrases = array();
	foreach ($infractions as $infractionlevelid => $infraction)
	{
		$phrase_title = 'infractionlevel' . $infractionlevelid . '_title';
		if (empty($vbphrase[$phrase_title]))
		{
			$missing_phrases[] = $phrase_title;
		}
	}

	if (!empty($missing_phrases))
	{
		$vbphrase += vB_API::instanceInternal('phrase')->fetch($missing_phrases);
	}

	foreach ($infractions AS $infraction)
	{
		switch($infraction['period'])
		{
			case 'H':
				$period = 'x_hours_ginfraction';
				break;
			case 'D':
				$period = 'x_days';
				break;
			case 'M':
				$period = 'x_months';
				break;
			case 'N':
				$period = 'never';
				break;
		}
		$expires = construct_phrase($vbphrase["$period"], $infraction['expires']);
		print_cells_row(array(
			'<b>' . htmlspecialchars_uni($vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title']) . '</b>',
			$infraction['points'],
			$infraction['reputation_penalty'],
			$expires,
			(empty($infraction['warning']) ? $vbphrase['no'] : $vbphrase['yes']),
			(empty($infraction['extend']) ? $vbphrase['no'] : $vbphrase['yes']),
			"\n\t<select name=\"i$infraction[infractionlevelid]\" onchange=\"js_usergroup_jump($infraction[infractionlevelid], this);\" class=\"bginput\">\n" . construct_select_options($options) . "\t</select>\n\t<input type=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_usergroup_jump($infraction[infractionlevelid], this.form.i$infraction[infractionlevelid]);\" />\n\t"
		));
	}

	print_submit_row($vbphrase['add_new_user_infraction_level_gcpuser'], 0, 7);

	$infractions = vB::getDbAssertor()->assertQuery('infractiongroup',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT),
		array('field' => 'pointlevel', 'direction' => vB_dB_Query::SORT_ASC)
	);

	$options = array(
		'editgroup' => $vbphrase['edit'],
		'killgroup' => $vbphrase['delete'],
	);

	print_form_header('admincp/admininfraction', 'editgroup');
	print_table_header($vbphrase['user_infraction_groups'], 5);

	print_cells_row(array($vbphrase['primary_usergroup'], $vbphrase['override_usergroup'], $vbphrase['override_display'], $vbphrase['points_ginfraction'], $vbphrase['controls']), 1);

	if ($infractions AND $infractions->valid())
	{
		foreach($infractions AS $infraction)
		{
			print_cells_row(array(
				($infraction['usergroupid'] == -1) ? $vbphrase['all_usergroups'] : "<a href=\"admincp/usergroup.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;usergroupid=$infraction[usergroupid]\" />" . $vbulletin->usergroupcache["$infraction[usergroupid]"]['title'] . "</a>",
				"<a href=\"admincp/usergroup.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;usergroupid=$infraction[orusergroupid]\" />" . $vbulletin->usergroupcache["$infraction[orusergroupid]"]['title'] . "</a>",
				($infraction['override'] ? $vbphrase['yes'] : $vbphrase['no']),
				$infraction['pointlevel'],
				"\n\t<select name=\"i$infraction[infractiongroupid]\" onchange=\"js_usergroup_jump($infraction[infractiongroupid], this);\" class=\"bginput\">\n" . construct_select_options($options) . "\t</select>\n\t<input type=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_usergroup_jump($infraction[infractiongroupid], this.form.i$infraction[infractiongroupid]);\" />\n\t"
			));
		}
	}

	print_submit_row($vbphrase['add_new_user_infraction_group_ginfraction'], 0, 6);

	$options = array(
		'editban' => $vbphrase['edit'],
		'killban' => $vbphrase['delete'],
	);

	print_form_header('admincp/admininfraction', 'editbangroup');
	print_table_header($vbphrase['automatic_ban'], 6);
	print_cells_row(
		array(
			$vbphrase['primary_usergroup'],
			$vbphrase['ban_usergroup'],
			$vbphrase['amount_ginfraction'],
			$vbphrase['method_ginfraction'],
			$vbphrase['ban_period'],
			$vbphrase['controls']
		),
		1
	);

	$infractions = vB::getDbAssertor()->assertQuery('infractionban',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT),
		array(
			'field' => array('method', 'amount'),
			'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC)
		)
	);
	if ($infractions AND $infractions->valid())
	{
		foreach ($infractions AS $infraction)
		{
			switch($infraction['period'])
			{
				case 'D_1':   $period = construct_phrase($vbphrase['x_days'], 1); break;
				case 'D_2':   $period = construct_phrase($vbphrase['x_days'], 2); break;
				case 'D_3':   $period = construct_phrase($vbphrase['x_days'], 3); break;
				case 'D_4':   $period = construct_phrase($vbphrase['x_days'], 4); break;
				case 'D_5':   $period = construct_phrase($vbphrase['x_days'], 5); break;
				case 'D_6':   $period = construct_phrase($vbphrase['x_days'], 6); break;
				case 'D_7':   $period = construct_phrase($vbphrase['x_days'], 7); break;
				case 'D_10':  $period = construct_phrase($vbphrase['x_days'], 10); break;
				case 'D_14':  $period = construct_phrase($vbphrase['x_weeks'], 2); break;
				case 'D_21':  $period = construct_phrase($vbphrase['x_weeks'], 3); break;
				case 'M_1':   $period = construct_phrase($vbphrase['x_months'], 1); break;
				case 'M_2':   $period = construct_phrase($vbphrase['x_months'], 2); break;
				case 'M_3':   $period = construct_phrase($vbphrase['x_months'], 3); break;
				case 'M_4':   $period = construct_phrase($vbphrase['x_months'], 4); break;
				case 'M_5':   $period = construct_phrase($vbphrase['x_months'], 5); break;
				case 'M_6':   $period = construct_phrase($vbphrase['x_months'], 6); break;
				case 'Y_1':   $period = construct_phrase($vbphrase['x_years'], 1); break;
				case 'Y_2':   $period = construct_phrase($vbphrase['x_years'], 2); break;
				case 'PERMA': $period = $vbphrase['permanent']; break;
				default: $period = '';
			}

			if($infraction['usergroupid'] != -1)
			{
				$usergroup = "<a href=\"admincp/usergroup.php?do=edit&amp;usergroupid=$infraction[usergroupid]\" />" .
				 	$vbulletin->usergroupcache["$infraction[usergroupid]"]['title'] . "</a>";
			}
			else
			{
				$usergroup = $vbphrase['all_usergroups'];
			}

			$bangroup = "<a href=\"admincp/usergroup.php?do=edit&amp;usergroupid=$infraction[banusergroupid]\" />" .
				$vbulletin->usergroupcache["$infraction[banusergroupid]"]['title'] . "</a>";

			if ($infraction['method'] == 'points')
			{
				$method = $vbphrase['points_ginfraction'];
			}
			else
			{
				$method = $vbphrase[$infraction['method']];
			}

			print_cells_row(array(
				$usergroup,
				$bangroup,
				$infraction['amount'],
				$method,
				$period,
				"\n\t<select name=\"i$infraction[infractionbanid]\" onchange=\"js_usergroup_jump($infraction[infractionbanid], this);\" class=\"bginput\">\n" . construct_select_options($options) . "\t</select>\n\t<input type=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_usergroup_jump($infraction[infractionbanid], this.form.i$infraction[infractionbanid]);\" />\n\t",
			));
		}
	}
	print_submit_row($vbphrase['add_new_automatic_ban_ginfraction'], 0, 6);

}


// ###################### Start Delete #######################
if ($_POST['do'] == 'killinfraction')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'nodeid' => vB_Cleaner::TYPE_UINT,
		'pagenumber'   => vB_Cleaner::TYPE_UINT,
		'orderby'      => vB_Cleaner::TYPE_NOHTML,
		'perpage'      => vB_Cleaner::TYPE_UINT,
		'status'       => vB_Cleaner::TYPE_NOHTML,
		'userid'       => vB_Cleaner::TYPE_UINT,
		'whoadded'     => vB_Cleaner::TYPE_UINT,
		'startstamp'   => vB_Cleaner::TYPE_UINT,
		'endstamp'     => vB_Cleaner::TYPE_UINT,
	));

	try
	{
		vB_Api::instanceInternal('Content_Infraction')->delete($vbulletin->GPC['nodeid']);
	}
	catch (vB_Exception_Api $e)
	{
		$errors = $e->get_errors();
		if (!empty($errors))
		{
			$error = array_shift($errors);
			print_stop_message2($error[0]);
		}
		print_stop_message2('error');
	}

	$args = array(
		'do'=>'modify',
		'status' => $vbulletin->GPC['status'],
		'u=' => $vbulletin->GPC['userid'],
		'whoadded' => $vbulletin->GPC['whoadded'],
		'startstamp' => $vbulletin->GPC['startstamp'],
		'endstamp' => $vbulletin->GPC['endstamp'],
		'pp' => $vbulletin->GPC['perpage'],
		'page' => $vbulletin->GPC['pagenumber'],
		'orderby' => $vbulletin->GPC['orderby'],
		'infractionlevelid' => $vbulletin->GPC['infractionlevelid']
	);

	print_stop_message2('deleted_infraction_successfully','admininfraction', $args);
}


// ###################### Start Delete #######################
if ($_REQUEST['do'] == 'deleteinfraction')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid' => vB_Cleaner::TYPE_UINT,
		'pagenumber'   => vB_Cleaner::TYPE_UINT,
		'orderby'      => vB_Cleaner::TYPE_NOHTML,
		'perpage'      => vB_Cleaner::TYPE_UINT,
		'status'       => vB_Cleaner::TYPE_NOHTML,
		'userid'       => vB_Cleaner::TYPE_UINT,
		'whoadded'     => vB_Cleaner::TYPE_UINT,
		'startstamp'   => vB_Cleaner::TYPE_UINT,
		'endstamp'     => vB_Cleaner::TYPE_UINT,
	));

	print_delete_confirmation('infraction', $vbulletin->GPC['nodeid'], 'admininfraction', 'killinfraction', '', array(
		'page'              => $vbulletin->GPC['pagenumber'],
		'orderby'           => $vbulletin->GPC['orderby'],
		'pp'                => $vbulletin->GPC['perpage'],
		'status'            => $vbulletin->GPC['status'],
		'u'                 => $vbulletin->GPC['userid'],
		'whoadded'          => $vbulletin->GPC['whoadded'],
		'startstamp'        => $vbulletin->GPC['startstamp'],
		'endstamp'          => $vbulletin->GPC['endstamp'],
		'infractionlevelid' => $vbulletin->GPC['infractionlevelid'],
	), '', 'title', 'nodeid');
}


// ###################### Start Reversal #######################
if ($_POST['do'] == 'doreverse')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid'       => vB_Cleaner::TYPE_UINT,
		'reason'       => vB_Cleaner::TYPE_STR,
		'pagenumber'   => vB_Cleaner::TYPE_UINT,
		'orderby'      => vB_Cleaner::TYPE_NOHTML,
		'perpage'      => vB_Cleaner::TYPE_UINT,
		'status'       => vB_Cleaner::TYPE_NOHTML,
		'userid'       => vB_Cleaner::TYPE_UINT,
		'whoadded'     => vB_Cleaner::TYPE_UINT,
		'startstamp'   => vB_Cleaner::TYPE_UINT,
		'endstamp'     => vB_Cleaner::TYPE_UINT,
	));

	$infractioninfo = vB::getDbAssertor()->getRow('infraction', array('nodeid' => $vbulletin->GPC['nodeid']));
	if ($infractioninfo)
	{
		if ($infractioninfo['action'] == 2)
		{
			print_stop_message2('infraction_already_reversed');
		}

		vB_Api::instanceInternal('Content_Infraction')->reverseInfraction($vbulletin->GPC['nodeid'], $vbulletin->GPC['reason']);

		$args = array(
			'do' => 'dolist',
			'status' => $vbulletin->GPC['status'],
			'u' => $vbulletin->GPC['userid'],
			'whoadded' => $vbulletin->GPC['whoadded'],
			'startstamp' => $vbulletin->GPC['startstamp'],
			'endstamp' => $vbulletin->GPC['endstamp'],
			'pp' => $vbulletin->GPC['perpage'],
			'page' => $vbulletin->GPC['pagenumber'],
			'orderby' => $vbulletin->GPC['orderby'],
			'infractionlevelid' => $vbulletin->GPC['infractionlevelid']
		);

		print_stop_message2('reversed_infraction_successfully', 'admininfraction', $args);
	}
	else
	{
		print_stop_message2('no_matches_found_gcpuser', 'admininfraction', $args);
	}
}


// ###################### Start Reversal #######################
if ($_REQUEST['do'] == 'reverse')
{
	$vbulletin->input->clean_array_gpc('r', array(
		//'infractionid' => vB_Cleaner::TYPE_UINT,
		'nodeid' => vB_Cleaner::TYPE_UINT,
		'pagenumber'   => vB_Cleaner::TYPE_UINT,
		'orderby'      => vB_Cleaner::TYPE_NOHTML,
		'perpage'      => vB_Cleaner::TYPE_UINT,
		'status'       => vB_Cleaner::TYPE_NOHTML,
		'userid'       => vB_Cleaner::TYPE_UINT,
		'whoadded'     => vB_Cleaner::TYPE_UINT,
		'startstamp'   => vB_Cleaner::TYPE_UINT,
		'endstamp'     => vB_Cleaner::TYPE_UINT
	));

	$infraction = vB::getDbAssertor()->getRow('fetchInfractionsByUser',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $vbulletin->GPC['nodeid'])
	);
	if ($infraction)
	{
		if ($infraction['action'] == 2)
		{
			print_stop_message2('infraction_already_reversed');
		}

		print_form_header('admincp/admininfraction', 'doreverse');
		print_table_header($vbphrase['reverse_infraction']);
		print_label_row($vbphrase['user_name'], $infraction['username']);
		print_label_row($vbphrase['left_by'], $infraction['whoadded_username']);

		$title = !empty($vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title']) ? $vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title'] : (!empty($infraction['customreason']) ? unhtmlspecialchars($infraction['customreason']) : $vbphrase['n_a']);

		if ($infraction['points'])
		{
			print_label_row(($infraction['action'] == 0) ? construct_phrase($vbphrase['active_infraction_x_points'], $infraction['points']) : construct_phrase($vbphrase['expired_infraction_x_points'], $infraction['points']), htmlspecialchars_uni($title));
		}
		else
		{
			print_label_row(($infraction['action'] == 0) ? $vbphrase['active_warning'] : $vbphrase['expired_warning'], htmlspecialchars_uni($title));
		}

		if ($infraction['reputation_penalty'])
		{
			print_label_row($vbphrase['reputation_penalty'], $infraction['reputation_penalty']);
		}

		if (!empty($infraction['reason']))
		{
			print_label_row($vbphrase['infraction_reason'], $infraction['reason']);
		}

		print_textarea_row($vbphrase['reversal_reason'] . '<dfn>' . construct_phrase($vbphrase['maximum_chars_x'], 255) . '</dfn>', 'reason', '', 0, 40, 2);
		construct_hidden_code('nodeid', $vbulletin->GPC['nodeid']);
		construct_hidden_code('pp', $vbulletin->GPC['perpage']);
		construct_hidden_code('page', $vbulletin->GPC['pagenumber']);
		construct_hidden_code('orderby', $vbulletin->GPC['orderby']);
		construct_hidden_code('status', $vbulletin->GPC['status']);
		construct_hidden_code('userid', $vbulletin->GPC['userid']);
		construct_hidden_code('whoadded', $vbulletin->GPC['whoadded']);
		construct_hidden_code('startstamp', $vbulletin->GPC['startstamp']);
		construct_hidden_code('endstamp', $vbulletin->GPC['endstamp']);
		construct_hidden_code('infractionlevelid', $vbulletin->GPC['infractionlevelid']);
		print_submit_row();
	}
	else
	{
		print_stop_message2('no_matches_found_gcpuser');
	}
}


// ###################### Start Details #######################
if ($_REQUEST['do'] == 'details')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid' => vB_Cleaner::TYPE_UINT
	));

	$infraction = vB::getDbAssertor()->getRow('fetchInfractionsByUser2',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $vbulletin->GPC['nodeid'])
	);
	if ($infraction)
	{
		print_form_header('admincp/', '');
		print_table_header($vbphrase['view_infraction']);
		print_label_row($vbphrase['user_name'], $infraction['username']);
		print_label_row($vbphrase['left_by'], $infraction['whoadded_username']);
		print_label_row($vbphrase['date'], vbdate($vbulletin->options['logdateformat'], $infraction['publishdate']));

		$title = !empty($vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title']) ? $vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title'] : (!empty($infraction['customreason']) ? unhtmlspecialchars($infraction['customreason']) : $vbphrase['n_a']);

		if ($infraction['points'])
		{
			print_label_row(($infraction['action'] == 0) ? construct_phrase($vbphrase['active_infraction_x_points'], $infraction['points']) : construct_phrase($vbphrase['expired_infraction_x_points'], $infraction['points']), htmlspecialchars_uni($title));
		}
		else
		{
			print_label_row(($infraction['action'] == 0) ? $vbphrase['active_warning'] : $vbphrase['expired_warning'], $title);
		}

		if ($infraction['reputation_penalty'])
		{
			print_label_row($vbphrase['reputation_penalty'], $infraction['reputation_penalty']);
		}

		if ($infraction['action'] == 0)
		{
			print_label_row($vbphrase['expires_ginfraction'], ($infraction['expires'] ? vbdate($vbulletin->options['logdateformat'], $infraction['expires']) : $vbphrase['never']));
		}
		else if ($infraction['action'] == 1)
		{
			print_label_row($vbphrase['expired_ginfraction'], vbdate($vbulletin->options['logdateformat'], $infraction['actiondateline']));
		}

		if (!empty($infraction['note']))
		{
			print_label_row($vbphrase['administrative_note'], $infraction['note']);
		}

		if ($infraction['action'] == 2)
		{
			print_table_break();
			print_table_header($vbphrase['reversed_ginfraction']);
			print_label_row($vbphrase['username'], $infraction['action_username']);
			print_label_row($vbphrase['date'], vbdate($vbulletin->options['logdateformat'], $infraction['actiondateline']));
			if ($infraction['actionreason'])
			{
				print_label_row($vbphrase['reversal_reason'], $infraction['actionreason']);
			}
		}

		print_table_footer();
	}
	else
	{
		print_stop_message2('no_matches_found_gcpuser');
	}
}


// ###################### Start List #######################
if ($_REQUEST['do'] == 'list')
{
	$infractions = vB::getDbAssertor()->assertQuery('fetchCountInfractionsByInfractionLvl');
	if ($infractions AND $infractions->valid())
	{
		print_form_header('admincp/', '');
		print_table_header($vbphrase['infraction_statistics']);
		print_cells_row(array($vbphrase['title'], $vbphrase['infractions']), 1);

		foreach ($infractions AS $infraction)
		{
			if ($infraction['infractionlevelid'])
			{
				$phrasename = 'infractionlevel' . $infraction['infractionlevelid'] . '_title';
				$title = (!empty($vbphrase[$phrasename]) ? $vbphrase[$phrasename] : $vbphrase['n_a']);
			}
			else
			{
				$title = '<em>' . $vbphrase['custom_infraction'] . '</em>';
			}

			$url = "admininfraction.php?do=dolist&infractionlevelid=$infraction[infractionlevelid]&startstamp=1&endstamp=" . TIMENOW;
			$link = construct_link_code($infraction['count'], $url, false, '', true);
			print_label_row($title, $link);
		}

		print_table_footer();
	}
}


// ###################### Start List and Dolist #######################
if ($_REQUEST['do'] == 'list' OR $_REQUEST['do'] == 'dolist')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'leftby'            => vB_Cleaner::TYPE_NOHTML,
		'leftfor'           => vB_Cleaner::TYPE_NOHTML,
		'userid'            => vB_Cleaner::TYPE_UINT,
		'whoadded'          => vB_Cleaner::TYPE_UINT,
		'pagenumber'        => vB_Cleaner::TYPE_UINT,
		'perpage'           => vB_Cleaner::TYPE_UINT,
		'orderby'           => vB_Cleaner::TYPE_NOHTML,
		'start'             => vB_Cleaner::TYPE_ARRAY_UINT,
		'end'               => vB_Cleaner::TYPE_ARRAY_UINT,
		'startstamp'        => vB_Cleaner::TYPE_UINT,
		'endstamp'          => vB_Cleaner::TYPE_UINT,
		'status'            => vB_Cleaner::TYPE_NOHTML,
		'infractionlevelid' => vB_Cleaner::TYPE_INT,
	));

	if($vbulletin->GPC['startstamp'])
	{
		$vbulletin->GPC['start'] = $vbulletin->GPC['startstamp'];
	}

	if($vbulletin->GPC['endstamp'])
	{
		$vbulletin->GPC['end'] = $vbulletin->GPC['endstamp'];
	}

	$userApi = vB_Api::instance('user');

	//if we don't get a valid user then just use no user value
	//this might not be ideal behavior, but it follows the prior logic
	if($vbulletin->GPC['whoadded'])
	{
		$whoaddedinfo = $userApi->fetchUserinfo($vbulletin->GPC['whoadded']);
		if (empty($whoaddedinfo['errors']))
		{
			$vbulletin->GPC['leftby'] = $whoaddedinfo['username'];
		}
		else
		{
			$vbulletin->GPC['whoadded'] = 0;
		}
	}

	if($vbulletin->GPC['userid'])
	{
		$userinfo = $userApi->fetchUserinfo($vbulletin->GPC['userid']);
		if (empty($userinfo['errors']))
		{
			$vbulletin->GPC['leftfor'] = $userinfo['username'];
		}
		else
		{
			$vbulletin->GPC['userid'] = 0;
		}
	}

	// Default View Values
	if (!$vbulletin->GPC['start'])
	{
		$vbulletin->GPC['start'] = TIMENOW - 3600 * 24 * 30;
	}

	if (!$vbulletin->GPC['end'])
	{
		$vbulletin->GPC['end'] = TIMENOW;
	}

	if (!$vbulletin->GPC['status'])
	{
		$vbulletin->GPC['status'] = 'all';
	}

	$statusoptions = array(
		'all'      => $vbphrase['all_guser'],
		'active'   => $vbphrase['active_ginfraction'],
		'expired'  => $vbphrase['expired_ginfraction'],
		'reversed' => $vbphrase['reversed_ginfraction'],
	);

	$infractionlevels = array (-1 => $vbphrase['all_guser']);

	$infractions = vB::getDbAssertor()->assertQuery('infractionlevel',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT),
		array('field' => 'points', 'direction' => vB_dB_Query::SORT_ASC)
	);
	if ($infractions AND $infractions->valid())
	{
		foreach ($infractions AS $infraction)
		{
			$infractionlevels["$infraction[infractionlevelid]"] = htmlspecialchars_uni($vbphrase['infractionlevel' . $infraction['infractionlevelid'] . '_title']);
		}
	}
	$infractionlevels[0] = $vbphrase['custom_infraction'];

	print_form_header('admincp/admininfraction', 'dolist');
	print_table_header($vbphrase['view_infractions_ginfraction']);
	print_input_row($vbphrase['leftfor_infraction'], 'leftfor', $vbulletin->GPC['leftfor'], 0);
	print_input_row($vbphrase['leftby_infraction'], 'leftby', $vbulletin->GPC['leftby'], 0);
	print_select_row($vbphrase['status_ginfraction'], 'status', $statusoptions, $vbulletin->GPC['status']);
	print_select_row($vbphrase['infraction_level'], 'infractionlevelid', $infractionlevels, $_REQUEST['do'] == 'list' ? -1 : $vbulletin->GPC['infractionlevelid']);
	print_time_row($vbphrase['start_date'], 'start', $vbulletin->GPC['start'], false);
	print_time_row($vbphrase['end_date'], 'end', $vbulletin->GPC['end'], false);
	print_submit_row($vbphrase['go']);
}


// ###################### Start list #######################
if ($_REQUEST['do'] == 'dolist')
{
	require_once(DIR . '/includes/functions_misc.php');
	if ($vbulletin->GPC['startstamp'])
	{
		$vbulletin->GPC['start'] = $vbulletin->GPC['startstamp'];
	}
	else
	{
		$vbulletin->GPC['start'] = vbmktime(0, 0, 0, $vbulletin->GPC['start']['month'], $vbulletin->GPC['start']['day'], $vbulletin->GPC['start']['year']);
	}

	if ($vbulletin->GPC['endstamp'])
	{
		$vbulletin->GPC['end'] = $vbulletin->GPC['endstamp'];
	}
	else
	{
		$vbulletin->GPC['end'] = vbmktime(23, 59, 59, $vbulletin->GPC['end']['month'], $vbulletin->GPC['end']['day'], $vbulletin->GPC['end']['year']);
	}

	if ($vbulletin->GPC['start'] >= $vbulletin->GPC['end'])
	{
		print_stop_message2('start_date_after_end_gerror', null, array(), '');
	}

	if ($vbulletin->GPC['leftby'])
	{
		if (!$leftby_user = vB_Api::instanceInternal("User")->fetchByUsername($vbulletin->GPC['leftby'], array(vB_Api_User::USERINFO_AVATAR)))
		{
			print_stop_message2(array('could_not_find_user_x', $vbulletin->GPC['leftby']), NULL, array(),'');
		}
		$vbulletin->GPC['whoadded'] = $leftby_user['userid'];
	}

	if ($vbulletin->GPC['leftfor'])
	{
		if (!$leftfor_user = vB_Api::instanceInternal("User")->fetchByUsername($vbulletin->GPC['leftfor'], array(vB_Api_User::USERINFO_AVATAR)))
		{
			print_stop_message2(array('could_not_find_user_x', $vbulletin->GPC['leftfor']), NULL, array(),'');
		}
		$vbulletin->GPC['userid'] = $leftfor_user['userid'];
	}

	if (empty($vbulletin->GPC['perpage']))
	{
		$vbulletin->GPC['perpage'] = 15;
	}

	$counter = vB::getDbAssertor()->getRow('fetchCountInfractionsByCond', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'status' => $vbulletin->GPC['status'],
			'whoadded' => $vbulletin->GPC['whoadded'],
			'userid' => $vbulletin->GPC['userid'],
			'start' => $vbulletin->GPC['start'],
			'end' => $vbulletin->GPC['end'],
		'infractionlevelid' => $vbulletin->GPC['infractionlevelid'],
	));

	if (!($totalinf = $counter['total']))
	{
		print_stop_message2('no_matches_found_gcpuser',NULL, array(),'');
	}

	sanitize_pageresults($totalinf, $vbulletin->GPC['pagenumber'], $vbulletin->GPC['perpage']);
	$startat = ($vbulletin->GPC['pagenumber'] - 1) * $vbulletin->GPC['perpage'];
	$totalpages = ceil($totalinf / $vbulletin->GPC['perpage']);

	$infractions = vB::getDbAssertor()->assertQuery('fetchInfractionsByCondLimit', array(
		'status' => $vbulletin->GPC['status'],
		'whoadded' => $vbulletin->GPC['whoadded'],
		'userid' => $vbulletin->GPC['userid'],
		'start' => $vbulletin->GPC['start'],
		'end' => $vbulletin->GPC['end'],
		'infractionlevelid' => $vbulletin->GPC['infractionlevelid'],
		vB_dB_Query::PARAM_LIMIT => $vbulletin->GPC['perpage'],
		vB_dB_Query::PARAM_LIMITSTART => $startat,
		'orderby' => $vbulletin->GPC['orderby'],
	));

	if ($infractions AND $infractions->valid())
	{
		$baseUrl = 'admincp/admininfraction.php?';
		//this get reused a number of places.  If you change any parameters
		//you need to make sure that they get reset downstream
		$query = array (
			'do' => 'dolist',
			'status' => $vbulletin->GPC['status'],
			'u' => $vbulletin->GPC['userid'],
			'whoadded' => $vbulletin->GPC['whoadded'],
			'startstamp' => $vbulletin->GPC['start'],
			'endstamp' => $vbulletin->GPC['end'],
			'pp' => $vbulletin->GPC['perpage'],
			'page' => $vbulletin->GPC['pagenumber'],
			'infractionlevelid' => $vbulletin->GPC['infractionlevelid'],
			'orderby' => $vbulletin->GPC['orderby'],
		);

		print_form_header('admincp/admininfraction', 'remove');
		print_table_header(construct_phrase($vbphrase['infraction_viewer_page_x_y_there_are_z_total_log_entries'], vb_number_format($vbulletin->GPC['pagenumber']), vb_number_format($totalpages), vb_number_format($counter['total'])), 9);

		$headings = array();

		$query['orderby'] = 'order_by_username';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_username'] . "'>" . $vbphrase['user_name'] . "</a>";

		$query['orderby'] = 'leftby_username';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_username'] . "'>" . $vbphrase['left_by'] . "</a>";

		$query['orderby'] = 'date';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_date'] . "'>" . $vbphrase['date'] . "</a>";

		$headings[] = $vbphrase['infraction_type'];

		$query['orderby'] = 'points';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_points'] . "'>" . $vbphrase['points_ginfraction'] . "</a>";

		$query['orderby'] = 'reputation_penalty';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_reputation_penalty'] . "'>" . $vbphrase['reputation_penalty'] . "</a>";

		$query['orderby'] = 'expires';
		$url = htmlspecialchars($baseUrl . http_build_query($query));
		$headings[] = "<a href='$url' title='" . $vbphrase['order_by_expiration'] . "'>" . $vbphrase['expires_ginfraction'] . "</a>";

		$headings[] = $vbphrase['post'];
		$headings[] = $vbphrase['controls'];

		//reset the order by field
		$query['orderby'] = $vbulletin->GPC['orderby'];
		print_cells_row($headings, 1);

		foreach ($infractions AS $infraction)
		{
			$cell = array();
			$cell[] = "<a href=\"admincp/user.php?do=edit&amp;u=$infraction[infracteduserid]\"><b>$infraction[username]</b></a>";
			$cell[] = "<a href=\"admincp/user.php?do=edit&amp;u=$infraction[whoadded]\"><b>$infraction[leftby_username]</b></a>";
			$cell[] = '<span class="smallfont">' . vbdate($vbulletin->options['logdateformat'], $infraction['publishdate']) . '</span>';
			if ($infraction['points'])
			{
				$cell[] = $vbphrase['infraction'];
				$cell[] = $infraction['points'];
				$cell[] = $infraction['reputation_penalty'];
				switch($infraction['action'])
				{
					case 0:
						if ($infraction['expires'] == 0)
						{
							$cell[] = $vbphrase['never'];
						}
						else
						{
							$cell[] = '<span class="smallfont">' . vbdate($vbulletin->options['logdateformat'], $infraction['expires']) . '</span>';
						}
						break;
					case 1:
						$cell[] = $vbphrase['expired_ginfraction'];
						break;
					case 2:
						$cell[] = $vbphrase['reversed_ginfraction'];
						break;
				}
			}
			else
			{
				$cell[] = $vbphrase['warning_ginfraction'];
				$cell[] = $infraction['points'];
				$cell[] = $infraction['reputation_penalty'];
				switch($infraction['action'])
				{
					case 0:
						if ($infraction['expires'] == 0)
						{
							$cell[] = $vbphrase['never'];
						}
						else
						{
							$cell[] = '<span class="smallfont">' . vbdate($vbulletin->options['logdateformat'], $infraction['expires']) . '</span>';
						}
						break;
					case 1:
						$cell[] = $vbphrase['expired_ginfraction'];
						break;
					case 2:
						$cell[] = $vbphrase['reversed_ginfraction'];
						break;
				}
			}

			$postlink = '';
			if (!empty($infraction['infractednodeid']) AND !$infraction['postdeleted'])
			{
				$infractedNode = vB_Api::instanceInternal('node')->getNodeFullContent($infraction['infractednodeid']);
				$infractedNode = $infractedNode[$infraction['infractednodeid']];
				$postlink = vB5_Route::buildUrl(
					$infractedNode['routeid'] . '|fullurl',
					array(
						'nodeid' => $infractedNode['nodeid'],
						'title' => $infractedNode['title']
					),
					array(
						'p' => $infractedNode['nodeid']
					)
				) . '#post' . $infractedNode['nodeid'];
			}

			if ($postlink)
			{
				$cell[] = construct_link_code(htmlspecialchars_uni($vbphrase['post']), $postlink, true, '', true, false);
			}
			else
			{
				$cell[] = '&nbsp;';
			}

			$actions = '';
			$query['nodeid'] = $infraction['nodeid'];
			if($infraction['action'] != 2)
			{
				$query['do'] = 'reverse';
				$url = htmlspecialchars($baseUrl . http_build_query($query));
				$actions .= construct_link_code($vbphrase['reverse_ginfraction'], $url, false, '', true, false);
			}

			$url = "admininfraction.php?do=details&nodeid=$infraction[nodeid]";
			$actions .= construct_link_code($vbphrase['infraction_view'], $url, false, '', true);

			$query['do'] = 'deleteinfraction';
			$url = htmlspecialchars($baseUrl . http_build_query($query));
			$actions .= construct_link_code($vbphrase['delete'], $url, false, '', true, false);

			$cell[] = $actions;
			$query['do'] = 'dolist';
			unset($query['nodeid']);
			print_cells_row($cell);
		}

		$paging = get_log_paging_html($vbulletin->GPC['pagenumber'], $totalpages, $baseUrl, $query, $vbphrase);
		print_table_footer(9, $paging);
	}
	else
	{
		print_stop_message2('no_matches_found_gcpuser', null, array(), '');
	}
}


// ###################### Start add #######################
if ($_REQUEST['do'] == 'editgroup')
{
	print_form_header('admincp/admininfraction', 'updategroup');
	if (!empty($vbulletin->GPC['infractiongroupid']))
	{
		$infraction = vB::getDbAssertor()->getRow('infractiongroup', array('infractiongroupid' => $vbulletin->GPC['infractiongroupid']));
		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['infraction_group'], '', $vbulletin->GPC['infractiongroupid']), 2, 0);
		construct_hidden_code('infractiongroupid', $vbulletin->GPC['infractiongroupid']);
	}
	else
	{
		$infraction = array(
			'override' => 1
		);
		print_table_header($vbphrase['add_new_user_infraction_group_ginfraction']);
	}

	print_input_row($vbphrase['points_ginfraction'], 'pointlevel', $infraction['pointlevel'], true, 5);
	print_chooser_row($vbphrase['primary_usergroup'], 'usergroupid', 'usergroup', $infraction['usergroupid'], '-- ' . $vbphrase['all_usergroups'] . ' --');

	print_chooser_row($vbphrase['override_with_permissions'], 'orusergroupid', 'usergroup', $infraction['orusergroupid']);
	print_yes_no_row($vbphrase['override_display'], 'override', $infraction['override']);
	print_submit_row($vbphrase['save']);
}


// ###################### Start do update #######################
if ($_POST['do'] == 'updategroup')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'pointlevel'    => vB_Cleaner::TYPE_UINT,
		'usergroupid'   => vB_Cleaner::TYPE_INT,
		'orusergroupid' => vB_Cleaner::TYPE_UINT,
		'override'      => vB_Cleaner::TYPE_BOOL,
	));

	if (empty($vbulletin->GPC['pointlevel']))
	{
		print_stop_message2('please_complete_required_fields');
	}

	try
	{
		vB_Api::instanceInternal('Content_Infraction')->saveInfractionGroup(
			$vbulletin->GPC['pointlevel'],
			$vbulletin->GPC['usergroupid'],
			$vbulletin->GPC['orusergroupid'],
			$vbulletin->GPC['override'],
			$vbulletin->GPC['infractiongroupid']
		);
	}
	catch (vB_Exception_Api $e)
	{
		$errors = $e->get_errors();
		if (!empty($errors))
		{
			$error = array_shift($errors);
			print_stop_message2($error[0]);
		}
		print_stop_message2('error');
	}

	print_stop_message2('saved_infraction_group_successfully', 'admininfraction', array('do'=>'modify'));
}


// ###################### Start Remove #######################
if ($_REQUEST['do'] == 'removegroup')
{
	print_form_header('admincp/admininfraction', 'killgroup');
	construct_hidden_code('infractiongroupid', $vbulletin->GPC['infractiongroupid']);
	print_table_header(construct_phrase($vbphrase['confirm_deletion_x'], $vbphrase['infraction_group']));
	print_description_row($vbphrase['are_you_sure_you_want_to_delete_this_infraction_group']);
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
}


// ###################### Start Kill #######################
if ($_POST['do'] == 'killgroup')
{
	vB_Api::instanceInternal('Content_Infraction')->deleteInfractionGroup($vbulletin->GPC['infractiongroupid']);
	print_stop_message2('deleted_infraction_group_successfully', 'admininfraction', array('do' => 'modify'));
}


// ###################### Start add #######################
if ($_REQUEST['do'] == 'editbangroup')
{
	print_form_header('admincp/admininfraction', 'updatebangroup');
	if (!empty($vbulletin->GPC['infractionbanid']))
	{
		$infraction = vB::getDbAssertor()->getRow('infractionban', array(
			'infractionbanid' => $vbulletin->GPC['infractionbanid']
		));

		$selectedid = $infraction['banusergroupid'];

		print_table_header(
			construct_phrase($vbphrase['x_y_id_z'], $vbphrase['automatic_ban'], '', $vbulletin->GPC['infractionbanid']),
			2,
			0
		);
		construct_hidden_code('infractionbanid', $vbulletin->GPC['infractionbanid']);
	}
	else
	{
		$infraction = array(
			'warnings'    => 0,
			'infractions' => 0,
			'pointlevel'  => 0,
		);
		$selectedid = 0;

		print_table_header($vbphrase['add_new_automatic_ban_ginfraction']);
	}

	// make a list of usergroups into which to move this user
	$usergroups = array();
	foreach ($vbulletin->usergroupcache AS $usergroupid => $usergroup)
	{
		if (!($usergroup['genericoptions'] & $vbulletin->bf_ugp_genericoptions['isnotbannedgroup']))
		{
			$usergroups["$usergroupid"] = $usergroup['title'];
			if ($selectedid == 0)
			{
				$selectedid = $usergroupid;
			}
		}
	}

	$temporary_phrase = $vbphrase['temporary_ban_options'];
	$permanent_phrase = $vbphrase['permanent_ban_options'];

	// make a list of banning period options
	$periodoptions = array(
		$temporary_phrase => array(
			'D_1'  => construct_phrase($vbphrase['x_days'], 1),
			'D_2'  => construct_phrase($vbphrase['x_days'], 2),
			'D_3'  => construct_phrase($vbphrase['x_days'], 3),
			'D_4'  => construct_phrase($vbphrase['x_days'], 4),
			'D_5'  => construct_phrase($vbphrase['x_days'], 5),
			'D_6'  => construct_phrase($vbphrase['x_days'], 6),
			'D_7'  => construct_phrase($vbphrase['x_days'], 7),
			'D_10' => construct_phrase($vbphrase['x_days'], 10),
			'D_14' => construct_phrase($vbphrase['x_weeks'], 2),
			'D_21' => construct_phrase($vbphrase['x_weeks'], 3),
			'M_1' => construct_phrase($vbphrase['x_months'], 1),
			'M_2' => construct_phrase($vbphrase['x_months'], 2),
			'M_3' => construct_phrase($vbphrase['x_months'], 3),
			'M_4' => construct_phrase($vbphrase['x_months'], 4),
			'M_5' => construct_phrase($vbphrase['x_months'], 5),
			'M_6' => construct_phrase($vbphrase['x_months'], 6),
			'Y_1' => construct_phrase($vbphrase['x_years'], 1),
			'Y_2' => construct_phrase($vbphrase['x_years'], 2),
		),
		$permanent_phrase => array(
			'PERMA' => "$vbphrase[permanent] - $vbphrase[never_lift_ban]"
		)
	);

	$methods = array(
		'points'      => $vbphrase['points_ginfraction'],
		'infractions' => $vbphrase['infractions'],
	);

	print_input_row($vbphrase['amount_ginfraction'], 'amount', $infraction['amount'], true, 5);
	print_select_row($vbphrase['method_ginfraction'], 'method', $methods, $infraction['method']);
	print_chooser_row($vbphrase['primary_usergroup'], 'usergroupid', 'usergroup', $infraction['usergroupid'], '-- ' . $vbphrase['all_usergroups'] . ' --');
	print_select_row($vbphrase['move_user_to_usergroup_gcpuser'], 'banusergroupid', $usergroups, $selectedid);
	print_select_row($vbphrase['lift_ban_after'], 'period', $periodoptions, $infraction['period']);
	print_submit_row($vbphrase['save']);
}


// ###################### Start do update #######################
if ($_POST['do'] == 'updatebangroup')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'method'         => vB_Cleaner::TYPE_NOHTML,
		'amount'         => vB_Cleaner::TYPE_UINT,
		'usergroupid'    => vB_Cleaner::TYPE_INT,
		'banusergroupid' => vB_Cleaner::TYPE_UINT,
		'period'         => vB_Cleaner::TYPE_NOHTML
	));

	if (empty($vbulletin->GPC['amount']))
	{
		print_stop_message2('please_complete_required_fields');
	}

	if (empty($vbulletin->GPC['infractionbanid']))
	{
		$vbulletin->GPC['infractionbanid'] = vB::getDbAssertor()->assertQuery('infractionban', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'amount' => 0,
		));
	}

	vB::getDbAssertor()->assertQuery('infractionban', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'amount' => $vbulletin->GPC['amount'],
			'method' => $vbulletin->GPC['method'],
			'usergroupid' => $vbulletin->GPC['usergroupid'],
			'banusergroupid' => $vbulletin->GPC['banusergroupid'],
			'period' => $vbulletin->GPC['period'],
			vB_dB_Query::CONDITIONS_KEY => array(
				'infractionbanid' => $vbulletin->GPC['infractionbanid']
			)
	));

	print_stop_message2('saved_automatic_ban_successfully', 'admininfraction', array('do'=>'modify'));
}


// ###################### Start Remove #######################
if ($_REQUEST['do'] == 'removebangroup')
{
	print_form_header('admincp/admininfraction', 'killbangroup');
	construct_hidden_code('infractionbanid', $vbulletin->GPC['infractionbanid']);
	print_table_header(construct_phrase($vbphrase['confirm_deletion_x'], $vbphrase['automatic_ban']));
	print_description_row($vbphrase['are_you_sure_you_want_to_delete_this_automatic_ban']);
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
}


// ###################### Start Kill #######################
if ($_POST['do'] == 'killbangroup')
{
	vB::getDbAssertor()->assertQuery('infractionban',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'infractionbanid' => $vbulletin->GPC['infractionbanid'])
	);

	print_stop_message2('deleted_automatic_ban_successfully', 'admininfraction', array('do'=>'modify'));
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100935 $
|| #######################################################################
\*=========================================================================*/
