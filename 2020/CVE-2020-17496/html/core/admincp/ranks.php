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
define('CVS_REVISION', '$RCSfile$ - $Revision: 99787 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;
$phrasegroups = array('user', 'cpuser', 'cprank');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminusers'))
{
	print_cp_no_permission();
}

$entryStructure = array(
	'ranklevel'   => vB_Cleaner::TYPE_UINT,
	'minposts'    => vB_Cleaner::TYPE_UINT,
	'rankimg'     => vB_Cleaner::TYPE_STR,
	'usergroupid' => vB_Cleaner::TYPE_INT,
	'doinsert'    => vB_Cleaner::TYPE_STR,
	'rankhtml'    => vB_Cleaner::TYPE_NOTRIM,
	'rankurl'    => vB_Cleaner::TYPE_NOTRIM,
	'stack'       => vB_Cleaner::TYPE_UINT,
	'display'     => vB_Cleaner::TYPE_UINT,
);

$cleanerObj = new vB_Cleaner();
$rankId = $cleanerObj->clean($_REQUEST['rankid'], vB_Cleaner::TYPE_UINT);

// ############################# LOG ACTION ###############################
log_admin_action(!empty($rankId) ? "rank id = " . $rankId : '');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################
$assertor = vB::getDbAssertor();
$rankapi =  vB_Api::instanceInternal('Userrank');

print_cp_header($vbphrase['user_rank_manager_gcprank']);

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'modify';
}

// ###################### Start insert #######################
if ($_POST['do'] == 'insert')
{
	$iClean = array();
	foreach ($entryStructure AS $field => $type)
	{
		$iClean[$field] = $cleanerObj->clean($_POST[$field], $type);
	}

	if (!$iClean['ranklevel'] OR (!$iClean['rankimg'] AND !$iClean['rankhtml'] AND !$iClean['rankurl']))
	{
		if ($iClean['doinsert'])
		{
			echo '<p><b>' . $vbphrase['invalid_file_path_specified'] . '</b></p>';
			$iClean['rankimg'] = $iClean['doinsert'];
		}
		else
		{
			print_stop_message2('please_complete_required_fields');
		}

	}

	if ($iClean['usergroupid'] == -1)
	{
		$iClean['usergroupid'] = 0;
	}

	if (!empty($iClean['rankhtml']))
	{
		$iClean['rankimg'] = $iClean['rankhtml'];
		$type = 1;
	}
	else if (!empty($iClean['rankurl']))
	{
		$iClean['rankimg'] = $iClean['rankurl'];
		$type = 2;
	}
	else
	{
		$iClean['rankimg'] = preg_replace('/\/$/s', '', $iClean['rankimg']);

		if($dirhandle = @opendir(DIR . '/' . $iClean['rankimg']))
		{ // Valid directory!
			readdir($dirhandle);
			readdir($dirhandle);
			while ($filename = readdir($dirhandle))
			{
				if (is_file(DIR . "/{$iClean['rankimg']}/" . $filename) AND (($filelen = strlen($filename)) >= 5))
				{
					$fileext = strtolower(substr($filename, $filelen - 4, $filelen - 1));
					if ($fileext == '.gif' OR $fileext == '.bmp' OR $fileext == '.jpg' OR $fileext == 'jpeg' OR $fileext == 'png')
					{
						$FileArray[] = htmlspecialchars_uni($filename);
					}
				}
			}
			if (!is_array($FileArray))
			{
				print_stop_message2('no_matches_found_gerror');
			}

			print_form_header('admincp/ranks', 'insert', 0, 1, 'name', '');
			print_table_header($vbphrase['images_gcprank']);
			construct_hidden_code('usergroupid', $iClean['usergroupid']);
			construct_hidden_code('ranklevel', $iClean['ranklevel']);
			construct_hidden_code('minposts', $iClean['minposts']);
			construct_hidden_code('doinsert', $iClean['rankimg']);
			foreach ($FileArray AS $key => $val)
			{
				print_yes_row("<img src='core/" . $iClean['rankimg'] . "/$val' border='0' alt='' align='center' />", 'rankimg', '', '', $iClean['rankimg'] . "/$val");
			}
			print_submit_row($vbphrase['save']);
			closedir($dirhandle);
			exit;
		}
		else
		{ // Not a valid dir so assume it is a filename
			$iClean['rankimg'] = '/' . ltrim($iClean['rankimg'], '/');

			if (!(@is_file(DIR . $iClean['rankimg'])))
			{
				print_stop_message2('invalid_file_path_specified');
			}
		}
		$type = 0;
	}

	/*insert query*/
	$data = array(
		'ranklevel' => $iClean['ranklevel'],
		'usergroupid' => $iClean['usergroupid'],
		'minposts' => $iClean['minposts'],
		'stack' => $iClean['stack'],
		'display' => $iClean['display'],
		'type' => $type,
		'rankurl' => $iClean['rankurl'],
		'rankimg' => $iClean['rankimg'],
		'rankhtml' => $iClean['rankhtml']
	);

	$rankapi->save($data);

	print_stop_message2('saved_user_rank_successfully', 'ranks', array('do'=>'modify'));
}

// ###################### Start edit #######################
if ($_REQUEST['do'] == 'edit' OR $_REQUEST['do'] == 'add')
{
	if ($_REQUEST['do'] == 'edit')
	{
		$ranks = $rankapi->fetchById($rankId);
		print_form_header('admincp/ranks', 'doupdate');
	}
	else
	{
		$ranks = array(
			'ranklevel'   => 1,
			'usergroupid' => -1,
			'minposts'    => 10,
			'rankimg'     => '/images/',
		);
		print_form_header('admincp/ranks', 'insert');
	}

	if ($ranks['type'] == 1)
	{
		$ranktext = $ranks['rankimg'];

	}
	else if ($ranks['type'] == 2)
	{
		$rankurl = $ranks['rankimg'];
	}
	else
	{
		$rankimg = $ranks['rankimg'];
		//the path should always start with bburl
		$bburl = vB::getDatastore()->getOption('bburl');

		if (substr($rankimg, 0, strlen($bburl)) == $bburl)
		{
			$rankimg = substr($rankimg, strlen($bburl));
		}
	}

	$displaytype = array(
		$vbphrase['always'],
		$vbphrase['if_displaygroup_equals_this_group'],
	);

	construct_hidden_code('rankid', $rankId);
	print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['user_rank'], '', $rankId));
	print_input_row($vbphrase['times_to_repeat_rank'], 'ranklevel', $ranks['ranklevel']);
	print_chooser_row($vbphrase['usergroup'], 'usergroupid', 'usergroup', $ranks['usergroupid'], $vbphrase['all_usergroups']);
	print_input_row($vbphrase['minimum_posts'], 'minposts', $ranks['minposts']);
	print_yes_no_row($vbphrase['stack_rank'], 'stack', $ranks['stack']);
	print_select_row($vbphrase['display_type'], 'display', $displaytype, $ranks['display']);
	print_table_header($vbphrase['rank_type']);
	print_input_row($vbphrase['user_rank_file_path'], 'rankimg', $rankimg);
	print_input_row($vbphrase['or_user_rank_url'], 'rankurl', $rankurl);
	print_input_row($vbphrase['or_you_may_enter_text'], 'rankhtml', $ranktext);

	print_submit_row();
}

// ###################### Start do update #######################
if ($_POST['do'] == 'doupdate')
{
	$iClean = array();
	foreach ($entryStructure AS $field => $type)
	{
		if ($field != 'doinsert')
		{
			$iClean[$field] = $cleanerObj->clean($_POST[$field], $type);
		}
	}

	if (!$iClean['ranklevel'] OR (!$iClean['rankimg'] AND !$iClean['rankhtml'] AND !$iClean['rankurl']))
	{
		print_stop_message2('please_complete_required_fields');
	}

	if ($iClean['rankhtml'])
	{
		$type = 1;
		$iClean['rankimg'] = $iClean['rankhtml'];
	}
	else if ($iClean['rankurl'])
	{
		$type = 2;
		$iClean['rankimg'] = $iClean['rankurl'];
	}
	else
	{
		$type = 0;
		if (!(@is_file(DIR . $iClean['rankimg'])))
		{
			if (is_file(DIR . '/' . $iClean['rankimg'] ))
			{
				$iClean['rankimg'] = '/' . $iClean['rankimg'];
			}
			else
			{
				print_stop_message2('invalid_file_path_specified');
			}
		}

	}

	$data = array(
		'ranklevel' => $iClean['ranklevel'],
		'usergroupid' => $iClean['usergroupid'],
		'minposts' => $iClean['minposts'],
		'stack' => $iClean['stack'],
		'type' => $type,
		'display' => $iClean['display'],
		'rankimg' => $iClean['rankimg'],
		'rankurl' => $iClean['rankurl'],
		'rankhtml' => $iClean['rankhtml'],
	);
	$rankapi->save($data, $rankId);

	print_stop_message2('saved_user_rank_successfully', 'ranks', array('do'=>'modify'));
}
// ###################### Start Remove #######################

if ($_REQUEST['do'] == 'remove')
{
	print_form_header('admincp/ranks', 'kill');
	construct_hidden_code('rankid', $rankId);
	print_table_header($vbphrase['confirm_deletion_gcpglobal']);
	print_description_row($vbphrase['are_you_sure_you_want_to_delete_this_user_rank']);
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);

}

// ###################### Start Kill #######################

if ($_POST['do'] == 'kill')
{
	$rankapi->delete($rankId);

	print_stop_message2('deleted_user_rank_successfully', 'ranks', array('do'=>'modify'));
}

// ###################### Start modify #######################
if ($_REQUEST['do'] == 'modify')
{
	$ranks = $rankapi->fetchAll();

	print_form_header('admincp/', '');
	print_table_header($vbphrase['user_rank_manager_gcprank']);
	print_description_row($vbphrase['user_ranks_desc'] . '<br /><br />' .
	construct_phrase($vbphrase['it_is_recommended_that_you_update_user_titles'], vB::getCurrentSession()->get('sessionurl'))
	,'',0);
	print_table_footer();

	if (!$ranks OR count($ranks) == 0)
	{
		print_stop_message2('no_user_ranks_defined');
	}

	print_form_header('admincp/', '');

	// the $tempgroup check in the foreach below relies on the first pass of $tempgroup not being 0,
	// which it will be if it is init to false.
	$tempgroup = null;
	foreach ($ranks AS $rank)
	{
		if ($tempgroup != $rank['usergroupid'])
		{
			if (!empty($tempgroup))
			{
				print_table_break();
			}
			$tempgroup = $rank['usergroupid'];

			print_table_header($rank['usergroupid'] == 0 ? $vbphrase['all_usergroups'] : $rank['title'], 5, 1);
			print_cells_row(array($vbphrase['user_rank'], $vbphrase['minimum_posts'], $vbphrase['display_type'], $vbphrase['stack_rank'], $vbphrase['controls']), 1, '', -1);
		}

		$count = 0;
		$rankhtml = '';
		while ($count++ < $rank['ranklevel'])
		{
			if (!$rank['type'])
			{
				$rankhtml .= "<img src=\"core$rank[rankimg]\" border=\"0\" alt=\"\" />";
			}
			else if ($rank['type'] == 2 )
			{
				$rankhtml .= '<img src="' . $rank['rankimg'] . '"/>';
			}
			else
			{
				$rankhtml .= $rank['rankimg'];
			}
		}

		$cell = array(
			$rankhtml,
			vb_number_format($rank['minposts']),
			($rank['display'] ? $vbphrase['displaygroup'] : $vbphrase['always']),
			($rank['stack'] ? $vbphrase['yes'] : $vbphrase['no']),
			construct_link_code($vbphrase['edit'], "ranks.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&rankid=$rank[rankid]") . construct_link_code($vbphrase['delete'], "ranks.php?" . vB::getCurrentSession()->get('sessionurl') . "do=remove&rankid=$rank[rankid]")
		);
		print_cells_row($cell, 0, '', -1);

	}
	print_table_footer();

}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
