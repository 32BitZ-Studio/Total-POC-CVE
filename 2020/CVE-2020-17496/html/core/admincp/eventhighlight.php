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
define('CVS_REVISION', '$RCSfile$ - $Revision: 103730 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array('style');

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_template.php'); // for color picker functions

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminforums'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################
$log_vars = array();
if (!empty($_REQUEST['eventhighlightid']))
{
	$log_vars[] = 'eventhighlightid = ' . intval($_REQUEST['eventhighlightid']);
}
log_admin_action(implode(', ', $log_vars));

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

// Set up Javascript
$vboptions = vB::getDatastore()->getValue('options');
$extraheader = array();

// Set up color picker
$colorpickerhtml = '';
if ($_REQUEST['do'] == 'add' OR $_REQUEST['do'] == 'edit')
{
	// for the color picker system
	global $colorPickerWidth, $colorPickerType, $numcolors;

	$numcolors = 0;
	$extraheader[] = '<script type="text/javascript" src="core/clientscript/vbulletin_cpcolorpicker.js?v=' . $vboptions['simpleversion'] . '"></script>';
	$colorpickerhtml = construct_color_picker(11);
	list($colorpickercss, $colorpickerhtml) = explode('</style>', $colorpickerhtml);
	$colorpickercss .= '</style>';
	$colorpickerphrases = array(
		'color_picker_not_ready' => $vbphrase['color_picker_not_ready'],
		'css_value_invalid' => $vbphrase['css_value_invalid'],
	);
	$userinfo = vB_User::fetchUserinfo(0, array('admin'));
	$colorpickerhtml .= '<div class="h-hide js-colorpicker-data"
		data-phrases="' . htmlspecialchars(json_encode($colorpickerphrases)) . '"
		data-bburl="' . htmlspecialchars($vboptions['bburl']) . '"
		data-cpstylefolder="' . htmlspecialchars($userinfo['cssprefs']) . '"
		data-colorpickerwidth="' . intval($colorPickerWidth) . '"
		data-colorpickertype="' . intval($colorPickerType) . '"
		></div>';
	$extraheader[] = $colorpickercss;
}

// Add Javascript
// Not all Javascript files will be relevant to all actions, but it's simpler to include
// it here, and Javascript files will be cached anyway.
$extraheader[] = '<script type="text/javascript" src="core/clientscript/vbulletin_eventhighlight.js?v=' . $vboptions['simpleversion'] . '"></script>';

// Print header
$extraheader = implode("\n", $extraheader);
print_cp_header($vbphrase['event_highlight_manager'], '', $extraheader);

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'list';
}


// Note: The event highlight display name uses a phrase as such:
// eventhighlight_<EVENT-HIGHLIGHT-ID>_name

// Set up some variables used for all/most actions
$eventHighlightApi = vB_Api::instanceInternal('eventhighlight');

// ########################################################################
if ($_POST['do'] == 'savepermissions')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'eventhighlightid'  => vB_Cleaner::TYPE_UINT,
		'allowbydefault'    => vB_Cleaner::TYPE_BOOL,
		'shownusergroups'   => vB_Cleaner::TYPE_ARRAY_INT,
		'allowedusergroups' => vB_Cleaner::TYPE_ARRAY_INT,
	));

	$denybydefault = !$vbulletin->GPC['allowbydefault'];
	$deniedusergroups = array_keys(array_diff_key($vbulletin->GPC['shownusergroups'], $vbulletin->GPC['allowedusergroups']));

	$eventHighlightApi->saveEventHighlightPermissions($vbulletin->GPC['eventhighlightid'], $denybydefault, $deniedusergroups);

	print_stop_message2('saved_event_highlight_permissions', 'eventhighlight', array('do' => 'list'));
}

// ########################################################################
if ($_REQUEST['do'] == 'permissions')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'eventhighlightid' => vB_Cleaner::TYPE_UINT,
	));

	$eventhighlightid = $vbulletin->GPC['eventhighlightid'];

	if (empty($eventhighlightid))
	{
		print_stop_message2('you_did_not_select_any_event_highlights');
	}

	$eventhighlight = $eventHighlightApi->getEventHighlightAdmin($eventhighlightid, true);
	$eventhighlight_html = '<a href="admincp/eventhighlight.php?do=edit&amp;eventhighlightid=' . htmlspecialchars_uni($eventhighlight['eventhighlightid']) . '">' . htmlspecialchars_uni($eventhighlight['name']) . '</a>';

	print_form_header('admincp/eventhighlight', 'savepermissions');
	print_table_header($vbphrase['edit_event_highlight_permissions']);

	construct_hidden_code('eventhighlightid', $eventhighlightid);

	print_description_row(construct_phrase($vbphrase['editing_event_highlight_permissions_for_x'], $eventhighlight_html));
	print_description_row($vbphrase['event_highlight_permission_explanation'], false, 2, '', '', 'permissionexplanation');
	print_yes_no_row($vbphrase['allow_new_groups_to_use_this_event_highlight'], 'allowbydefault', !$eventhighlight['denybydefault']);

	$checked = empty($eventhighlight['deniedusergroups']) ? 'checked="checked"' : '';
	$html = '
		<label>
			<input type="checkbox" class="js-checkable-toggle" ' . $checked . ' />
			' . $vbphrase['check_uncheck_all'] . '
		</label>
	';
	print_description_row($html, false, 2, 'thead', '', 'allowedusergroupscheckall');

	foreach ($vbulletin->usergroupcache AS $usergroupid => $usergroup)
	{
		construct_hidden_code('shownusergroups[' . $usergroupid . ']', '1');
		$name = 'allowedusergroups[' . $usergroupid . ']';
		$checked = empty($eventhighlight['deniedusergroups'][$usergroupid]) ? 'checked="checked"' : '';
		$html = '
			<label>
				<input
					type="checkbox"
					name="' . $name . '"
					class="js-checkable"
					value="1"
					' . $checked . '
					/>
				' . $usergroup['title'] . '
			</label>
		';
		print_description_row($html);
	}

	print_submit_row();
}

// ########################################################################
if ($_POST['do'] == 'kill')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'eventhighlightid' => vB_Cleaner::TYPE_UINT,
	));

	$eventHighlightApi->deleteEventHighlight($vbulletin->GPC['eventhighlightid']);

	print_stop_message2('eventhighlight_deleted', 'eventhighlight', array('do' => 'list'));
}

// ########################################################################
if ($_REQUEST['do'] == 'delete')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'eventhighlightid' => vB_Cleaner::TYPE_UINT,
	));

	print_delete_confirmation('eventhighlight', $vbulletin->GPC['eventhighlightid'], 'eventhighlight', 'kill', '', 0, $vbphrase['any_events_using_this_highlight_will_revert_to_unhighlighted']);
}

// ########################################################################
if ($_POST['do'] == 'insert')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'eventhighlightid' => vB_Cleaner::TYPE_UINT,
		'name'             => vB_Cleaner::TYPE_STR,
		'backgroundcolor'  => vB_Cleaner::TYPE_STR,
		'textcolor'        => vB_Cleaner::TYPE_STR,
		'displayorder'     => vB_Cleaner::TYPE_UINT,
	));

	$data = array(
		'name' => $vbulletin->GPC['name'],
		'eventhighlightid' => $vbulletin->GPC['eventhighlightid'],
		'backgroundcolor' => $vbulletin->GPC['backgroundcolor'],
		'textcolor' => $vbulletin->GPC['textcolor'],
		'displayorder' => $vbulletin->GPC['displayorder'],
	);

	$eventHighlightApi->saveEventHighlight($data);

	print_stop_message2('event_highlight_saved', 'eventhighlight', array('do' => 'list'));
}

// ########################################################################
if ($_REQUEST['do'] == 'add' OR $_REQUEST['do'] == 'edit')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'eventhighlightid' => vB_Cleaner::TYPE_UINT,
	));

	// fetch existing event highlight if we want to edit
	$eventhighlight = array();
	if ($vbulletin->GPC['eventhighlightid'])
	{
		$eventhighlight = $eventHighlightApi->getEventHighlightAdmin($vbulletin->GPC['eventhighlightid']);
	}

	print_form_header('admincp/eventhighlight', 'insert');

	if (empty($eventhighlight))
	{
		print_table_header($vbphrase['adding_event_highlight']);
	}
	else
	{
		print_table_header($vbphrase['editing_event_highlight']);
		construct_hidden_code('eventhighlightid', $eventhighlight['eventhighlightid']);
	}

	$namePhrase = $vbphrase['event_highlight_name'];
	if (!empty($eventhighlight))
	{
		$translationLink = 'phrase.php?do=edit&fieldname=global&t=1&varname=eventhighlight_' . $eventhighlight['eventhighlightid'] . '_name';
		$namePhrase .= '<dfn>' . construct_link_code($vbphrase['translations'], $translationLink, 1) . '</dfn>';
	}
	else
	{
		$namePhrase .= '<dfn>' . $vbphrase['translations_can_be_edited_after_saving'] . '</dfn>';
	}
	print_input_row($namePhrase, 'name', $eventhighlight['name']);
	print_color_input_row($vbphrase['event_highlight_background_color'], 'backgroundcolor', $eventhighlight['backgroundcolor'], true, 20, 50);
	print_color_input_row($vbphrase['event_highlight_text_color'], 'textcolor', $eventhighlight['textcolor'], true, 20, 50);
	print_input_row($vbphrase['display_order'], 'displayorder', $eventhighlight['displayorder']);

	print_submit_row();
}

// ########################################################################
if ($_POST['do'] == 'displayorder')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'eventhighlight_order' => vB_Cleaner::TYPE_ARRAY_UINT
	));

	$eventHighlightApi->saveEventHighlightDisplayOrder($vbulletin->GPC['eventhighlight_order']);

	print_stop_message2('saved_display_order_successfully', 'eventhighlight', array('do' => 'list'));
}

// ########################################################################
if ($_REQUEST['do'] == 'list')
{
	$colspan = 4;

	print_form_header('admincp/eventhighlight', 'displayorder');
	print_table_header($vbphrase['event_highlight_manager'], $colspan);

	$eventhighlights = $eventHighlightApi->getEventHighlightsAdmin(array(), true);

	if (empty($eventhighlights))
	{
		print_description_row($vbphrase['no_event_highlights_defined'], false, $colspan, '', 'center');
	}
	else
	{
		$cells = array($vbphrase['event_highlight'], $vbphrase['event_highlight_permissions'], $vbphrase['display_order'], $vbphrase['controls']);
		print_cells_row($cells, 1, 'tcat');
	}

	$usergroupcount = count($vbulletin->usergroupcache);
	foreach ($eventhighlights AS $eventhighlight)
	{
		$deniedusergroupcount = count($eventhighlight['deniedusergroups']);
		$allowedusergroupcount = $usergroupcount - $deniedusergroupcount;
		$plusnew = !$eventhighlight['denybydefault'] ? $vbphrase['plus_new'] : '';
		$string = vB::getString();
		print_cells_row(array(
			'<div style="background:' . $string->htmlspecialchars($eventhighlight['backgroundcolor']) . '; color: ' . $string->htmlspecialchars($eventhighlight['textcolor']) . '; padding:4px 10px; display:inline-block">' . $eventhighlight['name'] . '</div>',
			construct_phrase($vbphrase['x_of_y_usergroups_extra'], $allowedusergroupcount, $usergroupcount, $plusnew),
			'<input type="text" size="3" class="bginput" name="eventhighlight_order[' . $eventhighlight['eventhighlightid'] . ']" value="' . $eventhighlight['displayorder'] . '" />',
			'<div class="smallfont">'
				. construct_link_code($vbphrase['edit'], "eventhighlight.php?do=edit&amp;eventhighlightid=$eventhighlight[eventhighlightid]")
				. construct_link_code($vbphrase['delete'], "eventhighlight.php?do=delete&amp;eventhighlightid=$eventhighlight[eventhighlightid]")
				. construct_link_code($vbphrase['edit_permissions'], "eventhighlight.php?do=permissions&amp;eventhighlightid=$eventhighlight[eventhighlightid]")
			. '</div>'
		));
	}

	$buttons = '';
	if (!empty($eventhighlights))
	{
		$buttons .= '<input class="button" type="submit" value="'. $vbphrase['save_display_order'] . '" /> ';
	}
	$buttons .= '<input class="button" type="button" onclick="vBRedirect(\'admincp/eventhighlight.php?do=add\');" value="'. $vbphrase['add_event_highlight'] . '" /> ';

	print_table_footer($colspan, $buttons);
}

echo $colorpickerhtml;
print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
