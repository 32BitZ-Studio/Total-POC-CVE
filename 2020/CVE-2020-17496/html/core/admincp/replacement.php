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
global $phrasegroups, $specialtemplates, $vbphrase, $DEVDEBUG;
$phrasegroups = array('style');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_template.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminstyles'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'templateid' => vB_Cleaner::TYPE_INT,
	'dostyleid'  => vB_Cleaner::TYPE_INT,
));

// ############################# LOG ACTION ###############################
log_admin_action(iif($vbulletin->GPC['templateid'] != 0, "template id = " . $vbulletin->GPC['templateid'], iif($vbulletin->GPC['dostyleid'] != 0, "style id = " . $vbulletin->GPC['dostyleid'])));

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();
print_cp_header($vbphrase['replacement_variable_manager_gstyle'], '', '<style type="text/css">.ldi li, .lsq a { font: 11px tahoma; list-style-type:disc; }</style>');

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'modify';
}

// *********************** kill *********************
if ($_POST['do'] == 'kill')
{
	$template_api = vB_Api::instance('template');
	$result = $template_api->deleteReplacementVar($vbulletin->GPC['templateid']);
	if(isset($result['errors'][0]))
	{
		print_stop_message2($result['errors'][0]);
	}

	print_cp_redirect2('replacement', array('do' => 'modify'), 1, 'admincp');
}

// *********************** remove *********************
if ($_REQUEST['do'] == 'remove')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'group' => vB_Cleaner::TYPE_STR
	));

	$hidden = array();
	$hidden['dostyleid'] =& $vbulletin->GPC['dostyleid'];
	$hidden['group'] = $vbulletin->GPC['group'];
	print_delete_confirmation('template', $vbulletin->GPC['templateid'], 'replacement', 'kill', 'replacement_variable', $hidden, $vbphrase['please_be_aware_replacement_variable_is_inherited']);

}

// *********************** update *********************
if ($_POST['do'] == 'update')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'findtext'    => vB_Cleaner::TYPE_STR,
		'replacetext' => vB_Cleaner::TYPE_STR
	));

	$vbulletin->GPC['findtext'] = strtolower($vbulletin->GPC['findtext']);

	if ($vbulletin->GPC['findtext'] === '')
	{
		print_stop_message2('please_complete_required_fields');
	}

	$template_api = vB_Api::instance('template');
	$existing = $template_api->fetchReplacementVar($vbulletin->GPC['findtext'], $vbulletin->GPC['dostyleid'], true);

	if(isset($existing['errors'][0]))
	{
		print_stop_message2($existing['errors'][0]);
	}
	$existing = $existing['replacevar'];

	//if this totally doesn't exist, add it.  Not sure why this would happen on the edit page since it means the
	//system thinks we have a replacement var somewhere in the tree -- but the legacy code handles this case so
	//we will to
	if(!$existing)
	{
		$result = $template_api->insertReplacementVar($vbulletin->GPC['dostyleid'], $vbulletin->GPC['findtext'], $vbulletin->GPC['replacetext']);
		if(isset($result['errors'][0]))
		{
			print_stop_message2($result['errors'][0]);
		}
	}
	else
	{
		//if we don't have a templateid and but have a matching value don't try to insert a duplicate.  Not sure why this will happen
		//and am even less sure why we don't just update the item we find.  Again matching existing code behavior.
		if(($vbulletin->GPC['templateid'] == 0) AND ($existing['styleid'] == $vbulletin->GPC['dostyleid']))
		{
			print_stop_message2(array(
				'replacement_already_exists',
				htmlspecialchars($existing['title']),
				htmlspecialchars($existing['template']),
				"replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=$existing[styleid]&amp;templateid=$existing[templateid]"
			));
		}

		//if the text didn't change -- there is nothing we should do.  Especially not create an identical "customized" template.
		if ($existing['template'] != $vbulletin->GPC['replacetext'])
		{
			//changing inherited variable, insert a value for this style
			if ($existing['styleid'] != $vbulletin->GPC['dostyleid'])
			{
				$result = $template_api->insertReplacementVar($vbulletin->GPC['dostyleid'], $vbulletin->GPC['findtext'], $vbulletin->GPC['replacetext']);
				if(isset($result['errors'][0]))
				{
					print_stop_message2($result['errors'][0]);
				}
			}

			//changing a variable for this style, update it.
			else
			{
				$result = $template_api->updateReplacementVar($vbulletin->GPC['templateid'], $vbulletin->GPC['replacetext']);
				if(isset($result['errors'][0]))
				{
					print_stop_message2($result['errors'][0]);
				}
			}
		}
		else
		{
			print_stop_message2('nothing_to_do', 'replacement', array('do' => 'modify'));
		}
	}

	print_cp_redirect2('replacement', array('do' => 'modify'), 1, 'admincp');
}

// *********************** edit *********************
if ($_REQUEST['do'] == 'edit')
{
	$style = vB_Library::instance('Style')->fetchStyleByID($vbulletin->GPC['dostyleid'], false);
	$replacement = vB_Api::instance('template')->fetchByID($vbulletin->GPC['templateid']);

	print_form_header('admincp/replacement', 'update');
	construct_hidden_code('templateid', $vbulletin->GPC['templateid']);
	construct_hidden_code('dostyleid', $vbulletin->GPC['dostyleid']);
	construct_hidden_code('findtext', $replacement['title']);
	if ($replacement['styleid'] == $vbulletin->GPC['dostyleid'])
	{
		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['replacement_variable'], htmlspecialchars_uni($replacement['title']), $replacement['templateid']));
	}
	else
	{
		print_table_header(construct_phrase($vbphrase['customize_replacement_variable_x'], htmlspecialchars_uni($replacement['title'])));
	}
	print_label_row($vbphrase['style'], ($vbulletin->GPC['dostyleid'] == -1 ? $vbphrase['master_style'] : $style['title']));
	print_label_row("$vbphrase[search_for_text] <dfn>($vbphrase[case_insensitive])</dfn>", htmlspecialchars_uni($replacement['title']));
	print_textarea_row($vbphrase['replace_with_text'], 'replacetext', $replacement['template'], 5, 50);
	print_submit_row($vbphrase['save']);

}

// *********************** insert *********************
if ($_POST['do'] == 'insert')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'findtext'    => vB_Cleaner::TYPE_STR,
		'replacetext' => vB_Cleaner::TYPE_STR,
	));

	$vbulletin->GPC['findtext'] = strtolower($vbulletin->GPC['findtext']);

	if ($vbulletin->GPC['findtext'] === '')
	{
		print_stop_message2('please_complete_required_fields');
	}

	$template_api = vB_Api::instance('template');
	$result = $template_api->fetchReplacementVar($vbulletin->GPC['findtext'], $vbulletin->GPC['dostyleid']);
	if(isset($result['errors'][0]))
	{
		print_stop_message2($result['errors'][0]);
	}

	$existing = $result['replacmentvar'];
	if ($existing)
	{
		print_stop_message2(array(
			'replacement_already_exists',
			htmlspecialchars($existing['title']),
			htmlspecialchars($existing['template']),
			"replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=$existing[styleid]&amp;templateid=$existing[templateid]"
		));
	}
	else
	{
		$result = $template_api->insertReplacementVar($vbulletin->GPC['dostyleid'], $vbulletin->GPC['findtext'], $vbulletin->GPC['replacetext']);
		if(isset($result['errors'][0]))
		{
			print_stop_message2($result['errors'][0]);
		}

		$args = array();
		parse_str(vB::getCurrentSession()->get('sessionurl'),$args);
		$args['do'] = 'modify';
		print_cp_redirect2('replacement', $args, 1, 'admincp');
	}
}

// *********************** add *********************
if ($_REQUEST['do'] == 'add')
{
	print_form_header('admincp/replacement', 'insert');
	print_table_header($vbphrase['add_new_replacement_variable']);
	print_style_chooser_row('dostyleid', $vbulletin->GPC['dostyleid'], $vbphrase['master_style'], $vbphrase['style'], ($vb5_config['Misc']['debug'] == 1 ? 1 : 0));
	print_input_row("$vbphrase[search_for_text] <dfn>($vbphrase[case_insensitive])</dfn>", 'findtext', '');
	print_textarea_row($vbphrase['replace_with_text'], 'replacetext', '', 5, 50);
	print_submit_row($vbphrase['save']);

}

// *********************** modify *********************
if ($_REQUEST['do'] == 'modify')
{
	print_form_header('admincp/', '');
	print_table_header($vbphrase['color_key']);
	print_description_row('
	<div class="darkbg" style="border: 2px inset;"><ul class="darkbg">
		<li class="col-g">' . $vbphrase['replacement_variable_is_unchanged_from_the_default_style'] . '</li>
		<li class="col-i">' . $vbphrase['replacement_variable_is_inherited_from_a_parent_style'] . '</li>
		<li class="col-c">' . $vbphrase['replacement_variable_is_customized_in_this_style'] . '</li>
	</ul></div>
	');
	print_table_footer();

	echo "<center>\n";
	echo "<div class=\"tborder\" style=\"width: 100%\">";
	echo "<div class=\"tcat\" style=\"padding:4px\" align=\"center\"><b>$vbphrase[replacement_variables]</b></div>\n";
	echo "<div class=\"alt1\" style=\"padding: 8px\">";
	echo "<div class=\"darkbg\" style=\"padding: 4px; border: 2px inset; text-align: " . vB_Template_Runtime::fetchStyleVar('left') . "\">\n";

	print_replacements();

	echo "</div></div></div>\n</center>\n";
}

// Display Function //
function print_replacements($parentid = -1, $indent = "\t")
{
	global $vbulletin, $vbphrase;
	static $stylecache, $donecache = array();

	$vb5_config =& vB::getConfig();
	$assertor = vB::getDbAssertor();
	$styleLib = vB_Library::instance('Style');

	if ($parentid == -1 AND $vb5_config['Misc']['debug'])
	{
		echo "<ul class=\"lsq\">\n";
		echo "\t<li><b>" . $vbphrase['master_style'] . "</b>" . construct_link_code($vbphrase['add_new_replacement_variable'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=add&amp;dostyleid=-1") . "\n";
		echo "\t\t<ul class=\"ldi\">\n";
		$templates = $assertor->getRows('template',	array('templatetype' => 'replacement', 'styleid' => $parentid));

		if ($templates)
		{
			foreach ($templates AS $template)
			{
				echo "\t\t<li>" . htmlspecialchars_uni($template['title']) . construct_link_code($vbphrase['edit'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=-1&amp;templateid=$template[templateid]").construct_link_code($vbphrase['delete'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=remove&amp;dostyleid=-1&amp;templateid=$template[templateid]") . "\n";
			}
		}
		else
		{
			echo "\t\t\t<li>" . $vbphrase['no_replacements_defined'] . "</li>\n";
		}
		echo "\t\t</ul><br />\n\t</li>\n</ul>\n<hr size=\"1\" />\n";
	}

	if (empty($stylecache))
	{
		$styles = $styleLib->fetchStyles(false, true, array("skipReadCheck" => true));

		foreach ($styles AS $style)
		{
			$stylecache[$style['parentid']][$style['displayorder']][$style['styleid']] = $style;
		}
	}

	// Check style actually exists / has children
	if (!isset($stylecache[$parentid]))
	{
		return;
	}

	foreach ($stylecache[$parentid] AS $holder)
	{
		echo "$indent<ul class=\"lsq\">\n";
		foreach ($holder AS $styleid => $style)
		{
			$style = $styleLib->fetchStyleByID($styleid);

			// Themes are read-only, but they all have children that are writable.
			// Since each "level" has a read-only parent holding writable children,
			// If we just skip the read-only ones outright, no themes will show up.
			// If it's read-only, go through & print its descendants.
			if (!$styleLib->checkStyleReadProtection($styleid, $style))
			{
				print_replacements($styleid, "$indent\t");
				continue;
			}

			echo "$indent<li><b>$style[title]</b>" . construct_link_code($vbphrase['add_new_replacement_variable'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=add&amp;dostyleid=$styleid") . "\n";
			echo "\t$indent<ul class=\"ldi\">\n";

			$templates = $assertor->getRows('getReplacementTemplates',	array('templateids' => $style['templatelist']));

			if($templates)
			{
				foreach ($templates AS $template)
				{
					if (in_array($template['templateid'], $donecache))
					{
						echo "\t\t$indent<li class=\"col-i\">" . htmlspecialchars_uni($template['title']) . construct_link_code($vbphrase['customize_gstyle'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=$styleid&amp;templateid=$template[templateid]") . "</li>\n";
					}
					else if ($template['styleid'] != -1)
					{
						echo "\t\t$indent<li class=\"col-c\">" . htmlspecialchars_uni($template['title']) . construct_link_code($vbphrase['edit'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=$styleid&amp;templateid=$template[templateid]") . construct_link_code($vbphrase['delete'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=remove&amp;dostyleid=$styleid&amp;templateid=$template[templateid]") . "</li>\n";
						$donecache[] = $template['templateid'];
					}
					else
					{
						echo "\t\t$indent<li class=\"col-g\">" . htmlspecialchars_uni($template['title']) . construct_link_code($vbphrase['customize_gstyle'], "replacement.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&amp;dostyleid=$styleid&amp;templateid=$template[templateid]") . "</li>\n";
					}
				}
			}
			else
			{
				echo "\t\t$indent<li>" . $vbphrase['no_replacements_defined'] . "</li>\n";
			}

			echo "$indent\t</ul><br />\n";
			print_replacements($styleid, "$indent\t");
			echo "$indent</li>\n";
		}

		echo "$indent</ul>\n";
		if ($style['parentid'] == -1)
		{
			echo "<hr size=\"1\" />\n";
		}
	}
}

unset($DEVDEBUG);
print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
