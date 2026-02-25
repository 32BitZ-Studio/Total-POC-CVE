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
define('CVS_REVISION', '$RCSfile$ - $Revision: 104029 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase,$vbulletin;
$phrasegroups = array('socialgroups', 'search');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

if (!can_administer('canadminthreads'))
{
	print_cp_no_permission();
}

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'search';
}

// Print the Header
print_cp_header($vbphrase['social_groups_gsocialgroups']);

$vbulletin->input->clean_array_gpc('r', array(
	'userid'    => vB_Cleaner::TYPE_UINT
));

// #######################################################################
if ($_REQUEST['do'] == 'search')
{
	print_form_header('admincp/socialgroups', 'dosearch');

	print_table_header($vbphrase['search_social_groups_gsocialgroups']);

	print_input_row($vbphrase['key_words'], 'filtertext');

	// get category options
	$category_options = array();
	$categories = vB::getDbAssertor()->assertQuery('vBForum:getSocialGroupsCategories', array());

	foreach ($categories AS $category)
	{
		$category_options[$category['nodeid']] = $category['title'];
	}
	unset($categories);

	// add empty category
	$category_options[0] = '';

	print_select_row($vbphrase['category_is'], 'category', $category_options, 0);

	// TODO:  still need to implement members filters
//	print_input_row($vbphrase['members_greater_than'], 'members_gteq', '', true, 5);
//	print_input_row($vbphrase['members_less_than'], 'members_lteq', '', true, 5);
	print_time_row($vbphrase['creation_date_is_before'], 'date_lteq', '', false);
	print_time_row($vbphrase['creation_date_is_after'], 'date_gteq', '', false);
	print_input_row($vbphrase['group_created_by'], 'creator');

//	print_select_row($vbphrase['group_type'], 'type', array(
//		''           => '',
//		'public'     => $vbphrase['group_type_public'],
//		'moderated'  => $vbphrase['group_type_moderated'],
//		'inviteonly' => $vbphrase['group_type_inviteonly']
//	));

	print_submit_row($vbphrase['search']);
	print_cp_footer();
}

// #######################################################################
if ($_REQUEST['do'] == 'groupsby' AND !empty($vbulletin->GPC['userid']))
{
	$user = array();
	if($vbulletin->GPC['userid'])
	{
		$user = vB_User::fetchUserinfo($vbulletin->GPC['userid']);
	}

	if ($user)
	{
		$vbulletin->GPC['creatoruserid'] = $vbulletin->GPC['userid'];
		$_REQUEST['do'] = 'dosearch';
	}
	else
	{
		print_cp_message($vbphrase['invalid_username']);
	}
}

// #######################################################################
if ($_REQUEST['do'] == 'dosearch')
{
	// TODO:  still need to implement members filters
	$searchApi = vB_Api::instanceInternal('search');
	$sgChannel = vB_Api::instanceInternal('socialgroup')->getSGChannel();

	$vbulletin->input->clean_array_gpc('r', array(
		'filtertext'    => vB_Cleaner::TYPE_NOHTML,
		'category' => vB_Cleaner::TYPE_UINT,
		'members_lteq'  => vB_Cleaner::TYPE_UINT,
		'members_gteq'  => vB_Cleaner::TYPE_UINT,
		'date_gteq'     => vB_Cleaner::TYPE_UNIXTIME,
		'date_lteq'     => vB_Cleaner::TYPE_UNIXTIME,
		'creator'       => vB_Cleaner::TYPE_NOHTML,
		'type'          => vB_Cleaner::TYPE_NOHTML
	));

	if ($vbulletin->GPC['creator'] != '')
	{
		$user = vB::getDbAssertor()->getRow('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('username' => $vbulletin->GPC['creator'])
		));
		if (!empty($user['userid']))
		{
			$vbulletin->GPC['creatoruserid'] = $user['userid'];
		}
		else
		{
			print_cp_message($vbphrase['invalid_username']);
		}
	}

	$filters = array();

	if (!empty($vbulletin->GPC['filtertext']))
	{
		$filters['keywords'] = $vbulletin->GPC['filtertext'];
	}

	if ($vbulletin->GPC['category'])
	{
		$filters['channel'] = $vbulletin->GPC['category'];
		$filters['depth'] = 1;
	}
	else
	{
		$filters['channel'] = $sgChannel;
	}

	if (!empty($vbulletin->GPC['date_lteq']))
	{
		$filters['to'] = $vbulletin->GPC['date_lteq'];
	}

	if (!empty($vbulletin->GPC['date_gteq']))
	{
		$filters['from'] = $vbulletin->GPC['date_gteq'];
	}

//	if (!empty($vbulletin->GPC['members_lteq']))
//	{
//		$filters['members_lteq'] = $vbulletin->GPC['members_lteq'];
//	}
//
//	if (!empty($vbulletin->GPC['members_gteq']))
//	{
//		$filters['members_gteq'] = $vbulletin->GPC['members_gteq'];
//	}

	if (!empty($vbulletin->GPC['creatoruserid']))
	{
		$filters['authorid'] = intval($vbulletin->GPC['creatoruserid']);
	}

//	if (!empty($vbulletin->GPC['type']))
//	{
//		$filters['type'] = $vbulletin->GPC['type'];
//	}
//
//	foreach ($filters AS $key => $value)
//	{
//		$socialgroupsearch->add($key, $value);
//	}

//	$groups = $socialgroupsearch->fetch_results();
	$filters['contenttypeid'] = vB_Types::instance()->getContentTypeID('vBForum_Channel');
	$result = $searchApi->getSearchResult($filters);
	$groups = $searchApi->getMoreResults($result);

	if (!empty($groups['results']))
	{
		print_form_header('admincp/socialgroups','delete');
		print_table_header($vbphrase['search_results']);

		echo '
			<tr>
			<td class="thead"><input type="checkbox" name="allbox" id="cb_checkall" onclick="js_check_all(this.form)" /></td>
			<td width="100%" class="thead"><label for="cb_checkall">' . $vbphrase['check_uncheck_all'] . '</label></td>
			</tr>';

		foreach ($groups['results'] AS $group)
		{
			if ($group['parentid'] == $sgChannel)
			{
				// this is a category, skip
				continue;
			}

			$cell = "";
			$group = prepare_socialgroup($group);

//			$cell = '<span class="shade smallfont" style="float: ' . vB_Template_Runtime::fetchStyleVar('right') . '; text-align: ' . vB_Template_Runtime::fetchStyleVar('right') . ';">' . $vbphrase['group_desc_' . $group['type']] . '<br />' . construct_phrase($vbphrase['x_members'], $group['members']);
//
//			if ($group['moderatedmembers'])
//			{
//				$cell .= '<br />' . construct_phrase($vbphrase['x_awaiting_moderation'], $group['moderatedmembers']);
//			}

			$ownerlink = vB5_Route::buildUrl('profile', array('userid' => $group['userid']));
			$grouplink = vB5_Route::buildUrl($group['routeid']);
			$cell .= '</span>
				<div style="text-align: ' . vB_Template_Runtime::fetchStyleVar('left') . '"><a href="' . $grouplink . '" target="group">' . $group['title'] . '</a></div>
				<div class="smallfont" style="text-align: ' . vB_Template_Runtime::fetchStyleVar('left') . '">' . construct_phrase($vbphrase['group_created_by_x'], $ownerlink, $group['authorname']) . '</div>';

			if (!empty($group['description']))
			{
				$cell .= '<div style="text-align: ' . vB_Template_Runtime::fetchStyleVar('left') . '">' . $group['description'] . '</div>';
			}

			print_cells_row(array(
				'<input type="checkbox" name="ids[' . $group['nodeid'] . ']" />',
				$cell
			));

		}

		print_submit_row($vbphrase['delete_selected_groups']);
	}
	else
	{
		print_cp_message($vbphrase['no_groups_found']);
	}
}


// #######################################################################
if ($_POST['do'] == 'delete')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'ids' => vB_Cleaner::TYPE_ARRAY_KEYS_INT
	));

	if (empty($vbulletin->GPC['ids']))
	{
		print_cp_message($vbphrase['you_did_not_select_any_groups']);
	}

	print_form_header('admincp/socialgroups','kill');
	print_table_header($vbphrase['confirm_deletion_gcpglobal']);

	print_description_row(construct_phrase($vbphrase['are_you_sure_you_want_to_delete_x_groups'], sizeof($vbulletin->GPC['ids'])), false, 2, '', 'center');

	construct_hidden_code('ids', sign_client_string(serialize($vbulletin->GPC['ids'])));

	print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);
}


// #######################################################################
if ($_POST['do'] == 'kill')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'ids' => vB_Cleaner::TYPE_NOCLEAN
	));

	$ids = @unserialize(verify_client_string($vbulletin->GPC['ids']));

	if (is_array($ids) AND !empty($ids))
	{
		print_form_header('admincp/socialgroups', '');
		print_table_header($vbphrase['deleting_groups']);

		$channelApi = vB_Api::instance('content_channel');

		foreach ($ids as $groupId)
		{
			$group = $channelApi->getContent($groupId);
			if (is_array($group) AND isset($group['errors']))
			{
				print_stop_message2($group['errors'][0]);
			}
			else
			{
				if(isset($group[$groupId]))
				{
					$groupToDelete = $group[$groupId];
					$deleteResult = $channelApi->delete($groupToDelete['nodeid']);
					if (is_array($deleteResult) AND isset($deleteResult['errors']))
					{
						print_stop_message2($deleteResult['errors'][0]);
					}
					else
					{
						print_description_row(construct_phrase($vbphrase['deleting_x'], $groupToDelete['title']));
					}
				}
				else
				{
					print_stop_message2(array('invalid_node_id'));
				}
			}
		}
	}
	else
	{
		// This should never happen without playing with the URLs
		print_cp_message($vbphrase['no_groups_selected_or_invalid_input']);
	}

	print_table_footer();
	print_cp_redirect2('socialgroups', array(), 5, 'admincp');
}


// #######################################################################
if ($_POST['do'] == 'updatecategory')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'socialgroupcategoryid' => vB_Cleaner::TYPE_UINT,
		'title' => vB_Cleaner::TYPE_STR,
		'description' => vB_Cleaner::TYPE_STR
	));

	if ($vbulletin->GPC['socialgroupcategoryid'])
	{
		$category = vB::getDbAssertor()->getRow('vBForum:getSocialGroupsCategories', array('categoryId' => $vbulletin->GPC['socialgroupcategoryid']));
		if ($category)
		{
			// update
			$nodeId = $vbulletin->GPC['socialgroupcategoryid'];
			$input['previousParentId'] = $category['parentid'];
		}
		else
		{
			// error
			print_stop_message2('invalid_social_group_category_specified');
		}
	}
	else
	{
		// add
		$nodeId = 0;
	}

	if ('' == $vbulletin->GPC['title'])
	{
		print_stop_message2('please_complete_required_fields');
	}

	$input['title'] = $vbulletin->GPC['title'];
	$input['description'] = $vbulletin->GPC['description'];
	vB_Api::instanceInternal('socialgroup')->saveCategory($nodeId, $input);

	print_cp_redirect2('socialgroups', array('do' => 'categories'), 0, 'admincp');
}

// #######################################################################
if ($_REQUEST['do'] == 'editcategory')
{
	$vbulletin->input->clean_gpc('r', 'socialgroupcategoryid', vB_Cleaner::TYPE_UINT);

	if ($vbulletin->GPC['socialgroupcategoryid'] AND
		$category = vB::getDbAssertor()->getRow('vBForum:getSocialGroupsCategories', array('categoryId' => $vbulletin->GPC['socialgroupcategoryid'])))
	{
		// edit
		print_form_header('admincp/socialgroups', 'updatecategory');
		construct_hidden_code('socialgroupcategoryid', $category['nodeid']);
		print_table_header($vbphrase['edit_social_group_category'] . " <span class=\"normal\">" . htmlspecialchars_uni($category['title']) . "</span>");
	}
	else if ($vbulletin->GPC['socialgroupcategoryid'])
	{
		print_stop_message2('invalid_social_group_category_specified');
	}
	else
	{
		// add
		print_form_header('admincp/socialgroups', 'updatecategory');
		print_table_header($vbphrase['add_new_socialgroup_category']);
	}

	print_input_row($vbphrase['title'], 'title', $category['title']);
	print_textarea_row($vbphrase['description_gcpglobal'], 'description', $category['description']);
	print_submit_row();
}


// #############################################################################
// perform deletion of category
if ($_POST['do'] == 'killcategory')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'socialgroupcategoryid' => vB_Cleaner::TYPE_UINT,
		'destsocialgroupcategoryid' => vB_Cleaner::TYPE_UINT
	));

	$socialgroupcategoryid = $vbulletin->GPC['socialgroupcategoryid'];
	$destsocialgroupcategoryid = $vbulletin->GPC['destsocialgroupcategoryid'];

	if ($socialgroupcategoryid AND $destsocialgroupcategoryid)
	{
		$assertor = vB::getDbAssertor();
		$categoriesresult = $assertor->getRows('vBForum:getSocialGroupsCategories', array(
			'categoryId' => array($socialgroupcategoryid, $destsocialgroupcategoryid)
		));

		if (count($categoriesresult) == 2)
		{
			$nodeApi = vB_Api::instanceInternal('node');
			$channelApi = vB_Api::instanceInternal('content_channel');

			// move all groups that belong to this category into the destination category
			$groupsresult = $assertor->select('vBForum:node', array(
				'contenttypeid' => vB_Types::instance()->getContentTypeID('vBForum_Channel'),
				'parentid' => $socialgroupcategoryid,
			));

			$socialgroupIds = array();
			foreach ($groupsresult AS $socialgroup)
			{
				$socialgroupIds[] = $socialgroup['nodeid'];
			}

			if (!empty($socialgroupIds))
			{
				$nodeApi->moveNodes($socialgroupIds, $destsocialgroupcategoryid);
			}

			// delete the source category
			$channelApi->delete($socialgroupcategoryid);

			print_stop_message2('social_group_category_deleted', 'socialgroups', array('do'=>'categories'));
		}
	}
	else
	{
		print_stop_message2('invalid_social_group_category_specified');
	}
}

// #############################################################################
// confirm deletion of category
if ($_REQUEST['do'] == 'deletecategory')
{
	$vbulletin->input->clean_gpc('r', 'socialgroupcategoryid', vB_Cleaner::TYPE_UINT);

	if (!empty($vbulletin->GPC['socialgroupcategoryid']))
	{
		$category_for_deletion = array();
		$category_options = array();

		$categories = vB::getDbAssertor()->getRows('vBForum:getSocialGroupsCategories', array('doCount' => true));

		if (sizeof($categories) < 2)
		{
			print_stop_message2('cannot_delete_last_social_group_category');
		}

		$category_options = array();

		foreach ($categories AS $category)
		{
			if ($category['nodeid'] == $vbulletin->GPC['socialgroupcategoryid'])
			{
				$category_for_deletion = $category;
			}
			else
			{
				$category_options[$category['nodeid']] = $category['title'] . " (" . construct_phrase($vbphrase['x_groups'], $category['groupcount']) . ")";
			}
		}
		unset($categories);

		print_form_header('admincp/socialgroups', 'killcategory');
		construct_hidden_code('socialgroupcategoryid', $category_for_deletion['nodeid']);
		print_table_header($vbphrase['confirm_deletion_gcpglobal']);
		print_description_row(construct_phrase($vbphrase['are_you_sure_you_want_to_delete_category_x_y_groups'],
												$category_for_deletion['title'],
												$category_for_deletion['groupcount'])
		);
		print_select_row($vbphrase['select_destination_category'], 'destsocialgroupcategoryid', $category_options);
		print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
	}
	else
	{
		print_stop_message2('invalid_social_group_category_specified');
	}
}

// #######################################################################
if ($_REQUEST['do'] == 'categories')
{
	print_form_header('admincp/socialgroups', 'categoriesquickupdate');
	print_table_header($vbphrase['social_group_categories_gsocialgroups'], 5);
	print_cells_row(array(
		"$vbphrase[title] / $vbphrase[description]",
		$vbphrase['social_groups_gsocialgroups'],
		$vbphrase['creator'],
		$vbphrase['controls']
	), true);

//	$categories = vB::getDbAssertor()->assertQuery('vBForum:getSocialGroupsCategories', array('doCount' => true));
//	$groupcounts = array();
//
//	foreach ($categories as $category)
//	{
//		$groupcounts[$category['nodeid']] = $category['groupcount'];
//	}
//	unset($categories);

	$categories = vB::getDbAssertor()->assertQuery('vBForum:getSocialGroupsCategories', array('doCount' => true, 'fetchCreator' => true));
	if ($categories)
	{
		foreach($categories AS $category)
		{
			$category['title'] = htmlspecialchars_uni($category['title']);
			$category['description'] = htmlspecialchars_uni($category['description']);

			print_cells_row(array(
				"<a href=\"admincp/socialgroups.php?do=editcategory&amp;socialgroupcategoryid={$category['nodeid']}\">{$category['title']}</a> <small>{$category['description']}</small>",
				"<a href=\"admincp/socialgroups.php?do=dosearch&amp;category={$category['nodeid']}\">" . vb_number_format($category['groupcount']) . "</a>",
				"<a href=\"admincp/user.php?do=edit&amp;userid={$category['userid']}\">{$category['username']}</a>",
				'<div class="smallfont">' .
				construct_link_code($vbphrase['edit'], "socialgroups.php?do=editcategory&amp;socialgroupcategoryid=" . $category['nodeid']) .
				construct_link_code($vbphrase['delete'], "socialgroups.php?do=deletecategory&amp;socialgroupcategoryid=" . $category['nodeid']) .
				'</div>'
			));
		}
	}

	?>
	<tr>
		<td colspan="4" class="tfoot" align="center">
			<input type="button" class="button" value="<?php echo $vbphrase['add_new_category']; ?>" onClick="vBRedirect('admincp/socialgroups.php?<?php echo vB::getCurrentSession()->get('sessionurl'); ?>do=editcategory');" />
		</td>
	</tr>
	<?php

	print_table_footer();
}

// Print Footer
print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104029 $
|| #######################################################################
\*=========================================================================*/
