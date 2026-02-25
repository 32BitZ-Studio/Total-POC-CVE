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
@set_time_limit(0);
ignore_user_abort(true);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 103448 $');

// ################### DEFINE LOCAL SCRIPT CONSTANTS ######################

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;
$phrasegroups = array('tagscategories');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadmintags'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################
log_admin_action();

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################


$action = $_REQUEST['do'] ?? 'modify';

//I'm not sure how much we need this, but the old branch logic checks some
//actions against REQUEST and some against POST. This should maintain
//equivilent behavior (error instead of explicit fallthrough)
$post_only_actions = array('taginsert', 'tagclear', 'tagkill', 'tagmerge', 'tagdomerge');
if (in_array($action, $post_only_actions) AND empty($_POST['do']))
{
	exit;
}

$dispatch = array
(
	'taginsert' => 'taginsert',
	'tagclear' => 'tagclear',
	'tagmerge' => 'tagmerge',
	'tagdomerge' => 'tagdomerge',
	'tagdopromote' => 'tagdopromote',
	'tagkill' => 'tagkill',
	'tags' => 'displaytags', //legacy from when this was part of threads
	'modify' => 'displaytags',
);

global $stop_file, $stop_args;

$stop_file = '';
$stop_args = array();
if (array_key_exists($action, $dispatch))
{
	//this is a bit ugly, but do to some weirdness we set a path cookie on the client
	//cookie which overrides the more general cookie we set in this script.  There isn't
	//a good way for the user to *do* anything about it.  This will nuke that cookie without
	//affecting anything that we're currently using
	//We can probably remove this after a few releases.
	setcookie('vbulletin_inlinetag', '', TIMENOW - 3600);

	// these three actions need to set cookies, and will print the cp header themselves.
	if (!in_array($action, array('tagclear', 'tagdomerge', 'tagkill')))
	{
		tagcp_print_header();
	}
	tagcp_init_tag_action();
	call_user_func($dispatch[$action]);
	print_cp_footer();
}


// ########################################################################
// some utility function for the actions
function tagcp_init_tag_action()
{
	global $vbulletin, $stop_file, $stop_args;

	$vbulletin->input->clean_array_gpc('r', array(
		'page' => vB_Cleaner::TYPE_UINT,
		'sort'       => vB_Cleaner::TYPE_NOHTML,
		'orphaned'   => vB_Cleaner::TYPE_BOOL,
	));

	$stop_file = 'tag';
	$stop_args = array(
		'do' => 'tags',
		'page' => $vbulletin->GPC['page'],
		'sort' => $vbulletin->GPC['sort'],
		'orphaned' => $vbulletin->GPC['orphaned'],
	);
}

function tagcp_add_hidden_fields($params)
{
	foreach($params AS $field => $value)
	{
		//we'll handle this magically so that we can pass the "stop_args" array
		//to the this function.  It's a bit of a cheat, but avoids some annoying
		//hoops for the caller to field
		if($field != 'do')
		{
			construct_hidden_code('page', $value);
		}
	}
}



function tagcp_fetch_tag_list()
{
	global $vbulletin;

	$vbulletin->input->clean_array_gpc('p', array(
		'tag' => vB_Cleaner::TYPE_ARRAY_KEYS_INT
	));

	$vbulletin->input->clean_array_gpc('c', array(
		'vbulletin_inlinetag' => vB_Cleaner::TYPE_STR,
	));

	$taglist = $vbulletin->GPC['tag'];

	if (!empty($vbulletin->GPC['vbulletin_inlinetag']))
	{
		$cookielist = explode('-', $vbulletin->GPC['vbulletin_inlinetag']);
		$cookielist = $vbulletin->cleaner->clean($cookielist, vB_Cleaner::TYPE_ARRAY_UINT);

		$taglist = array_unique(array_merge($taglist, $cookielist));
	}

	return $taglist;
}


// ########################################################################
// handled inserting a form
function taginsert()
{
	global $vbulletin, $stop_file, $stop_args;

	$vbulletin->input->clean_array_gpc('p', array('tagtext' => vB_Cleaner::TYPE_NOHTML));

	$response = vB_Api::instance('Tags')->insertTags($vbulletin->GPC['tagtext']);
	if (!empty($response['errors']))
	{
		print_stop_message_array($response['errors']);
	}
	else
	{
		print_stop_message2('tag_saved', $stop_file, $stop_args);
	}
}

// ########################################################################
// clear the tag selection cookie
function tagclear()
{
	tagcp_clear_taglist_cookie();

	tagcp_print_header();
	displaytags();
}

// ########################################################################

function tagmerge()
{
	global $vbulletin, $vbphrase, $stop_file, $stop_args;

	tagcp_init_tag_action();
	$taglist = tagcp_fetch_tag_list();
	if (!sizeof($taglist))
	{
		print_stop_message2('no_tags_selected', $stop_file, $stop_args);
	}

	$tags = vB::getDbAssertor()->getRows('vBForum:tag',
		array('tagid' => $taglist),
		array('field' => 'tagtext', 'direction' => vB_dB_Query::SORT_ASC)
	);

	if (!$tags)
	{
		print_stop_message2('no_tags_selected', $stop_file, $stop_args);
	}

	print_form_header('admincp/tag', 'tagdomerge');
	$columns = array('','','');
	$counter = 0;
	foreach ($tags AS $tag)
	{
		$id = $tag['tagid'];
		$text = $tag['tagtext'];
		$column = floor($counter++ / ceil(count($tags) / 3));
		$columns[$column] .= '<label for="taglist_' . $id . '">' .
			'<input type="checkbox" name="tag[' . $id . ']" id="taglist_' . $id . '" value="' . $id . '" tabindex="' . $column . '" checked="checked" /> ' . $text .
		'</label><br/>';
	}

	print_description_row($vbphrase['tag_merge_description'], false, 3, '', vB_Template_Runtime::fetchStyleVar('left'));
	print_cells_row($columns, false, false, -3);
	tagcp_add_hidden_fields($stop_args);

	print_input_row($vbphrase['new_tag'], 'tagtext', '', true, 35, 0, '', false, false, array(1,2));
	print_submit_row($vbphrase['merge_tags'], false, 3, $vbphrase['go_back']);
}


// ########################################################################
function tagdomerge()
{
	global $vbulletin, $vbphrase, $stop_file, $stop_args;

	$taglist = tagcp_fetch_tag_list();
	if (!sizeof($taglist))
	{
		tagcp_print_header();
		print_stop_message2('no_tags_selected', $stop_file, $stop_args);
	}

	$vbulletin->input->clean_array_gpc('p', array(
		'tagtext' => vB_Cleaner::TYPE_NOHTML
	));

	$tagtext = $vbulletin->GPC['tagtext'];

	$name_changed = false;
	$tagExists = vB_Api::instance('Tags')->fetchTagByText($tagtext);
	if (!$tagExists['tag'])
	{
		//Create tag
		$response = vB_Api::instance('Tags')->insertTags($tagtext);
		if (!empty($response['errors']))
		{
			tagcp_print_header();
			print_stop_message_array($response['errors']);
		}
	}
	else
	{
		//if the old tag and new differ only by case, then update
		if ($tagtext != $tagExists['tag']['tagtext'] AND vbstrtolower($tagtext) == vbstrtolower($tagExists['tag']['tagtext']))
		{
			$name_changed = true;
			$update = vB_Api::instance('Tags')->updateTags($tagtext);
		}
	}

	$tagExists = vB_Api::instance('Tags')->fetchTagByText($tagtext);
	if (!$tagExists['tag'])
	{
		tagcp_print_header();
		print_stop_message2('no_changes_made', $stop_file, $stop_args);
	}
	else
	{
		$targetid = $tagExists['tag']['tagid'];
	}

	// check if source and targed are the same
	if (sizeof($taglist) == 1 AND in_array($targetid, $taglist))
	{
		if ($name_changed)
		{
			tagcp_print_header();
			print_stop_message2('tags_edited_successfully', $stop_file, $stop_args);
		}
		else
		{
			tagcp_print_header();
		 	print_stop_message2('no_changes_made', $stop_file, $stop_args);
		}
	}

	if (false !== ($selected = array_search($targetid, $taglist)))
	{
		// ensure targetid is not in taglist
		unset($taglist[$selected]);
	}

	$synonym = vB_Api::instance('Tags')->createSynonyms($taglist, $targetid);
	if ($synonym['errors'])
	{
		print_stop_message2($synonym['errors'][0]);
	}

	// need to invalidate the search and tag cloud caches
	build_datastore('tagcloud', '', 1);
	build_datastore('searchcloud', '', 1);

	tagcp_clear_taglist_cookie();
	tagcp_print_header();
	print_stop_message2('tags_edited_successfully', $stop_file, $stop_args);
}

// ########################################################################
function tagdopromote()
{
	global $vbulletin, $vbphrase, $stop_file, $stop_args;

	$taglist = tagcp_fetch_tag_list();
	if (!sizeof($taglist))
	{
		print_stop_message2('no_tags_selected', $stop_file, $stop_args);
	}
	$promote = vB_Api::instance('Tags')->promoteTags($taglist);
	if (!empty($promote['errors']))
	{
		tagcp_print_header();
		print_stop_message_array($promote['errors']);
	}
	else
	{
		print_stop_message2('tags_edited_successfully', $stop_file, $stop_args);
	}
}

// ########################################################################

function tagkill()
{
	global $vbulletin, $vbphrase, $stop_file, $stop_args;

	$taglist = tagcp_fetch_tag_list();
	if (sizeof($taglist))
	{
		$kill = vB_Api::instance('Tags')->killTags($taglist);
		if (!empty($kill['errors']))
		{
			tagcp_print_header();
			print_stop_message2($promote['errors'][0], $stop_file, $stop_args);
		}

		// need to invalidate the search and tag cloud caches
		build_datastore('tagcloud', '', 1);
		build_datastore('searchcloud', '', 1);
	}

	tagcp_clear_taglist_cookie();
	tagcp_print_header();
	print_stop_message2('tags_deleted_successfully', $stop_file, $stop_args);
}


// ########################################################################

function displaytags()
{
	global $vbphrase, $stop_args;
	$assertor = vB::getDbAssertor();
	$datastore = vB::getDatastore();

	$page = $stop_args['page'];
	$sort = $stop_args['sort'];
	$orphaned = $stop_args['orphaned'];

	if ($page < 1)
	{
		$page = 1;
	}

	$synonyms_in_list =  ($sort == 'alphaall');

	$column_count = 3;
	$max_per_column = 15;
	$perpage = $column_count * $max_per_column;

	$query = array();
	$query['synonyms_in_list'] = $synonyms_in_list;
	$query['orphaned_only'] = $orphaned;

	$tag_counts = $assertor->getRow('vBAdmincp:getTagsForAdminCount', $query);
	$tag_count  = $tag_counts['count'];

	$start = ($page - 1) * $perpage;
	if ($start >= $tag_count)
	{
		$start = max(0, $tag_count - $perpage);
	}

	$query[vB_dB_Query::PARAM_LIMIT] = $perpage;
	$query[vB_dB_Query::PARAM_LIMITSTART] = $start;
	$query['sort'] = $sort;

	$tags = $assertor->assertQuery('vBAdmincp:getTagsForAdmin', $query);

	print_form_header('admincp/tag', '', false, true, 'tagsform');
	print_table_header($vbphrase['tag_list'], 3);
	if ($tags AND $tags->valid())
	{
		$columns = array();
		$counter = 0;

		// build page navigation
		$pagenav = tagcp_build_page_nav($stop_args, ceil($tag_count / $perpage));

		$args = $stop_args;
		//we want to reset pagingation when we change the sort or orphan status
		unset($args['page']);

		$orphan_status = array(
			0 => 'all_tags',
			1 => 'unused_tags',
		);

		$orphan_links = tagcp_build_sortfilter_links($vbphrase, $orphan_status, $args, 'orphaned');

		$sorts = array(
			'' => 'display_alphabetically',
			'dateline' => 'display_newest',
			'alphaall' => 'display_alphabetically_all',
		);
		$sort_links = tagcp_build_sortfilter_links($vbphrase, $sorts, $args, 'sort');

		$spacer = '&nbsp;&nbsp;';

		$sort_links = implode($spacer, $sort_links);
		$orphan_links = implode($spacer, $orphan_links);

		$left = vB_Template_Runtime::fetchStyleVar('left');
		print_description_row(
			'<div style="float: ' . $left  . '">' . $sort_links .  str_repeat($spacer, 6) . $orphan_links . '</div>' . $pagenav,
			false, 3, 'thead', 'right'
		);

		// build columns
		foreach ($tags AS $tag)
		{
			$columnid = floor($counter++ / $max_per_column);
			$columns["$columnid"][] = tagcp_format_tag_entry($tag, $synonyms_in_list);
		}

		// make column values printable
		$cells = array();
		for ($i = 0; $i < $column_count; $i++)
		{
			if ($columns["$i"])
			{
				$cells[] = implode("\n", $columns["$i"]);
			}
			else
			{
				$cells[] = '&nbsp;';
			}
		}

		print_column_style_code(array(
			'width: 33%',
			'width: 33%',
			'width: 34%'
		));
		print_cells_row($cells, false, false, -3);
		tagcp_add_hidden_fields($stop_args);
		?>
		<tr>
			<td colspan="<?php echo $column_count; ?>" align="center" class="tfoot">
				<div class='js-tag-phrase-data hide' data-gox='<?php echo $vbphrase['go_x']; ?>'></div>
				<select id="select_tags" name="do">
					<option value="tagmerge" id="select_tags_merge"><?php echo $vbphrase['merge_selected_synonym']; ?></option>
					<option value="tagdopromote" id="select_tags_delete"><?php echo $vbphrase['promote_synonyms_selected']; ?></option>
					<option value="tagkill" id="select_tags_delete"><?php echo $vbphrase['delete_selected']; ?></option>
					<optgroup label="____________________">
						<option value="tagclear"><?php echo $vbphrase['deselect_all_tags']; ?></option>
					</optgroup>
				</select>
				<input type="submit" value="<?php echo $vbphrase['go']; ?>" id="tag_inlinego" class="button" />
			</td>
		</tr>
<?php
	}
	else
	{
		print_description_row($vbphrase['no_tags_defined'], false, 3, '', 'center');
	}

	print_table_footer();

	tagcp_add_hidden_fields($stop_args);

	print_form_header('admincp/tag', 'taginsert');
	print_input_row($vbphrase['add_tag'], 'tagtext');
	print_submit_row();
}

function format_tag_list_item($id, $text)
{
	return '<label for="taglist_' . $id . '"><input type="checkbox" ' .
		'name="tag[' . $id . ']" id="taglist_' . $id . '" ' .
		'value="1" tabindex="1" /> ' . $text . '</label>';
}

function tagcp_build_sortfilter_links($phrases, $source, $args, $field)
{
	$current = $args[$field];
	$links = array();
	foreach($source AS $key => $phrase)
	{
		if ($key == $current)
		{
			$links[] = '<b>' . $phrases[$phrase] . '</b>';
		}
		else
		{
			$args[$field] = $key;
			$url = 'admincp/tag.php?' . http_build_query($args);
			$links[] = '<a href="' . htmlspecialchars($url) . '">' . $phrases[$phrase] . '</a>';
		}
	}

	return $links;
}

function tagcp_print_header()
{
	$datastore = vB::getDatastore();
	$jsversion =  $datastore->getOption('simpleversion');

	global $vbphrase;

	//it's possible that not fall of this will be relevant for every action, but let's just include it
	//until it causes problems.  It's simpler that way and the js files get cached anyway.
	$extraheader[] = '<script type="text/javascript" src="core/clientscript/vbulletin_inlinemod.js?v=' . $jsversion .'"></script>';
	$extraheader[] = '<script type="text/javascript" src="core/clientscript/vbulletin_tags.js?v=' . $jsversion .'"></script>';

	print_cp_header($vbphrase['tag_manager'], '', implode("\n", $extraheader));
}

function tagcp_clear_taglist_cookie()
{
	setcookie('vbulletin_inlinetag', '', TIMENOW - 3600, '/');
}

function tagcp_build_page_nav($page_args, $total_pages)
{
	global $vbphrase;

	$page = $page_args['page'];
	$args = $page_args;

	if ($total_pages > 1)
	{
		$pagenav = '<strong>' . $vbphrase['go_to_page'] . '</strong>';
		for ($thispage = 1; $thispage <= $total_pages; $thispage++)
		{
			if ($page == $thispage)
			{
				$pagenav .= " <strong>[$thispage]</strong> ";
			}
			else
			{
				$args['page'] = $thispage;
				$url = 'admincp/tag.php?' . http_build_query($args);

				$pagenav .= ' <a href="' . htmlspecialchars($url) . '" class="normal">' . $thispage . '</a> ';
			}
		}

	}
	else
	{
		$pagenav = '';
	}
	return $pagenav;
}

function tagcp_format_tag_entry($tag, $synonyms_in_list)
{
	global $vbulletin;

	if (!$synonyms_in_list)
	{
		$label = $tag['tagtext'];
		$synonyms = vB_Api::instance('Tags')->getTagSynonyms($tag['tagid']);
		if (empty($synonyms['errors']) AND count($synonyms['tags']))
		{
			$synonym_list = '<span class="cbsubgroup-trigger">' .
				'<img class="js-synlist-collapseclose" src="' .  get_cpstyle_href('collapse_generic_collapsed.gif')  . '" />'.
				'<img class="js-synlist-collapseopen hide" src="' .  get_cpstyle_href('collapse_generic.gif')  . '" />'.
				'</span>';

			$synonym_list .= '<ul class="cbsubgroup hide">';
			foreach ($synonyms['tags'] AS $tagid => $tagtext)
			{
				$synonym_list .= '<li>' . format_tag_list_item($tagid, $tagtext) . '</li>';
			}
			$synonym_list .= '</ul>';
		}
	}
	else
	{
		if($tag['canonicaltagid'])
		{
			$canonical = vB_Api::instance('Tags')->getTags($tag['canonicaltagid']);
			$canonical = $canonical['tags'][$tag['canonicaltagid']];

			$label = '<i>' . $tag['tagtext'] . '</i> (' . $canonical['tagtext'] . ')';
		}
		else
		{
			$label = $tag['tagtext'];
		}


		$synonym_list = '';
	}

	$tag_item_text = format_tag_list_item($tag['tagid'], $label);

	$left = vB_Template_Runtime::fetchStyleVar('left');
	return '<div id="tag' . $tag['tagid'] . '" class="js-synlist-container alt1" style="float:' . $left . ';clear:' . $left . '">' . "\n" .
		$tag_item_text . "\n" . $synonym_list . "\n" .
	'</div>';
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103448 $
|| #######################################################################
\*=========================================================================*/
