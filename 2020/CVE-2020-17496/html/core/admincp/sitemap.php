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
define('CVS_REVISION', '$RCSfile$ - $Revision: 102830 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array('global');
$specialtemplates = array();
DEFINE ('THIS_SCRIPT', 'sitemap');
// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/class_sitemap.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('cansitemap'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################
log_admin_action();

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################
if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'menu';
}

print_cp_header($vbphrase['xml_sitemap_manager']);


// ########################################################################
if ($_REQUEST['do'] == 'menu')
{
	// edit content priority for...
	$options = array('channel' => $vbphrase['channel']);	// channel nodes
	// todo: custom priority settings for starter nodes
	$options['page'] = $vbphrase['page'];	// node-less pages

	print_form_header('admincp/sitemap');
	print_table_header($vbphrase['sitemap_priority_manager']);
	print_select_row($vbphrase['manage_priority_for_content_type'], 'do', $options);
	print_submit_row($vbphrase['manage'], null);
}

// Default priority settings, with clear
$default_settings = array(
	'default' => $vbphrase['default'],
	'0.0' => vb_number_format('0.0', 1),
	'0.1' => vb_number_format('0.1', 1),
	'0.2' => vb_number_format('0.2', 1),
	'0.3' => vb_number_format('0.3', 1),
	'0.4' => vb_number_format('0.4', 1),
	'0.5' => vb_number_format('0.5', 1),
	'0.6' => vb_number_format('0.6', 1),
	'0.7' => vb_number_format('0.7', 1),
	'0.8' => vb_number_format('0.8', 1),
	'0.9' => vb_number_format('0.9', 1),
	'1.0' => vb_number_format('1.0', 1),
	'-1' => $vbphrase['exclude'],
);


// ########################################## BEGIN VB5 #####

// #########################edit channel priority (VB5)#########################
if ($_REQUEST['do'] == 'channel')
{
	// Get the custom priorities
	$sitemap = new vB_SiteMap_Node($vbulletin);

	print_form_header('admincp/sitemap', 'savechannel');
	print_table_header($vbphrase['channel_priority_manager']);
	print_description_row($vbphrase['sitemap_forum_priority_desc']);

	$channels = $sitemap->get_allowed_channels();

	if (is_array($channels))
	{
		$priorityheader = construct_phrase($vbphrase['priority_default_x'], vb_number_format($vbulletin->options['sitemap_priority'], 1));
		print_cells_row(array($vbphrase['title'], $priorityheader), 1, 'tcat');

		foreach($channels AS $key => $channel)
		{
			//we don't want to display the root channel
			if ($channel['parentid'] == 0)
			{
				continue;
			}

			$priority = $sitemap->get_node_priority($channel['nodeid']);
			if ($priority === false)
			{
				$priority = 'default';
			}

			$cells = array();

			$channelurl = 'admincp/forum.php?do=edit&n=' . $channel['nodeid'];
			$depthmark = construct_depth_mark($channel['depth'], '- - ');
			$cells[] = '<b>' . $depthmark . '<a href="' . htmlspecialchars($channelurl) . '">' . $channel['title'] . '</a></b>';

			$cells[] = "\n\t<select name=\"priority[$channel[nodeid]]\" class=\"bginput\">\n" .
				construct_select_options($default_settings, $priority) .
				" />\n\t";

			print_cells_row($cells);
		}
	}

	print_submit_row($vbphrase['save_priority']);
}


// #########################save channel priority (VB5)#########################
if ($_POST['do'] == 'savechannel')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'priority' => vB_Cleaner::TYPE_ARRAY_STR
	));

	// Custom values to remove
	$update_values = array();

	foreach ($vbulletin->GPC['priority'] AS $nodeid => $priority)
	{
		if ($priority == 'default')
		{
			$vbulletin->db->query("
				DELETE FROM " . TABLE_PREFIX . "contentpriority
				WHERE contenttypeid = 'node' AND sourceid = " . intval($nodeid)
			);
		}
		else
		{
			$update_values[] = "('node', " . intval($nodeid) . "," . floatval($priority) . ")";
		}
	}

	// If there are any with custom values, set them
	if (count($update_values))
	{
		$vbulletin->db->query_write("
			REPLACE INTO " . TABLE_PREFIX . "contentpriority
				(contenttypeid, sourceid, prioritylevel)
			VALUES
				" . implode(',', $update_values)
		);
	}

	print_stop_message2('saved_content_priority_successfully', 'sitemap', array('do'=>'channel'));
}

// #########################edit page priority (VB5)#########################
if ($_REQUEST['do'] == 'page')
{
	// Get the custom forum priorities
	$sitemap = new vB_SiteMap_Page($vbulletin);

	print_form_header('admincp/sitemap', 'savepage');
	print_table_header($vbphrase['page_priority_manager']);
	print_description_row($vbphrase['sitemap_forum_priority_desc']);

	$pages = $sitemap->get_pages();

	if (is_array($pages))
	{
		$priorityheader = construct_phrase($vbphrase['priority_default_x'], vb_number_format($vbulletin->options['sitemap_priority'], 1));
		print_cells_row(array($vbphrase['title'], $priorityheader), 1, 'tcat');

		foreach($pages AS $key => $page)
		{
			$priority = $sitemap->get_priority($page['pageid']);
			if ($priority === false)
			{
				$priority = 'default';
			}

			$cells = array();

			$cells[] = "<b><a href=\"$page[url]\">$page[title]</a></b>";

			$cells[] = "\n\t<select name=\"priority[$page[pageid]]\" class=\"bginput\">\n"	.
				construct_select_options($default_settings, $priority) .
				" />\n\t";

			print_cells_row($cells);
		}
	}

	print_submit_row($vbphrase['save_priority']);
}

// #########################save page priority (VB5)#########################
if ($_POST['do'] == 'savepage')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'priority' => vB_Cleaner::TYPE_ARRAY_STR
	));

	// Custom values to remove
	$update_values = array();

	foreach ($vbulletin->GPC['priority'] AS $pageid => $priority)
	{
		if ($priority == 'default')
		{
			$vbulletin->db->query("
				DELETE FROM " . TABLE_PREFIX . "contentpriority
				WHERE contenttypeid = 'page' AND sourceid = " . intval($pageid)
			);
		}
		else
		{
			$update_values[] = "('page', " . intval($pageid) . "," . floatval($priority) . ")";
		}
	}

	// If there are any with custom values, set them
	if (count($update_values))
	{
		$vbulletin->db->query_write("
			REPLACE INTO " . TABLE_PREFIX . "contentpriority
				(contenttypeid, sourceid, prioritylevel)
			VALUES
				" . implode(',', $update_values)
		);
	}

	print_stop_message2('saved_content_priority_successfully', 'sitemap', array('do'=>'page'));
}

// ########################################## END VB5 #####

// ########################################################################
if ($_REQUEST['do'] == 'removesession')
{
	print_form_header('admincp/sitemap', 'doremovesession');
	print_table_header($vbphrase['remove_sitemap_session']);
	print_description_row($vbphrase['are_you_sure_remove_sitemap_session']);
	print_submit_row($vbphrase['remove_sitemap_session'], null);
}

// ########################################################################
if ($_POST['do'] == 'doremovesession')
{
	// reset the build time to be the next time the cron is supposed to run based on schedule (in case we're in the middle of running it)
	require_once(DIR . '/includes/functions_cron.php');
	$cron = $vbulletin->db->query_first("SELECT * FROM " . TABLE_PREFIX . "cron WHERE filename = './includes/cron/sitemap.php'");
	if ($cron)
	{
		build_cron_item($cron['cronid'], $cron);
	}

	$vbulletin->db->query("DELETE FROM " . TABLE_PREFIX . "adminutil WHERE title = 'sitemapsession'");

	$_REQUEST['do'] = 'buildsitemap';
}

// ########################################################################
if ($_REQUEST['do'] == 'buildsitemap')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'success' => vB_Cleaner::TYPE_BOOL
	));

	if ($vbulletin->GPC['success'])
	{
		print_table_start();
		print_description_row($vbphrase['sitemap_built_successfully_view_here'], false, 2, '', 'center');
		print_table_footer();
	}

	$runner = new vB_SiteMapRunner_Admin($vbulletin);

	$status = $runner->check_environment();
	if ($status['error'])
	{
		$sitemap_session = $runner->fetch_session();
		if ($sitemap_session['state'] != 'start')
		{
			print_table_start();
			print_description_row('<a href="admincp/sitemap.php?do=removesession">' . $vbphrase['remove_sitemap_session'] . '</a>', false, 2, '', 'center');
			print_table_footer();
		}

		print_stop_message2($status['error']);
	}

	// Manual Sitemap Build
	print_form_header('admincp/sitemap', 'dobuildsitemap');
	print_table_header($vbphrase['build_sitemap']);
	print_description_row($vbphrase['use_to_build_sitemap']);
	print_submit_row($vbphrase['build_sitemap'], null);
}

// ########################################################################
if ($_POST['do'] == 'dobuildsitemap')
{
	$runner = new vB_SiteMapRunner_Admin($vbulletin);

	$status = $runner->check_environment();
	if ($status['error'])
	{
		print_stop_message2($status['error']);
	}

	echo '<div>' . construct_phrase($vbphrase['processing_x'], '...') . '</div>';
	vbflush();

	$runner->generate();

	if ($runner->is_finished)
	{
		$args = array();
		$args['do'] = 'buildsitemap';
		$args['success'] = 1;
		print_cp_redirect2('sitemap', $args, 1, 'admincp');
	}
	else
	{
		echo '<div>' . construct_phrase($vbphrase['processing_x'], $runner->written_filename) . '</div>';

		print_form_header('admincp/sitemap', 'dobuildsitemap', false, true, 'cpform_dobuildsitemap');
		print_submit_row($vbphrase['next_page'], 0);
		print_form_auto_submit('cpform_dobuildsitemap');
	}
}

// ########################################################################

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102830 $
|| #######################################################################
\*=========================================================================*/
