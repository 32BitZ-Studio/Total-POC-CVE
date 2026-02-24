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

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;
$phrasegroups = array('sql', 'user', 'cpuser');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

$vbulletin->input->clean_array_gpc('r', array('query' => vB_Cleaner::TYPE_STR));

// ############################# LOG ACTION ###############################
log_admin_action(!empty($vbulletin->GPC['query']) ? "query = '" . htmlspecialchars_uni($vbulletin->GPC['query']) . "'" : '');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();

print_cp_header($vbphrase['execute_sql_query_gsql']);

if (!$vb5_config['Misc']['debug'])
{
	$userids = explode(',', str_replace(' ', '', $vb5_config['SpecialUsers']['canrunqueries']));
	if (!in_array($vbulletin->userinfo['userid'], $userids))
	{
		print_stop_message2('no_permission_queries');
	}
}

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'modify';
}

// define auto queries
$queryoptions = array(
	'-1'  => '',
	$vbphrase['all_users'] => array(
		'10'  => $vbphrase['yes'] . ' - ' . $vbphrase['invisible_mode_gsql'],
		'80'  => $vbphrase['no'] . ' - ' . $vbphrase['invisible_mode_gsql'],

		'30'  => $vbphrase['yes'] . ' - ' . $vbphrase['receive_admin_emails_gsql'],
		'100' => $vbphrase['no'] . ' - ' . $vbphrase['receive_admin_emails_gsql'],

		'50'  => $vbphrase['yes'] . ' - ' . $vbphrase['receive_private_messages_gsql'],
		'120' => $vbphrase['no'] . ' - ' . $vbphrase['receive_private_messages_gsql'],

		'60'  => $vbphrase['yes'] . ' - ' . $vbphrase['send_notification_email_when_a_private_message_is_received_gsql'],
		'130' => $vbphrase['no'] . ' - ' . $vbphrase['send_notification_email_when_a_private_message_is_received_gsql'],

		'65'  => $vbphrase['yes'] . ' - ' . $vbphrase['send_birthday_email_gsql'],
		'135' => $vbphrase['no'] . ' - ' . $vbphrase['send_birthday_email_gsql'],

		'70'  => $vbphrase['yes'] . ' - ' . $vbphrase['pop_up_notification_box_when_a_private_message_is_received'],
		'140' => $vbphrase['no'] . ' - ' . $vbphrase['pop_up_notification_box_when_a_private_message_is_received'],

		'150' => $vbphrase['on'] . ' - ' . $vbphrase['display_signatures_gsql'],
		'180' => $vbphrase['off'] . ' - ' . $vbphrase['display_signatures_gsql'],

		'160' => $vbphrase['on'] . ' - ' . $vbphrase['display_avatars_gsql'],
		'190' => $vbphrase['off'] . ' - ' . $vbphrase['display_avatars_gsql'],

		'170' => $vbphrase['on'] . ' - ' . $vbphrase['display_images_gsql'],
		'200' => $vbphrase['off'] . ' - ' . $vbphrase['display_images_gsql'],

		'175' => $vbphrase['on'] . ' - ' . $vbphrase['display_reputation_gsql'],
		'205' => $vbphrase['off'] . ' - ' . $vbphrase['display_reputation_gsql'],

		'blank1' => '',

		'210' => $vbphrase['on'] . ' - ' . $vbphrase['autosubscribe_when_posting'],
		'211' => $vbphrase['off'] . ' - ' . $vbphrase['autosubscribe_when_posting'],

		'blank2' => '',

		'220' => $vbphrase['usersetting_emailnotification'] . ' - ' . $vbphrase['usersetting_emailnotification_none'],
		'230' => $vbphrase['usersetting_emailnotification'] . ' - ' . $vbphrase['usersetting_emailnotification_on'],
		'240' => $vbphrase['usersetting_emailnotification'] . ' - ' . $vbphrase['usersetting_emailnotification_daily'],
		'250' => $vbphrase['usersetting_emailnotification'] . ' - ' . $vbphrase['usersetting_emailnotification_weekly'],

		'blank3' => '',

		'270' => $vbphrase['thread_display_mode_gsql'] . ' - ' . $vbphrase['linear'],
		'280' => $vbphrase['thread_display_mode_gsql'] . ' - ' . $vbphrase['threaded'],
		'290' => $vbphrase['thread_display_mode_gsql'] . ' - ' . $vbphrase['hybrid'],

		'blank4' => '',

		'300' => $vbphrase['do_not_show_editor_toolbar'],
		'310' => $vbphrase['show_standard_editor_toolbar_gsql'],
		'320' => $vbphrase['show_enhanced_editor_toolbar_gsql'],
	),
);

// Legacy Hook 'admin_queries_auto_options' Removed //

// ##################### START DO QUERY #####################

if ($_POST['do'] == 'doquery')
{
	require_once(DIR . '/includes/functions_misc.php');

	$vbulletin->input->clean_array_gpc('p', array(
		'autoquery'    => vB_Cleaner::TYPE_UINT,
		'perpage'      => vB_Cleaner::TYPE_UINT,
		'pagenumber'   => vB_Cleaner::TYPE_UINT,
		'confirmquery' => vB_Cleaner::TYPE_BOOL
	));

	$query =& $vbulletin->GPC['query'];

	if ($vbulletin->GPC['pagenumber'] < 1)
	{
		$vbulletin->GPC['pagenumber'] = 1;
	}

	if (!$vbulletin->GPC['perpage'])
	{
		$vbulletin->GPC['perpage'] = 20;
	}

	if (!$vbulletin->GPC['confirmquery'])
	{
		if (!$vbulletin->GPC['autoquery'] AND !$query)
		{
			print_stop_message2('please_complete_required_fields');
		}

		if ($vbulletin->GPC['autoquery'])
		{
			switch($vbulletin->GPC['autoquery'])
			{
				case 10:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['invisible'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['invisible'] . ")";
					break;
				case 30:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['adminemail'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['adminemail'] . ")";
					break;
				case 50:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['receivepm'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['receivepm'] . ")";
					break;
				case 60:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['emailonpm'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['emailonpm'] . ")";
					break;
				case 65:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['birthdayemail'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['birthdayemail'] . ")";
					break;
				case 70:
					$query = "UPDATE " . TABLE_PREFIX . "user SET pmpopup = 1";
					break;
				case 80:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['invisible'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['invisible'];
					break;
				case 100:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['adminemail'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['adminemail'];
					break;
				case 120:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['receivepm'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['receivepm'];
					break;
				case 130:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['emailonpm'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['emailonpm'];
					break;
				case 135:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['birthdayemail'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['birthdayemail'];
					break;
				case 140:
					$query = "UPDATE " . TABLE_PREFIX . "user SET pmpopup = 0";
					break;
				case 150:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['showsignatures'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['showsignatures'] . ")";
					break;
				case 160:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['showavatars'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['showavatars'] . ")";
					break;
				case 170:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['showimages'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['showimages'] . ")";
					break;
				case 175:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options + " . $vbulletin->bf_misc_useroptions['showreputation'] . " WHERE NOT (options & " . $vbulletin->bf_misc_useroptions['showreputation'] . ")";
					break;
				case 180:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['showsignatures'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['showsignatures'];
					break;
				case 190:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['showavatars'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['showavatars'];
					break;
				case 200:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['showimages'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['showimages'];
					break;
				case 205:
					$query = "UPDATE " . TABLE_PREFIX . "user SET options = options - " . $vbulletin->bf_misc_useroptions['showreputation'] . " WHERE options & " . $vbulletin->bf_misc_useroptions['showreputation'];
					break;
				case 210:
					$query = "UPDATE " . TABLE_PREFIX . "user SET autosubscribe = 1";
					break;
				case 211:
					$query = "UPDATE " . TABLE_PREFIX . "user SET autosubscribe = 0";
					break;
				case 220:
					$query = "UPDATE " . TABLE_PREFIX . "user SET emailnotification = 0";
					break;
				case 230:
					$query = "UPDATE " . TABLE_PREFIX . "user SET emailnotification = 1";
					break;
				case 240:
					$query = "UPDATE " . TABLE_PREFIX . "user SET emailnotification = 2";
					break;
				case 250:
					$query = "UPDATE " . TABLE_PREFIX . "user SET emailnotification = 3";
					break;
				case 270:
					$query = "UPDATE " . TABLE_PREFIX . "user SET threadedmode = 0";
					break;
				case 280:
					$query = "UPDATE " . TABLE_PREFIX . "user SET threadedmode = 1";
					break;
				case 290:
					$query = "UPDATE " . TABLE_PREFIX . "user SET threadedmode = 2";
					break;
				case 300:
					$query = "UPDATE " . TABLE_PREFIX . "user SET showvbcode = 0";
					break;
				case 310:
					$query = "UPDATE " . TABLE_PREFIX . "user SET showvbcode = 1";
					break;
				case 320:
					$query = "UPDATE " . TABLE_PREFIX . "user SET showvbcode = 2";
					break;
				default:
					// Legacy Hook 'admin_queries_auto_query' Removed //
			}
		}
	}

	if (substr($query, -1) == ';')
	{
		$query = substr($query, 0, -1);
	}
	$vbulletin->db->hide_errors();

	$queryid = $vbulletin->GPC['autoquery'];

	$auto_query_text = '';
	if ($queryid)
	{
		foreach ($queryoptions AS $query_group => $queries)
		{
			if (!is_array($queries))
			{
				continue;
			}

			if(isset($queries[$queryid]))
			{
				$auto_query_text = ' (' . $queries[$queryid] . ')';
				break;
			}
		}
	}

	print_form_header('admincp/', '');
	print_table_header($vbphrase['query'] . $auto_query_text);
	print_description_row('<code>' . nl2br(htmlspecialchars_uni($query)) . '</code>', 0, 2, '');
	print_description_row(construct_button_code($vbphrase['restart'], 'admincp/queries.php?' . vB::getCurrentSession()->get('sessionurl')), 0, 2, 'tfoot', 'center');
	print_table_footer();

	$query_stripped = preg_replace('@/\*.*?\*/@s', '', $query);
	$query_stripped = preg_replace('@(#|--).*?$@m', '', $query_stripped);

	preg_match('#^([A-Z]+)\s#si', trim($query_stripped), $regs);
	$querytype = strtoupper($regs[1]);

	switch ($querytype)
	{
		// EXPLAIN, SELECT, DESCRIBE & SHOW **********************************************************
		case 'EXPLAIN':
		case 'SELECT':
		case 'DESCRIBE':
		case 'SHOW':
			$query_mod = preg_replace('#\sLIMIT\s+(\d+(\s*,\s*\d+)?)#i', '', $query);

			$counter = $vbulletin->db->query_write($query_mod);
			print_form_header('admincp/queries', 'doquery', 0, 1, 'queryform');
			construct_hidden_code('do', 'doquery');
			construct_hidden_code('query', $query);
			construct_hidden_code('perpage', $vbulletin->GPC['perpage']);
			if ($errornum = $vbulletin->db->errno())
			{
				print_table_header($vbphrase['vbulletin_message']);
				print_description_row(construct_phrase($vbphrase['an_error_occurred_while_attempting_to_run_your_query'], $errornum, nl2br(htmlspecialchars_uni($vbulletin->db->error()))));
				$extras = '';
			}
			else
			{
				$numrows = $vbulletin->db->num_rows($counter);
				if ($vbulletin->GPC['pagenumber'] == -1)
				{
					$vbulletin->GPC['pagenumber'] = ceil($numrows / $vbulletin->GPC['perpage']);
				}
				$startat = ($vbulletin->GPC['pagenumber'] - 1) * $vbulletin->GPC['perpage'];
				if ($querytype == 'SELECT')
				{
					$query_mod = "$query_mod LIMIT $startat, " . $vbulletin->GPC['perpage'];
					$numpages = ceil($numrows / $vbulletin->GPC['perpage']);
				}
				else
				{
					$query_mod = $query;
					$numpages = 1;
				}

				$time_before = microtime();
				$result = $vbulletin->db->query_write($query_mod);
				$time_taken = fetch_microtime_difference($time_before);

				$colcount = $vbulletin->db->num_fields($result);
				print_table_header(construct_phrase($vbphrase['results_x_y'], vb_number_format($numrows), vb_number_format($time_taken, 4)) . ', ' . construct_phrase($vbphrase['page_x_of_y'], $vbulletin->GPC['pagenumber'], $numpages), $colcount);
				if ($numrows)
				{
					$collist = array();
					for ($i = 0; $i < $colcount; $i++)
					{
						$collist[] = $vbulletin->db->field_name($result, $i);
					}
					print_cells_row($collist, 1);

					while ($record = $vbulletin->db->fetch_array($result))
					{
						foreach ($record AS $colname => $value)
						{
							$record["$colname"] = htmlspecialchars_uni($value);
						}
						print_cells_row($record, 0, '', -$colcount);
					}

					if ($numpages > 1)
					{
						$extras = '<b>' . $vbphrase['page_gcpglobal'] . '</b> <select name="page" tabindex="1" onchange="document.queryform.submit();" class="bginput">';
						for ($i = 1; $i <= $numpages; $i++)
						{
							$selected = iif($i == $vbulletin->GPC['pagenumber'], 'selected="selected"');
							$extras .= "<option value=\"$i\" $selected>$i</option>";
						}
						$extras .= '</select> <input type="submit" class="button" tabindex="1" value="' . $vbphrase['go'] . '" accesskey="s" />';
					}
					else
					{
						$extras = '';
					}
				}
				else
				{
					$extras = '';
				}
			}
			print_table_footer($colcount, $extras);
			break;

		// queries that perform data changes **********************************************************
		case 'UPDATE':
		case 'INSERT':
		case 'REPLACE':
		case 'DELETE':
		case 'ALTER':
		case 'CREATE':
		case 'DROP':
		case 'RENAME':
		case 'TRUNCATE':
		case 'LOAD':
		default:
			if (!$vbulletin->GPC['confirmquery'])
			{
				print_form_header('admincp/queries', 'doquery');
				construct_hidden_code('do', 'doquery');
				construct_hidden_code('query', $query);
				construct_hidden_code('perpage', $vbulletin->GPC['perpage']);
				construct_hidden_code('confirmquery', 1);
				print_table_header($vbphrase['confirm_query_execution']);
				print_description_row($vbphrase['query_may_modify_database']);
				print_submit_row($vbphrase['continue'], false, 2, $vbphrase['go_back']);
			}
			else
			{
				$time_before = microtime();
				$vbulletin->db->query_write($query);
				$time_taken = fetch_microtime_difference($time_before);

				print_form_header('admincp/queries', 'doquery');
				print_table_header($vbphrase['vbulletin_message']);
				if ($errornum = $vbulletin->db->errno())
				{
					print_description_row(construct_phrase($vbphrase['an_error_occurred_while_attempting_to_run_your_query'], $errornum, nl2br(htmlspecialchars_uni($vbulletin->db->error()))));
				}
				else
				{
					print_description_row(construct_phrase($vbphrase['affected_rows'], vb_number_format($vbulletin->db->affected_rows()), vb_number_format($time_taken, 4)));
				}
				print_table_footer();
			}
			break;
	}
}

// ##################### START MODIFY #####################
if ($_REQUEST['do'] == 'modify')
{
	print_form_header('admincp/queries', 'doquery');
	print_table_header($vbphrase['execute_sql_query_gsql']);
	print_select_row($vbphrase['auto_query'], 'autoquery', $queryoptions, -1);
	print_textarea_row($vbphrase['manual_query'], 'query', '', 10, 55, true, false);
	print_input_row($vbphrase['results_to_show_per_page'], 'perpage', 20);
	print_submit_row($vbphrase['continue']);
	$bburl = vB::getDatastore()->getOption('bburl');
	?>
	<script src="core/clientscript/codemirror/lib/codemirror.js?v=<?php echo SIMPLE_VERSION ?>"></script>
	<link rel="stylesheet" href="core/clientscript/codemirror/lib/codemirror.css?v=<?php echo SIMPLE_VERSION ?>">
	<script src="core/clientscript/codemirror/mode/sql/sql.js?v=<?php echo SIMPLE_VERSION ?>"></script>
	<script src="core/clientscript/codemirror/addon/fold/foldcode.js?v=<?php echo SIMPLE_VERSION ?>"></script>
	<script type="text/javascript">
	<!--

	window.onload = function() {
		setUpCodeMirror({
			textarea_id : "<?php echo $vbulletin->textarea_id; ?>",
			phrase_fullscreen : "<?php echo $vbphrase['fullscreen']; ?>",
			mode:'text/x-mysql'
			})
	};

	//-->
	</script>

<?php
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102796 $
|| #######################################################################
\*=========================================================================*/
