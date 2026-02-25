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

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 101129 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array('attachment_image');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/functions_file.php');
//require_once(DIR . '/packages/vbattach/attach.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminthreads'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################
$vbulletin->input->clean_array_gpc('r', array(
	'nodeid' => vB_Cleaner::TYPE_INT,
	'extension'    => vB_Cleaner::TYPE_STR,
	'attachpath'   => vB_Cleaner::TYPE_STR,
	'dowhat'       => vB_Cleaner::TYPE_STR,
));


log_admin_action(iif($vbulletin->GPC['nodeid'] != 0, 'node id = ' . $vbulletin->GPC['nodeid'],
	iif(!empty($vbulletin->GPC['extension']), "extension = " . $vbulletin->GPC['extension'], '')));

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################
$vboptions = vB::getDatastore()->getValue('options');

$vb5_config =& vB::getConfig();
$baseurl = vB::getDatastore()->getOption('frontendurl');

if ($vb5_config['report_all_php_errors'])
{
	@ini_set('display_errors', 'On');
}

print_cp_header($vbphrase['attachment_manager_gattachment_image']);

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'intro';
}

// ###################### Swap from database to file system and vice versa ##########
if ($_REQUEST['do'] == 'storage')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}
	if ($vboptions['attachfile'])
	{
		$options = array(
			'FS_to_DB' => $vbphrase['move_items_from_filesystem_into_database'],
			'FS_to_FS' => $vbphrase['move_items_to_a_different_directory']
		);
	}
	else
	{
		$options = array(
			'DB_to_FS' => $vbphrase['move_items_from_database_into_filesystem']
		);
	}

	$i = 0;
	$dowhat = '';
	foreach($options AS $value => $text)
	{
		$dowhat .= "<label for=\"dw$value\"><input type=\"radio\" name=\"dowhat\" id=\"dw$value\" value=\"$value\"" . iif($i++ == 0, ' checked="checked"') . " />$text</label><br />";
	}

	print_form_header('admincp/attachment', 'switchtype');
	print_table_header("$vbphrase[storage_type]: <span class=\"normal\">$vbphrase[attachments]</span>");
	if ($vboptions['attachfile'])
	{
		print_description_row(construct_phrase($vbphrase['attachments_are_currently_being_stored_in_the_filesystem_at_x'], '<b>' . $vboptions['attachpath'] . '</b>'));
	}
	else
	{
		print_description_row($vbphrase['attachments_are_currently_being_stored_in_the_database']);
	}
	print_label_row($vbphrase['action'], $dowhat);
	print_submit_row($vbphrase['go'], 0);

}

// ###################### Swap from database to file system and vice versa ##########
if ($_REQUEST['do'] == 'switchtype')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('r', array(
		'dowhat' 	=> vB_Cleaner::TYPE_STR
	));

	if ($vbulletin->GPC['dowhat'] == 'FS_to_DB')
	{
		// redirect straight through to attachment mover
		$vbulletin->GPC['attachpath'] = $vboptions['attachpath'];
		$vbulletin->GPC['dowhat'] = 'FS_to_DB';
		$_POST['do'] = 'doswitchtype';
	}
	else
	{
		if ($vbulletin->GPC['dowhat'] == 'FS_to_FS')
		{
			// show a form to allow user to specify file path
			print_form_header('admincp/attachment', 'doswitchtype');
			construct_hidden_code('dowhat', $vbulletin->GPC['dowhat']);
			print_table_header($vbphrase['move_items_to_a_different_directory']);
			print_description_row(construct_phrase($vbphrase['attachments_are_currently_being_stored_in_the_filesystem_at_x'], '<b>' . $vboptions['attachpath'] . '</b>'));
		}
		else
		{
			// show a form to allow user to specify file path
			print_form_header('admincp/attachment', 'doswitchtype');
			construct_hidden_code('dowhat', $vbulletin->GPC['dowhat']);
			print_table_header($vbphrase['move_items_from_database_into_filesystem']);
			print_description_row($vbphrase['attachments_are_currently_being_stored_in_the_database']);
		}

		print_input_row($vbphrase['attachment_file_path_dfn'], 'attachpath', $vboptions['attachpath']);
		print_submit_row($vbphrase['go']);
	}
}

// ############### Move files from database to file system and vice versa ###########
if ($_POST['do'] == 'doswitchtype')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}

	$vbulletin->GPC['attachpath'] = preg_replace('#[/\\\]+$#', '', $vbulletin->GPC['attachpath']);

	switch($vbulletin->GPC['dowhat'])
	{
		// #############################################################################
		// update attachment file path
		case 'FS_to_FS':
			if ($vbulletin->GPC['attachpath'] === $vboptions['attachpath'])
			{
				// new and old path are the same - show error
				print_stop_message2('invalid_file_path_specified');
			}
			else
			{
				// new and old paths are different - check the directory is valid
				verify_upload_folder($vbulletin->GPC['attachpath']);
				$oldpath = $vboptions['attachpath'];

				// update $vboptions
				vB_Api::instanceInternal('options')->updateAttachPath($vbulletin->GPC['attachpath']);
				$vboptions = vB::getDatastore()->getValue('options');

				// show message
				print_stop_message2(array('your_vb_settings_have_been_updated_to_store_attachments_in_x', $vbulletin->GPC['attachpath'], $oldpath));
			}

			break;

		// #############################################################################
		// move attachments from database to filesystem
		case 'DB_to_FS':
			// check path is valid
			verify_upload_folder($vbulletin->GPC['attachpath']);

			// update $vboptions
			vB_Api::instanceInternal('options')->updateAttachPath($vbulletin->GPC['attachpath']);
			$vboptions = vB::getDatastore()->getValue('options');

			break;
	}

	// #############################################################################

	print_form_header('admincp/attachment', 'domoveattachment');
	print_table_header($vbphrase['edit_storage_type']);
	construct_hidden_code('dowhat', $vbulletin->GPC['dowhat']);

	if ($vbulletin->GPC['dowhat'] == 'DB_to_FS')
	{
		print_description_row($vbphrase['we_are_ready_to_attempt_to_move_your_attachments_from_database_to_filesystem']);
	}
	else
	{
		print_description_row($vbphrase['we_are_ready_to_attempt_to_move_your_attachments_from_filesystem_to_database']);
	}

	print_input_row($vbphrase['number_of_attachments_to_process_per_cycle_gattachment_image'], 'perpage', 300, 1, 5);
	if ($vb5_config['Misc']['debug'])
	{
		print_input_row($vbphrase['attachmentid_start_at'], 'startat', 0, 1, 5);
	}
	print_submit_row($vbphrase['go']);
}

// ################### Move attachments ######################################
if ($_REQUEST['do'] == 'domoveattachment')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('r', array(
		'perpage'          => vB_Cleaner::TYPE_UINT,
		'startat'          => vB_Cleaner::TYPE_UINT,
		'attacherrorcount' => vB_Cleaner::TYPE_UINT,
		'count'            => vB_Cleaner::TYPE_UINT
	));

	if (is_demo_mode())
	{
		print_cp_message('This function is disabled within demo mode');
	}

	if ($vbulletin->GPC['perpage'] < 1)
	{
		$vbulletin->GPC['perpage'] = 10;
	}

	if (empty($vbulletin->GPC['startat'])) // Grab the first attachmentid so that we don't process a bunch of nonexistent ids to begin with.
	{
		$start = vB::getDbAssertor()->getRow('vBForum:fetchMinFiledataId');
		$vbulletin->GPC['startat'] = intval($start['min']);
	}
	$finishat = $vbulletin->GPC['startat'] + $vbulletin->GPC['perpage'];

	$assertor = vB::getDbAssertor();

	//these will be the same for both the filedata and filedataresize tables.
	//we should probably switch this to use a limit rather than a ID range.  Otherwise if
	//the IDs are sparse we end up with a large number of batches for a small number records.
	//But it's not exactly broken so don't want to touch it now.
	$conditions = array(
		array('field' => 'filedataid', 'value' => $vbulletin->GPC['startat'], 'operator' => vB_dB_Query::OPERATOR_GTE),
		array('field' => 'filedataid', 'value' => $finishat, 'operator' => vB_dB_Query::OPERATOR_LT),
	);

	$sort = array('field' => 'filedataid', 'direction' => vB_dB_Query::SORT_ASC);

	$filedataQry = $assertor->select('filedata', $conditions, $sort);
	$resizeQry = $assertor->select('filedataresize', $conditions, $sort);

	if ($vb5_config['Misc']['debug'])
	{
		echo '<table width="100%" border="1" cellspacing="0" cellpadding="1">
				<tr>
				<td><b>Filedata ID</b></td><td><b>Size in Database</b></td><td><b>Size in Filesystem</b></td>
				</tr>
			';
	}
	$attachments_count = 0;

	if ($resizeQry->valid())
	{
		$resizeData = $resizeQry->current();
	}
	else
	{
		$resizeData = array('filedataid' => 99999999);
	}
	$filedataLib = vB_Library::instance('filedata');
	$attachfile = vB::getDatastore()->getOption('attachfile');
	foreach ($filedataQry as $filedata)
	{
		$vbulletin->GPC['count']++;
		$attachments_count ++;
		$resize = array();
		$thumbnail_filesize = 0;

		//it should be impossible to ever have a resize filedataid less than the filedata filedataid, but let's just be over-cautious
		while (($resizeData['filedataid'] < $filedata['filedataid']) AND $resizeQry->valid())
		{
			$resizeQry->next();
			$resizeData = $resizeQry->current();
		}

		//Now get any resize records
		while (($resizeData['filedataid'] == $filedata['filedataid']) AND $resizeQry->valid())
		{
			$resize[] = $resizeData;

			if ($resizeData['resize_type'] == 'thumb')
			{
				$thumbnail_filesize = $resizeData['resize_filesize'];
			}
			$resizeQry->next();
			$resizeData = $resizeQry->current();
		}

		try
		{
			// This looks backwards but the value in question is the *current*
			// one that we want to change.
			// Converting FROM mysql TO fs
			if ($attachfile == ATTACH_AS_DB)
			{
				$result = $filedataLib->moveToFs($filedata, false, $resize);
			}
			// Converting FROM fs TO mysql
			else
			{
				$result = $filedataLib->moveToDb($filedata, false, $resize);
			}
		}
		catch(Exception $e)
		{
			$attacherror = $e->getMessage();
		}

		if ($vb5_config['Misc']['debug'])
		{
			$thumbsize = array();
			$resultsize = 0;

			//if we have an error we almost certainly don't have a result
			if(isset($result))
			{
				$resultsize = $result['filesize'];
				foreach ($result['resize_sizes'] AS $resizeType => $resizeSize)
				{
					$thumbsize[] = $resizeType . '=' . $resizeSize;
				}
			}
			$thumbsize = implode(', ', $thumbsize);

			echo "	<tr>
					<td>$filedata[filedataid]" . ($attacherror ? "<br />$attacherror" : '') . "</td>
					<td>$filedata[filesize]</td>
					<td>$resultsize ($thumbsize)</td>
					</tr>
					";
		}
		else
		{
			echo "$vbphrase[attachment] : <b>$filedata[filedataid]</b><br />";

			if ($attacherror)
			{
				echo "$vbphrase[attachment] : <b>$filedata[filedataid] $vbphrase[error]</b> $attacherror<br />";
			}
			vbflush();
		}
	}

	if ($vb5_config['Misc']['debug'])
	{
		echo '</table>';
		//vbflush();
	}
	$checkmore = $assertor->getRow('filedata', array(
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'filedataid', 'value' => $finishat, 'operator' => vB_dB_Query::OPERATOR_GTE)
		),
		vB_dB_Query::COLUMNS_KEY => array('filedataid'),
		vB_dB_Query::PARAM_LIMIT => 1,
	));

	$args = array(
		'do'=> 'domoveattachment',
		'startat' => $finishat,
		'pp' => $vbulletin->GPC['perpage'],
		'count' => $vbulletin->GPC['count'],
		'attacherrorcount' => $vbulletin->GPC['attacherrorcount']
	);

	if ($checkmore)
	{
		//this will exit
		print_cp_redirect2('attachment', $args, 2, 'admincp');
	}
	else
	{
		if ($attachments_count > 0)
		{
			//this will exit
			print_cp_redirect2('attachment', $args, 2, 'admincp');
		}
		$totalattach = $vbulletin->GPC['startat'] = vB::getDbAssertor()->getRow('vBForum:fetchTotalAttach');

		if ($vboptions['attachfile'] == ATTACH_AS_DB)
		{
			// Here we get a form that the user must continue on to delete the filedata column so that they are really sure to complete this step!
			print_form_header('admincp/attachment', 'confirmattachmentremove');
			print_table_header($vbphrase['confirm_attachment_removal']);
			print_description_row(construct_phrase($vbphrase['attachment_removal'], $totalattach['count'], $vbulletin->GPC['count'], $vbulletin->GPC['attacherrorcount']));

			if ($totalattach['count'] != $vbulletin->GPC['count'] OR !$vbulletin->GPC['count'] OR ($vbulletin->GPC['attacherrorcount'] / $vbulletin->GPC['count']) * 10 > 1)
			{
				$finalizeoption = false;
			}
			else
			{
				$finalizeoption = true;
			}

			print_yes_no_row($vbphrase['finalize'], 'removeattachments', $finalizeoption);
			print_submit_row($vbphrase['go']);

		}
		else
		{
			$filetype = $vboptions['attachfile'];
			// update $vboptions // attachments are now being read from and saved to the database
			vB_Api::instanceInternal('options')->updateAttachSetting(ATTACH_AS_DB);
			$vboptions = vB::getDatastore()->getValue('options');

			print_form_header('admincp/attachment', 'confirmfileremove');
			print_table_header($vbphrase['confirm_attachment_removal']);
			print_description_row(construct_phrase($vbphrase['file_removal'], $totalattach['count'], $vbulletin->GPC['count'], $vbulletin->GPC['attacherrorcount'],$vbphrase['go']));
			construct_hidden_code('attachtype', $filetype);
			print_submit_row($vbphrase['go']);
		}
	}
}

// ###################### Confirm emptying of filedata ##########
if ($_REQUEST['do'] == 'confirmfileremove')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('r', array(
		'startat'    => vB_Cleaner::TYPE_UINT,
		'perpage'    => vB_Cleaner::TYPE_UINT,
		'attachtype' => vB_Cleaner::TYPE_UINT,
	));

	if (empty($vbulletin->GPC['perpage']))
	{
		$vbulletin->GPC['perpage'] = 200;
	}

	$attachments = $assertor->assertQuery('filedata',
		array(
			vB_dB_Query::PARAM_LIMIT => $vbulletin->GPC['perpage'],
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'filedataid', 'value' => $vbulletin->GPC['startat'], 'operator' => vB_dB_Query::OPERATOR_GTE)
			),
			vB_dB_Query::COLUMNS_KEY => array('userid', 'filedataid'),
		),
		array('field' => 'filedataid', 'direction' => vB_dB_Query::SORT_ASC)
	);

	$filedataLib = vB_Library::instance('filedata');

	if ($attachments->valid())
	{
		foreach ($attachments AS $attachment)
		{
			$filedataLib->deleteFileDataFiles($attachment['userid'], $attachment['filedataid']);
		}

		$args =  array(
			'do'=> 'confirmfileremove',
			//start with the next id -- it doesn't matter if it doesn't actually exist.
			'startat' => $attachment['filedataid'] + 1,
			"pp" => $vbulletin->GPC['perpage'],
			"attachtype" => $vbulletin->GPC['attachtype'],
		);

		//this will exit.
		print_cp_redirect2('attachment', $args, 2, 'admincp');
	}
	else
	{
		$filedataLib->trimEmptyFiledataDirectories();
		print_stop_message2('attachments_moved_to_the_database', 'attachment', array('do' => 'stats'), null, true);
	}
}

// ###################### Confirm emptying of filedata ##########
if ($_REQUEST['do'] == 'confirmattachmentremove')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig') OR !vB::getUserContext()->hasAdminPermission('canadminthreads'))
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('r', array(
		'removeattachments' => vB_Cleaner::TYPE_BOOL,
		'startat'           => vB_Cleaner::TYPE_UINT,
		'perpage'           => vB_Cleaner::TYPE_UINT,
	));

	if ($vbulletin->GPC['removeattachments'])
	{
		if (empty($vbulletin->GPC['perpage']))
		{
			$vbulletin->GPC['perpage'] = 500;
		}

		if ($vbulletin->GPC['startat'] == 0)
		{
			// update $vboptions to attachments as files...
			// attachfile is only set to 1 to indicate the PRE 3.0.0 RC1 attachment FS behaviour
			vB_Api::instanceInternal('options')->updateAttachSetting(ATTACH_AS_FILES_NEW);
			$vboptions = vB::getDatastore()->getValue('options');
		}

		$assertor = vB::getDbAssertor();

		$attachments = $assertor->assertQuery('filedata',
			array(
				vB_dB_Query::PARAM_LIMIT => $vbulletin->GPC['perpage'],
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'filedataid', 'value' => $vbulletin->GPC['startat'], 'operator' => vB_dB_Query::OPERATOR_GTE)
				),
				vB_dB_Query::COLUMNS_KEY => array('userid', 'filedataid'),
			),
			array('field' => 'filedataid', 'direction' => vB_dB_Query::SORT_ASC)
		);

		if ($attachments->valid())
		{
			$attachmentids = array();
			foreach ($attachments as $attachment)
			{
				$attachmentids[] = $attachment['filedataid'];
			}
			$assertor->update('filedata', array('filedata' => ''), array('filedataid' => $attachmentids));
			$assertor->update('vBForum:filedataresize', array('resize_filedata' => ''), array('filedataid' => $attachmentids));

			$finishat = $vbulletin->GPC['startat'] + $vbulletin->GPC['perpage'];
			$args = array(
				'do'=> 'confirmattachmentremove',
				//start with the next id -- it doesn't matter if it doesn't actually exist.
				'startat' => $attachment['filedataid'] + 1,
				"pp" => $vbulletin->GPC['perpage'],
				"removeattachments" => 1
			);

			print_cp_redirect2('attachment', $args, 2, 'admincp');
		}
		else
		{
			// Again, make sure we are on attachments as files setting.
			vB_Api::instanceInternal('options')->updateAttachSetting(ATTACH_AS_FILES_NEW);
			print_stop_message2('attachments_moved_to_the_filesystem', 'attachment', array('do' => 'stats'), null, true);
		}
	}
	else
	{
		print_stop_message2('attachments_not_moved_to_the_filesystem', 'attachment', array('do' => 'stats'), null, true);
	}
}

// ###################### Search attachments ####################

$vbulletin->input->clean_array_gpc('r', array(
	'massdelete' => vB_Cleaner::TYPE_STR
));

if ($_REQUEST['do'] == 'search' AND $vbulletin->GPC['massdelete'])
{
	$vbulletin->input->clean_array_gpc('r', array(
		'a_delete' => vB_Cleaner::TYPE_ARRAY_UINT
	));

	// they hit the mass delete submit button
	if (!is_array($vbulletin->GPC['a_delete']))
	{
		// nothing in the array
		print_stop_message2('invalid_attachments_specified');
	}
	else
	{
		$_REQUEST['do'] = 'massdelete';
	}
}

// ###################### Actually search attachments ####################
if ($_REQUEST['do'] == 'search')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'search'     => vB_Cleaner::TYPE_ARRAY,
		'prevsearch' => vB_Cleaner::TYPE_STR,
		'prunedate'  => vB_Cleaner::TYPE_INT,
		'pagenum'    => vB_Cleaner::TYPE_INT,
		'next_page'  => vB_Cleaner::TYPE_STR,
		'prev_page'  => vB_Cleaner::TYPE_STR,
	));

	// for additional pages of results
	if ($vbulletin->GPC['prevsearch'])
	{
		$vbulletin->GPC['search'] = @unserialize(verify_client_string($vbulletin->GPC['prevsearch']));
	}
	else
	{
		$vbulletin->GPC['prevsearch'] = sign_client_string(serialize($vbulletin->GPC['search']));
	}

	//much of this is now handled internal in the function query due to security policy, but
	//it doesn't hurt much to do it twice.
	$search = array();
	$search['downloadsmore'] = intval($vbulletin->GPC['search']['downloadsmore']);
	$search['downloadsless'] = intval($vbulletin->GPC['search']['downloadsless']);
	$search['sizemore'] = intval($vbulletin->GPC['search']['sizemore']);
	$search['sizeless'] = intval($vbulletin->GPC['search']['sizeless']);
	$search['datelinebefore'] = $vbulletin->GPC['search']['datelinebefore'];
	$search['datelineafter'] = $vbulletin->GPC['search']['datelineafter'];


	// special case
	if ($vbulletin->GPC['prunedate'] > 0)
	{
		$search['datelinebefore'] = date('Y-m-d', TIMENOW - 86400 * $vbulletin->GPC['prunedate']);
	}

	$search['visible'] = (isset($vbulletin->GPC['search']['visible']) ? intval($vbulletin->GPC['search']['visible']) : -1);
	// error prevention
	if ($search['visible'] < -1 OR $search['visible'] > 1)
	{
		$search['visible'] = -1;
	}

	//this can't be right.  We do an "includes" on the username ... which potentially returns
	//multiples, but quietly only use the first one.
	if ($vbulletin->GPC['search']['attachedby'])
	{
		$user = vB::getDbAssertor()->getRow('user', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'username', 'value' => $vbulletin->GPC['search']['attachedby'], 'operator' => vB_dB_Query::OPERATOR_INCLUDES)
			)
		));
		if (empty($user))
		{
			print_stop_message2('invalid_user_specified');
		}
		else
		{
			$search['attachedbyuser'] = $user['userid'];
		}
	}

	$perPage = intval($vbulletin->GPC['search']['results']);
	if (!$perPage)
	{
		$perPage = 10;
	}


	if ($vbulletin->GPC['pagenum'] < 1)
	{
		$vbulletin->GPC['pagenum'] = 1;
	}

	if ($vbulletin->GPC['next_page'])
	{
		++$vbulletin->GPC['pagenum'];
	}
	else if ($vbulletin->GPC['prev_page'])
	{
		--$vbulletin->GPC['pagenum'];
	}


	$attachments = vB::getDbAssertor()->getRow('vBForum:searchAttach', array('search' => $search, 'countonly' => true));

	$pages = ceil($attachments['count'] / $perPage);
	if (!$pages)
	{
		$pages = 1;
	}

	print_form_header('admincp/attachment', 'search', 0, 1);
	construct_hidden_code('prevsearch', $vbulletin->GPC['prevsearch']);
	construct_hidden_code('prunedate', $vbulletin->GPC['prunedate']);
	construct_hidden_code('pagenum', $vbulletin->GPC['pagenum']);
	print_table_header(
		construct_phrase($vbphrase['showing_attachments_x_to_y_of_z'],
		($vbulletin->GPC['pagenum'] - 1) * $perPage + 1,
		min($perPage * $vbulletin->GPC['pagenum'], $attachments['count']),
		$attachments['count']),
		7
	);

	print_cells_row(array(
		'<input type="checkbox" name="allbox" title="' . $vbphrase['check_all'] . '" onclick="js_check_all(this.form);" />',
		$vbphrase['filename_gcpglobal'],
		$vbphrase['username'],
		$vbphrase['date'],
		$vbphrase['filesize_gattachment_image'],
		$vbphrase['downloads_gattachment_image'],
		$vbphrase['controls']
	), 1);

	//sort and orderby are validated internally to the query
	$attachments = vB::getDbAssertor()->assertQuery('vBForum:searchAttach', array(
		'search' => $search,
		vB_dB_Query::PARAM_LIMITSTART =>  (($vbulletin->GPC['pagenum'] - 1) * $perPage),
		vB_dB_Query::PARAM_LIMIT => $perPage,
		'sort' => $vbulletin->GPC['search']['orderby'],
		'direction' => $vbulletin->GPC['search']['ordering']
	));

	$string = vB::getString();

	$currentrow = 1;
	foreach ($attachments AS $attachment)
	{
		$index = "<input type=\"checkbox\" name=\"a_delete[]\" value=\"$attachment[nodeid]\" tabindex=\"1\" />";
		$cells = getAttachmentCells($vboptions, $vbphrase, $string, $attachment, $index, array('filesize', 'counter'));
		print_cells_row($cells);

		$currentrow++;
		if ($currentrow > $perPage)
		{
			break;
		}
	}
	print_description_row('<input type="submit" class="button" name="massdelete" value="' . $vbphrase['delete_selected_attachments'] . '" tabindex="1" />', 0, 7, '', 'center');

	if ($pages > 1 AND $vbulletin->GPC['pagenum'] < $pages)
	{
		print_table_footer(7, iif($vbulletin->GPC['pagenum'] > 1, "<input type=\"submit\" name=\"prev_page\" class=\"button\" tabindex=\"1\" value=\"$vbphrase[prev_page]\" accesskey=\"s\" />") . "\n<input type=\"submit\" name=\"next_page\" class=\"button\" tabindex=\"1\" value=\"$vbphrase[next_page]\" accesskey=\"s\" />");
	}
	else if ($vbulletin->GPC['pagenum'] == $pages AND $pages > 1)
	{
		print_table_footer(7, "<input type=\"submit\" name=\"prev_page\" class=\"button\" tabindex=\"1\" value=\"$vbphrase[prev_page]\" accesskey=\"s\" />");
	}
	else
	{
		print_table_footer(7);
	}
}

// ###################### Edit an attachment ####################
if ($_REQUEST['do'] == 'edit')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid' => vB_Cleaner::TYPE_UINT
	));

	if (!$attachment = vB::getDbAssertor()->getRow('vBForum:fetchAttach', array('nodeid' => $vbulletin->GPC['nodeid'])))
	{
		print_stop_message2('no_matches_found_gerror');
	}
	print_form_header('admincp/attachment', 'doedit', true);
	construct_hidden_code('nodeid', $vbulletin->GPC['nodeid']);
	print_table_header($vbphrase['edit_attachment']);
	print_input_row($vbphrase['filename_gcpglobal'], 'a_filename', $attachment['filename']);
	print_input_row($vbphrase['views'], 'a_counter', $attachment['counter']);
	print_yes_no_row($vbphrase['visible_gattachment_image'], 'a_visible', $attachment['visible']);
	print_submit_row($vbphrase['save']);

}

// ###################### Edit an attachment ####################
if ($_POST['do'] == 'doedit')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'nodeid' => vB_Cleaner::TYPE_UINT,
		'a_filename'   => vB_Cleaner::TYPE_STR,
		'a_counter'    => vB_Cleaner::TYPE_UINT,
		'a_visible'    => vB_Cleaner::TYPE_BOOL,
		'newvisible'   => vB_Cleaner::TYPE_BOOL,
		'url'          => vB_Cleaner::TYPE_STR,
	));

	if (!$attachment = vB::getDbAssertor()->getRow('vBForum:fetchAttach', array('nodeid' => $vbulletin->GPC['nodeid'])))
	{
		print_stop_message2('no_matches_found_gerror');
	}

	# Update Attachment
	vB_Api::instanceInternal('Content_Attach')->update($vbulletin->GPC['nodeid'], array(
			'filename' => $vbulletin->GPC['a_filename'],
			'visible' => $vbulletin->GPC['a_visible'],
			'counter' => $vbulletin->GPC['a_counter'],
			));

	print_stop_message2('updated_attachment_successfully', 'attachment', array('do'=>'stats'));
}

// ###################### Delete an attachment ####################
if ($_REQUEST['do'] == 'delete')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid' => vB_Cleaner::TYPE_INT
	));

	$attachment = vB::getDbAssertor()->getRow('vBForum:fetchAttach', array('nodeid' => $vbulletin->GPC['nodeid']));

	print_form_header('admincp/attachment', 'dodelete');
	construct_hidden_code('nodeid', $vbulletin->GPC['nodeid']);
	print_table_header($vbphrase['confirm_deletion_gcpglobal']);
	print_description_row(construct_phrase($vbphrase['are_you_sure_you_want_to_delete_the_attachment_x'], $attachment['filename'], $vbulletin->GPC['nodeid']));
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
}

// ###################### Do delete the attachment ####################
if ($_POST['do'] == 'dodelete')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'nodeid' => vB_Cleaner::TYPE_UINT
	));

	vB_Api::instanceInternal('Content_Attach')->delete($vbulletin->GPC['nodeid']);

	print_stop_message2('deleted_attachment_successfully', 'attachment', array('do'=>'intro'));

}

// ###################### Mass Delete attachments ####################
if ($_REQUEST['do'] == 'massdelete')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'a_delete' => vB_Cleaner::TYPE_ARRAY_UINT
	));

	print_form_header('admincp/attachment','domassdelete');
	construct_hidden_code('a_delete', sign_client_string(serialize($vbulletin->GPC['a_delete'])));
	print_table_header($vbphrase['confirm_deletion_gcpglobal']);
	print_description_row($vbphrase['are_you_sure_you_want_to_delete_these_attachments']);
	print_submit_row($vbphrase['yes'], '', 2, $vbphrase['no']);
}

// ###################### Mass Delete attachments ####################
if ($_POST['do'] == 'domassdelete')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'a_delete' => vB_Cleaner::TYPE_STR,
	));

	$delete = @unserialize(verify_client_string($vbulletin->GPC['a_delete']));
	if ($delete AND is_array($delete))
	{
		$api = vB_Api::instanceInternal('Content_Attach');
		foreach ($delete as $nodeid)
		{
			$api->delete($nodeid);
		}
	}

	print_stop_message2('deleted_attachments_successfully', 'attachment', array('do'=>'intro'));
}

// ###################### Statistics ####################
if ($_REQUEST['do'] == 'stats')
{

	$stat_column_count = 6;

	$astats = vB::getDbAssertor()->getRow('vBForum:fetchAttachStatsAvarage');
	$fstats = vB::getDbAssertor()->getRow('vBForum:fetchAttachStatsTotal');
	if ($astats['count'])
	{
		$astats['average'] = vb_number_format(($astats['totalsize'] / $astats['count']), 1, true);
	}
	else
	{
		$astats['average'] = '0.00';
	}

	print_form_header('admincp/', '');
	print_table_header($vbphrase['statistics_gcpglobal']);
	print_label_row($vbphrase['unique_total_attachments'], vb_number_format($astats['count']) . ' / ' . vb_number_format($fstats['count']));
	print_label_row($vbphrase['attachment_filesize_sum'], vb_number_format(iif(!$astats['totalsize'], 0, $astats['totalsize']), 1, true));
	print_label_row($vbphrase['disk_space_used'], vb_number_format(iif(!$fstats['totalsize'], 0, $fstats['totalsize']), 1, true));

	if ($vboptions['attachfile'])
	{
		print_label_row($vbphrase['storage_type'], construct_phrase($vbphrase['attachments_are_currently_being_stored_in_the_filesystem_at_x'], '<b>' . $vboptions['attachpath'] . '</b>'));
	}
	else
	{
		print_label_row($vbphrase['storage_type'], $vbphrase['attachments_are_currently_being_stored_in_the_database']);
	}

	print_label_row($vbphrase['average_attachment_filesize'], $astats['average']);
	print_label_row($vbphrase['total_downloads'], vb_number_format($astats['downloads']));
	print_table_break();


	print_table_header($vbphrase['five_most_popular_attachments'], $stat_column_count);
	print_cells_row(
		array(
			'',
			$vbphrase['filename_gcpglobal'],
			$vbphrase['username'],
			$vbphrase['date'],
			$vbphrase['downloads_gattachment_image'],
			'&nbsp;',
		),
	1);

	$string = vB::getString();

	if ($attachments = vB::getDbAssertor()->assertQuery('vBForum:fetchTopAttachmentsCounter'))
	{
		$position = 0;
		foreach ($attachments AS $attachment)
		{
			$position++;
			$cells = getAttachmentCells($vboptions, $vbphrase, $string, $attachment, $position . '.', 'counter');
			print_cells_row($cells);
		}
	}
	print_table_break();


	print_table_header($vbphrase['five_largest_attachments'], $stat_column_count);
	print_cells_row(
		array(
			'&nbsp;',
			$vbphrase['filename_gcpglobal'],
			$vbphrase['username'],
			$vbphrase['date'],
			$vbphrase['filesize_gattachment_image'],
			'&nbsp;',
		),
	1);

	if ($attachments = vB::getDbAssertor()->assertQuery('vBForum:fetchTopAttachmentsSize'))
	{
		$position = 0;
		foreach ($attachments AS $attachment)
		{
			$position++;
			$cells = getAttachmentCells($vboptions, $vbphrase, $string, $attachment, $position . '.', 'filesize');
			print_cells_row($cells);
		}
	}
	print_table_break();

	$content = array();
	$largestuser = vB::getDbAssertor()->assertQuery('vBForum:fetchAttachStatsLargestUser');

	print_table_header($vbphrase['five_users_most_attachment_space'], 5);
	print_cells_row(array('&nbsp;', $vbphrase['username'], $vbphrase['attachments'], $vbphrase['total_size_gattachment_image'], '&nbsp;'), 1);

	$position = 0;
	foreach ($largestuser as $thispop)
	{
		$userurl = 'admincp/user.php?do=edit&u=' . $thispop['userid'];
		$searchurl = 'attachment.php?do=search&search[attachedby]=' . urlencode($thispop['username']);

		$position++;
		$cell = array();
		$cell[] = $position . '.';
		$cell[] = '<a href="' . $string->htmlspecialchars($userurl) . '">' . $thispop['username']. '</a>';
		$cell[] = vb_number_format($thispop['count']);
		$cell[] = vb_number_format($thispop['totalsize'], 1, true);
		$cell[] = '<span class="smallfont">' . construct_link_code($vbphrase['view_attachments'], $string->htmlspecialchars($searchurl)) .	'</span>';
		print_cells_row($cell);
	}
	print_table_footer();
}

function getAttachmentCells($vboptions, $vbphrase, $string, $attachment, $index, $metricfields)
{
	$posturl = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $attachment['parentid']));

	$user = $attachment['authorname'];
	if($attachment['userid'])
	{
		$userurl = 'admincp/user.php?do=edit&u=' . $attachment['userid'];
		$user = '<a href="' . $string->htmlspecialchars($userurl) . '">' . $attachment['authorname'] . '</a>';
	}

	$fileurl = 'filedata/fetch?id=' . $attachment['nodeid'];

	if(!is_array($metricfields))
	{
		$metricfields = array($metricfields);
	}

	$cell = array();
	$cell[] = $index;
	$cell[] = '<a href="' . $string->htmlspecialchars($fileurl)  . '">' . $attachment['filename'] . '</a>';
	$cell[] = $user;
	$cell[] = vbdate($vboptions['dateformat'], $attachment['dateline']);

	foreach($metricfields AS $metricfield)
	{
		$cell[] = vb_number_format($attachment[$metricfield]);
	}

	$cell[] = '<span class="smallfont">' .
		construct_link_code($vbphrase['view_content_gattachment_image'], $string->htmlspecialchars($posturl), true, '', false, false) .
		construct_link_code($vbphrase['edit'], $string->htmlspecialchars("attachment.php?do=edit&nodeid=$attachment[nodeid]")) .
		construct_link_code($vbphrase['delete'], $string->htmlspecialchars("attachment.php?do=delete&nodeid=$attachment[nodeid]")) .
		'</span>';

	return $cell;
}

// ###################### Introduction ####################
if ($_REQUEST['do'] == 'intro')
{
	print_form_header('admincp/attachment', 'search');
	print_table_header($vbphrase['quick_search']);
	print_description_row("
	<ul style=\"margin:0px; padding:0px; list-style:none\">
		<li><a href=\"admincp/attachment.php?do=search&amp;search[orderby]=fd.filesize&amp;search[ordering]=DESC\">" . $vbphrase['view_largest_attachments'] . "</a></li>
		<li><a href=\"admincp/attachment.php?do=search&amp;search[orderby]=a.counter&amp;search[ordering]=DESC\">" . $vbphrase['view_most_popular_attachments'] . "</a></li>
		<li><a href=\"admincp/attachment.php?do=search&amp;search[orderby]=fd.dateline&amp;search[ordering]=DESC\">" . $vbphrase['view_newest_attachments'] . "</a></li>
		<li><a href=\"admincp/attachment.php?do=search&amp;search[orderby]=fd.dateline&amp;search[ordering]=ASC\">" . $vbphrase['view_oldest_attachments'] . "</a></li>
	</ul>
	");
	print_table_break();

	print_table_header($vbphrase['prune_attachments']);
	print_input_row($vbphrase['find_all_attachments_older_than_days'], 'prunedate', 30);
	print_submit_row($vbphrase['search'], 0);

	print_form_header('admincp/attachment', 'search');
	print_table_header($vbphrase['advanced_search']);
	print_input_row($vbphrase['filename_gcpglobal'], 'search[filename]');
	print_input_row($vbphrase['attached_by'], 'search[attachedby]');
	print_input_row($vbphrase['attached_before'], 'search[datelinebefore]');
	print_input_row($vbphrase['attached_after'], 'search[datelineafter]');
	print_input_row($vbphrase['downloads_greater_than'], 'search[downloadsmore]');
	print_input_row($vbphrase['downloads_less_than'], 'search[downloadsless]');
	print_input_row($vbphrase['filesize_greater_than'], 'search[sizemore]');
	print_input_row($vbphrase['filesize_less_than'], 'search[sizeless]');
	print_yes_no_other_row($vbphrase['attachment_is_visible_gattachment_image'], 'search[visible]', $vbphrase['either'], -1);

	print_label_row($vbphrase['order_by_gcpglobal'],'
		<select name="search[orderby]" tabindex="1" class="bginput">
			<option value="username">' . $vbphrase['attached_by'] . '</option>
			<option value="counter">' . $vbphrase['downloads_gattachment_image'] . '</option>
			<option value="filename" selected="selected">' . $vbphrase['filename_gcpglobal'] . '</option>
			<option value="filesize">' . $vbphrase['filesize_gattachment_image'] . '</option>
			<option value="dateline">' . $vbphrase['time'] . '</option>
			<option value="state">' . $vbphrase['visible_gattachment_image'] . '</option>
		</select>
		<select name="search[ordering]" tabindex="1" class="bginput">
			<option value="DESC">' . $vbphrase['descending'] . '</option>
			<option value="ASC">' . $vbphrase['ascending'] . '</option>
		</select>
	', '', 'top', 'orderby');
	print_input_row($vbphrase['attachments_to_show_per_page'], 'search[results]', 20);

	print_submit_row($vbphrase['search'], 0);
}

// ###################### File Types ####################
if ($_REQUEST['do'] == 'types')
{
	$types = vB::getDbAssertor()->assertQuery('vBForum:attachmenttype', array(), array('extension'));
	// a little javascript for the options menus
	?>
	<script type="text/javascript">
	<!--
	function js_attachment_jump(attachinfo)
	{
		if (attachinfo == '')
		{
			alert('<?php echo addslashes_js($vbphrase['please_select_attachment']); ?>');
			return;
		}
		else
		{
			action = eval("document.cpform.a" + attachinfo + ".options[document.cpform.a" + attachinfo + ".selectedIndex].value");
		}
		if (action != '')
		{
			switch (action)
			{
				case 'edit':   page = "admincp/attachment.php?do=updatetype&extension="; break;
				case 'remove': page = "admincp/attachment.php?do=removetype&extension="; break;
				case 'perms':  page = "admincp/attachmentpermission.php?do=modify&extension=";

					break;
			}
			document.cpform.reset();
			jumptopage = page + attachinfo + "&s=<?php echo vB::getCurrentSession()->get('sessionhash'); ?>";
			if (action == 'perms')
			{
				vBRedirect(jumptopage + '#a_' + attachinfo);
			}
			else
			{
				vBRedirect(jumptopage);
			}
		}
		else
		{
			alert('<?php echo addslashes_js($vbphrase['invalid_action_specified_gcpglobal']); ?>');
		}
	}
	//-->
	</script>
	<?php

	print_form_header('admincp/attachment', 'updatetype');
	print_table_header($vbphrase['attachment_manager_gattachment_image'], 5);
	print_cells_row(array(
		$vbphrase['extension'],
		$vbphrase['maximum_filesize'],
		$vbphrase['maximum_width'],
		$vbphrase['maximum_height'],
		$vbphrase['controls']
	), 1, 'tcat');

	$attachoptions = array(
		'edit'   => $vbphrase['edit'],
		'remove' => $vbphrase['delete'],
		'perms'  => $vbphrase['view_permissions_gattachment_image'],
	);

	//while ($type = $vbulletin->db->fetch_array($types))
	foreach ($types as $type)
	{
		$contenttype = unserialize($type['contenttypes']);
		$type['size'] = iif($type['size'], $type['size'], $vbphrase['none']);
		switch($type['extension'])
		{
			case 'gif':
			case 'bmp':
			case 'jpg':
			case 'jpeg':
			case 'jpe':
			case 'png':
			case 'psd':
			case 'tiff':
			case 'tif':
				$type['width'] = iif($type['width'], $type['width'], $vbphrase['none']);
				$type['height'] = iif($type['height'], $type['height'], $vbphrase['none']);
				break;
			default:
				$type['width'] = '&nbsp;';
				$type['height'] = '&nbsp;';
		}
		$cell = array();
		$cell[] = "<b>$type[extension]</b>";
		$cell[] = $type['size'];
		$cell[] = $type['width'];
		$cell[] = $type['height'];

		$cell[] = "\n\t<select name=\"a$type[extension]\" onchange=\"js_attachment_jump('$type[extension]');\" class=\"bginput\">\n" . construct_select_options($attachoptions) . "\t</select><input type=\"button\" class=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_attachment_jump('$type[extension]');\" />\n\t";
		print_cells_row($cell);
	}
	print_submit_row($vbphrase['add_new_extension'], 0, 5);
}

// ###################### File Types ####################
if ($_REQUEST['do'] == 'updatetype')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'extension' => vB_Cleaner::TYPE_STR
	));

	print_form_header('admincp/attachment', 'doupdatetype');

	if ($vbulletin->GPC['extension'])
	{ // This is an edit
		$type = vB::getDbAssertor()->getRow('vBForum:attachmenttype',array('extension' => $vbulletin->GPC['extension']));
		if ($type)
		{
			if ($type['mimetype'])
			{
				$type['mimetype'] = implode("\n", unserialize($type['mimetype']));
			}
			construct_hidden_code('extension', $type['extension']);
			print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['attachment_type'], $type['extension'], $type['extension']));
		}
	}
	else
	{
		$type = null;
	}

	if (!$type)
	{
		$type = array('enabled' => 1);
		print_table_header($vbphrase['add_new_extension']);
	}

	print_input_row($vbphrase['extension'], 'type[extension]', $type['extension']);
	print_input_row(construct_phrase($vbphrase['maximum_filesize_dfn']), 'type[size]', $type['size']);
	print_input_row($vbphrase['max_width_dfn'], 'type[width]', $type['width']);
	print_input_row($vbphrase['max_height_dfn'], 'type[height]', $type['height']);
	print_textarea_row($vbphrase['mime_type_dfn'], 'type[mimetype]', $type['mimetype']);

	// Legacy Hook 'admin_attachmenttype' Removed //

	// TODO: Move this to proper channel permissions
	// Enable/disable and new window options for each content type used to be here.

	print_submit_row($vbulletin->GPC['extension'] ? $vbphrase['update'] : $vbphrase['save'], '_default_', 4);
}

// ###################### Update File Type ####################
if ($_POST['do'] == 'doupdatetype')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'extension'   => vB_Cleaner::TYPE_STR,
		'type'        => vB_Cleaner::TYPE_ARRAY,
		'contenttype' => vB_Cleaner::TYPE_ARRAY,
		'default'     => vB_Cleaner::TYPE_ARRAY,
	));

	$vbulletin->GPC['type']['extension'] = preg_replace('#[^a-z0-9_]#i', '', $vbulletin->GPC['type']['extension']);
	$vbulletin->GPC['type']['extension'] = strtolower($vbulletin->GPC['type']['extension']);

	if (empty($vbulletin->GPC['type']['extension']))
	{
		print_stop_message2('please_complete_required_fields');
	}

	if ($vbulletin->GPC['extension'] != $vbulletin->GPC['type']['extension'] AND $test = vB::getDbAssertor()->getRow('vBForum:attachmenttype',array('extension' => $vbulletin->GPC['type']['extension'])))
	{
		print_stop_message2(array('name_exists', $vbphrase['filetype_gattachment_image'], htmlspecialchars($vbulletin->GPC['type']['extension'])));
	}

	if ($vbulletin->GPC['type']['mimetype'])
	{
		$mimetype = explode("\n", $vbulletin->GPC['type']['mimetype']);
		foreach($mimetype AS $index => $value)
		{
			$mimetype["$index"] = trim($value);
		}
	}
	else
	{
		// If the byte range output in application light is not working in iOS,
		// ensure that the correct mime type is set in the admin cp.
		// TODO: should we add default fallbacks here, so that if the admin
		// leaves it empty it will populate the headers field with a default
		// content-type header? The problem with that is it may not always
		// be the desired behavior.
		$mimetype = array('Content-type: unknown/unknown');
	}
	$vbulletin->GPC['type']['mimetype'] = serialize($mimetype);

	// TODO: Move this to proper channel permissions
	// In vB4, this was used to determine where attachments of this extension could be posted (forum, blogs, etc).
	// And whether or not they should open in new windows.

	if ($vbulletin->GPC['extension'])
	{
		vB::getDbAssertor()->update('vBForum:attachmenttype',$vbulletin->GPC['type'], array('extension' => $vbulletin->GPC['extension']));
		build_attachment_permissions();
	}
	else
	{
		/*insert query*/
		vB::getDbAssertor()->insert('vBForum:attachmenttype',array(
				'extension' => $vbulletin->GPC['type']['extension'],
				'size' => intval($vbulletin->GPC['type']['size']),
				'height' => intval($vbulletin->GPC['type']['height']),
				'width' => intval($vbulletin->GPC['type']['width']),
				'mimetype' => $vbulletin->GPC['type']['mimetype'],
				'contenttypes' => serialize(array()),
		));

		build_attachment_permissions();
	}

	print_stop_message2(array('saved_attachment_type_x_successfully',  $vbulletin->GPC['type']['extension']), 'attachment', array('do'=>'types'));
}

// ###################### Remove File Type ####################
if ($_REQUEST['do'] == 'removetype')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'extension' => vB_Cleaner::TYPE_STR
	));

	print_form_header('admincp/attachment', 'killtype', 0, 1, '', '75%');
	construct_hidden_code('extension', $vbulletin->GPC['extension']);
	print_table_header(construct_phrase($vbphrase['confirm_deletion_of_attachment_type_x'], $vbulletin->GPC['extension']));
	print_description_row("
		<blockquote><br />".
		construct_phrase($vbphrase['are_you_sure_you_want_to_delete_the_attachment_type_x'], $vbulletin->GPC['extension'])."
		<br /></blockquote>\n\t");
	print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);
}

// ###################### Kill File Type ####################
if ($_POST['do'] == 'killtype')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'extension' => vB_Cleaner::TYPE_STR
	));
	vB::getDbAssertor()->delete('vBForum:attachmenttype',array('extension' => $vbulletin->GPC['extension']));
	vB::getDbAssertor()->delete('vBForum:attachmentpermission',array('extension' => $vbulletin->GPC['extension']));

	build_attachment_permissions();

	print_stop_message2('deleted_attachment_type_successfully', 'attachment', array('do'=>'types'));
}

// ###################### Requild Attachment ####################
if ($_REQUEST['do'] == 'rebuild')
{
	$vbulletin->input->clean_array_gpc('r', array(
			'type' => vB_Cleaner::TYPE_STR
	));

	if ($vbulletin->GPC['type']== 'all')
	{
		vB::getDbAssertor()->update('vBForum:filedataresize', array('reload' => 1), vB_dB_Query::CONDITION_ALL);
	}
	elseif (in_array(strtolower($vbulletin->GPC['type']), array('icon', 'thumb', 'small', 'medium', 'large')))
	{
		vB::getDbAssertor()->update('vBForum:filedataresize', array('reload' => 1), array('resize_type' => strtolower($vbulletin->GPC['type'])));
	}
	else
	{
		print_stop_message2(array('invalid_attachment_type_x', $vbulletin->GPC['type']));
	}
	print_stop_message2('attachment_rebuild_successful', 'options', array('do'=>'options', 'dogroup' => 'attachment'));
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101129 $
|| #######################################################################
\*=========================================================================*/
