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
define('CVS_REVISION', '$RCSfile$ - $Revision: 103556 $');
define('NOZIP', 1);

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array('diagnostic');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
$canUseAll = (bool)  vB::getUserContext()->hasAdminPermission('canuseallmaintenance');

if (!$canUseAll AND ! vB::getUserContext()->hasAdminPermission('canadminmaintain') AND
	!(($_REQUEST['do'] == 'payments') AND vB::getUserContext()->hasAdminPermission('canadminusers')))
{
	print_cp_no_permission();
}


// ############################# LOG ACTION ###############################
log_admin_action();

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();

// ###################### Start maketestresult #######################
function print_diagnostic_test_result($status, $reasons = array(), $exit = 1)
{
	// $status values = -1: indeterminate; 0: failed; 1: passed
	// $reasons a list of reasons why the test passed/failed
	// $exit values = 0: continue execution; 1: stop here
	global $vbphrase;

	print_form_header('admincp/', '');

	print_table_header($vbphrase['results']);

	if (is_array($reasons))
	{
		foreach ($reasons AS $reason)
		{
			print_description_row($reason);
		}
	}
	else if (!empty($reasons))
	{
		print_description_row($reasons);
	}

	print_table_footer();

	if ($exit == 1)
	{
		print_cp_footer();
	}
}

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'list';
}

print_cp_header($vbphrase['diagnostics']);
print_cp_description($vbphrase, 'diagnostic', $_REQUEST['do']);


// ###################### Start upload test #######################
if ($_POST['do'] == 'doupload')
{
	// additional checks should be added with testing on other OS's (Windows doesn't handle safe_mode the same as Linux).
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('f', array(
		'attachfile' => vB_Cleaner::TYPE_FILE
	));
	scanVbulletinGPCFile('attachfile');

	print_form_header('admincp/', '');
	print_table_header($vbphrase['pertinent_php_settings']);

	$file_uploads = ini_get('file_uploads');
	print_label_row('file_uploads:', $file_uploads == 1 ? $vbphrase['on'] : $vbphrase['off']);

	print_label_row('open_basedir:', iif($open_basedir = ini_get('open_basedir'), $open_basedir, '<i>' . $vbphrase['none'] . '</i>'));
	print_label_row('upload_tmp_dir:', iif($upload_tmp_dir = ini_get('upload_tmp_dir'), $upload_tmp_dir, '<i>' . $vbphrase['none'] . '</i>'));
	require_once(DIR . '/includes/functions_file.php');
	print_label_row('upload_max_filesize:', vb_number_format(fetch_max_upload_size(), 1, true));
	print_table_footer();

	if (sizeof($_FILES) == 0)
	{
		if ($file_uploads === 0)
		{ // don't match NULL
			print_diagnostic_test_result(0, $vbphrase['file_upload_setting_off']);
		}
		else
		{
			print_diagnostic_test_result(0, $vbphrase['unknown_error']);
		}
	}

	if (empty($vbulletin->GPC['attachfile']['tmp_name']))
	{
		$errorMsg = construct_phrase(
			$vbphrase['no_file_uploaded_and_no_local_file_found_gcpglobal'],
			$vbphrase['test_cannot_continue']
		);
		if (isset($vbulletin->GPC['attachfile']['error']))
		{
			$errorMsg .= '<br />' . construct_phrase(
				$vbphrase['upload_file_failed_php_error_x_phplink'],
				intval($vbulletin->GPC['attachfile']['error'])
			);
		}
		print_diagnostic_test_result(0, $errorMsg);
	}

	// do not use file_exists here, under IIS it will return false in some cases
	if (!is_uploaded_file($vbulletin->GPC['attachfile']['tmp_name']))
	{
		print_diagnostic_test_result(0, construct_phrase($vbphrase['unable_to_find_attached_file'], $vbulletin->GPC['attachfile']['tmp_name'], $vbphrase['test_cannot_continue']));
	}

	$fp = @fopen($vbulletin->GPC['attachfile']['tmp_name'], 'rb');
	if (!empty($fp))
	{
		@fclose($fp);
		if ($vbulletin->options['safeupload'])
		{
			$safeaddntl = $vbphrase['turn_safe_mode_option_off'];
		}
		else
		{
			$safeaddntl = '';
		}
		print_diagnostic_test_result(1, $vbphrase['no_errors_occurred_opening_upload']. ' ' . $safeaddntl);
	} // we had problems opening the file as is, but we need to run the other tests before dying

	if ($vbulletin->options['safeupload'])
	{
		if ($vbulletin->options['tmppath'] == '')
		{
			print_diagnostic_test_result(0, $vbphrase['safe_mode_enabled_no_tmp_dir']);
		}
		else if (!is_dir($vbulletin->options['tmppath']))
		{
			print_diagnostic_test_result(0, construct_phrase($vbphrase['safe_mode_dir_not_dir'], $vbulletin->options['tmppath']));
		}
		else if (!is_writable($vbulletin->options['tmppath']))
		{
			print_diagnostic_test_result(0, construct_phrase($vbphrase['safe_mode_not_writeable'], $vbulletin->options['tmppath']));
		}
		$copyto = $vbulletin->options['tmppath'] . '/' . $vbulletin->session->fetch_sessionhash();
		if ($result = @move_uploaded_file($vbulletin->GPC['attachfile']['tmp_name'], $copyto))
		{
			$fp = @fopen($copyto , 'rb');
			if (!empty($fp))
			{
				@fclose($fp);
				print_diagnostic_test_result(1, $vbphrase['file_copied_to_tmp_dir_now_readable']);
			}
			else
			{
				print_diagnostic_test_result(0, $vbphrase['file_copied_to_tmp_dir_now_unreadable']);
			}
			@unlink($copyto);
		}
		else
		{
			print_diagnostic_test_result(0, construct_phrase($vbphrase['unable_to_copy_attached_file'], $copyto));
		}
	}

	if ($open_basedir)
	{
		print_diagnostic_test_result(0, construct_phrase($vbphrase['open_basedir_in_effect'], $open_basedir));
	}

	print_diagnostic_test_result(-1, $vbphrase['test_indeterminate_contact_host']);
}

// ###################### Start mail test #######################
if ($_POST['do'] == 'domail')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'emailaddress' => vB_Cleaner::TYPE_STR,
	));

	print_form_header('admincp/', '');
	if ($vbulletin->options['use_smtp'])
	{
		print_table_header($vbphrase['pertinent_smtp_settings']);
		$smtp_tls = '';
		switch ($vbulletin->options['smtp_tls'])
		{
			case 'ssl':
				$smtp_tls = 'ssl://';
				break;
			case 'tls':
				$smtp_tls = 'tls://';
				break;
			default:
				$smtp_tls = '';
		}

		print_label_row('SMTP:', $smtp_tls . $vbulletin->options['smtp_host'] . ':' . (!empty($vbulletin->options['smtp_port']) ? intval($vbulletin->options['smtp_port']) : 25));
		print_label_row($vbphrase['smtp_username'], $vbulletin->options['smtp_user']);
	}
	else
	{
		print_table_header($vbphrase['pertinent_php_settings']);
		print_label_row('SMTP:', iif($SMTP = @ini_get('SMTP'), $SMTP, '<i>' . $vbphrase['none'] . '</i>'));
		print_label_row('sendmail_from:', iif($sendmail_from = @ini_get('sendmail_from'), $sendmail_from, '<i>' . $vbphrase['none'] . '</i>'));
		print_label_row('sendmail_path:', iif($sendmail_path = @ini_get('sendmail_path'), $sendmail_path, '<i>' . $vbphrase['none'] . '</i>'));
	}
	print_table_footer();

	$emailaddress = $vbulletin->GPC['emailaddress'];

	if (empty($emailaddress))
	{
		print_diagnostic_test_result(0, fetch_error('please_complete_required_fields'));
	}

	if (!is_valid_email($emailaddress))
	{
		print_diagnostic_test_result(0, $vbphrase['invalid_email_specified']);
	}

	$subject = ($vbulletin->options['needfromemail'] ? $vbphrase['vbulletin_email_test_withf'] : $vbphrase['vbulletin_email_test']);
	$message = construct_phrase($vbphrase['vbulletin_email_test_msg'], $vbulletin->options['bbtitle']);

	$mail = vB_Mail::fetchLibrary();
	$mail->setDebug(true);
	$mail->start($emailaddress, $subject, $message, $vbulletin->options['webmasteremail']);

	// error handling
	@ini_set('display_errors', true);
	if (strpos(@ini_get('disable_functions'), 'ob_start') !== false)
	{
		// alternate method in case OB is disabled; probably not as fool proof
		@ini_set('track_errors', true);
		$oldlevel = error_reporting(0);
	}
	else
	{
		ob_start();
	}

	$mailreturn = $mail->send(true);

	if (strpos(@ini_get('disable_functions'), 'ob_start') !== false)
	{
		error_reporting($oldlevel);
		$errors = $php_errormsg;
	}
	else
	{
		$errors = ob_get_contents();
		ob_end_clean();
	}
	// end error handling

	if (!$mailreturn OR $errors)
	{
		$results = array();
		if (!$mailreturn)
		{
			$results[] = $vbphrase['mail_function_returned_error'];
		}
		if ($errors)
		{
			$results[] = $vbphrase['mail_function_errors_returned_were'].'<br /><br />' . $errors;
		}
		if (!$vbulletin->options['use_smtp'])
		{
			$results[] = $vbphrase['check_mail_server_configured_correctly'];
		}
		print_diagnostic_test_result(0, $results);
	}
	else
	{
		print_diagnostic_test_result(1, construct_phrase($vbphrase['email_sent_check_shortly'], $emailaddress));
	}
}

// ###################### Start geoip test #######################
if ($_POST['do'] == 'dogeoip')
{
	// additional checks should be added with testing on other OS's (Windows doesn't handle safe_mode the same as Linux).
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('p', array(
		'ipaddress' => vB_Cleaner::TYPE_STR,
	));
	$ipaddress = $vbulletin->GPC['ipaddress'];

	$options = vB::getDatastore()->getValue('options');
	print_form_header('admincp/', '');
	print_table_header($vbphrase['pertinent_php_settings']);
	print_label_row($vbphrase['geoip_provider'] . ':', $options['geoip_provider']);
	print_label_row($vbphrase['ip_address'] . ':', $ipaddress);
	print_table_footer();


	if(!$options['geoip_provider'] OR $options['geoip_provider'] == 'none')
	{
		print_diagnostic_test_result(0, $vbphrase['geoip_provider_not_configured']);
	}

	if (empty($ipaddress))
	{
		print_diagnostic_test_result(0, fetch_error('please_complete_required_fields'));
	}

	$data = array();
	$data['urlLoader'] = vB::getUrlLoader();
	$data['key'] = $options['geoip_service_key'];

	try
	{
		$class = vB::getVbClassName($options['geoip_provider'], 'Utility_Geoip', 'vB_Utility_Geoip');
		$geoip = new $class($data);
		$response = $geoip->getIpData($ipaddress);

		print_diagnostic_test_result(1, construct_phrase($vbphrase['geoip_response_x'], $response));
	}
	catch(Throwable $e)
	{
		print_diagnostic_test_result(0, (string) $e);
	}
}

// ###################### Start imagick test #######################
if ($_POST['do'] == 'doimagick')
{
	// additional checks should be added with testing on other OS's (Windows doesn't handle safe_mode the same as Linux).
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}

	$info = vB_Image_Imagick::diagnostics();

	if (!empty($info['errors']))
	{
		print_form_header('admincp/', '');
		print_table_header($vbphrase['errors']);
		foreach($info['errors'] AS $__err)
		{
			print_description_row($__err);
		}
		print_table_footer();
	}

	if (!empty($info['pdf_thumbnail_sample']))
	{
		print_form_header('admincp/', '');
		print_table_header($vbphrase['imagick_test_pdf_thumbnail_header']);
		$src = 'data:image/png;base64,' . base64_encode($info['pdf_thumbnail_sample']);
		$html = "<img src='$src' />";
		print_cells_row(array($vbphrase['imagick_test_pdf_thumbnail_desc'], $html));
		print_table_footer();
	}




}

// ###################### Start system information #######################
if ($_POST['do'] == 'dosysinfo')
{
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('p', array(
		'type' => vB_Cleaner::TYPE_STR
	));

	switch ($vbulletin->GPC['type'])
	{
		case 'mysql_vars':
		case 'mysql_status':
			print_form_header('admincp/', '');
			if ($vbulletin->GPC['type'] == 'mysql_vars')
			{
				// use MASTER connection
				$result = $db->query_write('SHOW VARIABLES');
			}
			else if ($vbulletin->GPC['type'] == 'mysql_status')
			{
				$result = $db->query_write('SHOW /*!50002 GLOBAL */ STATUS');
			}

			$colcount = $db->num_fields($result);
			if ($vbulletin->GPC['type'] == 'mysql_vars')
			{
				print_table_header($vbphrase['mysql_variables'], $colcount);
			}
			else if ($vbulletin->GPC['type'] == 'mysql_status')
			{
				print_table_header($vbphrase['mysql_status'], $colcount);
			}

			$collist = array();
			for ($i = 0; $i < $colcount; $i++)
			{
				$collist[] = $db->field_name($result, $i);
			}
			print_cells_row($collist, 1);
			while ($row = $db->fetch_array($result))
			{
				print_cells_row($row);
			}

			print_table_footer();
			break;
		default:
			print_form_header('admincp/', '');
			$result = $db->query_write("SHOW TABLE STATUS");
			$colcount = $db->num_fields($result);
			print_table_header($vbphrase['table_status'], $colcount);
			$collist = array();
			for ($i = 0; $i < $colcount; $i++)
			{
				$collist[] = $db->field_name($result, $i);
			}
			print_cells_row($collist, 1);
			while ($row = $db->fetch_array($result))
			{
				print_cells_row($row);
			}

			print_table_footer();
			break;
	}
}

if ($_POST['do'] == 'doversion')
{
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}

	$phraseApi = vB_Api::instanceInternal('phrase');
	$string = vB::getString();
	$hashChecker = new vB_Utility_Hashchecker(array(), $string);
	$hashChecker->addIgnoredDir(DIR . '/install');
	$check = $hashChecker->verifyFiles();

	if (!$check['success'])
	{
		print_stop_message_array($check['fatalErrors']);
	}
	else
	{
		print_form_header('admincp/diagnostic', 'doversion');
		print_table_header($vbphrase['suspect_file_versions']);

		// Show which manifests were used.
		if (!empty($check['checksumManifests']))
		{
			$files = implode(', ', $check['checksumManifests']);
			$message = construct_phrase($vbphrase['following_manifests_used'], $files);
			print_label_row($message);
		}

		// Show any startup warnings (like md5 file writable, etc)
		if (!empty($check['startupWarnings']))
		{
			$errorPhrases = $phraseApi->renderPhrases($check['startupWarnings']);
			$errorPhrases = $errorPhrases['phrases'];
			print_description_row(implode('<br />', $errorPhrases), false, 2, 'warning-red');
		}

		// Output problematic directories
		if (empty($check['errors']))
		{
			/*
				Important note, this just signifies that of the files explicitly specified
				in the checksum manifest file(s) we did not find any mismatched content,
				however there may be skipped/ignored/unexpected files that we could not
				validate.
			 */
			print_label_row($vbphrase['no_failed_checksum']);
		}
		else
		{
			foreach ($check['errors'] AS $directory => $filesToErrors)
			{
				if (isset($check['fileCounts'][$directory]))
				{
					$file_count = $check['fileCounts'][$directory];
					$message = "<div style=\"float:" . vB_Template_Runtime::fetchStyleVar('right') . "\">"
								. construct_phrase($vbphrase['scanned_x_files'], $file_count)
								. "</div>.$directory";
				}
				else
				{
					/*
						I don't think we currently have any errors that can occur that doesn't have a
						corresponding fileCounts element.
						We used to have a few possible cases where we didn't keep track of certain
						folders that only contained subfolders, or if a directory wasn't recognized,
						the directory could've been missing from the fileCounts list, but we've changed
						a number of things to try to make sure every known (even if empty) directory has
						an entry in the checksum file, and that even empty directories get a fileCount row
						in the hashchecker return.
						However, I'm going to keep this here just in case I missed any, or in case we
						change things in the future.
					 */
					$message = ".$directory";
				}
				print_description_row($message, 0, 2, 'thead');

				foreach ($filesToErrors AS $file => $errors)
				{
					$errorPhrases = $phraseApi->renderPhrases($errors);
					$errorPhrases = $errorPhrases['phrases'];
					print_label_row($file, implode('<br />', $errorPhrases));
				}

				unset($check['errors'][$directory], $check['fileCounts'][$directory]);
			}
		}

		/*
		TODO: FLAG SKIPPED FOLDERS & FILES FOR MANUAL REVIEW - Skipping as it's new behavior not in scope,
		but need to revisit this later.
		if (!empty($check['skippedDirs']))
		{
		}
		if (!empty($check['skippedFiles']))
		{
		}
		 */
		// Adding a convenient repeat button in the "break" before clean directories listing
		print_submit_row($vbphrase['repeat_process'], false);

		if (!empty($check['fileCounts']))
		{
			$count = count($check['fileCounts']);
			$collapsed = ($count > 20);
			$expandPhrase = construct_phrase(
				$vbphrase['expand_x_directories'],
				$count
			);
			$collapsePhrase = $vbphrase['collapse'];


			// print_submit_row() also closes the form, so we have to re-open it here.
			$collapseId = print_form_header_with_collapsible_table($collapsed, 'admincp/diagnostic', 'doversion');
			print_table_header($vbphrase['following_directories_clean']);

			print_collapse_control_row(
				$expandPhrase,
				$collapsePhrase,
				$collapseId
			);

			$i = 0;
			$showCollapseEvery = 30;
			// Output clean directories
			foreach ($check['fileCounts'] AS $directory => $file_count)
			{
				$message = "<div style=\"float:" . vB_Template_Runtime::fetchStyleVar('right') . "\">"
							. construct_phrase($vbphrase['scanned_x_files'], $file_count)
							. "</div>.$directory";
				print_description_row($message, 0, 2, 'thead');

				if (++$i % $showCollapseEvery == 0)
				{
					print_collapse_control_row(
						$expandPhrase,
						$collapsePhrase,
						$collapseId
					);
				}
			}

			if ($i % $showCollapseEvery != 0)
			{
				print_collapse_control_row(
					$expandPhrase,
					$collapsePhrase,
					$collapseId
				);
			}

			print_submit_row($vbphrase['repeat_process'], false);
		}
	}
}
else if ($_REQUEST['do'] == 'doversion')
{
	// If we're here then this page was probably visited by a GET.
	// While the filescan doesn't do any writes or state changes, so GET *should*
	// be OK, let's not change that for now, but at least print a submit button
	// so they don't have to go back to the main diagnostics page to resubmit a scan.

	if (!$canUseAll)
	{
		print_cp_no_permission();
	}
	print_form_header('admincp/diagnostic', 'doversion');
	print_table_header($vbphrase['suspect_file_versions']);
	print_description_row(construct_phrase($vbphrase['file_versions_explained'], $vbulletin->options['templateversion']));
	print_submit_row($vbphrase['submit'], 0);
}

if ($_GET['do'] == 'payments')
{
	/**
	 * Note that this block cannot be accessed directly from this page.  It's called from the
	 * Paid Subscriptions -> Test Communication page
	 */

	require_once(DIR . '/includes/class_paid_subscription.php');
	$subobj = new vB_PaidSubscription($vbulletin);

	print_form_header('admincp/subscriptions');
	print_table_header($vbphrase['payment_api_tests'], 2);
	print_cells_row(array($vbphrase['title'], $vbphrase['pass']), 1, 'tcat', 1);
	$apis = $db->query_read("
		SELECT * FROM " . TABLE_PREFIX . "paymentapi WHERE active = 1
	");

	$yesImage = get_cpstyle_href('cp_tick_yes.gif');
	$noImage = get_cpstyle_href('cp_tick_no.gif');

	while ($api = $db->fetch_array($apis))
	{
		$cells = array();
		$cells[] = $api['title'];

		if (file_exists(DIR . '/includes/paymentapi/class_' . $api['classname'] . '.php'))
		{
			require_once(DIR . '/includes/paymentapi/class_' . $api['classname'] . '.php');
			$api_class = 'vB_PaidSubscriptionMethod_' . $api['classname'];
			$obj = new $api_class($vbulletin);

			if (!empty($api['settings']))
			{
				// need to convert this from a serialized array with types to a single value
				$obj->settings = $subobj->construct_payment_settings($api['settings']);
			}

			if ($obj->test())
			{
				$cells[] = "<img src=\"$yesImage\" alt=\"\" />";
			}
			else
			{
				$cells[] = "<img src=\"$noImage\" alt=\"\" />";
			}
		}
		print_cells_row($cells, 0, '', 1);
	}

	print_table_footer(2);
}

if ($_REQUEST['do'] == 'server_modules')
{
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}
	print_form_header('admincp/', '');
	print_table_header('Suhosin');

	$suhosin_loaded = extension_loaded('suhosin');
	print_label_row($vbphrase['module_loaded'], ($suhosin_loaded ? $vbphrase['yes'] : $vbphrase['no']));
	if ($suhosin_loaded)
	{
		print_diagnostic_test_result(0, $vbphrase['suhosin_problem_desc'], 0);
	}
	print_table_footer();

	print_form_header('admincp/', '');
	print_table_header('mod_security');

	print_label_row($vbphrase['mod_security_ajax_issue'], "<span id=\"mod_security_test_result\">$vbphrase[no]</span><img src=\"". $vbulletin->options['bburl'] . "/admincp/clear.gif?test=%u0067\" id=\"mod_security_test\" alt=\"\" />");
	print_diagnostic_test_result(-1, $vbphrase['mod_security_problem_desc'], 0);
	print_table_footer();
	?>
	<script type="text/javascript">
	YAHOO.util.Event.addListener("mod_security_test", "error", function(e) { YAHOO.util.Dom.get('mod_security_test_result').innerHTML = '<?php echo $vbphrase['yes']; ?>'; YAHOO.util.Dom.setStyle('mod_security_test', 'display', 'none'); });
	YAHOO.util.Event.addListener("mod_security_test", "load", function(e) { YAHOO.util.Dom.setStyle('mod_security_test', 'display', 'none'); });
	</script>
	<?php
}

if ($_POST['do'] == 'ssl')
{
	if (!$canUseAll)
	{
		print_cp_no_permission();
	}
	print_form_header('admincp/', '');
	print_table_header($vbphrase['tls_ssl']);

	$ssl_available = false;
	if (function_exists('curl_init') AND ($ch = curl_init()) !== false)
	{
		$curlinfo = curl_version();
		if (!empty($curlinfo['ssl_version']))
		{
			// passed
			$ssl_available = true;
		}
		curl_close($ch);
	}

	if (function_exists('openssl_open'))
	{
		// passed
		$ssl_available = true;
	}

	print_label_row($vbphrase['ssl_available'], ($ssl_available ? $vbphrase['yes'] : $vbphrase['no']));
	print_diagnostic_test_result(0, $vbphrase['ssl_unavailable_desc'], 0);

	print_table_footer();
}

// ###################### Start options list #######################
if ($_REQUEST['do'] == 'list')
{
	if ($canUseAll)
	{
		print_form_header('admincp/diagnostic', 'doupload', 1);
		print_table_header($vbphrase['upload']);
		print_description_row($vbphrase['upload_test_desc']);
		print_upload_row($vbphrase['filename_gcpglobal'], 'attachfile');
		print_submit_row($vbphrase['upload'],NULL);
	}

	print_form_header('admincp/diagnostic', 'domail');
	print_table_header($vbphrase['email']);
	print_description_row($vbphrase['email_test_explained']);
	print_input_row($vbphrase['email'], 'emailaddress');
	print_submit_row($vbphrase['send']);

	if ($canUseAll)
	{
		print_form_header('admincp/diagnostic', 'doversion');
		print_table_header($vbphrase['suspect_file_versions']);
		print_description_row(construct_phrase($vbphrase['file_versions_explained'], $vbulletin->options['templateversion']));
		print_submit_row($vbphrase['submit'], 0);

		print_form_header('admincp/diagnostic', 'server_modules');
		print_table_header($vbphrase['problematic_server_modules']);
		print_description_row($vbphrase['problematic_server_modules_explained']);
		print_submit_row($vbphrase['submit'], 0);

		print_form_header('admincp/diagnostic', 'ssl');
		print_table_header($vbphrase['tls_ssl']);
		print_description_row($vbphrase['facebook_connect_ssl_req_explained']);
		print_submit_row($vbphrase['submit'], 0);

		print_form_header('admincp/diagnostic', 'dosysinfo');
		print_table_header($vbphrase['system_information']);
		print_description_row($vbphrase['server_information_desc']);
		$selectopts = array(
			'mysql_vars' => $vbphrase['mysql_variables'],
			'mysql_status' => $vbphrase['mysql_status'],
			'table_status' => $vbphrase['table_status']
		);
		print_select_row($vbphrase['view'], 'type', $selectopts);
		print_submit_row($vbphrase['submit']);

		print_form_header('admincp/diagnostic', 'dogeoip');
		print_table_header($vbphrase['testgeoip']);
		print_description_row($vbphrase['geoip_test_explained']);
		print_input_row($vbphrase['ip_address'], 'ipaddress', vB::getRequest()->getIpAddress());
		print_submit_row($vbphrase['send']);


		print_form_header('admincp/diagnostic', 'doimagick');
		print_table_header($vbphrase['testimagick']);
		print_description_row($vbphrase['imagick_test_explained']);
		print_submit_row($vbphrase['submit']);
	}
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103556 $
|| #######################################################################
\*=========================================================================*/
