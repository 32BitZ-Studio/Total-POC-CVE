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
define('CVS_REVISION', '$RCSfile$ - $Revision: 101445 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array();
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ############################# LOG ACTION ###############################
log_admin_action();

// #############################################################################
// ########################### START MAIN SCRIPT ###############################
// #############################################################################

if (!vB::getUserContext()->hasAdminPermission('canadminsettings') AND !vB::getUserContext()->hasAdminPermission('canadminsettingsall'))
{
	print_cp_no_permission();
}

print_cp_header($vbphrase['firebasecloudmessaging']);

$options = vB::getDatastore()->getValue('options');
$fcmLib = vB_Library::instance('FCMessaging');

if (empty($options['fcm_enabled']))
{
	print_warning_table($vbphrase['fcm_disabled_options']);
}

if (empty($options['fcm_serverkey']))
{
	print_warning_table($vbphrase['fcm_missing_server_key']);
}
else
{
	print_warning_table($vbphrase['fcm_submit_long_wait_time']);

	// ###################### Start Test Server Key #######################
	print_form_header('admincp/fcm', 'testkey');
	construct_hidden_code("action", "testkey");
	print_table_header($vbphrase['fcm_test_server_key_header']);
	if ($_POST['action'] == "testkey")
	{
		$fcmResult = $fcmLib->testServerKey();

		if (!empty($fcmResult['errors']))
		{
			foreach($fcmResult['errors'] AS $__phrasekey)
			{
				print_description_row($vbphrase[$__phrasekey]);
			}
		}
		else
		{
			print_description_row($vbphrase["fcm_test_server_key_success"]);
		}
	}
	print_description_row($vbphrase['fcm_test_server_key_desc']);
	print_submit_row($vbphrase['submit'], '');



	// ###################### Start Send a Test Message #######################
	print_form_header('admincp/fcm', 'testmessage');
	construct_hidden_code("action", "testmessage");
	print_table_header($vbphrase['fcm_test_message_header']);
	$userid = vB::getCurrentSession()->get('userid');
	$tokensByUseridAndClientid = $fcmLib->convertUseridsToDeviceTokens(array($userid));
	$devicesString = "";
	$tokens = array();
	if (empty($tokensByUseridAndClientid[$userid]))
	{
		$devicesString = '<br />' . $vbphrase['fcm_test_message_no_tokens'];
	}
	else
	{
		$apiclientids = array_keys($tokensByUseridAndClientid[$userid]);
		$check = vB::getDbAssertor()->assertQuery('apiclient', array("apiclientid" => $apiclientids));
		foreach ($check AS $__row)
		{
			$devicesString .= '<br />' . $__row['clientname'] . " - " . $__row['platformname'];
		}
		$tokens = array_values($tokensByUseridAndClientid[$userid]);
	}
	if ($_POST['action'] == "testmessage")
	{
		$fcmResult = $fcmLib->testSendMessage($tokens);

		// This might send errors AND a success.
		if (!empty($fcmResult['errors']))
		{
			foreach($fcmResult['errors'] AS $__phrasekey)
			{
				print_description_row($vbphrase[$__phrasekey]);
			}
		}

		if (!empty($fcmResult['success']))
		{
			print_description_row(construct_phrase($vbphrase["fcm_test_send_message_success"], $fcmResult['success'], $fcmResult['total']));
		}

		if (!empty($fcmResult['errorCodes']))
		{
			$errorString = $vbphrase['fcm_error_check_codes'];
			foreach($fcmResult['errorCodes'] AS $__error)
			{
				$errorString .= '<br />' . $__error;
			}
			print_description_row($errorString);
		}
	}
	print_description_row($vbphrase['fcm_test_message_desc'] . $devicesString);
	print_submit_row($vbphrase['submit'], '');


	/*
	// TODO: This section is meant to allow testing opening a curl connection to {this forum}/worker
	// but I'm not sure if it's even needed, so I'm leaving this unfleshed-out.
	// ###################### Start Test Worker Connection #######################
	print_form_header('admincp/fcm', 'testworker');
	construct_hidden_code("action", "testworker");
	print_table_header($vbphrase['fcm_test_worker_header']);
	if ($_POST['action'] == "testworker")
	{
		$workerLib = vB_Library::instance('Worker');
		$workerResult = $workerLib->testWorkerConnection();
		print_description_row(print_r($workerResult, true));

	}
	print_description_row($vbphrase['fcm_test_worker_desc']);
	print_submit_row($vbphrase['submit'], '');
	*/
}



print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101445 $
|| #######################################################################
\*=========================================================================*/
