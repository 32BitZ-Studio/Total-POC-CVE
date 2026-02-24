<?php if (!defined('VB_ENTRY')) die('Access denied.');
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
require_once(DIR . '/includes/functions.php');

$timeNow = vB::getRequest()->getTimeNow();
$datastore = vB::getDatastore();
$vboptions = $datastore->getValue('options');
if (!$vboptions['enable_account_removal'])
{
	return;
}

//if an invalid value got saved, default to 3
$deletelimit = $vboptions['user_autodelete_limit'];
if ($deletelimit <= 0)
{
	$deletelimit = 3;
}

// If invalid value was somehow saved into the setting, fallback to the default of 3 days.
$cooldownperiod = intval($vboptions['user_autodelete_cooldown']);
if ($cooldownperiod <= 0)
{
	$cooldownperiod = 3;
}

// 1 day = 86400 seconds
$cooldownperiod = $cooldownperiod * 86400;

$config =& vB::getConfig();
$noalter = explode(',', $config['SpecialUsers']['undeletableusers']);

if (!is_array($noalter))
{
	$noalter = array();
}

$conditions = array(
	array('field' => 'eustatus', 'value' => '2', 'operator' => vB_dB_Query::OPERATOR_NE),
	array('field' => 'privacyconsent', 'value' => '-1', 'operator' => vB_dB_Query::OPERATOR_EQ),
	array('field' => 'privacyconsentupdated', 'value' => '0', 'operator' => vB_dB_Query::OPERATOR_GT),
	array('field' => 'privacyconsentupdated', 'value' => $timeNow - $cooldownperiod, 'operator' => vB_dB_Query::OPERATOR_LTE),
);

if (!empty($noalter))
{
	$conditions[] = array('field' => 'userid', 'value' => $noalter, 'operator' => vB_dB_Query::OPERATOR_NE);
}


$assertor = vB::getDbAssertor();

$rows = $assertor->assertQuery("user",
	array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
		vB_dB_Query::CONDITIONS_KEY => $conditions,
		vB_Db_Query::PARAM_LIMIT => $deletelimit,
		vB_dB_Query::COLUMNS_KEY => array('userid', 'privacyconsentupdated'),
	),
	array('field' => 'privacyconsentupdated', 'direction' => vB_dB_Query::SORT_ASC)
);

$userLibrary = vB_Library::instance('user');
$phraseApi  = vB_Api::instanceInternal('phrase');
// use default language since we don't know which user's session is running this.
// ... I wonder if anything terrible would happen if one of th edeleted users is the one
// whose session this cron kicked off of...
$languageid = $vboptions['languageid'];
if (!$languageid)
{
	$languageid = -1;
}
// prefetch known errors that might be used.
$phrases = $phraseApi->fetch(
	array(
		'cant_delete_last_admin',
		'failed_to_delete_user_x_because_y',
		'undeletable_user_withdrawn_consent',
	),
	$languageid
);

foreach ($rows AS $__row)
{
	$__timeStart = microtime(true);
	$__userid = $__row['userid'];

	try
	{
		$userLibrary->delete($__userid, false);
	}
	catch (vB_Exception_Api $e)
	{
		// Taken from print_stop_message2()
		$errors = $e->get_errors();
		$errors = array_pop($errors);
		$phrase = $errors[0];
		if (!is_array($phrase))
		{
			$phrase = array($phrase);
		}
		$phraseKey = $phrase[0];
		if (!isset($phrases[$phraseKey]))
		{
			$phraseAux = $phraseApi->fetch(array($phraseKey), $languageid);
			if (isset($phraseAux[$phraseKey]))
			{
				$phrases[$phraseKey] = $phraseAux[$phraseKey];
			}
		}
		if (isset($phrases[$phraseKey]))
		{
			$message = $phrases[$phraseKey];
		}
		else
		{
			$message = $phraseKey; // phrase doesn't exist or wasn't found, display the varname
		}
		// Construct err message if it was array(phrasekey, args...)
		if (sizeof($phrase) > 1)
		{
			$phrase[0] = $message;
			$message = call_user_func_array('construct_phrase', $phrase);
		}

		$logmessage = sprintf($phrases['failed_to_delete_user_x_because_y'], $__userid, $message);
		log_cron_action($logmessage, $nextitem, 0);
		continue;
	}
	catch (Exception $e)
	{
		$logmessage = sprintf($phrases['failed_to_delete_user_x_because_y'], $__userid, $e->getMessage());
		log_cron_action($logmessage, $nextitem, 0);
		continue;
	}

	$__timeElapsed = microtime(true) - $__timeStart;
	$__timeElapsed = number_format($__timeElapsed, 2, '.', ',');
	log_cron_action(serialize(array($__userid, $__row['privacyconsentupdated'], $__timeElapsed)), $nextitem, 1);
}


// Check for undeletable users who's withdrawn consent and flag them.
if (!empty($noalter))
{
	$conditions = array(
		array('field' => 'eustatus', 'value' => '2', 'operator' => vB_dB_Query::OPERATOR_NE),
		array('field' => 'privacyconsent', 'value' => '-1', 'operator' => vB_dB_Query::OPERATOR_EQ),
		array('field' => 'privacyconsentupdated', 'value' => '0', 'operator' => vB_dB_Query::OPERATOR_GT),
		array('field' => 'privacyconsentupdated', 'value' => $timeNow - $cooldownperiod, 'operator' => vB_dB_Query::OPERATOR_LTE),
	);
	$conditions[] = array('field' => 'userid', 'value' => $noalter, 'operator' => vB_dB_Query::OPERATOR_EQ);
	$rows = $assertor->assertQuery("user",
		array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => $conditions,
			vB_Db_Query::PARAM_LIMIT => 3,
			vB_dB_Query::COLUMNS_KEY => array('userid', 'privacyconsentupdated'),
		),
		array('field' => 'privacyconsentupdated', 'direction' => vB_dB_Query::SORT_ASC)
	);

	foreach ($rows AS $__row)
	{
		$logmessage = sprintf($phrases['undeletable_user_withdrawn_consent'], $__row['userid'], $__row['privacyconsentupdated']);
		log_cron_action($logmessage, $nextitem, 0);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
