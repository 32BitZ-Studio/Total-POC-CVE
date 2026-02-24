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

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################
$timenow = vB::getRequest()->getTimeNow();
$datastore = vB::getDatastore();
$assertor = vB::getDbAssertor();

$assertor->delete('session', array(
	array('field'=>'lastactivity', 'value' => $timenow - $datastore->getOption('cookietimeout'), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LT)
));

// expired registration images after 1 hour
$assertor->delete('humanverify', array(
	array('field'=>'dateline', 'value' => $timenow - 3600, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LT)
));


// Unused filedata is removed after 12 hours
$filedataids = $assertor->getColumn('filedata',
	'filedataid',
	array(
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'refcount', 'value' => 0, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field' => 'dateline', 'value' => $timenow - 43200, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LT)// older than 12 hours
		)
	)
);

$filedataLib = vB_Library::instance('filedata');
$filedataLib->deleteFileData($filedataids);

// Expired externalcache data
$assertor->delete('externalcache', array(
	array('field'=>'dateline', 'value' => $timenow - ($datastore->getOption('externalcache') * 60), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LT)
));

log_cron_action('', $nextitem, 1);

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99905 $
|| #######################################################################
\*=========================================================================*/
