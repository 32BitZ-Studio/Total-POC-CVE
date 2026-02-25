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

//This removes private messages with no activity for 30 days.

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

//First we get a list up to 500 records.

$assertor = vB::getDbAssertor();
$records = $assertor->assertQuery('vBForum:getDeletedMsgs', array(
	'deleteLimit' => vB::getRequest()->getTimeNow(),
	vB_dB_Query::PARAM_LIMIT => 500
));

if ($records AND $records->valid())
{
	$nodeids = array();
	foreach ($records as $record)
	{
		$nodeids[] = $record['nodeid'];
	}

	vB_Library::instance('content_privatemessage')->delete($nodeids);
}

log_cron_action('', $nextitem, 1);

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
