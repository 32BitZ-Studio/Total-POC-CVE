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
// if (!is_object($vbulletin->db))
// {
// 	exit;
// }

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$assertor = vB::getDbAssertor();

//  Clean up MAPI attachment helper table
$timenow = vB::getRequest()->getTimeNow();
$twodaysago = $timenow - (60*60*24*2);
$onemonthago = $timenow - (60 * 60 * 24 * 30);
$result = $assertor->assertQuery('vBMAPI:cleanPosthash', array('cutoff' => $twodaysago));

// Clean the nodehash table
$assertor->delete('vBForum:nodehash', array(array('field' => 'dateline', 'value' => $twodaysago, 'operator' => vB_dB_Query::OPERATOR_LT)));
// Clean all expired redirects
 vB_Library::instance('content_redirect')->deleteExpiredRedirects();

// SELECT announcements that are active, will be active in the future or were active in the last ten days
$anns = $assertor->getRows('vBForum:announcement',
	array(vB_dB_Query::CONDITIONS_KEY=> array(
		array('field'=>'enddate', 'value' => $timenow -  864000, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LTE)
	)),
	false,
	'announcementid'
);

// Delete all read markers for announcements expired > 10 days
if (!empty($anns))
{
	$assertor->delete('vBForum:announcementread',
		array(
			array('field'=>'announcementid', 'value' => array_keys($anns), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
		)
	);
}

$searchCloudeHistory = vB::getDatastore()->getOption('tagcloud_searchhistory');
if ($searchCloudeHistory)
{
	$assertor->delete('vBForum:tagsearch', array(
		array(
			'field'=>'dateline',
			'value' => $timenow - ($searchCloudeHistory * 60 * 60 * 24),
			vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LT,
		)
	));
}

// Clean out autosave
$assertor->delete('vBForum:autosavetext', array(array('field' => 'dateline', 'value' => $onemonthago, 'operator' => vB_dB_Query::OPERATOR_LT)));

vB_Library::instance('user')->cleanIpInfo();

log_cron_action('', $nextitem, 1);

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
