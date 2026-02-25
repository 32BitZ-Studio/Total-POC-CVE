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

// ########################## REQUIRE BACK-END ############################
require_once(DIR . '/includes/class_paid_subscription.php');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################
$subobj = new vB_PaidSubscription();
$subobj->cache_user_subscriptions();

if (is_array($subobj->subscriptioncache))
{
	$assertor = vB::getDbAssertor();

	foreach ($subobj->subscriptioncache as $key => $subscription)
	{
		// disable people :)
		$subscribers = $assertor->assertQuery('vBForum:subscriptionlog', array(
			vB_dB_Query::CONDITIONS_KEY=> array(
				array('field'=>'subscriptionid', 'value' => $subscription['subscriptionid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field'=>'expirydate', 'value' => vB::getRequest()->getTimeNow() , vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LTE),
				array('field'=>'status', 'value' => 1, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			)
		));
		foreach ($subscribers as $subscriber)
		{
			$subobj->delete_user_subscription($subscription['subscriptionid'], $subscriber['userid'], -1, true);
		}
	}

	// time for the reminders
	$subscriptions_reminders = $assertor->assertQuery('getSubscriptionsReminders', array(
		'time1' => vB::getRequest()->getTimeNow() + (86400 * 2),
		'time2' => vB::getRequest()->getTimeNow() + (86400 * 3)
	));

	vB_Mail::vbmailStart();

	$suburl = vB5_Route::buildUrl('settings|fullurl', array('tab' => 'subscriptions'));
	foreach ($subscriptions_reminders as $subscriptions_reminder)
	{
		$phraseAux = vB_Api::instanceInternal('phrase')->fetch(array('sub' . $subscriptions_reminder['subscriptionid'] . '_title', 'subscription'));
		$subscription_title = $phraseAux['sub' . $subscriptions_reminder['subscriptionid'] . '_title'];

		$username = unhtmlspecialchars($subscriptions_reminder['username']);
		$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
			'paidsubscription_reminder',
			array(
				$username,
				$subscription_title,
				$suburl,
				$vbulletin->options['bbtitle'],
			),
			array(),
			$subscriptions_reminder['languageid']
		);
		vB_Mail::vbmail($subscriptions_reminder['email'], $maildata['subject'], $maildata['message']);
	}
	vB_Mail::vbmailEnd();

	// Legacy Hook 'cron_script_subscriptions' Removed //
}

log_cron_action('', $nextitem, 1);

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99924 $
|| #######################################################################
\*=========================================================================*/
