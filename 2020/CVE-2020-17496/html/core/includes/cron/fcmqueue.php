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

$timeNow = vB::getRequest()->getTimeNow();
$assertor = vB::getDbAssertor();
// Lock the queue so we can reserve a number of queue items
// and not have another cron instance send duplicate messages.
// TODO: Will this cause contention?
$assertor->assertQuery('fcmqueue_locktable');

/*
	Note, we delete queue items older than 3 days at the end of this cron. We may want to reduce
	that grace period once we get some usage data in the wild, but this is mean to mitigate
	potential issues of really old messages that were never picked up by the cron to be
	resurrected by the cron.

	Note that this is not related to the lastactivity check.


	TODO: add a limit option, like "emailsendnum" for mailqueue? Current limit of 5000 is arbitrary.
 */
$rows = $assertor->getRows("vBForum:getFCMessageQueue", array('timenow' => $timeNow, 'limit' => 5000));

$messagesAndRecipients = array();
$clientidsByMessageid = array();
foreach ($rows AS $__row)
{
	$__messageid = $__row['messageid'];
	$__clientid = $__row['recipient_apiclientid'];

	if (empty($clientidsByMessageid[$__messageid]))
	{
		$clientidsByMessageid[$__messageid] = array();
	}
	$clientidsByMessageid[$__messageid][] = $__clientid;
}

$processedCount = count($rows);
// Reserve the queue items before doing anything else so we can unlock & reduce wait times.
foreach ($clientidsByMessageid AS $__messageid => $__clientids)
{
	$assertor->assertQuery(
		"vBForum:lockFCMQueueItems",
		array(
			'messageid' => $__messageid,
			'clientids' => $__clientids,
		)
	);

	// Batching code, untested, not sure if necessary yet.
		/*
	if (count($clientids) >= 500)
	{
		// batch the updates just in case the list of tokens gets too long
		$__batch = array_chunk($__clientids, 100);
		foreach ($__batch AS $__thisbatch)
		{
			$assertor->assertQuery(
				"vBForum:lockFCMQueueItems",
				array(
					'messageid' => $__messageid,
					'clientids' => $__thisbatch,
				)
			);
		}
	}
	else
	{
		$assertor->assertQuery(
			"vBForum:lockFCMQueueItems",
			array(
				'messageid' => $__messageid,
				'clientids' => $__clientids,
			)
		);
	}
	*/
}

// At this point we unlock the tables so any other process(es) such as a content add or another instance of this cron
// is not waiting on us to queue up or process messages.
$assertor->assertQuery('unlock_tables');

$fcmLib = vB_Library::instance("FCMessaging");
//$clientidsByMessageid[$__messageid][$__clientid]
foreach ($clientidsByMessageid AS $__messageid => $__clientids)
{
	if (count($__clientids) == 1 AND empty(reset($__clientids)))
	{
		// this is a "to: topic" message, which we do not use yet...
		// In this case, the "to" field will be saved as part of `fcmessage`.message_data, so
		// we send it without tokens & let the fcm service handle the "to" field.
		$fcmLib->sendMessageFromCron($__messageid);
	}
	else
	{
		// Send 1k max at a time.
		$batched = array_chunk($__clientids, 1000);
		foreach ($batched AS $__batchedClientids)
		{
			$fcmLib->sendMessageFromCron($__messageid, $__batchedClientids);
		}
	}
}




/*
	Ideally this will not happen, but since we process the oldest first, if there are a lot of
	queued up messages, that will impact newer, more relevant messages.
	Get rid of very old items in the queue that we never picked up.
	259200s = 3days
 */
$deleteCutoff = $timeNow - 259200;
$deletedCount = 0;
$count = $assertor->getRow("vBForum:getFCMQueueDeleteCount", array('delete_cutoff' => $deleteCutoff));
if (!empty($count['count']))
{
	$deletedCount = $count['count'];
	$fcmLib->logError(
		"Deleting " . intval($count['count']) . " items from FCM queue. If this happens frequently, please increase the FCM Queue processing limit",
		array("count" => $count['count']),
		vB_Library_FCMessaging::ERROR_TYPE_SETTING
	);
	$assertor->assertQuery("vBForum:deleteOldFCMQueue", array('delete_cutoff' => $deleteCutoff));
}

// Remove any unreferenced messages from fcmessage.
$unusedMessageidQuery = $assertor->assertQuery("vBForum:getUnusedFCMessageids");
$deleteMe = array();
foreach ($unusedMessageidQuery AS $__row)
{
	$deleteMe[] = $__row['messageid'];
}
if (!empty($deleteMe))
{
	$assertor->delete('vBForum:fcmessage',
		array(
			'messageid' => $deleteMe,
		)
	);
}



/*
Pick up "dropped" offload messages.

This section finds any old offloaded messages that were never sent (likely due to the curl request
to worker controller timing out before the default 3s (now configurable), as we saw on Cloud every
once in a while.

In such a case, just pick it up via cron & send it through the normal handling.

`fcmessage_offload` records notes:
Currently, removeafter is set to {addedtime} + 3600s (1hr), and each record is not expected to
live more than a few seconds, as when the offload worker receives the message hashes, it fetches
the records into memory then immediately deletes them from the database.
So, let's leave everything with a {addedtime} older than 1 minute ago and send them all.
addedtime + 3600 = removeafter
addedtime <= timenow - 60s
removeafter - 3600 <= timenow - 60
removeafter <= timenow + 3600 - 60
 */
$cutoff = $timeNow + 3600 - 60;
$conditions = array(
	array('field' => 'removeafter', 'value' => $cutoff, 'operator' => vB_dB_Query::OPERATOR_LTE),
);
$offloadHashes = $assertor->assertQuery('vBForum:fcmessage_offload', array(
	vB_dB_Query::CONDITIONS_KEY => $conditions,
	vB_dB_Query::COLUMNS_KEY => array('hash'),
));
/*
I'm not entirely sure what the expected volumes of "lost" FCMs are, nor
the optimal/tolerable throughput.. let's go with 20 for now. Note that
each message (which may have multiple recipients) is still sent one at
a time via handleOffloadedTask().
*/
$sendafter = 20;
$processedOffloadCounter = 0;
$hashes = array();
while ($offloadHashes->valid())
{
	$processedOffloadCounter++;
	$__row = $offloadHashes->current();

	$hashes[] = $__row['hash'];
	$offloadHashes->next();
	if ($processedOffloadCounter % $sendafter == 0 OR !$offloadHashes->valid())
	{
		$result = $fcmLib->handleOffloadedTask($hashes);
		$hashes = array();
	}
}

if (!empty($processedOffloadCounter))
{
	// ATM this only logs to the error log rather than into some form of fetchable/searchable log storage (db)
	// but having more diagnostic info never hurts.
	// Note, it says "processed" not "sent", because the sending might've failed if the FCM endpoint failed to
	// respond. In that case it's shifted into fcmessage_queue for a retry later (by this cron).
	$fcmLib->logError(
		"Belatedly processed " . $processedOffloadCounter . " items from FCM offload records. "
		. "If this happens frequently, please try increasing the 'Firebase Cloud Messaging Offload Timeout' option",
		array("count" => $processedOffloadCounter),
		vB_Library_FCMessaging::ERROR_TYPE_SETTING
	);
}

// todo: update cron messaging to include the picked up orphaned offloaded messages?
// Don't have a good wording for the log message ATM and don't want to hold the bulk of the JIRA up.

if (!empty($processedCount) OR !empty($deletedCount))
{
	log_cron_action(serialize(array($processedCount, $deletedCount)), $nextitem, 1);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101552 $
|| #######################################################################
\*=========================================================================*/
