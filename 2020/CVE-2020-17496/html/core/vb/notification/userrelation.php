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

abstract class vB_Notification_UserRelation extends vB_Notification
{

	/*
	 * Generally you want to specify triggers at the lowest level so you can specify the priorities
	 * without conflicts at the subclass siblings. In contrast, you may want specify updateEvents
	 * at the highest level, as each subclass might not have special handling, and the logic for
	 * dismissing & delete might not differ at all.
	 */
	//protected static $triggers = array();

	// Future features
	protected static $updateEvents = array(
		'visited_user_profile',
		'deleted_user',
		'merged_user',
	);

	const GUESTS_CAN_SEND = false;

	/*
	 * Unique, string identifier of this notification subclass.
	 * Must be composed of alphanumeric or underscore characters: [A-Za-z0-9_]+
	 */
	const TYPENAME = 'UserRelation';

	protected function validateProvidedRecipients($recipients)
	{
		// recipients MUST be provided for this type.
		if (empty($recipients))
		{
			throw new Exception("Missing recipients");
		}

		return parent::validateProvidedRecipients($recipients);
	}

	final protected function validateAndCleanNotificationData($notificationData)
	{
		$newData = parent::validateAndCleanNotificationData($notificationData);
		unset($notificationData);

		if (!isset($newData['sender']))
		{
			throw new Exception("Missing Notification Data: sender");
		}

		// sender cannot be a guest, as guests cannot have relations with members ATM.
		if (empty($newData['sender']))
		{
			throw new Exception("Invalid Notification Data: sender");
		}

		$newData['sentbynodeid'] = NULL;

		/*
		 If we could, we'd also check recipients here, but recipients are added later
		 */

		return $newData;
	}

	protected function overwriteRule()
	{
		return 'if_read';
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		// Group by the sender (note, since this doesn't group children, each subclass will
		// be grouped by its type by default, in addition to this)
		return array('sender' => (int) $notificationData['sender']);
	}

	/**
	 * Handle update events. The required data in $eventData depends on the particular event.
	 * Children may also handle their specific events.
	 *
	 * @param	String	$event			One of the event strings in static::$updateEvents
	 * @param	Array	$eventData		When $event is 'read_topic'|'read_channel', expects:
	 *										int 'nodeid'
	 *										int 'userid'	(Optional)
	 */
	public static function handleUpdateEvents($event, $eventData)
	{
		if (!static::validateUpdateEvent($event))
		{
			return false;
		}

		$types = vB_Library::instance('Notification')->getNotificationTypes();
		$typeid = $types[static::TYPENAME]['typeid'];
		$assertor = vB::getDbAssertor();

		switch($event)
		{
			case 'deleted_user':
				$userid = (int) $eventData['userid'];
				$check = $assertor->getRow('user', array('userid' => $userid));
				if (empty($check))
				{
					// remove any notification owned by deleted user.
					$assertor->assertQuery(
						'vBForum:notification',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
							'recipient' => $userid,
							'typeid' => $typeid
						)
					);
					// remove any userrelation notifications sent from now-deleted user.
					$assertor->assertQuery(
						'vBForum:notification',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
							'sender' => $userid,
							'typeid' => $typeid
						)
					);
				}
				break;
			default:
				break;
		}


		// skip parent handler. Nothing valid there that isn't already handled here.


		return;
	}

	protected function filterRecipients()
	{
		// Only node-view-perm filtering is implemented at this time.
		// Userrelations don't have associated nodes.
		return;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
