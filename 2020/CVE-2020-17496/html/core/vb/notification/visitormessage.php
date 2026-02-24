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

class vB_Notification_VisitorMessage extends vB_Notification
{
	protected static $triggers = array(
		'new-visitormessage'	=> 20,
	);

	// Future features
	protected static $updateEvents = array(
		'read_vms',
		'soft_deleted_node',
		'physically_deleted_node',
		'deleted_user',
	);

	const TYPENAME = 'VisitorMessage';

	/**
	 * Channel types that will be allowed to send notifications.
	 * Keep this in sync with vB_Channel::$channelTypes
	 * @var array
	 */
	protected $validSourceChannelTypes = array(
		'vm' => 1,
	);

	/*
	 * Whether it supports FCM or not
	 */
	const FCM_SUPPORTED = true;

	protected function validateProvidedRecipients($recipients)
	{
		// Recipients for this type will always be the node's 'setfor', and is
		// set by addAdditionalRecipients() and checked in validateAndCleanNotificationData
		return array();
	}

	protected function validateAndCleanNotificationData($notificationData)
	{
		$newData = parent::validateAndCleanNotificationData($notificationData);
		unset($notificationData);

		if (!isset($newData['sentbynodeid']))
		{
			throw new Exception("Missing Notification Data: sentbynodeid");
		}

		$nodeid = $newData['sentbynodeid'];
		$node = vB_Library::instance('node')->getNode($nodeid, false, true);	// we need to get the full content, to ensure 'channeltype' is there.
		if (!isset($node['nodeid']))
		{
			throw new Exception("Invalid Notification Data: sentbynodeid");
		}

		if (!isset($node['setfor']))
		{
			throw new Exception("Invalid Node Data: setfor");
		}

		// ensure that the source content type and source channel type
		// are allowed to send this type of notification
		$this->validateSourceContentType($node['contenttypeid']);
		$this->validateSourceChannelType($node['channeltype']);

		// We're good if we got to this point.
		$newData['sentbynodeid'] = (int) $node['nodeid'];

		if (!isset($node['userid']))
		{
			throw new Exception("Invalid Notification Data: sentbynodeid");
		}
		$newData['sender'] = (int) $node['userid'];

		return $newData;
	}

	protected function overwriteRule()
	{
		// Always show the latest VM from a sender.
		return 'always';
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		// Group VMs by sender.
		return array('sender' => (int) $notificationData['sender']);
	}

	protected function addAdditionalRecipients()
	{
		$nodeid = $this->notificationData['sentbynodeid'];
		$node = vB_Library::instance('node')->getNode($nodeid, false, true);
		// Note, isVisitorMessage() check is in validateAndCleanNotificationData().

		if (isset($node['setfor']))
		{
			return array($node['setfor']);
		}

		return array();
	}

	protected function typeEnabledForUser($user)
	{
		static $bf_masks;
		if (empty($bf_masks))
		{
			$bf_masks = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');
		}

		// The original mapping was taken from vB_Library_Privatemessage->userReceivesNotification()
		return ((bool) ($user['notification_options'] & $bf_masks['general_vm']));
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		try
		{
			$vmlink = vB5_Route::buildUrl('visitormessage|fullurl', array('nodeid' => $notificationData['sentbynodeid']));
		}
		catch (Exception $e)
		{
			$vmlink = '#';
		}

		$phraseTitle = "missing phrase for " . __CLASS__;
		$phraseData = array();
		if (empty($notificationData['sender']) OR is_null($notificationData['sender_username']))
		{
			$phraseTitle = 'guest_posted_visitormessage_url';
			$phraseData = array(
				$vmlink,
			);
		}
		else
		{
			$userid = $notificationData['sender'];
			$username = $notificationData['sender_username'];
			$userInfo = array('userid' => $userid, 'username' => $username);
			try
			{
				$userProfileUrl = vB5_Route::buildUrl('profile|fullurl', $userInfo);
			}
			catch (Exception $e)
			{
				$userProfileUrl = "#";
			}
			$phraseTitle = 'x_posted_visitormessage_url';
			$phraseData = array(
				$username,
				$userProfileUrl,
				$vmlink,
			);
		}

		return array($phraseTitle, $phraseData);
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

					/*
						UPDATE any visitormessage notifications sent from now-deleted user.
						Since sender is part of the lookupid, this is more complex than just
						updating the sender field to 0.
					*/

					// First, fetch the resulting lookupid
					$lookupid = static::fetchLookupid(array('sender' => 0), true);
					if (is_null($lookupid))
					{
						// This should never happen.
						throw new Exception("Invalid lookupid for vm notification!");
					}
					else
					{
						$lookupid_hashed = static::getHashedLookupid($lookupid); // lookupid_hashed		CHAR(32), md5() is 32 chars.
						$lookupid = substr($lookupid, 0, 150);	// lookupid		VARCHAR(150) NULL DEFAULT NULL,
					}

					$rowsToUpdate = $assertor->getRows(
						'vBForum:notification',
						array(
							'sender' => $userid,
							'typeid' => $typeid,
						)
					);
					if (!empty($rowsToUpdate))
					{
						// all keyed by recipient userid
						$updates = array();
						$lastsenttimes = array();
						$recipients = array();
						foreach ($rowsToUpdate AS $row)
						{
							$recipient = $row['recipient'];
							if (!isset($updates[$recipient]))
							{
								$updates[$recipient] = $row['notificationid'];
								$lastsenttimes[$recipient] = $row['lastsenttime'];
								$recipients[$recipient] = $recipient;
							}
							elseif ($row['lastsenttime'] > $lastsenttimes[$recipient])
							{
								// always keep the most recent per recipient.
								$updates[$recipient] = $row['notificationid'];
								$lastsenttimes[$recipient] = $row['lastsenttime'];
							}
						}

						// Grab already existing VM notifications with sender = 0.
						$conflicts = $assertor->getRows(
							'vBForum:notification',
							array(
								'lookupid_hashed' => $lookupid_hashed,
								'recipient' => $recipients,
							)
						);
						$deleteTheseFirst = array();
						foreach ($conflicts AS $row)
						{
							$recipient = $row['recipient'];
							if ($row['lastsenttime'] >= $lastsenttimes[$recipient])
							{
								// existing is newer, cancel the update
								unset($updates[$recipient]);
							}
							else
							{
								// one to be inserted is newer, delete the old one first
								// to avoid key conflicts
								$deleteTheseFirst[] = $row['notificationid'];
							}
						}

						if (!empty($deleteTheseFirst))
						{
							$assertor->assertQuery(
								'vBForum:notification',
								array(
									vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
									'notificationid' => $deleteTheseFirst
								)
							);
						}
						if (!empty($updates))
						{
							$assertor->assertQuery(
								'vBForum:notification',
								array(
									vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
									vB_dB_Query::CONDITIONS_KEY => array(
										array('field' => 'notificationid', 'value' => $updates, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
									),
									'sender' => 0,
									'lookupid' => $lookupid,
									'lookupid_hashed' => $lookupid_hashed,
								)
							);
						}
					}

					// Finally, delete any that might still be remaining.
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
			case 'read_vms':
				$currentUserid = vB::getCurrentSession()->get('userid');

				if (!isset($eventData['userid']))
				{
					$recipient = $currentUserid;
				}
				else
				{
					$recipient = (int) $eventData['userid'];
				}

				// For now, only allow dismissing notification for current user. See notes in vB_Notification::handleUpdateEvents()
				if ($recipient !== $currentUserid)
				{
					return;
				}

				if (!empty($recipient))
				{
					$assertor->update(
						'vBForum:notification',
						// values
						array(
							'lastreadtime'  => (int) vB::getRequest()->getTimeNow(),
						),
						// condition
						array(
							'typeid'    => $typeid,
							'recipient' => $recipient
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


	public static function getFCMExtraData($data, $languageids)
	{
		// We also have data.sender, but let's just grab the username from the node itself
		// to skip unnecessary queries/methods
		if (empty($data['sentbynodeid']))
		{
			return array();
		}

		$nodeLib = vB_Library::instance('node');
		// we need rawtext, so get full content.
		$node = $nodeLib->getNode($data['sentbynodeid'], false, true);

		if (empty($node['authorname']))
		{
			// Something weird happened & we can't recover from this.
			// Note that guest VMs will have an authorname of "Guest", it will not be empty.
			return array();
		}

		$phraseApi = vB_Api::instanceInternal('phrase');
		$titlePhraseid = 'fcm_visitormessage_title';
		// TODO: Do phrases like {1}: {2} that can be hard-coded concatenations require phrasing for
		// RTL??
		$bodyPhraseid = 'fcm_visitormessage_x_y';
		$bareText = vB_String::getPreviewText(vB_String::stripBbcode($node['rawtext']), 200);
		$bodyPhraseArgs = array($node['authorname'], $bareText);
		$return = array();

		foreach ($languageids AS $__langid)
		{
			$__phrases = $phraseApi->fetch(array($bodyPhraseid, $titlePhraseid), $__langid);
			$__bodyPhrase = $__phrases[$bodyPhraseid];
			$__renderedPhrase = vsprintf($__bodyPhrase, $bodyPhraseArgs);
			$__titlePhrase = $__phrases[$titlePhraseid];
			$return[$__langid] = array(
				'title' => $__titlePhrase,
				'body' => $__renderedPhrase,
				'click_action' => vB_Library_FCMessaging::CLICK_ACTION_VISITORMESSAGE,
			);
		}

		return $return;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
