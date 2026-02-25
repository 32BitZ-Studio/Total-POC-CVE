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

class vB_Notification_MonitoredWord extends vB_Notification
{
	const TYPENAME = 'MonitoredWord';

	protected static $triggers = array(
		'node-monitored-word-found' => 20,
		'user-monitored-word-found' => 20,
	);

	protected static $updateEvents = array(
		'physically_deleted_node',
		'deleted_user',
	);

	protected $moderatorUserIds = array();

	protected function validateProvidedRecipients($recipients)
	{
		// Recipients for this type will always be all moderators and admins,
		// and are set by addAdditionalRecipients()
		return array();
	}

	protected function overwriteRule()
	{
		// overwrite rule 'combine' works in conjunction with combineNotifications()
		return 'combine';
	}

	/**
	 * Combines a notification with a previous one to avoid showing duplicate notifications.
	 *
	 * @param  array The notification to be combined into the other one (notification being added)
	 * @param  array The notification we will combine the other one into (original notification)
	 * @param  bool  Whether or not we are combining with a notification from the database (if not,
	 *               it's combining with a notification in the pending queue)
	 *
	 * @return array Combined notification information
	 */
	public function combineNotifications($addNotificationData, $sourceNotificationData, $addNotificationFromDb)
	{
		// if $sourceNotificationData is not specified, it will use $this object's
		// data and save the combined data back to this object's data.

		$saveToSelf = !$sourceNotificationData;
		$sourceNotificationData = $saveToSelf ? $this->notificationData : $sourceNotificationData;
		$sourceCustomDataIsString = is_string($sourceNotificationData['customdata']);

		$sourceCustomData = self::normalizeCustomData($sourceNotificationData['customdata']);
		$addCustomData = self::normalizeCustomData($addNotificationData['customdata']);

		$combined = array();

		if ($addNotificationFromDb)
		{
			// When combining with a notification that's already in the db, then we need
			// to query the data in the database and use that instead. The reason is the
			// previous notification might have data that has been removed so we need to
			// check the cannonical source.

			if ($addCustomData['maintype'] == 'node')
			{
				$nodeid = $addNotificationData['sentbynodeid'];
				$node = vB_Library::instance("node")->getNodeFullContent($nodeid);
				$node = $node[$nodeid];

				$items = array();
				foreach (array('title', 'rawtext', 'edit_reason', 'taglist') AS $key)
				{
					if (!empty($node[$key]))
					{
						$k = $key;
						$v = $node[$key];
						if ($key == 'edit_reason')
						{
							$k = 'reason';
						}
						if ($key == 'taglist')
						{
							$k = 'tags';
							$v = implode(' ', explode(',', $v));
						}
						$items[$k] = $v;
					}
				}
				if (empty($node['rawtext']) AND !empty($node['description']))
				{
					$items['description'] = $node['description'];
				}

				$combined['words'] = array();
				$combined['subtypes'] = array();

				foreach ($items AS $subtype => $text)
				{
					$monitored = vB_String::getMonitoredWords($text);
					if (!empty($monitored))
					{
						$combined['words'] = array_merge($combined['words'], $monitored);
						$combined['subtypes'][] = $subtype;
					}
				}

				$combined['words'] = array_unique($combined['words']);
				$combined['subtypes'] = array_unique($combined['subtypes']);
				sort($combined['subtypes']);
				sort($combined['words']);

				if (empty($combined['words']))
				{
					// retract the notification since there are no longer any
					// monitored words found
					$this->cancelNotification();
					return false;
				}
			}
			else if ($addCustomData['maintype'] == 'user')
			{
				// since all subtypes of user are handled separately,
				// we can just use the new data and overwrite the old
				// (since there are no multiple subtypes to combine)
				$combined['subtypes'] = $sourceCustomData['subtypes'];
				$combined['words'] = $sourceCustomData['words'];
			}
		}
		else
		{
			// We are at a notification that's not being combined with a preexisting
			// notification from the database. Since it's combining with a notification
			// from the current queue to be added, we can just combine the values
			// without doing any database lookups

			$sources = array($sourceCustomData, $addCustomData);
			$elements = array('words', 'subtypes');

			// combine monitored words and subtypes from both notifictions
			foreach ($elements AS $element)
			{
				$combined[$element] = array();
				foreach ($sources AS $source)
				{
					if (is_array($source[$element]) AND !empty($source[$element]))
					{
						$temp = array_values($source[$element]);
						$combined[$element] = array_merge($combined[$element], $temp);
					}
				}
				$combined[$element] = array_unique($combined[$element]);
				sort($combined[$element]);
			}
		}


		// save combined values back to the source array
		$sourceCustomData['words'] = array_values($combined['words']);
		$sourceCustomData['subtypes'] = array_values($combined['subtypes']);

		if ($sourceCustomDataIsString)
		{
			$sourceCustomData = json_encode($sourceCustomData);
		}

		$sourceNotificationData['customdata'] = $sourceCustomData;

		// increase priority over the previous notifications
		if (!empty($addNotificationData['priority']) AND $addNotificationData['priority'] > $sourceNotificationData['priority'])
		{
			$sourceNotificationData['priority'] = $addNotificationData['priority'];
		}
		++$sourceNotificationData['priority'];

		if ($saveToSelf)
		{
			// save the source array back to the object if requested
			$this->notificationData = $sourceNotificationData;
		}

		return $sourceNotificationData;
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		$items = array();

		// sender (the user editing the node or userinfo)
		$items['senderid'] = (int) $notificationData['sender'];

		// the edited node (if it's a node)
		if (!empty($notificationData['sentbynodeid']))
		{
			$items['sentbynodeid'] = (int) $notificationData['sentbynodeid'];
		}

		$customData = self::normalizeCustomData($notificationData['customdata']);

		// the edited user (if it's a user)
		if (!empty($customData['targetuserid']))
		{
			$items['customdata_targetuserid'] = (int) $customData['targetuserid'];
		}

		// the main type ('node' or 'user')
		$items['customdata_maintype'] = $customData['maintype'];

		// add the subtype for the 'user' main type so we get a separate
		// notification for each one (signature, userfields, status, title, etc.)
		if ($customData['maintype'] == 'user')
		{
			$items['customdata_subtype'] = $customData['subtypes'];
		}

		return $items;
	}

	protected static function normalizeCustomData($customData)
	{
		if (is_string($customData))
		{
			$customData = json_decode($customData, true);
		}

		return $customData;
	}

	protected function getModeratorUserIds()
	{
		// if we want to add a moderator permission for monitored words, this
		// would be a pretty good place to apply it and and only populate
		// $this->moderatorUserIds with moderators that have it turned on.

		if (empty($this->moderatorUserIds))
		{
			$this->moderatorUserIds = vB::getDbAssertor()->getColumn('vBForum:moderator', 'userid', array(), false, 'userid');
		}

		return $this->moderatorUserIds;
	}

	protected function addAdditionalRecipients()
	{
		// add all moderators as recipients
		return $this->getModeratorUserIds();
	}

	protected function typeEnabledForUser($user)
	{
		$moderators = $this->getModeratorUserIds();

		// automatically enabled for all moderators only
		return isset($moderators[$user['userid']]);
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		// Note: This function currently uses phrases directly for the sub-types
		// which are inserted into the main phrase as data/parameters, and the
		// visitor message title phrase a_visitor_message. This may be problematic
		// if the output of this function is used for sending email notifications.

		$assertor = vB::getDbAssertor();

		$customData = self::normalizeCustomData($notificationData['customdata']);

		$phraseVarName = '';
		$phraseData = array();

		$wordCount = count($customData['words']);
		$words = implode(', ', $customData['words']);

		$subtypeCount = count($customData['subtypes']);
		$subtypes = implode(', ', $customData['subtypes']);
		$subtypeVarnames = array();
		foreach ($customData['subtypes'] AS $subtype)
		{
			$subtypeVarnames[] = 'monitored_word_subtype_' . $customData['maintype'] . '_' . $subtype;
		}
		$subtypePhrases = vB_Api::instanceInternal('phrase')->fetch($subtypeVarnames);
		$subtypePhrases = implode(', ', $subtypePhrases);

		// the phrases end in _ss, _sp, _ps, _pp for the 4 combinations
		// of words being singluar or plural and areas being singular or plural
		$pluralPhraseSuffix = '_';
		$pluralPhraseSuffix .= ($wordCount == 1) ? 's' : 'p';
		$pluralPhraseSuffix .= ($subtypeCount == 1) ? 's' : 'p';

		// sender user profile URL
		$userUrl = '#';
		try
		{
			$userUrl = vB5_Route::buildUrl('profile|fullurl', array(
				'userid' => $notificationData['senderid'],
				'username' => $notificationData['sender_username'],
			));
		}
		catch (Throwable $e){}

		// edited user profile URL (might not be the same as the sender)
		$targetUserUrl = '#';
		$targetUserName = '';
		$editedOwnProfile = true;
		if (!empty($customData['targetuserid']))
		{
			$editedOwnProfile = ($customData['targetuserid'] == $notificationData['senderid']);

			if ($editedOwnProfile)
			{
				$targetUserUrl = $userUrl;
				$targetUserName = $notificationData['sender_username'];
			}
			else
			{
				$targetUser = $assertor->getRow('user', array('userid' => $customData['targetuserid']));
				try
				{
					$targetUserUrl = vB5_Route::buildUrl('profile|fullurl', array(
						'userid' => $targetUser['userid'],
						'username' => $targetUser['username'],
					));
				}
				catch (Throwable $e){}
				$targetUserName = $targetUser['username'];
			}
		}

		// node URL
		$nodeUrl = '';
		if (!empty($notificationData['sentbynodeid']))
		{
			try
			{
				$nodeUrl = vB5_Route::buildUrl('node|fullurl', array(
					'nodeid' => $notificationData['sentbynodeid']
				));
			}
			catch (Throwable $e){}
		}

		// node title to use (might not be for *this* node, it might be the starter)
		if (empty($notificationData['aboutstartertitle']))
		{
			$node = $assertor->getRow('vBForum:node', array('nodeid' => $notificationData['sentbynodeid']));
			$nodeUseTitle = $node['title'];
		}
		else
		{
			$nodeUseTitle = $notificationData['aboutstartertitle'];
		}

		// flags
		$isStarter = (!empty($notificationData['sentbynodeid']) AND $notificationData['sentbynodeid'] == $notificationData['aboutstarterid']);
		$isChannel = (!empty($node) AND $node['displayorder'] != null);
		$isReplyOrComment = (!$isStarter AND !$isChannel);
		$isVisitorMessage = ($isStarter AND empty($nodeUseTitle));

		if ($isVisitorMessage)
		{
			$nodeUseTitle = vB_Api::instanceInternal('phrase')->fetch(array('a_visitor_message'));
			$nodeUseTitle = $nodeUseTitle['a_visitor_message'];

			try
			{
				$nodeUrl = vB5_Route::buildUrl('visitormessage|fullurl', array(
					'nodeid' => $notificationData['sentbynodeid'],
				));
			}
			catch (Throwable $e){}
		}

		// set up phrase information
		switch ($customData['maintype'])
		{
			case 'node':
				if ($isReplyOrComment)
				{
					$phraseVarName = 'ab_used_monitored_word_c_in_area_d_in_post_in_ef' . $pluralPhraseSuffix;
				}
				else
				{
					$phraseVarName = 'ab_used_monitored_word_c_in_area_d_in_ef' . $pluralPhraseSuffix;
				}
				$phraseData = array(
					$userUrl,
					$notificationData['sender_username'],
					$words,
					$subtypePhrases,
					$nodeUrl,
					$nodeUseTitle,
				);
				break;

			case 'user':
				if ($editedOwnProfile)
				{
					$phraseVarName = 'ab_used_monitored_word_c_in_area_d_on_their_profile_ef' . $pluralPhraseSuffix;
				}
				else
				{
					$phraseVarName = 'ab_used_monitored_word_c_in_area_d_on_profile_ef' . $pluralPhraseSuffix;
				}
				$phraseData = array(
					$userUrl,
					$notificationData['sender_username'],
					$words,
					$subtypePhrases,
					$targetUserUrl,
					$targetUserName,
				);
				break;

			default:
				break;
		}

		return array(
			$phraseVarName,
			$phraseData,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102433 $
|| #######################################################################
\*=========================================================================*/
