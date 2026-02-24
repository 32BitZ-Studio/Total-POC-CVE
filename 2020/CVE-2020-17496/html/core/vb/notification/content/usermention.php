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

class vB_Notification_Content_UserMention extends vB_Notification_Content
{
	/*
	 * We use late static bindings in this class, and absolutely require PHP 5.3+
	 */

	/*
	 * Int[String] $triggers
	 *
	 * Array of  [key => value]  pairs of  [(string) {trigger} => (int) {priority}]
	 * Where {trigger} is the trigger string that should generate this type of notification,
	 * and {priority} is the lookupid conflict resolver: When multiple notification types
	 * generate the same lookupid on the same trigger, the type with the highest priority
	 * will overwrite the others for insertion.
	 * If any there are priority conflicts, behavior is undefined. Good luck.
	 */
	protected static $triggers = array(
		'new-content'	=> 20,
		//'updated-content'	=> 5,
	);

	/*
	 * Unique, string identifier of this notification subclass.
	 * Must be composed of alphanumeric or underscore characters: [A-Za-z0-9_]+
	 */
	const TYPENAME = 'UserMention';

	protected function validateProvidedRecipients($recipients)
	{
		// Recipients for this type will always be set by analyzing the rawtext in addAdditionalRecipients()
		return array();
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		$nodeid = $notificationData['sentbynodeid'];

		// Each post should send out its own usermention notification, VBV-14214
		return array('nodeid' => (int) $nodeid);
	}

	protected function addAdditionalRecipients()
	{
		$nodeid = $this->notificationData['sentbynodeid'];
		$node = vB_Library::instance('node')->getNode($nodeid, false, true);	// we need the rawtext.
		$usermentions = array();
		if (isset($node['rawtext']))
		{
			// don't send a notification if the user mention is inside a [QUOTE] or [NOPARSE] tag.
			$find = array(
				'#\[QUOTE[^\]]*\].*\[/QUOTE\]#siU',
				'#\[NOPARSE\].*\[/NOPARSE\]#siU',
			);
			$replace = '';
			$rawTextForUserMentions = preg_replace($find, $replace, $node['rawtext']);
			if (preg_match_all('#\[USER=(["\'])?([0-9]+)(\1)?\](.*)\[/USER\]#siU', $rawTextForUserMentions, $matches, PREG_SET_ORDER))
			{
				foreach ($matches AS $match)
				{
					$userid = (int) $match[2];
					$usermentions[$userid] = $userid;
				}
			}
			unset($rawTextForUserMentions, $find, $replace, $matches);
		}

		return $usermentions;
	}

	/**
	 * Check any additional permissions that are specific to the notification type.
	 * Only subclasses know what global settings or usergroup permissions it needs to check.
	 *
	 * @return Bool		Return false to abort sending this notification
	 *
	 * @access protected
	 */
	protected function checkExtraPermissionsForSender($sender)
	{
		$globallyEnabled = (bool) vB::getDatastore()->getOption('notification_usermention_enabled');
		$userGroupEnabled = true; // TODO: Add UGP

		return ($globallyEnabled AND $userGroupEnabled);
	}

	protected function typeEnabledForUser($user)
	{
		static $bf_masks;
		if (empty($bf_masks))
		{
			$bf_masks = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');
		}

		// The original mapping was taken from vB_Library_Privatemessage->userReceivesNotification()
		return ((bool) ($user['notification_options'] & $bf_masks['general_usermention']));
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		$nodelink = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $notificationData['sentbynodeid']));

		if (empty($notificationData['sender']) OR is_null($notificationData['sender_username']))
		{
			$phraseTitle = 'guest_mentioned_you_in_post';
			$phraseData = array(
				$nodelink,
				$notificationData['aboutstartertitle']
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

			$phraseTitle = 'x_mentioned_you_in_post';
			$phraseData = array(
				$userProfileUrl,
				$username,
				$nodelink,
				$notificationData['aboutstartertitle']
			);
		}

		return array($phraseTitle, $phraseData);
	}

	/**
	 * This function allows "collisions" to occur to limit or allow multiple notifications to a recipient.
	 * Collisions are handled by the library based on the priority of the collided notification currently
	 * in the queue.
	 *
	 * @param	Array   Notification data required for this notification type, including
	 *					- int           recipient
	 *					- string        lookupid
	 *					- int           priority
	 *					- ...
	 *
	 * @return	String	   Note that empty string will be considered as an "always unique" request, meaning
	 *                     it will allow multiple notifications to a single recipient!
	 */
	public static function generateNotificationQueueKey($notificationData)
	{
		/*
		// Allow Usermention notifications to be separate from the other "content" types. Related: VBV-14214
		return "_" . $notificationData['recipient'] . vB_Notification::DELIM . "Usermention";
		*/
		return parent::generateNotificationQueueKey($notificationData);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
