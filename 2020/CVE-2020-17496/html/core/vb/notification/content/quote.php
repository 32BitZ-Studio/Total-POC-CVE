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

class vB_Notification_Content_Quote extends vB_Notification_Content
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
		'new-content'	=> 30,
		//'updated-content'	=> 5,
	);

	/*
	 * Unique, string identifier of this notification subclass.
	 * Must be composed of alphanumeric or underscore characters: [A-Za-z0-9_]+
	 */
	const TYPENAME = 'Quote';

	protected function validateProvidedRecipients($recipients)
	{
		// Recipients for this type will always be set by analyzing the rawtext in addAdditionalRecipients()
		return array();
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		$nodeid = $notificationData['sentbynodeid'];

		// Similar to usermentions, each post will send out its own quote notification
		return array('nodeid' => (int) $nodeid);
	}

	protected function addAdditionalRecipients()
	{
		$nodeid = $this->notificationData['sentbynodeid'];
		$node = vB_Library::instance('node')->getNode($nodeid, false, true);	// we need the rawtext.
		$quotedUsers = array();
		if (isset($node['rawtext']))
		{
			// don't send a notification if the user mention is inside a [NOPARSE] tag.
			$find = array(
				'#\[NOPARSE\].*\[/NOPARSE\]#siU',
			);
			$replace = '';
			$rawtext = preg_replace($find, $replace, $node['rawtext']);

			if (preg_match_all('#\[QUOTE=(?<username>[^\]]+)(;(?<node>(n?\d+)))?\](?<content>.*)\[/QUOTE\]#siU', $rawtext, $matches))
			{
				// Fetch userids based on found usernames.
				if (!empty($matches['username']))
				{
					$options = vB::getDatastore()->getValue('options');

					$fetchUsers = array();
					foreach ($matches['username'] AS $key => $username)
					{
						// Check if we need to apply the same fix as fixQuoteTags() in
						// the Bbcode parser(s). See comments there for more details.
						// Essentially we fix the case where the username contains a
						// left facing square bracket "]".
						if (empty($matches['node'][$key]) AND !empty($matches['content'][$key]))
						{
							$limit = (int) $options['maxuserlength'];
							$limit -= vB_String::vbStrlen($username);
							$limit += 20;
							$content = vB_String::vbChop($matches['content'][$key], $limit);
							if (preg_match('/^(.*)(?<!&#[0-9]{3}|&#[0-9]{4}|&#[0-9]{5});\s*n\d+\s*\]/U', $content, $match2))
							{
								$len = strlen($match2[1]);
								$username .= ']' . substr($matches['content'][$key], 0, $len);
							}
						}

						// Testing indicates that ajax/fetch-quotes will escape the names for us.
						// If we expect the usernames to be raw unescaped names, similar to a username that
						// would come in through the user API login, use the the "raw" to "DB-expected"
						// conversion below, taken from vB_Api_User::login() & vB_User::verifyAuthentication()
						// respectively :
						// $username = vB_String::htmlSpecialCharsUni($username);
						// $username = vB_String::convertStringToCurrentCharset($username);
						$fetchUsers[$username] = $username;
					}

					$useridsQuery = vB::getDbAssertor()->getRows('user', array(
						vB_dB_Query::COLUMNS_KEY => array('userid', 'username'),
						'username' => $fetchUsers
					));

					foreach($useridsQuery AS $row)
					{
						$quotedUsers[$row['userid']] = $row['userid'];
					}
				}
			}
			unset($rawtext, $find, $replace, $matches);
		}

		return $quotedUsers;
	}

	protected function typeEnabledForUser($user)
	{
		static $bf_masks;
		if (empty($bf_masks))
		{
			$bf_masks = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');
		}

		return ((bool) ($user['notification_options'] & $bf_masks['general_quote']));
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		$nodelink = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $notificationData['sentbynodeid']));

		if (empty($notificationData['sender']) OR is_null($notificationData['sender_username']))
		{
			$phraseTitle = 'guest_quoted_you_in_post';
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

			$phraseTitle = 'x_quoted_you_in_post';
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
	 * Returns the rendered phrase used in notification emails for this type.
	 *
	 * @param	Array	Notification data required for this notification type, including
	 *					- int       recipient
	 *					- int       languageid
	 *					- string    recipient_username
	 *					- ...		other data available from getNotificationData(), e.g.
	 *					- int|NULL		sender
	 *							- int|NULL		sentbynodeid
	 *
	 * @return	String[]|Bool	Rendered email phrases with keys "message" & "subject" or
	 *							False if it doesn't have an email or its email goes
	 *							through the legacy email function.
	 */
	public static function renderEmailPhrases($data)
	{
		$nodeid = $data['sentbynodeid'];
		$node = vB_Library::instance("node")->getNodeFullContent($nodeid);
		$node = $node[$nodeid];
		if (empty($node['startertitle']))
		{
			return false;
		}

		$senderName = vB_Api::instanceInternal('user')->fetchUserName($data['sender']);

		$mailPhrasePrefix = "notification_quote";
		if (empty($senderName))
		{
			// We're going through fetchEmailPhrases(), which requires the same "prefix" for
			// subject & body phrase keys.
			$mailPhrasePrefix = "notification_quote_guest";
		}


		$nodeurl = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $nodeid));
		$previewText = vB_String::getPreviewText($node['rawtext']);

		$options = vB::getDatastore()->getValue('options');

		$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
			$mailPhrasePrefix,
			array(
				$data['recipient_username'],
				$senderName,
				$nodeurl,
				$previewText,
				$options['bbtitle'],
			),
			array($node['startertitle']),
			$data['languageid']
		);

		return $maildata;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102584 $
|| #######################################################################
\*=========================================================================*/
