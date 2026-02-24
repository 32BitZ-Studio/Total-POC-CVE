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

class vB_Notification_UserRelation_SenderIsfollowing extends vB_Notification_Userrelation
{
	protected static $triggers = array(
		'user-added-follow-user'	=> 10,
	);

	const TYPENAME = 'SenderIsFollowing';

	protected function addAdditionalRecipients()
	{
		// Nothing to do. This particular type requires that the sender *always* specifies the recipient. If not,
		// nothing will be sent out.

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
		return ((bool) ($user['notification_options'] & $bf_masks['general_followsyou']));
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
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

		$phraseTitle = "x_is_following_you";
		$phraseData = array($username, $userProfileUrl);

		return array($phraseTitle, $phraseData);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
