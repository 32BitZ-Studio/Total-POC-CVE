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

class vB_Notification_LikedNode extends vB_Notification
{
	protected static $triggers = array(
		'node-reputation-vote'	=> 20,
	);

	protected static $updateEvents = array(
		'read_topic',
		'read_channel',
		'soft_deleted_node',
		'physically_deleted_node',
		'deleted_user',
	);

	const TYPENAME = 'LikedNode';

	protected function validateProvidedRecipients($recipients)
	{
		// Recipients for this type will always be the node owner, and is
		// set by addAdditionalRecipients()
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

		// Don't send notification if it's not visible to a "regular" user.
		if (!($node['showpublished'] AND $node['showapproved']))
		{
			throw new Exception("Invalid Notification Data: showpublished or showapproved");
		}

		// ensure that the source content type and source channel type
		// are allowed to send this type of notification
		$this->validateSourceContentType($node['contenttypeid']);
		$this->validateSourceChannelType($node['channeltype']);

		// We're good if we got to this point.
		$newData['sentbynodeid'] = (int) $node['nodeid'];

		// Sender must be specified when constructing this type. Set by parent::validateAndCleanNotificationData()
		if (!isset($newData['sender']))
		{
			throw new Exception("Invalid Notification Data: sender");
		}

		return $newData;
	}

	protected function overwriteRule()
	{
		// Always show the latest like from a sender.
		return 'always'; // TODO: Confirm this behavior, should this be if_read instead?
	}

	final protected static function defineUnique($notificationData, $skipValidation)
	{
		// Group by the liked node
		return array('liked_nodeid' => (int) $notificationData['sentbynodeid']);
	}

	protected function addAdditionalRecipients()
	{
		$nodeid = $this->notificationData['sentbynodeid'];
		$node = vB_Library::instance('node')->getNodeBare($nodeid);
		// Note, isVisitorMessage() check is in validateAndCleanNotificationData().

		if (!empty($node['userid']) AND $node['userid'] != $this->notificationData['sender'])
		{
			return array($node['userid']);
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
		return ((bool) ($user['notification_options'] & $bf_masks['general_likespost']));
	}

	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		$nodelink = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $notificationData['sentbynodeid']));

		$phraseTitle = "missing phrase for " . __CLASS__;
		$phraseData = array();
		if ($notificationData['showdetail'])
		{
			if (empty($notificationData['sender']) OR is_null($notificationData['sender_username']))
			{
				switch ($notificationData['otherRatersCount'])
				{
					case 0:
						$phraseTitle = 'guest_rated_y';
						$phraseData = array(
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
					case 1:
						$phraseTitle = 'guest_and_one_other_rated_y';
						$phraseData = array(
							$notificationData['sentbynodeid'],
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
					default:
						$phraseTitle = 'guest_and_y_others_rated_z';
						$phraseData = array(
							$notificationData['sentbynodeid'],
							$notificationData['otherRatersCount'],
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
				}
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
				switch ($notificationData['otherRatersCount'])
				{
					case 0:
						$phraseTitle = 'x_rated_y';
						$phraseData = array(
							$userProfileUrl,
							$username,
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
					case 1:
						$phraseTitle = 'x_and_one_other_rated_y';
						$phraseData = array(
							$userProfileUrl,
							$username,
							$notificationData['sentbynodeid'],
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
					default:
						$phraseTitle = 'x_and_y_others_rated_z';
						$phraseData = array(
							$userProfileUrl,
							$username,
							$notificationData['sentbynodeid'],
							$notificationData['otherRatersCount'],
							$nodelink,
							$notificationData['aboutstartertitle']
						);
						break;
				}
			}
		}
		else
		{
			switch ($notificationData['totalRatersCount'])
			{
				case 1:
					$phraseTitle = 'one_user_rated_x';
					$phraseData = array(
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
				default:
					$phraseTitle = 'x_users_rated_y';
					$phraseData = array(
						$notificationData['totalRatersCount'],
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
			}
		}

		return array($phraseTitle, $phraseData);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
