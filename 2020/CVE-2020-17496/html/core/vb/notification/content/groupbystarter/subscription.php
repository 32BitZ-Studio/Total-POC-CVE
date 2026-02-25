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

class vB_Notification_Content_GroupByStarter_Subscription extends vB_Notification_Content_GroupByStarter
{

	protected static $triggers = array(
		'new-content'	=> 10,
		//'updated-content'	=> 10,

	);

	const TYPENAME = 'Subscription';

	/*
	 * Whether it supports FCM or not
	 */
	const FCM_SUPPORTED = true;

	protected function addAdditionalRecipients()
	{
		$skipUsers = array();
		/*
			TODO: if we get ignore list caching in memory, add them to the skip list.
		 */
		if (!empty($this->notificationData['sender']))
		{
			$skipUsers[$this->notificationData['sender']] = (int) $this->notificationData['sender'];
		}
		$apiResult = vB_Api::instanceInternal('follow')->getSubscribersForNotifications(
			$this->notificationData['sentbynodeid'],
			$skipUsers
		);
		$subscribers = $apiResult['subscribers'];

		// Subscribers should be an array keyed by userids.
		return array_keys($subscribers);
	}

	protected function typeEnabledForUser($user)
	{
		// subscription doesn't have an option, because if they didn't want notifications they probably wouldn't
		// have subscribed in the first place...
		return true;
	}


	/**
	 * @see vB_Notification::fetchPhraseArray()
	 */
	public static function fetchPhraseArray($notificationData)
	{
		$nodelink = vB5_Route::buildUrl('node|fullurl', array('nodeid' => $notificationData['sentbynodeid']));

		$phraseTitle = "missing phrase for " . __CLASS__;
		$phraseData = array();
		if (empty($notificationData['sender']) OR is_null($notificationData['sender_username']))
		{
			switch ($notificationData['otherParticipantsCount'])
			{
				case 0:
					$phraseTitle = 'guest_posted_on_subscription';
					$phraseData = array(
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
				case 1:
					$phraseTitle = 'guest_and_one_other_posted_on_subscription';
					$phraseData = array(
						$notificationData['sentbynodeid'],
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
				default:
					$phraseTitle = 'guest_and_y_others_posted_on_subscription';
					$phraseData = array(
						$notificationData['sentbynodeid'],
						$notificationData['otherParticipantsCount'],
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
			switch ($notificationData['otherParticipantsCount'])
			{
				case 0:
					$phraseTitle = 'x_posted_on_subscription';
					$phraseData = array(
						$userProfileUrl,
						$username,
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
				case 1:
					$phraseTitle = 'x_and_one_other_posted_on_subscription';
					$phraseData = array(
						$userProfileUrl,
						$username,
						$notificationData['sentbynodeid'],
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
				default:
					$phraseTitle = 'x_and_y_others_posted_on_subscription';
					$phraseData = array(
						$userProfileUrl,
						$username,
						$notificationData['sentbynodeid'],
						$notificationData['otherParticipantsCount'],
						$nodelink,
						$notificationData['aboutstartertitle']
					);
					break;
			}
		}

		return array($phraseTitle, $phraseData);
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
		$node = $nodeLib->getNode($data['sentbynodeid']);
		if (empty($node['starter']))
		{
			// Something weird happened. Maybe the node wasn't a content node (e.g. channels don't have starters)?
			return array();
		}

		// Grab starter for title.
		if ($node['starter'] == $node['nodeid'])
		{
			$starter = $node;
		}
		else
		{
			$starter = $nodeLib->getNode($node['starter']);
		}

		// Fallback to the starter's title if exact subscription node wasn't found.
		$subscription = $starter;
		/*
			Note: We don't want to deal with different subscription origins ATM because this will
			further fragment the push notification message grouping/bulking.
		// Try to get the best node for subscription.
		if (isset($data['subscriptionnodeid']) AND $subscription['nodeid'] != $data['subscriptionnodeid'])
		{
			$subscription = $nodeLib->getNode($data['subscriptionnodeid']);
		}
		*/

		if (empty($starter['title']))
		{
			// Something weird happened & we can't recover from this.
			return array();
		}

		$phraseApi = vB_Api::instanceInternal('phrase');
		$phraseid = 'fcm_posted_on_subscription';
		$phraseArgs = array($subscription['title']);
		$return = array();
		$data = array(
			'INTENT_EXTRA_THREAD_ID' => $node['starter'],
			'INTENT_EXTRA_POST_ID' => $node['nodeid'],
		);
		$clickAction = vB_Library_FCMessaging::CLICK_ACTION_THREAD;
		// Comments need additional data, VBV-17891
		if ($node['nodeid'] != $node['starter'] AND $node['parentid'] != $node['starter'])
		{
			$clickAction = vB_Library_FCMessaging::CLICK_ACTION_COMMENT;
			$data['INTENT_EXTRA_POST_ID'] = $node['parentid'];
			$data['INTENT_EXTRA_COMMENT_ID'] = $node['nodeid'];
		}

		foreach ($languageids AS $__langid)
		{
			$__phrase = $phraseApi->fetch($phraseid, $__langid);
			$__phrase = $__phrase[$phraseid];
			$__renderedPhrase = vsprintf($__phrase, $phraseArgs);
			$return[$__langid] = array(
				'title' => $node['authorname'], // this will be unescaped in the FCM lib
				'body' => $__renderedPhrase,
				'click_action' => $clickAction,
				'data' => $data,
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
