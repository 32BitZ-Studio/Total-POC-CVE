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

/**
 * vB_Library_Content_Privatemessage
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Privatemessage extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_PrivateMessage';

	//The table for the type-specific data.
	protected $tablename = array('text', 'privatemessage');

	protected $folders = array();

	const TRASH_FOLDER = 'trash';
	const REQUEST_FOLDER = 'requests';
	const MESSAGE_FOLDER = 'messages';
	const NOTIFICATION_FOLDER = 'your_notifications';
	const PENDING_FOLDER = 'pending_posts';
	const SENT_FOLDER = 'sent_items';
	const INFRACTION_FOLDER = 'infractions';
	const DELETED_ITEMS_FOLDER = 'deleted_items';

	const NOTIFICATION_TYPE_VOTE = 'vote';
	const NOTIFICATION_TYPE_VOTEREPLY = 'vote_reply';
	const NOTIFICATION_TYPE_RATE = 'rate';
	const NOTIFICATION_TYPE_REPLY = 'reply';
	const NOTIFICATION_TYPE_FOLLOW = 'follow';
	const NOTIFICATION_TYPE_FOLLOWING = 'following';
	const NOTIFICATION_TYPE_VM = 'vm';
	const NOTIFICATION_TYPE_COMMENT = 'comment';
	const NOTIFICATION_TYPE_THREADCOMMENT = 'threadcomment';
	const NOTIFICATION_TYPE_SUBSCRIPTION = 'subscription';
	const NOTIFICATION_TYPE_MODERATE = 'moderate';
	const NOTIFICATION_TYPE_USERMENTION = 'usermention';
	const NOTIFICATION_TYPE_MONITOREDWORD = 'monitoredword';

	protected $nodeApi;
	protected $pmChannel;

	//Cache our knowledge of records the current user can see, to streamline permission checking.
	protected $canSee = array();
	protected $foldersInfo = array();

	//these are the notification message types. Message and request are handled differently.
	//the parameter is whether they need an aboutid.
	protected $notificationTypes = array(
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTE,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTEREPLY,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_RATE,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_REPLY,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOW,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOWING,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VM,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_COMMENT,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_THREADCOMMENT,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MODERATE,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_USERMENTION,
		vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MONITOREDWORD,
	);

	// these are channel requests for ownership/moderation/membership/subscription
	// the subscription requests are content-follow requests, but still required here in Privatemessage context
	protected $channelRequests = array(
		vB_Api_Node::REQUEST_TAKE_OWNER,
		vB_Api_Node::REQUEST_TAKE_MODERATOR,
		vB_Api_Node::REQUEST_TAKE_MEMBER,
		vB_Api_Node::REQUEST_GRANT_OWNER,
		vB_Api_Node::REQUEST_GRANT_MODERATOR,
		vB_Api_Node::REQUEST_GRANT_MEMBER,
		vB_Api_Node::REQUEST_GRANT_SUBSCRIBER,
		vB_Api_Node::REQUEST_SG_TAKE_OWNER,
		vB_Api_Node::REQUEST_SG_TAKE_MODERATOR,
		vB_Api_Node::REQUEST_SG_TAKE_MEMBER,
		vB_Api_Node::REQUEST_SG_GRANT_OWNER,
		vB_Api_Node::REQUEST_SG_GRANT_MODERATOR,
		vB_Api_Node::REQUEST_SG_GRANT_MEMBER,
		vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER,
	);

	// keep track of which of the "channel requests" are actually follow request (i.e. follow channel's content)
	protected $channelFollowRequests = array(
		vB_Api_Node::REQUEST_GRANT_SUBSCRIBER,
		vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER,
	);

	/**
	 * If true, then creating a node of this content type will increment
	 * the user's post count. If false, it will not. Generally, this should be
	 * true for topic starters and replies, and false for everything else.
	 *
	 * @var	bool
	 */
	protected $includeInUserPostCount = false;

	// Do not send a moderator notification when this contenttype is created
	protected $skipModNotification = true;

	protected function __construct()
	{
		parent::__construct();
		$this->pmChannel = $this->nodeApi->fetchPMChannel();
	}

	/**
	 * Adds a message without triggering the flood check.
	 *
	 * @param	array	The data for the message or notification
	 * @param	array	Array of options to send to the add() function
	 *
	 * @return	int	The nodeid of the created message/notification
	 */
	public function addMessageNoFlood($data, $options = array())
	{
		$floodcheck = $this->doFloodCheck;
		$this->doFloodCheck = false;

		if (empty($data['sender']))
		{
			$userInfo = vB::getCurrentSession()->fetch_userinfo();
			$data['sender'] = $userInfo['userid'];
		}

		$result = $this->add($data, $options);
		$this->doFloodCheck = $floodcheck;

		return $result['nodeid'];
	}

	/**
	 *	Sends the email notication for a private message
	 *
	 *	@param array $data --
	 *		'msgtype' string => the type of PM: request | message
	 *		'about' string => type of request: follow | moderator_to | owner_to
	 *		'aboutid' => user to follow (only for request -> follow)
	 *		'userid' => id of the message sender?
	 *		'username' => username of the message recipient
	 *		'email' => address to send to
	 *		'folderid' => folder to reference for link to message center.
	 */
	protected function sendEmailNotification($data)
	{
		//if we don't have information on what to do, there isn't anything we can do.
		if (!isset($data['msgtype']) OR ($data['msgtype'] == 'request' AND !isset($data['about'])))
		{
			return;
		}

		$phraseApi = vB_Api::instanceInternal('phrase');
		$bbtitle = vB::getDatastore()->getOption('bbtitle');
		$senderUsername = vB_Api::instanceInternal('user')->fetchUserName($data['userid']);

		$maildata = array();
		if ($data['msgtype'] == 'request')
		{
			$url = vB5_Route::buildUrl('privatemessage|fullurl',
				array('folderid' => $data['folderid'], 'pagenum' => 1, 'action' => $data['msgtype']));

			$username = $senderUsername;
			if ($data['about'] == 'follow')
			{
				$username = vB_Api::instanceInternal('user')->fetchUserName($data['aboutid']);
			}

			$phraseMap = array(
				'follow' => 'follow_request',
				'moderator_to' => 'moderation_request',
				'sg_moderator_to' => 'moderation_request',
				'owner_to' => 'ownership_request',
				'sg_owner_to' => 'ownership_request',
			);

			$phrase = '';
			if (isset($phraseMap[$data['about']]))
			{
				$phrase = $phraseMap[$data['about']];
			}

			if ($phrase)
			{
				$maildata = $phraseApi->fetchEmailPhrases(
					$phrase,
					array(
						$data['username'],
						$username,
						$url,
						$bbtitle,
					),
					array($bbtitle)
				);
			}
		}
		else if ($data['msgtype'] == 'message')
		{
			$url = vB5_Route::buildUrl('privatemessage|fullurl',
				array('folderid' => $data['folderid'], 'pagenum' => 1, 'action' => 'list'));

			$text = vB_String::getPreviewText($data['rawtext']);

			$maildata = $phraseApi->fetchEmailPhrases(
				'privatemessage',
				array(
					$data['username'],
					$senderUsername,
					$url,
					$text,
					$bbtitle,
				),
				array($bbtitle)
			);
		}

		if (!empty($maildata))
		{
			// Sending the email
			vB_Mail::vbmail($data['email'], $maildata['subject'], $maildata['message'], false);
		}
	}

	/**
	 * This adds a new message
	 *
	 * @param	mixed	must include 'sentto', 'contenttypeid', and the necessary data for that contenttype.
	 * @param	array	Array of options for the content being created.
	 * 	Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification,
	 * 		nl2br, autoparselinks, skipNonExistentRecipients, skipPMEmailForRecipients.
	 * 		- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *		- skipNonExistentRecipients (bool) skips recipients that don't exist instead of throwing an exception.
	 *    - skipPMEmailForRecipients array({userid} => {userid}) skips sendEmailNotifications() for a private message for
	 *    		specified recipients. Used by addPMRecipients() to skip newly added users for the PM notifying old
	 *    		recipients that people have been added to the PM thread.
	 * 	@return	mixed		array with errors, or nodeid.
	 *
	 * Notes: For Notifications, go through the notification library.
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//If we're installing, just abort.
		if (defined('VBINSTALL'))
		{
			return true;
		}

		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);

		$sender = $data['sender'];

		if (isset($data['msgRecipients']) AND empty($data['sentto']))
		{
			$recipientNames = explode(',', $data['msgRecipients']);
			foreach ($recipientNames AS $k => $name)
			{
				$recipientNames[$k] = vB_String::htmlSpecialCharsUni($name);
			}

			$recipQry = $this->assertor->getRows('fetchPmRecipients', array('usernames' => $recipientNames, 'userid' => $sender));

			if (!$recipQry OR !empty($recipQry['errors']))
			{
				throw new vB_Exception_Api('invalid_pm_recipients');
			}
			foreach ($recipQry AS $recipient)
			{
				$data['sentto'][] = $recipient['userid'];
			}
		}

		if (!isset($data['msgtype']) OR ($data['msgtype'] <> 'request' AND $data['msgtype'] <> 'notification'))
		{
			$data['msgtype'] = 'message';
		}
		else if (($data['msgtype'] == 'notification'))
		//If we have a notification we need an about and an aboutid
		{
			if (empty($data['about']) OR empty($data['aboutid']) OR empty($data['sentto']))
			{
				throw new vB_Exception_Api('invalid_data');
			}
		}


		//If we have a message we need text content
		if (($data['msgtype'] == 'message') AND (empty($data['rawtext']) AND empty($data['pagetext'])))
		{
			throw new vB_Exception_Api('need_privatemessage_text');
		}

		if (($data['msgtype'] == 'request') AND (empty($data['rawtext']) AND empty($data['pagetext'])) AND !empty($data['sentto']))
		{
			//it's not clear that we are using the text we generate here.  The PM recipeient for requests will see something
			//different on reciept in the main message center display
			$recipient = vB_User::fetchUserinfo($data['sentto']);
			switch ($data['about'])
			{
				case vB_Api_Node::REQUEST_TAKE_OWNER:
				case vB_Api_Node::REQUEST_SG_TAKE_OWNER:
					$channel = vB_Library::instance('node')->getNodeBare($data['aboutid']);
					$phrase = vB_Api::instanceInternal('phrase')->fetch(array('sent_ownership_transfer_request_for_x_to_y'));
					$data['rawtext'] = $data['pagetext'] = vsprintf($phrase['sent_ownership_transfer_request_for_x_to_y'], array($channel['title'], $recipient['username']));
				break;
				case vB_Api_Node::REQUEST_TAKE_MODERATOR:
				case vB_Api_Node::REQUEST_SG_TAKE_MODERATOR:
					$channel = vB_Library::instance('node')->getNodeBare($data['aboutid']);
					$phrase = vB_Api::instanceInternal('phrase')->fetch(array('sent_moderation_request_for_x_to_y'));
					$data['rawtext'] = $data['pagetext'] = vsprintf($phrase['sent_moderation_request_for_x_to_y'], array($channel['title'], $recipient['username']));
				break;
				case vB_Api_Node::REQUEST_GRANT_MEMBER:
					$channel = vB_Library::instance('node')->getNodeBare($data['aboutid']);
					$phrase = vB_Api::instanceInternal('phrase')->fetch(array('sent_subscription_request_to_x'));
					$data['rawtext'] = $data['pagetext'] = vsprintf($phrase['sent_subscription_request_to_x'], $channel['title']);
				break;
				case vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER:
					$channel = vB_Library::instance('node')->getNodeBare($data['aboutid']);
					$phrase = vB_Api::instanceInternal('phrase')->fetch(array('sent_subscription_request_to_x'));
					$data['rawtext'] = $data['pagetext'] = vsprintf($phrase['sent_subscription_request_to_x'], $channel['title']);
				break;
				default:
					$phrase = vB_Api::instanceInternal('phrase')->fetch(array('sent_follow_request_to_x'));
					$data['rawtext'] = $data['pagetext'] = vsprintf($phrase['sent_follow_request_to_x'], $recipient['username']);
				break;
			}
		}

		// don't check the skipNonExistentRecipients option since
		// we're actually checking the *sender's* folders here.
		// I have added this option because of upgrade failure in specific circumstances described in VBV-13331
		$skipNonExistentRecipients = !empty($options['skipNonExistentRecipients']);
		$this->checkFolders($sender, $skipNonExistentRecipients);

		$sendto = array();
		if (isset($data['respondto']))
		{
			//We have a reply. We maintain the node hierarchy.
			//we also need to keep the list of recipients.
			$data['parentid'] = $data['respondto'];
			//Obviously we've read this, if we're responding to it.
			$this->setRead($data['respondto'], 1, $sender);
			$recipients = $this->assertor->getRows('vBForum:getRecipientsForNode', array('nodeid' => $data['respondto']));
			$msgSender = 0;
			$senderIncluded = false;
			foreach ($recipients AS $recipient)
			{
				if ($msgSender)
				{
					continue;
				}

				if ($recipient['folder'] == self::SENT_FOLDER)
				{
					$msgSender = $recipient['userid'];
				}
			}

			foreach ($recipients as $recipient)
			{
				if ($recipient['userid'] == $msgSender AND $recipient['folder'] != self::SENT_FOLDER)
				{
					$senderIncluded = true;
				}

				$data['sentto'][] = intval($recipient['userid']);
			}
		}
		else if (isset($data['forward']))
		{
			if (empty($data['sentto']))
			{
				throw new vB_Exception_Api('invalid_request');
			}

			$data['parentid'] = $this->pmChannel;
			//Obviously we've read this, if we're forwarding it.
			$this->setRead($data['forward'], 1, $sender);
		}
		else
		{
			//We'll get the folders into which we need to insert this record. In the process we'll
			// validate that all the sentto id's are valid.
			$data['parentid'] = $this->pmChannel;
		}

		if (empty($data['sentto']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (!is_array($data['sentto']))
		{
			$sendto = array($data['sentto']);
		}
		else
		{
			$sendto = array_unique($data['sentto']);
		}

		if (!isset($data['respondto']) AND $data['msgtype'] != 'request')
		{
			foreach($sendto AS $userid)
			{
				//we do this below in most cases and it's cached so this
				//shouldn't add any additional load.
				$recipient = vB_Library::instance('User')->fetchUserinfo($userid);
				$this->checkCanReceivePM($recipient);
			}
		}

		//We can't pass recipients to the parent add method.
		$data['userid']	= $sender;
		$fields = array('parentid', 'rawtext', 'pagetext', 'msgtype', 'title', 'userid', 'about',
			'aboutid', 'folderid', 'deleted', 'msgread', 'publishdate', 'url', 'filedataid',
			'url_title', 'url_meta', 'url_image', 'attachments');
		$contentData = array();
		foreach ($fields AS $field)
		{
			if (isset($data[$field]))
			{
				$contentData[$field] = $data[$field];
			}
		}

		try
		{
			$options['skipTransaction'] = true;

			// create the node, unless it's a notification
			if (!($data['msgtype'] == 'notification'))
			{

				if (!$skipTransaction)
				{
					$this->assertor->beginTransaction();
				}
				$result = parent::add($contentData, $options, $convertWysiwygTextToBbcode);
			}
			else
			{
				// USE THE NOTIFICATION LIBRARY
				throw new vB_Exception_Api('invalid_data');
			}


			if (!$result OR !empty($result['errors']) OR !intval($result['nodeid']))
			{
				if (!$skipTransaction)
				{
					$this->assertor->rollbackTransaction();
				}
				throw new vB_Exception_Api('invalid_data');
			}

			if (!$skipTransaction)
			{
				$this->beforeCommit($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
				$this->assertor->commitTransaction();
			}
		}
		catch(exception $e)
		{
			if (!$skipTransaction)
			{
				$this->assertor->rollbackTransaction();
			}
			throw $e;
		}

		$nodeid = $result['nodeid'];

		//If we are passed 'request', then this is just inserted for the recipient. But the user must be an admin.
		$insertSent = false;
		if ($data['msgtype']== 'notification')
		{
			// USE THE NOTIFICATION LIBRARY
			throw new vB_Exception_Api('invalid_request');
			//$folderKey = self::NOTIFICATION_FOLDER;
		}
		else if ($data['msgtype'] == 'request')
		{
			$folderKey = self::REQUEST_FOLDER;
		}
		else
		{
			$folderKey = self::MESSAGE_FOLDER;
			$insertSent = true;
		}

		$userOptions = vB::getDatastore()->getValue('bf_misc_useroptions');
		//Note that if this is a response, sendto is empty.
		foreach ($sendto AS $recipient)
		{
			// verify recipient's folders, but instruct checkFolders to not throw
			// an exception if we have an invalid recipient
			$folderCheck = $this->checkFolders($recipient, $skipNonExistentRecipients);

			if ($skipNonExistentRecipients AND isset($folderCheck['result']) AND $folderCheck['result'] === 'user_skipped')
			{
				// bad recipient; skip this notification and continue
				continue;
			}

			$sendData = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid' => $recipient,
				'nodeid' => $result['nodeid'],
				'folderid' => $this->folders[$recipient]['systemfolders'][$folderKey],
			);

			// create a sentto record only if it's not an existing notification
			if (!($data['msgtype'] == 'notification' AND !empty($existingNotification) AND empty($existingNotification['errors'])))
			{
				$this->assertor->assertQuery('vBForum:sentto', $sendData);
			}

			// Going through user LIB not API. The API will mask the email field unless current user
			// has canadminusers.
			$recipientInfo = vB_Library::instance('User')->fetchUserinfo($recipient);
			$emailOnPm = ($recipientInfo['options'] & $userOptions['emailonpm']);

			if ($recipientInfo['emailnotification'] == 1)
			{
				if ($contentData['msgtype'] == 'request')
				{
					$contentData['sentto'] = $data['sentto'];
					$contentData['folderid'] = $this->folders[$recipient]['systemfolders'][$folderKey];
					$contentData['email'] = $recipientInfo['email'];
					$contentData['username'] = $recipientInfo['username'];
					$this->sendEmailNotification($contentData);
				}
			}

			// only send email about PM if this is a message, recipient isn't the sender &  the recipient opted in.
			$sendPMEmail = (
				($data['msgtype'] == 'message')	AND
				$recipient != vB::getCurrentSession()->get('userid') AND
				$emailOnPm AND
				empty($options['skipPMEmailForRecipients'][$recipient])
			);

			if ($sendPMEmail)
			{
				$data['folderid'] = $this->folders[$recipient]['systemfolders'][$folderKey];
				$data['recipient'] = $recipient;
				$data['contentid'] = $result['nodeid'];
				$data['email'] = $recipientInfo['email'];
				$data['username'] = $recipientInfo['username'];
				$this->sendEmailNotification($data);
			}
		}

		// insert message starter for sender if needed
		if (!empty($data['respondto']) AND ($msgSender AND !$senderIncluded))
		{
			// don't check the skipNonExistentRecipients option since
			// we're actually checking the *sender's* folders here.
			// I added the flag bacause update failures described in VBV-13331
			$this->checkFolders($msgSender, $skipNonExistentRecipients);
			$sendData = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid' => $msgSender,
				'nodeid' => $data['respondto'],
				'folderid' => $this->folders[$msgSender]['systemfolders'][$folderKey],
				'msgread' => 1,
			);

			$this->assertor->assertQuery('vBForum:sentto', $sendData);
		}

		//If this is a new message, we also insert a "sentto" record for the sender, but we mark that "read".
		//That ensures we properly handle replies.
		if (!in_array($data['msgtype'], array('notification', 'request')))
		{
			//If someone deleted their message we need to restore it. For that we need the starter.
			//This can only occur, of course, if this is a response.
			$parent = $this->nodeApi->getNode($data['parentid']);

			//if this is a new PM Starter then there isn't anything to restore.  Running the query
			//on the PM channel isn't going to hurt, but it isn't going to help either.
			if ($parent['contenttypeid'] != vB_Types::instance()->getContentTypeID('vBForum_Channel'))
			{
				$this->assertor->assertQuery('vBForum:resetStarterPmOnResponse', array(
					'nodeid' => $parent['starter'],
					'userid' => $sender,
					'folderphrases' => array(self::TRASH_FOLDER, self::MESSAGE_FOLDER),
				));
			}

			// @TODO : Shouldn't we move the "restored" messages back to the inbox...?
			$this->setRead($nodeid, 1, $sender, 'sent_items');
		}

		if ($insertSent)
		{
			// don't check the skipNonExistentRecipients option since
			// we're actually checking the *sender's* folders here.
			$this->checkFolders($sender, $skipNonExistentRecipients);

			$queryData = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid' => $sender,
				'nodeid' => $result['nodeid'],
				'folderid' => $this->folders[$sender]['systemfolders'][self::SENT_FOLDER],
				'msgread' => 1,
			);
			$this->assertor->assertQuery('vBForum:sentto', $queryData);
		}

		$sendto[] = $sender; // duplicate ids is fine in this array
		$this->buildPmTotals($sendto);

		if (!$skipTransaction)
		{
			//The child classes that have their own transactions all set this to true so afterAdd is always called just once.
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}
		// Are PMs ever searched? Why do we need to index them?
		vB_Library::instance('search')->index($result['nodeid']);

		//update user cached info
		if ($folderKey == self::MESSAGE_FOLDER)
		{
			vB_Library::instance('user')->clearUserInfo($sendto);
		}

		return $result;
	}

	// $recipient is either a user info array, or an array with a userid
	public function checkCanReceivePM($recipient)
	{
		// Make sure we have all user data.
		if (empty($recipient['username']))
		{
			$recipient = vB_Library::instance('user')->fetchUserinfo($recipient['userid']);
		}
		$usercontext = vB::getUserContext();
		$recipientcontext = vB::getUserContext($recipient['userid']);
		$recipientsettings = vB_Api::instanceInternal('user')->fetchUserSettings($recipient['userid']);
		$current_user_following = vB_Api::instanceInternal('follow')->isFollowingUser($recipient['userid']);
		$pmquota = $recipientcontext->getLimit('pmquota');


		$isStaff = ($usercontext->isAdministrator() OR $usercontext->isModerator());
		//user:
		//a) has PM on generally
		//b) has a PM quota
		//c) hasn't set PMs to buddies only OR the current user is a buddy
		$userCanReceive = ($recipientsettings['receivepm'] AND $pmquota AND (!$recipientsettings['receivepmbuddies'] OR ($current_user_following == 1)));

		if (!$isStaff	AND !$userCanReceive)
		{
			throw new vB_Exception_Api('pmrecipturnedoff', $recipient['username']);
		}

		if ($recipient['pmtotal'] >= $pmquota AND !$usercontext->hasPermission('pmpermissions', 'canignorequota'))
		{
			throw new vB_Exception_Api('pmquotaexceeded', array($recipient['username']));
		}
	}

	protected function needsFloodCheck($data, $options)
	{
		if ($data['msgtype'] != 'message')
		{
			// Only private messages (not requests, or legacy notifications that shouldn't come this way anymore) needs the special flood check.
			return parent::needsFloodCheck($data, $options);
		}

		if (empty($options['skipFloodCheck']) AND ($this->options['pm_floodchecktime'] > 0) AND ($this->doFloodCheck) AND !vB::getUserContext()->isAdministrator())
		{
			/*
				starteronly		isstarter	needscheck
				0				0			1
				0				1			1
				1				0			0
				1				1			1

				! (starteronly & !isstarter)
			 */
			$isStarter = ($data['parentid'] == $this->pmChannel);
			$canSkip = ($this->options['pm_floodcheck_starteronly'] AND !$isStarter);
			if ($canSkip)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
		else
		{
			return false;
		}
	}

	protected function checkFloodAndThrowException($data)
	{
		// Doubt this is still necessary as notifications should not come in through PM lib, but not changing it for VBV-16139
		if (isset($data['msgtype']) AND $data['msgtype'] == 'notification')
		{
			return false;
		}

		if ($data['msgtype'] != 'message')
		{
			// Only private messages (not requests, or legacy notifications that shouldn't come this way anymore) needs the special flood check.
			return parent::checkFloodAndThrowException($data);
		}

		if ($this->options['pm_floodchecktime'] == 0)
		{
			// disabled.
			return false;
		}

		$timenow = vB::getRequest()->getTimeNow();
		$cutoff =  $timenow - $this->options['pm_floodchecktime'];
		$conditions = array(
			array('field' => 'userid', 'value' => $data['userid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
			array('field' => 'created', 'value' => $cutoff, 'operator' => vB_dB_Query::OPERATOR_GT),
			array('field' => 'contenttypeid', 'value' => $this->contenttypeid, 'operator' => vB_dB_Query::OPERATOR_EQ),
		);

		if ($this->options['pm_floodcheck_starteronly'])
		{
			$conditions[] = array('field' => 'parentid', 'value' => $this->pmChannel, 'operator' => vB_dB_Query::OPERATOR_EQ);
		}

		$node = vB::getDbAssertor()->getRow('vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => $conditions
			),
			array('field' => array('created'), 'direction' => array(vB_dB_Query::SORT_DESC))
		);

		if (!empty($node))
		{
			$wait = $node['created'] - $cutoff;
			// I'm not sure why we write to cache here but the parent function (in vB_Library_Content) does, so we'll do it here.
			vB_Library_Content::writeToCache(array($node), vB_Library_Content::CACHELEVEL_NODE);

			throw new vB_Exception_Api('pmfloodcheck', array($this->options['pm_floodchecktime'], $wait));
		}
		else
		{
			return false;
		}
	}

	protected function duplicateCheck($data)
	{
		if (isset($data['msgtype']) AND (($data['msgtype'] == 'notification') OR ($data['msgtype'] == 'request')))
		{
			return false;
		}
		return parent::duplicateCheck($data);
	}


	/**
	 *	Permanently deletes a node
	 *	@param	integer	The nodeid of the record to be deleted
	 *
	 *	@return	boolean
	 */
	public function delete($nodeid)
	{
		/*
			VBV-15267
			Currently, a private message can have attachments. While the vb_library_content::delete() will handle removing the actual table records
			in each child content library's $tablename array (plus the node table by default), it doesn't actually bother calling each child content
			library's delete(), which might have more cleanup (for ex., attach would decrement the filedata refcount, video/link might remove its
			thumbnail filedata record, etc).

			I'm not about to overhaul the content delete, so I'll add some code here to prefetch all children and do cleanup. Since the only children
			allowed by privatemessage due to UI is privatemessage replies or attachments, I'll only handle those two cases here.

			TODO: Generalize this more, as the PM content should not have to know intricate details about any other content types.
			For ex, add an "afterDelete()" function, move all extra cleanup code in each content library's delete() into this
			new function and have delete() call afterDelete(), and have the root content library call each descendant's afterDelete()
			function. It might also help to ensure that afterDelete() is bulk-able as well, as descendants will be bulk removed.
		 */

		$descendants = $this->assertor->assertQuery('vBForum:getDescendants', array('nodeid' => $nodeid));
		$removeSenttoRecords = array(); // note that nodeds in $nodeid will be fetched @ depth==1 in above query.
		$attachLIB = vB_Library::instance('content_attach');
		foreach ($descendants as $row)
		{
			$className = '';
			$childLIB = self::getContentLib($row['contenttypeid']);
			if ($childLIB)
			{
				$className = $childLIB->fetchContentType();
				switch ($className)
				{
					case 'vBForum_Attach':
						$attachLIB->delete($row['child']);
						break;
					case 'vBForum_PrivateMessage':
						$removeSenttoRecords[$row['child']] = $row['child'];
						break;
					default:
						// not supported
						break;
				}
			}
		}

		//parent function allows an array of nodes to be deleted and I think all of
		//the queries in this function will actually work in this case.  So we'll assume for
		//this that the nodeid could be an array of nodes.

		//we want to use getRows here because we'll be doing more operations before
		//we use the data returned so keeping a recordset open is dodgy.  We need to do this
		//before we delete because the we need some of the records about to be deleted to
		//get the pending requests, but we don't want to actually delete them until we
		//succeed on the node deletion.
		$pendingRequests = $this->assertor->getRows('vBForum:getPendingRequestsForNodes', array(
			'nodeids' => $nodeid,
			'request' => vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOW,
		));

		//Call the parent first. It will do the permission checks, among other things.
		$result = parent::delete($nodeid);

		if ($result)
		{
			//

			//We need to delete from the sentto table.
			$users = array();

			foreach($pendingRequests AS $request)
			{
				$this->assertor->delete('userlist', $request);
			}

			$recipients = $this->assertor->select('vBForum:sentto', array('nodeid' => $removeSenttoRecords));
			foreach ($recipients AS $recipient)
			{
				$users[] = $recipient['userid'];
			}

			$this->assertor->delete('vBForum:sentto', array('nodeid' => $removeSenttoRecords));

			if (!empty($users))
			{
				$this->buildPmTotals($users);
			}
		}
		return $result;
	}

	/**
	 * Delete the records without updating the parent info. It is used when deleting a whole channel and it's children need to be removed
	 * @param array $childrenIds - list of node ids
	 */
	public function deleteChildren($childrenIds)
	{
		//delete the main tables
		parent::deleteChildren($childrenIds);

		//delete sentto
		$this->assertor->assertQuery('vBForum:sentto', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $childrenIds,
		));
	}

	/**
	 * 	Moves a message to a different folder
	 *
	 *	@param	int		the node to be moved
	 *	@param	int		the new parent node.
	 *
	 *	@return	bool	did it succeed?
	 *
	 */
	public function moveMessage($nodeid, $newFolderid, $existing)
	{
		//A user can only move, obviously, to one of their own folders
		$currentUser = vB::getCurrentSession()->get('userid');
		$this->checkFolders($currentUser);

		if (array_key_exists($newFolderid , $this->folders[$currentUser]['folders']))
		{
			$movedMsgs = array();
			foreach ($existing as $nodeRecord)
			{
				$key = $nodeRecord['nodeid'] . '-' . $nodeRecord['userid'];

				if (!in_array($key, $movedMsgs))
				{
					$data = array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'folderid' => $newFolderid,
						'deleted'  => 0,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'userid',   'value' => $currentUser),
							array('field' => 'nodeid',   'value' => $nodeRecord['nodeid']),
							array('field' => 'folderid', 'value' => $nodeRecord['folderid'])
					));
					$result = $this->assertor->assertQuery('vBForum:sentto', $data);
					$movedMsgs[] = $key;
				}
				else
				{
					$this->assertor->assertQuery('vBForum:sentto', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
						'userid' => $nodeRecord['userid'],
						'nodeid' => $nodeRecord['nodeid'],
						'folderid' => $nodeRecord['folderid']
					));
				}
			}
			return true;
		}
		else
		{
			throw new vB_Exception_Api('invalid_data');
		}
	}

	/**
	 * 	Get a message
	 *
	 *	@param	int		the nodeid
	 *	@return	mixed	array of data
	 **/
	public function getMessage($nodeid)
	{
		$content = $this->nodeApi->getNode($nodeid);
		$userid =  vB::getCurrentSession()->get('userid');

		// Note, getMessageTree() will mark the message as read.
		return $this->getMessageTree($nodeid, array($userid, $content['userid']), $userid);
	}

	/**
	 * Get a single request
	 * @param	int		the nodeid
	 * @return	array The node data array for the request
	 */
	public function getRequest($nodeid)
	{
		$userInfo =  vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$content = $this->nodeApi->getNodeContent($nodeid);

		//getNodeContent returns a list.
		$content = $content[$nodeid];

		//if this is the author we can return the value
		if ($content['userid'] == $userid)
		{
			return $content;
		}
		else
		{
			//Maybe this is a recipient.
			$recipients = $this->assertor->getRows('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'nodeid' => $nodeid));
			$canshow = false;
			foreach ($recipients as $recipient)
			{
				if ($recipient['userid'] == $userid)
				{
					return $content;
				}
			}
		}

		//If we got here, this user isn't authorized to see this record. Well, it's also possible this may not exist.
		throw new vB_Exception_Api('no_permission');
	}

	/**
	 * Get a message and all replies and sets the message to "read"
	 *
	 * @param	int    $nodeid    the nodeid
	 *
	 * @return	array    array of data
	 */
	public function getMessageTree($nodeid, $exclude, $userid)
	{
		//The permissions are checked before we get here, so we don't need to be concerned
		$messagesQry = $this->assertor->getRows('vBForum:getPrivateMessageTree', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'nodeid' => $nodeid,
			'userid' => $userid
		));

		$messages = array();
		foreach ($messagesQry AS $message)
		{
			if (isset($messages[$message['nodeid']]))
			{
				continue;
			}
			$content = vB_Library::instance('node')->getNodeContent($message['nodeid']);
			$messages[$message['nodeid']] = $message + $content[$message['nodeid']];
		}

		$userApi = vB_Api::instanceInternal('user');
		$initial = key($messages);
		$messageIds = array();
		foreach ($messages as $key => $message)
		{
			// @TODO implement fetchAvatars to get all avatars together instead of one by one
			$messages[$key]['senderAvatar'] = $messages[$key]['avatar'];//$userApi->fetchAvatar($message['userid']);
			$messages[$key]['starter'] = false;

			if (empty($message['pagetext']))
			{
				$messages[$key]['pagetext'] = $message['rawtext'];
			}
			$messageIds[] = $message['nodeid'];
		}
		// TODO: This isn't correct. There's no guarantee the first node (or ANY node requested here) is
		// a starter, because we don't verify that $nodeid is a starter.
		$messages[$initial]['starter'] = true;

		// try to set the first recipient
		$needLast = array();
		if (empty($messages[$initial]['lastauthorid']) OR $messages[$initial]['lastauthorid'] == $userid)
		{
			$needLast[] = $messages[$initial]['nodeid'];
		}

		// @TODO check for a way to implement a generic protected library method to fetch recipients instead of cloning code through methods.
		// fetch the right lastauthor if needed
		if (!empty($needLast))
		{
			$neededUsernames = $this->assertor->assertQuery('vBForum:getPMLastAuthor', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $needLast, 'userid' => $userid));
			foreach ($neededUsernames AS $user)
			{
				if ($user['nodeid'] == $messages[$initial]['nodeid'])
				{
					$messages[$initial]['lastcontentauthor'] = $user['username'];
					$messages[$initial]['lastauthorid'] = $user['userid'];
				}
			}
		}

		$included = false;
		$recipients = array();
		$recipientsInfo = $this->assertor->assertQuery('vBForum:getPMRecipientsForMessage', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'nodeid' => $messages[$initial]['nodeid']
		));

		foreach ($recipientsInfo as $recipient)
		{
			if (($recipient['userid'] == $userid))
			{
				if (!$included)
				{
					$included = true;
				}

				continue;
			}
			else if ($messages[$initial]['lastcontentauthor'] == $recipient['username'])
			{
				continue;
			}

			if (!isset($recipients[$recipient['userid']]))
			{
				$recipients[$recipient['userid']] = $recipient;
			}
		}

		// and set the first recipient properly if needed
		$firstRecipient = array();
		if (!empty($messages[$initial]['lastcontentauthor']) AND !empty($messages[$initial]['lastauthorid']) AND ($messages[$initial]['lastauthorid'] != $userid))
		{
			$firstRecipient = array(
				'userid' => $messages[$initial]['lastauthorid'],
				'username' => $messages[$initial]['lastcontentauthor']
			);
		}
		else if (!empty($recipients))
		{
			$firstRecipient = reset($recipients);
			unset($recipients[$firstRecipient['userid']]);
		}

		//set these messages read.
		$this->setRead($messageIds, 1, $userid);
		return array('message' => $messages[$initial], 'messages' => $messages, 'otherRecipients' => count($recipients), 'firstRecipient' => $firstRecipient, 'included' => $included);
	}


	/**
	 * 	This lists the folders.
	 *	@param	mixed	array of system folders to be hidden. like self::MESSAGE_FOLDER
	 *	@return	mixed	array of folderid => title
	 */
	public function listFolders($suppress = array())
	{
		$userInfo =  vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$this->checkFolders($userid);
		//You can only suppress system folders
		if (!empty($suppress))
		{
			$folders = $this->folders[$userid]['folders'];
			foreach ($suppress as $titlephrase)
			{
				if (array_key_exists($titlephrase, $this->folders[$userid]['systemfolders']))
				{
					$folderid = $this->folders[$userid]['systemfolders'][$titlephrase];

					if (array_key_exists($folderid, $folders))
					{
						unset($folders[$folderid]);
					}
				}
			}

			return $folders;
		}

		return $this->folders[$userid]['folders'];
	}

	/**
	 * This creates a new message folder. It returns false if the record already exists and the id if it is able to create the folder
	 * @return	int
	 */
	public function createMessageFolder($folderName, $userid)
	{
		$cleaner = vB::get_cleaner();
		$foldername = $cleaner->clean($folderName, $vartype = vB_Cleaner::TYPE_NOHTML);


		$this->checkFolders($userid);
		if (!in_array($foldername, $this->folders[$userid]['folders']))
		{
			$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT, 'userid' => $userid,	'title' => $foldername);
			//We need for the new folder to be sorted correctly. Easiest to unset, and if needed the folders will be rebuilt.
			unset($this->folders[$userid]);
			return $this->assertor->assertQuery('vBForum:messagefolder', $data);
		}
	}

	/**
	 * Moves a node to the trashcan. Wrapper for deleteMessage()
	 * @param	int
	 */
	public function toTrashcan($nodeid)
	{
		$userInfo =  vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$this->checkFolders($userid);
		//If we're already in the trashcan we delete it.
		$existing = $this->assertor->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid, 'folderid' => $this->folders[$userid]['systemfolders'][self::TRASH_FOLDER]));

		if ($existing->valid())
		{
			$this->delete($nodeid);
			return;
		}

		$this->moveMessage($nodeid, $this->folders[$userid]['systemfolders'][self::TRASH_FOLDER], $existing);
	}


	/**
	 * This summarizes messages for specified user
	 * @return	mixed - array-includes folderId, title, quantity not read.
	 */
	public function fetchSummary($userid)
	{
		$this->checkFolders($userid);
		$folders = $this->assertor->getRows('vBForum:messageSummary', array('userid' => $userid));
		/* Here we need to do some rearranging.  We get the user-created folders first, and the standards ones at the end.
		   But we want:
		   Message
		   <custom>
		   Trash
		   Requests
		   Notification
		*/

		$results = array('customFolders' => ARRAY());
		$totalUnread = 0;

		//messages first
		foreach ($folders as $key => $folder)
		{

			if ($folder['titlephrase'] == self::MESSAGE_FOLDER)
			{
				$phrase = vB_Phrase::fetchSinglePhrase($folder['titlephrase']);
				$folder['title'] = (string) $phrase;
				$totalUnread += $folder['qty'];
				$results['messages'] = $folder;
				unset($folders[$key]);
					break;
			}
		}

		// sent items
		foreach ($folders as $key => $folder)
		{
			if ($folder['titlephrase'] == self::SENT_FOLDER)
			{
				$phrase = vB_Phrase::fetchSinglePhrase($folder['titlephrase']);
				$folder['title'] = (string) $phrase;
				// never show the count
				$folder['qty'] = 0;
				$results['sent_items'] = $folder;
				unset($folders[$key]);
					break;
			}
		}

		//now custom
		foreach ($folders as $key => $folder)
		{
			//if it's a custom folder it won't have a title phrase.
			if (empty($folder['titlephrase']) )
			{
				$totalUnread += $folder['qty'];
				$results['customFolders'][] = $folder;
				unset($folders[$key]);
			}
		}

		//now trash
		foreach ($folders as $key => $folder)
		{

			if ($folder['titlephrase'] == self::TRASH_FOLDER)
			{
				$phrase = vB_Phrase::fetchSinglePhrase($folder['titlephrase']);
				$folder['title'] = (string) $phrase;
				$totalUnread += $folder['qty'];
				$results['trash'] = $folder;
				unset($folders[$key]);
					break;
			}
		}

		//Now requests
		foreach ($folders as $key => $folder)
		{

			if ($folder['titlephrase'] == self::REQUEST_FOLDER)
			{
				$phrase = vB_Phrase::fetchSinglePhrase($folder['titlephrase']);
				$folder['title'] = (string) $phrase;
					$totalUnread += $folder['qty'];
				$results['requests'] = $folder;
				unset($folders[$key]);
					break;
			}
		}

		//Notifications
		$cachedFoldersInfo = $this->fetchFolders($userid);	// this is built by the checkFolders() call @ the beginning of this function.
		$notificationFolderid = $cachedFoldersInfo['systemfolders'][self::NOTIFICATION_FOLDER];
		$notificationQty = vB_Library::instance('notification')->fetchNotificationCountForUser($userid, array('readFilter' => 'unread_only'));
		$results['notifications'] = array(
			'titlephrase'	=> self::NOTIFICATION_FOLDER,
			'title'			=> (string) vB_Phrase::fetchSinglePhrase(self::NOTIFICATION_FOLDER),
			'folderid'		=> $notificationFolderid,
			'qty'			=> $notificationQty,
		);
		$totalUnread += $notificationQty;

		// @TODO implement this nicer...
		$phrases = vB_Api::instanceInternal('Phrase')->fetch(array(self::PENDING_FOLDER, self::INFRACTION_FOLDER, self::DELETED_ITEMS_FOLDER));
		$folder['folderid'] = $this->getPendingPostFolderId();
		$folder['titlephrase'] = self::PENDING_FOLDER;
		$folder['title'] = $phrases[self::PENDING_FOLDER];
		$pendingPosts = vB_Api::instanceInternal('node')->listPendingPostsForCurrentUser(array('totalcount' => true));
		$folder['qty'] = !empty($pendingPosts['pageInfo']['totalcount']) ? $pendingPosts['pageInfo']['totalcount'] : 0;
		$results['pending'] = $folder;

		$folder = array();
		$folder['folderid'] = $this->getInfractionFolderId();
		$folder['titlephrase'] = self::INFRACTION_FOLDER;
		$folder['title'] = $phrases[self::INFRACTION_FOLDER];
		$folder['qty'] = 0;
		$results['infractions'] = $folder;

		$folder = array();
		$folder['folderid'] = $this->getDeletedItemsFolderId();
		$folder['titlephrase'] = self::DELETED_ITEMS_FOLDER;
		$folder['title'] = $phrases[self::DELETED_ITEMS_FOLDER];
		$folder['qty'] = 0;
		$results['deleted_items'] = $folder;
		return array('unread' => $totalUnread, 'folders' => $results);
	}

	/**
	 * 	This lists messages for current user
	 *
	 *	@param array $data-
	 *		'sortDir'
	 *		'pageNum
	 *		'perpage'
	 *		'folderid'
	 *		'showdeleted'
	 *		'ignoreRecipients'
	 *	@return	array - list of messages.
	 */
	public function listMessages($data, $userid)
	{
		$this->checkFolders($userid);
		// todo: This probably needs a check for $data['folderid'] == ...NOTIFICATION_FOLDER, and shortcircuit to listNotifications()
		// to make it easier for notifications 2.0 refactor.
		if ( isset($data['folderid']) AND !array_key_exists($data['folderid'], $this->folders[$userid]['folders']))
		{
			throw new vB_Exception_Api('no_permission');

		}
		else if (empty($data['folderid']))
		{
			$folderid = $this->folders[$userid]['systemfolders'][self::MESSAGE_FOLDER];
			$data['folderid'] = $folderid;
		}
		$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD, 'userid' => $userid);
		foreach (array('sortDir', 'folderid') as $param)
		{
			if (isset($data[$param]))
			{
				$params[$param] = $data[$param];
			}
		}

		if (!empty($data['showdeleted']))
		{
			$params['showdeleted'] = 1;
		}
		else
		{
			$params['showdeleted'] = 0;
		}

		if (isset($data['perpage']) AND intval($data['perpage']))
		{
			$params[vB_dB_Query::PARAM_LIMIT] = intval($data['perpage']);
		}
		else
		{
			$params[vB_dB_Query::PARAM_LIMIT] = 50;
		}

		if (empty($data['pageNum'] ))
		{
			$params[vB_dB_Query::PARAM_LIMITPAGE] = 1;
		}
		else
		{
			$params[vB_dB_Query::PARAM_LIMITPAGE] = intval($data['pageNum']);
		}

		$methodName = 'listPrivateMessages';
		if ($data['folderid'] == $this->folders[$userid]['systemfolders'][self::SENT_FOLDER])
		{
			$methodName = 'listSentMessages';
		}

		$messageQry = $this->assertor->assertQuery('vBForum:' . $methodName, $params);
		//Let's get all the recipients;
		$messages = array();
		$recipientsNeeded = array();
		if ($messageQry AND is_object($messageQry))
		{
			$orderListForJs = array();
			foreach ($messageQry AS $message)
			{
				$message['recipients'] = array();
				$message['included'] = false;
				if (empty($message['lastauthorid']) OR ($message['lastauthorid'] == $userid))
				{
					$recipientsNeeded[$message['nodeid']] = $message['nodeid'];
					$message['lastauthor'] = '';
					$message['lastauthorid'] = 0;
				}

				$messages[$message['nodeid']] = $message;
				$orderListForJs[] = $message['nodeid'];
			}

			if (!empty($messages))
			{
				$userApi = vB_Api::instanceInternal('user');
				if (empty($data['ignoreRecipients']))
				{
					$messageIds = array_keys($messages);
					$recipientsInfo = $this->assertor->assertQuery('vBForum:getPMRecipientsForMessage', array('nodeid' => $messageIds));

					// @TODO check for a way to implement a generic protected library method to fetch recipients instead of cloning code through methods.
					if (!empty($recipientsNeeded))
					{
						$neededUsernames = $this->assertor->assertQuery('vBForum:getPMLastAuthor', array(
							'nodeid' => $recipientsNeeded,
							'userid' => $userid,
						));

						foreach ($neededUsernames AS $username)
						{
							if (isset($messages[$username['nodeid']]))
							{
								$messages[$username['nodeid']]['lastauthor'] = $username['username'];
								$messages[$username['nodeid']]['lastauthorid'] = $username['userid'];
							}
						}
					}
					foreach ($recipientsInfo as $recipient)
					{
						if (isset($messages[$recipient['starter']]))
						{
							if (($recipient['userid'] == $userid))
							{
								if (empty($messages[$recipient['starter']]['included']))
								{
									$messages[$recipient['starter']]['included'] = true;
								}

								continue;
							}
							else if ($messages[$recipient['starter']]['lastauthor'] == $recipient['username'])
							{
								continue;
							}

							if (!isset($messages[$recipient['starter']]['recipients'][$recipient['userid']]))
							{
								$messages[$recipient['starter']]['recipients'][$recipient['userid']] = $recipient;
							}
						}
					}
				}

				foreach ($messages as $key => $message)
				{
					if (empty($data['ignoreRecipients']))
					{
						// set the first recipient
						if (!empty($message['lastauthor']) AND !empty($message['lastauthorid']) AND ($message['lastauthorid'] != $userid))
						{
							$messages[$key]['firstrecipient'] = array(
								'userid' => $message['lastauthorid'],
								'username' => $message['lastauthor']
							);
						}
						else if (!empty($message['recipients']))
						{
							$firstrecip = reset($message['recipients']);
							$messages[$key]['firstrecipient'] = $firstrecip;
							unset($messages[$key]['recipients'][$firstrecip['userid']]);
						}

						$messages[$key]['otherRecipients'] = count($messages[$key]['recipients']);
					}

					$messages[$key]['senderAvatar'] = $userApi->fetchAvatar($message['userid']);
					if (empty($message['previewtext']))
					{
						$messages[$key]['previewtext'] = vB_String::getPreviewText($message['rawtext']);
					}

					// we need these ordered in a specific way. JSON parse + decode will make the nodeid keys unordered object properties.
					// Just add this to every array as to not break the result format but still allow us to skip a re-sort in JS.
					$messages[$key]['orderListForJs'] = $orderListForJs;
				}
			}
		}

		return $messages;
	}

	/**
	 * @deprecated	5.1.6	Only used by unit tests
	 *
	 * This lists notifications for current user
	 *
	 * @param	Array	$data		@see vB_Library_Notification::fetchNotificationsForCurrentUser()
	 * @param	Int		$userid		Not used.
	 *
	 * @return	Array	@see vB_Library_Notification::fetchNotificationsForCurrentUser()
	 **/
	public function listNotifications($data, $userid)
	{
		$notifications = vB_Library::instance('notification')->fetchNotificationsForCurrentUser($data);
		return $notifications;
	}

	/**
	 * This lists messages for current user
	 *
	 * @param mixed- can pass sort direction, type, page, perpage, or folderid.
	 * @return mixed - array-includes folderId, title, quantity not read. Also 'page' is array of node records for page 1.
	 */
	public function listSpecialPrivateMessages($data = array())
	{
		$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD, 'userid' => vB::getCurrentSession()->get('userid'));
		foreach (array('sortDir', vB_dB_Query::PARAM_LIMITSTART, 'contenttypeid','folderid', 'userid') as $param)
		{
			if (isset($data[$param]))
			{
				$params[$param] = $data[$param];
			}
		}


		if (isset($params['perpage']) AND intval($params['perpage']))
		{
			$params[vB_dB_Query::PARAM_LIMIT]= 50;
		}
		else
		{
			$params[vB_dB_Query::PARAM_LIMIT]= 50;
		}

		if (empty($params[vB_dB_Query::PARAM_LIMITSTART] ))
		{
			$params[vB_dB_Query::PARAM_LIMITSTART]= 1;
		}

		$messageQry = $this->assertor->assertQuery('vBForum:listSpecialMessages', $params);

		$messages = array();

		if ($messageQry AND is_object($messageQry))
		{
			foreach ($messageQry AS $message)
			{
				$messages[$message['nodeid']] = $message;
			}

			if (!empty($messages))
			{
				$userApi = vB_Api::instanceInternal('user');

				foreach ($messages as  $key => $message)
				{
					$messages[$key]['senderAvatar'] = $userApi->fetchAvatar($message['userid']);
					if (empty($message['previewtext']))
					{
						$messages[$key]['previewtext'] = vB_String::getPreviewText($message['rawtext']);
					}
				}
			}

		}
		return $messages;

	}

	/**
	 * Permanently deletes a message
	 *
	 * @param	int	nodeid of the entry to be deleted.
	 * @return bool did the deletion succeed?
	 */
	public function deleteMessage($nodeid, $userid = false)
	{
		if (!$userid)
		{
			$userid = vB::getCurrentSession()->get('userid');
		}
		$this->checkFolders($userid);

		// if !$canUsePmSystem then only usable folders are notifications, requests, and pending
		$pmquota = vB::getUserContext($userid)->getLimit('pmquota');
		$vboptions = vB::getDatastore($userid)->getValue('options');
		$canUsePmSystem = ($vboptions['enablepms'] AND $pmquota);

		//We set "deleted" for this user's record. If there is nobody still connected we do the actual delete.
		$data = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'deleted' => 1,
			vB_dB_Query::CONDITIONS_KEY => array(
				'userid' => $userid,
				'nodeid' => $nodeid
			)
		);
		$this->assertor->assertQuery('vBForum:sentto', $data);

		//Is there anyone currently still accessing this message?
		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'deleted' => 0, 'nodeid' => $nodeid);
		$undeleted = $this->assertor->getRows('vBForum:sentto', $data);

		//If there's no matching records, we get an error message.
		if (empty($undeleted) OR !empty($undeleted['errors']))
		{
			//We set the record to "deleted"
			$data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'deleted' => vB::getRequest()->getTimeNow(),
				vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $nodeid)
			);
			$this->assertor->assertQuery('vBForum:privatemessage', $data);
		}

		$this->buildPmTotals(array($userid));

		// update userinfo
		vB_Library::instance('user')->clearUserInfo(array($userid));
		return true;
	}

	/**
	 * Deletes all pms for a given user
	 *
	 * This will mark all "sentto" records for the given user as deleted.
	 * In addtion it will mark any PM records for deletion that no longer have
	 * any users attached to them.  The actual deletion is handled via cron script.
	 *
	 * @param	int	userid
	 * @return int number of sentto items marked for delete (the users pms)
	 */
	public function deleteMessagesForUser($userid)
	{
		$this->checkFolders($userid);

		//We set "deleted" for this user's record. If there is nobody still connected we do the actual delete.
		$count = $this->assertor->assertQuery('vBForum:sentto', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'deleted' => 1,
			vB_dB_Query::CONDITIONS_KEY => array(
				'userid' => $userid,
			)
		));

		//Is there anyone currently still accessing this message?
		$this->assertor->assertQuery('vBForum:markUserPMsDeleted', array(
			'deletiondate' => vB::getRequest()->getTimeNow(),
			'userid' => $userid
		));

		$this->buildPmTotals(array($userid));

		// update userinfo
		vB_Library::instance('user')->clearUserInfo(array($userid));
		return $count;
	}

	public function deleteSentMessagesForUser($userid)
	{
		$this->checkFolders($userid);

		//We set "deleted" for this user's record. If there is nobody still connected we do the actual delete.
		$count = $this->assertor->assertQuery('vBForum:deleteSentMessagesForUser', array(
			'userid' => $userid,
			'contenttypeid' => vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage')
		));

		//Is there anyone currently still accessing this message?
		$this->assertor->assertQuery('vBForum:markUserPMsDeleted', array(
			'deletiondate' => vB::getRequest()->getTimeNow(),
			'userid' => $userid
		));

		$this->buildPmTotals(array($userid));

		// update userinfo
		vB_Library::instance('user')->clearUserInfo(array($userid));
		return $count;
	}

	/**
	 * This function checks that we have all the folders for the current user,
	 * and the set folders are there.
	 *
	 * @param	int	The user id to check folders for
	 * @param	bool	If true, do not error when the user isn't valid
	 *
	 * @return	array	Array with the 'result' element, indicating if the folders were loaded, were already loaded, or if the user was skipped.
	 */
	public function checkFolders($userid, $skipNonExistentRecipients = false)
	{
		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if (!empty($this->folders[$userid]))
		{
			//We've already loaded them
			return array('result' => 'folders_already_loaded');
		}

		//make sure this is a valid userid
		$userCheck = $this->assertor->getRows('user', array('userid' => $userid));

		if (empty($userCheck) OR !empty($userCheck['errors']))
		{
			if ($skipNonExistentRecipients)
			{
				return array('result' => 'user_skipped');
			}
			else
			{
				throw new vB_Exception_Api('invalid_message_recipient');
			}
		}

		//We need to load the folders.
		$folderResult = $this->assertor->getRows('vBForum:messagefolder', array('userid' => $userid),
			'title');

		//The folders WE put in will have titlephrase, but no title. The ones users put in will have title but
		//no titlephrase.
		$systemFolders = array(self::TRASH_FOLDER, self::MESSAGE_FOLDER, self::SENT_FOLDER, self::NOTIFICATION_FOLDER, self::REQUEST_FOLDER, self::PENDING_FOLDER, self::INFRACTION_FOLDER, self::DELETED_ITEMS_FOLDER);
		$systemFolderIds = array();
		$folders = array();
		foreach ($folderResult as $folder)
		{
			if (!empty($folder['titlephrase']))
			{
				$folders[$folder['folderid']] = vB_Phrase::fetchSinglePhrase($folder['titlephrase']);
				$systemFolderIds[$folder['titlephrase']] = $folder['folderid'];
				$systemKey = array_search($folder['titlephrase'], $systemFolders);

				if ($systemKey !== false)
				{
					unset($systemFolders[$systemKey]);
				}
			}
			else
			{
				$folders[$folder['folderid']] = $folder['title'];
			}
		}

		//If we don't have the five system folders we need to create them.
		foreach ($systemFolders as $folderNeeded)
		{
			$data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid' => $userid,
				'title' => '',
				'titlephrase' => $folderNeeded,
			);
			$folderid = $this->assertor->assertQuery('vBForum:messagefolder', $data);
			$systemFolderIds[$folderNeeded] = $folderid;
			$folders[$folderid] = vB_Phrase::fetchSinglePhrase($folderNeeded);
		}

		//We have it all now.
		$this->folders[$userid] = array(
			'folders' => $folders,
			'systemfolders' => $systemFolderIds,
		);

		return array('result' => 'folders_loaded');
	}

	/**
	 * Verifies that the request exists and its valid.
	 * Returns the message if no error is found.
	 * Throws vB_Exception_Api if an error is found.
	 * @param int $userid
	 * @param int $nodeid
	 * @return array - message info
	 */
	public function validateRequest($userid, $nodeid)
	{
		$sentto = $this->assertor->getRow('vBForum:sentto', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid, 'userid' => $userid
		));

		if (!$sentto OR !empty($sentto['errors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		//So the node is valid and the message was sent to this user. Let's confirm it was a request.
		$message = $this->assertor->getRow('vBForum:privatemessage', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid
		));

		if (!$sentto OR !empty($sentto['errors']) OR ($message['msgtype'] != 'request'))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		return $message;
	}

	/**
	 * This function denies a user follow request
	 *
	 *	@param	int		the nodeid of the request
	 *	@param	int		(optional) the userid to whom the request was sent
	 *	@return	array - array('result' => resultphrase) if resultphrase is empty, there
	 *		is nothing useful to say about what happened
	 */
	public function denyRequest($nodeid, $cancelRequestFor)
	{
		//We do the following
		// - validate the record
		// - call the following api to change the data.
		// - delete the message records

		$userid = (int) vB::getCurrentSession()->get('userid');

		//not sure if this should be in the library function
		if (!$userid)
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if (intval($cancelRequestFor) > 0)
		{
			$userid = $cancelRequestFor;
		}

		$message = $this->validateRequest($userid, $nodeid);

		// return a result phrase for use by the client, a blank value means nothing
		// to communicate to the user.
		$result = '';
		if (!in_array($message['about'], $this->channelRequests))
		{
			// @TODO we might want to distinguish between follow members and content here...
			// VBV-10480, since follow-content requests are added to the channelRequests array, only follow-member
			// requests will go through this. We do not want to add members to the ignorelist for denying a follow-content request.

			$result = 'follow_request_denied';
		}

		//Deletes the records from the node, privatemessage, text, sentto, and closure tables.
		$this->delete($nodeid);
		return array('result' => $result);
	}


	/**
	 * This function accepts a user follow request or a channel ownership/moderation/membership request
	 *
	 *	@param	int		the nodeid of the request
	 *	@return	bool
	 */
	public function acceptRequest($nodeid)
	{
		/* We do the following
		   - validate the record
		   - call the following api to change the data.
		   - delete the message records
		*/
		$userInfo =  vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$message = $this->validateRequest($userid, $nodeid);

		$nodeLib = vB_Library::instance('node');

		$resultphrase = '';
		//if this is one of the ownership/membership requests, send it to the node api.
		// If it's a subscriber request (content), handled in else block & send to follow API
		if (
			in_array($message['about'], $this->channelRequests) AND
			!in_array($message['about'], $this->channelFollowRequests)
		)
		{
			$result = $this->nodeApi->approveChannelRequest($nodeid);

			if ($result === true)
			{
				switch ($message['about'])
				{
					case vB_Api_Node::REQUEST_TAKE_OWNER:
					case vB_Api_Node::REQUEST_SG_TAKE_OWNER:
						$resultphrase = 'take_owner_request_accepted';
						break;
					case vB_Api_Node::REQUEST_TAKE_MODERATOR:
					case vB_Api_Node::REQUEST_SG_TAKE_MODERATOR:
						$resultphrase = 'take_moderator_request_accepted';
						break;
					case vB_Api_Node::REQUEST_TAKE_MEMBER:
					case vB_Api_Node::REQUEST_SG_TAKE_MEMBER:
						$resultphrase = 'take_member_request_accepted';
						break;
					case vB_Api_Node::REQUEST_GRANT_OWNER:
					case vB_Api_Node::REQUEST_SG_GRANT_OWNER:
						$resultphrase = 'grant_owner_request_accepted';
						break;
					case vB_Api_Node::REQUEST_GRANT_MODERATOR:
					case vB_Api_Node::REQUEST_SG_GRANT_MODERATOR:
						$resultphrase = 'grant_moderator_request_accepted';
						break;
					case vB_Api_Node::REQUEST_GRANT_MEMBER:
					case vB_Api_Node::REQUEST_SG_GRANT_MEMBER:
						$resultphrase = 'grant_member_request_accepted';
						break;
				}
			}
		}
		else
		{
			// it's a following request
			$aboutid = $message['aboutid'];
			$about = $message['about'];
			$message = $nodeLib->getNodeBare($nodeid);

			$followApi = vB_Api::instanceInternal('follow');
			// @TODO we might want to distinguish between follow members and content here...
			// which implicates adding new approve/deny methods and might need notification message as well.
			if (in_array($about, $this->channelFollowRequests))
			{
				$followApi->add($aboutid, vB_Api_Follow::FOLLOWTYPE_CONTENT, $message['userid']);
			}
			else
			{
				$followApi->approveFollowing($message['userid']);
			}

			/**
			 HERE IS WHERE FOLLOW NOTIFICATIONS ARE GENERATED!!!!
			 **/
			// send ACCEPTEDFOLLOW notification to the requester
			$notificationData = array('sender' => $userid);
			$recipients = array($message['userid']);
			vB_Library::instance('notification')->triggerNotificationEvent(
				'user-accepted-request-follow',
				$notificationData,
				$recipients
			);
			vB_Library::instance('notification')->insertNotificationsToDB();

			$resultphrase = 'follow_request_accepted';
			$result = true;
		}

		if ($result)
		{
			$params = array();
			// This relies on $message (initially holding `privatemessage` data) being overwritten by
			// bare node (`node` data lacking aboutid) data for follow-requests. TODO: Update this
			if (!empty($message['aboutid']))
			{
				$channel_info = $nodeLib->getChannelInfoForNode($message['aboutid']);
				$node_info = $this->nodeApi->getNode($nodeid);
				$params[] = $channel_info['title'];
				$params[] = vB5_Route::buildUrl($channel_info['routeid'] . '|fullurl');
				if ($node_info['userid'])
				{
					$requesting_user = vB_Api::instanceInternal("User")->fetchUserName($node_info['userid']);
					$params[] = $requesting_user;
					$params[] = vB5_Route::buildUrl('profile', array('userid' => $node_info['userid']));
				}
			}
			//Deletes the records from the node, privatemessage, text, sentto, and closure tables.
			$this->delete($nodeid);

			return vB_Phrase::fetchSinglePhrase($resultphrase, $params);
		}
		else
		{
			return false;
		}
	}

	/**
	 * Clears the cached folder information
	 */
	public function resetFolders()
	{
		$this->folders = array();
	}

	/**
	 * returns the cached folder information
	 **/
	public function fetchFolders($userid)
	{
		return $this->folders[$userid];
	}

	/**
	 * This sets a message to read
	 *
	 *	@param $nodeid
	 */
	public function setRead($nodeid, $read, $userid, $folderKey =  false)
	{
		if (is_string($nodeid) AND strpos($nodeid, ','))
		{
			$nodeid = explode(',', $nodeid);
		}

		$params = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid, 'userid' => $userid,
		);

		if (!empty($folderKey))
		{
			$this->checkFolders($userid);

			if (!empty($this->folders[$userid]['systemfolders'][$folderKey]))
			{
				$params['folderid'] = $this->folders[$userid]['systemfolders'][$folderKey];
			}
		}
		$node = $this->assertor->getRow('vBForum:sentto', $params);

		//We can only change if we have a valid node.
		if (empty($node) OR !empty($node['errors']))
		{
			return;
		}

		$this->assertor->assertQuery('vBForum:sentto', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'nodeid', 'value' => $nodeid),
				array('field' => 'userid', 'value' => $userid)
			),
			'msgread' => $read
		));
	}


	/**
	 * returns the cached folder information
	 */
	public function unsetFolders($userid)
	{
		unset($this->folders[$userid]);
	}

	/**
	 * Checks nodes to ensure that the current user can see them.
	 *	@param	mixed	integer	or array of integers for id in the primary table
	 *	@return	int
	 */
	public function checkCanSee($nodeids)
	{
		//We need to limit to only the records the current user can see.
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$currentUser = $userInfo['userid'];

		if (!intval($currentUser))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if (!isset($this->canSee[$currentUser]))
		{
			$this->canSee[$currentUser] = array();
		}

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		$canSeeQry = $this->assertor->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeids, 'userid' => $currentUser));
		foreach ($canSeeQry as $canSee)
		{
			$this->canSee[$currentUser][$canSee['nodeid']] = 1;
		}

		foreach ($nodeids as $key => $id)
		{
			if (!array_key_exists($id, $this->canSee[$currentUser]))
			{
				unset($nodeids[$key]);
			}
		}

		if (empty($nodeids))
		{
			return array();
		}
		return $nodeids;
	}


	/**
	 * Returns the node content as an associative array
	 *	@param	mixed	array of content records
	 *	@return	mixed	array of content records with extra "about" information for notifications.
	 */
	public function addMessageInfo($nodes)
	{
		if (empty($nodes))
		{
			return $nodes;
		}
		foreach ($nodes as $nodeid => $node)
		{
			$nodes[$nodeid]['recipients'] = array();
		}

		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$currentUser = $userInfo['userid'];
		$recipients = $this->assertor->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => array_keys($nodes)));
		//lets only call fetchAvatar once per user. We'll probably have overlaps
		$avatars = array();
		$userApi = vB_Api::instanceInternal('user');
		foreach ($recipients as $key => $recipient)
		{
			if ($recipient['userid'] != $currentUser)
			{
				if (!isset($avatars[$recipient['userid']]))
				{
					$avatars[$recipient['userid']] = $userApi->fetchAvatar($recipient['userid']);
				}
				$nodes[$recipient['nodeid']]['recipients'][$recipient['userid']] = $recipient;
				$nodes[$recipient['nodeid']]['recipients'][$recipient['userid']]['avatarUrl'] = $avatars[$recipient['userid']];
			}
		}

		$notifications = array();

		foreach ($nodes as $key => $node)
		{
			if (($node['msgtype'] == 'notification') AND ($node['about'] != 'vm'))
			{
				$notifications[] = $node['aboutid'];
			}
		}
		if (empty($notifications))
		{
			return $nodes;
		}

		$notifQry = vB::getDbAssertor()->assertQuery('vBForum:privatemessage',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $notifications));
		foreach ($notifQry as $notification)
		{
			$nodeid = $notification['nodeid'];
			$nodes[$nodeid]['aboutcount'] = max(0, $notification['textcount'] - 1);
			$nodes[$nodeid]['lastauthor'] = $notification['lastcontentauthor'];
			$nodes[$nodeid]['aboutuser'] = $notification['username'];
			$nodes[$nodeid]['abouttitle'] = $notification['title'];
			$nodes[$nodeid]['aboutrouteid'] = $notification['routeid'];
		}
		return $nodes;
	}

	/**
	 * Returns the node content as an associative array
	 *	@param	integer	The id in the primary table
	 *	@param array permissions
	 *	@param bool	appends to the content the channel routeid and title, and starter route and title the as an associative array
	 *	@return	int
	 */
	public function getFullContent($nodeid, $permissions = false)
	{
		$results = parent::getFullContent($nodeid, $permissions);
		return $this->addMessageInfo($results);
	}

	/**
	 * Get the pending posts folder id
	 *
	 * @return	int		The pending posts folder id from messagefolder.
	 */
	public function getPendingPostFolderId()
	{
		$folderInfo = $this->assertor->assertQuery('vBForum:messagefolder', array('titlephrase' => self::PENDING_FOLDER, 'userid' => vB::getUserContext()->fetchUserId()));
		if ($folderInfo AND !$folderInfo->valid())
		{
			return false;
		}

		$folder = $folderInfo->current();
		return intval($folder['folderid']);
	}

	/**
	 * Get the infraction folder id
	 *
	 * @return	int		The infraction folder id from messagefolder.
	 */
	public function getInfractionFolderId()
	{
		$folderInfo = $this->assertor->assertQuery('vBForum:messagefolder', array('titlephrase' => self::INFRACTION_FOLDER, 'userid' => vB::getUserContext()->fetchUserId()));
		if ($folderInfo AND !$folderInfo->valid())
		{
			return false;
		}

		$folder = $folderInfo->current();
		return intval($folder['folderid']);
	}

	/**
	 * Get the deleted_items folder id
	 *
	 * @return	int		The deleted_items folder id from messagefolder.
	 */
	public function getDeletedItemsFolderId()
	{
		$folderInfo = $this->assertor->assertQuery('vBForum:messagefolder', array('titlephrase' => self::DELETED_ITEMS_FOLDER, 'userid' => vB::getUserContext()->fetchUserId()));
		if ($folderInfo AND !$folderInfo->valid())
		{
			return false;
		}

		$folder = $folderInfo->current();
		return intval($folder['folderid']);
	}


	/** Returns array of Request message types
	 *
	 *	@return		mixed		array of strings
	 ***/
	public function getChannelRequestTypes()
	{
		return $this->channelRequests;
	}

	/** Return all the valid notification types
	 *
	 *	@return		mixed		array of strings
	 * */
	public function fetchNotificationTypes()
	{
		return $this->notificationTypes;
	}

	/**
	 * Move a message back to user inbox folder
	 *
	 * @params		int		The nodeid we are undeleting.
	 * @params		mixed	array of existing sent to records.
	 *
	 * @return		bool	True if succesfully done.
	 */
	public function undeleteMessage($nodeid, $existing)
	{
		$userid = vB::getCurrentSession()->get('userid');
		$this->checkFolders($userid);
		return $this->moveUndeleted($nodeid, $this->folders[$userid]['systemfolders'][self::MESSAGE_FOLDER], $existing);
	}

	/**
	 * Delete messages
	 *
	 * @params		array	Array of the nodeids from messages to delete.
	 *
	 * @return		bool	Indicating if deletion were succesfully done or will throw exception.
	 */
	public function deleteMessages($nodeids)
	{
		$nodes = vB_Library::instance('node')->getNodes($nodeids);
		$toDelete = array();
		foreach ($nodes AS $node)
		{
			$toDelete[] = $node['nodeid'];
		}

		$userid = vB::getCurrentSession()->get('userid');
		$this->assertor->assertQuery('vBForum:sentto', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'userid' => $userid,
			'nodeid' => $toDelete
		));

		$this->buildPmTotals(array($userid));

		return true;
	}

	/** Move messages to inbox marking them as undeleted.
	 *
	 *	@param	int		the node to be moved
	 *	@param	int		the new parent node.
	 *	@param	int		existing sent to records.
	 *
	 *	@return	bool	did it succeed?
	 *
	 **/
	protected function moveUndeleted($nodeid, $newFolderid, $existing)
	{
		//A user can only move, obviously, to one of their own folders
		$currentUser = vB::getCurrentSession()->get('userid');
		$this->checkFolders($currentUser);

		if (array_key_exists($newFolderid , $this->folders[$currentUser]['folders']))
		{
			foreach ($existing as $nodeRecord)
			{
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'folderid' => $newFolderid, 'deleted' => 0,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $currentUser),
					array('field' => 'nodeid', 'value' => $nodeRecord['nodeid']),
					array('field' => 'folderid', 'value' => $this->folders[$currentUser]['systemfolders'][self::SENT_FOLDER], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
				));
				$result = $this->assertor->assertQuery('vBForum:sentto', $data);

				// and restore sent item record
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 'deleted' => 0,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $currentUser),
					array('field' => 'nodeid', 'value' => $nodeRecord['nodeid']),
					array('field' => 'folderid', 'value' => $this->folders[$currentUser]['systemfolders'][self::SENT_FOLDER])
				));
				$result = $this->assertor->assertQuery('vBForum:sentto', $data);
			}

			return true;
		}
		else
		{
			throw new vB_Exception_Api('invalid_data');
		}
	}

	/**
	 * Gets the folder information from a given folderid. The folderid requested should belong to the user who is requesting.
	 *
	 * @param	int		The folderid to fetch information for.
	 *
	 * @return	array	The folder information such as folder title, titlephrase and if is custom folder.
	 *
	 */
	public function getFolderFromId($folderid, $userid)
	{
		if (!empty($this->foldersInfo[$userid][$folderid]))
		{
			return $this->foldersInfo[$userid][$folderid];
		}

		$folderInfo = $this->assertor->assertQuery('vBForum:getFolderInfoFromId', array('folderid' => $folderid));

		$folder = array();
		while ($folderInfo AND $folderInfo->valid())
		{
			$info = $folderInfo->current();
			$folder[$info['folderid']] = $info;
			$folderInfo->next();
		}

		$this->foldersInfo[$userid][$folderid] = $folder;
		return $this->foldersInfo[$userid][$folderid];
	}

	/**
	 * Calculates the number of private messages that a user has in the system
	 * Used to limit pm abilities based on overage of this count
	 *
	 * @param array|int	List of users to rebuild user.pmtotal for
	 */
	public function buildPmTotals($userids)
	{
		$this->assertor->assertQuery('vBForum:buildPmTotals', array('userid' => $userids));
	}

	/**
	 * Checks if userid's notification options for notification type
	 *
	 * @return boolean	true if user should receive the notificationType
	 */
	public function userReceivesNotification($userid, $notificationType)
	{
		// grab bitfield masks for notification options
		$bf_masks = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');

		// each notification type should have an option linked to it.
		// note that NOTIFICATION_TYPE_MODERATE should not exist anymore. Mod messages go to
		// the pending posts folder
		$notificationOptionBitfields = array(
			// votes in your poll
			self::NOTIFICATION_TYPE_VOTE => $bf_masks['general_voteconvs'],

			// votes in a poll that was a reply to your topic.
			// currently there is no way to reply with a poll, however
			self::NOTIFICATION_TYPE_VOTEREPLY => $bf_masks['general_votereplies'],

			// 'Likes' your post
			// NEEDS A BITFIELD/OPTION
			self::NOTIFICATION_TYPE_RATE => $bf_masks['general_likespost'],

			// replies to your topic
			self::NOTIFICATION_TYPE_REPLY => $bf_masks['discussions_on'],

			// comments on your post
			self::NOTIFICATION_TYPE_COMMENT => $bf_masks['discussion_comment'],

			// comments on a reply to your topic.
			// could possibly use the same one as reply "discussions_on"
			// but would be good to have its own option
			self::NOTIFICATION_TYPE_THREADCOMMENT => $bf_masks['discussions_on'],

			// someone accepts your follow request
			self::NOTIFICATION_TYPE_FOLLOW => $bf_masks['general_followrequest'],

			// when someone follows you & you allowed auto-accept subscribers
			self::NOTIFICATION_TYPE_FOLLOWING => $bf_masks['general_followsyou'],

			// when someone leaves a visitor message on your profile/wall
			self::NOTIFICATION_TYPE_VM => $bf_masks['general_vm'],

			// when someone mentions you (@username) in a post
			self::NOTIFICATION_TYPE_USERMENTION => $bf_masks['general_usermention'],

			// when someone posts something with a monitored word in it
			// self::NOTIFICATION_TYPE_MONITOREDWORD
			// there is no option for turning this notification off
			// this notification is automatically sent to all moderators
		);

		// grab user info
		$userInfo = vB_User::fetchUserinfo($userid);

		// if it has an option, check it. Notifications without an option are sent by default
		if (array_key_exists($notificationType, $notificationOptionBitfields))
		{
			// check options
			return (($userInfo['notification_options'] & $notificationOptionBitfields[$notificationType]) == true);
		}
		else
		{
			// no option for this notification type, send notification
			return true;
		}
	}


	/** This cleans up for a node that was found to be incomplete by deleting the child nodes and subsidiary table records
	 *
	@param	mixed	node record, which may have missing child table data.
	 */
	public function incompleteNodeCleanup($node)
	{
		$deleted = parent::incompleteNodeCleanup($node);

		if ($deleted)
		{
			//The text and privatemessage records will be deleted by the parent. We need to delete the sentto records.
			$this->assertor->assertQuery('vBForum:sentto', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $node['nodeid'],
			));
		}

		return $deleted;
	}

	/**
	 * Translates the legacy notification type string into the new notification typename
	 *
	 * @param	String		$aboutString
	 *
	 * @return	String|Bool		New notification typename, or False if mapping is unknown
	 */
	public function convertLegacyNotificationAboutString($aboutString)
	{
		$mapping = array(
			self::NOTIFICATION_TYPE_VOTE =>
				vB_Notification_PollVote::TYPENAME,
			self::NOTIFICATION_TYPE_VOTEREPLY =>
				false, // never existed.
			self::NOTIFICATION_TYPE_RATE =>
				vB_Notification_LikedNode::TYPENAME,
			self::NOTIFICATION_TYPE_REPLY =>
				vB_Notification_Content_GroupByStarter_Reply::TYPENAME,
			self::NOTIFICATION_TYPE_FOLLOW =>
				vB_Notification_UserRelation_SenderAcceptedFollowRequest::TYPENAME,
			self::NOTIFICATION_TYPE_FOLLOWING =>
				vB_Notification_UserRelation_SenderIsfollowing::TYPENAME,
			self::NOTIFICATION_TYPE_VM =>
				vB_Notification_VisitorMessage::TYPENAME,
			self::NOTIFICATION_TYPE_COMMENT =>
				vB_Notification_Content_GroupByParentid_Comment::TYPENAME,
			self::NOTIFICATION_TYPE_THREADCOMMENT =>
				vB_Notification_Content_GroupByParentid_ThreadComment::TYPENAME,
			self::NOTIFICATION_TYPE_SUBSCRIPTION =>
				vB_Notification_Content_GroupByStarter_Subscription::TYPENAME,
			self::NOTIFICATION_TYPE_MODERATE =>
				false, // no longer exists. Moderation items go into the pending folder
			self::NOTIFICATION_TYPE_USERMENTION =>
				vB_Notification_Content_UserMention::TYPENAME,
			self::NOTIFICATION_TYPE_MONITOREDWORD =>
				vB_Notification_MonitoredWord::TYPENAME,
		);

		if (!empty($mapping[$aboutString]))
		{
			return $mapping[$aboutString];
		}
		else
		{
			return false;
		}
	}


	/**
	 * Translates the legacy notification type string into an array of type information
	 *
	 * @param	String		$typename
	 *
	 * @return	String	Returns the legacy NOTIFICATION_TYPE_X string for the typename.
	 *					If the mapping is unknown, an empty string is returned.
	 */
	public function convertNotificationTypeToLegacyAboutString($typename)
	{
		$oldAboutString = array(
			vB_Notification_PollVote::TYPENAME => self::NOTIFICATION_TYPE_VOTE,
			vB_Notification_LikedNode::TYPENAME => self::NOTIFICATION_TYPE_RATE,
			vB_Notification_Content_GroupByStarter_Reply::TYPENAME => self::NOTIFICATION_TYPE_REPLY,
			vB_Notification_UserRelation_SenderAcceptedFollowRequest::TYPENAME => self::NOTIFICATION_TYPE_FOLLOW,
			vB_Notification_UserRelation_SenderIsfollowing::TYPENAME => self::NOTIFICATION_TYPE_FOLLOWING,
			vB_Notification_VisitorMessage::TYPENAME => self::NOTIFICATION_TYPE_VM,
			vB_Notification_Content_GroupByParentid_Comment::TYPENAME => self::NOTIFICATION_TYPE_COMMENT,
			vB_Notification_Content_GroupByParentid_ThreadComment::TYPENAME => self::NOTIFICATION_TYPE_THREADCOMMENT,
			vB_Notification_Content_GroupByStarter_Subscription::TYPENAME => self::NOTIFICATION_TYPE_SUBSCRIPTION,
			vB_Notification_Content_UserMention::TYPENAME => self::NOTIFICATION_TYPE_USERMENTION,
			vB_Notification_MonitoredWord::TYPENAME => self::NOTIFICATION_TYPE_MONITOREDWORD,
		);

		if (!empty($oldAboutString[$typename]))
		{
			return $oldAboutString[$typename];
		}
		else
		{
			return "";
		}
	}

	/**
	 * Validates the data according to the action to be taken
	 *
	 * @param  array  The standard node data array
	 * @param  string The "action" to be taken (one of the vB_Library_Content::ACTION_* constants)
	 * @param  int    (optional) Node ID
	 * @param  array  (optional) Array of Nodes.
	 *
	 * @return bool
	 */
	public function validate($data, $action = vB_Library_Content::ACTION_ADD, $nodeid = false, $nodes = false, $userid = null)
	{
		// Some actions, like verifying HV for action_add, are tied to the current session or request, so
		// we cannot use a custom userid here. For now only allow checking permissions on another user
		// for action_view
		$currentUserid = vB::getCurrentSession()->get('userid');
		if ($action != self::ACTION_VIEW AND !is_null($userid) AND $userid != $currentUserid)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, '$userid', __CLASS__, __FUNCTION__));
		}

		if (is_null($userid))
		{
			$userid = $currentUserid;
		}

		$userContext = vB::getUserContext($userid);
		if ($userContext->isSuperAdmin())
		{
			return true;
		}

		$pmApi = vB_Api::instanceInternal('content_privatemessage');
		if (!$pmApi->canUsePmSystem($userid))
		{
			return false;
		}

		// We need a valid userid for the queries that check sentto records. Guests cannot have sentto records.
		if (!intval($userid))
		{
			return false;
		}

		//we need a nodeid (or parentid if we are adding) or we cannot answer the question.
		if ($action == vB_Library_Content::ACTION_ADD)
		{
			if (empty($data['parentid']) OR !intval($data['parentid']))
			{
				$data['parentid'] = $this->pmChannel;
			}
			$parentid = $data['parentid'];
		}
		else
		{
			if (!$nodeid)
			{
				if (empty($data['nodeid']) OR !intval($data['nodeid']))
				{
					throw new vB_Exception_Api('invalid_data');
				}
				else
				{
					$nodeid = $data['nodeid'];
				}
			}

			if (!is_array($nodeid))
			{
				$nodeid = array($nodeid);
			}

			// Use library instead of API in case $userid is not current user.
			// This list is validated below for VIEW, DELETE, APPROVE & PUBLISH
			$nodes = vB_Library::instance('node')->getNodes($nodeid);

			if (empty($nodes))
			{
				return false;
			}
		}

		switch ($action)
		{
			case vB_Library_Content::ACTION_ADD:
				// VBV-3512
				if ($userContext->isGloballyIgnored())
				{
					throw new vB_Exception_Api('not_logged_no_permission');
					//todo: return false instead of throwing exception.
				}

				// HV is not needed while sending requests or notifications.
				if (!isset($data['msgtype']) OR !in_array($data['msgtype'], array('request', 'notification')))
				{
					// This doesn't support a non-current-user $userid yet.
					// Recaptcha2 for ex. requires the checked user's requests's IP address,
					// which we wouldn't have since the checked user may not be the one making
					// the request.
					vB_Api::instanceInternal('hv')->verifyToken($data['hvinput'], 'post');
					//todo: return false instead of throwing exception.
					// verifyToken() accepts a 3rd param that allows it to return false instead of throwing
					// an exception. Check that and return false here, or continue (do not return true yet,
					// we're not done checking permissions)
				}

				//parentid must be pmChannel or a descendant.
				if ($parentid != $this->pmChannel)
				{
					//this only returns the closure record that has the given ancestor (second param) so
					//if $parentid is isn't a decendant of pmChannel no records will be returned.
					//we only need to check if its empty not the specific contents
					$closure = vB_Library::instance('node')->fetchClosureParent($parentid, $this->pmChannel);
					if (empty($closure) OR !is_array($closure))
					{
						throw new vB_Exception_Api('invalid_data');
					}
				}

				return $userContext->getChannelPermission('createpermissions', $this->contenttype, $parentid);
				break;

			case vB_Library_Content::ACTION_UPDATE:
				//They can only update if they are a moderator with permission to moderate messages.
				// As a moderator
				foreach ($nodes as $node)
				{
					if (!$userContext->getChannelPermission('moderatorpermissions', 'caneditposts', $node['nodeid'], false, $node['parentid']))
					{
						return false;
					}
				}
				return true;
				break;

			case vB_Library_Content::ACTION_VIEW:
				$canSeeQry = $this->assertor->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $nodeid, 'userid' => $userid));

				//We scan the $canSeeQuery list. If there's a match then they can view this node.
				foreach ($canSeeQry as $sentto)
				{
					foreach ($nodes as $key => $node)
					{
						if ($node['nodeid'] == $sentto['nodeid'])
						{
							unset($nodes[$key]);
							if (count($nodes) == 0)
							{
								return true;
							}
							break;
						}
					}
				}

				//if we got here we have some unmatched nodes. That means no view permission
				return false;
				break;

			case vB_Library_Content::ACTION_DELETE:
				foreach ($nodes as $node)
				{
					//If the user has a sentto record, it's O.K.
					$canSeeQry = $this->assertor->assertQuery('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'nodeid' => $node['nodeid'], 'userid' => $userid));

					if ($canSeeQry->valid())
					{
						//skip to the next record
						continue;
					}
					else if (!$userContext->getChannelPermission('moderatorpermissions', 'canremoveposts', $node['nodeid'], false, $node['parentid']))
					{
						return false;
					}
				}
				return true;

				break;

			case vB_Library_Content::ACTION_APPROVE:
			case vB_Library_Content::ACTION_PUBLISH:
				/*
					Previously $nodes were being fetched by the API else block above this switch block,
					and this function returned false if $nodes was empty (since we only ever fetch 1 node
					at a time for $nodes, it *usually* didn't have to worry about a case where someone was
					trying to pass validation on multiple nodes at once. One edge case is if an array of
					nodes were passed into $data['nodeid'], but I don't think anything that actually
					uses validate() would do that...
					At that time, this block just returned true and relied on the node API filtering for any
					"permission" checks for the publish/approve actions.

					We now use the library to pull $nodes, so having this check duplicated here emulates
					that old behavior, and also catches the hypothetical edge case of validating this action
					for multiple nodes.

					Note that this simple check could mean that a user could possibly approve/publish replies
					that they don't own but were sent to them, but that behavior is not modified with this
					code change	nor do I believe that there's any actual scenario where a privatemessage needs
					to be published/approved.
				 */
				foreach ($nodes as $node)
				{
					$canSeeQry = $this->assertor->assertQuery(
						'vBForum:sentto',
						array(
							'nodeid' => $node['nodeid'],
							'userid' => $userid
						)
					);

					if (!$canSeeQry->valid())
					{
						return false;
					}
				}

				return true;
				break;
			default:
				;
		} // switch

		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103597 $
|| #######################################################################
\*=========================================================================*/
