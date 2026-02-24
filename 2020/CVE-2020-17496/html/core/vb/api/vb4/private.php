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
 * vB_Api_Vb4_private
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_private extends vB_Api
{
	public function movepm($messageids, $folderid)
	{
		$cleaner = vB::getCleaner();
		$messageids = $cleaner->clean($messageids, vB_Cleaner::TYPE_STR);
		$folderid = $cleaner->clean($folderid, vB_Cleaner::TYPE_UINT);

		$userid =  vB::getCurrentSession()->get('userid');
		$folders = vB_Api::instance('content_privatemessage')->fetchFolders($userid);
		if ($folders === null OR !empty($folders['errors']) OR empty($folders['systemfolders']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($folders);
		}

		switch($folderid)
		{
			case -1:
				$folderid = $folders['systemfolders']['sent_items'];
				break;
			case 0:
				$folderid = $folders['systemfolders']['messages'];
				break;
			default:
				// otherwise, assume it's custom folder and folderid is valid.
				break;
		}




		if (empty($messageids) || empty($folderid))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		$pm = vB_Utility_Unserialize::unserialize($messageids);

		if (empty($pm))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		// todo for VBV-19363 moveMessage() accepts comma-delimited string of nodeids
		// for $nodeid param. Do implode(',', array_keys($pm)) and call it once instead
		// of in a loop?
		foreach ($pm as $pmid => $nothing)
		{
			$result = vB_Api::instance('content_privatemessage')->moveMessage($pmid, $folderid);
			if ($result === null || isset($result['errors']))
			{
				return vB_Library::instance('vb4_functions')->getErrorResponse($result);
			}
		}
		return array('response' => array('errormessage' => array('pm_messagesmoved')));
	}

	public function managepm($pm, $dowhat, $folderid = null)
	{
		$cleaner = vB::getCleaner();
		$pm = $cleaner->clean($pm, vB_Cleaner::TYPE_ARRAY);
		$dowhat = $cleaner->clean($dowhat, vB_Cleaner::TYPE_STR);
		$folderid = $cleaner->clean($folderid, vB_Cleaner::TYPE_UINT);


		$userid =  vB::getCurrentSession()->get('userid');
		$folders = vB_Api::instance('content_privatemessage')->fetchFolders($userid);
		if ($folders === null OR !empty($folders['errors']) OR empty($folders['systemfolders']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($folders);
		}

		switch($folderid)
		{
			case -1:
				$folderid = $folders['systemfolders']['sent_items'];
				break;
			case 0:
				$folderid = $folders['systemfolders']['messages'];
				break;
			default:
				// otherwise, assume it's custom folder and folderid is valid.
				break;
		}


		if (empty($pm) ||
			empty($dowhat))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		if ($dowhat == 'move')
		{
			if (empty($folderid))
			{
				return array('response' => array('errormessage' => array('invalidid')));
			}
			foreach ($pm as $pmid => $nothing)
			{
				$result = vB_Api::instance('content_privatemessage')->moveMessage($pmid, $folderid);
				if ($result === null || isset($result['errors']))
				{
					return vB_Library::instance('vb4_functions')->getErrorResponse($result);
				}
			}
			return array('response' => array('HTML' => array('messageids' => serialize($pm))));
		}
		else if ($dowhat == 'unread')
		{
			foreach ($pm as $pmid => $nothing)
			{
				$result = vB_Api::instance('content_privatemessage')->setRead($pmid, 0);
				if ($result === null || isset($result['errors']))
				{
					return vB_Library::instance('vb4_functions')->getErrorResponse($result);
				}
			}
			return array('response' => array('errormessage' => array('pm_messagesmarkedas')));
		}
		else if ($dowhat == 'read')
		{
			foreach ($pm as $pmid => $nothing)
			{
				$result = vB_Api::instance('content_privatemessage')->setRead($pmid, 1);
				if ($result === null || isset($result['errors']))
				{
					return vB_Library::instance('vb4_functions')->getErrorResponse($result);
				}
			}
			return array('response' => array('errormessage' => array('pm_messagesmarkedas')));
		}
		else if ($dowhat == 'delete')
		{
			foreach ($pm as $pmid => $nothing)
			{
				$result = vB_Api::instance('content_privatemessage')->deleteMessage($pmid);
				if (isset($result['errors']))
				{
					return vB_Library::instance('vb4_functions')->getErrorResponse($result);
				}
			}

			return array('response' => array('errormessage' => array('pm_messagesdeleted')));
		}
		else
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}
	}

	public function insertpm($message, $title = '', $recipients = '', $replypmid = null)
	{
		$cleaner = vB::getCleaner();
		$message = $cleaner->clean($message, vB_Cleaner::TYPE_STR);
		$title = $cleaner->clean($title, vB_Cleaner::TYPE_STR);
		$recipients = $cleaner->clean($recipients, vB_Cleaner::TYPE_STR);
		$replypmid = $cleaner->clean($replypmid, vB_Cleaner::TYPE_UINT);

		if (empty($message))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		if (!empty($replypmid))
		{
			$pmThread = vB_Api::instance("node")->getNode($replypmid);
			if (!empty($pmThread['errors']) OR empty($pmThread['starter']))
			{
				return array('response' => array('errormessage' => array('invalidid')));
			}

			// respondto
			$data = array(
				'respondto' => $pmThread['starter'],
				'rawtext' => $message,
			);
		}
		else
		{
			if (empty($title) OR empty($recipients))
			{
				return array('response' => array('errormessage' => array('invalidid')));
			}

			$recipients = implode(',', array_map('trim', explode(';', $recipients)));

			$data = array(
				'msgRecipients' => $recipients,
				'title' => $title,
				'rawtext' => $message,
			);
		}

		$result = vB_Api::instance('content_privatemessage')->add($data, array('wysiwyg' => false));

		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}
		return array('response' => array('errormessage' => 'pm_messagesent'));
	}

	//VBV-11007
	public function sendemail($pmid, $reason){
		$cleaner = vB::getCleaner();
		$postid = $cleaner->clean($pmid, vB_Cleaner::TYPE_UINT);
		$reason = $cleaner->clean($reason, vB_Cleaner::TYPE_STR);

		if (empty($pmid))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		if (empty($reason))
		{
			return array('response' => array('errormessage' => array('invalidreason')));
		}

		return vB_Api::instance('vb4_report')->sendemail($pmid, $reason);
	}

	public function showpm($pmid)
	{
		/*
			getMessage() & downstream functions seem to be written to expect a starter
			nodeid as the parameter. If given a reply nodeid as the parameter, the result
			doesn't seem quite correct. Particularly it sets the reply's "starter" = true
			even though it's not a starter (in other "node" return arrays, starter would
			hold the starter's nodeid, not a bool) which isn't really helpful.

			This function regularly gets a reply nodeid for $pmid because vB4 didn't really
			have "threads" of private messages and the mobile clients don't have support
			for private message threads yet.

			However we can't just get the starter and call getMessage() on the starter because
			that would mark the entire tree as "read", while we only want this specific node
			to be marked as read.

			Thankfully, the results of getMessage() contains a "startertitle" field, which
			was filled in by the getNodeContent() call from inside of PM Lib's getMessageTree(),
			so we'll use that.
		 */
		$pm = vB_Api::instanceInternal('content_privatemessage')->getMessage($pmid);

		if(empty($pm))
		{
			return array("response" => array("errormessage" => array("invalidid")));
		}

		$pm_response = array();

		$recipients = $this->parseRecipients($pm);

		$title = $pm['message']['title'];
		if (empty($title) AND !empty($pm['message']['startertitle']))
		{
			$title = $pm['message']['startertitle'];
			$title = vB_Phrase::fetchSinglePhrase('re_x', $title);
		}
		$username = $pm['message']['authorname'];

		$pm_response['response']['HTML']['pm'] = array(
			'pmid' => $pmid,
			'fromusername' => $username,
			'title' => $title,
			'recipients' => $recipients,
		);

		$pm_response['response']['HTML']['postbit']['post'] = array(
			'posttime' => $pm['message']['publishdate'],
			'username' => $username,
			'title' => $title,
			'avatarurl' => !empty($pm['message']['senderAvatar']) ? $pm['message']['senderAvatar']['avatarpath'] : '',
			'message' => $this->parseBBCodeMessage($pm['message']),
			'message_plain' => strip_bbcode($pm['message']['rawtext']),
			'message_bbcode' => $pm['message']['rawtext'],
		);

		return $pm_response;
	}

	protected function parseRecipients($pm)
	{
		$pm = $pm['message'];
		if (!empty($pm['recipients']))
		{
			$recipients = array();
			foreach ($pm['recipients'] as $recipient)
			{
				$rinfo = vB_Library::instance('user')->fetchUserinfo($recipient['userid']);
				$recipients[] = $rinfo['username'];
			}
			return implode(';', $recipients);
		}
		else
		{
			return $pm['username'];
		}
	}

	public function editfolders()
	{
		$folders = vB_Api::instanceInternal('content_privatemessage')->fetchSummary();

		$custom_folders = array('response' => array('HTML' => array('editfolderbits' => array())));
		foreach($folders['folders']['customFolders'] as $folder)
		{
			$custom_folders['response']['HTML']['editfolderbits'][] = array(
				'folderid' => $folder['folderid'],
				'foldername' => $folder['title'],
				'foldertotal' => $folder['qty']
			);
		}

		return $custom_folders;
	}

	public function messagelist($folderid = 0, $perpage = 10, $pagenumber = 1, $sort = 'date', $order = 'desc')
	{
		//
		//  vB4 folders are:
		//      0   = Inbox
		//      -1  = Sent
		//      N   = Custom
		//

		$userid =  vB::getCurrentSession()->get('userid');
		if (empty($userid))
		{
			return array("response" => array("errormessage" => 'nopermission_loggedout'));
		}

		// Note: api constructor calls checkFolders() on userid, so it's OK that
		// fetchFolders() doesn't check for folder existence first like listFolders() does.
		$folders = vB_Api::instance('content_privatemessage')->fetchFolders($userid);


		if ($folders === null OR !empty($folders['errors']) OR empty($folders['systemfolders']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($folders);
		}


		$inbox = false;
		$skipSelfPMs = false;
		$folderid = intval($folderid);
		switch($folderid)
		{
			case -1:
				$vB5Folderid = $folders['systemfolders']['sent_items'];
				break;
			case 0:
				$skipSelfPMs = true;
				$inbox = true;
				$vB5Folderid = $folders['systemfolders']['messages'];
				break;
			default:
				// otherwise, assume it's custom folder and folderid is valid.
				$vB5Folderid = $folderid;
				break;
		}

		// blocked users
		$blocked = vB_Library::instance('vb4_functions')->getBlockedUsers();

		if ($skipSelfPMs)
		{
			$blocked[] = $userid;
		}

		$params = array(
				'userid' => $userid,
				'folderid' => $vB5Folderid,
				'skipSenders' => $blocked,
				'sort' => $sort,
				'sortDir' => $order,
				vB_dB_Query::PARAM_LIMIT => $perpage,
				vB_dB_Query::PARAM_LIMITPAGE => $pagenumber,
		);

		$assertor = vB::getDbAssertor();
		$messageQry = $assertor->assertQuery('vBForum:listFlattenedPrivateMessages', $params);

		$pmNodeids = array();
		$messages = array();
		$recipients = array();
		foreach ($messageQry AS $message)
		{
			if (empty($message['previewtext']))
			{
				$message['previewtext'] = vB_String::getPreviewText($message['rawtext']);
			}
			unset ($message['rawtext']);

			if ($message['nodeid'] != $message['starter'])
			{
				// this is a reply. Add a RE: prefix.
				$message['title'] = vB_Phrase::fetchSinglePhrase('re_x', $message['title']);
			}

			$messages[$message['nodeid']] = $message;
			// These are used for "sent" userbits handling.
			$pmNodeids[] = $message['nodeid'];
			$recipients[$message['nodeid']] = array();
		}

		/*
			In vB4, folderid of -1 = sent box, folderid of 0 = inbox .
			For Inbox PMs, the "userbits" was an array of the pm's "fromuserid" & "fromusername"
			data, but for Sent PMs, the "userbits" was an array of the userid & username info
			for each user in the pm's "touserarray" serialized data.
		 */
		if ($folderid === -1)
		{
			// Grab recipients that are missing from the "flat" privatemessage data above.
			$recipientsQry = $assertor->assertQuery('vBForum:sentto', array('nodeid' => $pmNodeids));
			foreach ($recipientsQry as $_row)
			{

				$recipients[$_row['nodeid']][$_row['userid']] = $_row['userid'];
			}
		}

		/*
			In vB4, each message was a stand alone item.
			A reply was usually sent to others but not yourself, so it wouldn't be shown (but if you added yourself to the reply recipient, persumably it'd show up)
			In vB5, each message is part of a message thread.
			Since only thread starters are listed in listMessages, we need to go through each starter and fetch the replies,
			and include all the replies. We could potentially check if the replier is the current user and skip that one, but I don't think it's a good idea to put in
			those weird work arounds.
			Another issue is that "sent" starters are excluded from listMessages() until someone replies to it in vB5 due to weird inconsistencies with the sentto record handling.
			I'm going to ignore all those, and just straight up fetch all replies, and flatten the structure.

			One thing that we need to worry about is that the date order might be off.
			How do we wanna handle multiple threads whose replies are interspersed in terms of dates
		 */
		// TODO: when should a PM be read when fetched from MAPI?

		$final_messages = array();
		foreach($messages as $_nodeid => $_message)
		{
			$final_messages[] = $this->parseMessage($_message, $folderid, $recipients[$_nodeid]);
		}

		$totalCount = $assertor->getRow('vBForum:countFlattenedPrivateMessages', $params);
		if (isset($totalCount['total']))
		{
			$totalCount = $totalCount['total'];
		}
		else
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($totalCount);
		}

		$page_nav = vB_Library::instance('vb4_functions')->pageNav($pagenumber, $perpage, $totalCount);

		$response = array();
		$response['response']['HTML']['folderid'] = $inbox? 0 : $vB5Folderid;
		$response['response']['HTML']['pagenav'] = $page_nav;
		$response['response']['HTML']['messagelist_periodgroups']['messagelistbits'] = $final_messages;

		return $response;
	}

	private function parseMessage($message, $requestedFolderid, $recipients)
	{
		/*
			In vB4, folderid of -1 = sent box, folderid of 0 = inbox .
			For Inbox PMs, the "userbits" was an array of the pm's "fromuserid" & "fromusername"
			data, but for Sent PMs, the "userbits" was an array of the userid & username info
			for each user in the pm's "touserarray" serialized data.
		 */

		$currentUserinfo = vB::getCurrentSession()->fetch_userinfo();
		$currentUserid =  $currentUserinfo['userid'];
		$userbit = array();
		if ($requestedFolderid === -1)
		{
			$userLib = vB_Library::instance('user');
			foreach ($recipients AS $_userid)
			{
				// remove current user from sent item's recipient list to make it match vB4
				// behavior (except see below) ...
				if ($currentUserid !== $_userid)
				{
					$_rinfo = $userLib->fetchUserinfo($_userid);
					$userbit[] = array(
						'userinfo' => array(
							'userid' => $_userid,
							'username' => $_rinfo['username'],
						),
					);
				}
			}
			/*
				... except if there is *no* other recipients. This might be due to either a deleted user(s)
				or because this was a self-PM.
				This is an edge-case and also has to do with some slight differences in how "recipients"
				are defined in vB4 vs vB5's private message systems.
				In vB5, everyone, including the recipient, is a recipient (note 1: when fetching PMs through
				the normal API/LIB,	vB_Library_Content_Privatemessage::addMessageInfo() will always skip
				setting the *current* user from the "recipients" array as the current user being part of a PM
				they can view is implicit, at least until some third-party-access feature (e.g. admin review
				of PMs) is requested. note 2: for the starter PM, the original sender does not get an inbox
				sentto record, but all PM replies send a sentto record to all parties).
				In vB4 however, the sender is only a recipient iff they explicitly specified themselves in the
				[cc]recipients field. Furthermore, reply-all was not a default feature in vB4, while reply-all
				is the only mode of reply in vB5.
				What this boils down to is that unlike in vB4, where it was crystal clear whether the current
				user will be included in the recipients/userbits list or not, we have to guess at this in vB5.
				Speaking to the mobile team, having *any* valid recipient, including the current user, is better
				than having *no* recipients in these edge cases, and I don't think adding oneself to a pm in vB4
				was a common use case since a reply-all function didn't exist. Therefore, we're removing the
				current user from the list except when they're the only recipient.
			 */
			if (empty($userbit))
			{
				$userbit[] = array(
					'userinfo' => array(
						'userid' => $currentUserid,
						'username' => $currentUserinfo['username'],
					),
				);
			}
		}
		else
		{
			// For inbox, or custom folders (for which this behavior is currently UNDEFINED),
			// set it to the sender's data.
			$userbit[] = array(
				'userinfo' => array(
					'userid' => $message['userid'],
					'username' => $message['username'],
				),
			);
		}

		// This is weird, and I think leaving the 0th element *in* userbit is probably unintended at best
		// and a bug at worst, but it's exactly as vB4's code dictates.
		// It was explicitly removed/missing in the previous documented example in the private_messagelist
		// documentation (on the internal wiki) and only came up during testing & reviewing the vB4 code.
		if (count($userbit) == 1)
		{
			// "Only one username ? we only send userinfo"
			$userbit['userinfo'] = $userbit[0]['userinfo'];
		}

		return array(
			'pm' => array(
				'pmid' => $message['nodeid'],
				'sendtime' => $message['publishdate'],
				'title' => $message['title'] ? $message['title'] : $message['previewtext'],
				'statusicon' => $message['msgread'] ? 'old' : 'new'
			),
			'userbit' => $userbit,
			'show' => array(
				'unread' => $message['msgread'] ? 0 : 1
			)
		);
	}

	private function parseBBCodeMessage($message)
	{
		$this->bbcode_parser = new vB_Library_BbCode(true, true);
		$this->bbcode_parser->setAttachments($message['attach']);
		$this->bbcode_parser->setParseUserinfo($message['userid']);

		$authorContext = vB::getUserContext($message['userid']);

		$canusehtml = $authorContext->getChannelPermission('forumpermissions2', 'canusehtml', $message['parentid']);
		require_once DIR . '/includes/functions.php';

		return fetch_censored_text($this->bbcode_parser->doParse(
			$message['rawtext'],
			$canusehtml,
			true,
			true,
			$authorContext->getChannelPermission('forumpermissions', 'cangetattachment', $message['parentid']),
			true
		));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102435 $
|| #######################################################################
\*=========================================================================*/
