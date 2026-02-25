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
 * vB_Api_Content_Privatemessage
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: privatemessage.php 103410 2019-11-09 00:28:58Z dgrove $
 * @access public
 */
class vB_Api_Content_Privatemessage extends vB_Api_Content_Text
{

	//override in client- the text name
	protected $contenttype = 'vBForum_PrivateMessage';
	//The table for the type-specific data.
	protected $tablename = array('text', 'privatemessage');
	protected $folders = array();
	protected $assertor;
	protected $pmChannel;
	//Cache our knowledge of records the current user can see, to streamline permission checking.
	protected $canSee = array();
	//these are the notification message types. Message and request are handled differently.
	//the parameter is whether they need an aboutid.
	protected $notificationTypes = array();
	protected $bbcodeOptions = array();

	protected $disableWhiteList = array('getUnreadInboxCount', 'canUsePmSystem', 'fetchSummary');
	protected $disableFalseReturnOnly = array('getHeaderCounts');

	const PARTICIPANTS_PM = 'PrivateMessage';
	const PARTICIPANTS_POLL = 'Poll';
	const PARTICIPANTS_CHANNEL = 'Channel';

	/**
	 * Constructor, no external instantiation.
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Privatemessage');
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		if ($userInfo['userid'] > 0)
		{
			$this->library->checkFolders($userInfo['userid']);
			$this->pmChannel = $this->nodeApi->fetchPMChannel();
			$this->notificationTypes = $this->library->fetchNotificationTypes();
		}
	}

	/**
	 * Private messaging can be disabled either by pmquota or enablepms
	 *
	 * @return bool True if the current user can use the PM system, false otherwise
	 */
	public function canUsePmSystem($userid = null)
	{
		if (empty($userid))
		{
			$userid = intval(vB::getCurrentSession()->get('userid'));
		}
		$pmquota = vB::getUserContext($userid)->getLimit('pmquota');
		$vboptions = vB::getDatastore()->getValue('options');

		if (!$userid OR !$pmquota OR !$vboptions['enablepms'])
		{
			return false;
		}

		return true;
	}

	/*
	 * TODO: Func Desc
	 *
	 * @param	int               $pmid             Nodeid of private message topic (or reply) to expand
	 * @param	array|string      $usernames        Array or a semicolon-delimited string of usernames to add.
	 *                                              Must not be empty even if $usernamesToIds is provided.
	 * @param   array             $usernamesToIds   (Optional) Known mappings of usernames to ids (provided by
	 *                                              autocomplete helper). This function will assume this mapping
	 *                                              is absolutely correct. Any names found here will be skipped from
	 *                                              database lookup.
	 * @param   string            $delimiter        (Optional) Delimiter used by $usernames, if $usernames is a string and
	 *                                              something other than semicolon was used as the delimiter.
	 *
	 * @return	array       array('result' => (bool) true|false)
	 * @throws		TODO
	 */
	public function addPMRecipientsByUsernames($pmid, $usernames = array(), $usernamesToIds = array(), $delimiter = ';')
	{
		if (empty($pmid) OR !is_numeric($pmid))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($pmid, 'pmid', __CLASS__, __FUNCTION__));
		}

		// Do not allow this function to be used to "mine" data (e.g. brute force participant names...) about private messages that the user does not have access to.
		// this call with throw an exception if we don't have permission to load it.
		$pmNode = $this->nodeApi->getNode($pmid);

		if (empty($usernames))
		{
			// Slightly more useful message for the end-user than "invalid_data_...", but possibly less useful for developers...
			throw new vB_Exception_Api('invalid_pm_participants');
		}

		$usernamesArr = array();
		if (is_array($usernames))
		{
			$usernamesArr = $usernames;
		}
		else if (is_string($usernames))
		{
			$usernamesArr = explode($delimiter, $usernames);
		}

		if (empty($usernamesArr))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($usernames, 'usernames', __CLASS__, __FUNCTION__));
		}

		$expectedUsers = count($usernamesArr);


		$invalidUsers = array();
		$userids = array();
		$useridsToUsernames = array();
		foreach ($usernamesArr AS $__key => $__username)
		{
			if (isset($usernamesToIds[$__username]))
			{
				$__userid = $usernamesToIds[$__username];
				$userids[$__userid] = $__userid;
				unset($usernamesArr[$__key]);

				$__username = vB_String::htmlSpecialCharsUni($__username);
				$useridsToUsernames[$__userid] = $__username;
			}
			else
			{
				// taken from how PM Lib's add() fetches userids from a list of names
				$__username = vB_String::htmlSpecialCharsUni($__username);
				$usernamesArr[$__key] = $__username;
				$invalidUsers[$__username] = $__username;
			}
		}
		unset($__key, $__userid, $__username);

		if (!empty($usernamesArr))
		{
			// taken from PM Lib's add()
			$currentUserid = vB::getCurrentSession()->get('userid');
			$recipQry = $this->assertor->getRows('fetchPmRecipients', array('usernames' => $usernamesArr, 'userid' => $currentUserid));

			if (!empty($recipQry['errors']))
			{
				throw new vB_Exception_Api('invalid_pm_participants');
			}
			if (is_array($recipQry))
			{
				foreach ($recipQry as $__recipient)
				{
					$__userid = $__recipient['userid'];
					$__username = $__recipient['username'];
					$userids[$__userid] = $__userid;
					unset($invalidUsers[$__username]);
					$useridsToUsernames[$__userid] = $__username;
				}
				unset($__recipient, $__userid, $__username);
			}
		}

		if (!empty($invalidUsers))
		{
			if (count($invalidUsers) == 1)
			{
				throw new vB_Exception_Api('invalid_pm_participant_x', reset($invalidUsers));
			}
			else
			{
				throw new vB_Exception_Api('invalid_pm_participants_x', implode('; ', $invalidUsers));
			}
		}

		// As a end-user courtesy (addPMRecipients() will work OK with a partial match, but fail if *every* userid is already part of this PM thread)
		// check for existing recipients, and ask user to remove them.
		$existingRecipients = array();
		$existingRecipientsQry = $this->assertor->getRows('vBForum:getRecipientsForNode', array('nodeid' => $pmid));
		foreach ($existingRecipientsQry AS $__recipient)
		{
			$__userid = $__recipient['userid'];
			if (isset($userids[$__userid]))
			{
				$existingRecipients[$__userid] = $useridsToUsernames[$__userid];
			}
		}
		unset($__recipient, $__userid);

		if (!empty($existingRecipients))
		{
			if (count($existingRecipients) == 1)
			{
				throw new vB_Exception_Api('existing_pm_participant_x', reset($existingRecipients));
			}
			else
			{
				throw new vB_Exception_Api('existing_pm_participants_x', implode('; ', $existingRecipients));
			}
		}

		// if we got this far, and userids is empty but invalidUsers is not empty, something went sideways...
		if (empty($userids))
		{
			// something went wrong... let's assume the usernames were invalid.
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($usernames, 'usernames', __CLASS__, __FUNCTION__));
		}

		/*
			TODO:
			What to do when not *all* of the $usernames were added? (i.e. count($userids) & count($usernames) do not match)
		 */
		// debug
		/*
		return array(
			'success' => true,
			'message' => 'Actual add stopped due to debug',
			'debug' => $userids,
		);
		 */

		return $this->addPMRecipients($pmid, $userids);
	}

	/*
	 * TODO: Func Desc
	 *
	 * @param	int         $pmid          Nodeid of private message topic (or reply) to expand
	 * @param	array|int   $recipients    Userid or array of userids to add as private message recipients.
	 *
	 * @return	array       array('result' => (bool) true|false)
	 * @throws		TODO
	 *				not_logged_no_permission	if user cannot use private messaging
	 *				no_permission 			if user cannot view $pmid
	 *				invalid_data_w_x_y_z	if $pmid was not a private message node
	 *				add_recipients_error_not_owner		if user can view the PM but is not the topic starter
	 *				invalid_data_w_x_y_z
	 *				pmtoomanyrecipients
	 */
	public function addPMRecipients($pmid, $recipients)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		// Below is currently checked as part of the validate() call.
		// Leaving this here as a reminder to restore if we decide this shouldn't go through the validate(...ADD) check.
		/*
		// VBV-3512
		if (vB::getUserContext()->isGloballyIgnored())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		*/

		//this call with throw an exception if we don't have permission to load it.
		$pmNode = $this->nodeApi->getNode($pmid);
		$starter = $this->nodeApi->getNodeFullContent($pmNode['starter']);
		$starter = $starter[$pmNode['starter']]; // getNodeFullContent() returns array({nodeid} => {node array})
		if (empty($starter) OR $starter['parentid'] != $this->pmChannel)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($pmid, 'pmid', __CLASS__, __FUNCTION__));
		}

		// fail for requests.
		if ($starter['msgtype'] !== 'message')
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($pmid, 'pmid', __CLASS__, __FUNCTION__));
		}


		/*
			If we got this far, current user can *view* the pm node.
			Only allow the PM topic owner to add recipients
		 */
		$currentUserid = vB::getCurrentSession()->get('userid');
		if ($currentUserid != $starter['userid'])
		{
			// note that there isn't an admin bypass for this ATM.
			throw new vB_Exception_Api('add_participants_error_not_owner');
		}

		// re-key recipients with the userids, and also check if they can receive new PMs.
		if (!is_array($recipients))
		{
			$recipients = array($recipients);
		}
		$recipientsCopy = $recipients;
		$recipients = array();
		foreach ($recipientsCopy AS $_key => $_userid)
		{
			$_userid = intval($_userid);
			if (empty($_userid))
			{
				continue;
			}
			// Below will throw vB_Exception_Api('pmrecipturnedoff') or vB_Exception_Api('pmquotaexceeded')
			// if there are problems with this recipient.
			$this->library->checkCanReceivePM(array('userid' => $_userid));
			$recipients[$_userid] = $_userid;

			// also fetch & cache folders. Used way below when we add sentto records.
			$folderCheck = $this->library->checkFolders($_userid);
		}

		// Unset any recipient that's already part of this PM thread.
		$existingRecipients = array();
		$existingRecipientsQry = $this->assertor->getRows('vBForum:getRecipientsForNode', array('nodeid' => $pmNode['starter']));
		foreach ($existingRecipientsQry AS $_recipient)
		{
			$existingRecipients[$_recipient['userid']] = $_recipient['userid'];
			unset($recipients[$_recipient['userid']]);
		}

		if (empty($recipients))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($recipientsCopy, 'recipients', __CLASS__, __FUNCTION__));
		}

		// Check pmsendmax limit
		$pmsendmax = vB::getUserContext()->getLimit('pmsendmax');
		if ($pmsendmax > 0)
		{
			/*
				When a PM Thread is first started, the sender is usually not specified in msgRecipients, and not counted towards
				the pmsendmax limit. However, after a reply is made, the starter's sender gets a 'Inbox' sentto record for the
				original message (not that vBForum:getRecipientsForNode cares for *specific* messagefolders). So the original
				sender (who should be user $currentUserid if we got this far) may be part of $existingRecipients, but we should
				probably not count them towards pmsendmax for this, as we do not for a new thread add().
			 */
			unset($existingRecipients[$currentUserid]);
			$count = count($existingRecipients) + count($recipients);
			if ($count > $pmsendmax)
			{
				throw new vB_Exception_Api('pmtoomanyrecipients', array($count, $pmsendmax));
			}
		}


		// Make sure current user can still start a new PM thread, as that's kind of what they're doing by adding new recipients.
		$data = array(
			'parentid' => $this->pmChannel,
			'hvinput' => array(),
		);
		$hvAPI = vB_Api::instanceInternal('hv');
		if ($hvAPI->fetchRequireHvcheck('post'))
		{
			// vB_Library_Content_PrivateMessage::validate() may require an hvinput check.
			// Since this is an already added post, I don't think it makes a lot of sense to require
			// user to provide this again. We're just making sure that the other "create" permissions
			// are still valid. We don't have a record of whether or not they had a hvinput back then
			// or not, we simply don't hv blocking the other checks in validate().
			$token = $hvAPI->generateToken();
			// $token['answer'] is only available in unit tests, so we have to fetch it from the DB ourselves...
			$answer = vB::getDbAssertor()->getRow('humanverify',
				array(
					'hash' => $token['hash'],
					'dateline' => vB::getRequest()->getTimeNow(),
				)
			);
			if (!empty($answer['answer']))
			{
				// Hypothetical, but if this user requires hv tokens for add(), and either the token/answer-generation the answer-fetch failed for some reason,
				// we're going to exception out in the verifyToken() check that's part of validate().
				// There's very little we can do about that (likely a database failure), and the end user will probably have more problems than trying to add
				// participants (like posting anything), as it suggests a general failure with HV rather than something specific to adding participants.
				$data['hvinput'] = array(
					'input' => $answer['answer'],
					'hash' => $token['hash']
				);
			}
			// TODO: Is there any reason to delete the humanverify record after the validate() call below instead of letting the cron deal with it?
		}

		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		/*
			Add recipients to the thread.

			We need to fetch every message nodeid, and add a sentto record for the "Inbox" folder for each new recipient.
			There're probably other ways to do this, but let's make it simple and just fetch every node in the topic starter's folders.
			This will result in dupes and may be inconsistent depending on whether the topic has replies yet or not, but we shouldn't
			be *missing* any nodes (ignoring unsupported pm "comments"). We'll just go through and filter to force unique.
		 */
		$nodeids = array();
		$nodeidsQry = $this->assertor->getRows('vBForum:getSimplifiedPMNodelist', array('starter' => $pmNode['starter'], 'userid' => $currentUserid));
		foreach ($nodeidsQry AS $_row)
		{
			$_nodeid = $_row['nodeid'];
			$nodeids[$_nodeid] = $_nodeid;
		}

		$folderKey = vB_Library_Content_Privatemessage::MESSAGE_FOLDER;
		$insertColumns = array(	// keep this in sync w/ $insertValues() order below
			'nodeid',
			'userid',
			'folderid',
		);


		$this->assertor->beginTransaction();
		$doCommit = true;
		$errors = array();
		$emailData = array();
		$userLib = vB_Library::instance('user');
		$userOptions = vB::getDatastore()->getValue('bf_misc_useroptions');
		$recipientUsernames = array();
		foreach ($recipients AS $_recipient)
		{
			// we checked folders earlier, so this should throw no exceptions or errors
			$folders = $this->library->fetchFolders($_recipient);
			$folderid = $folders['systemfolders'][vB_Library_Content_Privatemessage::MESSAGE_FOLDER];

			$insertValues = array();
			foreach ($nodeids AS $_nodeid)
			{
				$insertValues[] = array($_nodeid, $_recipient, $folderid);
			}

			$check = false;
			$qryResult = $this->assertor->insertMultiple('vBForum:sentto', $insertColumns, $insertValues);
			// errors array is always set, but empty when there are no errors.
			if (empty($qryResult['errors']))
			{
				// This is a bit awkward, but insertMultiple will return something like
				// array('errors' => array(...), 0 => false|{insert_result})
				unset($qryResult['errors']);
				if (!empty($qryResult))
				{
					$check = true;
				}
				else
				{
					$errors[] = "Insert failed without returning an error. Insert data: " . json_encode($insertValues);
				}
			}
			else
			{
				$errors[] = $qryResult['errors'];
			}

			// abort & rollback commit on any instance of multi-insert failure
			$doCommit = ($doCommit AND $check);

			// Email info
			if ($doCommit)
			{
				$recipientInfo = $userLib->fetchUserinfo($_recipient);
				$emailOnPm = ($recipientInfo['options'] & $userOptions['emailonpm']);
				if ($emailOnPm)
				{
					$_data = array();
					$_data['folderid'] = $folderid;
					$_data['email'] = $recipientInfo['email'];
					$_data['username'] = $recipientInfo['username'];

					$emailData[$_recipient] = $_data;
				}
				// below is not strictly for emails, but for the auto-generated "new participants..." message.
				$recipientUsernames[$_recipient] = $recipientInfo['username'];
			}
		}


		if ($doCommit)
		{
			$this->assertor->commitTransaction();
		}
		else
		{
			$this->assertor->rollbackTransaction();
			throw new vB_Exception_Api('invalid_data');
			// TODO log these errors.
			// error_log($errors);
		}

		/*
			Send an email notification.
			Mostly copied from PM Lib's sendEmailNotification()...
			Use the last (most current) message for the preview text.
			todo: We may want a *different* email message for this as to differentiate...
		 */
		$lastNodeid = end($nodeids);
		reset($nodeids);
		$lastNode = vB_Library::instance('node')->getNodeFullContent($lastNodeid);
		$lastNode = array_pop($lastNode);
		$lastNodePreviewText = vB_String::getPreviewText($lastNode['rawtext']);
		$bbtitle = vB::getDatastore()->getOption('bbtitle');
		$senderUsername = vB_Api::instanceInternal('user')->fetchUserName($currentUserid);
		$phraseApi = vB_Api::instanceInternal('phrase');
		foreach ($emailData AS $_data)
		{
			try
			{
				// At the moment I'm not sure if privatemessage routes can throw exceptions, but let's avoid having that crash the entire process when we're
				// practically done.
				$url = vB5_Route::buildUrl('privatemessage|fullurl',
					array('folderid' => $_data['folderid'], 'pagenum' => 1, 'action' => 'list')
				);
			}
			catch(Exception $e)
			{
				$url = '';
			}


			$maildata = $phraseApi->fetchEmailPhrases(
				'privatemessage',
				array(
					$_data['username'],
					$senderUsername,
					$url,
					$lastNodePreviewText,
					$bbtitle,
				),
				array($bbtitle)
			);

			// Sending the email
			vB_Mail::vbmail($_data['email'], $maildata['subject'], $maildata['message'], false);
		}

		/*
			Send a PM notifying everyone that the users have been added.
			Skip sending an email notification to *new* recipients, as this email is not very useful compared to the one sent above,
			and we don't want to always spam the new recipient.
		 */
		$phraseid = 'privatemessage_new_participant_x';
		if (count($recipients) > 1)
		{
			$phraseid = 'privatemessage_new_participants_x';
		}

		// usernames are already html escaped, so using them should be safe.
		$options = vB::getDatastore()->getValue('options');
		if ($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_USER)
		{
			$usermentions = array();
			foreach ($recipientUsernames AS $__userid => $__username)
			{
				$usermentions[] = "[USER='" . $__userid . "']" . $__username . "[/USER]";
			}
			$phraseData = array(
				implode('; ', $usermentions),
			);
		}
		else
		{
			$phraseData = array(
				implode('; ', $recipientUsernames),
			);
		}

		$data = array(
			'sender' => $currentUserid,
			'respondto' => $pmNode['starter'],
			'rawtext' => vB_Phrase::fetchSinglePhrase($phraseid, $phraseData),
			'parentid' => $pmNode['starter'],
			'msgtype' => 'message',
		);

		$options = array(
			'skipPMEmailForRecipients' => $recipients,
			'skipFloodCheck' => true,
			'skipDupCheck' => true,
		);



		try
		{
			$tryAdd = $this->library->add($data, $options);
		}
		catch(Exception $e)
		{
			// catch these in tests so we can figure out what might go wrong.
			// However, it's not worth breaking out of the function when the "main" task is complete and only the
			// "nice to have" bit is broken.
			if (defined('VB_UNITTEST'))
			{
				throw $e;
			}
		}


		/*
			TODO: Ignored user? Currently PM allows an ignored user to send a PM to an ignorer. The ignorer just never sees the PM(s) from the ignoree. As such
			I'm leaving any ignored user checks out ATM...
		 */

		return array(
			'result' => true,
		);

	}

	/**
	 * Adds a new private message
	 *
	 * @param  mixed must include 'sentto', 'contenttypeid', and the necessary data for that contenttype.
	 * @param  array Array of options for the content being created.
	 *               Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification,
	 *               nl2br, autoparselinks, skipNonExistentRecipients.
	 *               - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *               - skipNonExistentRecipients (bool) skips recipients that don't exist instead of throwing an exception.
	 *               - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return int   the new nodeid.
	 */
	public function add($data, $options = array())
	{
		$vboptions = vB::getDatastore()->getValue('options');
		if (!empty($data['title']))
		{
			$strlen = vB_String::vbStrlen(trim($data['title']), true);
			if ($strlen > $vboptions['titlemaxchars'])
			{
				throw new vB_Exception_Api('maxchars_exceeded_x_title_y', array($vboptions['titlemaxchars'], $strlen));
			}
		}

		//If this is a response, we have a "respondto" = nodeid
		//If it's a forward, we set "forward" = nodeid
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$sender = intval($userInfo['userid']);

		if (!intval($sender) OR !$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if (!$userInfo['receivepm'])
		{
			throw new vB_Exception_Api('pm_turnedoff');
		}

		$data['sender'] = $sender;
		$recipientNames = 0;
		//check if the user from the usergroup can send the pm to the number of recipients
		$pmsendmax = vB::getUserContext()->getLimit('pmsendmax');
		if (!empty($data['msgRecipients']))
		{
			$recipientNames = count(explode(',', $data['msgRecipients']));
		}
		else if (!empty($data['sentto']))
		{
			//sentto can be a single recipient id
			$recipientNames = (is_array($data['sentto']) ? count($data['sentto']) : 1);
		}
		if ($pmsendmax > 0 AND $recipientNames > $pmsendmax)
		{
			throw new vB_Exception_Api('pmtoomanyrecipients', array($recipientNames, $pmsendmax));
		}

		if (!empty($data['pagetext']))
		{
			$strlen = vB_String::vbStrlen($this->library->parseAndStrip($data['pagetext']), true);
			if ($strlen < $vboptions['pmminchars'])
			{
				throw new vB_Exception_Api('please_enter_message_x_chars', $vboptions['pmminchars']);
			}
			if ($vboptions['pmmaxchars'] != 0 AND $strlen > $vboptions['pmmaxchars'])
			{
				throw new vB_Exception_Api('maxchars_exceeded_x_y', array($vboptions['pmmaxchars'], $strlen));
			}
		}
		else if (!empty($data['rawtext']))
		{
			$strlen = vB_String::vbStrlen($this->library->parseAndStrip($data['rawtext']), true);
			if ($strlen < $vboptions['pmminchars'])
			{
				throw new vB_Exception_Api('please_enter_message_x_chars', $vboptions['pmminchars']);
			}
			if ($vboptions['pmmaxchars'] != 0 AND $strlen > $vboptions['pmmaxchars'])
			{
				throw new vB_Exception_Api('maxchars_exceeded_x_y', array($vboptions['pmmaxchars'], $strlen));
			}
		}
		else
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (empty($data['parentid']))
		{
			$data['parentid'] = $this->pmChannel;
		}

		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		if (isset($data['respondto']))
		{
			if (!empty($data['respondto']))
			{
				//if we don't have access to see a node we can't respond to it.
				//this call with throw an exception if we don't have permission to load it.
				$respondToNode = $this->nodeApi->getNode($data['respondto']);

				if ($data['respondto'] ==  $this->pmChannel OR empty($respondToNode['starter']))
				{
					// PMChat will set this to the pm channel. Quick shortcut check for the common case.
					// Also ignore it if it's somehow set to another channel (which would lack node.starter)
					unset($data['respondto']);
				}
				else
				{
					// check parentage, make sure it's a pm node.
					$starter = $this->nodeApi->getNode($respondToNode['starter']);
					// If it's not a PM node, it may create the child node anyways along with the appropriate sentto records, but the usual
					// pm queries seem to fail to retrieve it, as it's not visible on the frontend either in the inbox, or in the relevant node.
					// However, it leaves behind bad DB records, so let's just unset it.
					if ($starter['parentid'] != $this->pmChannel)
					{
						unset($data['respondto']);
					}
				}
			}
			else
			{
				unset($data['respondto']);
			}
		}

		//only enforce quota if this isn't a response
		if (!isset($data['respondto']))
		{
			$pmquota = vB::getUserContext()->getLimit('pmquota');
			if ($userInfo['pmtotal'] >= $pmquota)
			{
				throw new vB_Exception_Api('yourpmquotaexceeded', array($pmquota, $userInfo['pmtotal']));
			}
		}

		$data = $this->cleanInput($data);
		$this->cleanOptions($options);

		$wysiwyg = true;
		if(isset($options['wysiwyg']))
		{
			$wysiwyg = (bool) $options['wysiwyg'];
		}

		//If this is a response, we have a "respondto" = nodeid
		$result = $this->library->add($data, $options, $wysiwyg);

		return $result['nodeid'];
	}

	/**
	 * Permanently deletes a message
	 *
	 * @param  int  nodeid of the entry to be deleted.
	 *
	 * @return bool did the deletion succeed?
	 */
	public function deleteMessage($nodeid)
	{
		//We need a copy of the existing node.
		$content = $this->nodeApi->getNode($nodeid);

		if (empty($content) OR !empty($content['error']))
		{
			throw new vB_Exception_Api('invalid_data');
		}
		$currentUser = vB::getCurrentSession()->get('userid');

		if (!intval($currentUser) OR !$this->library->validate($content, vB_Library_Content::ACTION_DELETE, $nodeid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		return $this->library->deleteMessage($nodeid, $currentUser);
	}

	/**
	 * Deletes all pms for a given user
	 *
	 * This will mark all "sentto" records for the given user as deleted.
	 * In addtion it will mark any PM records for deletion that no longer have
	 * any users attached to them.  The actual deletion is handled via cron script.
	 *
	 * The requested user must much the current user or the current use have the 'canadminusers' permission
	 *
	 * @param  int              $userid
	 *
	 * @return array
	 *  'deleted' int -- number of items marked for delete (for the user, the pm itself might be referenced
	 *                          by another user and therefore still around)
	 *
	 * @throws vB_Exception_Api
	 *	-- invalid_data_w_x_y_z when userid is not valid
	 *	-- not_logged_no_permission user is not an admin and does not have permission to use pm system
	 */
	public function deleteMessagesForUser($userid)
	{
		$userid = intval($userid);
		if ($userid <= 0)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, 'userid', __CLASS__, __FUNCTION__));
		}

		if (vB::getCurrentSession()->get('userid') != $userid)
		{
			$this->checkHasAdminPermission('canadminusers');
		}
		else
		{
			//don't use canUsePmSystem here because that validates against the current
			//logged in user and we want to allow admins to use this function for other users
			//we should eventually fix the entire library to work that way.
			$pmquota = vB::getUserContext()->getLimit('pmquota');
			$vboptions = vB::getDatastore()->getValue('options');

			if (!$pmquota OR !$vboptions['enablepms'])
			{
				throw new vB_Exception_Api('not_logged_no_permission');
			}
		}

		$count = $this->library->deleteMessagesForUser($userid);

		return array('deleted' => $count);
	}

	/**
	 * Deletes all pms for a given user
	 *
	 * This will mark all "sentto" records for PM nodes sent by the given user as deleted.
	 * In addtion it will mark any PM records for deletion that no longer have
	 * any users attached to them.  The actual deletion is handled via cron script.
	 *
	 * The the current user must have the 'canadminusers' permission.  (This deletes things from
	 * other people's inboxes so we don't want to allow normal users to use it)
	 *
	 * @param  int              $userid
	 *
	 * @return array
	 *  'deleted' int -- number of items marked for delete (for the user, the pm itself might be referenced
	 *		by another user and therefore still around)
	 *
	 * @throws vB_Exception_Api
	 *	-- invalid_data_w_x_y_z when userid is not valid
	 */
	public function deleteSentMessagesForUser($userid)
	{
		$userid = intval($userid);
		if ($userid <= 0)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, 'userid', __CLASS__, __FUNCTION__));
		}

		$this->checkHasAdminPermission('canadminusers');
		$count = $this->library->deleteSentMessagesForUser($userid);

		return array('deleted' => $count);
	}

	/**
	 * Calculates the number of private messages that a user has in the system
	 * Used to limit pm abilities based on overage of this count
	 *
	 * @param array|int	List of users to rebuild user.pmtotal for
	 */
	public function buildPmTotals($userids)
	{
		if (is_array($userids))
		{
			$userids = array_map('intval', $userids);
		}
		else
		{
			$userids = intval($userids);
		}

		$this->checkHasAdminPermission('canadminusers');
		$count = $this->library->buildPmTotals($userids);
	}

	/**
	 * Moves a message to a different folder
	 *
	 * @param  int  the node to be moved
	 * @param  int  the new parent node.
	 *
	 * @return bool did it succeed?
	 */
	public function moveMessage($nodeid, $newFolderid = false)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$currentUser = $userInfo['userid'];

		if (!intval($currentUser))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$nodeids = explode(',', $nodeid);

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		// if it's not message we can't move
		$pmRec = $this->assertor->getRows('vBForum:privatemessage', array(
			'nodeid' => $nodeids
		));

		foreach ($pmRec AS $node)
		{
			if ($node['msgtype'] != 'message')
			{
				throw new vB_Exception_Api('no_move_permission_x', array($node['nodeid']));
			}
		}

		//we can only move a record to which the user has access.
		$this->library->checkFolders($currentUser);
		$folders = $this->library->fetchFolders($currentUser);
		$sentFolder = $folders['systemfolders'][vB_Library_Content_Privatemessage::SENT_FOLDER];

		if (
			in_array($newFolderid, $folders['systemfolders'])
			AND !in_array($newFolderid, array(
				$folders['systemfolders'][vB_Library_Content_Privatemessage::MESSAGE_FOLDER],
				$folders['systemfolders'][vB_Library_Content_Privatemessage::TRASH_FOLDER]
			))
		)
		{
			throw new vB_Exception_Api('invalid_move_folder');
		}
		$conditions = array(
			array('field' => 'userid', 'value' => $currentUser),
			array('field' => 'nodeid', 'value' => $nodeids)
		);
		// allow deleting sent items
		if ($newFolderid != $folders['systemfolders'][vB_Library_Content_Privatemessage::TRASH_FOLDER])
		{
			$conditions[] = array('field' => 'folderid', 'value' => $sentFolder, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE);
		}

		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, vB_dB_Query::CONDITIONS_KEY => $conditions);
		$existing = $this->assertor->getRows('vBForum:sentto', $data);

		if (empty($existing) OR !empty($existing['errors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		return $this->library->moveMessage($nodeid, $newFolderid, $existing);
	}

	/**
	 * Gets a message
	 *
	 * @param  int   The Node ID
	 *
	 * @return mixed Array of data
	 */
	public function getMessage($nodeid)
	{
		$content = $this->nodeApi->getNode($nodeid);

		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		//if this is the author we can return the value
		if ($content['userid'] == $userid)
		{
			return $this->library->getMessage($nodeid);
		}

		//Maybe this is a recipient.
		$recipients = $this->assertor->getRows('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid));
		foreach ($recipients as $recipient)
		{
			if ($recipient['userid'] == $userid)
			{
				return $this->library->getMessage($nodeid);
			}
		}

		//If we got here, this user isn't authorized to see this record. Well, it's also possible this may not exist.
		throw new vB_Exception_Api('no_permission');
	}

	/**
	 * Get a single request
	 *
	 * @param  int   the nodeid
	 *
	 * @return array The node data array for the request
	 */
	public function getRequest($nodeid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

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
	 * Lists the folders.
	 *
	 * @param  mixed array of system folders to be hidden. like vB_Library_Content_Privatemessage::MESSAGE_FOLDER
	 *
	 * @return mixed array of folderid => title
	 */
	public function listFolders($suppress = array())
	{
		return $this->library->listFolders($suppress);
	}

	/**
	 * Creates a new message folder. It returns false if the record already exists and the id if it is able to create the folder
	 *
	 * @return int
	 */
	public function createMessageFolder($folderName)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if(vB_String::vbStrlen($folderName) > 50)
		{
			throw new vB_Exception_Api('error_foldername_maxlength');
		}
		$userid = vB::getCurrentSession()->get('userid');

		return $this->library->createMessageFolder($folderName, $userid);
	}

	/**
	 * Moves a node to the trashcan. Wrapper for deleteMessage()
	 *
	 * @param int
	 */
	public function toTrashcan($nodeid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		$this->library->checkFolders($userid);
		$folders = $this->library->fetchFolders($userid);

		return $this->moveMessage($nodeid, $folders['systemfolders'][vB_Library_Content_Privatemessage::TRASH_FOLDER]);
	}

	/**
	 * Returns a summary of messages for current user
	 *
	 * @return array Array of information including:
	 *               folderId, title, quantity not read.
	 */
	public function fetchSummary()
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		return $this->library->fetchSummary($userid);
	}

	/**
	 * Lists messages for current user
	 *
	 *	@param array $data-
	 *		'sortDir'
	 *		'pageNum'
	 *		'perpage'
	 *		'folderid'
	 *		'showdeleted'
	 *		'ignoreRecipients'
	 *	@return	array - list of messages.
	 */
	public function listMessages($data = array())
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		return $this->library->listMessages($data, $userid);
	}

	/**
	 * Lists notifications for current user
	 *
	 * @deprecated 5.1.6  Only used by unit tests
	 *
	 * @param      mixed- can pass sort direction, type, page, perpage
	 *
	 * @return     Array  @see vB_Library_Notification::fetchNotificationsforCurrentUser()
	 */
	public function listNotifications($data = array())
	{
		// TODO: remove this function. Do not simply deprecate since
		// notification API returns different data and isn't compatible.
		// This stopgap is meant for internal calls only!!
		if (!isset($data['readFilter']))
		{
			// Really only used by unit tests nowadays, but the 'read' status is a new concept and wasn't around back when
			// notifications were part of the PM code. So the default when going through PM API would be "both" not "unread_only"
			$data['readFilter'] = 'both';
		}
		$notifications = vB_Api::instanceInternal('notification')->fetchNotificationsForCurrentUser($data);
		return $notifications;

	}

	/**
	 * Lists messages for current user
	 *
	 * @param  mixed- can pass sort direction, type, page, perpage, or folderid.
	 *
	 * @return mixed  - array-includes folderId, title, quantity not read. Also 'page' is array of node records for page 1.
	 */
	protected function listSpecialPrivateMessages($data = array())
	{
		$userid = vB::getCurrentSession()->get('userid');
		if (!intval($userid))
		{
			return false;
		}

		return $this->library->listSpecialPrivateMessages($data);
	}

	/**
	 * Lists messages for current user
	 *
	 * @param  mixed- can pass sort direction, type, page, perpage, or folderid.
	 *
	 * @return mixed  - array-includes folderId, title, quantity not read. Also 'page' is array of node records for page 1.
	 */
	public function listRequests($data = array())
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$this->library->checkFolders($userid);

		$folders = $this->library->fetchFolders($userid);
		$data['folderid'] = $folders['systemfolders'][vB_Library_Content_Privatemessage::REQUEST_FOLDER];
		$data['userid'] = $userid;

		$requests = $this->listSpecialPrivateMessages($data);

		//We need blog info

		$channelRequests = $this->library->getChannelRequestTypes();

		$channels = array();

		if (!empty($requests))
		{
			foreach ($requests as $key => &$request)
			{
				//if it's a channel request we need the channel title
				if (in_array($request['about'], $channelRequests))
				{
					$channels[] = $request['aboutid'];
				}

				/* construct phrase name.  Be sure to create the new
				 * phrases when new requests are added! Also add any new channel requests to
				 * library\content\privatemessage's $channelRequests array.
				 * Channel requests: received_<about string>_request_from_x_link_y_<to/for>_channel_z
				 * Other requests: received_<about string>_request_from_x_link_y
				 * If the about string is equal to another request's about string after stripping sg_ and _to, the same phrase will be used.
				 * */
				$cleanAboutStr = preg_replace('/(^sg_)?|(_to$)?/', '', $request['about']);
				$request['phrasename'] = 'received_' . $cleanAboutStr . '_request_from_x_link_y';
			}
		}

		//If we have some channel info to get let's do it now.
		if (!empty($channels))
		{
			$channelInfo = vB_Api::instanceInternal('node')->getNodes($channels);

			foreach ($channelInfo AS $channel)
			{
				foreach ($requests as $key => &$request)
				{
					if ($request['aboutid'] == $channel['nodeid'])
					{
						$request['abouttitle'] = $channel['title'];
						$request['aboutrouteid'] = $channel['routeid'];

						// if it's a channel request, and has a title & url, the phrase name
						// should have a "_to_channel_z" (take request) or "_for_channel_z" (grant request) appended
						if(strpos($request['about'], '_to') !== false)
						{
							$request['phrasename'] .= '_to_channel_z';
						}
						else
						{
							$request['phrasename'] .= '_for_channel_z';
						}
					}
				}
			}
		}

		return $requests;
	}

	/**
	 * Returns an array with bbcode options for PMs
	 *
	 * @return array Options
	 */
	public function getBbcodeOptions($nodeid = 0)
	{
		if (!$this->bbcodeOptions)
		{
			// all pm nodes have the same options
			$response = vB_Api::instanceInternal('bbcode')->initInfo();
			$this->bbcodeOptions = $response['defaultOptions']['privatemessage'];
		}
		return $this->bbcodeOptions;
	}

	/**
	 * Gets the count of undeleted messages in a folder
	 *
	 * @param  int    $folderid the folderid to search
	 * @param  int    $pageNum
	 * @param  int    $perpage
	 * @param  String $about Optional "about" string
	 * @param  Array  $filterParams Optional filter parameters, only used for notifications.
	 *                See vB_Library_Notification::fetchNotificationsForCurrentUser()
	 *                - 'sortDir'
	 *                - 'perpage'
	 *                - 'page'
	 *                - 'showdetail'
	 *                - 'about'
	 *
	 * @return Array  the count & page data, including: 'count', 'pages' (total pages), 'pagenum' (selected page #), 'nextpage', 'prevpage'
	 */
	public function getFolderMsgCount($folderid, $pageNum = 1, $perpage = 50, $about = false, $filterParams = false)
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$this->library->checkFolders($userid);
		$folders = $this->library->fetchFolders($userid);

		$notificationFolderid = $folders['systemfolders'][vB_Library_Content_Privatemessage::NOTIFICATION_FOLDER];

		if (!array_key_exists($folderid, $folders['folders']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if ($folderid == $notificationFolderid)
		{
			$qty = vB_Library::instance('notification')->fetchNotificationCountForUser($userid, $filterParams);

			if (isset($filterParams['page']))
			{
				$pageNum = $filterParams['page'];
			}

			if (isset($filterParams['perpage']))
			{
				$perpage = $filterParams['perpage'];
			}
		}
		else
		{
			// @TODO improve the queries to return the count already to avoid using count() from rows
			if (empty($about))
			{
				$result = $this->assertor->getRows('vBForum:getMsgCountInFolder', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'folderid' => $folderid));
			}
			else
			{
				$result = $this->assertor->getRows('vBForum:getMsgCountInFolderAbout', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'userid' => $userid, 'folderid' => $folderid, 'about' => $about));
			}


			if (empty($result) OR !empty($result['errors']))
			{
				$qty = 0;
			}
			else
			{
				$qty = count($result);
			}
		}

		if (empty($perpage))
		{
			$pagecount = ceil($qty / 50);
		}
		else
		{
			$pagecount = ceil($qty / $perpage);
		}

		if ($pageNum > 1)
		{
			$prevpage = $pageNum - 1;
		}
		else
		{
			$prevpage = false;
		}

		if ($pageNum < $pagecount)
		{
			$nextpage = $pageNum + 1;
		}
		else
		{
			$nextpage = false;
		}

		return array('count' => $qty, 'pages' => $pagecount, 'pagenum' => $pageNum, 'nextpage' => $nextpage, 'prevpage' => $prevpage);
	}

	/**
	 * Gets the count of undeleted messages & notifications
	 *
	 * @param  int the folderid to search
	 *
	 * @return int the count
	 */
	public function getUnreadInboxCount()
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			return 0;
		}

		$this->library->checkFolders($userid);

		if ($this->canUsePmSystem())
		{
			$result = $this->assertor->getRow('vBForum:getUnreadMsgCount', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'userid' => $userid));
		}
		else
		{
			$result = $this->assertor->getRow('vBForum:getUnreadSystemMsgCount', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'userid' => $userid));
		}

		if (empty($result) OR !empty($result['errors']))
		{
			return 0;
		}

		$reportsCount = $this->getOpenReportsCount();
		$notificationsCount = vB_Library::instance('notification')->fetchNotificationCountForUser($userid, array('readFilter' => 'unread_only'));
		$total = $result['qty'] + $reportsCount + $notificationsCount;


		return $total;
	}

	/**
	 * Gets the count of undeleted privatemessages, requests, notifications & reports
	 *
	 * @return array
	 *                int  'messages'             private messages
	 *                int  'requests'
	 *                int  'notifications'
	 *                int  'pending_posts'
	 *                int  'reports'
	 *                bool 'canviewreports'        if the "reports" should be displayed.
	 *                int  'nonpms_sum'            sum of the int counts minus 'messages' count
	 *                int  'folderid_messages'
	 */
	public function getHeaderCounts()
	{
		/*
			TODO: How are 'pending_posts' sentto records created??
		 */
		$result = array('messages' => 0, 'requests' => 0, 'notifications' => 0, 'pending_posts' => 0, 'reports' => 0, 'canviewreports' => false,  'nonpms_sum' => 0, 'folderid_messages' => 0);

		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			return $result;
		}

		$this->library->checkFolders($userid);


		$queryResult = $this->assertor->getRows('vBForum:getHeaderMsgCount', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'userid' => $userid));
		foreach ($queryResult AS $row)
		{
			$result[$row['folder']] = $row['qty'];
			if ($row['folder'] == 'messages')
			{
				$result['folderid_' . $row['folder']] = $row['folderid'];
			}
		}

		if (!$this->canUsePmSystem())
		{
			$result['messages'] = 0;
		}

		$canViewReports = vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', vB_Api::instanceInternal('node')->fetchReportChannel());
		if ($canViewReports)
		{
			$result['canviewreports'] = true;
			$result['reports'] = $this->getOpenReportsCount();
		}
		else
		{
			$result['canviewreports'] = false;
			$result['reports'] = 0;
		}

		$result['notifications'] = vB_Library::instance('notification')->fetchNotificationCountForUser($userid, array('readFilter' => 'unread_only'));
		$result['nonpms_sum'] = $result['requests'] + $result['notifications'] + $result['pending_posts'] + $result['reports'];

		// If there were no new messages, this may not be set correctly.
		if (empty($result['folderid_messages']))
		{
			// messagefolder AS f ON f.folderid = s.folderid AND f.titlephrase IN
			$qry = $this->assertor->getRow('vBForum:messagefolder', array('userid' => $userid, 'titlephrase' => array('messages')));
			if (!empty($qry['folderid']))
			{
				$result['folderid_messages'] = $qry['folderid'];
			}

		}

		return $result;
	}

	/**
	 * Gets the count of open reports
	 *
	 * @return int the count of open reports
	 */
	public function getOpenReportsCount()
	{
		if (vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', vB_Api::instanceInternal('node')->fetchReportChannel()))
		{
			$result = $this->assertor->getRow('vBForum:getOpenReportsCount');
			return $result['qty'];
		}
		else
		{
			// they cannot view reports. return 0
			return 0;
		}
	}

	/**
	 * Gets the preview for the messages
	 *
	 * @return mixed array of record-up to five each messages, then requests, then notifications
	 */
	public function previewMessages()
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$userid = vB::getCurrentSession()->get('userid');
		$this->library->checkFolders($userid);
		$folders = $this->library->fetchFolders($userid);

		$exclude = array(
			$folders['systemfolders'][vB_Library_Content_Privatemessage::TRASH_FOLDER],
			$folders['systemfolders'][vB_Library_Content_Privatemessage::NOTIFICATION_FOLDER],
		);

		$lastnodeidsQry = $this->assertor->getRows('vBForum:lastNodeids', array('userid' => $userid, 'excludeFolders' => $exclude));
		// since the above query might not return anything, if there are no privatemessages for the user, add a -1 to prevent
		// the qryResults query from breaking
		$lastnodeids = array(-1);
		foreach ($lastnodeidsQry AS $lastnode)
		{
			$lastnodeids[] = $lastnode['nodeid'];
		}
		$ignoreUsersQry = $this->assertor->getRows('vBForum:getIgnoredUserids', array('userid' => $userid));
		$ignoreUsers = array(-1);
		foreach ($ignoreUsersQry as $ignoreUser)
		{
			$ignoreUsers[] = $ignoreUser['userid'];
		}
		$qryResults = $this->assertor->assertQuery('vBForum:pmPreview', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'userid' => $userid,
			'ignoreUsers' => $ignoreUsers,
			'excludeFolders' => $exclude,
			'nodeids' => $lastnodeids,
		));

		/*
		TODO: the 'title' fields used to be used by privatemessage_foldersummary template. They were used in a way that made translations difficult,
		so that template no longer relies on it, but other callers might use it, so I haven't removed 'title' yet.
		At some point we should check for the dependency and remove 'title', as they'd be unnecessary fetchSinglePhrase() calls.
		 */
		$results = array(
			'message' => array(
				'count' => 0,
				'title'=> vB_Phrase::fetchSinglePhrase('messages'),
				'folderid' => 0,
				'messages' => array(),
				'phrase_titles' => array(
					'preview' => 'inbox_preview',
					'see_all' => 'see_all_inbox',
				),
			),
			'request' => array(
				'count' => 0,
				'title'=> vB_Phrase::fetchSinglePhrase('requests'),
				'folderid' => 0,
				'messages' => array(),
				'phrase_titles' => array(
					'preview' => 'requests_preview',
					'see_all' => 'see_all_requests',
				),
			),
			'notification' => array(
				'count' => 0,
				'title'=> vB_Phrase::fetchSinglePhrase('notifications'),
				'folderid' => 0,
				'messages' => array(),
				'phrase_titles' => array(
					'preview' => 'notifications_preview',
					'see_all' => 'see_all_notifications',
				),
			),
		);

		$messageIds = array();
		$nodeIds = array();
		$userIds = array();
		$userApi = vB_Api::instanceInternal('user');
		$receiptDetail = vB::getUserContext()->hasPermission('genericpermissions', 'canseewholiked');

		$needLast = array();
		if ($qryResults->valid())
		{
			foreach ($qryResults AS $result)
			{
				if (empty($result['previewtext']))
				{
					$result['previewtext'] = vB_String::getPreviewText($result['rawtext']);
				}

				if ($result['titlephrase'] == 'messages')
				{
					$messageIds[] = $result['nodeid'];
				}
				else
				{
					$nodeIds[] = $result['nodeid'];
				}

				// privatemessage_requestdetail template requires you to pass back the phrase name for requests.
				// See listRequests() for more details
				if($result['msgtype'] == 'request')
				{
					// remove starting sg_ and ending _to from the about string
					$cleanAboutStr = preg_replace('/(^sg_)?|(_to$)?/', '', $result['about']);
					$result['phrasename'] = 'received_' . $cleanAboutStr . '_request_from_x_link_y';

					// grab channel request types
					$channelRequests = $this->library->getChannelRequestTypes();

					// append correct suffix for channel requests
					if(in_array($result['about'], $channelRequests))
					{
						// should have a "_to_channel_z" (take request) or "_for_channel_z" (grant request) appended
						if(strpos($result['about'], '_to') !== false)
						{
							$result['phrasename'] .= '_to_channel_z';
						}
						else
						{
							$result['phrasename'] .= '_for_channel_z';
						}
					}
				}

				$result['senderAvatar'] = $userApi->fetchAvatar($result['userid']);
				$result['recipients'] = array();
				$result['otherRecipients'] = 0;
				$result['responded'] = 0;
				$results[$result['msgtype']]['messages'][$result['nodeid']] = $result;
				$results[$result['msgtype']]['count']++;
				$userIds[] = $result['userid'];

				if (intval($result['lastauthorid']))
				{
					$userIds[] = $result['lastauthorid'];
				}
				if (!$results[$result['msgtype']]['folderid'])
				{
					$results[$result['msgtype']]['folderid'] = $result['folderid'];
				}

				// set recipients needed
				if ($result['msgtype'] == 'message')
				{
					if (empty($result['lastauthorid']) OR $result['lastauthorid'] == $userid)
					{
						$needLast[] = $result['nodeid'];
					}
				}
			}

			// @TODO check for a way to implement a generic protected library method to fetch recipients instead of cloning code through methods.
			// drag the needed info
			if (!empty($needLast))
			{
				$needLast = array_unique($needLast);
				$neededUsernames = $this->assertor->assertQuery('vBForum:getPMLastAuthor', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $needLast, 'userid' => $userid));
				foreach ($neededUsernames AS $username)
				{
					if (isset($results['message']['messages'][$username['nodeid']]))
					{
						$results['message']['messages'][$username['nodeid']]['lastcontentauthor'] = $username['username'];
						$results['message']['messages'][$username['nodeid']]['lastauthorid'] = $username['userid'];
					}
				}
			}

			//Now we need to sort out the other recipients for this message.
			$recipients = array();
			if (!empty($nodeIds))
			{
				$recipientQry = $this->assertor->assertQuery('vBForum:getPMRecipients', array(
					'nodeid' => array_unique($nodeIds),
					'userid' => $userid,
				));
				foreach ($recipientQry AS $recipient)
				{
					$recipients[$recipient['nodeid']][$recipient['userid']] = $recipient;
				}
			}

			$messageRecipients = array();
			if (!empty($messageIds))
			{
				$recipientsInfo = $this->assertor->assertQuery('vBForum:getPMRecipientsForMessage', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'nodeid' => $messageIds
				));

				$recipients = array();
				if (!empty($recipientsInfo))
				{
					foreach ($recipientsInfo AS $recipient)
					{
						if (isset($results['message']['messages'][$recipient['starter']]))
						{
							if (($recipient['userid'] == $userid))
							{
								if (empty($results['message']['messages'][$recipient['starter']]['included']))
								{
									$results['message']['messages'][$recipient['starter']]['included'] = true;
								}

								continue;
							}
							else if ($results['message']['messages'][$recipient['starter']]['lastcontentauthor'] == $recipient['username'])
							{
								continue;
							}

							if (!isset($results['message']['messages'][$recipient['starter']]['recipients'][$recipient['userid']]))
							{
								$results['message']['messages'][$recipient['starter']]['recipients'][$recipient['userid']] = $recipient;
							}
						}
					}
				}
			}

			//Collect the user info. Doing it this way we get a lot of info in one query.
			$userQuery = $this->assertor->assertQuery('user', array('userid' => array_unique($userIds)));
			$userInfo = array();
			$userApi = vB_Api::instanceInternal('user');
			foreach ($userQuery AS $userRecord)
			{
				//some information we shouldn't pass along.
				foreach (array('token', 'scheme', 'secret', 'coppauser', 'securitytoken_raw', 'securitytoken', 'logouthash',
					'passworddate', 'parentemail', 'logintype', 'ipaddress', 'passworddate',
					'referrerid', 'ipoints', 'infractions', 'warnings', 'infractiongroupids', 'infractiongroupid',
				) AS $field)
				{
					unset($userRecord[$field]);
				}

				$userRecord['avatar'] = $userApi->fetchAvatar($userRecord['userid'], true, $userRecord);
				$userInfo[$userRecord['userid']] = $userRecord;
			}

			//Now we need to scan the results list and assign the other recipients.
			foreach ($results AS $key => $folder)
			{
				foreach ($folder['messages'] AS $msgkey => $message)
				{
					if ($message['titlephrase'] == 'messages')
					{
						// set the first recipient
						if (!empty($message['lastcontentauthor']) AND !empty($message['lastauthorid']) AND ($message['lastauthorid'] != $userid))
						{
							$results[$key]['messages'][$msgkey]['firstrecipient'] = array(
								'userid' => $message['lastauthorid'],
								'username' => $message['lastcontentauthor']
							);
						}
						else if (!empty($message['recipients']))
						{
							$firstrecip = reset($message['recipients']);
							$results[$key]['messages'][$msgkey]['firstrecipient'] = $firstrecip;
							unset($results[$key]['messages'][$msgkey]['recipients'][$firstrecip['userid']]);
						}

						$results[$key]['messages'][$msgkey]['otherRecipients'] = count($results[$key]['messages'][$msgkey]['recipients']);
					}
					else
					{
						if (!empty($recipients[$message['nodeid']]))
						{
							$results[$key]['messages'][$msgkey]['recipients'] = $recipients[$message['nodeid']];
							$results[$key]['messages'][$msgkey]['otherRecipients'] = count($recipients[$message['nodeid']]);
							$results[$key]['messages'][$msgkey]['userinfo'] = $userInfo[$message['userid']];
						}
					}

					if ($message['lastauthorid'])
					{
						$results[$key]['messages'][$msgkey]['lastauthor'] = $userInfo[$message['lastauthorid']]['username'];
						$results[$key]['messages'][$msgkey]['lastcontentauthorid'] = $message['lastauthorid'];
						$results[$key]['messages'][$msgkey]['lastcontentavatar'] = $userInfo[$message['lastauthorid']]['avatar'];
					}
				}

				if (empty($message['previewtext']))
				{
					$results[$key]['previewtext'] = vB_String::getPreviewText($message['rawtext']);
				}
			}
		}

		$channelRequests = $this->library->getChannelRequestTypes();

		$nodeIds = array();
		foreach ($results['request']['messages'] AS $message)
		{
			if (in_array($message['about'], $channelRequests))
			{
				$nodeIds[] = $message['aboutid'];
			}
		}

		if (!empty($nodeIds))
		{
			$nodesInfo = vB_Library::instance('node')->getNodes($nodeIds);

			$arrayNodeInfo = array();
			foreach ($nodesInfo as $node)
			{
				$arrayNodeInfo[$node['nodeid']] = array('title' => $node['title'], 'routeid' => $node['routeid']);
			}

			foreach ($results['request']['messages'] AS $key => &$val)
			{
				if (isset($arrayNodeInfo[$val['aboutid']]))
				{
					$val['abouttitle'] = $arrayNodeInfo[$val['aboutid']]['title'];
					$val['aboutrouteid'] = $arrayNodeInfo[$val['aboutid']]['routeid'];
				}
			}
		}


		// add notifications
		$params = array(
			'showdetail' => $receiptDetail,
			'perpage' => 5,
			'page' => 1,
			'sortDir' => "DESC",
		);
		$notifications = vB_Library::instance('notification')->fetchNotificationsForCurrentUser($params);
		$results['notification']['messages'] = $notifications;
		$results['notification']['count'] = count($notifications);
		$results['notification']['folderid'] = $folders['systemfolders'][vB_Library_Content_Privatemessage::NOTIFICATION_FOLDER];


		return $results;
	}

	/**
	 * Returns the text for a "reply" or "forward" message. Not implemented yet
	 */
	public function getReplyText($nodeid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		throw new vB_Exception_Api('not_implemented');
	}

	/**
	 * Sets a message to read
	 *
	 * @param $nodeid
	 * @return standard success array
	 */
	public function setRead($nodeid, $read = 1)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$this->library->setRead($nodeid, $read, vB::getCurrentSession()->get('userid'));
		return array('success' => true);
	}

	/**
	 * Checks that we have all the folders for the current user, and the set folders are there.
	 *
	 * @param int User ID of the current user
	 */
	public function checkFolders($userid = false)
	{
		if (empty($userid))
		{
			if (!$this->canUsePmSystem())
			{
				throw new vB_Exception_Api('not_logged_no_permission');
			}
		}
		return $this->library->checkFolders(vB::getCurrentSession()->get('userid'));
	}

	/**
	 * Updates the title
	 *
	 * @param  string The folder name
	 * @param  int    The folder ID
	 *
	 * @return array  The array of folder information for this folder.
	 */
	public function updateFolderTitle($folderName, $folderid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		$this->library->checkFolders($userid);

		if (empty($folderid) OR empty($folderName))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$cleaner = vB::getCleaner();
		$foldername = $cleaner->clean($folderName, $vartype = vB_Cleaner::TYPE_NOHTML);
		$folderid = intval($folderid);
		$folders = $this->library->fetchFolders($userid);

		if (
			!array_key_exists($folderid, $folders['folders']) OR
			in_array($folderid, $folders['systemfolders'])
		)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		if (empty($foldername) OR (strlen($foldername) > 512))
		{
			throw new vB_Exception_Api('invalid_msgfolder_name');
		}

		//If we got here we have valid data.
		return $this->assertor->assertQuery('vBForum:messagefolder', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			vB_dB_Query::CONDITIONS_KEY => array('folderid' => $folderid),
			'title' => $foldername
		));
	}

	/**
	 * Deletes a folder and moves its contents to trash
	 *
	 * @param string The new folder title.
	 */
	public function deleteFolder($folderid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		$this->library->checkFolders($userid);
		$folders = $this->library->fetchFolders($userid);

		if (!array_key_exists($folderid, $folders['folders']) OR
			in_array($folderid, $folders['systemfolders']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		//If we got here we have valid data. First move the existing messages to trash
		$this->assertor->assertQuery('vBForum:sentto', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'folderid' => $folders['systemfolders'][vB_Library_Content_Privatemessage::TRASH_FOLDER],
			vB_dB_Query::CONDITIONS_KEY => array('folderid' => $folderid)));
		//Then delete the folder
		$this->assertor->assertQuery('vBForum:messagefolder', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'folderid' => $folderid));

		return true;
	}

	/**
	 * Returns the node content as an associative array
	 *
	 * @param  integer The id in the primary table
	 * @param  array   permissions
	 * @param  bool    appends to the content the channel routeid and title, and starter route and title the as an associative array
	 *
	 * @return int
	 */
	public function getFullContent($nodeid, $permissions = false)
	{
		$results = $this->library->getFullContent($this->library->checkCanSee($nodeid), $permissions);

		if (empty($results))
		{
			throw new vB_Exception_Api('no_permission');
		}
		return $results;
	}

	/**
	 * Gets the title and forward
	 *
	 * @param  mixed will accept an array, but normall a comma-delimited string
	 *
	 * @return mixed array of first (single db record), messages- nodeid=> array(title, recipents(string), to (array of names), pagetext, date)
	 */
	public function getForward($nodeids)
	{
		if (!is_array($nodeids))
		{
			$nodeids = explode(',', $nodeids);
		}

		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		$valid = array();

		foreach ($nodeids as $nodeid)
		{
			$content = $this->nodeApi->getNode($nodeid);
			//if this is the author we can return the value
			if ($content['userid'] == $userid)
			{
				$valid[] = $nodeid;
			}
			else
			{
				//Maybe this is a recipient.
				$recipients = $this->assertor->getRows('vBForum:getPMRecipients', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
					'nodeid' => $nodeid, 'userid' => -1));
				foreach ($recipients as $recipient)
				{
					if ($recipient['userid'] == $userid)
					{
						$valid[] = $nodeid;
						break;
					}
				}
			}
		}

		if (empty($valid))
		{
			throw new vB_Exception_Api('invalid_data');
		}
		//Now build the response.
		$messageInfo = $this->assertor->assertQuery('vBForum:getPrivateMessageForward', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'nodeid' => $valid));

		if (!$messageInfo OR !$messageInfo->valid())
		{
			throw new vB_Exception_Api('invalid_data');
		}
		$results = array();
		$currentNode = false;
		$currentQuote = false;
		$currentAuthors = array();
		//We may have several messages, but normally all will be from one person to the same list.
		foreach ($messageInfo as $message)
		{
			if ($message['messageid'] != $currentNode['messageid'])
			{
				if ($currentNode)
				{
					$results[$currentNode['messageid']] = array('from' => $currentNode['messageauthor'], 'to' => $currentAuthors,
						'recipients' => implode(', ', $currentAuthors),
						'title' => $currentNode['title'],
						'date' => $currentNode['publishdate']);

					if (empty($currentNode['pagetext']))
					{
						$results[$currentNode['messageid']]['pagetext'] = $currentNode['rawtext'];
					}
					else
					{
						$results[$currentNode['messageid']]['pagetext'] = $currentNode['pagetext'];
					}
				}

				$currentNode = $message;
				$currentAuthors = array($message['username']);
			}
			else
			{
				$currentAuthors[] = $message['username'];
			}
		}

		//we'll have a last node that didn't get loaded.
		if ($currentNode)
		{
			$results[$currentNode['messageid']] = array('from' => $currentNode['messageauthor'], 'to' => $currentAuthors,
				'recipients' => implode(', ', $currentAuthors),
				'title' => $currentNode['title'],
				'date' => $currentNode['publishdate']);

			if (empty($currentNode['pagetext']))
			{
				$results[$currentNode['messageid']]['pagetext'] = $currentNode['rawtext'];
			}
			else
			{
				$results[$currentNode['messageid']]['pagetext'] = $currentNode['pagetext'];
			}
		}

		$firstMessage = reset($results);
		return array('first' => $firstMessage, 'messages' => $results);
	}

	/**
	 * Verifies that the request exists and its valid.
	 * Returns the message if no error is found.
	 * Throws vB_Exception_Api if an error is found.
	 *
	 * @param  int   $userid
	 * @param  int   $nodeid
	 *
	 * @return array - message info
	 */
	protected function validateRequest($userid, $nodeid)
	{
		return $this->library->validateRequest($userid, $nodeid);
	}

	/**
	 * Denies a user follow request
	 *
	 * @param  int  the nodeid of the request
	 * @param  int  (optional) the userid to whom the request was sent, if not given,
	 *		will use current logged in user.  If it is not the currently logged in user
	 *		then will return a "no_permission" error.  This may be extended in the future
	 *		to allow admins to denyRequests on behalf of other users.
	 *
	 *	@return	array - array('result' => resultphrase) if resultphrase is empty, there
	 *		is nothing useful to say about what happened
	 */
	public function denyRequest($nodeid, $cancelRequestFor = 0)
	{
		$userid = (int) vB::getCurrentSession()->get('userid');

		//not sure if this should be in the library function
		if (!$userid)
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		if ($cancelRequestFor != 0 AND $cancelRequestFor != $userid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->denyRequest($nodeid, $userid);
	}

	/**
	 * Accepts a user follow request or a channel ownership/moderation/membership request
	 *
	 * @param  int  the nodeid of the request
	 *
	 * @return bool
	 */
	public function acceptRequest($nodeid)
	{
		return $this->library->acceptRequest($nodeid);
	}

	/**
	 * Clears the cached folder information
	 */
	public function resetFolders()
	{
		$this->library->resetFolders();
	}

	/**
	 * Returns a formatted json string appropriate for the search api interface
	 *
	 * @param  string the search query
	 *
	 * @return string the json string
	 */
	public function getSearchJSON($queryText)
	{
		return json_encode(array('keywords' => $queryText,
				/* 'contenttypeid' => vB_Types::instance()->getContentTypeId('vBForum_PrivateMessage' ) */
				'type' => 'vBForum_PrivateMessage'));
	}

	/**
	 * Gets the pending posts folder id
	 *
	 * @return int The pending posts folder id from messagefolder.
	 */
	public function getPendingPostFolderId()
	{
		return $this->library->getPendingPostFolderId();
	}

	/**
	 * Gets the infractions folder id
	 *
	 * @return int The infractions folder id from messagefolder.
	 */
	public function getInfractionFolderId()
	{
		return $this->library->getInfractionFolderId();
	}

	/**
	 * Gets the deleted_items folder id
	 *
	 * @return int The deleted_items folder id from messagefolder.
	 */
	public function getDeletedItemsFolderId()
	{
		return $this->library->getDeletedItemsFolderId();
	}


	/**
	 * Moves a message back to user inbox folder
	 *
	 * @params int  The nodeid we are undeleting.
	 *
	 * @return bool True if succesfully done.
	 */
	public function undeleteMessage($nodeid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$currentUser = vB::getCurrentSession()->get('userid');

		if (!intval($currentUser))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$nodeids = explode(',', $nodeid);

		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		//we can only move a record to which the user has access.
		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'value' => $currentUser),
				array('field' => 'nodeid', 'value' => $nodeids)
			));
		$existing = $this->assertor->getRows('vBForum:sentto', $data);

		if (empty($existing) OR !empty($existing['errors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		return $this->library->undeleteMessage($nodeid, $existing);
	}

	/**
	 * Delete private messages. Once deleted user won't be able to retrieve them again.
	 *
	 * @params mixed Array or comma separated nodeids from messages to delete.
	 *
	 * @return array Whether delete action succeeded or not.
	 *               keys -- success
	 */
	public function deleteMessages($nodeid)
	{
		$nodeids = $nodeid;
		if (is_string($nodeid) AND strpos($nodeid, ',') !== false)
		{
			$nodeids = explode(',', $nodeid);
		}
		else if (!is_array($nodeid))
		{
			$nodeids = array($nodeid);
		}


		foreach ($nodeids as $nodeid)
		{
			if (!$this->deleteMessage($nodeid))
			{
				return array('success' => false);
			}
		}
		return array('success' => true);
	}

	/**
	 * Gets the folder information from a given folderid. The folderid requested should belong to the user who is requesting.
	 *
	 * @param  int   The folderid to fetch information for.
	 *
	 * @return array The folder information such as folder title, titlephrase and if is custom folder.
	 */
	public function getFolderInfoFromId($folderid)
	{
		if (!$this->canUsePmSystem())
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$userid = vB::getCurrentSession()->get('userid');

		$folderid = intval($folderid);
		if (!$folderid)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		// check that the folderid belongs to the user request.
		// @TODO we might want to let admin to fetch any requested folder
		$folders = $this->library->listFolders();
		if (!in_array($folderid, array_keys($folders)))
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $this->library->getFolderFromId($folderid, $userid);
	}

	/**
	 * Returns the cached folder information
	 *
	 * @param  int   Userid we are fetching folders for.
	 *
	 * @return mixed Array containing user folders info.
	 */
	public function fetchFolders($userid)
	{
		$userid = intval($userid);
		if (!$userid)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		return $this->library->fetchFolders($userid);
	}

	/**
	 * Returns an array of all users participating in a discussion
	 *
	 * @param  int   the nodeid of the discussion
	 *
	 * @return array of user information
	 *               * following -- is the participant a follower of the current user (may be NULL)
	 *               * userid -- ID of the participant
	 *               * username -- Name of the participant
	 *               * avatarurl -- Url for the participant's avatar
	 *               * starter -- ID of the starter for $nodeid
	 */
	public function fetchParticipants($nodeid)
	{
		if (!intval($nodeid))
		{
			throw new vB_Exception_Api('invalid_data');
		}
		$currentUser = vB::getCurrentSession()->get('userid');

		//We always should have something in $exclude.
		$exclude = array('-1');

		if (intval($currentUser))
		{
			$options = vB::getDatastore()->get_value('options');
			if (trim($options['globalignore']) != '')
			{
				$exclude = preg_split('#\s+#s', $options['globalignore'], -1, PREG_SPLIT_NO_EMPTY);
			}
		}

		$node = vB_Api::instanceInternal('node')->getNode($nodeid);
		$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
		$valid = $contentLib->validate($node, vB_Library_Content::ACTION_VIEW, $node['nodeid'], array($node['nodeid'] => $node));

		//if the user can't see the node, then don't allow them to see the participants.
		if (!$valid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$nodeCTClass = vB_Types::instance()->getContentTypeClass($node['contenttypeid']);

		switch ($nodeCTClass)
		{
			case self::PARTICIPANTS_PM :
				$queryPart = 'vBForum:getPMRecipientsForMessageOverlay';
				$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $nodeid);
				break;
			case self::PARTICIPANTS_POLL :
				// this seems a bit sketchy. This works (I think) because polls are always the starter due to
				// frontend restrictions, and no current notification will expect anything different when
				// calling this on a poll post, but if we have poll replies, and a notification called this function
				// expecting to get the thread participants, NOT poll voters, this would be a bug...
				$queryPart = 'vBForum:getNotificationPollVoters';
				$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $nodeid);
				break;
			//for a channel we will quietly fail.  Trying to look up the participants is too expensive, is a potential DOS
			//and we don't really need it.
			case self::PARTICIPANTS_CHANNEL :
				return array();
				break;
			default :
				// private messages should've been caught by the first case. At this point, we should only be concerned with content
				// nodes (excluding polls)
				$queryPart = 'vBForum:fetchParticipants';
				$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED, 'nodeid' => $nodeid, 'currentuser' => $currentUser, 'exclude' => $exclude);
				break;
		}

		$members = vB::getDbAssertor()->getRows($queryPart, $params);

		$participants = array();
		foreach ($members AS $member)
		{
			if (isset($participants[$member['userid']]))
			{
				continue;
			}

			$participants[$member['userid']] = $member;
		}

		$userApi = vB_Api::instanceInternal('user');
		foreach ($participants as $uid => $participant)
		{
			$participants[$uid]['avatarurl'] = $userApi->fetchAvatar($uid, true, $participant);
		}

		return $participants;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103410 $
|| #######################################################################
\*=========================================================================*/
