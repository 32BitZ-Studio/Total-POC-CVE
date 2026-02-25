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
 * vB_Library_FCMessaging
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_FCMessaging extends vB_Library
{
	/*
		Firebase Cloud Messaging wrapper functions
		VBV-16928
	 */

	// vB_Db_Assertor instance
	protected $assertor;

	/*
		server key should be set in the options. Admins can get their key from
		the "Cloud Messaging" tab under Firebase console's "Settings" pane.
	 */

	// Authorizes this server for access to Google services.
	// Per google: "Important: Do not include the server key anywhere in your client code."
	// This means mobile apps should not have knowledge of this key.
	protected $serverKey;

	// String disabled reason
	protected $failureReason = "";

	// vB_Library_Worker instance. Used to spawn a child thread to offload
	//	FCM requests from the initial request.
	protected $worker;

	// String    Google endpoint
	protected $fcm_url = 'https://fcm.googleapis.com/fcm/send';

	const MESSAGE_TYPE_PRIVATEMESSAGE   = "privatemessage";
	const MESSAGE_TYPE_NOTIFICATION     = "notification";

	const CLICK_ACTION_PRIVATEMESSAGE   = "SHOW_PM_ACTION";
	const CLICK_ACTION_THREAD           = "SHOW_THREAD_ACTION";
	const CLICK_ACTION_POST             = "SHOW_POST_ACTION";
	const CLICK_ACTION_COMMENT          = "SHOW_COMMENT_ACTION";
	const CLICK_ACTION_VISITORMESSAGE   = "SHOW_VISITOR_MESSAGES_ACTION";
	//const CLICK_ACTION_NOTIFICATION     = "NOT_IMPLEMENTED";


	const ERROR_TYPE_SETTING = "SETTING";
	const ERROR_TYPE_GENERIC = "GENERIC";

	/**
	 * Constructor
	 *
	 */
	protected function __construct()
	{
		$options = vB::getDatastore()->getValue('options');

		if (!empty($options['fcm_serverkey']))
		{
			// todo: trim & or other cleaning?
			$this->serverKey = $options['fcm_serverkey'];
		}

		if (!empty($options['fcm_enabled']))
		{
			$this->fcmEnabled = (bool) $options['fcm_enabled'];
		}

		$this->assertor = vB::getDbAssertor();
		$this->worker = vB_Library::instance("worker");




		return $this->enabled();
	}

	public function testServerKey()
	{
		/*
			THIS FUNCTION EXPLICITLY IGNORES ENABLED OPTION!
			This is meant to be called via admincp/fcm.php only.
		 */
		if (empty($this->serverKey))
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_missing_serverkey"
				),
			);
		}


		$postData = array(
			// https://firebase.google.com/docs/cloud-messaging/http-server-ref#table1
			// test a request without sending message.
			'dry_run' => true,
			'to' => "test_dry_run_topic",
		);

		$skipPostProcess = true;
		$result = $this->postToFCMServer($postData, $skipPostProcess);

		$result = reset($result);

		// Timeout.
		if (empty($result))
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_timed_out"
				),
			);
		}

		$statusCode = $result['headers']['http-response']['statuscode'];
		if ($statusCode == 401)
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_invalid_server_key"
				),
			);
		}
		else if ($statusCode >= 500 AND $statusCode <= 599)
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_server_issue"
				),
			);
		}

		return array(
			'result' => $statusCode,
			'errors' => array(
			),
		);
	}

	public function testSendMessage($registration_ids)
	{
		/*
			THIS FUNCTION EXPLICITLY IGNORES ENABLED OPTION!
			This is meant to be called via admincp/fcm.php only.
		 */
		if (empty($this->serverKey))
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_missing_serverkey"
				),
			);
		}
		if (empty($registration_ids))
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_missing_recipients"
				),
			);
		}


		$postData = array(
			'registration_ids' => $registration_ids,
			'notification' => array(
				'title' => "Firebase Cloud Messaging",
				'body' => "Firebase Cloud Messaging is functional.",
				'click_action' => "FCM_TEST_IGNORE",
			),
		);

		$skipPostProcess = true;
		$result = $this->postToFCMServer($postData, $skipPostProcess);

		$result = reset($result);

		// Timeout.
		if (empty($result))
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_timed_out"
				),
			);
		}

		$statusCode = $result['headers']['http-response']['statuscode'];
		if ($statusCode == 401)
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_invalid_server_key"
				),
			);
		}
		else if ($statusCode >= 500 AND $statusCode <= 599)
		{
			return array(
				'result' => null,
				'errors' => array(
					"fcm_error_server_issue"
				),
			);
		}

		$body = json_decode($result['body'], true);

		$errorCodes = array();
		$success = 0;
		$total = 0;
		foreach ($body['results'] AS $__check)
		{
			if (isset($__check['error']))
			{
				$errorCodes[] = $__check['error'];
			}
			else
			{
				$success++;
			}
			$total++;
		}

		return array(
			'result' => $statusCode,
			'success' => $success,
			'total' => $total,
			'errors' => array(),
			'errorCodes' => $errorCodes,
		);
	}

	public function sendMessageFromCron($messageid, $clientIds = array())
	{
		if (!$this->enabled())
		{
			return array(
				'note' => "disabled",
			);
		}

		// Check lastactivity. Note, if $clientIds is empty, then this is probably a
		// "to" message going out to a topic subscription, so we have nothing to check here.
		$registration_ids = array();
		// 604800 = 7 days in seconds
		$cutofftime = (vB::getRequest()->getTimeNow() - 604800);
		if (!empty($clientIds))
		{
			$apiclients = $this->assertor->assertQuery('vBForum:getLastActivityAndDeviceTokens', array('clientids' => $clientIds));
			foreach ($apiclients AS $__row)
			{
				if ($__row['lastactivity'] >= $cutofftime)
				{
					$registration_ids[] = $__row['devicetoken'];
				}
			}
		}

		// Grab the message data.
		$message = $this->assertor->getRow('vBForum:fcmessage', array('messageid' => $messageid));
		if (!empty($message['message_data']))
		{
			$postData = json_decode($message['message_data'], true);
			if (!empty($registration_ids))
			{
				$postData['registration_ids'] = $registration_ids;
			}

			try
			{
				$result = $this->postToFCMServer($postData);
			}
			catch (Exception $e)
			{
				// In actual use, this is probably not going to be hit often. In testing, the single case
				// I saw was when the recipients' lastactivity hadn't been updated in a while, so it
				// tried to send to empty recipients & errored out

				// todo: log this?
				/*
				error_log(
						__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
						. "\n" . "e: " . print_r($e, true)
				);
				*/
			}
		}

		// Any messages re-registered in the queue will have status = 'ready'.
		// Get rid of everything else, and assume they were either processed OK,
		// or invalid due to client being inactive.
		$this->assertor->delete('vBForum:fcmessage_queue',
			array(
				'status' => 'processing',
				'messageid' => $messageid,
				'recipient_apiclientid' => $clientIds
			)
		);
	}

	public function sendMessages($messageHashes)
	{
		if (!is_array($messageHashes))
		{
			$messageHashes = array($messageHashes);
		}

		$strHashes = array();
		foreach ($messageHashes AS $__hash)
		{
			$strHashes[] = strval($__hash);
		}

		return $this->offloadTasks($strHashes);
	}

	/*
	 * Convert title & body to UTF-8 for JSON and unescape any HTML entities
	 *
	 * @param string    $title
	 * @param string    $body
	 *
	 * @return array(string title, string body)
	 * @access private
	 */
	private function prepareTitleAndBodyForFCM($title, $body)
	{
		/*
			Some notes on truncating message title & bodies :

			"
			Maximum payload for both [notification & data] message types is 4KB,
			except when sending messages from the Firebase console, which
			enforces a 1024 character limit.
			"
			https://firebase.google.com/docs/cloud-messaging/concept-options#notifications_and_data_messages

			In UTF-8, a character 1-4 bytes, so in the worst case this is 1024
			characters even though we're not sending these via the console. This
			is the absolute max for the entire payload sent to Firebase.
			This is different from the display limits of the recipient devices,
			which is likely much smaller, and depends heavily on the device model
			& os.

			Some best practices articles suggest ballparks of
			Some best practices:

			https://help.pushwoosh.com/hc/en-us/articles/360000440366-The-limit-of-characters-that-can-be-sent-through-a-push-notification
			https://blog.pushowl.com/push-notification-best-practices-the-ideal-length-2019/


			Using the notifications composer in firebase console
			(https://console.firebase.google.com/project/_/notification) and
			looking at their "device preview", it seems like <50 characters
			is likely best for the unexpanded/collapsed "initial state" view
			to not ellipsize (...) the title and body. The body can be a bit
			longer (~60 characters + "hero image"?) as it seems the android
			& iOS UI will show more of the body when the notification is
			expanded. Note that having the title & body be automatically
			ellipsized by the notification tray is not necessarily a bad
			thing for our purposes, since these notifications are meant to
			be gateways to the full posts.

			In any case, changing the truncation limit(s) is out of scope
			for the current issue (VBV-19731), so I will stay with the
			previous limit of 200 characters at this time.
		 */
		$titleLimit = 200;
		$bodyLimit = 200;

		$stringUtil = vB::getString();
		$currentlyUTF8 = $stringUtil->isDefaultCharset("utf-8");

		/*
			XSS warning:
			Android notification tray does not seem to parse HTML entities.
			So I'm seeing  &amp;&lt;  instead of  &<  . This applies to
			usernames, PM titles, & PM body.
			I don't know if XSS in notifications is possible for android/iOS
			but I've warned mobile team know that the FCM payload will contain
			raw HTML instead of escaped entities.

			Additional note: per issue VBV-19731, we need to also convert the MB characters
			that were converted to html entities for non-utf8 boards. However, to avoid
			double encoding, we must first convert the rest of the text to UTF-8, since
			unHtmlSpecialChars($text, $doUniCode=true) will convert the entities into
			UTF-8 (because multibyte).

			MESSAGE_TYPE_NOTIFICATION Notes:
			Todo: we may want to offload the unescaping to the vB_Notification_X class as well,
			in case we legitimately need escaped HTML for something.
			The unescaping is mostly required for usernames, which may be in the title or body
			depending on the vB_Notification type.
		 */

		// Convert to UTF-8 for JSON
		if (!$currentlyUTF8)
		{
			$title = $stringUtil->toUtf8($title);
			$body = $stringUtil->toUtf8($body);
		}

		// Convert entities, escaped multibyte characters back to characters that mobile devices can show.
		$title = vB_String::unHtmlSpecialChars($title, true);
		$body = vB_String::unHtmlSpecialChars($body, true);

		// Truncate.
		$title = $stringUtil->substr($title, 0, $titleLimit, 'UTF-8');
		$body =  $stringUtil->substr($body, 0, $bodyLimit, 'UTF-8');

		return array(
			$title,
			$body,
		);
	}

	public function queueMessage($recipientIds, $messageType, $extra = array())
	{
		if (!$this->enabled())
		{
			return array(
				'error' => "disabled",
			);
		}

		if (is_numeric($recipientIds))
		{
			$recipientIds = array($recipientIds);
		}


		$postData = array();
		switch($messageType)
		{
			case self::MESSAGE_TYPE_PRIVATEMESSAGE:
				/*
					'title' => $starter['title'],
					'rawtext' => $thisNode['rawtext'],
					'username' => $thisNode['authorname'],
				 */
				// node.title has a column limit of varchar(512).
				// todo: fetchCensoredText() on username or title??
				$title = $extra['title'];
				// get rid of bbcode. In particular, stuff like [font][color] etc.
				$body = vB_String::stripBbcode($extra['rawtext']);
				/*
					Note 1) getPreviewText() puts the text through htmlSpecialCharsUni().
					This will be undone in prepareTitleAndBodyForFCM().
					Note 2) if getPreviewText() is called with the html entities intact
					(e.g. non utf-8 boards with multibyte characters,) the character count
					can be a LOT less than it's supposed to be. Even if we unescape first
					before sending it to getPreviewText() (after which we'd have to unescape
					again due to it calling htmlSpecialChars..), since its truncation is
					based on byte length & multibyte-unfriendly, the character count will
					still be shorter than expected for multibyte characters.
				 */
				$limit = 200;
				$body = $extra['username'] . ': ' . vB_String::getPreviewText($body, $limit);

				// Convert to UTF-8, unescape HTML entities.
				list($title, $body) = $this->prepareTitleAndBodyForFCM($title, $body);

				$postData = array(
					//'registration_ids' => $registration_ids,
					'notification' => array(
						'click_action' => self::CLICK_ACTION_PRIVATEMESSAGE,
						'title' => $title,
						'body' => $body,
					),
					'data' => array(
						'INTENT_EXTRA_PM_ID' => intval($extra['nodeid']),
					),
				);
				break;
			case self::MESSAGE_TYPE_NOTIFICATION:
				foreach (array('title', 'body', 'click_action') AS $__required)
				{
					if (empty($extra[$__required]))
					{
						return array(
							'error' => "missing \$extra[" . $__required . "]",
						);
					}
				}

				// Convert to UTF-8, unescape HTML entities.
				list($title, $body) = $this->prepareTitleAndBodyForFCM($extra['title'], $extra['body']);

				$postData = array(
					//'registration_ids' => $registration_ids,
					'notification' => array(
						'click_action' => self::CLICK_ACTION_THREAD,
						'title' => $title,
						'body' => $body,
					),
				);
				if (!empty($extra['click_action']))
				{
					$postData['notification']['click_action'] = $extra['click_action'];
				}
				if (!empty($extra['data']))
				{
					$postData['data'] = $extra['data'];
				}
				break;
			default:
				return array(
					'error' => "unknown_message_type",
				);
				break;
		}

		if (empty($postData))
		{
			return array(
				'error' => "unknown_message_type",
			);
		}

		$messageid = $this->getMessageId($postData);
		if (empty($messageid))
		{
			// something went wrong, and we can't recover.
			return array(
				'error' => "failed_to_generate_messageid",
			);
		}


		// Save recipients.
		$recipientIdsJson = json_encode($recipientIds);
		$messageDataJson = json_encode($postData);
		$hash = md5($recipientIdsJson . $messageDataJson);
		$timeNow = vB::getRequest()->getTimeNow();
		// it really should NOT take more than a few minutes to process this, so 1 hour is being generous
		$removeAfter = $timeNow + 3600;

		/*
			Add to the offload queue so the child thread has enough
			data to handle the request. Also remove any old records
			from the queue - if there are any, the request probably
			died off before it could finish handling it and we'll
			never get the notifications out then.
		 */
		$this->assertor->assertQuery(
			'vBForum:updateFCMOffload',
			array(
				'recipientids'  => $recipientIdsJson,
				'message_data'  => $messageDataJson,
				'hash'          => $hash,
				'removeafter'   => $removeAfter,
			)
		);
		$this->assertor->delete(
			'vBForum:fcmessage_offload',
			array(
				array('field' => 'removeafter', 'value' => $timeNow, 'operator' => vB_dB_Query::OPERATOR_LT)
			)
		);

		return array('hash' => $hash);
	}

	public function handleOffloadedTask($messageHashes)
	{
		if (!is_array($messageHashes))
		{
			$messageHashes = array($messageHashes);
		}

		$strHashes = array();
		foreach ($messageHashes AS $__hash)
		{
			$strHashes[] = strval($__hash);
		}

		if (empty($strHashes))
		{
			return;
		}

		$messages = $this->assertor->getRows('vBForum:fcmessage_offload', array('hash' => $strHashes));
		$this->assertor->delete('vBForum:fcmessage_offload',array('hash' => $strHashes));

		if (empty($messages))
		{
			return;
		}

		$results = array();
		foreach ($messages as $__message)
		{
			$__recipientIds = json_decode($__message['recipientids'], true);
			$__messageData = json_decode($__message['message_data'], true);

			$__tokenGroupsByUserid = $this->convertUseridsToDeviceTokens($__recipientIds);
			$__registrationIds = array();
			foreach ($__tokenGroupsByUserid AS $__userid => $__appClientIdToTokens)
			{
				foreach ($__appClientIdToTokens AS $__id => $__token)
				{
					$__registrationIds[] = $__token;
				}
			}

			if (empty($__registrationIds) OR empty($__messageData))
			{
				$results[] = array(
					'error' => 'empty_recipients_or_data',
					'message' => $__message,
				);
				continue;
			}

			$__messageData['registration_ids'] = $__registrationIds;

			try
			{
				$result = $this->postToFCMServer($__messageData);
			}
			catch (Exception $e)
			{
				// In actual use, this is probably not going to be hit often. In testing, the single case
				// I saw was when the recipients' lastactivity hadn't been updated in a while, so it
				// tried to send to empty recipients & errored out

				$result = array(
					'error' => "exception",
					'exception_message' => $e->getMessage(),
				);
			}

			$results[] = $result;

		}

		return array(
			'results' => $results,
		);
	}

	private function offloadTasks($hashes)
	{
		if (!$this->enabled())
		{
			return array(
				'note' => "disabled",
			);
		}

		if (!is_array($hashes) OR empty($hashes))
		{
			return array(
				'note' => "no_tasks",
			);
		}

		$postData = array(
			'securitytoken' => 'guest',
			'hashes' => $hashes,
		);
		$result = $this->worker->callWorker("send-fcm", $postData);

		return $result;
	}

	private function postToFCMServer($postData, $skipResultProcessing = false)
	{
		// https://firebase.google.com/docs/cloud-messaging/server#auth
		$httpHeaders = array(
			'Authorization: key=' . $this->serverKey,
			'Content-Type: application/json',
		);

		// We're sending json here.
		if (is_array($postData))
		{
			// All good here.
		}
		else if (is_string($postData))
		{
			$postData = json_decode($postData, true);
			if (json_last_error() != JSON_ERROR_NONE)
			{
				throw new Exception("\$postData must be Array or JSON only. Instead, received an undecodeable string" );
			}
		}
		else
		{
			throw new Exception("\$postData must be Array or JSON string only. Instead, received a(n) " . gettype($postData) );
		}


		// Check for any required data.
		if (empty($postData['to']) AND empty($postData['registration_ids']))
		{
			throw new Exception("\$postData missing required 'to' (or 'registration_ids') parameter");
		}

		if (!empty($postData['registration_ids']) AND !is_array($postData['registration_ids']))
		{
			throw new Exception("'registration_ids' must be an Array of strings");
		}

		// For single recipients, we can use "to". For multiple, we should use "registration_ids".
		// However, we should NOT use both as that's ambiguous for response processing and the expected
		// behavior is not defined.
		if (!empty($postData['to']) AND !empty($postData['registration_ids']))
		{
			throw new Exception("\$postData must not have both 'to' or 'registration_ids' parameters for recipient(s).");
		}

		if (!empty($postData['registration_ids']) AND count($postData['registration_ids']) > 1000)
		{
			throw new Exception("'registration_ids' must contain at least 1 and at most 1000 tokens.");
		}

		if (empty($postData['notification']) AND empty($postData['data']))
		{
			if (empty($postData['dry_run']))
			{
				throw new Exception("\$postData missing required 'notification' or 'data' payload. Empty notifications are only allowed for tests ('dry_run' = true).");
			}
		}
		/*
			For notification array, strongly recommend setting a "title" for when the app is in the background & notification
			is displayed on the system tray. I think you can set the default notification icon via AndroidManifest, but
			not certain about default title. It seems the title in the tray will default to "Firebase Cloud Messaging" if
			it's not set.
		 */



		if (empty($postData))
		{
			throw new Exception("Payload \$postData must not be empty." );
		}
		$jsonPostData = json_encode($postData);

		/*
			We could possibly check for any recipients already in retry period & filter them
			out here.
			However, if this got called on the same message with the same recipient, it's either
			a cron picking up a retry, or a technically new message (even though the content is
			the same) that was trigger off of a new forum content.

			If we do the check & filter out any recipients in waiting, that could mean worse user
			experience as some temporary issue earlier could delay "new" messages for a few minutes.

			If we do not filter, and the usage pattern is such that google deems it spammy, they
			could blacklist the project or server (both tied to the specific forum).

			I'm leaving out the check for now, as this seems like something we need to see in action
			in the wild before adding anything to it.

			"
			Check that the total size of the payload data included in a message does not exceed
			FCM limits: 4096 bytes for most messages, or 2048 bytes in the case of messages to
			topics or notification messages on iOS. This includes both the keys and the values.
			"
			- https://firebase.google.com/docs/cloud-messaging/http-server-ref

			Testing reveals that the "registration_ids" field is not counted towards the size.
			Since we cannot reduce the payload size other than batching the recipients, and since
			some parts of the payload ("registration_ids", probably "to" as well & possibly other
			fields) we no longer check the length of jsonPostData. If the message is too long, FCM
			server will return an error, which will be ignored by processRequestResponse() since
			queueing it up for a cron to just fail again won't help anyone.
		 */

		$vurl = vB::getUrlLoader();

		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HTTPHEADER, $httpHeaders);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$vurl->setOption(vB_Utility_Url::TIMEOUT, 5);
		$result = $vurl->post($this->fcm_url, $jsonPostData);

		/*
		error_log(
				__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
				. "\n" . "httpHeaders: " . print_r($httpHeaders, true)
				. "\n" . "postData: " . print_r($postData, true)
				. "\n" . "result: " . print_r($result, true)
		);
		*/

		// Do not register retries ETC for a test.
		if (empty($postData['dry_run']) AND !$skipResultProcessing)
		{
			$this->processRequestResponse($result, $postData);
		}

		// Put the single-call result into an array to make the return format match
		// the recursive/batched result.
		return array($result);
	}

	public function logError($message, $data, $errorType = self::ERROR_TYPE_GENERIC)
	{
		/*
			This doesn't do anything ATM.
			We may want to log certain errors to DB so the admin can later take a look at the issues.
		 */

		error_log(
			__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
			. "\n" . "message: " . print_r($message, true)
			. "\n" . "data: " . print_r($data, true)
			. "\n" . "errorType: " . print_r($errorType, true)
		);
	}

	private function getMessageId($postData, $readOnly = false)
	{
		// The recipient is not part of the "fcmessage" identity. A single message could have
		// multiple recipients, or can even be reused in the future.
		// There will likely be very few distinct messages, but different recipients & send times.
		unset($postData['registration_ids']);
		// However, let's allow "to" to be part of the identity, as the "to" field may *not* be a recipient token
		// but a topic instead, which won't correspond to any API clients on our side (the topic will likely be
		// something requiring setting up on the FCM project that we currently do not have any plans of using).
		//unset($postData['to']);

		/*
			VBV-17420
			When we implement badge counts, we will want to remove it from the message identity as it has to
			be re-calculated each time, since it likely changed for each recipient.

			unset($postData['notification']['badge'], $postData['data']['badge_count']);
		 */

		$jsonPostData = json_encode($postData);
		$message_hash = md5($jsonPostData);

		// Check if it exists.
		$messageid = $this->assertor->getRow('vBForum:fcmessage', array('message_hash' => $message_hash));
		if (!empty($messageid['messageid']))
		{
			return $messageid['messageid'];
		}

		// If we're here, this messageid doesn't exist yet, so we have to create one.
		// Avoid creating one unless absolutely necessary (e.g. may not need it in
		// unregisterRetry())
		if ($readOnly)
		{
			return false;
		}

		$messageid = $this->assertor->insertIgnore(
			'vBForum:fcmessage',
			array(
				'message_data'  => $jsonPostData,
				'message_hash'  => $message_hash,
			)
		);
		// inexplicably vB_Db_Query_InsertIgnore::doInserts() returns an array
		// instead of just the {int id}|false that we expect from vB_Db_Query_Insert::doInserts()
		if (is_array($messageid))
		{
			$messageid = reset($messageid);
		}

		if (empty($messageid))
		{
			// We didn't find an existing one, and we couldn't insert a new one either.
			// At this point, we may have a DB connection error or some other unrecoverable
			// failure.
			return null;
		}

		return $messageid;
	}

	private function getNextRetryInterval($nth_attempt, $retry_after_delta_seconds = null)
	{
		/*
			The FCM server could not process the request in time. You should retry the same request, but you must:
				Honor the Retry-After header if it is included in the response from the FCM Connection Server.
				Implement exponential back-off in your retry mechanism. For example, if you waited one second before the first retry, wait at least two seconds before the next one, then four seconds, and so on. If you're sending multiple messages, delay each one independently by an additional random amount to avoid issuing a new request for all messages at the same time.
			Senders that cause problems risk being blacklisted.
		 */
		// Google's specs require we implement exponential back-off.
		// They don't provide any hard numbers, so these values are rather arbitrary.

		// Let's wait 15s, then 30s, then 60, and so on
		$default_wait_time = 15;
		$max_wait_time = 120; //  No longer than 2 minutes between retries.

		// Stop and give up after 20 retries.
		$max_retries = 20;

		// todo: suffer amnesia and ignore max retries if retry_after_delta_seconds is provided?
		if ($nth_attempt > $max_retries)
		{
			return null;
		}

		if ($nth_attempt < 0)
		{
			$nth_attempt = 0;
		}

		// We probably won't need this since we don't have true crons to send retries
		// at the precisely requested time, but apparently some noise is required to
		// prevent multiple failure-retries syncing up & flooding the google server
		// when service is restored after an outage.
		// Since the cron wait time is likely to be much larger (minutes vs.
		$fuzz = 0.5;

		if (empty($retry_after_delta_seconds))
		{
			return ceil(pow(2, $nth_attempt) * $default_wait_time * rand(1 - $fuzz, 1 + $fuzz));
		}
		else
		{
			// Let's also add some random extra wait time for retry-after.
			return ceil($retry_after_delta_seconds + $default_wait_time * rand(1, 1 + $fuzz));
		}
	}

	private function processRequestResponse($response, $postData)
	{
		/*
			Some basic references:

			https://developers.google.com/cloud-messaging/http#response
		 */
		$registration_ids = array();
		if (!empty($postData['to']))
		{
			$registration_ids[] = $postData['to'];
		}
		else if (!empty($postData['registration_ids']))
		{
			$registration_ids = $postData['registration_ids'];
		}
		else
		{
			// this shouldn't happen, but if it does then the caller likely screwed up, or
			// something else entirely. In any case we can't handle this here.
		}


		if (empty($response))
		{
			// If response is empty, it could mean either the request timed out (timeout set to 5s)
			// or some unknown failure we don't know how to handle.
			// For this, handle it as a "retry".
			$statusCode = 500;
			$body = null;
			$this->logError(
				"No response from FCM server within timeout period of 5s. Registering retry.",
				array(
					"postData" => $postData,
				)
			);
		}
		else
		{
			$statusCode = $response['headers']['http-response']['statuscode'];
			$body = json_decode($response['body'], true);
			if (empty($body))
			{
				// sometimes with errors, the body might not be a full json
				// Just grab the raw body so we can at least show it.
				$body = $response['body'];
			}
		}

		switch($statusCode)
		{
			case 200:
				$this->handleNormalResponse($registration_ids, $postData, $response, $body);
				break;
			case 400:
				// JSON payload was borked (or missing required data)
				break;
			case 401:
				// Auth failed
				// Tell admin to check their server key.
				break;
			default:
				if ($statusCode >= 500 AND $statusCode <= 599)
				{
					$this->registerRetry($registration_ids, $postData, $response);
				}
				else
				{
					// this wasn't specified, so we don't know what to do here.
					// maybe connection error between forum server & google endpoint?
					// Tell Admin to double check their server
				}
				break;
		}
	}

	private function handleNormalResponse($registration_ids, $postData, $response, $body)
	{
		if (!is_array($body))
		{
			// This indicates that the json_decode failed, or some other reason.
			// This isn't known to be possible, and is undefined behavior.
			// Do nothing and return.
			// In case of cron retries, the queue items will have status = 'processing',
			// and since we're not setting them now, they'll be removed and will not be
			// resent.

			// todo: Log this error?

			return;
		}

		/*
			We need to go through the body and process each recipient-result.
			Note that this does NOT mean that we have knowledge of each device's receipt of the message!
		 */
		$unregisterRetriesForTokens = array();
		$registerRetriesForTokens = array();
		$removeTokens = array();
		if ($body['failure'] == 0 AND $body['canonical_ids'] == 0)
		{
			// We don't have to process their response in this case.
			// Just remove any retries that might've triggered this
			// since we were able to send the message to the client.
			$unregisterRetriesForTokens = $registration_ids;
		}
		else
		{
			$results = $body['results'];
			if (count($registration_ids) != count($results))
			{
				// something unexpected happened, we do not know how to handle this.
				$this->logError(
					"Unexpected response from FCM server. # of registration_ids does not match # of results",
					array(
						"registration_ids" => $registration_ids,
						"results" => $result,
						"postData" => $postData,
					)
				);
			}
			else
			{
				$remove_tokens = array();
				// According to specs the numerical index will match up between registration_ids & results.
				foreach ($results AS $__ind => $__result)
				{
					$__token = $registration_ids[$__ind];
					/*
						https://firebase.google.com/docs/cloud-messaging/http-server-ref#table9
					 */
					if (isset($__result['error']))
					{
						switch($__result['error'])
						{
							case "MissingRegistration":
								// We shouldn't ever hit this *after* we send the request,
								// because we check for to|registration_ids in the actual
								// POST handler
								$this->logError(
									"Error:MissingRegistration",
									array(
										"postData" => $postData,
										"response" => $response,
										"token" => $__token,
									)
								);
								break;
							case "InvalidRegistration":
								// Token was incorrect or not in the expected format.
								// AFAIK this usually happens if token gets corrupted/truncated, or when testing.
								$this->logError(
									"Error:InvalidRegistration",
									array(
										"postData" => $postData,
										"response" => $response,
										"token" => $__token,
										"note" => "Token Removed",
									)
								);
								// Let's go ahead and just remove it because there's nothing we can do about this
								// broken token.
								$removeTokens[] = $__token;
								$unregisterRetriesForTokens[] = $__token;
								break;
							case "NotRegistered":
								/*
									One of the following happened:
										App unregistered with FCM
										User uninstalled the app triggering automatic unregistration
										Registration token expired
										App isn't configured to receive messages (e.g. after an app update)
									Per Google, we should remove this token & stop using it.
								*/
								$removeTokens[] = $__token;
								$unregisterRetriesForTokens[] = $__token;
								break;
							case "Unavailable":
								$registerRetriesForTokens[] = $__token;
								break;
							case "InvalidPackageName":
							case "MismatchSenderId":
							case "MessageTooBig":
							case "InvalidDataKey":
							case "InvalidTtl":
								$this->logError(
									"Error:" . $__result['error'],
									array(
										"postData" => $postData,
										"response" => $response,
										"token" => $__token,
									)
								);
								// Not handled ATM.
							default:
								// Unknown/unhandled error.
								// todo: log this error?
								break;
						}
					}
					else
					{
						$unregisterRetriesForTokens[] = $__token;
					}

					// Update outdated token if specified.
					if (isset($__result['registration_id']))
					{
						$this->assertor->update(
							'vBForum:apiclient_devicetoken',
							array( // value
								'devicetoken' => $__result['registration_id'],
							),
							array( // condition
								'devicetoken' => $__token,
							)
						);
					}
				}
			}
		}


		$this->assertor->delete('vBForum:apiclient_devicetoken', array('devicetoken' => $removeTokens));
		$this->registerRetry($registerRetriesForTokens, $postData, $response);
		$this->unregisterRetry($unregisterRetriesForTokens, $postData);

	}

	private function unregisterRetry($registration_ids, $postData)
	{
		if (empty($registration_ids))
		{
			return;
		}

		$readOnly = true;
		$messageid = $this->getMessageId($postData, $readOnly);
		if (empty($messageid))
		{
			// Since we didn't find a messageid, there should be NO
			// existing retries in the queue.
			return;
		}

		$apiClientIds = array();
		$apiClientIdsQuery = $this->assertor->assertQuery(
			'vBForum:apiclient_devicetoken',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('apiclientid'),
				'devicetoken' => $registration_ids,
			)
		);
		foreach ($apiClientIdsQuery AS $__row)
		{
			$apiClientIds[] = $__row['apiclientid'];
		}

		$this->assertor->delete(
			'vBForum:fcmessage_queue',
			array(
				'recipient_apiclientid' => $apiClientIds,
				'messageid' => $messageid,
			)
		);
	}

	private function registerRetry($registration_ids, $postData, $response = array())
	{
		/*
			The server couldn't process the request in time. Retry the same request, but you must:
			Honor the Retry-After header if it is included in the response from the FCM Connection Server.
			Implement exponential back-off in your retry mechanism. (e.g. if you waited one second before the first retry, wait at least two second before the next one, then 4 seconds and so on). If you're sending multiple messages, delay each one independently by an additional random amount to avoid issuing a new request for all messages at the same time.
			Senders that cause problems risk being blacklisted.
		 */

		if (empty($registration_ids))
		{
			return;
		}

		$messageid = $this->getMessageId($postData);
		if (empty($messageid))
		{
			// something went wrong and we can't recover from it.
			$this->logError(
				"Failed to register FCMessage to queue because we could not generate the messageid for queue",
				array(
					"postData" => $postData,
				)
			);
			return;
		}

		$timeNow = vB::getRequest()->getTimeNow();

		$tokenToApiClientId = array();
		$apiClientIdsAndTokens = $this->assertor->assertQuery('vBForum:apiclient_devicetoken', array('devicetoken' => $registration_ids));
		foreach ($apiClientIdsAndTokens AS $__row)
		{
			$tokenToApiClientId[$__row['devicetoken']] = $__row['apiclientid'];
		}


		$alreadyInTransaction = $this->assertor->inTransaction();
		if (!$alreadyInTransaction)
		{
			$this->assertor->beginTransaction();
		}

		/*
			The FCM server could not process the request in time. You should retry the same request, but you must:
				Honor the Retry-After header if it is included in the response from the FCM Connection Server.
				Implement exponential back-off in your retry mechanism. For example, if you waited one second before the first retry, wait at least two seconds before the next one, then four seconds, and so on. If you're sending multiple messages, delay each one independently by an additional random amount to avoid issuing a new request for all messages at the same time.
			Senders that cause problems risk being blacklisted.
		 */
		$retryAfterHeader = 0;
		$retryAfterHeaderTimestamp = 0;
		/*
			If it's in "delta-seconds", that's what getNextRetryInterval expects.
			If it's in HTTP-date string, we need to convert it to delta-seconds
		 */
		if (!empty($response['headers']['retry-after']))
		{
			$retryAfterHeader = trim($response['headers']['retry-after']);
			if (!is_numeric($retryAfterHeader))
			{
				// https://tools.ietf.org/html/rfc2616#section-3.3
				// In case they use the 3rd format and skip explicitly setting TZ to GMT,
				// temporarily set TZ to UTC...
				$prevTZ = date_default_timezone_get();
				date_default_timezone_set("UTC");

				$retryAfterHeader = strtotime($retryAfterHeader);

				// ... then restore timezone back to whatever it was.
				date_default_timezone_set($prevTZ);

				// Convert timestamp to delta-seconds
				$retryAfterHeader = $retryAfterHeader - $timeNow;
			}
			// I don't know if they would ever return a retry-after
			// in the past, but just in case.
			$retryAfterHeader = max(0, $retryAfterHeader);
		}

		if (!empty($retryAfterHeader))
		{
			$retryAfterHeaderTimestamp = $timeNow + $retryAfterHeader;
		}




		foreach ($registration_ids AS $__id)
		{
			/*
				If we have a $postData['to'] set, it might be a "topic" message, and we won't have a apiclientid associated with it.
				So the "to" will become part of the message identity, and the recipient_apiclientid will be 0.
				However, if we don't have a "to" set, and we failed to fetch an apiclientid, skip it, because we have no idea what
				that is.
				It might be a removed device token, which could happen if multiple threads are processing the queue...
			 */
			$__apiclientid = 0;
			if (isset($tokenToApiClientId[$__id]))
			{
				$__apiclientid  = $tokenToApiClientId[$__id];
			}
			else
			{
				if (!isset($postData['to']))
				{
					// skip processing this one.
					continue;
				}
			}

			// Check if we have a previous queue item.
			$__check = $this->assertor->getRow('vBForum:fcmessage_queue',
				array(
					'recipient_apiclientid' => $__apiclientid,
					'messageid' => $messageid,
				)
			);
			if (empty($__check))
			{
				// First try.
				$__retryafter = $timeNow + $this->getNextRetryInterval(0, $retryAfterHeader);
				$this->assertor->insertIgnore(
					'vBForum:fcmessage_queue',
					array(
						'recipient_apiclientid' => $__apiclientid,
						'messageid'             => $messageid,
						'retryafter'            => $__retryafter,
						'retryafterheader'      => $retryAfterHeaderTimestamp,
						'retries'               => 0,
						'status'                => "ready",
					)
				);
			}
			else
			{
				$__check['retries']++;
				// $timeNow will always be >= $__check['retryafter'] if the cron pick-up logic is correct.
				$__retryafter = $timeNow + $this->getNextRetryInterval($__check['retries'], $retryAfterHeader);
				$this->assertor->update(
					'vBForum:fcmessage_queue',
					array( // value
						'retryafter'            => $__retryafter,
						'retryafterheader'      => $retryAfterHeaderTimestamp,
						'retries'               => $__check['retries'],
						'status'                => "ready",
					),
					array( // condition
						'recipient_apiclientid' => $__apiclientid,
						'messageid'             => $messageid,
					)
				);
			}
		}

		if (!$alreadyInTransaction)
		{
			$this->assertor->commitTransaction();
		}
	}

	public function enabled()
	{
		if (empty($this->fcmEnabled))
		{
			$this->failureReason = "FCM is disabled by Admin";
			return false;
		}

		if (empty($this->serverKey))
		{
			$this->failureReason = "FCM is not configured";
			return false;
		}
		// todo: any other checks here?


		return true;
	}

	/*
	 * This function inserts or updates the device token for the current
	 * api client.
	 *
	 * @return null
	 */
	public function updateDeviceToken($deviceToken)
	{
		if (strlen($deviceToken) > 191)
		{
			throw new Exception("apiclient_devicetoken table does not allow device tokens greater than 191 characters");
		}

		// Note, if you want to unset the token, you want to call removeDeviceToken() instead.
		if (empty($deviceToken))
		{
			return;
		}

		$currentSession = vB::getCurrentSession();
		$currentUser = $currentSession->get('userid');
		if (!$currentUser)
		{
			return;
		}

		$apiClient = array();
		if ($currentSession instanceof vB_Session_Api)
		{
			$apiClient = $currentSession->getApiClient();
		}

		if (!empty($apiClient['apiclientid']))
		{
			// TODO: do we have to validate the device token (aka registration id)?
			$this->assertor->replace(
				'vBForum:apiclient_devicetoken',
				array(
					'apiclientid' => $apiClient['apiclientid'],
					'userid'      => $apiClient['userid'],
					'devicetoken' => $deviceToken,
				)
			);
		}
	}

	/*
	 * This function deletes the device token for the current api client.
	 *
	 * @return null
	 */
	public function removeDeviceToken()
	{
		/*
			If we want to allow unsetting device tokens of other API clients that's under this user,
			we can do so by checking apiclient.userid. However, note that if they already logged out,
			apiclient.userid for that device will be 0, though in that case that record's device token
			should've already been unregistered. So the only use case I can think of is if they want
			logging out of just 1 device to stop push notifications for *all* devices that they have
			logged in with.
		 */

		$currentSession = vB::getCurrentSession();
		$currentUser = $currentSession->get('userid');
		if (!$currentUser)
		{
			return;
		}

		$apiClient = array();
		if ($currentSession instanceof vB_Session_Api)
		{
			$apiClient = $currentSession->getApiClient();
		}

		if (!empty($apiClient['apiclientid']))
		{
			// TODO: do we have to validate the device token (aka registration id)?
			$this->assertor->delete(
				'vBForum:apiclient_devicetoken',
				array(
					'apiclientid' => $apiClient['apiclientid'],
				)
			);
		}
	}

	// Returns a nested array keyed by userid.
	// Inner array lists device tokens for specified user (each token keyed by apiclientid)
	// Note, only tokens whose apiclient has been active in the last 7 days are returned.
	// This means each user could get an empty array!!
	public function convertUseridsToDeviceTokens($recipientUserids)
	{
		if (empty($recipientUserids))
		{
			return array();
		}

		$tokensByUseridAndClientid = array();
		foreach ($recipientUserids AS $__userid)
		{
			$__userid = intval($__userid);
			$tokensByUseridAndClientid[$__userid] = array();
		}
		$found = $this->assertor->assertQuery(
			'vBForum:getMultipleUsersDeviceTokensForPushNotification',
			array('userids' => $recipientUserids)
		);

		// 604800 = 7 days in seconds
		$cutofftime = (vB::getRequest()->getTimeNow() - 604800);
		foreach ($found AS $__row)
		{
			$__userid = $__row['userid'];
			// Only push to recipients whose apiclient has been active in the last 7 days.
			if ($__row['lastactivity'] >= $cutofftime)
			{
				// we key it by apiclientid in case single user has multiple active devices registered
				$tokensByUseridAndClientid[$__userid][$__row['apiclientid']] = $__row['devicetoken'];
			}
		}

		return $tokensByUseridAndClientid;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103441 $
|| #######################################################################
\*=========================================================================*/
