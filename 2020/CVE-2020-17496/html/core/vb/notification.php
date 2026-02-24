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

abstract class vB_Notification
{
	use vB_Trait_NoSerialize;

	/*
	 * We use late static bindings in this class, and absolutely require PHP 5.3+
	 */

	/*
	 * Array[String]
	 * Notificationdata including... TODO: DOCBLOCK
	 */
	protected $notificationData = array();

	/*
	 * Int[String|Int]
	 * Array of userids, keyed by String RECIPIENT_KEY_PREFIX . {userid} OR automatic numeric key, depending on
	 * where it was added. Integer key is not used by the default types. The recipients added with the string
	 * key is guaranteed to be unique, exclude the sender, and exclude recipients that are ignoring the sender.
	 */
	protected $recipients = array();

	const RECIPIENT_KEY_PREFIX = '_';

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
	protected static $triggers = array();


	/*
	 * String[] $updateEvents
	 *
	 * String array of events that should dismiss or delete the notification based on
	 * lookupid. Only valid for things that have a non-empty/non-null lookupid!
	 * Every event you add to these arrays must have a handler in handleUpdateEvents().
	 */
	protected static $updateEvents = array();


	/*
	 * Boolean
	 *
	 * If this is false, the sender cannot be empty.
	 */
	const GUESTS_CAN_SEND = true;

	/*
	 * Boolean
	 *
	 * If this is true, any subclass's lookupid will exclude its class's TYPENAME such that
	 * it can be grouped by this type. GROUP_CHILDREN = true only makes sense
	 * if this class's implementation of defineUnique() is FINAL
	 */
	const GROUP_CHILDREN = false;

	/*
	 * Unique, string identifier of this notification subclass.
	 * Must be composed of alphanumeric or underscore characters: [A-Za-z0-9_]+
	 */
	const TYPENAME = 'Notification';
	const REGEX_ALLOWED_TYPENAME = "/[A-Za-z0-9_]+/";


	// Delimiter used in lookupid.
	const DELIM = '.';

	/*
	 * Save some common information in memory to prevent multiple dupe queries from
	 * hitting the DB in the same page load.
	 * Note that we can clear these by clearMemory().
	 *
	 * $recipientsInfoCache - 'userid', 'email', '
	 */
	static $recipientsInfoCache = array();

	/*
	 * Whether it supports FCM or not
	 */
	const FCM_SUPPORTED = false;

	/**
	 * Content types that will be allowed to send notifications.
	 * @var array
	 */
	protected $validSourceContentTypes = array(
		'Gallery' => 1,
		'Link'    => 1,
		'Poll'    => 1,
		'Text'    => 1,
		'Video'   => 1,
		'Event'   => 1,
	);

	/**
	 * Channel types that will be allowed to send notifications.
	 * Keep this in sync with vB_Channel::$channelTypes where appropriate
	 * @var array
	 */
	protected $validSourceChannelTypes = array(
		'forum'   => 1,
		'blog'    => 1,
		'article' => 1,
		'group'   => 1,
	);

	final function __construct($trigger = '', $notificationData = array(), $recipients = array())
	{
		/*
			First, validate the input data. If anything goes wrong, catch the exception and just cancel out so the
			upstream code will go through OK. This is because upstream code is has higher priority than
			notifications, and we probably do NOT want to block its processes just because something with the
			notifications went wrong.
			On the flip side, this might mean it'll be harder to know when there's a bug with notifications.
		*/
		try
		{
			$notificationData = $this->validateAndCleanNotificationData($notificationData);
			$recipients = $this->validateProvidedRecipients($recipients);
		}
		catch (Exception $e)
		{
			/*
			 * Super hacky hacky hack. validateAndCleanNotificationData() might NOT be okay with this notification going out.
			 * For example, the function might decide that the sentbynodeid is bogus or of the wrong contenttype, and we
			 * should abort immediately. Such might happen if there's an attachment to a post that triggers a subscription
			 * notification. In such a case, we want to abort and not waste CPU cycles or hit the DB trying to fetch
			 * subscribers & filtering through them, but we do not want to cause the caller to halt. So we take this
			 * silent death approach.
			 */
			$this->cancelNotification();
			return;
		}

		// Check trigger. No need for exceptions here.
		if (isset(static::$triggers[$trigger]))
		{
			$notificationData['trigger'] = (string) $trigger;
			$notificationData['priority'] = (int) static::$triggers[$trigger];
		}
		else
		{
			// unknown trigger
			$this->cancelNotification();
			return;
		}

		// If sender is banned, just cancel out.
		if (!$this->checkIfSenderCanSend($notificationData['sender']))
		{
			$this->cancelNotification();
			return;
		}

		$notificationData['lastsenttime'] = (int) vB::getRequest()->getTimeNow();
		$notificationData['typename'] = static::TYPENAME;

		$this->notificationData = $notificationData;


		// fetchLookupid() depends on the rest of the notificationData being set, so we have to delay the call
		// until we set the data above.
		try
		{
			$lookupid = static::fetchLookupid($this->notificationData);
		}
		catch (Exception $e)
		{
			// Similar to handling the validateAndCleanNotificationData() exceptions above, just
			// die silently if fetchLookupid() failed with an exception due to missing data.
			$this->cancelNotification();
			return;
		}
		/*
		 *	the `lookupid` field is a human-readable field used for debugging & testing.
		 * 	the `lookupid_hashed` field is the actual column used as part of the unique key (recipient, lookupid_hashed).
		 *	We use the md5() hash as a lossy (but ideally virtually collision-less) compression for performance.
		 */
		if (is_null($lookupid))
		{
			$this->notificationData['lookupid'] = NULL;
			$this->notificationData['lookupid_hashed'] = NULL;
		}
		else
		{
			$this->notificationData['lookupid'] = substr($lookupid, 0, 150);	// lookupid		VARCHAR(150) NULL DEFAULT NULL,
			$this->notificationData['lookupid_hashed'] = static::getHashedLookupid($lookupid); // lookupid_hashed		CHAR(32), md5() is 32 chars.
		}


		/*
			If we got to this point, then all that's left to do is to add the additional recipients (typically
			automatically generated recipients independent of the provided recipients, like subscribers or
			mentioned users etc.). This is done in setRecipients()
			Then we'll check for existing notifications, and remove affected recipients according to whether their
			existing notifications should be overwritten or not.
		 */
		$this->setRecipients($recipients);
		$this->checkExistingNotifications();
	}

	/**
	 * Returns the md5() of the $lookupid or NULL if $lookupid is empty.
	 *
	 * @param	String	$lookupid
	 *
	 * @return	String|NULL		32 character string or NULL.
	 */
	final public static function getHashedLookupid($lookupid)
	{
		if (empty($lookupid))
		{
			return NULL;
		}

		return md5($lookupid);
	}


	/**
	 * Returns the notification data.
	 *
	 * @return Array[String]	Notification data including
	 *							- int|NULL		sender
	 *							- string|NULL	lookupid
	 *							- int|NULL		sentbynodeid
	 *							- string		typename
	 *							- int			lastsenttime
	 *							- string		trigger
	 *							- int			priority
	 */
	final public function getNotificationData()
	{
		return $this->notificationData;
	}

	/**
	 * Returns the array of recipients to receive this notification
	 *
	 * @return Int[]	Recipients.
	 */
	final public function getRecipients()
	{
		return $this->recipients;
	}


	/**
	 * Returns the memory cached array of recipients' information like email, languageid etc.
	 *
	 * @return Array[int]	Nested array of user data keyed by userid. Each subarray holds an individual
	 *						recipient's data including:
	 *						- string	'email'
	 *						- string	'username'
	 *						- int		'languageid'
	 *						- int		'emailnotification'
	 */
	final public function getCachedRecipientData()
	{
		return self::$recipientsInfoCache;
	}

	final public function shouldCombine()
	{
		return $this->overwriteRule() == 'combine';
	}

	final protected function checkExistingNotifications()
	{
		/*
		 * TODO: check for existing notification and see if we should allow overwrite, etc.
		 */
		if (empty($this->notificationData['lookupid']))
		{
			return;
		}
		else
		{
			/*
			 * TODO: Implement a "partial" update method
			 */
			$rule = $this->overwriteRule();
			switch($rule)
			{
				case 'always':
					// do nothing, allow overwriting
					break;

				case 'combine':
					// we only need the first existing notification since they will all be the same
					$notification = vB::getDbAssertor()->getRow('vBForum:notification', array(
						'recipient' => $this->recipients,
						'lookupid' => $this->notificationData['lookupid'],
					));
					if ($notification)
					{
						// we are combining the existing db notification into the
						// current one, so we can now continue and let this one
						// overwrite the existing one.
						$this->combineNotifications($notification, false, true);
					}
					break;

				case 'if_read':
					$existingArr = vB::getDbAssertor()->getRows('vBForum:notification',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							'recipient' => $this->recipients,
							'lookupid' => $this->notificationData['lookupid'],
						)
					);
					$rkp = vB_Notification::RECIPIENT_KEY_PREFIX;
					foreach ($existingArr AS $existing)
					{
						if ($existing['lastsenttime'] > $existing['lastreadtime'])
						{
							$userid = $existing['recipient'];
							unset($this->recipients["$rkp$userid"]); // This isn't sufficient for the numeric keyed userids, see below.
						}
					}
					break;

				case 'never':
					$this->cancelNotification();
					break;

				default:
					// do nothing, allow overwriting
					break;
			}
		}
	}

	// Using an abstract function here would force all the subclasses to define an empty
	// implementation of this even if they do not use the 'combine' overwrite rule.
	public function combineNotifications($addNotificationData, $sourceNotificationData, $addNotificationFromDb)
	{
		throw new Exception('combineNotifications() must be implemented in the subclass in order to use the "combine" overwrite rule.');
	}

	final protected function cancelNotification()
	{
		$this->notificationData = array();
		$this->recipients = array();
	}

	final protected static function validateUpdateEvent($event)
	{
		if (empty($event) OR !in_array($event, static::$updateEvents))
		{
			return false;
		}

		/*
		 * Make sure current type is installed
		 */
		$types = vB_Library::instance('Notification')->getNotificationTypes();
		if (!isset($types[static::TYPENAME]['typeid']))
		{
			return false;
		}

		return true;
	}

	/**
	 * Handle update/dismiss events. The required data in $eventData depends on the particular event.
	 * Children may also handle their specific events.
	 *
	 * @param	String	$event			One of the event strings in static::$updateEvents
	 * @param	Array	$eventData		When $event is 'read_topic'|'read_channel', expects:
	 *										int 'nodeid'
	 *										int 'userid'	(Optional)
	 */
	public static function handleUpdateEvents($event, $eventData)
	{
		if (!static::validateUpdateEvent($event))
		{
			return;
		}

		$types = vB_Library::instance('Notification')->getNotificationTypes();
		$typeid = $types[static::TYPENAME]['typeid'];
		$assertor = vB::getDbAssertor();

		switch($event)
		{
			case 'read_topic':
			case 'read_channel':
				/*
				 * Required data validation
				 */
				if (!isset($eventData['nodeid']))
				{
					return;
				}
				$parent = (int) $eventData['nodeid'];


				/*
				 * Optional data validation
				 */
				$currentUserid = vB::getCurrentSession()->get('userid');

				if (!isset($eventData['userid']))
				{
					$userid = $currentUserid;
				}
				else
				{
					$userid = (int) $eventData['userid'];
				}

				// In the future, we may want to allow auto-dismissal of notifications for other users by admins. But not right now.
				if ($userid !== $currentUserid)
				{
					return;
				}

				unset($eventData);

				/*
				 * Work.
				 * Fetch all children of passed in nodeid, and for all notifications of this type and sentbynodeid IN (fetched children) set lastreadtime = timenow
				 * But rather than fetching everything in closure (in case nodeid is 1/low), meaning a huge closure tree, let's use a stored query that joins on the
				 * notification table to reduce the # of records.
				 */
				$assertor->assertQuery(
					'vBForum:readNotificationsSentbynodeDescendantsOfX',
					array(
						'timenow' => (int) vB::getRequest()->getTimeNow(),
						'userid' => $userid,
						'parentid' => $parent,
						'typeids' => $typeid,
					)
				);
				break;

			case 'deleted_user':
				$userid = (int) $eventData['userid'];
				$check = $assertor->getRow('user', array('userid' => $userid));
				if (empty($check))
				{
					// remove any notification owned by deleted user.
					$assertor->assertQuery(
						'vBForum:notification',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
							'recipient' => $userid,
							'typeid' => $typeid
						)
					);

					// set sender to 0 if it was deleted user.
					$assertor->assertQuery(
						'vBForum:notification',
						array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
							vB_dB_Query::CONDITIONS_KEY => array(
								array('field' => 'sender', 'value' => $userid, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
								array('field' => 'typeid', 'value' => $typeid, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
							),
							'sender' => 0,
						)
					);
				}
				break;

			default:
				break;
		}
		return;
	}

	/**
	 * If there is an existing notification for a recipient (judged by comparing the lookupid), this function
	 * guides whether the new notification should overwrite the old one. Coder may want to consider checking for
	 * $this->notificationData['trigger'] for a more complex handling for different triggers.
	 *
	 * @return	String		Must be 'always'|'if_read'|'never'. These values indicate, respectively, that the
	 *						new notification should always overwrite, only overwrite if the old one is read, or
	 *						never overwrite while the old one exists.
	 *
	 * @access protected
	 */
	protected function overwriteRule()
	{
		return 'always';
	}

	/**
	 * Ensures that the recipients list is unique. Subclasses may perform
	 * additional validation and unset certain recipients as necessary.
	 *
	 * @param	Int[]		List of recipients provided to constructor.
	 *
	 * @return	Int[Int]	Userids keyed by userids
	 *
	 * @throws Exception()	If for some reason this notification cannot be constructed given
	 *						the context data in $notificationData. Constructor will catch the
	 *						exception and cancel this notification.
	 *
	 * @access protected
	 */
	protected function validateProvidedRecipients($recipients)
	{
		/*
			TODO add a generic final recipient validation against the user table
			to ensure all recipients exist.
		 */
		$uniqueRecipients = array();
		foreach($recipients AS $userid)
		{
			$userid = (int) $userid;
			$uniqueRecipients[$userid] = $userid;
		}

		return $uniqueRecipients;
	}

	/*
	 * Validates the notification data, checks the context to see if we should send this
	 * notification type, and throws exceptions if we should not or cannot send this notification
	 * type. If all is okay, it may set additional notification data specific to this notification type.
	 *
	 * @param	Array	$notificationData
	 *						- int|NULL 	sender
	 *						- int|NULL	sentbynodeid
	 *						- String|Array|Null		customdata
	 *
	 * @return	Array	Notification data to be set to $this->notificationData by constructor:
	 *						- int|NULL 	sender
	 *						- int|NULL	sentbynodeid
	 *						- String|Array|Null		customdata
	 *
	 * @throws Exception()	If for some reason this notification cannot be constructed given
	 *						the context data in $notificationData. Constructor will catch the
	 *						exception and cancel this notification.
	 *
	 * @access protected
	 */
	protected function validateAndCleanNotificationData($notificationData)
	{
		/*
		 *	It's good practice to start off a subclass's implementation of this function with
		 *  $newData = parent::validateAndCleanNotificationData($notificationData);
		 *	but not absolutely necessary IF YOU KNOW WHAT YOU'RE DOING.
		 */
		$newData = array(
			'sender' => NULL,
			'sentbynodeid' => NULL,
			'customdata' => NULL,
		);

		// Children should do a more thorough job of validating. for ex.,
		// ensuring that sentbynodeid is a real nodeid, etc.
		if (isset($notificationData['sender']))
		{
			$newData['sender'] = (int) $notificationData['sender'];
		}

		if (isset($notificationData['sentbynodeid']))
		{
			$newData['sentbynodeid'] = (int) $notificationData['sentbynodeid'];
		}

		if (isset($notificationData['customdata']))
		{
			// If it hasn't been json_encoded yet, do so now.
			if (is_array($notificationData['customdata']))
			{
				$notificationData['customdata'] = json_encode($notificationData['customdata']);
				$newData['customdata'] = (string) $notificationData['customdata'];
			}
		}

		return $newData;
	}

	/**
	 * Checks the source node content type and throws an exception if
	 * it is not allowed to send a notification.
	 *
	 * @param int Content type id for the source node
	 */
	protected function validateSourceContentType($nodecontenttypeid)
	{
		$contenttypeclass = vB_Types::instance()->getContentTypeClass($nodecontenttypeid);

		if (!isset($this->validSourceContentTypes[$contenttypeclass]))
		{
			throw new Exception("Cannot send this notification for the node's content type.");
		}
	}

	/**
	 * Checks the source channel type and throws an exception if
	 * it is not allowed to send a notification.
	 *
	 * @param string Channel type for the source node
	 */
	protected function validateSourceChannelType($nodechanneltype)
	{
		if (!isset($this->validSourceChannelTypes[$nodechanneltype]))
		{
			throw new Exception("Cannot send this notification for the node's channel type.");
		}
	}

	/**
	 * Set the recipients array. Goes through the provided list of userids,
	 * removes the sender, any recipients that are ignoring the sender, & any
	 * duplicates before setting the remaining list to the $this->recipients
	 * instance variable.
	 *
	 * @param	Int[]	$recipients
	 *
	 * @access protected
	 */
	final protected function setRecipients($recipients = array())
	{
		// This is needed to distinguish between the default recipients &
		// ones added by forceAddRecipients()
		// Note I decided to not include forceAddRecipients() in this version, but it's not worth
		// getting rid of this key just yet.
		$rkp = vB_Notification::RECIPIENT_KEY_PREFIX;

		foreach($recipients AS $userid)
		{
			$userid = (int) $userid;
			$this->recipients["$rkp$userid"] = $userid;
		}

		/*
		 * Additions.
		 */
		// We can't rely on custom plugins to follow the "always set userid to both key & value" rule
		$additions = $this->addAdditionalRecipients();
		foreach ($additions AS $userid)
		{
			$userid = (int) $userid;
			$this->recipients["$rkp$userid"] = $userid;
		}
		unset($additions);


		/*
		 * Removals
		 */
		// remove sender. Note this means custom notifications cannot send a notification to sender.
		if (isset($this->notificationData['sender']))
		{
			unset($this->recipients[$rkp . $this->notificationData['sender']]);
		}

		// remove recipients ignoring sender
		$this->removeIgnoringRecipients();

		// remove recipients who opted out of this notification.
		$this->removeOptOuts();

		// Filter them based on type-specific rules.
		$this->filterRecipients();


		/*
			TODO add some validation on recipients (ex., do these users exist) & remove them if necessary.
		 */
	}

	/**
	 * Child may override this to set specific rules on how to filter out recipients
	 * (e.g. view permissions, friend status, etc).
	 * This is in the base class because most notifications are related to a node and
	 * should check view perms on the node.
	 * Remove any recipients who cannot view the triggering node to prevent leaking
	 * data via notification emails or firebase cloud messages.
	 *
	 * @access protected
	 */
	protected function filterRecipients()
	{
		if (isset($this->notificationData['sentbynodeid']))
		{
			$nodeid = $this->notificationData['sentbynodeid'];
			$node = vB_Library::instance("node")->getNodeFullContent($nodeid);
			if (!isset($node[$nodeid]))
			{
				// This shouldn't happen... but if something weird happened, maybe we should unset all recipients?
				// For now, just return.
				return;
			}
			$node = $node[$nodeid];

			$contentLib = vB_Library_Content::getContentLib($node['contenttypeid']);
			foreach($this->recipients AS $__key => $__userid)
			{
				/*
					$rkp = vB_Notification::RECIPIENT_KEY_PREFIX;
					$__key == $rkp . $__userid
				 */
				$__canview = $contentLib->validate(
					$node,
					vB_Library_Content::ACTION_VIEW,
					$nodeid,
					array($nodeid => $node),
					$__userid
				);
				if (!$__canview)
				{
					unset($this->recipients[$__key]);
				}
			}
		}
		return;
	}

	/**
	 * Only subclasses know which users it should automatically add to the recipients list.
	 * Recipients generated by this function WILL NOT allow duplicate recipients.
	 *
	 * @return Int[]	Integer list of recipients.
	 *
	 * @access protected
	 */
	protected function addAdditionalRecipients()
	{
		return array();
	}

	final protected function checkIfSenderCanSend($sender)
	{
		if (empty($sender))
		{
			return (bool) static::GUESTS_CAN_SEND;
		}
		else if (vB_Library::instance('user')->isBanned($sender))
		{
			return false;
		}

		/*
			If we got to this point, we're good in terms of checks that span *all* notification types.
			However we might have some type-specific checks.
		 */
		return $this->checkExtraPermissionsForSender($sender);
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
		return true;
	}

	/**
	 * Remove any recipient in $this->recipients who is ignoring the sender.
	 *
	 * @access protected
	 */
	final protected function removeOptOuts()
	{
		if (empty($this->recipients))
		{
			return;
		}

		$rkp = vB_Notification::RECIPIENT_KEY_PREFIX;
		$needToQuery = array();
		foreach ($this->recipients AS $userid)
		{
			if (!isset(self::$recipientsInfoCache[$userid]))
			{
				// we check & unset these later after we query the missing info.
				$needToQuery[$userid] = $userid;
			}
			else
			{
				// also see unset() in the next code block
				if (!$this->typeEnabledForUser(self::$recipientsInfoCache[$userid]))
				{
					unset($this->recipients["$rkp$userid"]);
				}
			}
		}

		if (!empty($needToQuery))
		{
			$recipientsInfo = vB::getDbAssertor()->getRows('user',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'userid' => $needToQuery,
					vB_dB_Query::COLUMNS_KEY => array(
						'userid',
						'username',
						'notification_options',
						'email',
						'emailnotification',
						'languageid'
					)
				)
			);
			foreach ($recipientsInfo AS $user)
			{
				$userid = $user['userid'];
				self::$recipientsInfoCache[$userid] = $user;
				if (!$this->typeEnabledForUser($user))
				{
					unset($this->recipients["$rkp$userid"]);
				}
			}
		}
	}

	/**
	 * Returns False if user opted out of this notification type.
	 *
	 * @param	Array	$user	Expecting user table data including:
	 *							-	int	'userid'
	 *							-	int	'notification_options'
	 *
	 * @return	Bool
	 *
	 * @access protected
	 */
	protected function typeEnabledForUser($user)
	{
		return false;
	}

	public static function getTriggers()
	{
		return static::$triggers;
	}

	public static function getUpdateEvents()
	{
		return static::$updateEvents;
	}

	/**
	 * Remove any recipient in $this->recipients who is ignoring the sender.
	 *
	 * @access protected
	 */
	final protected function removeIgnoringRecipients()
	{
		if (empty($this->recipients) OR !isset($this->notificationData['sender']))
		{
			return;
		}
		/*
		 *TODO: CACHE THE IGNORELIST IN MEMORY.
		 * 		But we'll need to clear the memory caching in vB_Library_Notification->triggerEvent() because
		 *		of unit tests.
		 */
		$ignoreQuery = vB::getDbAssertor()->getRows('userlist',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'type' => "ignore",	// is there a class constant somewhere instead of hard-coded string?
				'relationid' => $this->notificationData['sender'],
				'userid' => $this->recipients,
			)
		);

		$rkp = vB_Notification::RECIPIENT_KEY_PREFIX;
		foreach ($ignoreQuery AS $row)
		{
			$userid = (int) $row['userid'];
			unset($this->recipients["$rkp$userid"]);
		}
	}


	/**
	 * Fetch the lookupid based on the defineUnique() function & the class's "address".
	 *
	 * @param	Array	$notificationData	Data required by this class's defineUnique() function to
	 *							generate a lookupid. Usually includes:
	 *							- INT|NULL sender,
	 *							- INT|NULL sentbynodeid,
	 *							- String|NULL customdata
	 * @param	Bool	$skipValidation		Optional, default false. If true, defineUnique will skip
	 *							any validation and assume that $notificationData is correct and that
	 *							$notificationData contains all data required to create the unique key.
	 *
	 * @return String|NULL		NULL only if defineUnique() returns empty string/array, indicating
	 *							that this type should NEVER be grouped.
	 *
	 * @throws Exception()		If fetching lookupid fails ...
	 *							... because fetching the unique prefix fails due to missing data
	 *							... TODO: finish DOCBLOCK
	 */
	final public static function fetchLookupid($notificationData, $skipValidation = false)
	{
		$delim = vB_Notification::DELIM;

		// Get the uniqueness array.
		$uniqueArr = static::defineUnique($notificationData, $skipValidation);

		if (empty($uniqueArr) OR !is_array($uniqueArr))
		{
			// If it's empty, that means this type doesn't do groupings at all, and lookupid must be NULL to
			// ensure that every notification record of this type is unique in the DB.
			return NULL;
		}
		else
		{
			// ... otherwise, ensure that every value is NOT empty. If a value is empty that does NOT contribute
			// to the uniqueness and is probably an error (unless review or customer feedback indicate otherwise).
			foreach($uniqueArr AS $key => $value)
			{
				// sender for VMs can be a guest, as seen in the wild. It's a special case, because for senders who are regular members
				// we group by their id, and for different guest senders we would group them all together...
				if (empty($value) AND $key != 'sender')
				{
					throw new Exception("A value (for key $key) in the uniqueness identifier is empty!");
				}
			}
		}

		// Let's just use json_encode() rather than coming up with our own array to string strategy.
		$unique = json_encode($uniqueArr);
		if (empty($unique))
		{
			throw new Exception("Error during json_encode() of the uniqueness identifier array!");
		}

		/*
		 * Now we group by this type (or parent type, depending on the parent's GROUP_CHILDREN setting)
		 * The way we do this is to just create a delim separated string of the hierarchy of
		 * TYPENAME's. So for ex., if we have vB_Notification_Custom_Cool, the lookupid would
		 * be suffixed by something like ".Cool.Custom.Notification".
		 */

		$current_class = (string) get_called_class();	// because there isn't a late-static-binding equivalent of __CLASS__
		$parents = class_parents($current_class);
		if (empty($parents))
		{
			// Something went wrong in class_parents(). For now just return a generic error.
			throw new Exception("Class $current_class is missing the required parents.");
		}

		$address = array();
		foreach ($parents AS $class)
		{
			// is_a() with a 3rd param to allow the 1st param to be STRING is PHP 5.3.9+ ONLY.
			// However, is_subclass_of() allowed 1st param as STRING since 5.0.3+...
			if (!(is_subclass_of($class, 'vB_Notification') OR $class == 'vB_Notification'))
			{
				throw new Exception("Notification class $class is NOT a subclass of vB_Notification.");
			}
			$address[] = $class::TYPENAME;
		}
		$address = implode($delim, $address);
		// Figure out if current class's parent has restricted that its children (current class) must be grouped together.
		$immediateParent = get_parent_class($current_class);
		$groupThis = ( $immediateParent AND $immediateParent::GROUP_CHILDREN );
		if (!$groupThis)
		{
			$address = (string) (static::TYPENAME . $delim . $address);
		}

		return (string) ($unique . $delim . $address);
	}

	/**
	 * This function defines what makes 2 notifications of this TYPE sent to, or belonging
	 * to a single recipient distinct or duplicates.
	 * For example, you may group a notification type by the sentbynodeid and sender. In that case,
	 * you should return the following:
	 *		return array(
	 *			"sentbynodeid"	=> $notificationData['sentbynodeid'],
	 *			"sender"		=> $notificationData['sender'],
	 *		);
	 * If every single notification of this type should be unique, just return an empty array:
	 * 		return array();
	 * else if every single notification of this type should be grouped together per recipient, just
	 * return an array of constant(s):
	 *		return array(
	 *			"group"	=> "all",
	 *		);
	 * Note that if any of the specified values in the return array is EMPTY, the notification generation
	 * code will throw an exception.
	 *
	 * @return	String[String]
	 *
	 * @access protected
	 */
	protected static function defineUnique($notificationData, $skipValidation)
	{
		return array();
	}

	final public static function clearMemory()
	{
		// Required for unit testing... Usually we can probably ignore user info changes
		// that happen *within* a pageload / session, but unit tests have a single PHP session
		// that lasts for multiple "user sessions".
		// This is called by vB_Library_Notification->triggerNotificationEvent().

		self::$recipientsInfoCache = array();
	}

	/**
	 * Returns the phrase data used by privatemessage_notificationdetail template to render
	 * the individual notification.
	 *
	 * @param	Array	Notification data required for this notification type, including
	 *					- int		sender
	 *					- ...
	 *
	 * @return	Array	First element is the string phrase title, second element is an array of
	 *					replacement data used by the phrase.
	 */
	public static function fetchPhraseArray($notificationData)
	{
		$current_class = (string) get_called_class();
		return array('missing_phrase_handler_for_notification', array($current_class, __FUNCTION__));
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
		// Only alphamerics and '_' are allowed in typenames, and the unique prefix in the
		// lookupid is json_encoded (so have the form of {"blah":"cool"}) so using _{$userid}
		// in the array key should prevent conflicts from super weird/creative custom type names.
		// I hope.
		if (empty($notificationData['recipient']))
		{
			return '';
		}
		$key = "_" . $notificationData['recipient'] . vB_Notification::DELIM . $notificationData['lookupid'];

		return	$key;
	}

	public static function getFCMExtraData($data, $languageids)
	{
		return array();
	}

	/**
	 * Returns the rendered phrase used in notification emails for this type.
	 *
	 * @param	Array	Notification data required for this notification type, including
	 *					- int       recipient
	 *					- int       languageid
	 *					- string    recipient_username
	 *					- ...		other data from getNotificationData()
	 *
	 * @return	String|Bool		Rendered email phrase or False if it doesn't have an email
	 *							or its email goes through the legacy email function.
	 */
	public static function renderEmailPhrases($data)
	{
		// most of the default ones have a legacy "about" string associated with it, and
		// go through vB_Library_Notification::sendLegacyEmailNotification()
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102433 $
|| #######################################################################
\*=========================================================================*/
