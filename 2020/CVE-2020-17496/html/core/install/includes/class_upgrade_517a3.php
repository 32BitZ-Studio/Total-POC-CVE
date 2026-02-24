<?php
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
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_517a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '517a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.7 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.7 Alpha 2';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	/*
	 * Step 1 : Add notificationevent table
	 */
	function step_1()
	{
		if (!$this->tableExists('notificationevent'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'notificationevent'),
				"CREATE TABLE " . TABLE_PREFIX . "notificationevent (
					eventname		VARCHAR(191) NOT NULL UNIQUE,
					classes 		MEDIUMTEXT NULL DEFAULT NULL,
					PRIMARY KEY  	(eventname)
				) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
			);
		}
		else
		{
			$this->skip_message();
		}
		$this->long_next_step();
	}

	/*
	 * Step 2 : notificationtype table
	 */
	function step_2($data = NULL)
	{
		if (!$this->tableExists('notificationtype'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'notificationtype'),
				"CREATE TABLE " . TABLE_PREFIX . "notificationtype (
					typeid 			SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
					typename 		VARCHAR(191) NOT NULL UNIQUE,
					class			VARCHAR(191) NOT NULL UNIQUE,
					PRIMARY KEY  	(typeid)
				) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
			);
		}
		else
		{
			// potentially a re-run, or we may have 516 tables to worry about.
			if ($this->field_exists('notificationtype', 'categoryid'))
			{
				$this->run_query(
					sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . "notificationtype"),
					"RENAME TABLE " . TABLE_PREFIX . "notificationtype TO " . TABLE_PREFIX . "notificationtype_temporary",
					self::MYSQL_ERROR_TABLE_EXISTS
				);

				// Now create the 517 table. We'll import old data in the next step(s).
				return array('startat' => 1);
			}
			else
			{
				$this->skip_message();
			}
		}
	}

	/*
	 * Add the new notificationtype & notificationevent data
	 */
	function step_3()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->addNotificationDefaultData();
		$this->show_message($this->phrase['final']['adding_notification_defaults']);
		$this->long_next_step();
	}


	/*
	 * Step 4 : Add notification table
	 */
	function step_4($data = NULL)
	{
		if (!$this->tableExists('notification'))
		{
			// No 516 to worry about, add the new table.
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'notification'),
				"CREATE TABLE " . TABLE_PREFIX . "notification (
					notificationid		INT UNSIGNED NOT NULL AUTO_INCREMENT,
					recipient	 		INT UNSIGNED NOT NULL,
					sender	 			INT UNSIGNED DEFAULT NULL,
					lookupid			VARCHAR(150) NULL DEFAULT NULL,
					lookupid_hashed		CHAR(32) NULL DEFAULT NULL,
					sentbynodeid		INT UNSIGNED DEFAULT NULL,
					customdata			MEDIUMTEXT,
					typeid				SMALLINT UNSIGNED NOT NULL,
					lastsenttime 		INT(10) UNSIGNED NOT NULL DEFAULT '0',
					lastreadtime 		INT(10) UNSIGNED NOT NULL DEFAULT '0',
					PRIMARY KEY 	(notificationid),
					UNIQUE KEY guid	(recipient, lookupid_hashed),
					KEY 			(recipient),
					KEY 			(lookupid_hashed),
					KEY 			(lastsenttime),
					KEY 			(lastreadtime)
				) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
			);
		}
		else
		{
			// potentially a re-run, or we may have 516 tables to worry about.
			if ($this->field_exists('notification', 'aboutstarterid'))
			{
				$this->run_query(
					sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . "notification"),
					"RENAME TABLE " . TABLE_PREFIX . "notification TO " . TABLE_PREFIX . "notification_temporary",
					self::MYSQL_ERROR_TABLE_EXISTS
				);

				// Now create the 517 table. We'll import old data in the next step(s).
				return array('startat' => 1);
			}
			else
			{
				$this->skip_message();
			}
		}
		$this->long_next_step();
	}

	/*
	 * Step 5 : Add delete helper column for step_6. THIS CAN TAKE A WHILE
	 */
	function step_5($data = NULL)
	{
		if ($this->tableExists('notification_temporary')
			AND !$this->field_exists('notification_temporary', 'deleted')
		)
		{

			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'notification_temporary ', 1, 1),
				'notification_temporary',
				'deleted',
				'tinyint',
				array('null' => false, 'default' => 0)
			);
		}
		else
		{
			$this->skip_message();
		}
		$this->long_next_step();
	}

	/*
	 * Step 6 : Import 516 notification data.
	 */
	function step_6($data = NULL)
	{
		if ($this->tableExists('notification_temporary'))
		{
			$batchSize = 5000;
			$assertor = vB::getDbAssertor();
			$oldNotifications = $assertor->getRows(
				'vBInstall:fetch516Notifications',
				array(
					'batchsize'	=> $batchSize
				)
			);

			if (empty($oldNotifications))
			{
				$this->long_next_step();
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$typeQuery = $assertor->getRows('vBInstall:fetch516NotificationTypeData');
			$oldTypesByTypeid = array();
			foreach ($typeQuery AS $row)
			{
				$oldTypesByTypeid[$row['typeid']] = $row;
			}

			// old categoryname.typename => new notification class name
			$newTypeClassMap = array(
				'content' => array(
					'subscription' => 'vB_Notification_Content_GroupByStarter_Subscription',
					'reply' => 'vB_Notification_Content_GroupByStarter_Reply',
					'comment' => 'vB_Notification_Content_GroupByParentid_Comment',
					'threadcomment' => 'vB_Notification_Content_GroupByParentid_ThreadComment',
				),
				'special' => array(
					'usermention' => 'vB_Notification_Content_UserMention',
					'vm' => 'vB_Notification_VisitorMessage',
				),
				'pollvote' => array(
					'vote' => 'vB_Notification_PollVote',
				),
				'nodeaction' => array(
					'like' => 'vB_Notification_LikedNode',
				),
				'userrelation' => array(
					'following' => 'vB_Notification_UserRelation_SenderIsfollowing',
					'accepted_follow' => 'vB_Notification_UserRelation_SenderAcceptedFollowRequest',
				),
			);

			$newTypesByName = vB_Library::instance('notification')->getNotificationTypes();

			$start = NULL;
			$end = NULL;
			$deleteThese = array();
			$insertThese = array();
			foreach ($oldNotifications AS $row)
			{
				$deleteThese[] = $row['notificationid'];
				$end = $row['notificationid'];
				if(is_null($start))
				{
					$start = $row['notificationid'];
				}


				$oldType = $oldTypesByTypeid[$row['typeid']];
				if (empty($oldType) OR !isset($newTypeClassMap[$oldType['categoryname']][$oldType['typename']]))
				{
					// We don't know what type this is.
					continue;
				}

				if ($oldType['categoryname'] == 'content' AND (empty($row['parentid']) OR empty($row['starter'])))
				{
					// this indicates a node was removed in 516. We need to skip importing this or else vB_Notification::fetchLookupid()
					// will throw an exception.
					continue;
				}

				$notificationClass = $newTypeClassMap[$oldType['categoryname']][$oldType['typename']];
				if (!is_subclass_of($notificationClass, 'vB_Notification'))
				{
					continue;
				}
				$lookupid = $notificationClass::fetchLookupid($row, true);
				if (is_null($lookupid))
				{
					$row['lookupid_hashed'] = NULL;
				}
				else
				{
					$row['lookupid_hashed'] = $notificationClass::getHashedLookupid($lookupid); // lookupid_hashed		CHAR(32), md5() is 32 chars.
					$row['lookupid'] = substr($lookupid, 0, 150);	// lookupid		VARCHAR(150) NULL DEFAULT NULL,
				}

				$row['typeid'] = $newTypesByName[$notificationClass::TYPENAME]['typeid'];


				if (empty($row['lookupid_hashed']))
				{
					$insertThese[] = $row;
				}
				else
				{
					$key = "_{$row['recipient']}" . vB_Notification::DELIM . $row['lookupid_hashed'];
					// For these imports, just ignore priority and just import the last one if any old ones now collapse.
					$insertThese[$key] = $row;
				}
			}

			if (!empty($insertThese))
			{
				$assertor->assertQuery('vBForum:addNotifications', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD, 'notifications' => $insertThese));
			}


			if (!empty($deleteThese))
			{
				$assertor->assertQuery('vBInstall:delete516Notifications', array('deleteids' => $deleteThese));
			}
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));

			return array('startat' => $end);
		}
		else
		{
			$this->skip_message();
		}
		$this->long_next_step();
	}


	/*
	 * Step 7 : Drop the old data.
	 */
	function step_7($data = NULL)
	{
		if ($this->tableExists('notification_temporary')
			OR $this->tableExists('notificationtype_temporary')
			OR $this->tableExists('notificationcategory')
		)
		{
			$batchSize = 1;
			$assertor = vB::getDbAssertor();
			$oldNotifications = $assertor->getRows(
				'vBInstall:fetch516Notifications',
				array(
					'batchsize'	=> $batchSize
				)
			);

			if (empty($oldNotifications))
			{
				$this->run_query(
					sprintf($this->phrase['core']['dropping_old_table_x'], TABLE_PREFIX . "notification_temporary"),
					"DROP TABLE IF EXISTS " . TABLE_PREFIX . "notification_temporary"
				);
				$this->run_query(
					sprintf($this->phrase['core']['dropping_old_table_x'], TABLE_PREFIX . "notificationtype_temporary"),
					"DROP TABLE IF EXISTS " . TABLE_PREFIX . "notificationtype_temporary"
				);
				$this->run_query(
					sprintf($this->phrase['core']['dropping_old_table_x'], TABLE_PREFIX . "notificationcategory"),
					"DROP TABLE IF EXISTS " . TABLE_PREFIX . "notificationcategory"
				);
				return;
			}
		}
		else
		{
			$this->skip_message();
		}
		$this->long_next_step();
	}

	/*
		Below steps were previously in 516a5.
		Import pre-516 data into 517.

		The basic plan is to fetch old notifications data by a query based on the one used by
		vBForum:listNotifications, insert them into the new table (excepting any that might be duplicated
		or was sent by the recipient), and then update the old PM/sentto notification records to deleted = 0 .
		The PM cron will handle actually deleting the old notifications.
		At the moment, we don't check for showpublished or showapproved for the import. Note that in 5.1.6
		*generation* requires that node is published & approved.
	 */

	/*
	  Step 8 - import old content notifications
			'reply', 'comment', 'threadcomment', 'subscription', 'usermention', 'vm'
	*/
	function step_8($data = NULL)
	{
		$assertor = vB::getDbAssertor();

		// This batchsize was selected based on testing on the saas DB with 3 million legacy notifications.
		$batchSize = 5000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['517a3']['importing_content_notification']);
		}
		else
		{
			$startat = intval($data['startat']);	// not used
		}

		$pmLib = vB_Library::instance('content_privatemessage');
		$allowedTypes = array('Gallery', 'Link', 'Poll', 'Text', 'Video');
		$allowedTypeids = array();
		$typePrefix = 'vBForum_';
		foreach ($allowedTypes AS $typeText)
		{
			$typeText = $typePrefix . $typeText;
			$typeid = vB_Types::instance()->getContentTypeID($typeText);
			if (!empty($typeid))
			{
				$allowedTypeids[$typeText] = $typeid;
			}
		}
		$importThese = $assertor->getRows(
			'vBInstall:fetchOldContentNotifications',
			array(
				'batchsize'	=> $batchSize
			)
		);

		$newTypesByName = vB_Library::instance('notification')->getNotificationTypes();
		$deleteNodeids = array();
		$notifications = array();
		$start = NULL;
		$end = NULL;
		foreach ($importThese AS $row)
		{
			$deleteNodeids[] = $row['delete_nodeid'];
			$end = $row['delete_nodeid'];
			if(is_null($start))
			{
				$start = $row['delete_nodeid'];
			}

			// Ignorelist & missing user record checks
			if (!empty($row['skip']) OR !empty($row['skip_missing_recipient']))
			{
				continue;
			}

			/*
				About $row['message_sender'] : In the old system, when a notification overwrite a previous one, the aboutid changes to the
				new content node, but the notification's sender stays the same. This conflicts, for example, if Alex has a thread and Bob
				and Cat responds to that thread, respectively, where the message_sender would point to Bob, but the aboutid will point to
				Cat's reply. I've decided to ignore the sentto data and rely on the content node's userid as the sender, but I've left
				the old column select to allow this explanation to have some context.
			 */

			/*
				comments and thread comments use the "parent" instead of the actual comment node
				for aboutid, so we need to grab the first comment for each parent...
				If 'sentbynodeid' is a reply (which most likely it is), its starter will be equal to its parent.
				If somehow it's the comment, then its starter will not be its parent.
			 */
			if ($row['about'] == "comment" OR $row['about'] == "threadcomment")
			{
				$firstCommentNode = $assertor->getRow(
					'vBInstall:fetchFirstComment',
					array(
						'parentid'	=> $row['sentbynodeid'],
						'contenttypeids'	=> $allowedTypeids,
						'recipient'	=> $row['recipient'],
					)
				);
				if (!empty($firstCommentNode['nodeid']))
				{
					$row['sender'] = $firstCommentNode['userid'];
					$row['sentbynodeid'] = $firstCommentNode['nodeid'];
				}
				else
				{
					// If we cannot find the first comment that's not owned by
					// the recipient or an ignored user, just skip importing this one.
					continue;
				}
			}

			$typeName = $pmLib->convertLegacyNotificationAboutString($row['about']);
			$typeData = $newTypesByName[$typeName];
			if (!empty($typeData['class']) AND is_subclass_of($typeData['class'], 'vB_Notification'))
			{
				$row['typeid'] = $typeData['typeid'];

				$notificationClass = $typeData['class'];
				$lookupid = $notificationClass::fetchLookupid($row, true);
				$row['lookupid_hashed'] = $notificationClass::getHashedLookupid($lookupid);
				if (!is_null($lookupid))
				{
					$row['lookupid'] = substr($lookupid, 0, 150);
				}


				$addme = array(
					'recipient' 	=> $row['recipient'],
					'sender' 		=> $row['sender'],
					'lookupid'		=> $row['lookupid'],
					'lookupid_hashed'	=> $row['lookupid_hashed'],
					'sentbynodeid'	=> $row['sentbynodeid'],
					'typeid' 		=> $row['typeid'],
					'lastsenttime' 	=> $row['lastsenttime'],
				);

				$notifications[] = $addme;
			}
		}

		if (!empty($notifications))
		{
			$try = $assertor->assertQuery(
				'vBInstall:insertOldNotification',
				array('notifications' => $notifications)
			);
		}

		if (!empty($deleteNodeids))
		{
			$assertor->assertQuery(
				'vBInstall:flagNotificationsForDelete',
				array('deleteNodeids' => $deleteNodeids)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
	}



	/*
	  Step 9 - 	import old vote notifications
				import old like (previously 'rate') notifications
	*/
	function step_9($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		// See notes about batch size in step_8()
		$batchSize = 5000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['517a3']['importing_pollvote_like_notification']);
		}
		else
		{
			$startat = intval($data['startat']);	// not used
		}

		$pmLib = vB_Library::instance('content_privatemessage');
		$importThese = $assertor->getRows(
			'vBInstall:fetchOldContentlessNotifications',
			array(
				'batchsize'	=> $batchSize,
			)
		);

		$newTypesByName = vB_Library::instance('notification')->getNotificationTypes();
		$start = NULL;
		$end = NULL;
		$deleteNodeids = array();
		$notifications = array();
		foreach ($importThese AS $row)
		{
			$deleteNodeids[] = $row['delete_nodeid'];
			$end = $row['delete_nodeid'];
			if(is_null($start))
			{
				$start = $row['delete_nodeid'];
			}

			// Ignorelist & missing user record checks
			if (!empty($row['skip']) OR !empty($row['skip_missing_recipient']))
			{
				continue;
			}

			$typeName = $pmLib->convertLegacyNotificationAboutString($row['about']);
			$typeData = $newTypesByName[$typeName];
			if (!empty($typeData['class']) AND is_subclass_of($typeData['class'], 'vB_Notification'))
			{
				$row['typeid'] = $typeData['typeid'];

				$notificationClass = $typeData['class'];
				$lookupid = $notificationClass::fetchLookupid($row, true);
				$row['lookupid_hashed'] = $notificationClass::getHashedLookupid($lookupid);
				if (!is_null($lookupid))
				{
					$row['lookupid'] = substr($lookupid, 0, 150);
				}

				$addme = array(
					'recipient' 	=> $row['recipient'],
					'sender' 		=> $row['sender'],
					'lookupid'		=> $row['lookupid'],
					'lookupid_hashed'	=> $row['lookupid_hashed'],
					'sentbynodeid'	=> $row['sentbynodeid'],
					'typeid' 		=> $row['typeid'],
					'lastsenttime' 	=> $row['lastsenttime'],
				);

				$notifications[] = $addme;
			}
		}

		if (!empty($notifications))
		{
			$try = $assertor->assertQuery(
				'vBInstall:insertOldNotification',
				array('notifications' => $notifications)
			);
		}

		if (!empty($deleteNodeids))
		{
			$assertor->assertQuery(
				'vBInstall:flagNotificationsForDelete',
				array('deleteNodeids' => $deleteNodeids)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
	}


	/*
	  Step 10 - import old follow & following notifications
	*/
	function step_10($data = NULL)
	{
		$assertor = vB::getDbAssertor();

		// See notes about batch size in step_8()
		$batchSize = 5000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['517a3']['importing_userrelation_notification']);
		}
		else
		{
			$startat = intval($data['startat']);	// not used
		}

		$pmLib = vB_Library::instance('content_privatemessage');
		$importThese = $assertor->getRows(
			'vBInstall:fetchOldUserrelationNotifications',
			array(
				'batchsize'	=> $batchSize,
			)
		);

		$newTypesByName = vB_Library::instance('notification')->getNotificationTypes();
		$start = NULL;
		$end = NULL;
		$deleteNodeids = array();
		$notifications = array();
		foreach ($importThese AS $row)
		{
			$deleteNodeids[] = $row['delete_nodeid'];
			$end = $row['delete_nodeid'];
			if(is_null($start))
			{
				$start = $row['delete_nodeid'];
			}

			// Ignorelist & missing user record checks
			if (!empty($row['skip']) OR !empty($row['skip_missing_recipient']) OR !empty($row['skip_missing_sender']))
			{
				continue;
			}

			$typeName = $pmLib->convertLegacyNotificationAboutString($row['about']);
			$typeData = $newTypesByName[$typeName];
			if (!empty($typeData['class']) AND is_subclass_of($typeData['class'], 'vB_Notification'))
			{
				$row['typeid'] = $typeData['typeid'];

				$notificationClass = $typeData['class'];
				$lookupid = $notificationClass::fetchLookupid($row, true);
				$row['lookupid_hashed'] = $notificationClass::getHashedLookupid($lookupid);
				if (!is_null($lookupid))
				{
					$row['lookupid'] = substr($lookupid, 0, 150);
				}


				$addme = array(
					'recipient' 	=> $row['recipient'],
					'sender' 		=> $row['sender'],
					'lookupid'		=> $row['lookupid'],
					'lookupid_hashed'	=> $row['lookupid_hashed'],
					'sentbynodeid'	=> $row['sentbynodeid'],
					'typeid' 		=> $row['typeid'],
					'lastsenttime' 	=> $row['lastsenttime'],
				);

				$notifications[] = $addme;
			}
		}

		if (!empty($notifications))
		{
			$try = $assertor->assertQuery(
				'vBInstall:insertOldNotification',
				array('notifications' => $notifications)
			);
		}

		if (!empty($deleteNodeids))
		{
			$assertor->assertQuery(
				'vBInstall:flagNotificationsForDelete',
				array('deleteNodeids' => $deleteNodeids)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));

			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
	}


	/**
	 * Import notifications for new visitor messages
	 * Moved here from 500rc1 step_8 because inserting notifications post 516 & 517 refactors
	 * requires the existence of the new notification tables & default data, which are added
	 * in the earlier upgrade steps.
	 */
	function step_11($data = NULL)
	{
		$process = 500;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['517a3']['importing_vm_notification']);
		}
		$startat = intval($data['startat']);

		//First see if we need to do something. Maybe we're O.K.
		if (!empty($data['maxvB5']))
		{
			$maxvB5 = $data['maxvB5'];
		}
		else
		{
			$maxvB5 = vB::getDbAssertor()->getRow('vBInstall:getMaxUseridWithVM');
			$maxvB5 = $maxvB5['maxid'];
		}

		if ($maxvB5 <= $startat)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		// Note, vB_dB_Query::OPERATOR_GT makes $starat an *exclusive* limit.
		$endat = ($startat + $process); // Note, vB_dB_Query::OPERATOR_LTE below makes this an *inclusive* limit.
		$bf_masks = vB::getDatastore()->getValue('bf_misc_usernotificationoptions');
		// Fetch user info
		$users = vB::getDbAssertor()->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('userid', 'vmunreadcount', 'notification_options'),
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'value' => $startat, 'operator' => vB_dB_Query::OPERATOR_GT),
				array('field' => 'userid', 'value' => $endat, 'operator' => vB_dB_Query::OPERATOR_LTE),
				array('field' => 'vmunreadcount', 'value' => 0, 'operator' => vB_dB_Query::OPERATOR_GT),
			)
		));

		if ($users)
		{
			vB_Upgrade::createAdminSession();

			$messageLibrary = vB_Library::instance('Content_Privatemessage');
			$notificationLibrary = vB_Library::instance('Notification');
			$nodeLibrary = vB_Library::instance('node');
			$vmChannelId = $nodeLibrary->fetchVMChannel();
			$vmTypeid = vB_Types::instance()->getContentTypeID('vBForum_VisitorMessage');

			$notifications = array();

			$recipients = array();
			foreach($users AS $user)
			{

				$userReceivesNotification = ( $bf_masks['general_vm'] & $user['notification_options'] );
				if (!$userReceivesNotification)
				{
					continue;
				}

				if ($user['vmunreadcount'] > 0)
				{
					// fetch last N visitor messages
					$lastVM = vB::getDbAssertor()->assertQuery(
						'vBInstall:fetchImportedVMNodes',
						array(
							'recipient' => $user['userid'],
							'vmChannelId' => $vmChannelId,
							'vmTypeId' => $vmTypeid,
							'vmunreadcount' => $user['vmunreadcount'],
						)
					);

					if ($lastVM)
					{
						foreach ($lastVM AS $node)
						{
							$recipients[$node['setfor']] = $node['setfor'];
							// Group by recipient & sender. Prevent subsequent, older ones from the same sender from overwriting newer ones.
							$key = $node['setfor'] . "_" . $node['userid'];
							if (!isset($notifications[$key]))
							{
								$notifications[$key] = array(
									'sentbynodeid' => $node['nodeid'],
								);
							}
						}
					}
				}
			}

			foreach ($notifications AS $notificationData)
			{
				$notificationLibrary->triggerNotificationEvent('new-visitormessage', $notificationData, array());
			}
			$notificationLibrary->insertNotificationsToDB();

			// set unreadcount to 0. Otherwise, re-running this step will keep adding the VM notifications.
			if (!empty($recipients))
			{
				$params = array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'userid' => $recipients, 	// key, condition
					'vmunreadcount' => 0,
				);
				vB::getDbAssertor()->assertQuery('user', $params);
			}
		}

		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat + 1, $endat));

		// See notes above $endat assignment above for more info. startat is exclusive, $endat is inclusive.
		return array('startat' => ($endat), 'maxvB5' => $maxvB5);
	}



	/*
	  Step 12 - Add Notification cleanup cron
	*/
	function step_12()
	{
		$this->add_cronjob(
			array(
				'varname'  => 'notificationcleanup',
				'nextrun'  => 0,
				'weekday'  => -1,
				'day'      => -1,
				'hour'     => 0,
				'minute'   => 'a:1:{i:0;i:20;}',
				'filename' => './includes/cron/notification_cleanup.php',
				'loglevel' => 1,
				'volatile' => 1,
				'product'  => 'vbulletin'
			)
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
