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

class vB_Upgrade_518a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '518a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.8 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.7';

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

	function step_1($data = NULL)
	{
		$this->long_next_step();
	}

	/*
	 *	step 2: remove old notifications with deleted recipients
	 */
	function step_2($data = NULL)
	{
		$assertor = vB::getDbAssertor();

		$batchSize = 10000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['518a1']['removing_recipientless_notifications']);
		}

		$rows = $assertor->getRows(
			'vBInstall:fetchNotificationsWithDeletedRecipients',
			array(
				'batchsize'	=> $batchSize
			)
		);
		if (empty($rows))
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			$this->long_next_step();
			return;
		}
		else
		{
			$ids = array();
			$start = reset($rows);
			$start = $start['notificationid'];
			$end = null;
			foreach($rows AS $row)
			{
				$end = $ids[] = $row['notificationid'];
			}

			vB::getDbAssertor()->assertQuery(
				'vBForum:notification',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'notificationid' => $ids
				)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
	}

	/*
	 *	step 3: Delete any userrelation notifications sent from a deleted
	 *		user.
	 */
	function step_3($data = NULL)
	{
		$assertor = vB::getDbAssertor();

		$batchSize = 10000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['518a1']['removing_senderless_notifications_userrelation']);
		}

		$typesByName = vB_Library::instance('notification')->getNotificationTypes();

		$typeids = array(
			$typesByName[vB_Notification_UserRelation_SenderAcceptedFollowRequest::TYPENAME]['typeid'],
			$typesByName[vB_Notification_UserRelation_SenderIsfollowing::TYPENAME]['typeid']
		);

		$rows = $assertor->getRows(
			'vBInstall:fetchNotificationsWithDeletedSendersOfTypesX',
			array(
				'batchsize'	=> $batchSize,
				'typeids' => $typeids,
			)
		);
		if (empty($rows))
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			$this->long_next_step();
			return;
		}
		else
		{
			$ids = array();
			$start = reset($rows);
			$start = $start['notificationid'];
			$end = null;
			foreach($rows AS $row)
			{
				$end = $ids[] = $row['notificationid'];
			}

			vB::getDbAssertor()->assertQuery(
				'vBForum:notification',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'notificationid' => $ids
				)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
	}

	// step 4 update VMs
	function step_4($data = NULL)
	{
		/*
			VM logic is complex, so let's just fetch 1 deleted sender at a time and go through the vB_Notification_VisitorMessage class
		 */
		$assertor = vB::getDbAssertor();

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['518a1']['removing_senderless_notifications_vm']);
		}

		$typesByName = vB_Library::instance('notification')->getNotificationTypes();

		$vmTypeid = $typesByName[vB_Notification_VisitorMessage::TYPENAME]['typeid'];

		$row = $assertor->getRow(
			'vBInstall:fetchDeletedSenderForNotificationsOfTypeX',
			array(
				'typeid' => $vmTypeid,
			)
		);
		if (empty($row))
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			$this->long_next_step();
			return;
		}
		else
		{
			vB_Notification_VisitorMessage::handleUpdateEvents('deleted_user', array('userid' => $row['sender']));

			$this->show_message(sprintf($this->phrase['version']['518a1']['updating_deleted_sender_x'], $row['sender']));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $row['sender']);
		}
	}

	// step 5 update non userrelation, nonvms to guest
	function step_5($data = NULL)
	{
		$assertor = vB::getDbAssertor();

		$batchSize = 10000;

		if (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['518a1']['updating_senderless_notifications_to_guest']);
		}

		$typesByName = vB_Library::instance('notification')->getNotificationTypes();

		$typeidsToSkip = array(
			$typesByName[vB_Notification_UserRelation_SenderAcceptedFollowRequest::TYPENAME]['typeid'],
			$typesByName[vB_Notification_UserRelation_SenderIsfollowing::TYPENAME]['typeid'],
			$typesByName[vB_Notification_VisitorMessage::TYPENAME]['typeid'],
		);

		$rows = $assertor->getRows(
			'vBInstall:fetchNotificationsWithDeletedSendersOfTypesNOTX',
			array(
				'batchsize'	=> $batchSize,
				'typeids' => $typeids,
			)
		);
		if (empty($rows))
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			$this->long_next_step();
			return;
		}
		else
		{
			$ids = array();
			$start = reset($rows);
			$start = $start['notificationid'];
			$end = null;
			foreach($rows AS $row)
			{
				$end = $ids[] = $row['notificationid'];
			}

			$assertor->assertQuery(
				'vBForum:notification',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'notificationid', 'value' => $ids, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
					),
					'sender' => 0,
				)
			);

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $start, $end));
			// startat not used, but we need to loop this step. Any other data you might pass through is not reliable due to
			// bugs w/ web interface
			return array('startat' => $end);
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/