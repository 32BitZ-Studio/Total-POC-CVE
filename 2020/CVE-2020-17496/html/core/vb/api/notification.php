<?php if (!defined('VB_ENTRY')) die('Access denied.');
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ?2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html # ||
|| #################################################################### ||
\*======================================================================*/

/**
 * vB_Api_Notification
 *
 * @package vBLibrary
 * @access public
 */
class vB_Api_Notification extends vB_Api
{
	/**
	 *	DB Assertor object
	 */
	protected $assertor;

	/**
	 * Instance of vB_Library_Notification
	 */
	protected $library;



	protected function __construct()
	{
		parent::__construct();
		$this->assertor = vB::getDbAssertor();

		$this->library = vB_Library::instance('Notification');
	}


	/**
	 * Return current user's notifications from DB.
	 *
	 * @param	Array	$data	@see vB_Library_Notification::fetchNotificationsForCurrentUser()
	 *
	 * @return	Array	@see vB_Library_Notification::fetchNotificationsForCurrentUser()
	 *
	 * @throws vB_Exception_Api('not_logged_no_permission')		If user is not logged in
	 */
	public function fetchNotificationsForCurrentUser($data = array())
	{
		$userid = vB::getCurrentSession()->get('userid');

		if (!intval($userid))
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}

		$data['showdetail'] = vB::getUserContext()->hasPermission('genericpermissions', 'canseewholiked');

		$notifications = vB_Library::instance('notification')->fetchNotificationsForCurrentUser($data);
		return $notifications;
	}

	/**
	 * Updates all notifications owned by user and marks them as read (sets the lastreadtime to current time).
	 *
	 * @param	Int 		$userid			Optional user who owns the $readIds. Currently unused.
	 *
	 * @return	Array	Results data including the following type & keys:
	 *			- Int		'affected_rows'		Number of rows affected by update query
	 *
	 * @throws vB_Exception_Api('no_permission')	If current user does not have permission to read the specified
	 *												user's notifications.
	 */
	public function dismissAllNotifications($userid = false)
	{
		$currentUserid = vB::getCurrentSession()->get('userid');
		// assuming we never have a userid = 0 / guest for this...
		if (empty($userid))
		{
			$userid = $currentUserid;
		}

		/*
		 *	In the future, we may want to allow admins to dismiss notifications for other users.
		 *	In that case, we'll check permissions below before just throwing an exception.
		 */
		if ($userid !== $currentUserid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$timeNow = vB::getRequest()->getTimeNow();

		/*
			vB_dB_Query_Update->execSQL() will either return the # of affected rows, or
			throw an exception.
		*/
		$result = $this->assertor->assertQuery(
			'vBForum:notification',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'recipient', 'value' => $userid, 	'operator' =>  vB_dB_Query::OPERATOR_EQ),
				),
				'lastreadtime' => $timeNow,	// Note, this will always reset the "lastreadtime" for *all* notifications to current, even those that were already read.
			)
		);

		return array(
			'affected_rows' => $result,
		);
	}

	/**
	 * Updates the specified notificationids to mark them as read, and returns a single "next" notification based
	 * on the filter parameters.
	 *
	 * @param	Int|Int[]	$readIds		Integer(s) notificationid(s) being dismissed.
	 * @param	Int|Int[]	$idsOnPage		Notifications on the current page.
	 * @param	Array		$filterParams	@see vB_Library_Notification::fetchNotificationsForCurrentUser(),
	 *										$data param. If empty or if $skipFetch is true, the function will
	 *										skip fetching the "next" notification.
	 * @param	Bool 		$skipFetch		Default false. If true or if $filterParams is empty, the function
	 *										will skip fetching the "next" notification.
	 * @param	Int 		$userid			Optional user who owns the $readIds. Currently unused.
	 *
	 * @return	Array	Results data including the following type & keys:
	 *			- String	'insertNotification'	Rendered template HTML string for a notification row that should
	 *												be inserted into the DOM
	 *			- Int		'affected_rows'		Number of rows affected by update query
	 *			- String	'info'				''|'fetch_skipped'|'page_empty'	If not empty string, indicates the
	 *											reason API returned early.
	 *			- Int	'lastsenttime'			Lastsenttime of the notification, to be used by the frontend code
	 *											for sorting in the future.
	 *
	 * @throws vB_Exception_Api('no_permission')	If current user does not have permission to read the specified
	 *												user's notifications.
	 */
	public function dismissNotification($readIds, $idsOnPage = array(), $filterParams = array(), $skipFetch = false, $userid = false)
	{
		$currentUserid = vB::getCurrentSession()->get('userid');
		// assuming we never have a userid = 0 / guest for this...
		if (empty($userid))
		{
			$userid = $currentUserid;
		}

		/*
		 *	In the future, we may want to allow admins to dismiss notifications for other users.
		 *	In that case, we'll check permissions below before just throwing an exception.
		 */
		if ($userid !== $currentUserid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$timeNow = vB::getRequest()->getTimeNow();

		/*
			vB_dB_Query_Update->execSQL() will either return the # of affected rows, or
			throw an exception.
		*/
		$result = $this->assertor->assertQuery(
			'vBForum:notification',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'recipient', 'value' => $userid, 	'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'notificationid', 'value' => $readIds, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
				),
				'lastreadtime' => $timeNow,
			)
		);

		if (empty($filterParams))
		{
			$skipFetch = true;
		}

		// this is used for bulk dismissals, since we will be reloading the page most likely
		// and don't need to fetch the next single notification.
		if ($skipFetch)
		{
			return array(
				'insertNotification' => '',
				'affected_rows' => $result,
				'info'	=> 'fetch_skipped'
			);
		}


		// We need to fetch a notification to insert into the current page.
		$filterParams['skipIds'] = $idsOnPage;
		// todo may want to add a "fetch this many" param since readIds may be more than 1, in case we want to
		// update our frontend to do auto-loading for dismissing the page (currently we just do location.reload())
		$notification = vB_Library::instance('Notification')->fetchNotificationsForCurrentUser($filterParams);

		if (empty($notification))
		{
			return array(
				'insertNotification' => '',
				'affected_rows' => $result,
				'info'	=> 'page_empty'
			);
		}

		// pop it out. We're only expecting 1 notification array at most.
		$notification = reset($notification);
		$template = new vB5_Template('privatemessage_notificationdetail');
		$template->register('message', $notification);
		$template->register('messageid', $notification['notificationid']);
		$template->register('showCheckbox', 0);
		$template = $template->render();

		return array(
			'insertNotification' => $template,
			'affected_rows' => $result,
			'lastsenttime'	=> $notification['lastsenttime'],
			'info'	=> ''
		);
	}

	/**
	 * Deletes specified notificationds, but only if it's owned by the current user.
	 * Use the library's deleteNotification() function to ignore ownership.
	 *
	 * @param	Int|Int[]	$notificationids	Array of notificationids to delete.
	 * @param	Int			$userid				Optional. User who owns the specified notificationids. Currently
	 *											not supported.
	 *
	 * @throws vB_Exception_Api('no_permission')	If current user does not have permission to delete the specified
	 *												user's notifications.
	 */
	public function deleteNotification($notificationids, $userid = false)
	{
		$currentUserid = vB::getCurrentSession()->get('userid');
		// assuming we never have a userid = 0 / guest for this...
		if (empty($userid))
		{
			$userid = $currentUserid;
		}

		/*
		 *	In the future, we may want to allow admins to delete notifications for other users.
		 *	In that case, we'll check permissions below before just throwing an exception.
		 */
		if ($userid !== $currentUserid)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$this->assertor->assertQuery(
			'vBForum:notification',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => array (
					'recipient' => $userid,
					'notificationid' => $notificationids
				)
			)
		);

	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # SVN: $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
