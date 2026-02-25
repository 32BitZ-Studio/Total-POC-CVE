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
 * vB_Api_Content_Event
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Content_Event extends vB_Api_Content_Text
{
	//override in child- the text name
	protected $contenttype = 'vBForum_Event';

	//The table for the type-specific data.
	protected $tablename = array('event', 'text');

	//Is text required for this content type?
	protected $textRequired = false;

	/**
	 * Constructor, cannot be instantiated externally
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Event');
	}


	/**
	 * Adds a new node.
	 *
	 * @param  Array   $data       Array of field => value pairs which define the record.
	 * @param  Array   $options    Array of options for the content being created. See parent:add()
	 *
	 * @return int   the new nodeid
	 */
	public function add($data, $options = array())
	{
		// at the moment only starters are allowed to be events.
		$parent = vB_Library::instance('node')->getNodeBare($data['parentid']);
		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		if ($parent['contenttypeid'] != $channelTypeId)
		{
			throw new vB_Exception_Api('event_node_not_starter');
		}

		$data = $this->library->checkEventData($data);

		return parent::add($data, $options);
	}

	/**
	 * Updates a record
	 *
	 * @param  int     $nodeid   Nodeid to update
	 * @param  Array   $data     Array of field => value pairs which define the record.
	 *
	 * @return bool
	 */
	public function update($nodeid, $data)
	{
		// $withJoinableContent = true so we get the event-table data for checkEventData()
		$existing = vB_Library::instance('node')->getNode($nodeid, false, true);
		// at the moment only starters are allowed to be events.
		if ($existing['starter'] != $nodeid)
		{
			throw new vB_Exception_Api('event_node_not_starter');
		}

		$data = $this->library->checkEventData($data, $existing);
		/*
			TODO: should we do things like check if $nodeid is of this contenttype?
		 */

		return parent::update($nodeid, $data);
	}

	/**
	 * Cleans the input in the $data array, directly updating $data.
	 *
	 * @param mixed     Array of fieldname => data pairs, passed by reference.
	 * @param int|false Nodeid of the node being edited, false if creating new
	 */
	public function cleanInput($data, $nodeid = false)
	{
		$data = parent::cleanInput($data, $nodeid);

		$unclean = $data;
		$clean = vB::getCleaner()->cleanArray($unclean, array(
			'location' => vB_Cleaner::TYPE_STR,	// DO NOT USE IN HTML WITHOUT ESCAPING!!
			'eventstartdate' => vB_Cleaner::TYPE_UNIXTIME,
			'eventenddate' => vB_Cleaner::TYPE_UNIXTIME,
			'eventhighlightid' => vB_Cleaner::TYPE_UINT,
		));

		// check if the user has permission to use this event highlight
		if ($clean['eventhighlightid'] > 0)
		{
			// query all the event highlights that the current user can apply to an event
			$eventhighlights = vB_Api::instance('eventhighlight')->getEventHighlightsUser();
			$found = false;

			foreach ($eventhighlights AS $eventhighlight)
			{
				if ($eventhighlight['eventhighlightid'] == $clean['eventhighlightid'])
				{
					$found = true;
					break;
				}
			}

			if (!$found)
			{
				$clean['eventhighlightid'] = 0;
			}
		}

		if ($nodeid)
		{
			// updating existing event

			// if one of these items is not specified at all, then don't change
			// it in the database

			if (isset($data['location']))
			{
				$data['location'] = trim($clean['location']);
			}

			if (isset($data['eventstartdate']))
			{
				$data['eventstartdate'] = $clean['eventstartdate'];
			}

			if (isset($data['eventenddate']))
			{
				$data['eventenddate'] = $clean['eventenddate'];
			}

			if (isset($data['eventhighlightid']))
			{
				$data['eventhighlightid'] = $clean['eventhighlightid'];
			}
		}
		else
		{
			// adding new event
			$data['location'] = trim($clean['location']);
			$data['eventstartdate'] = $clean['eventstartdate'];
			$data['eventenddate'] = $clean['eventenddate'];
			$data['eventhighlightid'] = $clean['eventhighlightid'];
		}

		return $data;
	}

	/**
	 * Generate the default start and end timestamps for when creating a new Event.
	 * The start timestamp is the next hour past the current time (no minutes or seconds),
	 * and the end timestamp is one hour past the start timestamp.
	 *
	 * @return array Array with start_timestamp and end_timestamp.
	 */
	public function getDefaultEventTimestamps()
	{
		$timenow = vB::getRequest()->getTimeNow();

		// get the next nearest even hour, from 5:00:01 to 5:59:59, that would be 6:00:00
		$secondsPastTheHour = $timenow % 3600;
		$nextEvenHour = $timenow - $secondsPastTheHour + 3600;

		return array(
			'start_timestamp' => $nextEvenHour,
			// end_timestamp is one hour after the start by default
			// keep this in sync with the 1 hour specified in
			// vBulletin.contentEntryBox.handleEventStartEndTimeChanges()
			// and the contententry_panel_event template
			'end_timestamp' => $nextEvenHour + 3600,
		);
	}

	/*
	 * Takes a UTC/GMT unix timestamp and splits it into human readable formatted array of year, month, day, hour, minute, second
	 * and ampm for the specified user's timezone offset.
	 *
	 * @param   int   $timestamp
	 * @param   bool  $ampm         (Optional) If true, use the 12-hour format instead of the default 24-hour format, and show the 'ampm' info.
	 * @param   int   $userid       (Optional) Use specified user's timezone offset. If not set, it will use the current user's offset.
	 * @param   bool  $skipOffset   (Optional) Skip adjusting for user's timezone offset.
	 */
	public function splitUnixtimestamp($timestamp = '', $ampm = false, $userid = false, $skipOffset = false, $ignoreDST = true)
	{
		if (empty($timestamp))
		{
			// do now.
			$timestamp = vB::getRequest()->getTimeNow();
		}
		$timestamp = intval($timestamp);

		if (!$skipOffset)
		{
			if (empty($userid))
			{
				$userid = false; // fetchTimeOffset() will grab the current user if $userid param is boolean false.
			}
			$offset = vB_Api::instanceInternal('user')->fetchTimeOffset(false, $userid, $ignoreDST);
			// Take GMT timestamp and convert it to current user's. This is kind of a hackaround...
			$timestamp += $offset;
		}

		/*
			We use gmdate() instead of date() so we don't have to set & unset the date_default_timezone.
			Since we just added the user's timezone offset above, we need to get the GMT/UTC time to get the
			"correct" offset time. Otherwise we'd use the user's offset to actually set the default timezone
			and use date() instead.
		 */

		$splitarray = array(
			'year' => gmdate("Y", $timestamp),
			'month' => gmdate("m", $timestamp),
			'day' => gmdate("d", $timestamp),
			'hour' => gmdate("H", $timestamp),
			'minute' => gmdate("i", $timestamp),
			'second' => gmdate("s", $timestamp),
			//'timezone_offset' => gmdate("Z T", $timestamp),

			// keep datepickerstr in sync with the string formatted in
			// vBulletin.contentEntryBox.handleEventStartEndTimeChanges()
			'datepickerstr' => gmdate("m/d/Y H:i", $timestamp),
		);

		/*
		$splitarray = getdate($timestamp);
		*/
		if ($ampm)
		{
			// This used to be used when we had the "date" & "time" inputs/displays separate in early Event prototype.
			// We no longer use this, because we use datepicker that combines both (see datepickerstr above & in templates/js)
			$splitarray['hour'] = gmdate("h", $timestamp);
			$splitarray['ampm'] = gmdate("a", $timestamp);
		}


		return array('datetime' => $splitarray);
	}

	public function getEventDateTimeStr($timestamp, $allday, $ignoreDST)
	{
		$userAPI = vB_Api::instance("user");
		// based on template runtime datetime() function & vB_Api_vB4_CMS
		$userinfo = $userAPI->fetchUserinfo();
		$options = vB::getDatastore()->getValue('options');
		if ($userinfo['lang_dateoverride'] != '')
		{
			$dateformat = $userinfo['lang_dateoverride'];
		}
		else
		{
			$dateformat = $options['dateformat'];
		}

		$timeformat = "";
		if (!$allday)
		{
			if ($userinfo['lang_timeoverride'] != '')
			{
				$timeformat = $userinfo['lang_timeoverride'];
			}
			else
			{
				$timeformat = $options['timeformat'];
			}
			$timeformat = " " . $timeformat;
		}

		$format = $dateformat . $timeformat;
		$userid = isset($userinfo['userid']) ? $userinfo['userid'] : false;

		return $userAPI->unixtimestampToUserDateString($timestamp, $userid, $format, $ignoreDST);
	}

	/*
	 * Get the unixtimestamp for the beginning or end of day (or whatever hour-minute-seconds string
	 * is specified). Passes through to the library function.
	 *
	 * @param	int    $timestamp   Unix timestamp of the particular day to get the end of day timestmap for.
	 * @param	int    $userid      (Optional) userid to get the time for. Use current user if false.
	 * @param	string $hmsString   (Optional) "Hour:Minutes:Seconds AM|PM" string if not trying to get the
	 *			                    end of the day (11:59:59 PM).
	 * @param	bool   $ignoreDST   (Optional) False if conversion needs to take DST offset into account.
	 *
	 * @return	array('unixtime' => int)
	 */
	public function getEndOfDayUnixtime($timestamp, $userid = false, $hmsString = "11:59:59 PM", $ignoreDST = true)
	{
		// Just a pass through function for the library function.
		return array(
			"unixtime" => $this->library->getEndOfDayUnixtime($timestamp, $userid, $hmsString, $ignoreDST),
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
