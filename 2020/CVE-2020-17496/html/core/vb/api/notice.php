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
 * vB_Api_Notice
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Notice extends vB_Api
{
	/**
	 * @var vB_dB_Assertor
	 */
	protected $assertor;

	protected $disableFalseReturnOnly = array('fetch');


	protected function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
	}

	public function dismiss($noticeid)
	{
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		if (!$userinfo['userid'])
		{
			throw new vB_Exception_Api('no_permission');
		}

		$library = vB_Library::instance('notice');
		$noticecache = $library->getNoticeCache();
		if (!$noticecache[$noticeid]['dismissible'])
		{
			throw new vB_Exception_Api('notice_not_dismissible');
		}

		$this->assertor->assertQuery('vBForum:dismissnotice', array(
			'noticeid' => intval($noticeid),
			'userid' => $userinfo['userid'],
		));

		return true;
	}

	/**
	 * Fetch notices to be displayed
	 *
	 * @param int $channelid Current Channel ID
	 * @param array $ignore_np_notices Ignored non-persistent notice ids
	 * @return array Notices
	 */
	public function fetch($channelid = 0, $ignore_np_notices = array())
	{
		if ($channelid)
		{
			$channelapi = vB_Api::instanceInternal('content_channel');
			// This is to verify $channelid
			$channelapi->fetchChannelById($channelid);
		}

		$library = vB_Library::instance('notice');
		$noticecache = $library->getNoticeCache();

		$datastore = vB::getDatastore();
		$vboptions = $datastore->getValue('options');

		if(!is_array($ignore_np_notices))
		{
			$ignore_np_notices = array();
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$dimissedNotices = $this->assertor->getColumn('vBForum:noticedismissed', 'noticeid', array('userid' => $userinfo['userid']));

		$display_notices = array();
		foreach ($noticecache AS $noticeid => $notice)
		{
			//the criteria 'notice_x_not_displayed' is handled seperately because we need
			//to process all of the notices before "x is/is not displayed" becomes a
			//meaningful thing to talk about.

			//these aren't really criteria per se and they'll always be available
			if ($notice['persistent'] == 0 AND in_array($noticeid, $ignore_np_notices))
			{
				continue;
			}

			if ($notice['dismissible'] == 1 AND in_array($noticeid, $dimissedNotices))
			{
				continue;
			}

			if(!$this->validateCriteria($notice, $channelid, $userinfo, $vboptions))
			{
				continue;
			}

			$display_notices[$noticeid] = $noticeid;
		}

		// Now that we have the tentive list of what's displaying we could remove any
		// notices with the 'notice_x_not_displayed' criteria that point to notices that
		// are displaying.
		//
		// Note that this processing is subtly wrong because it doesn't take into account
		// the effect of the 'notice_x_not_displayed' itself.  So if you have notices
		// A, B, anc C and notice C is set to display when notice B doesn't and B is set
		// to display when A doesn't (and no other criteria for B and C) then B will display
		// when A doesn't and C will never display because B will always pass the above
		// filter and A will check that before B is removed.
		//
		// While this is wrong, it's not clear what right is.  Especially in the case where
		// we have cycles (A is set to display when B doesn't, B is set to display when A doesn't).
		// Both defining the behavior here and checking it get complicated very quickly and
		// I'm not sure that any users have noticed the problem in the first place.
		$remove_display_notices = array();
		foreach ($noticecache AS $noticeid => $notice)
		{
			if (isset($notice['notice_x_not_displayed']) AND isset($display_notices[intval($notice['notice_x_not_displayed'][0])]))
			{
				$remove_display_notices[$noticeid] = $noticeid;
			}
		}

		foreach ($remove_display_notices AS $noticeid)
		{
			unset($display_notices[$noticeid]);
		}

		$return = array();

		if ($display_notices)
		{
			foreach ($display_notices AS $display_notice)
			{
				$value = $noticecache[$display_notice];
				$value['notice_phrase_varname'] = "notice_{$display_notice}_html";
				$return[$display_notice] = $value;
			}
		}

		return $return;
	}

	private function validateCriteria($notice, $channelid, $userinfo, $vboptions)
	{
		$timeNow = vB::getRequest()->getTimeNow();

		if(isset($notice['in_usergroup_x']))
		{
			$conditions = $notice['in_usergroup_x'];
			if (!is_member_of($userinfo, intval($conditions[0])))
			{
				return false;
			}
		}

		if(isset($notice['not_in_usergroup_x']))
		{
			$conditions = $notice['not_in_usergroup_x'];
			if (is_member_of($userinfo, intval($conditions[0])))
			{
				return false;
			}
		}

		if(isset($notice['browsing_forum_x']))
		{
			$conditions = $notice['browsing_forum_x'];
			if (!$channelid OR $channelid != intval($conditions[0]))
			{
				return false;
			}
		}

		if(isset($notice['browsing_forum_x_and_children']))
		{
			$conditions = $notice['browsing_forum_x_and_children'];

			//if this isn't a channel specific page then we aren't viewing that channel
			if (!$channelid)
			{
				return false;
			}

			$checkforum = intval($conditions[0]);

			//if this channel is the one we are checking we don't really need to load the ancestors
			if($channelid != $checkforum)
			{
				//Need to think about this.  We don't want to generate it multiple times because it's
				//going to be the same for each chanel.  On the third hand, caching it in this class
				//is awkward because the value is different based on the channelid
				$parents = vB_Library::instance('node')->getParents($channelid);
				$parentids = array();
				foreach ($parents AS $parent)
				{
					if ($parent['nodeid'] != 1)
					{
						$parentids[] = $parent['nodeid'];
					}
				}

				if (!in_array($checkforum, $parentids))
				{
					return false;
				}
			}
		}

		if(isset($notice['no_visit_in_x_days']))
		{
			$conditions = $notice['no_visit_in_x_days'];
			if ($userinfo['lastvisit'] > ($timeNow - ($conditions[0] * 86400)))
			{
				return false;
			}
		}

		if(isset($notice['no_visit_in_x_days']))
		{
			$conditions = $notice['no_visit_in_x_days'];
			if ($userinfo['lastvisit'] > ($timeNow - ($conditions[0] * 86400)))
			{
				return false;
			}
		}

		if(isset($notice['has_never_posted']))
		{
			if ($userinfo['posts'] > 0)
			{
				return false;
			}
		}

		if(isset($notice['no_posts_in_x_days']))
		{
			$conditions = $notice['no_posts_in_x_days'];
			if ($userinfo['lastpost'] == 0 OR $userinfo['lastpost'] > ($timeNow - ($conditions[0] * 86400)))
			{
				return false;
			}
		}

		if(isset($notice['has_x_postcount']))
		{
			$conditions = $notice['has_x_postcount'];
			if (!$this->checkNoticeCriteriaBetween($userinfo['posts'], $conditions[0], $conditions[1]))
			{
				return false;
			}
		}

		if(isset($notice['has_x_reputation']))
		{
			$conditions = $notice['has_x_reputation'];
			if (!$this->checkNoticeCriteriaBetween($userinfo['reputation'], $conditions[0], $conditions[1]))
			{
				return false;
			}
		}

		if(isset($notice['has_x_infraction_points']))
		{
			$conditions = $notice['has_x_infraction_points'];
			if (!$this->checkNoticeCriteriaBetween($userinfo['ipoints'], $conditions[0], $conditions[1]))
			{
				return false;
			}
		}

		if(isset($notice['pm_storage_x_percent_full']))
		{
			$conditions = $notice['pm_storage_x_percent_full'];
			$pmquota = vB::getUserContext()->getLimit('pmquota');
			if(!$pmquota)
			{
				return false;
			}

			$pmboxpercentage = ($userinfo['pmtotal'] / $pmquota) * 100;
			if (!$this->checkNoticeCriteriaBetween($pmboxpercentage, $conditions[0], $conditions[1]))
			{
				return false;
			}
		}

		if(isset($notice['username_is']))
		{
			$conditions = $notice['username_is'];
			if (strtolower($userinfo['username']) != strtolower(trim($conditions[0])))
			{
				return false;
			}
		}

		if(isset($notice['is_birthday']))
		{
			if (substr($userinfo['birthday'], 0, 5) != vbdate('m-d', $timeNow, false, false))
			{
				return false;
			}
		}

		if(isset($notice['came_from_search_engine']))
		{
			if (!is_came_from_search_engine())
			{
				return false;
			}
		}

		if(isset($notice['style_is_x']))
		{
			$conditions = $notice['style_is_x'];
			$styleid = vB::getCurrentSession()->get('styleid');
			if ($styleid != intval($conditions[0]))
			{
				return false;
			}
		}

		if(isset($notice['in_coventry']))
		{
			$globalIgnore = preg_split('#\s+#', $vboptions['globalignore'], -1, PREG_SPLIT_NO_EMPTY);
			if (!in_array($userinfo['userid'], $globalIgnore))
			{
				return false;
			}
		}

		if(isset($notice['has_x_reputation']))
		{
			$conditions = $notice['has_x_reputation'];
			if (!$this->checkNoticeCriteriaBetween($userinfo['reputation'], $conditions[0], $conditions[1]))
			{
				return false;
			}
		}


		if(isset($notice['is_date_range']))
		{
			$conditions = $notice['is_date_range'];

			//we'll use a string compare because timestamps are inherently different days in different timezones
			//and we are entering "dates".  When the notice display may be different depending on the viewing user.
			$start = $this->formatCriteriaDates($conditions[0]);
			$end = $this->formatCriteriaDates($conditions[1]);
			$tzflag = $conditions[2];

			//if the dates are backwards let's adjust to a valid range.
			if($end < $start)
			{
				$temp = $start;
				$start = $end;
				$end = $temp;
			}

			//tzflag is 0 = usertimezone, 1 = UTC
			if($tzflag)
			{
				$now = gmdate('Y-m-d', $timeNow);
			}
			else
			{
				$now = vbdate('Y-m-d', $timeNow, false, false);
			}

			if(!$this->checkNoticeCriteriaBetweenString($now, $start, $end))
			{
				return false;
			}
		}

		if(isset($notice['is_time']))
		{
			$conditions = $notice['is_time'];

			$start_time = array();
			$end_time = array();

			if (preg_match('#^(\d{1,2}):(\d{2})$#', $conditions[0], $start_time) AND preg_match('#^(\d{1,2}):(\d{2})$#', $conditions[1], $end_time))
			{
				if (empty($conditions[2])) // user timezone
				{
					$start = mktime($start_time[1], $start_time[2]) + $userinfo['servertimediff'];
					$end   = mktime($end_time[1], $end_time[2]) + $userinfo['servertimediff'];
					$now = time();
				}
				else // utc
				{
					$start = gmmktime($start_time[1], $start_time[2]);
					$end   = gmmktime($end_time[1], $end_time[2]);
					$now   = gmmktime();
				}

				//if we end earlier than we start, interpret that as a range that overlaps
				//midnight.  However we need account for the range that starts yesterday
				//as well as the one that starts today.  If we are currently less than the
				//start time we can only be in yesterday's range.  If we are currently greater
				//than the start time we can only be in today's range.  We can simplify this
				//a little since if we are greater than the start time we *are* in todays range
				//since we've established that the end time is tomorrow.  However given the
				//negation of the logic below (we skip this case if we aren't in the range)
				//it's not clear that checking the intervals directly instead of doing the
				//math is going to overall simply the code and it could obscure what we are doing.
				if ($end < $start)
				{
					if ($now < $start)
					{
						$start = $start - (24 * 60 * 60);
					}
					else
					{
						$end = $end + (24 * 60 * 60);
					}
				}

				if ($now < $start OR $now > $end)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		return true;
	}

	/**
	 *	Get a data for a notice 
	 *
	 *	@param int|array $noticeid
	 *	@return array -- standard success array
	 */
	public function getNotice($noticeid)
	{
		//for now this is only used in the admincp and it's not clear if we want just anybody
		//to be able to pull inforamtion on notices that may or may not be active.
		$this->checkHasAdminPermission('canadminnotices');
		$noticeid = vB::getCleaner()->clean($noticeid, vB_Cleaner::TYPE_UINT);
		$notice = vB_Library::instance('notice')->getNotice($noticeid);
		return array ('notice' => $notice);
	}


	/**
	 *	Delete notices
	 *
	 *	@param int|array $noticeid
	 *	@return array -- standard success array
	 */
	public function delete($noticeid)
	{
		$this->checkHasAdminPermission('canadminnotices');
		$noticeid = vB::getCleaner()->clean($noticeid, (is_array($noticeid) ? vB_Cleaner::TYPE_ARRAY_UINT : vB_Cleaner::TYPE_UINT));
		$success = vB_Library::instance('notice')->delete($noticeid);
		return array ('success' => $success);
	}

	/**
	 *	Save a notice
	 *
	 *	@param array $data
	 *		int noticeid (optional) -- if given update the notice otherwise save a new one.
	 *		string title
	 *		int displayorder
	 *		boolean active
	 *		boolean persistent
	 *		boolean dismissible
	 *		array criteria -- criteriaid => array(
	 *			string $condition1
	 *			string $condition2
	 *			string $condition3
	 *		)
	 *	@return array -- standard success array
	 */
	public function save($data)
	{
		$this->checkHasAdminPermission('canadminnotices');

		$types = array(
			'title' => vB_Cleaner::TYPE_NOHTML,
			'text' => vB_Cleaner::TYPE_STR,
			'displayorder' => vB_Cleaner::TYPE_INT,
			'active' => vB_Cleaner::TYPE_BOOL,
			'persistent' => vB_Cleaner::TYPE_BOOL,
			'dismissible' => vB_Cleaner::TYPE_BOOL,
			'criteria' => vB_Cleaner::TYPE_ARRAY,
			'noticeoptions' => vB_Cleaner::TYPE_ARRAY_BOOL,
		);

		//if we set this as a param to clean it will end up set in the output value
		//which we probably don't want
		if(isset($data['noticeid']))
		{
			$types['noticeid'] = vB_Cleaner::TYPE_UINT;
		}

		//clean the data and ensure that no unexpected fields are passed through
		//to the library
		$data = vB::getCleaner()->cleanArray($data, $types);
		$noticeid = vB_Library::instance('notice')->save($data);

		return array('noticeid' => $noticeid);
	}

	/**
	 *	Take the date in the UI format (m-d-Y) and convert to a format we can compare
	 *	(Y-m-d).  We'll also ensure that the day and month have leading zeros
	 *
	 *	@param string $date
	 *	@return string|bool The date if the input is valid or false if it is not.
	 */
	private function formatCriteriaDates($date)
	{
		//let's be a little flexible about how this gets formatted.
		$separators = array('-', '/');

		$found = false;
		$parts = array();
		foreach($separators AS $separator)
		{
			$parts = explode($separator, $date);
			if(count($parts) == 3)
			{
				$found = true;
				break;
			}
		}

		if (!$found)
		{
			return false;
		}

		list($day, $month, $year) = $parts;

		$monthlen = strlen($month);
		$daylen = strlen($day);
		$yearlen = strlen($year);

		if(($monthlen < 1 OR $monthlen > 2) OR ($daylen < 1 OR $daylen > 2) OR $yearlen != 4)
		{
			return false;
		}

		if($monthlen == 1)
		{
			$month = '0' . $month;
		}

		if($daylen == 1)
		{
			$day = '0' . $month;
		}


		return "$year-$month-$day";
	}

	private function checkNoticeCriteriaBetweenString($value, $cond1, $cond2)
	{
		if ($cond1 === '' OR $cond1 === false)
		{
			// no value for first condition, treat as <= $cond2
			return ($value <= $cond2);
		}
		else if ($cond2 === '' OR $cond1 === false)
		{
			// no value for second condition, treat as >= $cond1
			return ($value >= $cond2);
		}
		else
		{
			// check that value is between (inclusive) the two given conditions
			return ($value >= $cond1 AND $value <= $cond2);
		}
	}

	/**
	* Checks if the specified criteria is between 2 values.
	* If either bound is the empty string, it is ignored.
	* Bounds are inclusive on either side (>= / <=).
	*
	* @param	integer			Value to check
	* @param	string|integer	Lower bound. If === '', ignored.
	* @param	string|integer	Upper bound. If === '', ignored.
	*
	* @return	boolean			True if between
	*/
	private function checkNoticeCriteriaBetween($value, $cond1, $cond2)
	{
		if ($cond1 === '')
		{
			// no value for first condition, treat as <= $cond2
			return ($value <= intval($cond2));
		}
		else if ($cond2 === '')
		{
			// no value for second condition, treat as >= $cond1
			return ($value >= intval($cond2));
		}
		else
		{
			// check that value is between (inclusive) the two given conditions
			return ($value >= intval($cond1) AND $value <= intval($cond2));
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103168 $
|| #######################################################################
\*=========================================================================*/
