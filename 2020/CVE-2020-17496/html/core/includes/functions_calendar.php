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

global 	$_CALENDAROPTIONS,
		$_CALENDARHOLIDAYS,
		$months,
		$days,
		$period,
		$reminder;

// Defined constants used for calendars
$_CALENDAROPTIONS = array(
	'showbirthdays' => 1,
	'showweekends'  => 4,
	'allowhtml'     => 8,
	'allowbbcode'   => 16,
	'allowimgcode'  => 32,
	'allowsmilies'  => 64,
	'weekly'        => 128,
	'yearly'        => 256,
	'showupcoming'  => 512, # Display upcoming events from this calendar on the front page
);

// Defined constants for pre-defined holidays
$_CALENDARHOLIDAYS = array(
	'easter'         => 1,
	'good_friday'    => 2,
	'palm_sunday'    => 4,
	'ash_wednesday'  => 8,
	'pentecost'      => 16,
	'mardi_gras'     => 32,
	'corpus_christi' => 64,
);

$months = array(
	1 => 'january',
	2 => 'february',
	3 => 'march',
	4 => 'april',
	5 => 'may',
	6 => 'june',
	7 => 'july',
	8 => 'august',
	9 => 'september',
	10 => 'october',
	11 => 'november',
	12 => 'december'
);

$days = array(
	1 => 'sunday',
	2 => 'monday',
	3 => 'tuesday',
	4 => 'wednesday',
	5 => 'thursday',
	6 => 'friday',
	7 => 'saturday'
);

$period = array(
	1 => 'date_first',
	'second',
	'third',
	'fourth',
	'date_last'
);

$reminders = array(
	'3600'   => 'one_hour',
	'7200'   => 'two_hours',
	'10800'  => 'three_hours',
	'14400'  => 'four_hours',
	'21600'  => 'six_hours',
	'28800'  => 'eight_hours',
	'43200'  => 'twelve_hours',
	'64800'  => 'eighteen_hours',
	'86400'  => 'one_day',
	'172800' => 'two_days',
	'259200' => 'three_days',
);


// ###################### Start getevent #######################
function cache_event_info(&$event, $month, $day, $year, $adjust = 1, $cache = true)
{
	static $foundday, $foundevent, $foundholiday, $e;

	global $vbulletin;

	$eventid = $event['eventid'];

	if (isset($event['holidayid']) AND $event['holidayid'] AND $foundholiday["$month-$day-$year"]["$event[holidayid]"] AND $cache)
	{
		return true;
	}
	else if ($eventid AND $foundevent["$month-$day-$year"]["$eventid"] AND $cache)
	{
		return true;
	}

	if ((empty($e["$eventid"]) OR !$cache) AND !$event['singleday'])
	{
		$e["$eventid"]['startday'] = gmmktime(0, 0, 0, gmdate('n', $event['dateline_from_user']), gmdate('j', $event['dateline_from_user']), gmdate('Y', $event['dateline_from_user']));
		$e["$eventid"]['startmonth'] = gmmktime(0, 0, 0, gmdate('n', $event['dateline_from_user']), 1, gmdate('Y', $event['dateline_from_user']));
		$e["$eventid"]['endday'] = gmmktime(0, 0, 0, gmdate('n', $event['dateline_to_user']), gmdate('j', $event['dateline_to_user']), gmdate('Y', $event['dateline_to_user']));
	}

	$todaystart = gmmktime(0, 0, 0, $month, $day, $year);
	$todaymid = gmmktime(12, 0, 0, $month, $day, $year);
	$todayend = gmmktime(23, 59, 59, $month, $day, $year);
	$thismonth = gmmktime(0, 0, 0, $month, 1, $year);

	if ($event['singleday'])
	{
		if ("$month-$day-$year" == gmdate('n-j-Y', $event['dateline_from']))
		{
			return true;
		}
	}

	if ($event['dateline_to_user'] < $todaystart OR $event['dateline_from_user'] > $todayend)
	{
		return false;
	}

	if ($event['recurring'])
	{ // this is a recurring event
		if ($event['recurring'] == 1)
		{
			if ($event['recuroption'] == 0 OR ($todaystart - $e["$eventid"]['startday']) % (86400 * $event['recuroption']))
			{
				return false;
			}
			else
			{
				return true;
			}
		}
		else if ($event['recurring'] == 2)
		{
			if (gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust)
			{
				if ($event['dateline_from_user'] > $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$todaymid -= 86400;
				}
				else
				{
					$todaymid += 86400;
				}
			}

			if (gmdate('w', $todaymid) < 1 OR gmdate('w', $todaymid) > 5)
			{
				return false;
			}
		}
		else if ($event['recurring'] == 3)
		{
			$monthbit = explode('|', $event['recuroption']);
			$weekrep = $monthbit[0];
			if ($weekrep == 0)
			{
				return false;
			}

			$daysfromstart = ($todaystart - $e["$eventid"]['startday']) / 86400;
			$week = intval($daysfromstart / 7);
			if ($week % $weekrep)
			{
				return false;
			}

			if ($monthbit[1] & 1)
			{
				$haveday[0] = 1;
			}
			else
			{
				unset($haveday[1]);
			}
			if ($monthbit[1] & 2)
			{
				$haveday[1] = 1;
			}
			else
			{
				unset($haveday[2]);
			}
			if ($monthbit[1] & 4)
			{
				$haveday[2] = 1;
			}
			else
			{
				unset($haveday[3]);
			}
			if ($monthbit[1] & 8)
			{
				$haveday[3] = 1;
			}
			else
			{
				unset($haveday[4]);
			}
			if ($monthbit[1] & 16)
			{
				$haveday[4] = 1;
			}
			else
			{
				unset($haveday[5]);
			}
			if ($monthbit[1] & 32)
			{
				$haveday[5] = 1;
			}
			else
			{
				unset($haveday[6]);
			}
			if ($monthbit[1] & 64)
			{
				$haveday[6] = 1;
			}
			else
			{
				unset($haveday[7]);
			}

			if (gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust)
			{
				if ($event['dateline_from_user'] > $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$todaymid -= 86400;
				}
				else
				{
					$todaymid += 86400;
				}
			}

			$dayofweek = gmdate('w', $todaymid);

			if (!$haveday["$dayofweek"])
			{
				return false;
			}
		}
		else if ($event['recurring'] == 4)
		{
			$monthbit = explode('|', $event['recuroption']);
			$monthrep = $monthbit[1];

			if ($monthbit[0] == 0 OR $monthbit[1] == 0)
			{
				return false;
			}

			if (gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust)
			{
				if ($event['dateline_from_user'] > $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$monthbit[0]++;
					if ($day == 1)
					{
						$todaymid -= 86400;
					}
					if ($monthbit[0] > gmdate('t', $todaymid))
					{
						$monthbit[0] = 1;
					}
				}
				else
				{
					$monthbit[0]--;
					if ($day == gmdate('t', $todaymid))
					{
						$todaymid += 86400;
					}
					if ($monthbit[0] == 0)
					{
						$monthbit[0] = gmdate('t', $todaymid);
					}
				}
			}

			if ($day != $monthbit[0])
			{
				return false;
			}

			if (empty($e["$eventid"]['currentmonth']))
			{
				if ($e["$eventid"]['startday'] > gmmktime(0, 0, 0, gmdate('n', $event['dateline_from_user']), $monthbit[0], gmdate('Y', $event['dateline_from_user'])))
				{
					$e["$eventid"]['currentmonth'] =  gmmktime(0, 0, 0, gmdate('n', $event['dateline_from_user']) + 1, 1, gmdate('Y', $event['dateline_from_user']));
				}
				else
				{
					$e["$eventid"]['currentmonth'] = $e["$eventid"]['startmonth'];
				}
			}

			while ($e["$eventid"]['currentmonth'] != $thismonth)
			{
				$e["$eventid"]['currentmonth'] = gmmktime(0, 0, 0, gmdate('n', $e["$eventid"]['currentmonth']) + 1, 1, gmdate('Y', $e["$eventid"]['currentmonth']));
				$e["$eventid"]['monthcount']++;
			}

			if ($e["$eventid"]['monthcount'] % $monthrep)
			{
				return false;
			}
		}
		else if ($event['recurring'] == 5)
		{
			if (gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust)
			{
				if ($event['dateline_from_user'] > $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$todaystart -= 86400;
				}
				else
				{
					$todaystart += 86400;
				}
			}
			$monthbit = explode('|', $event['recuroption']);
			$monthrep = $monthbit[2];
			$monthday = $monthbit[1];
			$monthweek = $monthbit[0];

			if ($monthrep == 0 OR $monthweek < 1 OR $monthweek > 5 OR $monthday < 1 OR $monthday > 7)
			{
				return false;
			}

			$fromdate = $e["$eventid"]['startday'];
			$todate = $e["$eventid"]['endday'];
			if (!is_array($foundday["$eventid"]))
			{
				while ($fromdate <= $todate)
				{
					$stopday = false;
					$tempday = gmdate('j', $fromdate);
					$whatday = gmdate('w', $fromdate) + 1;
					if ($monthday != $whatday)
					{
						$stopday = true;
					}
					else if ($tempday > ($monthweek * 7) OR $tempday < ($monthweek * 7 - 6))
					{
						$DaysInMonth = gmdate('t', $fromdate);
						if ($monthweek != 5 OR $tempday + 7 <= $DaysInMonth)
						{
							$stopday = true;
						}
					}
					if ($stopday)
					{	// Add one day
						$fromdate += 86400;
					}
					else
					{
						// We found a day this occurs on.
						$foundday["$eventid"]["$fromdate"] = 1;
						// Move to the next month depending on repetition
						$temp = gmdate('n-j-Y', $fromdate);
						$temp = explode('-', $temp);
						$fromdate = gmmktime(0, 0, 0, $temp[0] + $monthrep, 1, $temp[2]);
					}
				}
			}
			if (!$foundday["$eventid"]["$todaystart"])
			{
				return false;
			}
		}
		else if ($event['recurring'] == 6)
		{
			if (empty($event['holidayid']) AND gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust)
			{
				if ($event['dateline_from_user'] > $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$todaystart -= 86400;
				}
				else
				{
					$todaystart += 86400;
				}
			}
			$monthbit = explode('|', $event['recuroption']);
			if ($monthbit[0] < 1 OR $monthbit[0] > 12 OR $monthbit[1] < 1 OR $monthbit[1] > 31)
			{
				return false;
			}
			if ($todaystart != gmmktime(0, 0, 0, $monthbit[0], $monthbit[1], $year))
			{
				return false;
			}
		}
		else if ($event['recurring'] == 7)
		{
			$monthbit = explode('|', $event['recuroption']);

			if ($monthbit[0] < 1 OR $monthbit[0] > 5 OR $monthbit[1] < 1 OR $monthbit[1] > 7 OR $monthbit[2] < 1 OR $monthbit[2] > 12)
			{
				return false;
			}

			$tempmonth = $month;
			$tempday = $day;

			if (gmdate('w', $event['dateline_from_user']) != gmdate('w', $event['dateline_from'] + ($event['utc'] * 3600)) AND $adjust AND !$event['holidayid'])
			{
				if ($event['dateline_from_user'] < $event['dateline_from'] + ($event['utc'] * 3600))
				{
					$day++;
					if ($day > gmdate('t', $todaymid))
					{
						$day = 1;
						$month++;
						if ($month == 13)
						{
							$month = 1;
						}
					}
					$todaymid += 86400;
				}
				else
				{
					$todaymid -= 86400;
					$day--;
					if ($day == 0)
					{
						$day = gmdate('t', $todaymid);
						$month--;
						if ($month == 0)
						{
							$month = 12;
						}
					}
				}
			}

			$dayofweek = gmdate('w', $todaymid) + 1;

			if ($month != $monthbit[2] OR $dayofweek != $monthbit[1])
			{
				return false;
			}
			else if ($day > ($monthbit[0] * 7) OR $day < ($monthbit[0] * 7 - 6)			)
			{
				// Now check to see if we aren't looking for the 'last' day of a month
				// sometimes that is the 5th day and sometimes the 4th
				$DaysInMonth = gmdate('t', $todaymid);
				if ($monthbit[0] != 5 OR $day + 7 <= $DaysInMonth)
				{
					return false;
				}
			}
			$day = $tempday;
			$month = $tempmonth;
		}

		if ($event['holidayid'])
		{
			$foundholiday["$month-$day-$year"]["$event[holidayid]"] = true;
		}
		else
		{
			$foundevent["$month-$day-$year"]["$eventid"] = true;
		}
		return true;
	}
	else
	{
		$foundevent["$month-$day-$year"]["$eventid"] = true;
		return true;
	}

	return false;
}

// ###################### Start getevents #######################
function build_events()
{
	global $vbulletin, $vbphrase, $_CALENDAROPTIONS;

	$storeevents = array();

	// Store timestamp 48 hours before the current time and 48 hours after the showevent period
	$beginday = TIMENOW - 172800;
	$endday = TIMENOW + 86400 + 86400;
	$storeevents['date'] = gmdate('n-j-Y' , $endday);

	$events = $vbulletin->db->query_read_slave("
		SELECT eventid, userid, event.title, recurring, recuroption, dateline_from, dateline_to, event.calendarid, IF (dateline_to = 0, 1, 0) AS singleday, customfields,
			dateline_from AS dateline_from_user, dateline_to AS dateline_to_user, utc, dst
		FROM " . TABLE_PREFIX . "event AS event
		INNER JOIN " . TABLE_PREFIX . "calendar AS calendar USING (calendarid)
		WHERE ((dateline_to >= $beginday AND dateline_from < $endday) OR (dateline_to = 0 AND dateline_from >= $beginday AND dateline_from <= $endday ))
			AND visible = 1
			AND calendar.options & " . intval($_CALENDAROPTIONS['showupcoming']) . "
		ORDER BY dateline_from
	");

	while ($event = $vbulletin->db->fetch_array($events))
	{
		$event['title'] = htmlspecialchars_uni($event['title']);
		$storeevents["$event[eventid]"] = $event;
	}

	build_datastore('eventcache', serialize($storeevents), 1);

	return $storeevents;

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
