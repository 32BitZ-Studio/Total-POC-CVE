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
 * vB_Api_Vb4_events
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_events extends vB_Api
{
	public function listing(
		$beginperiod = 0,
		$endperiod = null,
		$perpage = 20,
		$pagenumber = 1
	)
	{
		$cleaner = vB::getCleaner();

		$beginperiod = $cleaner->clean($beginperiod, vB_Cleaner::TYPE_UINT);
		if (empty($beginperiod))
		{
			$beginperiod = vB::getRequest()->getTimeNow();
		}

		// if not empty, it'll change $searchJSON.eventstartdate below
		$endperiod = $cleaner->clean($endperiod, vB_Cleaner::TYPE_UINT);


		$perpage = $cleaner->clean($perpage, vB_Cleaner::TYPE_UINT);
		if ($perpage < 1)
		{
			$perpage = 20;
		}

		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);
		if ($pagenumber < 1)
		{
			$pagenumber = 1;
		}

		/*
			Based on the default searchJSON for the calendar widget
			{
				"type":["vBForum_Event"],
				"eventstartdate":"future",
				"sort":{"eventstartdate":"ASC"},
				"view":"event",
				"exclude_type":["vBForum_PrivateMessage"]
			}
		 */
		$searchSort = array(
			"eventstartdate" => "ASC",
		);
		$searchJSON = array(
			"type"           => "vBForum_Event",
			"eventstartdate" => $beginperiod,
			"sort"           => $searchSort,
			"view"           => "event",
			"exclude_type"   => "vBForum_PrivateMessage",
		);

		if (!empty($endperiod))
		{
			$searchJSON['eventstartdate'] = array(
				'from'  => $beginperiod,
				'to'    => $endperiod,
			);
		}

		$events = vB_Api::instance('search')->getInitialResults($searchJSON, $perpage, $pagenumber);
		if ($events === null || isset($events['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($events);
		}

		$eventlist = array();

		foreach ($events['results'] AS $__nodeid => $__node)
		{
			$__event = array(
				'nodeid' => (int) $__node['nodeid'],
				'eventstarttime' => (int) $__node['content']['eventstartdate'],
				// Null instead of default 0 or "". If not-empty, these are assigned below.
				'eventendtime' => null,
				'location' => null,
				// ATM all events are starters, so they will all have titles set. If this changes,
				// we should change this to point to starter.title (probably) & notify the mobile team.
				'title' => (string) $__node['title'],
			);

			if (!empty($__node['content']['eventenddate']))
			{
				$__event['eventendtime'] = (int) $__node['content']['eventenddate'];
			}

			if (!empty($__node['content']['location']))
			{
				$__event['location'] = (string) $__node['content']['location'];
			}

			$eventlist[] = $__event;
		}
		$total = $events['totalRecords'];


		$pagenav = vB_Library::instance('vb4_functions')->pageNav($pagenumber, $perpage, $total);

		$response = array();
		$response['response'] = array(
			'eventlist'     => $eventlist,
			'perpage'       => $perpage,
			'pagenumber'    => $pagenumber,
			'total'         => $total,
			'pagenav'       => $pagenav,
			//'totalpages'    => $totalpages,
		);

		return $response;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
