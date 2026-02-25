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
 * vB_Api_Content_Poll
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: poll.php 102567 2019-08-16 16:47:02Z ksours $
 * @access public
 */
class vB_Api_Content_Poll extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Poll';

	//The table for the type-specific data.
	protected $tablename = array('poll', 'text');

	//When we parse the page.
	protected $bbcode_parser = false;

	protected $tableFields = array();

	//Is text required for this content type?
	protected $textRequired = false;

	/**
	 * Constructor, cannot be instantiated externally
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Poll');
	}

	/**
	 * Vote on a Poll (for the current user)
	 *
	 * @param  int|array Int or an array of poll option IDs to be "voted"
	 *
	 * @return int       The node ID of the poll that was voted on.
	 */
	public function vote($polloptionids)
	{
		$usercontext = &vB::getUserContext();

		if (is_numeric($polloptionids))
		{
			$polloptionids = array($polloptionids);
		}
		elseif (!is_array($polloptionids))
		{
			throw new vB_Exception_Api('invalidparameter');
		}

		$options = array();
		$nodeid = 0;
		foreach ($polloptionids as $polloptionid)
		{
			$option = $this->assertor->getRow('vBForum:polloption', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'polloptionid' => intval($polloptionid),
			));

			if (!$option OR ($nodeid AND ($nodeid != $option['nodeid'])))
			{
				throw new vB_Exception_Api('invalidvote');
			}

			if (!$usercontext->getChannelPermission('forumpermissions', 'canvote', $option['nodeid']))
			{
				throw new vB_Exception_Api('no_permission');
			}

			$options[] = $option;
			$nodeid = $option['nodeid'];
		}
		unset($option);

		$polls = $this->getContent($nodeid);
		if(empty($polls) OR empty($polls[$nodeid]))
		{
			return false;
		}

		// Check if the poll is timeout
		if ($polls[$nodeid]['timeout'] AND $polls[$nodeid]['timeout'] < vB::getRequest()->getTimeNow())
		{
			return false;
		}

		// Check if the user has voted the poll
		if ($this->checkVoted($nodeid))
		{
			return false;
		}

		$nodeid = $this->library->vote($options);

		// All options should be in a same poll
		$this->library->updatePollCache($nodeid, true);

		return $nodeid;
	}

	/**
	 * Checks if the current user has voted on this poll
	 *
	 * @param  int  Node ID for the poll to check.
	 *
	 * @return bool True if the current user has voted on this poll, false otherwise.
	 */
	protected function checkVoted($nodeid)
	{
		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		if (!$loginuser['userid'])
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$uservoteinfo = vB::getDbAssertor()->getRow('vBForum:pollvote', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'userid' => $loginuser['userid'],
			'nodeid' => $nodeid,
		));

		if ($uservoteinfo)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102567 $
|| #######################################################################
\*=========================================================================*/
