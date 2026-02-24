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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_503rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '503rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.3 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3 Beta 1';

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
	 *	Step 1 - Find incorrectly imported polls and update the starter node
	 *  The issue ocurred in upgrader 500a1 steps 149-152, VBV-9818
	 *
	 *	NOTE: Also see 510a8 step_1
	*/
	public function step_1($data = NULL)
	{

		if ($this->tableExists('poll') AND $this->tableExists('polloption'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503rc1']['importing_stray_polls']);

			$assertor = vB::getDbAssertor();
			$batchsize = 500000;
			$startat = intval($data['startat']);

			//First see if we need to do something. Maybe we're O.K.
			if (!empty($data['maxToFix']))
			{
				$maxToFix = $data['maxToFix'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxPollNodeid', array());
				$maxToFix = intval($maxToFix['maxToFix']);
				//If we don't have any we're done.
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if ($startat >= $maxToFix)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Get the poll data, nodeid of the starter, nodeid of the poll and the options from poll table
			$pollData = $assertor->assertQuery('vBInstall:getStrayPollsAndOptions', array(
				'startat' => $startat,
				'batchsize' => $batchsize,
				'pollcontenttypeid' => vB_Api_ContentType::OLDTYPE_POLL,
				'threadcontenttypeid' => vB_Types::instance()->getContentTypeID('vBForum_Thread'),
			));

			if (!$pollData->valid())
			{
				return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
			}

			// Update the polloption table
			$assertor->assertQuery('vBInstall:fixNodeidInPolloption', array(
				'startat' => $startat,
				'batchsize' => $batchsize,
				'contenttypeid' => vB_Api_ContentType::OLDTYPE_POLL,
			));

			$oldPollList = array();
			foreach ($pollData AS $poll)
			{
				$votes = 0;
				if (!empty($poll['options']) AND ($options = unserialize($poll['options']))
						AND is_array($options))
				{
					foreach ($options AS $key => $option)
					{
						$options[$key]['nodeid'] = $poll['nodeid'];
						$votes += $options[$key]['votes'];
					}

					foreach ($options AS &$option)
					{
						if ($votes)
						{
							$option['percentage'] = number_format($option['votes'] / $votes * 100, 2);
						}
						else
						{
							$option['percentage'] = 0;
						}
					}

					// Update nodeid, poll options and number of votes for each poll
					$assertor->assertQuery('vBForum:poll', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						vB_dB_Query::CONDITIONS_KEY => array(array('field' => 'nodeid', 'value' => $poll['pollnodeid'])),
						'nodeid' => $poll['nodeid'],
						'options' => serialize($options),
						'votes' => $votes
					));

				}
				$oldPollList[] = $poll['pollnodeid'];
			}

			// Fix starter contenttypes
			$assertor->assertQuery('vBInstall:fixPollContentTypes', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_POLL));

			// Remove this batch of old poll nodes (the ones that shouldn't have been created)
			$assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'nodeid' => $oldPollList));
			$assertor->assertQuery('vBForum:closure', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'child' => $oldPollList));

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));

			return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}

	// removing redundant infraction table fields
	public function step_2()
	{
		$made_changes = false;
		if ($this->field_exists('infraction', 'infractionid'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 6),
					'infraction',
					'infractionid'
			);
			$made_changes = true;
		}

		if ($this->field_exists('infraction', 'postid'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 2, 6),
					'infraction',
					'postid'
			);
			$made_changes = true;
		}

		if ($this->field_exists('infraction', 'userid'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 3, 6),
					'infraction',
					'userid'
			);
			$made_changes = true;
		}

		if ($this->field_exists('infraction', 'dateline'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 4, 6),
					'infraction',
					'dateline'
			);
			$made_changes = true;
		}
		if ($this->field_exists('infraction', 'channelid'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 5, 6),
					'infraction',
					'channelid'
			);
			$made_changes = true;
		}

		if ($this->field_exists('infraction', 'threadid'))
		{
			$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 6, 6),
					'infraction',
					'threadid'
			);
			$made_changes = true;
		}

		if (!$made_changes)
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
