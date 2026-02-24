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

class vB_Upgrade_510a8 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a8';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 8';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 7';

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
	 *	Step 1 - Find stray polls whose nodes have been deleted but poll.nodeid haven't been updated
	 *		properly and update those records.
	 *		Most of this step is copied from 503rc1 step_1 since it replicates the portion
	 *		of that step that was skipped due to the typo.
	*/
	public function step_1($data = NULL)
	{
		if ($this->tableExists('poll') AND $this->tableExists('polloption') AND $this->tableExists('thread'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['510a8']['fixing_imported_polls']);

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
			$pollData = $assertor->assertQuery('vBInstall:getStrayPolls',
				array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'pollcontenttypeid' => vB_Api_ContentType::OLDTYPE_POLL
				)
			);

			if (!$pollData->valid())
			{
				return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
			}

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
						vB_dB_Query::CONDITIONS_KEY => array(array('field' => 'pollid', 'value' => $poll['pollid'])),
						'nodeid' => $poll['nodeid'],
						'options' => serialize($options),
						'votes' => $votes
					));

				}
			}

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));

			return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
		}
		else
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
