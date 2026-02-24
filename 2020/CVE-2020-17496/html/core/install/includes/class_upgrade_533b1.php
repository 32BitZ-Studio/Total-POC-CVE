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

class vB_Upgrade_533b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '533b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.3 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.3 Alpha 4';

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

	public function step_1($data = NULL)
	{

		$assertor = vB::getDbAssertor();
		$batchsize = 500000;
		$startat = intval($data['startat']);

		// output what we're doing -- but only on the first iteration
		if($startat == 0)
		{
			$this->show_message($this->phrase['version']['510a8']['fixing_imported_polls']);
		}

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
		$pollData = $assertor->assertQuery('vBInstall:pollFixPollVote',
			array(
				'startat' => $startat,
				'batchsize' => $batchsize,
			)
		);

		$processed = min($startat + $batchsize, $maxToFix);

		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $processed, $maxToFix));
		return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
