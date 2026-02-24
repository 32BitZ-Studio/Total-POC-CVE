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

class vB_Upgrade_525a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '525a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.5 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.4';

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
	 * Enable user.options[134217728] by default. Run once only.
	 */
	public function step_1($data = null)
	{
		// Only run once.
		if (empty($data['startat']) AND $this->iRan(__FUNCTION__))
		{
			return;
		}
		elseif (empty($data['startat']))
		{
			$this->show_message($this->phrase['version']['525a1']['setting_user_vbmessenger']);
			$data['startat'] = 0;
		}

		$startat = $data['startat'];
		$batchsize = 5000;

		$max = vB::getDbAssertor()->getRow('vBInstall:getMaxUserid');
		$maxid = $max['maxid'];
		if ($maxid <= $startat)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}


		$count = vB::getDbAssertor()->assertQuery('vBInstall:setUserPmchatOption', array('startat' => $startat, 'batchsize' => $batchsize));
		$this->show_message(sprintf($this->phrase['core']['processed_x_records_starting_at_y'], $count, $startat + 1));

		$data['startat'] = $startat + $batchsize;
		return $data;
	}



	public function step_2()
	{
		// Place holder to allow iRan() to work properly, as the last step gets recorded as step '0' in the upgrade log for CLI upgrade.
		$this->skip_message();
		return;
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/