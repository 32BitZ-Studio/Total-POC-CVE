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

class vB_Upgrade_524a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '524a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.4 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.4 Alpha 1';

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

	public function step_1($data = null)
	{
		$batchSize = 1000;

		if (empty($data['startat']))
		{
			$data['startat'] = 0;
			$this->show_message($this->phrase['version']['524a2']['fix_userpmtotals']);
		}

		$assertor = vB::getDbAssertor();

		$users = $assertor->assertQuery('user',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $data['startat'], 'operator' =>  vB_dB_Query::OPERATOR_GTE),
				),
				vB_dB_Query::PARAM_LIMIT => $batchSize,
				vB_dB_Query::COLUMNS_KEY => array('userid')
			),
			'userid'
		);

		$userids = array();
		foreach($users AS $user)
		{
			$userids[] = $user['userid'];
		}

		if (count($userids))
		{
			vB_Library::instance('content_privatemessage')->buildPmTotals($userids);

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], count($userids)));
			return array('startat' => $userids[count($userids)-1]+1);
		}
		else
		{
			$this->show_message($this->phrase['core']['process_done']);
			return;
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
