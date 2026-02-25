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

class vB_Upgrade_526a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '526a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.6 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.6 Alpha 2';

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


	public function step_1()
	{
		$this->skip_message();
	}

	public function step_2($data = NULL)
	{
		$db = vB::getDbAssertor();
		$batchsize = 1000;

		$startat = (empty($data['startat']) ? 0 : $data['startat']);

		$this->show_message(sprintf($this->phrase['version']['526a3']['deleting_orphaned_tag_associations_x'], $startat), true);

		$nodeids = $db->getColumn('vBInstall:getOrphanedTagAssociations', 'nodeid',
			array('startatnodeid' => 'startat', 'batchsize' => $batchsize)
		);

		//putting distinct in the query causes mysql to do a sort.  Which interacts
		//badly with doing the limit on what could be a fairly expensive query to
		//run to completion.
		$nodeids = array_unique($nodeids);

		if(!$nodeids)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$db->delete('vBForum:tagnode', array('nodeid' => $nodeids));

		return array('startat' => end($nodeids));
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
