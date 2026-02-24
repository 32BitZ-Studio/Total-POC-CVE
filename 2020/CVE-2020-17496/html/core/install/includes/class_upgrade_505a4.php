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

class vB_Upgrade_505a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '505a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.5 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.5 Alpha 3';

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

	/**
	 * Set systemgroupid for those groups
	 * Needed here due beta maintenance, we don't want to rerun old upgraders for this
	 */
	function step_1()
	{
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'widegetinstance', 1, 1));
		vB::getDbAssertor()->assertQuery('vBInstall:makeWidgetInstanceConfUtf8');
	}

	/*
	 *	Step 2 - Make sure old pages have GUID
	 */
	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['version']['505a4']['fix_page_guid']));

		$assertor = vB::getDbAssertor();
		$pages = $assertor->getRows('getPagesWithoutGUID');

		foreach ($pages as $page)
		{
			$assertor->update('page', array('guid' => vB_GUID::get()), array('pageid' => $page['pageid']));
		}

		$this->show_message(sprintf($this->phrase['core']['process_done']));
	}

	/**
	 * Scan and fix filedata refcount
	 */
	public function step_3($data = array())
	{
		$assertor = vB::getDbAssertor();
		$batchsize = 1000;
		$startat = intval($data['startat']);
		$nextid = $assertor->getRow('vBInstall:getNextZeroRefcount', array('startat' => $startat));

		// Check if any users have custom folders
		if (empty($nextid) OR !empty($nextid['errors']) OR empty($nextid['filedataid']))
		{
			if (empty($startat))
			{
				$this->skip_message();
				return;
			}
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		if (empty($startat))
		{
			$this->show_message($this->phrase['version']['505a4']['fix_filedata_refcount']);
		}

		$startat = $nextid['filedataid'];
		// Get the users for import
		$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $batchsize));
		$assertor->assertQuery('vbinstall:fixRefCount', array('startat' => $startat, 'batchsize' => $batchsize));
		return array('startat' => ($startat + $batchsize), 'maxid' => $maxid);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102032 $
|| #######################################################################
\*=========================================================================*/
