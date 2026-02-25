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

class vB_Upgrade_510a7 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a7';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 7';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 6';

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
	 *	Step 1 :
	 *	There are 3 possibly dupe page records inserted by 500a1 step_23.
	 * 	The first of these is causing problems, so let's delete it.
	 *	upgrade final's step_8 should fix the route record
	 */
	function step_1()
	{
		vB_Upgrade::createAdminSession();

		$possibleDupes = array(
			array("pageid" => 1, "parentid" => 0, "routeid" => 9, "guid" => "vbulletin-4ecbdac82ef5d4.12817784"),
			//array("pageid" => 2, "parentid" => 0, "routeid" => 24, "guid" => "vbulletin-52b4c3c6590572.75515897"),
			//array("pageid" => 3, "parentid" => 30, "routeid" => 30, "guid" => "vbulletin-52b4c3c65906c1.50869326"),
		);

		$this->show_message($this->phrase['version']['510a7']['removing_duplicate_page']);

		$importChannels = false;
		foreach($possibleDupes AS $page)
		{
			$dupes = vB::getDbAssertor()->getRows('vBForum:page',
				array(
					'guid' => $page['guid'],
				)
			);

			if (count($dupes) > 1)
			{
				vB::getDbAssertor()->assertQuery('vBForum:page',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
						'pageid' => $page['pageid'],
						'parentid' => $page['parentid'],
						'routeid' => $page['routeid'],
						'guid' => $page['guid'],
					)
				);
				$importChannels = true;
			}
		}
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_9();

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
