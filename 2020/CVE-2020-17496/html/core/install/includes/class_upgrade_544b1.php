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

class vB_Upgrade_544b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '544b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.4 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.4 Alpha 4';

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
	 *	Fix nodes that point to redirect routes.  This not only causes extra processing when generating
	 *	urls for those nodes, it causes other difficulties.
	 */
	public function step_1($data)
	{
		if(empty($data['startat']))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}

		$db = vB::getDbAssertor();
		$startat = intval($data['startat']);

		//this doesn't really work because "max" isn't propagated in $data, but
		//leaving it in so that it will work if we fix that.
		if (!empty($data['max']))
		{
			$max = $data['max'];
		}
		else
		{
			$max = $db->getRow('vBInstall:getMaxNodeRedirectRoute');

			//If we don't have any posts, we're done.
			if (intval($max) < 1)
			{
				$this->skip_message();
				return;
			}
		}

		if ($startat > $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		//there aren't going to be *that* many affected routes, but the update query could
		//be a little time consuming if we have a lot of nodes in a topic.  So we'll handle
		//it one by one
		$route = $db->getRow('vBInstall:getNodeRedirectRoutes', array('startat' => $startat));
		if($route)
		{
			$db->update('vBForum:node', array('routeid' => $route['redirect301']), array('routeid' => $route['routeid']));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $route['routeid'], $route['routeid']), true);
		}
		else
		{
			//this probably shouldn't happen since we should hit the greater than max
			//case above in all cases.  But just in case.
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		return array('startat' => $route['routeid'] + 1, 'max' => $max);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
