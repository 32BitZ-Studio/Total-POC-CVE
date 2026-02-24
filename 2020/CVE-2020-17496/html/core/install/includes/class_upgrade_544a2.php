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

class vB_Upgrade_544a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '544a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.4 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.4 Alpha 1';

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
		$this->updateHeaderUrls(array(
			'blogadmin/create' => 'blogadmin/create/settings',
			'sgadmin/create' => 'sgadmin/create/settings'
		));
	}

	public function step_2()
	{
		//update the pages so they point back to the routes that point at them.  This managed to get out of
		//sync due to some previous bugs.  Don't update redirect routes -- we never want a page to point to
		//a redirect route.
		$db = vB::getDbAssertor();
		$routes = $db->select('routenew', array(array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL)));
		foreach($routes AS $route)
		{
			$args = unserialize($route['arguments']);
			if(!empty($args['pageid']))
			{
				//we should always have a page, but if we don't we aren't going to try to correct that here.
				$page = $db->getRow('page', array('pageid' => $args['pageid']));
				if($page AND ($page['routeid'] != $route['routeid']))
				{
					$db->update('page', array('routeid' => $route['routeid']), array('pageid' => $page['pageid']));
				}
			}
		}
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'page'));
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
