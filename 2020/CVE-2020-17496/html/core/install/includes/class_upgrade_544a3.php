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

class vB_Upgrade_544a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '544a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.4 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.4 Alpha 2';

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

	function step_1()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'routeid', TABLE_PREFIX . 'node'),
			'node',
			'routeid',
			array('routeid')
		);
	}

	public function step_2()
	{
		//previous logic didn't update the contentid of the route when changing the conversation route for
		//a topic to a custom url.  In which case we'll have multiple conversation routes that have a
		//channels noteid as the contentid.  We use this to set the routeid for new nodes in channel
		//which could cause all kinds of problems if people actually set the url for a topic.
		//
		//Due to they way mysql works this is likely to continue working... right up until it stops.
		//so let's point custom topic urls at the topic node instead.
		$db = vB::getDbAssertor();
		$routes = $db->select('routenew', array(
			'class' => 'vB5_Route_Conversation',
			array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNULL)
		));

		foreach($routes AS $route)
		{
			$args = unserialize($route['arguments']);
			if(!empty($args['customUrl']) AND $args['nodeid'] != $route['contentid'])
			{
				$db->update('routenew', array('contentid' => $args['nodeid']), array('routeid' => $route['routeid']));
			}
		}
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'route'));
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
