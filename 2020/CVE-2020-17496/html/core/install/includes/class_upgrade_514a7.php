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

class vB_Upgrade_514a7 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '514a7';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.4 Alpha 7';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.4 Alpha 6';

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
	 * Add the nodeid as one of the arguments to all channel routes that are missing it.
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();

		$routes = $assertor->assertQuery('routenew', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				'class' => 'vB5_Route_Channel',
			),
		));

		$updated = false;
		foreach ($routes AS $route)
		{
			$args = unserialize($route['arguments']);

			if (!$args OR !empty($args['nodeid']))
			{
				continue;
			}

			// add nodeid
			$args['nodeid'] = $args['channelid'];

			$values = array('arguments' => serialize($args));
			$conditions = array('routeid' => $route['routeid']);
			$assertor->update('routenew', $values, $conditions);

			$updated = true;
		}

		if ($updated)
		{
			$this->show_message($this->phrase['version']['514a7']['fixing_channel_routes_missing_nodeid']);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add contentpagenum as one of the arguments to all conversation routes that are missing it.
	 */
	public function step_2()
	{
		$assertor = vB::getDbAssertor();

		$routes = $assertor->assertQuery('routenew', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				'class' => 'vB5_Route_Conversation',
			),
		));

		$updated = false;
		foreach ($routes AS $route)
		{
			$args = unserialize($route['arguments']);

			if (!$args OR !empty($args['contentpagenum']))
			{
				continue;
			}

			// don't mess with the regex for custom URLs
			if (!empty($args['customUrl']))
			{
				continue;
			}

			// add contentpagenum to arguments
			$args['contentpagenum'] = '$contentpagenum';

			// update regex to include contentpagenum
			$regex = preg_quote($route['prefix']) . '/' . vB5_Route_Conversation::REGEXP;

			// do update
			$values = array('arguments' => serialize($args));
			$conditions = array(
				'routeid' => $route['routeid'],
				'regex' => $regex,
			);
			$assertor->update('routenew', $values, $conditions);

			$updated = true;
		}

		if ($updated)
		{
			$this->show_message($this->phrase['version']['514a7']['fixing_conversation_routes_missing_contentpagenum']);
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
