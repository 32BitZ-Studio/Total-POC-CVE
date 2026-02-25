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

class vB_Upgrade_544a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '544a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.4 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.4 Alpha 3';

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
		// Create ishomeroute field
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'routenew', 1, 2),
			'routenew',
			'ishomeroute',
			'TINYINT',
			array(
				'null' => true,
			)
		);
	}

	public function step_2()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'routenew', 2, 2),
			'routenew',
			'ishomeroute',
			array('ishomeroute')
		);
	}

	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'routenew', 1, 1));
		$db = vB::getDbAssertor();

		//we need to set the blank prefix to a placeholder.  This won't really change the behavior (aside
		//from {site}/homepage being a redirect) but we can't have a blank prefix or things get weird
		//when you make another page the homepage.
		$newprefix = 'homepage';

		$result = $db->select('routenew', array('prefix' => ''));
		foreach($result AS $row)
		{
			$re = $newprefix;

			//the default conversation route does it's own thing in regards to the prefix.  We want a slash after the
			//prefix *unless* the prefix is blank.  There isn't a good way to capture this case because it's implicitly
			//buried in the route logic (specifically in the isValid function of conversation route class and the
			//updateContentRoute function of the channel route class.
			//
			//Custom topic urls follow the normal case of not having a slash directly after hte prefix.
			//Also do not add a slash if that's already the first character.  That *shouldn't* happen
			//but we never want a double slash.
			if (is_a($row['class'], 'vB5_Route_Conversation', true) AND $row['regex'][0] != '/')
			{
				$arguments = unserialize($row['arguments']);
				if(empty($arguments['customUrl']))
				{
					$re .= '/';
				}
			}

			$re .= $row['regex'];

			$data = array(
				'prefix' => $newprefix,
				'regex' => $re,
				'ishomeroute' => 1
			);

			$db->update('routenew', $data, array('routeid' => $row['routeid']));
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
