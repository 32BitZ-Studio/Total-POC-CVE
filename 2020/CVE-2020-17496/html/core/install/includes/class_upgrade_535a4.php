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

class vB_Upgrade_535a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '535a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.5 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.5 Alpha 3';

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
		$db = vB::getDBAssertor();
		$row = $db->getRow('routenew', array('name' => 'blog'));

		$changes = array();
		if($row['prefix'] == $row['regex'])
		{
			$changes['regex'] = $row['prefix'] . '(?:(?:/|^)page(?P<pagenum>[0-9]+))?';
		}
		else
		{
			$newre = str_replace('(?:/page(', '(?:(?:/|^)page(', $row['regex']);

			if($newre != $row['regex'])
			{
				$changes['regex'] = $newre;
			}
		}

		$arguments = unserialize($row['arguments']);
		if(!isset($arguments['channelid']) OR !isset($arguments['pagenum']))
		{
			if(!isset($arguments['channelid']))
			{
				$arguments['channelid'] = vB_Library::instance('blog')->getBlogChannel();
			}

			if(!isset($arguments['pagenum']))
			{
				$arguments['pagenum'] = '$pagenum';
			}

			$changes['arguments'] = serialize($arguments);
		}

		if($changes)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
			$row = $db->update('routenew', $changes, array('name' => 'blog'));
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_2()
	{
		$db = vB::getDBAssertor();
		$row = $db->getRow('routenew', array('name' => 'sghome'));

		$changes = array();
		if($row['prefix'] == $row['regex'])
		{
			$changes['regex'] = $row['prefix'] . '(?:(?:/|^)page(?P<pagenum>[0-9]+))?';
		}
		else
		{
			$newre = str_replace('(?:/page(', '(?:(?:/|^)page(', $row['regex']);

			if($newre != $row['regex'])
			{
				$changes['regex'] = $newre;
			}
		}

		$arguments = unserialize($row['arguments']);
		if(!isset($arguments['channelid']) OR !isset($arguments['pagenum']))
		{
			if(!isset($arguments['channelid']))
			{
				$arguments['channelid'] = vB_Library::instance('node')->getSGChannel();
			}

			if(!isset($arguments['pagenum']))
			{
				$arguments['pagenum'] = '$pagenum';
			}

			$changes['arguments'] = serialize($arguments);
		}

		if($changes)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
			$row = $db->update('routenew', $changes, array('name' => 'sghome'));
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_3()
	{
		$db = vB::getDBAssertor();
		$set = $db->select('routenew', array(array('field' => 'redirect301', 'operator' => vB_dB_Query::OPERATOR_ISNOTNULL)));

		$redirectMap = array();
		foreach($set AS $row)
		{
			$redirectMap[$row['routeid']] = $row['redirect301'];
		}

		$haveupdate = false;
		//collapse redirects so we aren't redirecting to a redirect...
		foreach($redirectMap AS $routeid => $redirectid)
		{
			//if we are redirecting to a redirect
			if (isset($redirectMap[$redirectid]))
			{
				$haveupdate = true;
				$seen = array();
				$finalredirectid = $redirectid;
				while(isset($redirectMap[$finalredirectid]))
				{
					$seen[] = $finalredirectid;
					$finalredirectid = $redirectMap[$finalredirectid];

					//if we've already seen this ID, we have a redirect loop.  This shouldn't happen,
					//but it's best to avoid infinite loops and who knows what's out there in the wild
					//In theory we should probably do something about this (likely deleting all the
					//routes in question, since they can't do anything good) but I'd rather wait for
					//a concrete example to test before doing something rash
					if(in_array($finalredirectid, $seen))
					{
						continue 2;
					}
				}

				$row = $db->update('routenew', array('redirect301' => $finalredirectid), array('routeid' => $routeid));
			}
		}

		if ($haveupdate)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
